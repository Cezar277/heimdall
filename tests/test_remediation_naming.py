"""Preuves T30.2 (#84) : validation et déduplication des noms de variables.

Toutes les valeurs sont synthétiques ; aucun secret réel. Le nom proposé
par le LLM est traité comme une entrée non fiable.
"""

from __future__ import annotations

import itertools

import pytest

from heimdall.cli.review import _VARIABLE as _REVIEW_VARIABLE
from heimdall.cli.vault_client import _SECRET_NAME_PATTERN as _VAULT_CLI_PATTERN
from heimdall.cli.vault_client import is_dangerous_env_var as vault_is_dangerous
from heimdall.remediation import naming as naming_module
from heimdall.remediation.naming import (
    deduplicate_variable_name,
    is_dangerous_env_var,
    validate_variable_name,
)
from heimdall.remediation.templates import _VARIABLE as _TEMPLATES_VARIABLE
from heimdall.remediation.templates import TemplateError
from heimdall.vault.client import _SECRET_NAME_PATTERN as _VAULT_PATTERN

#: Batterie d'équivalence des grammaires dispersées (ne pas les laisser diverger).
_GRAMMAR_CASES: tuple[object, ...] = (
    "AB",
    "A1",
    "APP_KEY",
    "Z_0",
    "A" * 64,
    "DB_PASSWORD_2",
    "",
    "A",
    "a",
    "Ab",
    "9ABC",
    "_ABC",
    "APP KEY",
    "APP-KEY",
    "APP.KEY",
    "APPÉ",
    "A\nB",
    "A\tB",
    " APP",
    "APP ",
    "A" * 65,
    "a" * 64,
    None,
    123,
    b"APP",
)


def _accepts(pattern: object, value: object) -> bool:
    assert hasattr(pattern, "fullmatch")
    return pattern.fullmatch(value) is not None if isinstance(value, str) else False


@pytest.mark.parametrize("value", _GRAMMAR_CASES)
def test_grammars_agree_everywhere(value: object) -> None:
    """Les 5 copies historiques de la grammaire acceptent/refusent pareil."""
    results = {
        _accepts(naming_module._VARIABLE, value),
        _accepts(_TEMPLATES_VARIABLE, value),
        _accepts(_REVIEW_VARIABLE, value),
        _accepts(_VAULT_CLI_PATTERN, value),
        _accepts(_VAULT_PATTERN, value),
    }
    assert results in ({True}, {False})


@pytest.mark.parametrize(
    "name",
    ["APP_KEY", "A1", "DB_PASSWORD_2", "Z_0", "A" * 64, "MY_LD_VAR"],
)
def test_validate_accepts_safe_names(name: str) -> None:
    assert validate_variable_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "A",
        "aBC",
        "APP KEY",
        "APP-KEY",
        "A\nB",
        "A\tB",
        "A" * 65,
        None,
        123,
        b"APP",
        "PATH",
        "LD_PRELOAD",
        "PYTHONPATH",
        "SHELL",
        "HOME",
        "TERM",
        "LD_X",
        "PYTHONIC",
        "HEIMDALL_API_KEY",
        "NODE_ENV",
    ],
)
def test_validate_rejects_bad_or_dangerous_names(name: object) -> None:
    """Grammaire (dont retours à la ligne) + denylist : rejet statique, jamais de reflet."""
    with pytest.raises(TemplateError):
        validate_variable_name(name)


def test_dangerous_names_come_from_one_source() -> None:
    """Pas de divergence : le CLI réutilise la denylist de la remédiation."""
    assert vault_is_dangerous is naming_module.is_dangerous_env_var


@pytest.mark.parametrize("name", ["PATH", "LD_PRELOAD", "PYTHONPATH", "LD_X", "PYTHONIC", "TERM"])
def test_is_dangerous_env_var_flags_system_names(name: str) -> None:
    assert is_dangerous_env_var(name) is True


@pytest.mark.parametrize("name", ["APP_KEY", "DB_PASSWORD", "MY_LD_VAR"])
def test_is_dangerous_env_var_spares_app_names(name: str) -> None:
    assert is_dangerous_env_var(name) is False


@pytest.mark.parametrize(
    ("desired", "taken", "expected"),
    [
        ("APP_KEY", set(), "APP_KEY"),
        ("APP_KEY", {"APP_KEY"}, "APP_KEY_2"),
        ("APP_KEY", {"APP_KEY", "APP_KEY_2"}, "APP_KEY_3"),
        ("APP_KEY", ["APP_KEY"], "APP_KEY_2"),
        ("DB_PASSWORD", {"OTHER", "DB_PASSWORD", "DB_PASSWORD_2"}, "DB_PASSWORD_3"),
    ],
)
def test_deduplicate_appends_suffix(desired: str, taken: object, expected: str) -> None:
    assert deduplicate_variable_name(desired, taken) == expected  # type: ignore[arg-type]


def test_deduplicate_result_stays_valid() -> None:
    taken = {"APP_KEY", "APP_KEY_2", "APP_KEY_3"}
    result = deduplicate_variable_name("APP_KEY", taken)
    assert result == "APP_KEY_4"
    assert validate_variable_name(result) == result


@pytest.mark.parametrize("desired", ["", "A", "aBC", "A\nB", "PATH", "LD_X", None, 123])
def test_deduplicate_rejects_invalid_base(desired: object) -> None:
    with pytest.raises(TemplateError):
        deduplicate_variable_name(desired, set())  # type: ignore[arg-type]


def test_deduplicate_overflow_is_fail_closed() -> None:
    """Base de 64 caractères : aucun suffixe ne tient, refus plutôt que troncature."""
    with pytest.raises(TemplateError):
        deduplicate_variable_name("A" * 64, {"A" * 64})


@pytest.mark.parametrize("name", [None, 123, b"APP", ["APP"]])
def test_is_dangerous_env_var_fail_closed_on_non_str(name: object) -> None:
    assert is_dangerous_env_var(name) is True


def test_deduplicate_refuses_infinite_taken_without_hanging() -> None:
    with pytest.raises(TemplateError):
        deduplicate_variable_name("APP_KEY", itertools.repeat("APP_KEY"))


def test_deduplicate_refuses_huge_taken() -> None:
    huge = [f"OTHER_{index}" for index in range(10_001)]
    with pytest.raises(TemplateError):
        deduplicate_variable_name("APP_KEY", huge)


def test_deduplicate_gives_up_when_all_candidates_are_dangerous() -> None:
    """``AWS`` est un nom valide, mais ``AWS_n`` tombe sous le préfixe ``AWS_``."""
    with pytest.raises(TemplateError):
        deduplicate_variable_name("AWS", {"AWS"})
