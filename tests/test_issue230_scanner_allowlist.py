"""Audit E-02 : corpus synthétique, contournements et vrais parcours CLI."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Iterator

import pytest
from support.fake_secrets import fake_token
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli.fix import run_fix
from heimdall.cli.main import app
from heimdall.cli.review import Choice, ReviewOutcome, ReviewReport
from heimdall.scanner.allowlist import AllowlistRule, _compile_safe_regex, _split_alternatives
from heimdall.scanner.entropy_detection import EntropyConfig, find_line_matches
from heimdall.scanner.errors import ScanError
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import FileTarget
from heimdall.scanner.signature_engine import SignatureEngine
from heimdall.scanner.signatures import find_signature_matches
from heimdall.scanner.signatures.service_tokens import PREFIXES
from heimdall.vault.atomic import _get_git_toplevel, is_git_tracked

FAKE_PASSWORD = "FAKE-only!42#local"  # noqa: S105 - marqueur synthétique explicite


def _short_token(index: int, length: int) -> str:
    raw = hashlib.sha256(f"heimdall-e02-synthetic-only-{index}".encode()).digest()
    return base64.b64encode(raw).decode()[:length]


def _positives() -> list[tuple[str, str]]:
    values = [(f'item = "{fake_token(prefix, 32)}"', "service_token") for _, prefix in PREFIXES]
    values += [
        (f'DB_PASSWORD = "{FAKE_PASSWORD}"', "credential"),
        (f"passwd: '{FAKE_PASSWORD}'", "credential"),
        (f"api_key={FAKE_PASSWORD}", "credential"),
        (f'"auth": "{FAKE_PASSWORD}"', "credential"),
        (f"postgres://fake-user:{FAKE_PASSWORD}@localhost/db", "url_credentials"),
        (
            "Authorization: Basic " + base64.b64encode(b"fake-user:fake-pass").decode(),
            "authorization",
        ),
        ("Authorization: Bearer " + fake_token("", 18), "authorization"),
        ('PASSWORD="changeme"', "credential"),
    ]
    values += [
        (f"opaque {_short_token(index, length)}", "high_entropy_base64")
        for length in (20, 21, 22)
        for index in range(20)
    ]
    return values


NEGATIVES = (
    'author = "fake-author"',
    'tokenizer = "wordpiece"',
    "password: str",
    "password = None",
    "token = False",
    'api_key = os.environ["KEY"]',
    'password = "${DB_PASSWORD}"',
    'token = "{{ token }}"',
    'api_key = "your_key_here"',
    'url = "https://localhost/db"',
    "Authorization: None",
    'size = "abcdefghijklmnopqrst"',
    'key = "ordinary-data"',
    'value = "' + "A" * 64 + '"',
    'uuid = "550e8400-e29b-41d4-a716-446655440000"',
)


def test_synthetic_corpus_recall_and_precision() -> None:
    """Mesure figée de ce corpus uniquement, aucune garantie universelle."""
    positives = _positives()
    true_positives = sum(
        any(m.secret_type == kind for m in find_line_matches(line)) for line, kind in positives
    )
    false_positives = sum(bool(tuple(find_line_matches(line))) for line in NEGATIVES)
    recall = true_positives / len(positives)
    precision = true_positives / (true_positives + false_positives)
    assert recall >= 0.90, (true_positives, len(positives))
    assert precision >= 0.95, false_positives


@pytest.mark.parametrize("line,kind", _positives()[:15])
def test_contextual_and_service_signatures_emit_no_raw_value(line: str, kind: str) -> None:
    hasher = SnippetHasher(key=b"T" * 32)
    findings = SignatureEngine(hasher).analyser(FileTarget("config.txt", line))
    assert any(finding.type == kind for finding in findings)
    assert all(len(finding.snippet_hash) == 64 for finding in findings)
    assert FAKE_PASSWORD not in json.dumps([finding.as_dict() for finding in findings])


def test_short_token_adjustment_can_be_disabled_or_tightened() -> None:
    value = _short_token(0, 20)
    assert tuple(find_line_matches(value))
    assert not tuple(find_line_matches(value, EntropyConfig(short_token_adjustment=0)))
    assert not tuple(find_line_matches(value, EntropyConfig(base64_threshold=6)))


@pytest.mark.parametrize("value", [-1, 2, True, "x", float("nan"), float("inf")])
def test_invalid_short_token_configuration_is_refused(value: object) -> None:
    with pytest.raises(ValueError, match="configuration d'entropie invalide"):
        EntropyConfig(short_token_adjustment=value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "pattern",
    [
        r"(?!abc).",
        r"(?<!abc).",
        r"(?=abc).",
        r"a?b?c?.",
        r"a*b*c*.",
        r"a{0,1}b{0,2}c{0,3}.",
        r"(?:abc)?.",
        r"(?:abc){0,1}.",
        r"(abc)?.",
        r"(abc){0,1}.",
        r"(?:abc|).",
        r"(?:abc|x).",
        r"EXAMPLE|(?:abc)?.",
        r"(?i:a?b?c?).",
        r"(?:EXAMPLE|x)?foo?",
        r"\x61?\x62?\x63?.",
        r"a{,3}b{,3}c{,3}.",
        r"a{00,1}b{000,2}c{0000,3}.",
    ],
)
def test_allowlist_cannot_be_made_universal_with_optional_markers(pattern: str) -> None:
    with pytest.raises(ScanError, match="configuration"):
        _compile_safe_regex(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"EXAMPLE-[0-9]{4}",
        r"(?:EXAMPLE|SAMPLE)-[0-9]{4}",
        r"EXAMPLE(?!bad)",
        r"EXAMPLE(abc)?",
        r"(abc)?EXAMPLE",
        r"\x45\x58\x41MPLE",
        r"(?i:EXAMPLE)",
        r"(?P<marker>EXAMPLE)",
    ],
)
def test_narrow_allowlist_markers_remain_accepted(pattern: str) -> None:
    _compile_safe_regex(pattern)


def test_alternation_split_respects_groups_escapes_and_classes() -> None:
    assert _split_alternatives(r"(?:abc|def)[|]x\|y|EXAMPLE") == (
        r"(?:abc|def)[|]x\|y",
        "EXAMPLE",
    )


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("tests/*", "tests/fixture.py", True),
        ("tests/*", "tests/nested/production.py", False),
        ("tests/**", "tests/nested/fixture.py", True),
        ("**/fixtures/*.txt", "fixtures/demo.txt", True),
        ("**/fixtures/*.txt", "deep/fixtures/demo.txt", True),
        ("tests/*", "Tests/fixture.py", False),
    ],
)
def test_allowlist_path_globs_are_segment_scoped(pattern: str, path: str, expected: bool) -> None:
    rule = AllowlistRule(
        name="scoped", description="synthetic", keywords=("example",), paths=(pattern,)
    )
    kind = "credential"
    result = rule.matches(value="example", file_path=path, line_number=1, secret_type=kind)
    assert result is expected


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> Iterator[GitRepo]:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "00" * 32)
    repository = GitRepo("heimdall-t230-")
    try:
        repository.write("readme", "safe\n")
        repository.commit_all("base")
        yield repository
    finally:
        repository.close()


@pytest.mark.parametrize("scope", ["tree", "staged", "diff", "history"])
def test_contextual_secret_blocks_all_cli_scopes(repo: GitRepo, scope: str) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write("config.py", f'DB_PASSWORD = "{FAKE_PASSWORD}"\n')
    repo.stage("config.py")
    if scope in {"diff", "history"}:
        repo.git("commit", "-qm", "synthetic only")
    args = ["deep-scan" if scope == "history" else "scan", "--ci", "--json", str(repo.root)]
    if scope != "history":
        args.append("--no-allowlist")
    if scope == "staged":
        args.append("--staged")
    if scope == "diff":
        args.extend(["--diff", base])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1, result.output
    assert FAKE_PASSWORD not in result.output
    payload = json.loads(result.stdout)
    assert payload["findings"]


def test_adversarial_regex_parsing_remains_bounded() -> None:
    start = time.monotonic()
    for depth in range(1, 30):
        with pytest.raises(ScanError):
            _compile_safe_regex("(?:" * depth + "abc" + ")" * depth + "?.")
    assert time.monotonic() - start < 2


@pytest.mark.parametrize("pattern", [r"(?!abc).", r"a?b?c?.", r"(abc)?."])
def test_invalid_allowlist_fails_closed_in_cli(repo: GitRepo, pattern: str) -> None:
    repo.write("config.py", f'DB_PASSWORD="{FAKE_PASSWORD}"\n')
    config = repo.root.parent / "external-allowlist.toml"
    config.write_text(
        '[allowlist]\nversion="1"\n[[allowlist.rules]]\nname="e02"\ndescription="synthetic"\n'
        + "patterns=["
        + json.dumps(pattern)
        + ']\npaths=["**"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["scan", "--ci", "--config", str(config), str(repo.root)])
    assert result.exit_code == 2
    assert FAKE_PASSWORD not in result.output


@pytest.mark.parametrize("value", ["None", "false", "getenv(KEY)"])
def test_quoted_literals_are_not_confused_with_expressions(value: str) -> None:
    kind = "credential"
    assert any(m.secret_type == kind for m in find_line_matches(f'PASSWORD="{value}"'))


def test_service_inventory_covers_the_requested_prefixes() -> None:
    assert {prefix for _, prefix in PREFIXES} == {
        "glpat-",
        "AIza",
        "ya29.",
        "npm_",
        "whsec_",
        "dop_v1_",
        "shpat_",
    }


def test_regex_compilation_overflow_is_a_scan_error() -> None:
    with pytest.raises(ScanError, match="configuration"):
        _compile_safe_regex("EXAMPLEa{999999999999999999}")


@pytest.mark.parametrize("nested", [False, True])
def test_single_star_cannot_suppress_a_nested_cli_finding(repo: GitRepo, nested: bool) -> None:
    path = "tests/nested/config.py" if nested else "tests/config.py"
    repo.write(path, f'DB_PASSWORD="{FAKE_PASSWORD}"\n')
    config = repo.root.parent / "external-allowlist.toml"
    config.write_text(
        '[allowlist]\nversion="1"\n[[allowlist.rules]]\nname="e02"\ndescription="synthetic"\n'
        'patterns=["FAKE"]\npaths=["tests/*"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app, ["scan", "--ci", "--json", "--config", str(config), str(repo.root)]
    )
    assert result.exit_code == (1 if nested else 0), result.output
    assert json.loads(result.stdout)["count"] == (1 if nested else 0)
    assert FAKE_PASSWORD not in result.output


def test_invalid_unicode_literal_uses_static_scan_error() -> None:
    with pytest.raises(ScanError, match="^ligne d'analyse non conforme au contrat$"):
        find_signature_matches('PASSWORD="FAKE' + "\ud800" + '42"')


def test_joined_comments_cannot_manufacture_a_sensitive_key() -> None:
    source = 'EXAMPLE="example" # python-example\n' + f'PASSWORD="{FAKE_PASSWORD}"\n'
    engine = SignatureEngine(SnippetHasher(key=b"T" * 32))
    findings = engine.analyser(FileTarget("config.py", source))
    assert [(finding.line, finding.type) for finding in findings] == [(2, "credential")]


@pytest.mark.parametrize("ci", [False, True])
def test_typed_service_allowlist_cannot_erase_credential_view(repo: GitRepo, ci: bool) -> None:
    value = "glpat-" + "EXAMPLE" + "A" * 32
    line = f'DB_PASSWORD="{value}"'
    matches = find_signature_matches(line)
    assert {(match.secret_type, match.value) for match in matches} == {
        ("service_token", value),
        ("credential", value),
    }
    repo.write("config.py", line + "\n")
    config = repo.root.parent / "typed-allowlist.toml"
    config.write_text(
        '[allowlist]\nversion="1"\n[[allowlist.rules]]\nname="service-only"\n'
        'description="synthetic"\npatterns=["glpat-EXAMPLE"]\n'
        'secret_types=["service_token"]\n',
        encoding="utf-8",
    )
    args = ["scan", "--json", "--config", str(config), str(repo.root)]
    if ci:
        args.append("--ci")
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert [finding["type"] for finding in payload["findings"]] == ["credential"]
    assert payload["ignored_count"] == 1
    assert payload["traces"][0]["rule"] == "service-only"
    assert value not in result.output


@pytest.mark.parametrize("identifier", ["npm_packages", "npm_config_registry"])
def test_ordinary_npm_identifiers_are_not_service_tokens(identifier: str) -> None:
    kind = "service_token"
    assert not any(match.secret_type == kind for match in find_signature_matches(identifier))


@pytest.mark.parametrize("length", [15, 16])
def test_npm_minimum_payload_boundary(length: int) -> None:
    value = "npm_" + "A" * length
    matches = find_signature_matches(value)
    assert bool(matches) is (length == 16)


@pytest.mark.parametrize("line", ["pwd=123", "pin=abc"])
def test_very_short_unquoted_values_are_documented_residuals(line: str) -> None:
    assert not tuple(find_line_matches(line))


@pytest.mark.parametrize("value", ["ghijklmnopqrstuvwxyz", "GHIJKLMNOPQRSTUVWXYZ"])
def test_short_tokens_without_three_classes_are_documented_residuals(value: str) -> None:
    assert len(value) == 20
    assert not tuple(find_line_matches(value))


def test_fix_applies_once_for_two_views_after_allowlist_filtering(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = "glpat-" + "A" * 32
    repo.write("config.py", f'DB_PASSWORD="{value}"\n')
    repo.write(".gitignore", "*.bak\n")
    proposals_seen = []

    def review(proposals, *, apply, **kwargs):
        proposals_seen.extend(proposals)
        assert len(proposals_seen) == 1
        proposal = proposals_seen[0]
        apply(proposal)
        return ReviewReport((ReviewOutcome(Choice.VALIDATE, True, 0, proposal),), True)

    monkeypatch.setattr("heimdall.cli.fix.review_proposals", review)
    report, remaining = run_fix(repo.root, interactive=True)
    assert remaining == 0
    assert len(report.outcomes) == 1
    assert value not in (repo.root / "config.py").read_text(encoding="utf-8")
    assert not (repo.root / "config.py.bak").exists()


def test_git_status_discovers_root_from_nested_directory_with_spaces(repo: GitRepo) -> None:
    repo.write("a b/nested/.env", "FAKE_VALUE=x\n")
    repo.stage("a b/nested/.env")
    target = repo.root / "a b/nested/.env"
    assert _get_git_toplevel(target) == repo.root
    assert is_git_tracked(target)


def test_git_discovery_refuses_symlinked_metadata_before_execution(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = repo.root / ".git"
    saved = repo.root.parent / "saved-metadata"
    metadata.rename(saved)
    metadata.symlink_to(saved, target_is_directory=True)
    repo.write(".env", "FAKE_VALUE=x\n")

    def forbidden(*args, **kwargs):
        pytest.fail("symlinked Git metadata must not be executed")

    monkeypatch.setattr("heimdall.vault.atomic.GitAccess.execute", forbidden)
    assert _get_git_toplevel(repo.root / ".env") is None
