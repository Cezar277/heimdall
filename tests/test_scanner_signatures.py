"""Tests des signatures de secrets (#54, sous-tickets #55 à #58).

Le test central est paramétré sur **toutes** les règles du registre : chaque
exemple positif doit être reconnu, chaque exemple négatif doit rester muet.
Les autres tests verrouillent les pièges du ticket :

- une règle est identifiable (id, description, regex, type, exemples) ;
- les faux positifs du corpus T21 ne sont pas signalés ;
- chaque regex reste linéaire sur une ligne de 100 000 caractères (ReDoS) ;
- le moteur branché sur l'interface #53 ne rend jamais la valeur brute.

Toutes les valeurs sont synthétiques : aucune clé réelle, aucun appel réseau.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from heimdall.scanner import (
    DiffTarget,
    FileTarget,
    Finding,
    ScanError,
    Scanner,
    SignatureEngine,
    find_signature_matches,
)
from heimdall.scanner import signatures as registry
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.hashing import KEY_ENV, SnippetHasher, load_local_key
from heimdall.scanner.signatures import FAMILIES, RULES, Rule, rules_for_family

ROOT = Path(__file__).resolve().parents[1]
FINDING_SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(FINDING_SCHEMA)

#: Ligne hostile de la taille demandée par le ticket (100 000 caractères).
HOSTILE_LENGTH = 100_000
#: Marge large : une regex linéaire fait quelques millisecondes, pas 2 s.
REDOS_BUDGET_SECONDS = 2.0


@pytest.fixture(autouse=True)
def _fixed_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clé fixe en mémoire : aucun test n'écrit dans le HOME ni le dépôt."""
    monkeypatch.setenv(KEY_ENV, "42" * 32)


# --- Le registre et ses exemples -------------------------------------------


def test_registry_has_one_file_per_family_and_unique_rules() -> None:
    """Quatre familles (#55 à #58), un fichier chacune, des ids uniques."""
    assert [name for name, _rules in FAMILIES] == [
        "aws_cloud",
        "stripe_slack",
        "github_jwt",
        "pem",
    ]
    assert len(RULES) == sum(len(rules) for _name, rules in FAMILIES)
    identifiers = [rule.id for rule in RULES]
    assert len(identifiers) == len(set(identifiers))
    assert all(rule.id == rule.name for rule in RULES)
    assert all(rule.type == rule.secret_type for rule in RULES)
    assert rules_for_family("pem") == (registry.RULES[-1],)
    with pytest.raises(KeyError):
        rules_for_family("inconnue")


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_each_rule_declares_its_contract(rule: Rule) -> None:
    """Chaque règle porte id, description, regex, type et deux exemples."""
    assert rule.id
    assert rule.description
    assert rule.regex
    assert rule.secret_type
    assert rule.positive_example
    assert rule.negative_example
    assert "value" in rule.pattern.groupindex


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_positive_example_is_recognized(rule: Rule) -> None:
    """L'exemple positif est reconnu et sa valeur n'est pas vide."""
    matches = rule.matches(rule.positive_example)
    assert matches
    assert all(match.group("value") for match in matches)


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_negative_example_is_ignored(rule: Rule) -> None:
    """L'exemple négatif ne produit aucune correspondance."""
    assert rule.matches(rule.negative_example) == ()


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_positive_example_is_found_by_the_public_matcher(rule: Rule) -> None:
    """Le matcher public rend la règle et la valeur de l'exemple positif."""
    matches = find_signature_matches(rule.positive_example)
    assert any(match.rule_id == rule.id and match.value for match in matches)
    assert all(match.type == match.secret_type for match in matches)


def test_keywords_are_a_context_filter() -> None:
    """Un mot-clé déclaré filtre le contexte sans remplacer l'ancrage."""
    rule = rules_for_family("aws_cloud")[1]
    assert rule.id == "aws_secret_access_key"
    assert rule.keywords
    value_only = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert rule.matches(value_only) == ()
    assert rule.matches(f'aws_secret_access_key = "{value_only}"')


def test_identical_value_is_deduplicated_but_distinct_values_are_not() -> None:
    """Deux valeurs distinctes du même type restent deux candidats."""
    aws_a = "AKIA" + "A" * 16
    aws_b = "AKIA" + "B" * 16
    assert len(find_signature_matches(f'"{aws_a}" "{aws_a}"')) == 1
    matches = find_signature_matches(f'"{aws_a}" "{aws_b}"')
    assert len(matches) == 2
    assert {match.value for match in matches} == {aws_a, aws_b}


def test_known_false_positives_are_not_reported() -> None:
    """Les non-leaks du corpus T21 ne déclenchent aucune signature."""
    lines = [
        'UUID = "550e8400-e29b-41d4-a716-446655440000"',
        'SHA256 = "' + "a" * 64 + '"',
        'COMMIT = "' + "b" * 40 + '"',
        'INTEGRITY = "sha512-' + "A" * 64 + '"',
        'EXAMPLE = "example"',
        'PASSWORD = "changeme"',
        'API_KEY = "your_key_here"',
        'IMAGE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"',
        'MOCK = "MOCK_TOKEN_FOR_TESTS_ONLY"',
        'SHORT_AWS = "AKIA1234"',
        'SHORT_PAT = "ghp_"',
        'TRUNCATED_JWT = "eyJhbGciOiJIUzI1NiJ9.e30"',
        'PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----"',
        'CERTIFICATE = "-----BEGIN CERTIFICATE-----"',
    ]
    for line in lines:
        assert find_signature_matches(line) == (), line


def test_rule_validation_refuses_a_broken_example() -> None:
    """Le registre refuse une règle dont l'exemple ment (fail-closed)."""
    with pytest.raises(ValueError, match="positif"):
        Rule(
            id="broken_positive",
            description="exemple positif faux",
            regex=r"(?P<value>AKIA[0-9A-Z]{16})",
            secret_type="aws",
            positive_example="AKIA1234",
            negative_example="rien",
        )
    with pytest.raises(ValueError, match="négatif"):
        Rule(
            id="broken_negative",
            description="exemple négatif faux",
            regex=r"(?P<value>AKIA[0-9A-Z]{16})",
            secret_type="aws",
            positive_example="AKIAIOSFODNN7EXAMPLE",
            negative_example="AKIAIOSFODNN7EXAMPLE",
        )


def test_rule_validation_refuses_broken_patterns_and_metadata() -> None:
    """Regex invalide, groupe absent et registre incohérent sont refusés."""
    base: dict[str, object] = {
        "id": "valid_rule",
        "description": "règle valide",
        "regex": r"(?P<value>AKIA[0-9A-Z]{16})",
        "secret_type": "aws",
        "positive_example": "AKIAIOSFODNN7EXAMPLE",
        "negative_example": "rien",
    }
    with pytest.raises(ValueError, match="regex invalide"):
        Rule(**{**base, "regex": "("})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="groupe nommé"):
        Rule(**{**base, "regex": r"AKIA[0-9A-Z]{16}"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="registre de signatures vide"):
        registry.validate_rules(())
    duplicate = Rule(**base)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="règle dupliquée"):
        registry.validate_rules((duplicate, duplicate))


def test_matches_refuses_a_non_string_line() -> None:
    """Une entrée qui n'est pas une ligne ne produit jamais de correspondance."""
    rule = rules_for_family("aws_cloud")[0]
    assert rule.matches(42) == ()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", "Pas-Un-Id", "id de règle"),
        ("id", "a" * 65, "id de règle"),
        ("secret_type", "Type", "type de Finding"),
        ("description", "   ", "description"),
        ("regex", "", "regex"),
        ("positive_example", "", "positif vide"),
        ("negative_example", "", "négatif vide"),
        ("keywords", ("",), "mot-clé"),
    ],
)
def test_rule_validation_refuses_invalid_metadata(field: str, value: object, message: str) -> None:
    """Les métadonnées invalides sont refusées à la construction."""
    values: dict[str, object] = {
        "id": "valid_rule",
        "description": "règle valide",
        "regex": r"(?P<value>AKIA[0-9A-Z]{16})",
        "secret_type": "aws",
        "positive_example": "AKIAIOSFODNN7EXAMPLE",
        "negative_example": "rien",
        "keywords": (),
    }
    values[field] = value
    with pytest.raises(ValueError, match=message):
        Rule(**values)  # type: ignore[arg-type]


# --- Anti-ReDoS -------------------------------------------------------------


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_each_rule_is_linear_on_a_100k_hostile_line(rule: Rule) -> None:
    """Chaque règle reste rapide sur une ligne piégée de 100 000 caractères.

    Deux formes couvrent les deux pièges classiques : un remplissage sans
    correspondance, et un préfixe qui force le moteur à backtracker sur une
    borne ouverte (PEM). Aucun quantificateur imbriqué n'est utilisé.
    """
    payloads = (
        "A" * HOSTILE_LENGTH,
        "-----BEGIN " + "A" * (HOSTILE_LENGTH - 11),
    )
    for payload in payloads:
        started = time.perf_counter()
        matches = rule.matches(payload)
        elapsed = time.perf_counter() - started
        assert isinstance(matches, tuple)
        assert elapsed < REDOS_BUDGET_SECONDS, (rule.id, elapsed)


# --- Moteur branché sur l'interface #53 ------------------------------------


def _findings(target: FileTarget | DiffTarget) -> list[Finding]:
    return Scanner(SignatureEngine()).scan(target)


def test_engine_produces_contract_findings_without_raw_values() -> None:
    """Un Finding est conforme au schéma #14 et ne contient jamais la valeur."""
    rule = rules_for_family("aws_cloud")[0]
    findings = _findings(FileTarget(path="src/app.py", text=rule.positive_example))
    assert len(findings) == 1
    finding = findings[0]
    VALIDATOR.validate(finding.as_dict())
    assert finding.file == "src/app.py"
    assert finding.line == 1
    assert finding.type == "aws"
    assert finding.status == "detecte"
    assert finding.source == "regex"
    serialized = json.dumps(finding.as_dict())
    assert rule.positive_example.split('"')[1] not in serialized
    assert rule.positive_example.split('"')[1] not in repr(finding)


def test_engine_keeps_diff_line_numbers() -> None:
    """Le moteur analyse les lignes ajoutées et conserve leur numéro réel."""
    rule = rules_for_family("stripe_slack")[0]
    target = DiffTarget(
        path="src/payment.py",
        lines=((12, "pass"), (15, rule.positive_example)),
    )
    findings = _findings(target)
    assert [(finding.file, finding.line, finding.type) for finding in findings] == [
        ("src/payment.py", 15, "stripe")
    ]


def test_engine_reports_two_distinct_values_on_one_line() -> None:
    """Deux secrets distincts sur la même ligne ne fusionnent pas."""
    aws_a = "AKIA" + "A" * 16
    aws_b = "AKIA" + "B" * 16
    findings = _findings(FileTarget(path="config.py", text=f'"{aws_a}" "{aws_b}"'))
    assert len(findings) == 2
    assert len({finding.snippet_hash for finding in findings}) == 2


def test_engine_deduplicates_an_identical_value() -> None:
    """Une valeur strictement identique n'est produite qu'une fois par ligne."""
    aws = "AKIA" + "C" * 16
    findings = _findings(FileTarget(path="config.py", text=f'"{aws}" "{aws}"'))
    assert len(findings) == 1


def test_engine_detects_a_secret_split_across_two_lines() -> None:
    """Un secret coupé par un retour à la ligne est détecté (fenêtre bornée)."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = _findings(
        FileTarget(path="config.py", text=f'aws_secret_access_key =\n"{secret}"\n')
    )
    assert [(finding.line, finding.type) for finding in findings] == [(1, "aws")]


def test_engine_does_not_join_beyond_the_documented_window() -> None:
    """Au-delà de 4 Kio, la jointure n'est pas faite : limite documentée."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    text = "aws_secret_access_key = " + "x" * 5_000 + f'\n"{secret}"\n'
    assert _findings(FileTarget(path="config.py", text=text)) == []


def test_engine_scan_is_deterministic() -> None:
    """Deux scans de la même cible rendent la même liste, dans le même ordre."""
    text = "\n".join(rule.positive_example for rule in RULES)
    target = FileTarget(path="all.txt", text=text)
    first = _findings(target)
    second = _findings(target)
    assert first == second
    assert first == sorted(first, key=lambda item: (item.line, item.type, item.snippet_hash))


# --- Entropie et empreinte --------------------------------------------------


def test_shannon_entropy_bounds_and_values() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert shannon_entropy(b"ab") == 1.0
    assert 0.0 < shannon_entropy(bytes(range(256))) <= 8.0


def test_hmac_is_stable_and_never_reversible() -> None:
    """L'empreinte est stable, distincte par valeur et ne contient pas la valeur."""
    hasher = SnippetHasher(b"k" * 32)
    first = hasher.hash("SYNTHETIC_VALUE")
    assert first == hasher.hash("SYNTHETIC_VALUE")
    assert first != hasher.hash("SYNTHETIC_VALUE_2")
    assert len(first) == 64
    assert "SYNTHETIC_VALUE" not in first


def test_local_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_ENV, "ab" * 32)
    assert load_local_key() == bytes.fromhex("ab" * 32)
    with pytest.raises(ScanError):
        SnippetHasher(b"short")


def test_local_key_is_created_outside_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", str(tmp_path / "state" / "key"))
    key = load_local_key()
    assert len(key) == 32
    assert (tmp_path / "state" / "key").is_file()
    assert load_local_key() == key
