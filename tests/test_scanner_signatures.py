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

import importlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Final

import pytest
from jsonschema import Draft202012Validator

from heimdall.scanner import (
    DiffTarget,
    FileTarget,
    Finding,
    ScanError,
    Scanner,
    SignatureEngine,
    hashing,
)
from heimdall.scanner import signatures as registry
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.hashing import (
    KEY_ENV,
    KEY_FILE_ENV,
    SnippetHasher,
    load_local_key,
)
from heimdall.scanner.signatures import (
    FAMILIES,
    RULES,
    Rule,
    find_signature_matches,
    rules_for_family,
)
from heimdall.scanner.signatures.model import ALLOWED_SECRET_TYPES

ROOT = Path(__file__).resolve().parents[1]
FINDING_SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(FINDING_SCHEMA)

#: Ligne hostile de la taille demandée par le ticket (100 000 caractères).
HOSTILE_LENGTH = 100_000
#: Marge large : une regex linéaire fait quelques millisecondes, pas 2 s.
REDOS_BUDGET_SECONDS = 2.0
#: `os.getuid` n'existe pas hors POSIX : le test qui s'appuie sur la lecture
#: seule d'un répertoire est neutralisé sous root (où le bit n'oppose rien).
_IS_ROOT: Final[bool] = getattr(os, "getuid", lambda: -1)() == 0


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


#: Les trois noms de paramètre AWS acceptés, plus leurs variantes de casse.
#: Ils correspondent **exactement** aux mots-clés déclarés par la règle : un
#: mot-clé sans effet dans le motif serait une couverture annoncée plus
#: large que le code (faux sentiment de sécurité, puis faux négatif).
_AWS_SECRET_PARAMETER_NAMES: Final[tuple[str, ...]] = (
    "aws_secret_access_key",
    "aws_secret_key",
    "secret_access_key",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "Secret_Access_Key",
)


@pytest.mark.parametrize("parameter", _AWS_SECRET_PARAMETER_NAMES)
def test_every_declared_aws_parameter_name_is_really_covered(parameter: str) -> None:
    """Chaque nom de paramètre annoncé est détecté (verrou anti-régression).

    Régression corrigée : les mots-clés annonçaient trois noms alors que la
    regex n'en reconnaissait qu'un. Les deux autres ne donnaient **aucune**
    correspondance : un secret manqué, pas une fuite.
    """
    rule = rules_for_family("aws_cloud")[1]
    assert rule.id == "aws_secret_access_key"
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    matches = rule.matches(f'{parameter} = "{value}"')
    assert len(matches) == 1
    assert matches[0].group("value") == value


@pytest.mark.parametrize(
    "template",
    [
        '{name} = "{value}"',
        "{name}={value}",
        "{name}: {value}",
        '"{name}": "{value}"',
        '"{name}" : "{value}"',
        "os.environ['{name}'] = '{value}'",
    ],
)
def test_aws_secret_is_detected_in_every_common_assignment_form(template: str) -> None:
    """Le nom du paramètre est reconnu quelle que soit la forme d'écriture.

    Les fichiers JSON et `.env` sont les formes les plus fréquentes en
    dépôt : un guillemet fermant après le nom ne doit pas masquer la clé.
    """
    rule = rules_for_family("aws_cloud")[1]
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    matches = rule.matches(template.format(name="aws_secret_access_key", value=value))
    assert len(matches) == 1
    assert matches[0].group("value") == value


@pytest.mark.parametrize(
    "parameter",
    [
        "aws_secret_access_keys",  # pluriel
        "aws_secret_access_key_hash",  # suffixe
        "aws_secret_key_rotation",  # suffixe
        "secret_access_keys",  # pluriel
        "access_key_secret",  # nom différent
    ],
)
def test_a_parameter_name_outside_the_announced_scope_stays_silent(
    parameter: str,
) -> None:
    """Hors des trois noms annoncés, la règle reste muette (pas de faux positif)."""
    rule = rules_for_family("aws_cloud")[1]
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert rule.matches(f'{parameter} = "{value}"') == ()
    assert rule.matches(f'"{parameter}": "{value}"') == ()


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


def test_validate_rules_refuses_a_secret_type_outside_the_closed_set() -> None:
    """Un type de Finding hors de l'ensemble documenté est refusé.

    ``validate_rules`` annonce ce contrôle : sans lui, une règle portant un
    type que rien ne documente produirait un Finding dont le ``type`` est
    inexpliqué. Le refus est fail-closed à l'import du registre.
    """
    hors_ensemble = Rule(
        id="regle_hors_ensemble",
        description="règle dont le type n'est pas documenté",
        regex=r"(?P<value>AKIA[0-9A-Z]{16})",
        secret_type="gcp",
        positive_example="AKIAIOSFODNN7EXAMPLE",
        negative_example="rien",
    )
    with pytest.raises(ValueError, match="type de Finding hors ensemble"):
        registry.validate_rules((hors_ensemble,))


def test_every_registered_secret_type_is_in_the_closed_set() -> None:
    """Le registre livré ne produit que des types documentés."""
    assert {rule.secret_type for rule in RULES} == set(ALLOWED_SECRET_TYPES)


def test_matches_refuses_a_non_string_line() -> None:
    """Une entrée qui n'est pas une ligne échoue au lieu d'être ignorée.

    L'interface #53 refuse déjà toute ligne non textuelle
    (``interface._check_lines``) : cette garde de défense ne doit pas
    dégrader un « miss » silencieux, qui ferait passer une ligne jamais
    analysée pour une ligne propre.
    """
    rule = rules_for_family("aws_cloud")[0]
    with pytest.raises(ScanError):
        rule.matches(42)  # type: ignore[arg-type]


def test_find_signature_matches_refuses_a_non_string_line() -> None:
    """Le matcher public applique la même garde fail-closed."""
    with pytest.raises(ScanError):
        find_signature_matches(None)  # type: ignore[arg-type]


# --- Surface d'export : une seule politique, vérifiée ----------------------


def test_the_raw_value_matcher_is_not_reexported_by_the_scanner_package() -> None:
    """La surface sensible n'est exportée qu'à un seul endroit.

    ``find_signature_matches`` rend la **valeur brute** des candidats : elle
    est réservée au moteur et aux tests. La réexportation par
    ``heimdall.scanner`` élargissait cette surface au niveau le plus visible
    du paquet, alors que le registre la tient hors de son ``__all__``. Ce
    test verrouille une **seule** politique d'export : le matcher n'est
    accessible que par un import explicite de ``heimdall.scanner.signatures``.

    L'absence de l'attribut au niveau du paquet est ce qui fait échouer
    ``from heimdall.scanner import find_signature_matches``.
    """
    scanner_module = importlib.import_module("heimdall.scanner")
    assert "find_signature_matches" not in scanner_module.__all__
    assert not hasattr(scanner_module, "find_signature_matches")
    assert "find_signature_matches" not in registry.__all__
    assert registry.find_signature_matches is find_signature_matches


def test_the_scanner_package_still_exports_its_documented_surface() -> None:
    """La suppression de la réexportation n'ampute pas la surface publique.

    Chaque nom annoncé par ``__all__`` doit rester un attribut réel du
    paquet : retirer l'export sensible ne doit pas casser les importations
    des appelants légitimes.
    """
    scanner_module = importlib.import_module("heimdall.scanner")
    assert scanner_module.__all__
    assert all(hasattr(scanner_module, name) for name in scanner_module.__all__)
    assert "SignatureEngine" in scanner_module.__all__
    assert "find_candidates" in scanner_module.__all__


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


#: Préfixe réellement ancré de chaque règle, pour un payload hostile qui
#: traverse le motif au lieu d'être rejeté dès le premier caractère.
_ANCHORED_HOSTILE_PREFIX: dict[str, str] = {
    "aws_access_key_id": "AKIA",
    "aws_secret_access_key": "aws_secret_access_key = ",
    "stripe_secret_key": "sk_live_",
    "slack_token": "xoxb-",
    "slack_app_token": "xapp-",
    "slack_rotating_token": "xoxe.",
    "github_classic_pat": "ghp_",
    "github_fine_grained_pat": "github_pat_",
    "jwt": "eyJ",
    "pem_private_key": "-----BEGIN ",
}


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_each_rule_is_linear_on_an_anchored_100k_line(rule: Rule) -> None:
    """La borne tient même quand le payload commence par l'ancre de la règle.

    Les deux payloads génériques ci-dessus sont rejetés dès le premier
    caractère par neuf règles sur dix ; ce test exerce réellement le parcours
    de la regex (préfixe valide puis 100 000 caractères de charge).
    """
    prefix = _ANCHORED_HOSTILE_PREFIX[rule.id]
    payload = prefix + "A" * (HOSTILE_LENGTH - len(prefix))
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


def test_signature_match_repr_never_contains_the_candidate() -> None:
    """Miroir de l'invariant Finding : un match journalisé reste masqué."""
    value = "AKIA" + "Z" * 16
    match = find_signature_matches(value)[0]
    assert match.value == value
    assert value not in repr(match)
    assert value not in str(match)


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_rule_match_repr_never_contains_the_candidate(rule: Rule) -> None:
    """Le wrapper de ``re.Match`` masque aussi le candidat dans son ``repr``."""
    matches = rule.matches(rule.positive_example)
    assert matches
    value = matches[0].group("value")
    assert value
    assert value not in repr(matches[0])
    assert value not in str(matches[0])


def test_rule_match_delegates_the_re_match_api() -> None:
    """Le wrapper masqué reste utilisable comme un ``re.Match`` par le moteur."""
    rule = rules_for_family("aws_cloud")[0]
    line = rule.positive_example
    match = rule.matches(line)[0]
    value = match.group("value")
    assert value
    assert match.group(0) == value
    assert match["value"] == value
    assert match.groups() == (value,)
    assert match.groupdict() == {"value": value}
    assert match.start() == line.index(value)
    assert match.end() == match.start() + len(value)
    assert match.span("value") == (match.start(), match.end())
    assert match.expand(r"\g<value>") == value
    assert match.re is rule.pattern
    assert match.string == line
    assert match.pos == 0
    assert match.endpos == len(line)
    assert match.lastindex == 1
    assert match.lastgroup == "value"


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


class _ConstantHasher(SnippetHasher):
    """Hacheur de test : rend toujours la même empreinte, quelle que soit la valeur."""

    def __init__(self) -> None:
        super().__init__(b"k" * 32)

    def hash(self, candidate: str) -> str:
        del candidate
        return "0" * 64


def test_engine_deduplicates_on_the_fingerprint_and_keeps_no_raw_value() -> None:
    """La clé de déduplication est l'empreinte, jamais la valeur brute.

    Un hacheur constant le prouve : deux valeurs distinctes partagent la
    même empreinte, donc le moteur les fusionne. Avec une clé de
    déduplication portant la valeur brute, il rendrait deux Findings. La
    valeur candidate n'est donc conservée que le temps de son hachage,
    jamais dans l'ensemble de déduplication du moteur.
    """
    aws_a = "AKIA" + "F" * 16
    aws_b = "AKIA" + "G" * 16
    engine = SignatureEngine(_ConstantHasher())
    findings = engine.analyser(FileTarget(path="config.py", text=f'"{aws_a}" "{aws_b}"'))
    assert len(findings) == 1
    assert findings[0].snippet_hash == "0" * 64


def test_engine_keeps_no_raw_value_after_the_scan() -> None:
    """Ni le moteur ni ses Findings ne conservent la valeur brute."""
    aws = "AKIA" + "H" * 16
    engine = SignatureEngine()
    findings = engine.analyser(FileTarget(path="config.py", text=f'"{aws}"'))
    assert len(findings) == 1
    assert aws not in repr(findings)
    assert aws not in repr(engine)
    assert aws not in findings[0].snippet_hash


def test_engine_detects_a_secret_split_across_two_lines() -> None:
    """Un secret coupé par un retour à la ligne est détecté (fenêtre bornée)."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = _findings(
        FileTarget(path="config.py", text=f'aws_secret_access_key =\n"{secret}"\n')
    )
    assert [(finding.line, finding.type) for finding in findings] == [(1, "aws")]


def test_engine_joins_consecutive_diff_lines() -> None:
    """Deux lignes ajoutées contiguës d'un diff sont jointes normalement."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    target = DiffTarget(
        path="config.py",
        lines=((12, "aws_secret_access_key ="), (13, f'"{secret}"')),
    )
    assert [(finding.line, finding.type) for finding in _findings(target)] == [(12, "aws")]


def test_engine_does_not_join_non_consecutive_diff_lines() -> None:
    """Une ligne ajoutée isolée n'est jamais jointe à une ligne distante.

    ``DiffTarget`` ne contient que les lignes ajoutées : joindre les entrées
    12 et 15 fabriquerait une chaîne absente de tout fichier et attribuerait
    un faux Finding à la ligne 12.
    """
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    target = DiffTarget(
        path="config.py",
        lines=((12, "aws_secret_access_key ="), (15, f'"{secret}"')),
    )
    assert _findings(target) == []


def test_engine_does_not_join_beyond_the_documented_window() -> None:
    """Au-delà de 4 Kio, la jointure n'est pas faite : limite documentée."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    text = "aws_secret_access_key = " + "x" * 5_000 + f'\n"{secret}"\n'
    assert _findings(FileTarget(path="config.py", text=text)) == []


def test_engine_measures_the_window_in_utf8_bytes() -> None:
    """La fenêtre de 4 Kio est mesurée en octets, pas en caractères.

    La ligne de tête reste sous 4096 caractères, mais dépasse 4096 octets en
    UTF-8 : la jointure doit être refusée, sinon la borne documentée serait
    élargie par les caractères multi-octets.
    """
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    prefix = "aws_secret_access_key = "
    padding = "é" * 2_040
    text = f'{prefix}{padding}\n"{secret}"\n'
    assert len(prefix) + len(padding) + len(secret) + 2 <= 4096  # caractères
    assert len((prefix + padding + secret + '""').encode("utf-8")) > 4096  # octets
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


def _write_key_file(path: Path, data: bytes = b"k" * 32, mode: int = 0o600) -> Path:
    """Crée une clé sur disque pour les tests de refus (jamais dans le HOME)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_key_file_env_requires_an_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(KEY_FILE_ENV, "relative/state/key")
    with pytest.raises(ScanError):
        load_local_key()


def test_key_file_env_refuses_parent_segments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "state" / ".." / "key"))
    with pytest.raises(ScanError):
        load_local_key()


@pytest.mark.parametrize("encoded", ["zz" * 32, "ab" * 31, "ab" * 33, "abc"])
def test_environment_key_requires_exactly_32_bytes_of_hex(
    encoded: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, encoded)
    with pytest.raises(ScanError):
        load_local_key()


@pytest.mark.parametrize(
    "encoded",
    [
        "41" * 31 + "4 1",  # espace au milieu
        "41 " + "41" * 31,  # espace en tête
        "41" * 32 + "\n",  # saut de ligne final
        "41" * 31 + "\n41",  # saut de ligne au milieu
        "4 1" * 16,  # une espace tous les deux octets
    ],
)
def test_environment_key_refuses_separators(encoded: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Une clé d'environnement séparée est refusée fail-closed.

    ``bytes.fromhex`` ignore les espaces et les sauts de ligne : sans le
    contrôle de format, une faute de frappe (``"41 42 …"``) produirait une
    clé acceptée, alors que l'opérateur croyait en donner une autre. Le
    refus porte le message statique ``_KEY_ERROR``, jamais la valeur.
    """
    monkeypatch.setenv(KEY_ENV, encoded)
    with pytest.raises(ScanError) as excinfo:
        load_local_key()
    assert str(excinfo.value) == "clé d'empreinte locale invalide"


def test_environment_key_accepts_the_exact_hexadecimal_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le format strict accepte les 64 caractères hexadécimaux, majuscules inclus."""
    monkeypatch.setenv(KEY_ENV, "AB" * 32)
    assert load_local_key() == bytes.fromhex("AB" * 32)


def test_key_file_readable_by_others_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_file = _write_key_file(tmp_path / "state" / "key", mode=0o644)
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_file_with_another_owner_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_file = _write_key_file(tmp_path / "state" / "key")
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    # Isole le contrôle du fichier : le parent est déjà privé et appartient à
    # l'utilisateur, seul le propriétaire simulé du fichier diffère.
    monkeypatch.setattr(hashing, "_harden_parent", lambda parent: parent)
    monkeypatch.setattr(hashing, "_current_uid", lambda: os.getuid() + 1)
    with pytest.raises(ScanError):
        load_local_key()


def test_key_parent_symlink_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(KEY_FILE_ENV, str(link / "key"))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_intermediate_symlink_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(KEY_FILE_ENV, str(link / "nested" / "key"))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_file_symlink_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV)
    target = _write_key_file(tmp_path / "real-key")
    link = tmp_path / "state" / "key"
    link.parent.mkdir(mode=0o700, parents=True)
    link.symlink_to(target)
    monkeypatch.setenv(KEY_FILE_ENV, str(link))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_file_with_a_wrong_length_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_file = _write_key_file(tmp_path / "state" / "key", data=b"k" * 31)
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_parent_that_is_a_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    parent = tmp_path / "state"
    parent.write_text("pas un répertoire", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(parent / "key"))
    with pytest.raises(ScanError):
        load_local_key()


def test_local_key_race_reads_the_key_created_by_another_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Course ``FileExistsError`` : le second ``_read_key`` lit la clé gagnante."""
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "state" / "key"))
    expected = b"r" * 32
    calls: list[Path] = []

    def fake_read(path: Path) -> bytes:
        calls.append(path)
        if len(calls) == 1:
            raise ScanError("absente")
        return expected

    monkeypatch.setattr(hashing, "_read_key", fake_read)
    monkeypatch.setattr(hashing, "_create_key", lambda path: None)
    assert load_local_key() == expected
    assert len(calls) == 2


def test_create_key_refuses_a_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state" / "key"
    path.parent.mkdir(mode=0o700, parents=True)

    def partial_write(descriptor: int, data: bytes) -> int:
        del descriptor, data
        return 0

    monkeypatch.setattr(hashing.os, "write", partial_write)
    with pytest.raises(ScanError):
        hashing._create_key(path)
    assert not path.exists()


def test_existing_parent_permissions_are_hardened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    parent = tmp_path / "state"
    parent.mkdir()
    parent.chmod(0o755)
    monkeypatch.setenv(KEY_FILE_ENV, str(parent / "key"))
    assert len(load_local_key()) == 32
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700


def test_xdg_data_home_default_location_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    key = load_local_key()
    key_file = tmp_path / "heimdall" / "snippet-hmac.key"
    assert key_file.is_file()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_file.parent.stat().st_mode) == 0o700
    assert load_local_key() == key


def test_ci_scan_with_an_exported_key_writes_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """En CI, une clé exportée évite toute écriture et stabilise les empreintes.

    Sans ``HEIMDALL_SNIPPET_HMAC_KEY``, le premier scan crée
    ``$XDG_DATA_HOME/heimdall/snippet-hmac.key`` : sur un runner éphémère en
    lecture seule, le scan échoue ; sur un runner inscriptible, la clé est
    régénérée à chaque run et les ``snippet_hash`` ne sont plus stables
    d'un run à l'autre. La CI exporte donc la clé (64 caractères
    hexadécimaux, 32 octets) : aucun fichier n'est écrit, et l'empreinte
    est reproductible.
    """
    monkeypatch.setenv(KEY_ENV, "42" * 32)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    xdg.chmod(0o500)  # Lecture seule : une écriture y échouerait.
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    try:
        findings = _findings(
            FileTarget(path="config.json", text=f'"aws_secret_access_key": "{value}"')
        )
        assert [(finding.line, finding.type) for finding in findings] == [(1, "aws")]
        # Aucun fichier créé : le répertoire est resté vide.
        assert list(xdg.iterdir()) == []
        # Empreinte stable, reproductible avec la seule clé exportée.
        expected = SnippetHasher(bytes.fromhex("42" * 32)).hash(value)
        assert findings[0].snippet_hash == expected
    finally:
        xdg.chmod(0o700)


@pytest.mark.skipif(
    _IS_ROOT,
    reason="root : la lecture seule d'un répertoire n'est pas opposable",
)
def test_scan_without_any_usable_key_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ni clé exportée ni répertoire inscriptible : le scan échoue.

    Le comportement fail-closed est **conservé** : aucune clé éphémère ne
    masque une panne, car une clé régénérée à chaque run produirait des
    empreintes instables sans que l'opérateur ne voie d'erreur.
    """
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    xdg.chmod(0o500)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    try:
        with pytest.raises(ScanError):
            _findings(FileTarget(path="config.json", text=f'"aws_secret_access_key": "{value}"'))
    finally:
        xdg.chmod(0o700)


def test_xdg_data_home_refuses_parent_segments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "state" / ".."))
    with pytest.raises(ScanError):
        load_local_key()


def test_key_parent_with_another_owner_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv(KEY_FILE_ENV, str(parent / "key"))
    monkeypatch.setattr(hashing, "_current_uid", lambda: os.getuid() + 1)
    with pytest.raises(ScanError):
        load_local_key()


def test_world_writable_parent_is_refused_without_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un répertoire partagé comme /tmp n'est jamais chmodé par le scanner."""
    monkeypatch.delenv(KEY_ENV)
    parent = tmp_path / "state"
    parent.mkdir()
    parent.chmod(0o777)
    monkeypatch.setenv(KEY_FILE_ENV, str(parent / "key"))
    with pytest.raises(ScanError):
        load_local_key()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o777


def test_key_parent_whose_mode_cannot_be_hardened_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    parent = tmp_path / "state"
    parent.mkdir()
    parent.chmod(0o755)
    monkeypatch.setenv(KEY_FILE_ENV, str(parent / "key"))
    monkeypatch.setattr(hashing.os, "chmod", lambda *args, **kwargs: None)
    with pytest.raises(ScanError):
        load_local_key()


def test_read_key_converts_oserror_to_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = _write_key_file(tmp_path / "state" / "key")

    def failing_fstat(descriptor: int) -> os.stat_result:
        del descriptor
        raise OSError("panne simulée")

    monkeypatch.setattr(hashing.os, "fstat", failing_fstat)
    with pytest.raises(ScanError):
        hashing._read_key(key_file)


def test_read_key_refuses_a_short_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = _write_key_file(tmp_path / "state" / "key")
    monkeypatch.setattr(hashing.os, "read", lambda descriptor, size: b"court")
    with pytest.raises(ScanError):
        hashing._read_key(key_file)


def test_create_key_converts_open_oserror_to_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state" / "key"
    path.parent.mkdir(mode=0o700, parents=True)

    def failing_open(*args: object, **kwargs: object) -> int:
        del args, kwargs
        raise PermissionError("refus simulé")

    monkeypatch.setattr(hashing.os, "open", failing_open)
    with pytest.raises(ScanError):
        hashing._create_key(path)


def test_create_key_returns_none_when_the_file_already_exists(tmp_path: Path) -> None:
    path = _write_key_file(tmp_path / "state" / "key")
    assert hashing._create_key(path) is None


def test_create_key_works_when_fchmod_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state" / "key"
    path.parent.mkdir(mode=0o700, parents=True)
    monkeypatch.setattr(hashing.os, "fchmod", None)
    key = hashing._create_key(path)
    assert key is not None
    assert len(key) == 32
    assert path.is_file()


def test_create_key_removes_a_file_with_an_unexpected_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state" / "key"
    path.parent.mkdir(mode=0o700, parents=True)

    class FakeStat:
        st_size = 0

    monkeypatch.setattr(hashing.os, "fstat", lambda descriptor: FakeStat())
    with pytest.raises(ScanError):
        hashing._create_key(path)
    assert not path.exists()
