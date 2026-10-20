"""T53 : interface du scanner et sortie Finding (#53).

Le test central du ticket est ``test_finding_serializes_to_the_contract`` :
un ``Finding`` sérialisé doit valider contre le JSON Schema de #14
(``schemas/finding.schema.json``). Les autres tests verrouillent deux
propriétés :

- le code est **au moins aussi strict** que le schéma (anti-dérive) ;
- aucune valeur de secret ne sort dans un Finding ni dans un message
  d'erreur (invariant 8).

Les valeurs employées sont synthétiques : aucun secret réel n'entre dans le
dépôt.
"""

import dataclasses
import json
import math
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import heimdall.scanner
import heimdall.scanner.detect
from heimdall.scanner import (
    FINDING_FIELDS,
    DiffTarget,
    FileTarget,
    Finding,
    InvalidFinding,
    InvalidTarget,
    ScanError,
    Scanner,
)
from heimdall.scanner import finding as finding_module

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

# Empreinte synthétique : 64 caractères hexadécimaux, sans valeur de secret.
FAKE_HASH = "a" * 64

BASE: dict[str, object] = {
    "file": "config/app.py",
    "line": 12,
    "type": "api_key",
    "entropy": 4.25,
    "snippet_hash": FAKE_HASH,
    "status": "detecte",
    "source": "regex",
}


def _finding(**overrides: object) -> Finding:
    values = dict(BASE)
    values.update(overrides)
    return Finding.from_dict(values)


def _schema_accepts(payload: dict[str, object]) -> bool:
    return VALIDATOR.is_valid(payload)


def _code_accepts(payload: dict[str, object]) -> bool:
    try:
        Finding.from_dict(payload)
    except InvalidFinding:
        return False
    return True


# --- Test central du ticket : sérialisation validée par le JSON Schema ---


def test_finding_serializes_to_the_contract():
    """Un Finding sérialisé valide contre le schéma #14 (draft 2020-12)."""
    finding = _finding()
    payload = finding.as_dict()

    VALIDATOR.validate(payload)
    assert set(payload) == set(SCHEMA["properties"])
    assert set(payload) == set(SCHEMA["required"])
    # La forme sérialisée est du JSON strict : ni NaN, ni infinity.
    assert json.loads(json.dumps(payload)) == payload


def test_finding_fields_match_the_schema_exactly():
    """Aucun champ surnuméraire, aucun champ manquant (anti-dérive #14)."""
    fields = tuple(field.name for field in dataclasses.fields(Finding))
    assert fields == FINDING_FIELDS
    assert set(fields) == set(SCHEMA["properties"])
    assert list(SCHEMA["required"]) == list(FINDING_FIELDS)


def test_finding_round_trip_through_json():
    """Sérialiser puis relire redonne le même Finding."""
    finding = _finding()
    reloaded = Finding.from_dict(json.loads(json.dumps(finding.as_dict())))
    assert reloaded == finding
    assert hash(reloaded) == hash(finding)


def test_finding_is_immutable():
    """Un Finding est figé : personne ne peut le réécrire après coup."""
    finding = _finding()
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = "confirme"  # type: ignore[misc]


# --- Le code est au moins aussi strict que le schéma ---


def _sample(**overrides: object) -> dict[str, object]:
    payload = dict(BASE)
    payload.update(overrides)
    return payload


VALID_SAMPLES: list[dict[str, object]] = [
    _sample(),
    _sample(file=".env.example", line=1, type="unknown", entropy=0, snippet_hash="0" * 64),
    _sample(
        file="src/nested/config.py",
        line=4096,
        type="private_key",
        entropy=8,
        snippet_hash="f" * 64,
        status="detecte",
        source="llm",
    ),
    _sample(file="src/été.py", type="a"),
    _sample(file="src/name..py", type="a_b_c9"),
    _sample(file="...", type="a"),
    _sample(file="a" * 4096, type="a"),
    _sample(status="confirme"),
    _sample(status="vaulte"),
    _sample(status="rote"),
    _sample(status="faux_positif"),
    _sample(source="entropy"),
]

INVALID_SAMPLES: list[dict[str, object]] = [
    # champ file
    _sample(file=""),
    _sample(file="/etc/passwd"),
    _sample(file="../escape.py"),
    _sample(file="src/../escape.py"),
    _sample(file="src/./config.py"),
    _sample(file="src/.."),
    _sample(file="src/."),
    _sample(file=".."),
    _sample(file="src//config.py"),
    _sample(file="src/config.py/"),
    _sample(file="C:/config.py"),
    _sample(file="src\\config.py"),
    _sample(file="src/config\n.py"),
    _sample(file="src/config\u2028.py"),
    _sample(file="src/config\u007f.py"),
    _sample(file="a" * 4097),
    # champ line
    _sample(line=0),
    _sample(line=-1),
    _sample(line=1.5),
    _sample(line="12"),
    _sample(line=True),
    # champ type
    _sample(type=""),
    _sample(type="API_KEY"),
    _sample(type="api-key"),
    _sample(type="9key"),
    _sample(type="a" * 65),
    # champ entropy
    _sample(entropy=-0.01),
    _sample(entropy=8.01),
    _sample(entropy="4.25"),
    _sample(entropy=True),
    # champ snippet_hash
    _sample(snippet_hash=""),
    _sample(snippet_hash="a" * 63),
    _sample(snippet_hash="a" * 65),
    _sample(snippet_hash="A" * 64),
    _sample(snippet_hash="g" * 64),
    # champ status
    _sample(status="inconnu"),
    # champ source
    _sample(source="humain"),
]

# Propriétés inconnues : le schéma les refuse (`additionalProperties: false`).
UNKNOWN_FIELD_SAMPLES: list[dict[str, object]] = [
    {**BASE, "secret": "PLACEHOLDER_NOT_A_SECRET"},
    {**BASE, "value": "PLACEHOLDER_NOT_A_SECRET"},
]


@pytest.mark.parametrize("sample", VALID_SAMPLES, ids=lambda sample: f"{sample['file']}"[:24])
def test_valid_samples_are_accepted_by_schema_and_code(sample):
    assert _schema_accepts(sample)
    assert _code_accepts(sample)


@pytest.mark.parametrize(
    "sample",
    INVALID_SAMPLES,
    ids=lambda sample: ",".join(
        sorted(key for key, value in sample.items() if value != BASE.get(key))
    ),
)
def test_invalid_samples_are_refused_by_schema_and_code(sample):
    """Le schéma et le code sont d'accord : même acceptation, même refus."""
    assert not _schema_accepts(sample)
    assert not _code_accepts(sample)


def test_missing_field_is_refused():
    payload = _sample()
    del payload["status"]
    assert not _schema_accepts(payload)
    assert not _code_accepts(payload)


@pytest.mark.parametrize("sample", UNKNOWN_FIELD_SAMPLES, ids=["secret", "value"])
def test_unknown_field_is_refused(sample):
    """Propriété inconnue : refusée par le schéma comme par le code."""
    assert not _schema_accepts(sample)
    assert not _code_accepts(sample)


def test_code_is_stricter_than_the_schema_on_two_edge_cases():
    """Deux écarts assumés : le code refuse ce que le schéma tolère.

    1. ``line = 1.0`` : depuis le draft 6, JSON Schema considère un flottant
       entier comme un « integer ». Le code exige un vrai entier : une ligne
       de fichier est un entier, pas un flottant.
    2. ``entropy = NaN`` : les comparaisons de ``jsonschema`` (``<``/``>``)
       sont fausses pour NaN, donc NaN passe les bornes. NaN n'est pas du
       JSON et ``json.dumps`` n'en produirait pas un document valide.

    Dans les deux cas, le code est **plus strict** que le schéma : il refuse,
    il ne répare pas (fail-closed).
    """
    integral_float = _sample(line=1.0)
    assert _schema_accepts(integral_float)
    assert not _code_accepts(integral_float)

    for value in (math.nan, math.inf, -math.inf):
        payload = _sample(entropy=value)
        assert not _code_accepts(payload)
    assert _schema_accepts(_sample(entropy=math.nan))


# --- Aucun secret en clair, aucun reflet dans les messages ---


def test_finding_never_carries_the_secret():
    """Le Finding porte une empreinte, jamais la valeur candidate."""
    canary = "SYNTHETIC_CANARY_7f3a"
    payload = _finding().as_dict()
    serialized = json.dumps(payload)

    assert canary not in serialized
    assert "value" not in payload
    assert "secret" not in payload
    assert "snippet" not in payload
    assert payload["snippet_hash"] == FAKE_HASH


def test_error_messages_never_reflect_the_rejected_value():
    """Invariant 8 : un message d'erreur ne reflète jamais l'entrée refusée."""
    canary = "SYNTHETIC_CANARY_7f3a"
    with pytest.raises(InvalidFinding) as ctx:
        _finding(snippet_hash=canary)
    assert canary not in str(ctx.value)

    with pytest.raises(InvalidFinding) as ctx:
        _finding(file=f"../{canary}")
    assert canary not in str(ctx.value)

    with pytest.raises(InvalidTarget) as ctx:
        DiffTarget(path=f"../{canary}", lines=())
    assert canary not in str(ctx.value)


def test_invalid_finding_raises_a_typed_error():
    with pytest.raises(InvalidFinding):
        _finding(line=0)
    with pytest.raises(InvalidFinding):
        _finding(status="confirme_sans_valider")
    # InvalidFinding est aussi une ValueError : les appelants « contrat »
    # continuent de fonctionner.
    with pytest.raises(ValueError):
        _finding(type="API_KEY")
    assert issubclass(InvalidFinding, ScanError)


def test_non_object_and_non_string_inputs_are_refused():
    """Un Finding se relit depuis un objet ; un chemin se relit depuis une chaîne."""
    with pytest.raises(InvalidFinding):
        Finding.from_dict("pas un objet")  # type: ignore[arg-type]
    with pytest.raises(InvalidFinding):
        _finding(file=42)  # type: ignore[arg-type]
    with pytest.raises(InvalidTarget):
        FileTarget(path="src/app.py", text=42)  # type: ignore[arg-type]


# --- Cibles d'analyse ---


def test_diff_target_keeps_real_line_numbers():
    target = DiffTarget(path="src/app.py", lines=((7, "TOKEN = ..."), (9, "OTHER = 1")))
    assert target.lignes() == ((7, "TOKEN = ..."), (9, "OTHER = 1"))


def test_diff_target_refuses_unordered_or_invalid_lines():
    with pytest.raises(InvalidTarget):
        DiffTarget(path="src/app.py", lines=((9, "a"), (7, "b")))
    with pytest.raises(InvalidTarget):
        DiffTarget(path="src/app.py", lines=((0, "a"),))
    with pytest.raises(InvalidTarget):
        DiffTarget(path="src/app.py", lines=((1, "a"), (1, "b")))
    with pytest.raises(InvalidTarget):
        DiffTarget(path="src/app.py", lines=((1, 42),))  # type: ignore[arg-type]


def test_file_target_numbers_lines_from_one():
    target = FileTarget(path="src/app.py", text="a\nb\nc")
    assert target.lignes() == ((1, "a"), (2, "b"), (3, "c"))


@pytest.mark.parametrize("path", ["../escape.py", "/etc/passwd", "src/../x.py", "C:/x.py"])
def test_targets_refuse_unsafe_paths(path):
    with pytest.raises(InvalidTarget):
        DiffTarget(path=path, lines=())
    with pytest.raises(InvalidTarget):
        FileTarget(path=path, text="x")


# --- La façade Scanner ---


class _MoteurFactice:
    """Moteur de test : rend une liste fixe, sans filtrer (utile aux refus)."""

    def __init__(self, findings):
        self.findings = findings
        self.cibles = []

    def analyser(self, cible):
        self.cibles.append(cible)
        return list(self.findings)


class _MoteurParFichier:
    """Moteur de test : ne rend que les Findings du fichier ciblé, comme le vrai."""

    def __init__(self, findings):
        self.findings = findings
        self.cibles = []

    def analyser(self, cible):
        self.cibles.append(cible)
        return [finding for finding in self.findings if finding.file == cible.path]


def test_scanner_delegates_and_sorts():
    cible = DiffTarget(path="src/app.py", lines=((3, "a"), (9, "b")))
    moteur = _MoteurParFichier(
        [
            _finding(file="src/app.py", line=9, type="b"),
            _finding(file="src/app.py", line=3, type="a"),
        ]
    )
    findings = Scanner(moteur).scan(cible)

    assert [finding.line for finding in findings] == [3, 9]
    assert moteur.cibles == [cible]


def test_scanner_scan_all_sorts_by_file_then_line():
    moteur = _MoteurParFichier(
        [
            _finding(file="src/b.py", line=2),
            _finding(file="src/a.py", line=10),
            _finding(file="src/a.py", line=1),
        ]
    )
    findings = Scanner(moteur).scan_all(
        [
            FileTarget(path="src/b.py", text="x"),
            FileTarget(path="src/a.py", text="x"),
        ]
    )
    assert [(finding.file, finding.line) for finding in findings] == [
        ("src/a.py", 1),
        ("src/a.py", 10),
        ("src/b.py", 2),
    ]


@pytest.mark.parametrize(
    "finding",
    [
        "pas un Finding",
        _finding(file="src/autre.py", line=1),  # chemin différent de la cible
        _finding(file="src/app.py", line=1, status="confirme"),  # état non initial
        _finding(file="src/app.py", line=1, source="llm"),  # origine non déterministe
    ],
)
def test_scanner_refuses_a_non_conforming_engine_output(finding):
    moteur = _MoteurFactice([finding])
    with pytest.raises(ScanError):
        Scanner(moteur).scan(DiffTarget(path="src/app.py", lines=((1, "x"),)))


def test_scanner_propagates_engine_failure_without_partial_result():
    class _MoteurCasse:
        def analyser(self, cible):
            raise RuntimeError("panne du moteur")

    with pytest.raises(RuntimeError):
        Scanner(_MoteurCasse()).scan(DiffTarget(path="src/app.py", lines=((1, "x"),)))


def test_scanner_output_validates_against_the_contract():
    """Sortie du scanner -> sérialisation -> schéma #14."""
    moteur = _MoteurFactice([_finding(file="src/app.py", line=4)])
    findings = Scanner(moteur).scan(DiffTarget(path="src/app.py", lines=((4, "x"),)))
    for finding in findings:
        VALIDATOR.validate(finding.as_dict())


def test_public_api_is_exported_once():
    """Une seule classe Finding dans tout le paquet (source de vérité)."""
    assert heimdall.scanner.Finding is finding_module.Finding
    assert heimdall.scanner.detect.Finding is finding_module.Finding
    assert heimdall.scanner.Scanner.__module__ == "heimdall.scanner.interface"
