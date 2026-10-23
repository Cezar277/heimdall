"""Tests unitaires du scanner T22 (#60) : signatures, exclusions, Finding.

Toutes les valeurs sont synthétiques et dérivées par hachage (aucune clé
réelle). Les tests couvrent chaque signature, les faux positifs du corpus T21,
les exclusions, le confinement, les erreurs fail-closed et le coût linéaire
des regex sur de longues lignes (anti-ReDoS).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import time
import types
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from support.fake_secrets import fake_token

from heimdall.scanner import hashing
from heimdall.scanner.detect import (
    MAX_FILE_BYTES,
    Finding,
    RapportScan,
    ScanError,
    ScannerRacine,
    _open_flags,
    _safe_path,
    find_candidates,
    scan,
    scan_rapport,
)
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.exclusions import (
    Perimetre,
    classer_chemin,
    classer_repertoire,
    decode_text,
)
from heimdall.scanner.hashing import KEY_ENV, KEY_FILE_ENV, SnippetHasher, load_local_key
from heimdall.scanner.signatures import SIGNATURES, find_signature_matches
from heimdall.scanner.signatures.stripe_slack import (
    ROTATING_PAYLOAD_MAX,
    ROTATING_PAYLOAD_MIN,
    SLACK_PAYLOAD_MAX,
    SLACK_PREFIX_MAX,
    SLACK_TOKEN_MAX,
    SLACK_TOKEN_MIN,
)

ROOT = Path(__file__).resolve().parents[1]
FINDING_SCHEMA = ROOT / "schemas" / "finding.schema.json"


@pytest.fixture(autouse=True)
def _fixed_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clé fixe en mémoire : aucun test ne touche au dépôt ni au HOME."""
    monkeypatch.setenv(KEY_ENV, "42" * 32)


def _aws(seed: str = "aws", prefix: str = "AKIA") -> str:
    return prefix + hashlib.sha256(f"heimdall-t22-{seed}".encode()).hexdigest()[:16].upper()


def _stripe(seed: str = "stripe") -> str:
    return fake_token("sk_" + "live_", 24) + hashlib.sha256(seed.encode()).hexdigest()[:1]


def _slack() -> str:
    return fake_token("xoxb-", 24)


def _pat() -> str:
    return fake_token("ghp_", 36)


def _fine_grained_pat() -> str:
    return "github_" + "pat_" + hashlib.sha256(b"heimdall-t22-fine").hexdigest()[:40]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _jwt() -> str:
    return ".".join(
        [
            _b64(b'{"alg":"HS256","typ":"JWT"}'),
            _b64(b'{"sub":"heimdall-factice","exp":0}'),
            _b64(hashlib.sha256(b"heimdall-invalid-signature").digest()),
        ]
    )


def _pem_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


def _write(directory: Path, name: str, content: str | bytes) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")
    return path


def _scan_lines(tmp_path: Path, *lines: str) -> list[dict[str, object]]:
    _write(tmp_path, "sample.txt", "\n".join(lines) + "\n")
    return find_candidates(str(tmp_path))


# --- Signatures (#54) -------------------------------------------------------


def test_each_signature_is_detected_with_its_type(tmp_path: Path) -> None:
    aws_secret = fake_token("", 40)
    findings = _scan_lines(
        tmp_path,
        f'AWS = "{_aws()}"',
        f'STRIPE = "{_stripe()}"',
        f'SLACK = "{_slack()}"',
        f'PAT = "{_pat()}"',
        f'FINE = "{_fine_grained_pat()}"',
        f'JWT = "{_jwt()}"',
        f'PEM = "{_pem_header()}"',
        f'aws_secret_access_key = "{aws_secret}"',
    )
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "aws"),
        (2, "stripe"),
        (3, "slack"),
        (4, "pat"),
        (5, "pat"),
        (6, "jwt"),
        (7, "pem"),
        (8, "aws"),
    ]
    assert all(finding["status"] == "detecte" for finding in findings)
    assert all(finding["source"] == "regex" for finding in findings)


def test_signature_rules_are_identifiable() -> None:
    """Chaque détection cite la règle stable qui l'a produite (#54)."""
    names = {signature.name for signature in SIGNATURES}
    assert names == {
        "aws_access_key_id",
        "aws_secret_access_key",
        "stripe_secret_key",
        "slack_token",
        "slack_app_token",
        "slack_rotating_token",
        "github_classic_pat",
        "github_fine_grained_pat",
        "jwt",
        "pem_private_key",
    }
    matches = find_signature_matches(f'AWS = "{_aws()}"')
    assert len(matches) == 1
    assert matches[0].signature == "aws_access_key_id"
    assert matches[0].secret_type == "aws"  # noqa: S105 - type, not a password.


def test_finding_contains_no_raw_secret(tmp_path: Path) -> None:
    secret = _aws()
    finding = find_candidates(str(_write(tmp_path, "sample.py", f'"{secret}"')))[0]
    serialized = json.dumps(finding)
    assert secret not in serialized
    assert finding["snippet_hash"] != secret
    assert re.fullmatch(r"[0-9a-f]{64}", str(finding["snippet_hash"]))


def test_finding_matches_contract_schema(tmp_path: Path) -> None:
    finding = _scan_lines(tmp_path, f'AWS = "{_aws()}"')[0]
    assert set(finding) == {
        "file",
        "line",
        "type",
        "entropy",
        "snippet_hash",
        "status",
        "source",
    }
    schema = json.loads(FINDING_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(finding)
    assert finding["file"] == "sample.txt"
    assert finding["line"] == 1


@pytest.mark.parametrize(
    "line",
    [
        'UUID = "550e8400-e29b-41d4-a716-446655440000"',
        f'SHA256 = "{hashlib.sha256(b"public").hexdigest()}"',
        f'COMMIT = "{hashlib.sha1(b"public", usedforsecurity=False).hexdigest()}"',
        'INTEGRITY = "sha512-' + base64.b64encode(b"public package").decode() + '"',
        'EXAMPLE = "example"',
        'PASSWORD = "changeme"',
        'API_KEY = "your_key_here"',
        'IMAGE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"',
        'MOCK = "MOCK_TOKEN_FOR_TESTS_ONLY"',
        'SHORT_AWS = "AKIA1234"',
        'SHORT_PAT = "ghp_"',
        'TRUNCATED_JWT = "eyJhbGciOiJIUzI1NiJ9.e30"',
        'DOC = "-----BEGIN CERTIFICATE-----"',
    ],
)
def test_known_false_positives_are_not_reported(tmp_path: Path, line: str) -> None:
    assert _scan_lines(tmp_path, line) == []


def test_multiple_types_on_one_line_are_all_reported(tmp_path: Path) -> None:
    findings = _scan_lines(tmp_path, f'AWS = "{_aws()}"; STRIPE = "{_stripe()}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "aws"),
        (1, "stripe"),
    ]


@pytest.mark.parametrize("prefix", ["AKIA", "ASIA", "ABIA", "ACCA"])
def test_aws_access_key_prefixes_are_detected(tmp_path: Path, prefix: str) -> None:
    findings = _scan_lines(tmp_path, f'AWS = "{_aws(prefix, prefix)}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


def test_distinct_values_same_type_on_one_line_are_all_reported(tmp_path: Path) -> None:
    """Invariant 1 : deux secrets distincts ne doivent jamais fusionner."""
    findings = _scan_lines(tmp_path, f'A = "{_aws("a")}"; B = "{_aws("b")}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "aws"),
        (1, "aws"),
    ]
    assert len({finding["snippet_hash"] for finding in findings}) == 2


def test_identical_value_same_type_on_one_line_is_reported_once(tmp_path: Path) -> None:
    secret = _aws("same")
    findings = _scan_lines(tmp_path, f'A = "{secret}"; B = "{secret}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


def test_jwt_payload_above_previous_bound_is_detected(tmp_path: Path) -> None:
    """Une charge JWT de 9 000 caractères reste dans la borne 64 Kio."""
    jwt = ".".join(
        [
            _b64(b'{"alg":"HS256","typ":"JWT"}'),
            "A" * 9_000,
            _b64(hashlib.sha256(b"heimdall-long-jwt").digest()),
        ]
    )
    findings = _scan_lines(tmp_path, f'JWT = "{jwt}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "jwt")]


@pytest.mark.parametrize("prefix", ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-", "xwfp-"])
def test_slack_token_families_are_detected(tmp_path: Path, prefix: str) -> None:
    """Familles Slack documentées (docs.slack.dev, consultées le 2026-10-20)."""
    token = fake_token(prefix, 24)
    findings = _scan_lines(tmp_path, f'SLACK = "{token}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_slack_rotating_token_is_detected(tmp_path: Path) -> None:
    r"""Un jeton rotatif est détecté, forme emboîtée `xoxe.xapp-…` comprise.

    Le registre #54 signalait les deux formes emboîtées (rotatif + app) et
    tolérait le doublon (« doublon acceptable, jamais un manqué »). La garde
    `(?<!xoxe\.)` de ce Correctif le supprime : un seul secret, une seule
    empreinte, une seule entrée Vault à révoquer. « Jamais un manqué » reste
    vrai — l'évasion par préfixe (`.xapp-…`) reste couverte par
    `test_dot_prefixed_app_token_is_still_detected`.
    """
    token = "xoxe." + fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "{token}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_dot_prefixed_app_token_is_still_detected(tmp_path: Path) -> None:
    """Non-régression évasion par préfixe : `.xapp-…` reste signalé."""
    token = fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "evil.{token}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_unknown_slack_family_is_not_reported(tmp_path: Path) -> None:
    """Limite documentée : une famille Slack non publiée n'est pas couverte."""
    token = fake_token("xoxo-", 24)
    assert _scan_lines(tmp_path, f'SLACK = "{token}"') == []


def test_slack_token_after_a_dot_is_detected(tmp_path: Path) -> None:
    """Non-régression LOW : un point ne doit pas masquer un jeton Slack.

    Le lookbehind était élargi à `.` : un jeton collé à un préfixe de domaine
    ou à une concaténation (`foo.xapp-…`) disparaissait. Un faux négatif
    n'est jamais acceptable pour laisser passer un secret.
    """
    token = fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'foo.{token}')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_slack_rotating_token_after_a_dot_is_detected(tmp_path: Path) -> None:
    """Un jeton rotatif derrière un point reste détecté (faux négatif interdit)."""
    token = "xoxe." + fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'foo.{token}')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_a_rotating_token_is_reported_once(tmp_path: Path) -> None:
    """Un jeton rotatif est un seul secret : un seul Finding, une seule empreinte."""
    token = "xoxe." + fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "{token}"')
    assert len(findings) == 1
    assert findings[0]["type"] == "slack"


def test_a_rotating_bot_token_is_reported_once(tmp_path: Path) -> None:
    """`xoxe.xoxb-…` est un seul secret, pas deux (une entrée Vault, pas deux)."""
    token = "xoxe." + fake_token("xoxb-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "{token}"')
    assert len(findings) == 1
    assert findings[0]["type"] == "slack"


def test_an_inner_slack_token_copied_alone_is_still_detected(tmp_path: Path) -> None:
    """Non-régression LOW : l'« inner » d'un jeton rotatif reste détecté seul.

    La garde `xoxe.` neutralise le **second** signalement d'un même secret
    (une empreinte, une entrée Vault). Elle ne doit jamais neutraliser un
    jeton qui apparaît ailleurs : le secret est alors une autre occurrence,
    avec sa propre empreinte.
    """
    inner = fake_token("xapp-", 24)
    _write(tmp_path, "rotatif.txt", f'SLACK = "xoxe.{inner}"')
    _write(tmp_path, "copie.txt", f'SLACK = "{inner}"')
    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        ("copie.txt", "slack"),
        ("rotatif.txt", "slack"),
    ]
    # Deux occurrences distinctes du même secret : deux empreintes distinctes.
    assert len({finding["snippet_hash"] for finding in findings}) == 2


def test_a_padded_rotating_prefix_does_not_hide_the_inner_token(tmp_path: Path) -> None:
    """Non-régression LOW : un préfixe rotatif bourré ne masque pas le secret.

    `xxoxe.xapp-…` n'est pas un jeton rotatif (le préfixe `xoxe.` n'est pas
    ancré) : le jeton app-level qu'il contient reste un vrai secret et doit
    être signalé. La garde `xoxe.` ne neutralise le jeton interne que si la
    règle rotative le reconnaît elle-même.
    """
    inner = fake_token("xapp-", 24)
    _write(tmp_path, "bourrage.txt", f'SLACK = "xxoxe.{inner}"')
    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        ("bourrage.txt", "slack"),
    ]


@pytest.mark.parametrize("prefixe", ["xapp-", "xoxb-"])
@pytest.mark.parametrize("charge", [0, 4, 5, 9, 10, 100, 245, 250, 251])
def test_the_rotating_prefix_never_hides_a_token_under_the_threshold(
    prefixe: str, charge: int
) -> None:
    """Le préfixe `xoxe.` ne peut jamais faire disparaître un jeton detectable.

    Un jeton interne detectable seul doit rester detectable une fois
    préfixé par `xoxe.` (faux négatif interdit) ; un jeton interne déjà
    trop court pour la fenêtre n'est pas (non plus) pretexté. Le bourrage du
    préfixe (`xxoxe.`) est transparent : il ne correspond pas à la forme
    rotative, donc le jeton interne est signalé tel quel.
    """
    interne = prefixe + "a" * charge
    seul = find_signature_matches(interne)
    compose = find_signature_matches("xoxe." + interne)
    compose_bourre = find_signature_matches("xxoxe." + interne)
    # Jamais de faux négatif : ce qui est detectable seul l'est aussi préfixé.
    if seul:
        assert compose
    # Le bourrage du préfixe est transparent : même résultat que le jeton seul.
    assert bool(compose_bourre) == bool(seul)
    if not seul:
        return
    # « Un secret, une empreinte, une entrée Vault » : le jeton interne n'est
    # pas signalé une seconde fois quand le préfixe rotatif est reconnu…
    assert len(compose) == 1
    assert compose[0].signature == "slack_rotating_token"
    # … mais il l'est dès que le préfixe rotatif est bourré (le jeton interne
    # est alors le seul secret présent).
    assert len(compose_bourre) == 1
    assert compose_bourre[0].signature in {"slack_app_token", "slack_token"}


def test_the_slack_bounds_are_coupled_by_construction() -> None:
    """Non-régression LOW : le couplage des bornes Slack est structurel.

    La forme rotative `xoxe.` *porte* le jeton qu'elle enveloppe : sa
    charge doit donc couvrir le jeton interne **en entier**. Les deux
    bornes ne sont pas écrites l'une à côté de l'autre : elles dérivent des
    mêmes constantes. Si une seule évoluait, un secret préfixé
    disparaîtrait **des deux** règles (la garde neutralise le jeton interne
    sans vérifier la longueur de la charge).
    """
    # La borne rotative couvre le jeton interne, préfixe compris.
    assert ROTATING_PAYLOAD_MAX >= SLACK_TOKEN_MAX
    assert ROTATING_PAYLOAD_MAX == SLACK_TOKEN_MAX == 255
    assert SLACK_TOKEN_MAX == SLACK_PREFIX_MAX + SLACK_PAYLOAD_MAX
    # La borne rotative n'exclut pas les jetons plus courts : son minimum
    # ne dépasse pas celui du jeton interne.
    assert ROTATING_PAYLOAD_MIN <= SLACK_TOKEN_MIN


@pytest.mark.parametrize("prefixe", ["xapp-", "xoxb-"])
def test_a_maximal_inner_token_stays_detectable_once_prefixed(prefixe: str) -> None:
    """Non-régression LOW : aux bornes exactes, un jeton préfixé reste vu.

    Le jeton interne est à sa charge **maximale** : c'est le cas limite où
    la forme rotative pourrait dépasser sa propre borne et où le jeton
    interne deviendrait invisible des deux règles. Le couplage des bornes
    l'interdit : exactement un finding, et c'est la forme rotative (« un
    secret, une empreinte, une entrée Vault »).
    """
    interne = prefixe + "a" * SLACK_PAYLOAD_MAX
    assert len(interne) == SLACK_TOKEN_MAX
    seul = find_signature_matches(interne)
    compose = find_signature_matches("xoxe." + interne)
    # Le jeton interne, seul, est detectable…
    assert len(seul) == 1
    # … et il ne disparaît pas une fois préfixé : la forme rotative le
    # porte (une seule fois, pas deux).
    assert len(compose) == 1
    assert compose[0].signature == "slack_rotating_token"
    assert compose[0].value == "xoxe." + interne


def test_an_oversized_inner_token_is_a_documented_limit() -> None:
    """Limite figée : au-delà de la charge maximale, rien n'est détecté.

    Un jeton plus long que la borne documentée n'est detectable **ni seul
    ni préfixé** : la limite est écrite (et non un secret perdu en
    silence par la garde `xoxe.`). Le comportement est figé ici.
    """
    interne = "xapp-" + "a" * (SLACK_PAYLOAD_MAX + 1)
    assert len(interne) == SLACK_TOKEN_MAX + 1
    assert find_signature_matches(interne) == ()
    assert find_signature_matches("xoxe." + interne) == ()


def test_secret_split_across_two_lines_is_detected(tmp_path: Path) -> None:
    """Un secret coupé par un retour à la ligne reste détecté (fenêtre 4 Kio)."""
    secret = fake_token("", 40)
    _write(tmp_path, "split.py", f'aws_secret_access_key =\n"{secret}"\n')
    findings = find_candidates(str(tmp_path))
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


def test_split_secret_beyond_the_window_is_a_documented_limit(tmp_path: Path) -> None:
    """Au-delà de la fenêtre de 4 Kio, le secret coupé n'est pas recherché."""
    secret = fake_token("", 40)
    _write(tmp_path, "wide.py", "aws_secret_access_key = " + "x" * 5_000 + f'\n"{secret}"\n')
    assert find_candidates(str(tmp_path)) == []


def test_secret_split_by_a_blank_line_is_detected(tmp_path: Path) -> None:
    """Non-régression MEDIUM : une ligne vide intercalée ne fait plus perdre le secret.

    La fenêtre joint jusqu'à trois lignes contiguës : `aws_secret_access_key =`,
    une ligne vide, puis la valeur. Avant, la jointure ne portait que sur deux
    lignes et le secret disparaissait sans laisser de trace.
    """
    secret = fake_token("", 40)
    _write(tmp_path, "blank.py", f'aws_secret_access_key =\n\n"{secret}"\n')
    findings = find_candidates(str(tmp_path))
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


def test_secret_split_over_three_lines_is_detected(tmp_path: Path) -> None:
    """La fenêtre de trois lignes couvre un secret réparti sur trois lignes."""
    secret = fake_token("", 40)
    _write(tmp_path, "three.py", f'aws_secret_access_key = "{secret[:20]}\n{secret[20:]}"\n')
    findings = find_candidates(str(tmp_path))
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


def test_secret_split_by_more_than_two_newlines_is_a_documented_limit(tmp_path: Path) -> None:
    """Limite figée : au-delà de trois lignes jointes, la coupure n'est pas vue."""
    secret = fake_token("", 40)
    _write(tmp_path, "gap.py", f'aws_secret_access_key =\n\n\n"{secret}"\n')
    assert find_candidates(str(tmp_path)) == []


# --- Exclusions (#59) -------------------------------------------------------


def test_perimetre_classifie_les_repertoires_sans_exclure_de_fichier() -> None:
    """Le nom ne qualifie que la *conséquence* d'un échec de lecture."""
    assert classer_repertoire("vendor") is Perimetre.TIERS
    assert classer_repertoire("VENDOR") is Perimetre.TIERS
    assert classer_repertoire("node_modules") is Perimetre.TIERS
    assert classer_repertoire(".venv") is Perimetre.TIERS
    assert classer_repertoire(".git") is Perimetre.HORS_PERIMETRE
    assert classer_repertoire(".hg") is Perimetre.HORS_PERIMETRE
    assert classer_repertoire("src") is Perimetre.STRICT
    assert classer_repertoire("env") is Perimetre.STRICT
    assert classer_repertoire("") is Perimetre.STRICT
    assert classer_chemin("vendor/lib.py") is Perimetre.TIERS
    assert classer_chemin("src/vendor/lib.py") is Perimetre.TIERS
    assert classer_chemin(".git/config") is Perimetre.HORS_PERIMETRE
    assert classer_chemin("src/app.py") is Perimetre.STRICT
    assert classer_chemin("app.py") is Perimetre.STRICT


def test_a_nom_exclu_ne_cache_plus_aucon_secret(tmp_path: Path) -> None:
    """Non-régression HIGH : un nom « exclu » ne dispense jamais de lire.

    `evil.png`, `evil.lock`, `package-lock.json` et `vendor/s.txt` étaient
    ignorés sur leur seul nom : un secret y passait inaperçu et le verdict
    « dépôt propre » était faux. Le contenu décide : ces fichiers sont lus,
    décodés et scannés.
    """
    secret = _aws("nom")
    _write(tmp_path, "evil.png", f'AWS = "{secret}"')
    _write(tmp_path, "evil.lock", f'AWS = "{secret}"')
    _write(tmp_path, "package-lock.json", f'AWS = "{secret}"')
    _write(tmp_path, "vendor/s.txt", f'AWS = "{secret}"')
    _write(tmp_path, "node_modules/pkg/index.js", f'AWS = "{secret}"')
    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        ("evil.lock", "aws"),
        ("evil.png", "aws"),
        ("node_modules/pkg/index.js", "aws"),
        ("package-lock.json", "aws"),
        ("vendor/s.txt", "aws"),
    ]


def test_scan_covers_the_named_files_and_skips_only_real_binaries(tmp_path: Path) -> None:
    """Les fichiers « exclus » par nom sont scannés ; seul le binaire est ignoré."""
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    _write(tmp_path, ".env", f'STRIPE = "{_stripe()}"')
    _write(tmp_path, "deploy.pem", _pem_header())
    _write(tmp_path, "requirements.txt", f'AWS = "{_aws("req")}"')
    _write(tmp_path, "vendor/lib.py", f'AWS = "{_aws("vendor")}"')
    _write(tmp_path, "node_modules/pkg/index.js", f'AWS = "{_aws("node")}"')
    _write(tmp_path, "package-lock.json", f'AWS = "{_aws("lock")}"')
    _write(tmp_path, ".gitignore", f'AWS = "{_aws("ignore")}"')
    _write(tmp_path, "image.png", f'AWS = "{_aws("image")}"')
    _write(tmp_path, "blob.bin", f'AWS = "{_aws("blob")}"')
    _write(tmp_path, "script", f'AWS = "{_aws("script")}"')

    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        (".env", "stripe"),
        (".gitignore", "aws"),
        ("app.py", "aws"),
        ("blob.bin", "aws"),
        ("deploy.pem", "pem"),
        ("image.png", "aws"),
        ("node_modules/pkg/index.js", "aws"),
        ("package-lock.json", "aws"),
        ("requirements.txt", "aws"),
        ("script", "aws"),
        ("vendor/lib.py", "aws"),
    ]


def test_virtualenv_is_a_tier_tree_and_is_still_scanned(tmp_path: Path) -> None:
    """``.venv`` n'est plus un trou : c'est un arbre de tiers, donc scanné."""
    _write(tmp_path, "env/app.py", f'AWS = "{_aws("env")}"')
    _write(tmp_path, ".venv/lib.py", f'AWS = "{_aws("dotvenv")}"')
    _write(tmp_path, "venv/lib.py", f'AWS = "{_aws("venv")}"')
    _write(tmp_path, "virtualenv/lib.py", f'AWS = "{_aws("virtualenv")}"')
    findings = find_candidates(str(tmp_path))
    assert [finding["file"] for finding in findings] == [
        ".venv/lib.py",
        "env/app.py",
        "venv/lib.py",
        "virtualenv/lib.py",
    ]


def test_a_real_binary_is_traced_and_counted_without_leaking_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Non-régression MEDIUM : un binaire ignoré reste *visible*.

    Le binaire est le seul contenu non analysable toléré ; il doit laisser une
    trace (chemin journalisé + compteur) sans jamais laisser fuir une
    valeur.
    """
    _write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.binaires_ignores == 1
    assert rapport.non_analyses == 0
    # Un binaire n'est pas lu : son contenu peut cacher un secret. Le verdict
    # « propre » n'est donc **pas** fondé (`complet` faux) tant qu'il
    # subsiste, même si le fichier est apparemment inoffensif.
    assert rapport.complet is False
    assert [finding.file for finding in rapport.findings] == ["app.py"]
    trace = capsys.readouterr().err
    assert "image.png" in trace
    assert "binaire" in trace
    # Aucune valeur de secret ne fuit dans la trace.
    assert _aws() not in trace


def test_the_report_exposes_what_was_not_analysed(tmp_path: Path) -> None:
    """Le rapport distingue un dépôt propre d'un dépôt partiellement lu."""
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    rapport = scan_rapport(str(tmp_path))
    assert isinstance(rapport, RapportScan)
    assert rapport.binaires_ignores == 0
    assert rapport.non_analyses == 0
    assert rapport.liens_ignores == 0
    assert rapport.hors_perimetre == 0
    assert rapport.complet is True


def test_the_vcs_database_is_not_walked_but_is_traced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``.git/`` n'est pas le contenu du dépôt : il n'est pas parcouru, mais tracé."""
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git")}"')
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.hors_perimetre == 1
    assert [finding.file for finding in rapport.findings] == ["app.py"]
    assert ".git" in capsys.readouterr().err


def test_a_file_ignored_in_a_tier_tree_does_not_break_the_scan(tmp_path: Path) -> None:
    """Un fichier illisible dans un arbre de tiers est tracé, pas fatal."""
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    _write(tmp_path, "vendor/broken.bin", b"\x00\x01\x02not-decodable")
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1
    assert [finding.file for finding in rapport.findings] == ["vendor/secret.txt"]


def test_a_broken_file_in_the_strict_perimeter_is_fail_closed(tmp_path: Path) -> None:
    """Dans le contenu du dépôt, un fichier illisible reste fatal."""
    _write(tmp_path, "broken.bin", b"\x00\x01\x02not-decodable")
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_an_oversized_file_in_a_tier_tree_is_traced_not_fatal(tmp_path: Path) -> None:
    """Dans un arbre de tiers, un fichier hors borne est tracé, pas fatal."""
    _write(tmp_path, "vendor/huge.txt", b"A" * (MAX_FILE_BYTES + 1))
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1
    assert [finding.file for finding in rapport.findings] == ["vendor/secret.txt"]


def test_a_fifo_in_a_tier_tree_is_traced_not_fatal(tmp_path: Path) -> None:
    """Un fichier non régulier dans un arbre de tiers est tracé, pas fatal."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo indisponible")
    (tmp_path / "vendor").mkdir()
    os.mkfifo(tmp_path / "vendor" / "pipe")
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1


def test_an_invalid_name_in_a_tier_tree_is_traced_not_fatal(tmp_path: Path) -> None:
    """Un nom hors contrat dans un arbre de tiers est tracé, pas fatal."""
    _write(tmp_path, "vendor/bad:name.txt", f'AWS = "{_aws("vendor")}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1
    assert rapport.findings == ()


# --- Verdict propre partiel : fail-closed strict ------------------------------


def _arbre_de_tiers_avec_un_fichier_illisible(tmp_path: Path) -> Path:
    """Prépare un arbre de tiers contenant un fichier illisible."""
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    bloque = _write(tmp_path, "vendor/bloque.txt", "contenu")
    bloque.chmod(0o000)
    return bloque


def test_a_tier_failure_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier non analysable en arbre de tiers n'est jamais un `[]` propre.

    `scan()` et `find_candidates()` jetaient les compteurs : un fichier
    illisible, hors borne, non régulier ou mal nommé dans `vendor/` rendait
    une liste vide — un **verdict propre inventé** alors qu'une partie du
    périmètre n'avait pas été lue. Les deux API lèvent désormais
    `ScanError` ; seul `scan_rapport()` expose le bilan partiel.
    """
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    _write(tmp_path, "vendor/broken.bin", b"\x00\x01\x02not-decodable")
    with pytest.raises(ScanError) as context:
        scan(tmp_path)
    assert str(context.value) == "scan impossible : entrée non analysable"
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1
    assert [finding.file for finding in rapport.findings] == ["vendor/secret.txt"]


def test_an_oversized_tier_file_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier hors borne en arbre de tiers n'est jamais un `[]` propre."""
    _write(tmp_path, "vendor/huge.txt", b"A" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ScanError):
        scan(tmp_path)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_a_fifo_in_a_tier_tree_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier non régulier en arbre de tiers n'est jamais un `[]` propre."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo indisponible")
    (tmp_path / "vendor").mkdir()
    os.mkfifo(tmp_path / "vendor" / "pipe")
    with pytest.raises(ScanError):
        scan(tmp_path)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_an_invalid_name_in_a_tier_tree_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un nom hors contrat en arbre de tiers n'est jamais un `[]` propre."""
    _write(tmp_path, "vendor/bad:name.txt", f'AWS = "{_aws("vendor")}"')
    with pytest.raises(ScanError):
        scan(tmp_path)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_an_unreadable_tier_file_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier illisible en arbre de tiers n'est jamais un `[]` propre."""
    bloque = _arbre_de_tiers_avec_un_fichier_illisible(tmp_path)
    try:
        with pytest.raises(ScanError):
            scan(tmp_path)
        with pytest.raises(ScanError):
            find_candidates(str(tmp_path))
        rapport = scan_rapport(str(tmp_path))
    finally:
        bloque.chmod(0o600)
    assert rapport.non_analyses == 1
    assert [finding.file for finding in rapport.findings] == ["vendor/secret.txt"]


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_a_walk_error_in_a_tier_tree_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Une erreur de parcours en arbre de tiers n'est jamais un `[]` propre.

    Le chemin `_on_walk_error` (répertoire illisible) est le même que celui
    d'un fichier illisible : le compteur était jeté par `scan()`, donc un
    dépôt dont un sous-arbre n'a pas été parcouru rendait une liste vide.
    """
    bloque = tmp_path / "vendor" / "bloque"
    bloque.mkdir(parents=True)
    (bloque / "secret.txt").write_text("x", encoding="utf-8")
    bloque.chmod(0o000)
    try:
        with pytest.raises(ScanError):
            scan(tmp_path)
        with pytest.raises(ScanError):
            find_candidates(str(tmp_path))
        rapport = scan_rapport(str(tmp_path))
    finally:
        bloque.chmod(0o700)
    assert rapport.non_analyses == 1


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_an_unreadable_tier_directory_at_the_root_is_traced(tmp_path: Path) -> None:
    """Le répertoire de tiers fautif est classé par son propre nom.

    ``classer_chemin`` classe des **fichiers** et ignore le dernier segment.
    Pour une erreur de parcours, le dernier segment est le répertoire fautif :
    un ``vendor/`` illisible à la racine doit être tracé (tiers), pas pris
    pour le périmètre strict.
    """
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "secret.txt").write_text(f'AWS = "{_aws("vendor")}"', encoding="utf-8")
    vendor.chmod(0o000)
    try:
        with pytest.raises(ScanError):
            scan(tmp_path)
        with pytest.raises(ScanError):
            find_candidates(str(tmp_path))
        rapport = scan_rapport(str(tmp_path))
    finally:
        vendor.chmod(0o700)
    assert rapport.non_analyses == 1
    assert rapport.complet is False
    assert rapport.findings == ()


def test_the_report_is_not_complete_when_a_binary_was_left_aside(tmp_path: Path) -> None:
    """Un binaire non lu rend le verdict « propre » non fondé."""
    _write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    rapport = scan_rapport(str(tmp_path))
    assert rapport.binaires_ignores == 1
    assert rapport.complet is False


def test_the_report_is_not_complete_when_a_link_was_left_aside(tmp_path: Path) -> None:
    """Un lien symbolique non suivi rend le verdict « propre » non fondé."""
    if not hasattr(os, "symlink"):
        pytest.skip("liens symboliques indisponibles")
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "leak.py", f'AWS = "{_aws("outside")}"')
    repository = tmp_path / "repo"
    repository.mkdir()
    try:
        (repository / "link.py").symlink_to(outside / "leak.py")
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    rapport = scan_rapport(str(repository))
    assert rapport.liens_ignores == 1
    assert rapport.complet is False


def test_the_report_is_not_complete_when_the_vcs_base_was_left_aside(tmp_path: Path) -> None:
    """Une base VCS non parcourue rend le verdict « propre » non fondé."""
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git")}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.hors_perimetre == 1
    assert rapport.complet is False


def test_a_complete_scan_is_the_only_one_that_is_founded(tmp_path: Path) -> None:
    """Un dépôt entièrement lu (rien de laissé de côté) est `complet`."""
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    rapport = scan_rapport(str(tmp_path))
    assert rapport.complet is True
    assert rapport.binaires_ignores == 0
    assert rapport.non_analyses == 0
    assert rapport.liens_ignores == 0
    assert rapport.hors_perimetre == 0


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="liens symboliques indisponibles")
def test_a_symlinked_directory_is_traced_and_never_followed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un répertoire symlinké n'est jamais suivi : il est compté et tracé."""
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "leak.py", f'AWS = "{_aws("outside")}"')
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", f'AWS = "{_aws()}"')
    try:
        (repository / "linked").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    rapport = scan_rapport(str(repository))
    assert rapport.liens_ignores == 1
    assert [finding.file for finding in rapport.findings] == ["app.py"]
    assert "linked" in capsys.readouterr().err


def test_the_trace_neutralises_control_characters_in_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un nom de fichier ne peut pas injecter de fausse ligne de journal."""
    _write(tmp_path, "vendor/binaire\nFAUSSE LIGNE.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    rapport = scan_rapport(str(tmp_path))
    # Le nom est hors contrat : le fichier n'est pas analysable, mais il est
    # tracé — sur une seule ligne, sans le retour à la ligne injecté.
    assert rapport.non_analyses == 1
    trace = capsys.readouterr().err
    assert "vendor/binaire?FAUSSE LIGNE.png" in trace
    assert "\nFAUSSE LIGNE" not in trace
    assert trace.count("\n") == 1


@pytest.mark.parametrize(
    "separateur",
    [
        pytest.param("\u2028", id="U+2028"),
        pytest.param("\u2029", id="U+2029"),
        pytest.param("\u0085", id="U+0085"),
        pytest.param("\u202e", id="U+202E"),
    ],
)
def test_the_trace_neutralises_unicode_separators_in_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], separateur: str
) -> None:
    """Un séparateur Unicode ne doit pas injecter de fausse ligne de journal.

    U+2028/U+2029 séparent les lignes pour un lecteur Markdown ou JSON ;
    U+0085 est un « next line » ; U+202E inverse l'affichage. Aucun de ces
    caractères ne doit survivre dans la trace : le journal reste une ligne
    logique par fichier.
    """
    _write(
        tmp_path,
        f"vendor/binaire{separateur}FAUSSE LIGNE.png",
        b"\x89PNG\r\n\x1a\n" + bytes(range(256)),
    )
    rapport = scan_rapport(str(tmp_path))
    # Selon le caractère, le nom est hors contrat (U+2028/U+2029 : fichier non
    # analysé) ou valide (U+0085/U+202E : fichier lu, binaire ignoré). Dans
    # les deux cas, le fichier laisse **une** trace et une seule.
    assert rapport.non_analyses + rapport.binaires_ignores == 1
    trace = capsys.readouterr().err
    assert separateur not in trace
    assert "vendor/binaire?FAUSSE LIGNE.png" in trace
    assert trace.count("\n") == 1
    # Une seule ligne logique : aucun séparateur Unicode ne subsiste.
    assert trace.splitlines() == [trace.rstrip("\n")]


def test_the_trace_neutralises_surrogates_from_non_utf8_names() -> None:
    """Un nom POSIX non UTF-8 (surrogate) ne casse pas le journal.

    Python expose les octets invalides d'un nom de fichier sous forme de
    surrogates (catégorie ``Cs``). Les laisser passer ferait échouer une
    écriture de journal en UTF-8 strict : ils sont neutralisés comme les
    autres caractères non sûrs.
    """
    assert _safe_path("vendor/binaire\udcff.png") == "vendor/binaire?.png"


def test_the_trace_truncates_an_absurdly_long_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un chemin démesuré ne noie pas le journal."""
    _write(tmp_path, "vendor/" + "/".join("d" * 200 for _ in range(12)) + "/b.png",
           b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    rapport = scan_rapport(str(tmp_path))
    assert rapport.binaires_ignores == 1
    trace = capsys.readouterr().err
    assert len(trace) < 512


def test_utf16_utf32_without_bom_is_scanned(tmp_path: Path) -> None:
    encodings = ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
    for index, encoding in enumerate(encodings):
        _write(
            tmp_path,
            f"encoded_{index}.txt",
            f'AWS = "{_aws(encoding)}"'.encode(encoding),
        )
    findings = find_candidates(str(tmp_path))
    assert [finding["type"] for finding in findings] == ["aws"] * len(encodings)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_utf16_utf32_with_bom_is_scanned(tmp_path: Path, encoding: str) -> None:
    _write(tmp_path, "encoded.txt", f'AWS = "{_aws(encoding)}"'.encode(encoding))
    assert [finding["type"] for finding in find_candidates(str(tmp_path))] == ["aws"]


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_decode_text_handles_utf16_utf32_without_bom(encoding: str) -> None:
    text = 'AWS = "AKIA' + "A" * 16 + '"'
    assert decode_text(text.encode(encoding)) == text


def test_decode_text_handles_bom_and_plain_utf8() -> None:
    assert decode_text(b"") == ""
    assert decode_text(b"abc") == "abc"
    for encoding in ("utf-8-sig", "utf-16", "utf-32"):
        assert decode_text("AZERTY".encode(encoding)) == "AZERTY"
    assert decode_text(b"caf\xe9") == "caf\ufffd"
    assert decode_text(b"\xef\xbb\xbf") == ""


@pytest.mark.parametrize("payload", [b"\xff\xfeA", b"\xef\xbb\xbf\xff", b"\xfe\xff\x00\x00"])
def test_decode_text_fails_closed_on_invalid_bom_text(payload: bytes) -> None:
    with pytest.raises(ScanError):
        decode_text(payload)


def test_decode_text_fails_closed_on_ambiguous_nul() -> None:
    with pytest.raises(ScanError):
        decode_text(b"abc\x00def")


@pytest.mark.parametrize("magic", [b"\x7fELF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04"])
def test_decode_text_identifies_known_binary_magic(magic: bytes) -> None:
    """Un vrai binaire (majorité non textuelle) reste ignoré par politique."""
    assert decode_text(magic + bytes(range(256))) is None


@pytest.mark.parametrize("magic", [b"\x7fELF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04"])
def test_decode_text_refuses_magic_followed_by_text(magic: bytes) -> None:
    """Une signature binaire suivie de texte clair n'est pas un contournement."""
    with pytest.raises(ScanError):
        decode_text(magic + b"\x00" + b"AKIA" + b"A" * 16)


def test_extensionless_known_binary_is_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "elf", b"\x7fELF" + bytes(range(256)))
    assert find_candidates(str(tmp_path)) == []


def test_binary_magic_followed_by_a_secret_is_fail_closed(tmp_path: Path) -> None:
    """4 octets de signature ne doivent pas transformer un refus en silence."""
    _write(tmp_path, "polyglot_zip", b"PK\x03\x04\x00AKIA" + b"A" * 16)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_png_magic_followed_by_a_secret_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "polyglot_png", b"\x89PNG\r\n\x1a\n\x00" + b"AKIA" + b"A" * 16)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_extensionless_ambiguous_nul_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "ambiguous", b"hello\x00world")
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_case_insensitive_tier_directory(tmp_path: Path) -> None:
    """``VENDOR/`` est un arbre de tiers (scanné), quelle que soit sa casse."""
    _write(tmp_path, "VENDOR/lib.py", f'AWS = "{_aws("upper")}"')
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    assert [finding["file"] for finding in find_candidates(str(tmp_path))] == [
        "VENDOR/lib.py",
        "app.py",
    ]


def test_symlinked_root_is_refused(tmp_path: Path) -> None:
    """Une racine symlinkée est refusée : la cible ne doit pas être lue."""
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "secret.txt", f'AWS = "{_aws("outside")}"')
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    with pytest.raises(ScanError):
        scan(link)


def test_symlinked_single_file_root_is_refused(tmp_path: Path) -> None:
    target = _write(tmp_path, "outside.txt", f'AWS = "{_aws("outside")}"')
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    with pytest.raises(ScanError):
        scan(link)


def test_root_under_a_symlinked_directory_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "secret.txt", f'AWS = "{_aws("outside")}"')
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    with pytest.raises(ScanError):
        scan(link / "secret.txt")


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "leak.py", f'AWS = "{_aws("outside")}"')
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", f'AWS = "{_aws()}"')
    try:
        (repository / "link.py").symlink_to(outside / "leak.py")
        (repository / "linked").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    assert [finding["file"] for finding in find_candidates(str(repository))] == ["app.py"]


# --- Lecture, confinement et fail-closed ------------------------------------


def test_single_file_root_uses_a_relative_name(tmp_path: Path) -> None:
    path = _write(tmp_path, "one.py", f'AWS = "{_aws()}"')
    findings = scan(path)
    assert isinstance(findings[0], Finding)
    assert [finding.file for finding in findings] == ["one.py"]


def test_invalid_utf8_is_scanned_with_replacement(tmp_path: Path) -> None:
    _write(tmp_path, "latin1.py", f'AWS = "{_aws()}"'.encode("ascii") + b" \xff\n")
    assert [finding["file"] for finding in find_candidates(str(tmp_path))] == ["latin1.py"]


def test_missing_root_is_fail_closed_without_reflection(tmp_path: Path) -> None:
    marker = "SENTINELLE_CHEMIN_NON_FIABLE"
    with pytest.raises(ScanError) as context:
        find_candidates(str(tmp_path / marker))
    assert marker not in str(context.value)
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_non_regular_file_is_fail_closed(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo indisponible")
    os.mkfifo(fifo)
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_oversized_file_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "huge.txt", b"A" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_invalid_relative_name_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "bad:name.txt", f'AWS = "{_aws()}"')
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_file_changed_during_read_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, "changing.txt", f'AWS = "{_aws("changing")}"')
    real_fstat = os.fstat
    calls = 0

    def altered_fstat(descriptor: int) -> object:
        nonlocal calls
        metadata = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            return types.SimpleNamespace(
                st_mode=metadata.st_mode,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
            )
        return metadata

    monkeypatch.setattr("heimdall.scanner.detect.os.fstat", altered_fstat)
    with pytest.raises(ScanError) as context:
        scan(path)
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_a_file_truncated_between_the_stat_and_the_open_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une troncature entre le `stat` et l'`open` n'est jamais un scan partiel.

    Le fichier garde la même identité (dev/ino) : seule la comparaison
    ``before``/``after`` (taille et date de modification) peut le voir. Sans
    elle, le scan ne portait que sur le **préfixe** restant : un secret
    placé dans la partie tronquée disparaissait et le verdict « propre »
    était inventé.
    """
    secret = _aws("tronque")
    path = _write(tmp_path, "changing.txt", f'AWS = "{secret}"\n')
    real_fstat = os.fstat
    calls = 0

    def truncated_fstat(descriptor: int) -> object:
        nonlocal calls
        metadata = real_fstat(descriptor)
        calls += 1
        if calls == 1:
            # Le fichier a été tronqué après le `stat` : même inode, taille
            # réduite, date de modification inchangée.
            return types.SimpleNamespace(
                st_mode=metadata.st_mode,
                st_size=metadata.st_size // 2,
                st_mtime_ns=metadata.st_mtime_ns,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
            )
        return metadata

    monkeypatch.setattr("heimdall.scanner.detect.os.fstat", truncated_fstat)
    with pytest.raises(ScanError) as context:
        scan(path)
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_a_root_with_a_nul_byte_is_fail_closed() -> None:
    """Une racine avec un octet NUL est un `ScanError`, pas une `ValueError` nue.

    `Path(root)` puis `resolve()` lèvent `ValueError` sur un octet NUL : sans
    conversion, l'exception brute traversait le contrat d'erreur (message
    statique, code 2 côté CLI).
    """
    with pytest.raises(ScanError) as context:
        ScannerRacine("a\x00b")
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_an_empty_root_is_fail_closed() -> None:
    """Un chemin vide n'est pas « le répertoire courant » : il est refusé.

    La docstring de ``_resolve_root`` promet le refus du chemin vide ; sans
    garde explicite, ``Path("")`` vaut ``.`` et le scanner analyserait le
    répertoire courant à l'insu de l'appelant.
    """
    for api in (ScannerRacine, scan, find_candidates):
        with pytest.raises(ScanError) as context:
            api("")
        assert str(context.value) == "scan impossible : entrée non analysable"


def test_a_non_path_root_is_fail_closed() -> None:
    """Un type qui n'est pas un chemin ne fuit pas une ``TypeError`` nue."""
    with pytest.raises(ScanError) as context:
        ScannerRacine(42)  # type: ignore[arg-type]
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_open_flags_are_read_only_non_blocking_and_never_follow_links() -> None:
    """L'ouverture ne suit pas un lien et ne bloque jamais sur un FIFO."""
    flags = _open_flags()
    assert flags & os.O_WRONLY == 0
    assert flags & os.O_RDWR == 0
    assert flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)
    assert flags & getattr(os, "O_NONBLOCK", 0) == getattr(os, "O_NONBLOCK", 0)


def test_report_is_deterministic_and_sorted(tmp_path: Path) -> None:
    _write(tmp_path, "z.py", f'AWS = "{_aws("z")}"')
    _write(tmp_path, "a.py", f'STRIPE = "{_stripe()}"\nAWS = "{_aws()}"')
    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["line"]) for finding in findings] == [
        ("a.py", 1),
        ("a.py", 2),
        ("z.py", 1),
    ]


def test_crlf_line_numbers_are_preserved(tmp_path: Path) -> None:
    _write(tmp_path, "windows.py", f"header\r\nAWS = \"{_aws()}\"\r\n")
    assert [finding["line"] for finding in find_candidates(str(tmp_path))] == [2]


# --- Fail-closed : les défenses de lecture -----------------------------------


def test_a_root_that_is_neither_a_file_nor_a_directory_is_refused(tmp_path: Path) -> None:
    """Une racine non régulière est refusée, jamais lue."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo indisponible")
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ScanError):
        scan(fifo)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_an_unreadable_directory_is_fail_closed(tmp_path: Path) -> None:
    """Un répertoire illisible dans le périmètre strict interrompt le scan."""
    bloque = tmp_path / "bloque"
    bloque.mkdir()
    (bloque / "secret.txt").write_text("x", encoding="utf-8")
    bloque.chmod(0o000)
    try:
        with pytest.raises(ScanError):
            scan(tmp_path)
    finally:
        bloque.chmod(0o700)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_an_unreadable_directory_in_a_tier_tree_is_traced(tmp_path: Path) -> None:
    """Dans un arbre de tiers, un répertoire illisible est tracé, pas fatal."""
    bloque = tmp_path / "vendor" / "bloque"
    bloque.mkdir(parents=True)
    (bloque / "secret.txt").write_text("x", encoding="utf-8")
    bloque.chmod(0o000)
    try:
        rapport = scan_rapport(str(tmp_path))
    finally:
        bloque.chmod(0o700)
    assert rapport.non_analyses == 1


def test_a_file_removed_before_being_read_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un fichier disparu entre le parcours et la lecture n'est pas analysable."""
    _write(tmp_path, "gone.txt", f'AWS = "{_aws()}"')
    real_resolve = Path.resolve

    def broken_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "gone.txt":
            raise OSError("disparu")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", broken_resolve)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_file_resolving_outside_the_root_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un fichier dont la résolution sort de la racine rompt le confinement."""
    _write(tmp_path, "escape.txt", "x")
    real_resolve = Path.resolve
    outside = tmp_path.parent / "outside.txt"

    def escaping_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "escape.txt":
            return outside
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escaping_resolve)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_file_that_cannot_be_stated_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ``stat`` impossible rend le fichier non analysable (fail-closed)."""
    _write(tmp_path, "stat.txt", "x")
    real_stat = os.stat

    def broken_stat(path: object, *args: object, **kwargs: object) -> object:
        if str(path).endswith("stat.txt"):
            raise OSError("panne")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("heimdall.scanner.detect.os.stat", broken_stat)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_file_that_cannot_be_opened_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ``open`` impossible rend le fichier non analysable (fail-closed)."""
    _write(tmp_path, "open.txt", "x")
    real_open = os.open

    def broken_open(path: object, *args: object, **kwargs: object) -> int:
        if str(path).endswith("open.txt"):
            raise OSError("panne")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("heimdall.scanner.detect.os.open", broken_open)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_file_replaced_before_being_read_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un descripteur qui ne désigne plus le même fichier est refusé."""
    _write(tmp_path, "swap.txt", "x")
    real_fstat = os.fstat

    def altered_fstat(descriptor: int) -> object:
        metadata = real_fstat(descriptor)
        return types.SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino + 1,
        )

    monkeypatch.setattr("heimdall.scanner.detect.os.fstat", altered_fstat)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_file_that_cannot_be_read_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une lecture impossible rend le fichier non analysable (fail-closed)."""
    _write(tmp_path, "read.txt", "x")
    real_read = os.read

    def broken_read(descriptor: int, size: int) -> bytes:
        if size > 0:
            raise OSError("panne")
        return real_read(descriptor, size)

    monkeypatch.setattr("heimdall.scanner.detect.os.read", broken_read)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_path_that_cannot_be_inspected_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ``lstat`` impossible est fail-closed, jamais un ``continue``."""
    _write(tmp_path, "link.txt", "x")
    real_is_symlink = Path.is_symlink

    def broken_is_symlink(self: Path) -> bool:
        if self.name == "link.txt":
            raise OSError("panne")
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", broken_is_symlink)
    with pytest.raises(ScanError):
        scan(tmp_path)


def test_a_path_outside_the_root_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un chemin qui ne peut pas être rendu relatif est fail-closed."""
    _write(tmp_path, "app.py", "x")
    real_relative_to = Path.relative_to

    def broken_relative_to(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "app.py":
            raise ValueError("hors racine")
        return real_relative_to(self, *args, **kwargs)

    monkeypatch.setattr(Path, "relative_to", broken_relative_to)
    with pytest.raises(ScanError):
        scan(tmp_path)


# --- Entropie et empreinte --------------------------------------------------


def test_shannon_entropy_bounds_and_values() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert shannon_entropy(b"ab") == 1.0
    assert 0.0 < shannon_entropy(bytes(range(256))) <= 8.0


def test_hmac_is_stable_and_never_reversible(tmp_path: Path) -> None:
    hasher = SnippetHasher(b"k" * 32)
    first = hasher.hash("SYNTHETIC_VALUE")
    assert first == hasher.hash("SYNTHETIC_VALUE")
    assert first != hasher.hash("SYNTHETIC_VALUE_2")
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert "SYNTHETIC_VALUE" not in first
    with pytest.raises(ScanError):
        SnippetHasher(b"short")


def test_local_key_is_created_outside_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_path = tmp_path / "state" / "snippet.key"
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    key = load_local_key()
    assert len(key) == 32
    assert key_path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert load_local_key() == key
    assert SnippetHasher().hash("SYNTHETIC_VALUE") == SnippetHasher().hash("SYNTHETIC_VALUE")


def test_local_key_rejects_invalid_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "key"))
    invalid = tmp_path / "invalid.key"
    invalid.write_bytes(b"short")
    monkeypatch.setenv(KEY_FILE_ENV, str(invalid))
    with pytest.raises(ScanError):
        load_local_key()
    monkeypatch.setenv(KEY_FILE_ENV, "relative.key")
    with pytest.raises(ScanError):
        load_local_key()
    monkeypatch.setenv(KEY_ENV, "zz")
    with pytest.raises(ScanError):
        SnippetHasher()


@pytest.mark.skipif(os.name != "posix", reason="modes et UID POSIX")
def test_local_key_rejects_permissive_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_path = tmp_path / "permissive.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o644)
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    with pytest.raises(ScanError):
        load_local_key()


@pytest.mark.skipif(os.name != "posix", reason="UID POSIX")
def test_local_key_rejects_foreign_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_path = tmp_path / "foreign.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    real_getuid = os.getuid
    monkeypatch.setattr(hashing.os, "getuid", lambda: real_getuid() + 1)
    with pytest.raises(ScanError):
        load_local_key()


def test_local_key_storage_unavailable_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Aucune clé éphémère : un stockage indisponible doit lever ScanError."""
    monkeypatch.delenv(KEY_ENV)
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(blocked / "key"))
    with pytest.raises(ScanError):
        load_local_key()


def test_local_key_default_xdg_path_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    key = load_local_key()
    key_path = xdg / "heimdall" / "snippet-hmac.key"
    assert key_path.is_file()
    assert len(key) == 32
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700


def test_local_key_requires_absolute_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", "relative")
    with pytest.raises(ScanError):
        load_local_key()


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="permissions POSIX non applicables (root)",
)
def test_local_key_unwritable_parent_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    restricted = tmp_path / "restricted"
    restricted.mkdir()
    restricted.chmod(0o500)
    monkeypatch.setenv(KEY_FILE_ENV, str(restricted / "key"))
    try:
        with pytest.raises(ScanError):
            load_local_key()
    finally:
        restricted.chmod(0o700)


def test_local_key_rejects_parent_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``..`` dans l'override réécrirait le chemin de la clé : refus."""
    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "a" / ".." / "b.key"))
    with pytest.raises(ScanError):
        load_local_key()


def test_local_key_write_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    key_path = tmp_path / "partial.key"
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    real_write = os.write

    def broken_write(descriptor: int, data: bytes) -> int:
        if len(data) == 32:
            return 0
        return real_write(descriptor, data)

    monkeypatch.setattr(hashing.os, "write", broken_write)
    with pytest.raises(ScanError):
        load_local_key()
    assert not key_path.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="liens symboliques indisponibles")
def test_local_key_rejects_symlink_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv(KEY_FILE_ENV, str(link / "key"))
    with pytest.raises(ScanError):
        load_local_key()


# --- Anti-ReDoS -------------------------------------------------------------


def test_long_lines_are_processed_linearly(tmp_path: Path) -> None:
    """Aucune regex ne doit exploser sur une ligne proche de la borne 1 Mio."""
    filler = "A" * 1_000_000
    payloads = [
        "eyJ" + filler,
        "-----BEGIN " + filler,
        "sk_live_" + filler,
        "xoxb-" + filler,
        "ghp_" + filler,
        "AKIA" + filler,
        "github_pat_" + filler,
    ]
    for index, payload in enumerate(payloads):
        path = _write(tmp_path, f"long_{index}.txt", payload)
        started = time.perf_counter()
        scan(path)
        elapsed = time.perf_counter() - started
        assert elapsed < 10.0, (index, elapsed)
