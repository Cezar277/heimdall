"""Tests unitaires du scanner T22 (#60) : signatures, exclusions, Finding.

Toutes les valeurs sont synthétiques et dérivées par hachage (aucune clé
réelle). Les tests couvrent chaque signature, les faux positifs du corpus T21,
les exclusions, le confinement, les erreurs fail-closed et le coût linéaire
des regex sur de longues lignes (anti-ReDoS).
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import re
import shutil
import stat
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from support.fake_secrets import fake_token

from heimdall.scanner import detect as detect_module
from heimdall.scanner import exclusions, hashing
from heimdall.scanner.detect import (
    MAX_FILE_BYTES,
    Finding,
    ScanError,
    Scanner,
    _open_flags,
    _validate_relative_path,
    find_candidates,
    scan,
)
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.exclusions import (
    decode_text,
    est_base_vcs,
    est_chemin_hors_perimetre,
)
from heimdall.scanner.finding import validate_relative_path
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


@pytest.mark.parametrize("anchored", [False, True])
@pytest.mark.parametrize("single", [False, True])
def test_size_skip_preserves_confined_readers_and_file_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, anchored: bool, single: bool
) -> None:
    if anchored and not detect_module._DIR_FD_SUPPORTED:
        pytest.skip("directory descriptors required")
    monkeypatch.setattr(detect_module, "_DIR_FD_SUPPORTED", anchored)
    nested = tmp_path / "nested"
    nested.mkdir()
    oversized = nested / "large.txt"
    oversized.write_bytes(b"x" * 100)
    (nested / "small.txt").write_bytes(b"safe\n")
    original_read = os.read

    def bounded_read(descriptor: int, size: int) -> bytes:
        assert os.fstat(descriptor).st_size <= 32, "oversized file must never be read"
        return original_read(descriptor, size)

    monkeypatch.setattr(os, "read", bounded_read)
    skipped: list[str] = []
    scanner = Scanner(
        oversized if single else tmp_path, max_file_bytes=32, skipped_files=skipped, strict=False
    )
    assert scanner.scan() == []
    assert skipped == ["large.txt" if single else "nested/large.txt"]
    assert scanner.files_scanned == (0 if single else 1)
    with pytest.raises(ScanError):
        Scanner(oversized if single else tmp_path, max_file_bytes=32, strict=True).scan()
    with pytest.raises(ScanError):
        Scanner(
            oversized if single else tmp_path,
            max_file_bytes=32,
            skipped_files=[],
            strict=True,
        ).scan()


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
        (8, "credential"),
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
        "service_gitlab",
        "service_google_api",
        "service_google_oauth",
        "service_npm",
        "service_stripe_webhook",
        "service_digitalocean",
        "service_shopify",
        "url_password",
        "authorization_header",
        "credential_double_quoted",
        "credential_single_quoted",
        "credential_unquoted",
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
def test_public_values_are_not_silently_allowlisted(tmp_path: Path, line: str) -> None:
    findings = _scan_lines(tmp_path, line)
    if line.startswith(("UUID =", "SHA256 =", "COMMIT =")):
        assert findings and all(f["source"] == "entropy" for f in findings)
    elif line.startswith("PASSWORD ="):
        assert findings and all(f["type"] == "credential" for f in findings)
    else:
        assert findings == []


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


def test_jwt_payload_above_token_bound_is_fail_closed(tmp_path: Path) -> None:
    """T23 : la borne par jeton refuse aussi les longues charges JWT."""
    jwt = ".".join(
        [
            _b64(b'{"alg":"HS256","typ":"JWT"}'),
            "A" * 9_000,
            _b64(hashlib.sha256(b"heimdall-long-jwt").digest()),
        ]
    )
    with pytest.raises(ScanError):
        _scan_lines(tmp_path, f'JWT = "{jwt}"')


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


@pytest.mark.parametrize("charge", [SLACK_PAYLOAD_MAX + 1, 256])
def test_an_oversized_inner_token_is_a_documented_limit(charge: int) -> None:
    """Limite figée : au-delà de la charge maximale, rien n'est détecté.

    Un jeton plus long que la borne documentée n'est detectable **ni seul
    ni préfixé** : la limite est écrite (et non un secret perdu en
    silence par la neutralisation `xoxe.`). Le comportement est figé ici,
    y compris pour la charge 256 citée par la revue.
    """
    interne = "xapp-" + "a" * charge
    assert len(interne) > SLACK_TOKEN_MAX
    assert find_signature_matches(interne) == ()
    assert find_signature_matches("xoxe." + interne) == ()


@pytest.mark.parametrize(
    ("charge", "attendu"),
    [
        (SLACK_PAYLOAD_MAX, 1),
        (SLACK_PAYLOAD_MAX + 1, 0),
        (256, 0),
    ],
)
def test_the_rotating_bounds_are_frozen_at_scan_level(
    tmp_path: Path, charge: int, attendu: int
) -> None:
    """Revue (LOW) : les bornes Slack sont figées jusqu'au Finding.

    ``xoxe.`` + charge 250 est **un** secret rotatif (un seul Finding, type
    ``slack``) ; au-delà de la borne documentée (251, 256), rien n'est
    détecté. Ce test passe par ``scan()``, pas seulement par le registre :
    la limite reste écrite et observable, jamais un ``[]`` silencieux
    présenté comme une couverture sans borne.
    """
    token = "xoxe.xapp-" + "a" * charge
    _write(tmp_path, "slack.txt", f'SLACK = "{token}"\n')

    findings = scan(tmp_path)
    assert len(findings) == attendu
    if attendu:
        assert findings[0].type == "slack"
        assert findings[0].line == 1


def test_secret_split_across_two_lines_is_detected(tmp_path: Path) -> None:
    """Un secret coupé par un retour à la ligne reste détecté (fenêtre 4 Kio)."""
    secret = fake_token("", 40)
    _write(tmp_path, "split.py", f'aws_secret_access_key =\n"{secret}"\n')
    findings = find_candidates(str(tmp_path))
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "aws"), (1, "credential"),
    ]


def test_split_secret_beyond_the_window_is_fail_closed(tmp_path: Path) -> None:
    """Une affectation non analysable au-delà de 4 Kio est refusée."""
    secret = fake_token("", 40)
    _write(tmp_path, "wide.py", "aws_secret_access_key = " + "x" * 5_000 + f'\n"{secret}"\n')
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_secret_split_by_a_blank_line_is_a_documented_limit(tmp_path: Path) -> None:
    """Limite figée : la fenêtre ne joint que deux lignes contiguës.

    Une ligne vide intercalée sort de la fenêtre : le secret n'est pas
    détecté, conformément à la limite documentée du scanner.
    """
    secret = fake_token("", 40)
    _write(tmp_path, "blank.py", f'aws_secret_access_key =\n\n"{secret}"\n')
    assert find_candidates(str(tmp_path)) == []


def test_secret_split_across_two_contiguous_lines_is_detected(tmp_path: Path) -> None:
    """La fenêtre de deux lignes contiguës couvre le secret réparti sur celles-ci."""
    secret = fake_token("", 40)
    _write(tmp_path, "three.py", f'aws_secret_access_key = "{secret[:20]}\n{secret[20:]}"\n')
    findings = find_candidates(str(tmp_path))
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "aws"), (1, "credential"),
    ]


def test_secret_split_by_more_than_two_newlines_is_a_documented_limit(tmp_path: Path) -> None:
    """Limite figée : au-delà de deux lignes contiguës, la coupure n'est pas vue."""
    secret = fake_token("", 40)
    _write(tmp_path, "gap.py", f'aws_secret_access_key =\n\n\n"{secret}"\n')
    assert find_candidates(str(tmp_path)) == []


# --- Exclusions (#59) -------------------------------------------------------


def test_detect_path_guard_is_the_finding_contract() -> None:
    """Revue (LOW) : la garde de chemin du scanner est celle du contrat #14.

    Fuzz court sur les caractères qui distinguent les deux grammaires : toute
    divergence future (nouveau caractère interdit, longueur, segments) casse
    ce test au lieu de produire un ``FileTarget``/``Finding`` incohérent.
    """
    alphabet = ("a", "/", ".", ":", "\\", "\x00", "\x7f", "\u2028")
    for length in range(4):
        for characters in itertools.product(alphabet, repeat=length):
            chemin = "".join(characters)
            try:
                attendu = validate_relative_path(chemin)
            except ValueError:
                with pytest.raises(ScanError):
                    _validate_relative_path(chemin)
            else:
                assert _validate_relative_path(chemin) == attendu


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


def test_a_real_binary_is_fail_closed(tmp_path: Path) -> None:
    """Un vrai binaire interrompt le scan au lieu d'être ignoré."""
    _write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    with pytest.raises(ScanError):
        scan(tmp_path, strict=True)


def test_scanner_does_not_consult_the_deprecated_binary_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : le nom public ``is_known_binary`` n'a plus d'autorité.

    Le scanner passe par le helper interne de ``decode_text``. Instrumenter le
    nom public (pour lever) ne doit donc pas changer le verdict : un binaire
    connu reste refusé par ``ScanError``, jamais ignoré ni transformé en
    exception arbitraire. Un futur appelant ne peut pas réintroduire un
    contournement nominal en réutilisant ce nom.
    """
    _write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))

    def forbidden(_data: bytes) -> bool:
        raise AssertionError("le scanner ne doit pas appeler is_known_binary")

    monkeypatch.setattr(exclusions, "is_known_binary", forbidden)
    with pytest.raises(ScanError):
        scan(tmp_path, strict=True)


def test_the_deprecated_binary_helper_warns_and_stays_without_authority() -> None:
    """Revue (LOW) : un appel au nom déprécié est signalé, jamais silencieux."""
    data = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
    with pytest.warns(DeprecationWarning):
        assert exclusions.is_known_binary(data) is True


def test_the_deprecated_binary_helper_is_not_exported() -> None:
    """Revue (LOW) : le nom déprécié ne fait pas partie de la surface publique.

    Il reste importable pour compatibilité historique, mais ``__all__`` ne
    l'expose pas : un nouvel appelant ne peut pas le découvrir comme une API
    de périmètre et réintroduire une exclusion par nom.
    """
    assert hasattr(exclusions, "is_known_binary")
    assert "is_known_binary" not in exclusions.__all__
    assert set(exclusions.__all__) == {
        "ARBRES_HORS_PERIMETRE",
        "decode_text",
        "est_base_vcs",
        "est_chemin_hors_perimetre",
    }


def test_gitlink_file_is_scanned_vs_vcs_directory_matrix(tmp_path: Path) -> None:
    """Revue (LOW) : la décision de périmètre est un prédicat booléen figé.

    ``est_base_vcs`` ne classe que les **répertoires** VCS. Un fichier
    régulier ``.git`` (gitlink) n'est jamais hors périmètre, seul un segment
    **parent** ``.git/`` l'est. La matrice est explicite pour qu'aucun futur
    appelant ne réintroduise un régime ambigu.
    """
    assert est_base_vcs(".git") is True
    assert est_base_vcs(".GIT") is True
    assert est_base_vcs(".hg") is True
    assert est_base_vcs(".svn") is True
    assert est_base_vcs("vendor") is False
    assert est_base_vcs(".gitignore") is False

    assert est_chemin_hors_perimetre(".git") is False
    assert est_chemin_hors_perimetre("a/.git") is False
    assert est_chemin_hors_perimetre("a/.git/b.txt") is True
    assert est_chemin_hors_perimetre("vendor/secret.txt") is False

    _write(tmp_path, ".git", "gitdir: ../.git/worktrees/example\n")
    _write(tmp_path, "clean.txt", "x = 1\n")
    assert scan(tmp_path) == []


def test_the_vcs_database_is_not_walked(tmp_path: Path) -> None:
    """``.git/`` n'est pas le contenu du dépôt : il n'est pas parcouru."""
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git")}"')
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    findings = scan(tmp_path)
    assert [finding.file for finding in findings] == ["app.py"]


def test_a_vcs_database_with_a_secret_returns_an_empty_list(tmp_path: Path) -> None:
    """Politique VCS figée : l'historique de ``.git/`` n'est jamais scanné."""
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git-only")}"')
    assert scan(tmp_path) == []
    assert find_candidates(str(tmp_path)) == []


def test_the_vcs_skip_is_counted_and_never_claimed_complete(tmp_path: Path) -> None:
    """Revue (MEDIUM) : l'élagage VCS n'est plus silencieux.

    Un dépôt dont la seule base VCS contient un candidat rend ``[]`` : c'est
    la politique annoncée (l'historique n'est pas le contenu), mais l'appelant
    doit pouvoir distinguer « aucune base VCS » de « base VCS non parcourue ».
    ``Scanner.vcs_ignored`` expose ce compteur, sans chemin ni valeur ; un
    second scan ne cumule pas.
    """
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git-only")}"')
    scanner = Scanner(tmp_path)
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1
    _write(tmp_path, "app.py", "x = 1\n")
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1


def test_vcs_ignored_is_reset_between_scans(tmp_path: Path) -> None:
    """Revue : le compteur décrit **ce** scan, pas l'accumulation des appels.

    Un premier scan sans base VCS vaut 0 ; l'ajout d'un ``.git/`` fait passer
    le second scan à 1 ; sa suppression ramène le troisième à 0. Aucun état
    d'un scan précédent ne fuit dans le suivant.
    """
    scanner = Scanner(tmp_path)
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 0

    _write(tmp_path, ".git/config", f'AWS = "{_aws("git-only")}"')
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1

    shutil.rmtree(tmp_path / ".git")
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 0


def test_files_scanned_describes_the_current_scan(tmp_path: Path) -> None:
    """``files_scanned`` compte le contenu réellement lu, jamais la base VCS.

    Ce compteur rend observable le cas d'un arbre réduit à ``.git/`` (aucun
    fichier de contenu lu) sans transformer un dépôt vide en erreur. Il doit
    être remis à zéro à chaque scan et ne compter que les fichiers dont le
    contenu a été lu et vérifié.
    """
    scanner = Scanner(tmp_path)
    assert scanner.scan() == []
    assert scanner.files_scanned == 0

    _write(tmp_path, "app.py", "x = 1\n")
    assert scanner.scan() == []
    assert scanner.files_scanned == 1

    _write(tmp_path, ".git/config", f'AWS = "{_aws("git-only")}"')
    assert scanner.scan() == []
    assert scanner.files_scanned == 1  # seul app.py est du contenu
    assert scanner.vcs_ignored == 1

    (tmp_path / "app.py").unlink()
    assert scanner.scan() == []
    assert scanner.files_scanned == 0
    assert scanner.vcs_ignored == 1


def test_gitlink_file_and_vcs_directory_scan_matrix(tmp_path: Path) -> None:
    """Matrice gitlink : fichier ``.git`` lu, répertoire ``.git/`` élagué.

    Les trois cas sont figés ensemble : un fichier régulier ``.git``
    (``gitdir: …``) est scanné par contenu ; un répertoire ``.git/`` est
    élagué et **compté** ; un chemin dont un parent est ``.git/`` est refusé
    par le prédicat de défense en profondeur.
    """
    _write(tmp_path, ".git", "gitdir: ../.git/worktrees/example\n")
    _write(tmp_path, "a/.git/b.txt", f'AWS = "{_aws("vcs-dir")}"')
    _write(tmp_path, "a/clean.txt", "x = 1\n")

    assert est_chemin_hors_perimetre(".git") is False
    assert est_chemin_hors_perimetre("a/.git") is False
    assert est_chemin_hors_perimetre("a/.git/b.txt") is True

    scanner = Scanner(tmp_path)
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1

    _write(tmp_path, ".git", f'AWS = "{_aws("gitlink")}"\n')
    findings = scanner.scan()
    assert [finding.file for finding in findings] == [".git"]
    assert scanner.vcs_ignored == 1


def test_a_gitlink_file_is_not_mistaken_for_the_vcs_database(tmp_path: Path) -> None:
    """Revue (MEDIUM) : un fichier ``.git`` de worktree/sous-module est lu.

    Un gitlink légitime (``gitdir: …``) est un **fichier régulier** : il ne
    doit pas être classé hors périmètre comme le répertoire ``.git/``, sinon
    tout dépôt avec worktree ou sous-module sortait en ``ScanError``. Le
    contenu décide : un texte nommé ``.git`` est scanné comme les autres.
    """
    _write(tmp_path, ".git", "gitdir: ../.git/worktrees/example\n")
    _write(tmp_path, "clean.txt", "x = 1\n")
    scanner = Scanner(tmp_path)
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 0

    _write(tmp_path, ".git", f'AWS = "{_aws("gitlink")}"\n')
    assert [finding.file for finding in scan(tmp_path)] == [".git"]


def test_strict_mode_never_changes_the_content_perimeter(tmp_path: Path) -> None:
    """Revue (LOW) : ``strict`` n'ouvre pas un second régime de périmètre.

    Le paramètre reste accepté pour compatibilité avec #29, mais il ne change
    rien : seule la base VCS est élaguée, et tous les fichiers de contenu
    (``vendor/``, ``node_modules/``, lockfile, sortie de build, ``evil.png``
    textuel) sont lus par contenu. Le test fige l'équivalence exacte des
    Findings et des compteurs entre ``strict=True`` et ``strict=False`` :
    aucun futur appelant ne peut croire durcir le scan en passant ce drapeau.
    """
    _write(tmp_path, "app.py", "x = 1\n")
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"\n')
    _write(tmp_path, "node_modules/pkg/index.js", f'AWS = "{_aws("node")}"\n')
    _write(tmp_path, "package-lock.json", f'AWS = "{_aws("lock")}"\n')
    _write(tmp_path, "build/output.js", f'AWS = "{_aws("build")}"\n')
    _write(tmp_path, "evil.png", f'AWS = "{_aws("png-text")}"\n')
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git-only")}"\n')

    strict_scanner = Scanner(tmp_path, strict=True)
    default_scanner = Scanner(tmp_path, strict=False)
    strict_findings = strict_scanner.scan()
    default_findings = default_scanner.scan()

    assert strict_findings == default_findings
    assert scan(tmp_path, strict=True) == scan(tmp_path, strict=False)
    assert strict_scanner.vcs_ignored == default_scanner.vcs_ignored == 1
    assert strict_scanner.files_scanned == default_scanner.files_scanned == 6
    assert [finding.file for finding in strict_findings] == [
        "build/output.js",
        "evil.png",
        "node_modules/pkg/index.js",
        "package-lock.json",
        "vendor/secret.txt",
    ]


def test_a_broken_file_in_the_strict_perimeter_is_fail_closed(tmp_path: Path) -> None:
    """Dans le contenu du dépôt, un fichier illisible reste fatal."""
    _write(tmp_path, "broken.bin", b"\x00\x01\x02not-decodable")
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


# --- Fail-closed dans les arbres de tiers ------------------------------------


def _arbre_de_tiers_avec_un_fichier_illisible(tmp_path: Path) -> Path:
    """Prépare un arbre de tiers contenant un fichier illisible."""
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    bloque = _write(tmp_path, "vendor/bloque.txt", "contenu")
    bloque.chmod(0o000)
    return bloque


def test_a_tier_failure_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier non analysable en arbre de tiers n'est jamais un `[]` propre.

    Un fichier illisible, hors borne, non régulier ou mal nommé dans
    `vendor/` ne doit jamais rendre une liste vide — un **verdict propre
    inventé** alors qu'une partie du périmètre n'a pas été lue. `scan()` et
    `find_candidates()` lèvent `ScanError`.
    """
    _write(tmp_path, "vendor/secret.txt", f'AWS = "{_aws("vendor")}"')
    _write(tmp_path, "vendor/broken.bin", b"\x00\x01\x02not-decodable")
    with pytest.raises(ScanError) as context:
        scan(tmp_path, strict=True)
    assert str(context.value) == "scan impossible : entrée non analysable"
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


def test_an_oversized_tier_file_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Un fichier hors borne en arbre de tiers n'est jamais un `[]` propre."""
    _write(tmp_path, "vendor/huge.txt", b"A" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ScanError):
        scan(tmp_path, strict=True)
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
    finally:
        bloque.chmod(0o600)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_a_walk_error_in_a_tier_tree_never_becomes_a_clean_list(tmp_path: Path) -> None:
    """Une erreur de parcours en arbre de tiers n'est jamais un `[]` propre.

    Le chemin ``_raise_walk_error`` (répertoire illisible) est le même que
    celui d'un fichier illisible : un dépôt dont un sous-arbre n'a pas été
    parcouru lève ``ScanError`` au lieu de rendre une liste vide.
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
    finally:
        bloque.chmod(0o700)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="permissions POSIX")
def test_an_unreadable_tier_directory_at_the_root_never_becomes_a_clean_list(
    tmp_path: Path,
) -> None:
    """Un ``vendor/`` illisible à la racine est fail-closed, jamais un `[]`."""
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "secret.txt").write_text(f'AWS = "{_aws("vendor")}"', encoding="utf-8")
    vendor.chmod(0o000)
    try:
        with pytest.raises(ScanError):
            scan(tmp_path)
        with pytest.raises(ScanError):
            find_candidates(str(tmp_path))
    finally:
        vendor.chmod(0o700)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="liens symboliques indisponibles")
def test_a_symlinked_directory_is_fail_closed(tmp_path: Path) -> None:
    """Un répertoire symlinké interrompt le scan au lieu d'être ignoré."""
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
    with pytest.raises(ScanError):
        scan(repository, strict=True)


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
    assert decode_text(b"", strict=True) == ""
    assert decode_text(b"abc", strict=True) == "abc"
    for encoding in ("utf-8-sig", "utf-16", "utf-32"):
        assert decode_text("AZERTY".encode(encoding), strict=True) == "AZERTY"
    with pytest.raises(ScanError):
        decode_text(b"caf\xe9", strict=True)
    assert decode_text(b"\xef\xbb\xbf", strict=True) == ""


@pytest.mark.parametrize("payload", [b"\xff\xfeA", b"\xef\xbb\xbf\xff", b"\xfe\xff\x00\x00"])
def test_decode_text_fails_closed_on_invalid_bom_text(payload: bytes) -> None:
    with pytest.raises(ScanError):
        decode_text(payload, strict=True)


def test_decode_text_fails_closed_on_ambiguous_nul() -> None:
    with pytest.raises(ScanError):
        decode_text(b"abc\x00def", strict=True)


@pytest.mark.parametrize("magic", [b"\x7fELF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04"])
def test_decode_text_identifies_known_binary_magic(magic: bytes) -> None:
    """Un vrai binaire (majorité non textuelle) reste ignoré par politique."""
    assert decode_text(magic + bytes(range(256))) is None


@pytest.mark.parametrize("magic", [b"\x7fELF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04"])
def test_decode_text_refuses_magic_followed_by_text(magic: bytes) -> None:
    """Une signature binaire suivie de texte clair n'est pas un contournement."""
    with pytest.raises(ScanError):
        decode_text(magic + b"\x00" + b"AKIA" + b"A" * 16, strict=True)


def test_extensionless_known_binary_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "elf", b"\x7fELF" + bytes(range(256)))
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


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


def test_an_ancestor_of_the_root_replaced_by_a_symlink_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un ancêtre remplacé par un lien est refusé avant le walk.

    Le re-``lstat`` du seul dernier segment suivrait un ancêtre symlinké et
    verrait le répertoire cible. Chaque composant du chemin est donc
    re-contrôlé ; le test interdit ``os.walk`` pour prouver que le refus
    intervient avant tout parcours hors racine.
    """
    outside = tmp_path / "outside"
    (outside / "repo").mkdir(parents=True)
    _write(outside / "repo", "leak.py", f'AWS = "{_aws("outside")}"')
    parent = tmp_path / "parent"
    repository = parent / "repo"
    repository.mkdir(parents=True)
    _write(repository, "app.py", "x = 1\n")
    scanner = Scanner(repository)
    parent.rename(tmp_path / "parent.original")
    try:
        parent.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise

    def forbidden_walk(*args: object, **kwargs: object) -> object:
        raise AssertionError("os.walk ne doit pas suivre un ancêtre remplacé")

    monkeypatch.setattr("heimdall.scanner.detect.os.walk", forbidden_walk)
    with pytest.raises(ScanError):
        scanner.scan()


def test_the_root_replaced_by_another_directory_is_fail_closed(
    tmp_path: Path,
) -> None:
    """Revue (LOW) : l'identité de la racine figée détecte un sosie.

    Remplacer la racine par un autre répertoire au même chemin (sans lien)
    change ``st_dev``/``st_ino`` : le scan refuse au lieu de lire un
    périmètre substitué.
    """
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", "x = 1\n")
    scanner = Scanner(repository)
    repository.rename(tmp_path / "repo.original")
    repository.mkdir()
    _write(repository, "other.py", f'AWS = "{_aws("substitute")}"')

    with pytest.raises(ScanError):
        scanner.scan()


def test_a_root_swapped_between_recheck_and_open_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La racine est figée par descripteur : un swap après le re-``lstat`` échoue.

    Il restait une fenêtre entre ``_recheck_root`` et ``os.walk`` : un
    répertoire substitué au même chemin pouvait être parcouru. La racine est
    désormais ouverte en ``O_NOFOLLOW|O_DIRECTORY`` et son identité
    ``(st_dev, st_ino)`` comparée à celle figée. Le test remplace la racine
    **après** le re-contrôle : l'ouverture doit refuser avant toute lecture.
    """
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", "x = 1\n")
    scanner = Scanner(repository)
    original_recheck = Scanner._recheck_root

    def recheck_then_swap(self: Scanner) -> None:
        original_recheck(self)
        repository.rename(tmp_path / "repo.original")
        repository.mkdir()
        _write(repository, "evil.py", f'AWS = "{_aws("swapped")}"')

    monkeypatch.setattr(Scanner, "_recheck_root", recheck_then_swap)
    with pytest.raises(ScanError):
        scanner.scan()


def test_a_root_swapped_after_open_cannot_redirect_the_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un descripteur de racine déjà ouvert ne lit jamais l'arbre substitué.

    Après l'ouverture, la racine est renommée puis remplacée par un répertoire
    contenant un fichier du même nom mais un secret. Le parcours ancré lit le
    fichier d'origine (propre) et ignore le remplaçant : aucune fuite ni faux
    verdict sur l'arbre substitué.
    """
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", "x = 1\n")
    scanner = Scanner(repository)
    original_iter = Scanner._iter_files_at

    def iter_after_swap(
        self: Scanner, dir_fd: int, prefix: str
    ) -> Iterator[tuple[str, Any]]:
        repository.rename(tmp_path / "repo.original")
        repository.mkdir()
        _write(repository, "app.py", f'AWS = "{_aws("substitute")}"')
        yield from original_iter(self, dir_fd, prefix)

    monkeypatch.setattr(Scanner, "_iter_files_at", iter_after_swap)
    assert scanner.scan() == []


def test_extreme_depth_in_anchored_traversal_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un arbre trop profond lève ``ScanError``, jamais une exception brute."""
    _write(tmp_path, "app.py", "x = 1\n")
    scanner = Scanner(tmp_path)

    def too_deep(self: Scanner, dir_fd: int, prefix: str) -> Iterator[tuple[str, Any]]:
        raise RecursionError
        yield from ()  # pragma: no cover - le générateur échoue avant tout yield

    monkeypatch.setattr(Scanner, "_iter_files_at", too_deep)
    with pytest.raises(ScanError):
        scanner.scan()


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


def test_a_root_replaced_by_a_symlink_before_the_walk_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La racine est re-vérifiée par ``lstat`` juste avant ``os.walk`` (TOCTOU).

    Un remplacement furtif de la racine par un lien symbolique entre
    ``Scanner.__init__`` et le parcours ne doit jamais être suivi. Le test
    interdit aussi l'appel à ``os.walk`` : la garde ``lstat`` doit refuser
    avant même le parcours.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "leak.py", f'AWS = "{_aws("outside")}"')
    repository = tmp_path / "repo"
    repository.mkdir()
    _write(repository, "app.py", "x = 1\n")
    scanner = Scanner(repository)
    repository.rename(tmp_path / "repo.original")
    try:
        repository.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise

    def forbidden_walk(*args: object, **kwargs: object) -> object:
        raise AssertionError("os.walk ne doit pas suivre une racine remplacée")

    monkeypatch.setattr("heimdall.scanner.detect.os.walk", forbidden_walk)
    with pytest.raises(ScanError):
        scanner.scan()


def test_a_single_file_parent_replaced_by_a_symlink_before_reading_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : le mode fichier unique re-vérifie sa racine parente.

    Le re-``lstat`` de ``_iter_files`` ne couvre que le mode arbre. En mode
    fichier unique, remplacer le répertoire parent par un lien symbolique
    entre ``__init__`` et ``scan()`` ne doit jamais être suivi : la racine est
    re-contrôlée avant la moindre lecture de fichier.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "leak.py", f'AWS = "{_aws("outside")}"')
    repository = tmp_path / "repo"
    repository.mkdir()
    target = _write(repository, "one.py", "x = 1\n")
    scanner = Scanner(target)
    repository.rename(tmp_path / "repo.original")
    try:
        repository.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise

    def forbidden_read(_self: Scanner, _path: Path) -> tuple[str, int]:
        raise AssertionError("aucun fichier ne doit être lu après le remplacement")

    monkeypatch.setattr(Scanner, "_read_text", forbidden_read)
    with pytest.raises(ScanError):
        scanner.scan()


def test_symlinks_are_fail_closed(tmp_path: Path) -> None:
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
    with pytest.raises(ScanError):
        find_candidates(str(repository))


def test_directory_is_symlink_oserror_raises_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `os.walk` avec `is_symlink` dossier qui lève OSError -> ScanError.

    En cas d'erreur système lors du contrôle d'un sous-répertoire (permission,
    course, composant illisible), le scanner bibliothèque doit lever ScanError
    (contrat fail-closed), jamais une OSError brute.
    """
    repository = tmp_path / "repo"
    repository.mkdir()
    subdir = repository / "sub"
    subdir.mkdir()
    _write(subdir, "file.py", "x = 1\n")
    scanner = Scanner(repository)

    real_is_symlink = Path.is_symlink

    def failing_is_symlink(self: Path) -> bool:
        if self == subdir:
            raise OSError("permission denied")
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", failing_is_symlink)
    with pytest.raises(ScanError):
        scanner.scan()


# --- Lecture, confinement et fail-closed ------------------------------------


def test_single_file_root_uses_a_relative_name(tmp_path: Path) -> None:
    path = _write(tmp_path, "one.py", f'AWS = "{_aws()}"')
    findings = scan(path)
    assert isinstance(findings[0], Finding)
    assert [finding.file for finding in findings] == ["one.py"]


def test_scanner_refuses_an_expired_deadline(tmp_path: Path) -> None:
    """Revue (LOW) : la deadline arbre est fail-closed même sans fichier lu.

    La CLI borne le mode arbre comme `--staged` ; le scanner bibliothèque
    accepte une échéance optionnelle et refuse avant de rendre un résultat.
    """
    _write(tmp_path, "app.py", "x = 1\n")
    with pytest.raises(ScanError):
        Scanner(tmp_path).scan(deadline=time.monotonic() - 1)


def test_scan_text_checks_deadline_intra_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un seul fichier dense ne peut pas ignorer la deadline.

    L'horloge expire au premier candidat : `_append` doit refuser avant le
    hachage HMAC, pas attendre le plafond de 10 000 Findings.
    """
    _write(tmp_path, "dense.py", "x = 1\n")
    appels = [0]

    def monotonic() -> float:
        appels[0] += 1
        return 0.0 if appels[0] == 1 else 2.0

    monkeypatch.setattr("heimdall.scanner.detect.time.monotonic", monotonic)
    with pytest.raises(ScanError):
        Scanner(tmp_path)._scan_text(
            f'AWS = "{_aws()}"',
            "dense.py",
            deadline=1.0,
        )


def test_invalid_utf8_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "latin1.py", f'AWS = "{_aws()}"'.encode("ascii") + b" \xff\n")
    with pytest.raises(ScanError):
        find_candidates(str(tmp_path))


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
        if calls == 2:
            # Le premier `fstat` porte sur la racine ouverte en `O_DIRECTORY` ;
            # le suivant est celui du fichier, tronqué après son `stat` :
            # même inode, taille réduite, date de modification inchangée.
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


def test_a_file_truncated_between_the_stat_and_the_fstat_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une troncature entre le ``stat`` et le ``fstat`` est refusée avant lecture.

    Le fichier conserve son inode : seule la comparaison de taille et de
    ``st_mtime_ns`` entre ``before`` et ``after`` voit la course. Sans elle,
    la lecture du contenu restant serait un scan partiel, donc un verdict
    propre inventé.
    """
    path = _write(tmp_path, "truncated.txt", f'AWS = "{_aws("truncated")}"\n')
    real_open = os.open

    def truncating_open(file: object, *args: object, **kwargs: object) -> int:
        if str(file).endswith("truncated.txt"):
            os.truncate(file, path.stat().st_size // 2)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("heimdall.scanner.detect.os.open", truncating_open)
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
        scan("a\x00b")
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_an_empty_root_is_fail_closed() -> None:
    """Un chemin vide n'est pas « le répertoire courant » : il est refusé.

    La docstring de ``_resolve_root`` promet le refus du chemin vide ; sans
    garde explicite, ``Path("")`` vaut ``.`` et le scanner analyserait le
    répertoire courant à l'insu de l'appelant.
    """
    for api in (scan, find_candidates):
        with pytest.raises(ScanError) as context:
            api("")
        assert str(context.value) == "scan impossible : entrée non analysable"


def test_a_non_path_root_is_fail_closed() -> None:
    """Un type qui n'est pas un chemin ne fuit pas une ``TypeError`` nue."""
    with pytest.raises(ScanError) as context:
        scan(42)  # type: ignore[arg-type]
    assert str(context.value) == "scan impossible : entrée non analysable"


def test_open_flags_are_read_only_non_blocking_and_never_follow_links() -> None:
    """L'ouverture ne suit pas un lien et ne bloque jamais sur un FIFO."""
    flags = _open_flags()
    assert flags & os.O_WRONLY == 0
    assert flags & os.O_RDWR == 0
    assert flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)
    assert flags & getattr(os, "O_NONBLOCK", 0) == getattr(os, "O_NONBLOCK", 0)


def test_findings_are_deterministic_and_sorted(tmp_path: Path) -> None:
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


def test_read_text_close_failure_is_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `os.close` en échec pendant la lecture → `ScanError`."""
    target = tmp_path / "code.py"
    target.write_text("password = 'x'\n", encoding="utf-8")
    scanner = Scanner(tmp_path)
    real_close = os.close

    def boom(fd: int) -> None:
        real_close(fd)
        raise OSError("EBADF simulé")

    monkeypatch.setattr(os, "close", boom)
    with pytest.raises(ScanError):
        scanner._read_text(target)


def test_key_close_failures_are_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `os.close` en échec sur le fichier de clé → `ScanError`."""
    key_path = tmp_path / "snippet.key"
    created = hashing._create_key(key_path)
    assert created is not None and len(created) == hashing.KEY_BYTES
    real_close = os.close

    def boom(fd: int) -> None:
        real_close(fd)
        raise OSError("EBADF simulé")

    monkeypatch.setattr(os, "close", boom)
    with pytest.raises(ScanError):
        hashing._read_key(key_path)
    with pytest.raises(ScanError):
        hashing._create_key(tmp_path / "other.key")


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
        with pytest.raises(ScanError):
            scan(path, strict=True)
        elapsed = time.perf_counter() - started
        assert elapsed < 10.0, (index, elapsed)
