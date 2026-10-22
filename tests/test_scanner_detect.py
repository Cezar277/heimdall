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
    ScanError,
    _validate_relative_path,
    find_candidates,
    scan,
)
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.exclusions import (
    decode_text,
    is_excluded,
    is_excluded_directory,
)
from heimdall.scanner.finding import validate_relative_path
from heimdall.scanner.hashing import KEY_ENV, KEY_FILE_ENV, SnippetHasher, load_local_key
from heimdall.scanner.signatures import SIGNATURES, find_signature_matches

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
    token = "xoxe." + fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "{token}"')
    # Le registre #54 signale les deux formes emboîtées (rotatif + app) :
    # doublon acceptable (même ligne, même type), jamais un manqué. Exclure
    # le `.` devant `xapp-` créerait une évasion par préfixe (`.xapp-…`).
    assert [(finding["line"], finding["type"]) for finding in findings] == [
        (1, "slack"),
        (1, "slack"),
    ]


def test_dot_prefixed_app_token_is_still_detected(tmp_path: Path) -> None:
    """Non-régression évasion par préfixe : `.xapp-…` reste signalé."""
    token = fake_token("xapp-", 24)
    findings = _scan_lines(tmp_path, f'SLACK = "evil.{token}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "slack")]


def test_unknown_slack_family_is_not_reported(tmp_path: Path) -> None:
    """Limite documentée : une famille Slack non publiée n'est pas couverte."""
    token = fake_token("xoxo-", 24)
    assert _scan_lines(tmp_path, f'SLACK = "{token}"') == []


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


# --- Exclusions (#59) -------------------------------------------------------


def test_exclusions_cover_gitignore_lockfiles_vendor_and_binaries() -> None:
    for path in (
        ".coverage",
        ".gitignore",
        ".git/config",
        "package-lock.json",
        "poetry.lock",
        "vendor/lib.py",
        "node_modules/pkg/index.js",
        "Vendor/lib.py",
        "image.png",
        "archive.zip",
    ):
        assert is_excluded(path), path
    for path in (".env", "app.py", "deploy.pem", "requirements.txt", "notes"):
        assert not is_excluded(path), path
    assert is_excluded_directory("VENDOR")
    assert is_excluded_directory(".venv")
    assert not is_excluded_directory("env")
    assert not is_excluded_directory("src")
    assert not is_excluded("")
    # Revue (LOW) : en strict, un suffixe binaire n'exclut plus à lui seul ;
    # le contenu décide (un texte mal nommé doit être scanné).
    assert not is_excluded("image.png", strict=True)
    assert is_excluded(".coverage", strict=True)
    assert is_excluded("node_modules/pkg/index.js", strict=True)


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


def test_scan_skips_excluded_files_but_scans_env_and_pem(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    _write(tmp_path, ".env", f'STRIPE = "{_stripe()}"')
    _write(tmp_path, "deploy.pem", _pem_header())
    _write(tmp_path, "requirements.txt", f'AWS = "{_aws("req")}"')
    _write(tmp_path, "vendor/lib.py", f'AWS = "{_aws("vendor")}"')
    _write(tmp_path, "node_modules/pkg/index.js", f'AWS = "{_aws("node")}"')
    _write(tmp_path, ".git/config", f'AWS = "{_aws("git")}"')
    _write(tmp_path, "package-lock.json", f'AWS = "{_aws("lock")}"')
    _write(tmp_path, ".gitignore", f'AWS = "{_aws("ignore")}"')
    _write(tmp_path, "image.png", f'AWS = "{_aws("image")}"')
    _write(tmp_path, "blob.bin", f'AWS = "{_aws("blob")}"')
    _write(tmp_path, "script", f'AWS = "{_aws("script")}"')

    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        (".env", "stripe"),
        ("app.py", "aws"),
        ("deploy.pem", "pem"),
        ("requirements.txt", "aws"),
        ("script", "aws"),
    ]


def test_env_directory_is_scanned_but_virtualenvs_are_excluded(tmp_path: Path) -> None:
    """"env" n'est pas un virtualenv par convention : ne jamais le sauter."""
    _write(tmp_path, "env/app.py", f'AWS = "{_aws("env")}"')
    _write(tmp_path, ".venv/lib.py", f'AWS = "{_aws("dotvenv")}"')
    _write(tmp_path, "venv/lib.py", f'AWS = "{_aws("venv")}"')
    _write(tmp_path, "virtualenv/lib.py", f'AWS = "{_aws("virtualenv")}"')
    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        ("env/app.py", "aws")
    ]


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


def test_case_insensitive_excluded_directory(tmp_path: Path) -> None:
    _write(tmp_path, "VENDOR/lib.py", f'AWS = "{_aws("upper")}"')
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    assert [finding["file"] for finding in find_candidates(str(tmp_path))] == ["app.py"]


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
