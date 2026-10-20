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
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from support.fake_secrets import fake_token

from heimdall.scanner.detect import (
    MAX_FILE_BYTES,
    Finding,
    ScanError,
    find_candidates,
    scan,
)
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.exclusions import (
    is_binary,
    is_excluded,
    is_excluded_directory,
)
from heimdall.scanner.hashing import KEY_ENV, KEY_FILE_ENV, SnippetHasher, load_local_key
from heimdall.scanner.signatures import SIGNATURES, find_signature_matches

ROOT = Path(__file__).resolve().parents[1]
FINDING_SCHEMA = ROOT / "schemas" / "finding.schema.json"


@pytest.fixture(autouse=True)
def _fixed_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clé fixe en mémoire : aucun test ne touche au dépôt ni au HOME."""
    monkeypatch.setenv(KEY_ENV, "42" * 32)


def _aws(seed: str = "aws") -> str:
    return "AK" + "IA" + hashlib.sha256(f"heimdall-t22-{seed}".encode()).hexdigest()[:16].upper()


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


def test_duplicate_same_type_on_one_line_is_reported_once(tmp_path: Path) -> None:
    findings = _scan_lines(tmp_path, f'A = "{_aws("a")}"; B = "{_aws("b")}"')
    assert [(finding["line"], finding["type"]) for finding in findings] == [(1, "aws")]


# --- Exclusions (#59) -------------------------------------------------------


def test_exclusions_cover_gitignore_lockfiles_vendor_and_binaries() -> None:
    for path in (
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
    assert not is_excluded_directory("src")
    assert is_binary(b"abc\x00def")
    assert not is_binary(b"abc")


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
    _write(tmp_path, "binary_noext", (f'AWS = "{_aws("nul")}"\n').encode() + b"\x00")
    _write(tmp_path, "script", f'AWS = "{_aws("script")}"')

    findings = find_candidates(str(tmp_path))
    assert [(finding["file"], finding["type"]) for finding in findings] == [
        (".env", "stripe"),
        ("app.py", "aws"),
        ("deploy.pem", "pem"),
        ("requirements.txt", "aws"),
        ("script", "aws"),
    ]


def test_case_insensitive_excluded_directory(tmp_path: Path) -> None:
    _write(tmp_path, "VENDOR/lib.py", f'AWS = "{_aws("upper")}"')
    _write(tmp_path, "app.py", f'AWS = "{_aws()}"')
    assert [finding["file"] for finding in find_candidates(str(tmp_path))] == ["app.py"]


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
