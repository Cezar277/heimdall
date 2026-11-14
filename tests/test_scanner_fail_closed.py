"""Abus E-01 : aucun contenu écarté ne peut produire un verdict propre."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.fake_secrets import fake_token
from support.git_repo import GitRepo
from typer.testing import CliRunner

import heimdall.cli.scan as scan_module
from heimdall.cli.history import collect_history
from heimdall.cli.main import app
from heimdall.cli.scan import collect
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner.detect import MAX_FILE_BYTES, Scanner, find_candidates, scan
from heimdall.scanner.errors import ScanError
from heimdall.scanner.policy import ScanSkip, prepare_text

SYNTHETIC = fake_token("ghp_", 36)


@pytest.fixture(autouse=True)
def _hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "00" * 32)


@pytest.fixture
def repo() -> Iterator[GitRepo]:
    repository = GitRepo("heimdall-t229-abuse-")
    try:
        repository.write("readme", "safe\n")
        repository.commit_all("base")
        yield repository
    finally:
        repository.close()


def _payload(kind: str) -> bytes:  # noqa: PLR0911 - charges adverses distinctes
    token = f'TOKEN="{SYNTHETIC}"\n'.encode()
    if kind == "nul":
        return b"\x00" + token + b"\n#"
    if kind == "noise":
        return token + b"\x01" * 100
    if kind == "cp1252_noise":
        return b"# caf\xe9\n" + token + b"\x01" * 100
    if kind == "too_large":
        return b"x " * (MAX_FILE_BYTES // 2) + token
    if kind == "long_token":
        return ("A" * 5000 + SYNTHETIC + "B" * 5000).encode()
    if kind == "multiline":
        return (" " * 4080 + "ghp_\n" + "a" * 36 + "\n").encode()
    return b"OTTO" + b"\x00\x01" * 50


@pytest.mark.parametrize("scope", ["tree", "staged", "diff", "history"])
@pytest.mark.parametrize(
    "kind", ["nul", "noise", "cp1252_noise", "too_large", "long_token", "multiline", "font"]
)
def test_ci_cannot_greenlight_a_hidden_secret(repo: GitRepo, scope: str, kind: str) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write_bytes("payload.dat", _payload(kind))
    repo.stage("payload.dat")
    if scope in {"diff", "history"}:
        repo.git("commit", "-qm", "synthetic payload")
    if scope == "history":
        args = ["deep-scan", "--ci", "--json", str(repo.root)]
    else:
        args = ["scan", "--ci", "--no-allowlist", "--json", str(repo.root)]
        if scope == "staged":
            args.append("--staged")
        elif scope == "diff":
            args.extend(["--diff", base])
    result = CliRunner().invoke(app, args)
    assert result.exit_code in {1, 2}, result.output
    assert SYNTHETIC not in result.output
    report = json.loads(result.stdout)
    if kind in {"noise", "cp1252_noise"}:
        assert result.exit_code == 1
        assert report["findings"]
    else:
        assert result.exit_code == 2
        assert report["complete"] is False


@pytest.mark.parametrize("ci", [False, True])
def test_symlink_and_partial_local_runs_are_never_clean(repo: GitRepo, ci: bool) -> None:
    outside = repo.root.parent / "outside.py"
    outside.write_text(SYNTHETIC, encoding="utf-8")
    (repo.root / "link.py").symlink_to(outside)
    args = ["scan", "--json", "--no-allowlist", str(repo.root)]
    result = CliRunner().invoke(app, [*args, "--ci"] if ci else args)
    assert result.exit_code == 2
    assert json.loads(result.stdout)["skipped"][0]["reason"] == "symlink"
    assert SYNTHETIC not in result.output


@pytest.mark.parametrize("api", ["scanner", "scan", "find_candidates", "collect", "history"])
def test_library_defaults_are_strict(repo: GitRepo, api: str) -> None:
    repo.write_bytes("payload.dat", _payload("nul"))
    repo.commit_all("synthetic payload")
    with pytest.raises(ScanError):
        if api == "scanner":
            Scanner(repo.root).scan()
        elif api == "scan":
            scan(repo.root)
        elif api == "find_candidates":
            find_candidates(str(repo.root))
        elif api == "collect":
            collect(repo.root, staged=False)
        else:
            collect_history(repo.root, ci=True)


@pytest.mark.parametrize("scope", ["tree", "staged", "diff", "history"])
def test_partial_report_with_a_finding_returns_one(repo: GitRepo, scope: str) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write_bytes("binary.dat", _payload("font"))
    repo.write("app.py", f'TOKEN="{SYNTHETIC}"\n')
    repo.stage("binary.dat", "app.py")
    if scope in {"diff", "history"}:
        repo.git("commit", "-qm", "synthetic payload")
    if scope == "history":
        args = ["deep-scan", "--ci", "--json", str(repo.root)]
    else:
        args = ["scan", "--ci", "--no-allowlist", "--json", str(repo.root)]
        if scope == "staged":
            args.append("--staged")
        elif scope == "diff":
            args.extend(["--diff", base])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["findings"]
    assert report["complete"] is False
    assert SYNTHETIC not in result.output


@pytest.mark.parametrize("limit", [32, MAX_FILE_BYTES])
def test_oversized_files_consume_the_tree_volume_budget(tmp_path: Path, limit: int) -> None:
    for name in ("a", "b"):
        (tmp_path / name).write_bytes(b"x" * (limit + 1))
    scanner = Scanner(tmp_path, strict=False, max_file_bytes=limit, max_bytes=2 * limit)
    with pytest.raises(ScanError):
        scanner.scan()


@pytest.mark.parametrize("limit", [32, MAX_FILE_BYTES])
def test_oversized_blobs_consume_the_staged_volume_budget(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    for name in ("a", "b"):
        repo.write_bytes(name, b"x" * (limit + 1))
        repo.stage(name)
    monkeypatch.setattr(scan_module, "MAX_FILE_BYTES", limit)
    monkeypatch.setattr(scan_module, "MAX_STAGED_BYTES", 2 * limit)
    monkeypatch.setattr(
        GitAccess, "blob_bytes", lambda *args, **kwargs: pytest.fail("oversized read")
    )
    with pytest.raises(ScanError):
        collect(repo.root, staged=True, strict=False)


@pytest.mark.parametrize("command", ["scan", "deep-scan"])
def test_partial_local_command_is_not_clean(repo: GitRepo, command: str) -> None:
    repo.write_bytes("binary.dat", _payload("font"))
    repo.commit_all("binary")
    options = ["--no-allowlist"] if command == "scan" else ["--no-llm"]
    result = CliRunner().invoke(app, [command, "--json", *options, str(repo.root)])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False


def test_megabyte_of_long_tokens_is_bounded_and_keeps_line_numbers() -> None:
    text = ("A" * 5000 + "\n") * 200
    skipped: list[ScanSkip] = []
    started = time.monotonic()
    cleaned = prepare_text(text, "payload.dat", strict=False, skipped=skipped)
    assert time.monotonic() - started < 5
    assert len(cleaned) == len(text)
    assert cleaned.count("\n") == text.count("\n")
    assert skipped == [
        ScanSkip("payload.dat", "long_token", 1),
        ScanSkip("payload.dat", "multiline_limit", 1),
    ]


def test_long_token_trace_uses_the_actual_later_line() -> None:
    skipped: list[ScanSkip] = []
    prepare_text("safe\nsafe\n" + "A" * 5000, "payload.dat", strict=False, skipped=skipped)
    assert next(item for item in skipped if item.reason == "long_token").line == 3
