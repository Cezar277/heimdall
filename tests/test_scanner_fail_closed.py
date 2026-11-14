"""Abus E-01 : aucun contenu écarté ne peut produire un verdict propre."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.fake_secrets import fake_token
from support.git_repo import GitRepo
from test_cli_scan import _scan_validator
from typer.testing import CliRunner

import heimdall.cli.history as history_module
import heimdall.cli.main as main_module
import heimdall.cli.scan as scan_module
import heimdall.scanner.detect as detect_module
from heimdall.cli.cold_start import ColdStartReport
from heimdall.cli.history import collect_history
from heimdall.cli.main import app
from heimdall.cli.scan import ScanReport, collect, render_json
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner import entropy_detection, limits, policy, signature_engine
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.detect import MAX_FILE_BYTES, Scanner, find_candidates, scan
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.policy import ScanSkip, prepare_text, skip_file

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
    if kind == "cp1252_split":
        return token[:15] + b"\x81" + token[15:]
    if kind == "too_large":
        return b"x " * (MAX_FILE_BYTES // 2) + token
    if kind == "long_token":
        return ("A" * 5000 + SYNTHETIC + "B" * 5000).encode()
    if kind == "multiline":
        return (" " * 4080 + "ghp_\n" + "a" * 36 + "\n").encode()
    return b"OTTO" + b"\x00\x01" * 50


@pytest.mark.parametrize("scope", ["tree", "staged", "diff", "history"])
@pytest.mark.parametrize(
    "kind",
    [
        "nul", "noise", "cp1252_noise", "cp1252_split",
        "too_large", "long_token", "multiline", "font",
    ],
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


def test_all_4k_bounds_share_one_source() -> None:
    assert limits.TEXT_WINDOW_BYTES == 4096
    assert limits.MAX_TOKEN_LENGTH == limits.TEXT_WINDOW_BYTES
    assert limits.MULTILINE_WINDOW == limits.TEXT_WINDOW_BYTES
    assert policy.TEXT_WINDOW_BYTES == limits.TEXT_WINDOW_BYTES
    assert entropy_detection.MAX_TOKEN_LENGTH == limits.TEXT_WINDOW_BYTES
    assert detect_module.MULTILINE_WINDOW == limits.TEXT_WINDOW_BYTES
    assert signature_engine.MULTILINE_WINDOW == limits.TEXT_WINDOW_BYTES


def test_megabyte_of_long_tokens_is_bounded_and_keeps_line_numbers() -> None:
    text = ("A" * 5000 + "\n") * 200
    skipped: list[ScanSkip] = []
    started = time.monotonic()
    cleaned = prepare_text(text, "payload.dat", strict=False, skipped=skipped)
    assert time.monotonic() - started < 5
    assert len(text) <= len(cleaned) <= 40 * len(text)
    assert cleaned.count("\n") == text.count("\n")
    assert skipped == [
        ScanSkip("payload.dat", "long_token", 1),
        ScanSkip("payload.dat", "multiline_limit", 1),
    ]


def test_long_token_trace_uses_the_actual_later_line() -> None:
    skipped: list[ScanSkip] = []
    prepare_text("safe\nsafe\n" + "A" * 5000, "payload.dat", strict=False, skipped=skipped)
    assert next(item for item in skipped if item.reason == "long_token").line == 3
    second_skips: list[ScanSkip] = []
    prepare_text("safe\n" + "B" * 5000, "second.dat", strict=False, skipped=second_skips)
    assert next(item for item in second_skips if item.reason == "long_token").line == 2


def test_cold_start_checks_inner_coverage_without_legacy_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = ColdStartReport(
        scan=ScanReport(
            scope="working-tree", findings=(), skipped=(ScanSkip("image.png", "binary"),)
        ),
        opinions=(),
        skipped_files=(),
    )
    monkeypatch.setattr(main_module, "collect_cold_start", lambda *args, **kwargs: report)
    result = CliRunner().invoke(app, ["cold-start", "--ci", "--json", "."])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False


@pytest.mark.parametrize("helper", ["tree", "staged", "diff", "changes"])
def test_private_scan_helpers_are_strict_by_default(repo: GitRepo, helper: str) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write_bytes("payload.dat", _payload("nul"))
    repo.stage("payload.dat")
    if helper == "diff":
        repo.git("commit", "-qm", "synthetic payload")
    with pytest.raises(ScanError):
        if helper == "tree":
            scan_module._collect_tree(repo.root)
        elif helper == "staged":
            scan_module._collect_staged(repo.root)
        elif helper == "diff":
            scan_module._collect_diff(repo.root, base=base)
        else:
            access = GitAccess(repo.root)
            scan_module._scan_changes(
                access,
                access.staged_changes(),
                Allowlist.empty(),
                time.monotonic() + 30,
            )


def test_history_oversized_blobs_consume_volume_without_being_read(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo.write_bytes("a", b"x" * 100)
    repo.write_bytes("b", b"y" * 100)
    repo.commit_all("two oversized blobs")
    oversized = {repo.git_output("rev-parse", f"HEAD:{name}").strip() for name in ("a", "b")}
    original = GitAccess.blob_bytes

    def read(access: GitAccess, oid: str, **kwargs: object) -> bytes:
        assert oid not in oversized, "oversized historical blob read"
        return original(access, oid, **kwargs)

    monkeypatch.setattr(GitAccess, "blob_bytes", read)
    monkeypatch.setattr(history_module, "MAX_READ_BYTES", 150)
    with pytest.raises(ScanError, match="limite historique dépassée"):
        collect_history(repo.root, ci=True, strict=False, max_file_bytes=32)
    monkeypatch.setattr(history_module, "MAX_READ_BYTES", 250)
    report = collect_history(repo.root, ci=True, strict=False, max_file_bytes=32)
    assert report.bytes_scanned == len(b"safe\n")
    assert report.bytes_budgeted == report.bytes_scanned + 200
    assert not report.complete
    payload = json.loads(history_module.render_history(report, json_output=True))
    assert payload["bytes_scanned"] < payload["bytes_budgeted"] == 205
    assert "5 octet(s) lu(s), 205 octet(s) imputé(s) au budget" in (
        history_module.render_history(report)
    )


@pytest.mark.parametrize("reason", ["binary", "too_large", "text"])
def test_staged_skip_traces_have_a_hard_limit(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    data = b"A" * 5000 + b"\n" if reason == "text" else _payload("font")
    for name in ("a", "b"):
        repo.write_bytes(name, data)
        repo.stage(name)
    monkeypatch.setattr(scan_module, "MAX_STAGED_FINDINGS", 1)
    if reason == "too_large":
        monkeypatch.setattr(scan_module, "MAX_FILE_BYTES", 32)
    with pytest.raises(ScanError):
        collect(repo.root, staged=True, strict=False)


def test_private_scan_rejects_an_already_overfull_skip_collector(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "MAX_STAGED_FINDINGS", 1)
    with pytest.raises(ScanError):
        scan_module._scan_changes(
            GitAccess(repo.root),
            (),
            Allowlist.empty(),
            time.monotonic() + 30,
            strict=False,
            skipped=[ScanSkip("a", "binary"), ScanSkip("b", "binary")],
        )


def test_decoder_is_strict_by_default_and_tolerance_is_explicit() -> None:
    with pytest.raises(ScanError):
        decode_text(b"caf\xe9")
    assert decode_text(b"caf\xe9", strict=False) == "café"


@pytest.mark.parametrize("fallback", [False, True])
def test_tree_preprocessing_keeps_skip_collector_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    for name in ("a", "b"):
        (tmp_path / name).write_text("A" * 5000 + "\n", encoding="utf-8")
    if fallback:
        monkeypatch.setattr(detect_module, "_DIR_FD_SUPPORTED", False)
    scanner = Scanner(tmp_path, strict=False, max_files=2)
    with pytest.raises(ScanError):
        scanner.scan()
    assert len(scanner.skipped) == 2
    assert {item.file for item in scanner.skipped} == {"a"}


class _EmptyPath:
    def __fspath__(self) -> str:
        return ""


@pytest.mark.parametrize("api", ["scanner", "collect"])
@pytest.mark.parametrize("kind", ["str", "pathlike"])
def test_raw_empty_roots_are_rejected_before_path_normalization(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch, api: str, kind: str
) -> None:
    monkeypatch.chdir(repo.root)
    root = "" if kind == "str" else _EmptyPath()
    with pytest.raises(ScanError):
        if api == "scanner":
            Scanner(root).scan()
        else:
            collect(root, staged=False)


def test_normalized_dot_paths_remain_valid_explicit_current_directory(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo.root)
    assert Path("") == Path(".")
    assert os.fspath(Path("")) == "."
    assert Scanner(Path(".")).scan() == []
    assert collect(Path(""), staged=False).complete


@pytest.mark.parametrize("command", ["scan", "cold-start", "deep-scan"])
def test_cli_rejects_empty_root_argument(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    monkeypatch.chdir(repo.root)
    result = CliRunner().invoke(app, [command, "--ci", ""])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_complete_field_is_required_and_partial_requires_skipped() -> None:
    validator = _scan_validator()
    assert validator.schema["properties"]["complete"]["default"] is True
    complete = json.loads(render_json(ScanReport(scope="working-tree", findings=())))
    validator.validate(complete)
    assert complete["complete"] is True
    assert complete["skipped"] == []
    assert complete["skipped_count"] == 0
    without_complete = dict(complete)
    without_complete.pop("complete")
    assert not validator.is_valid(without_complete)
    partial = json.loads(
        render_json(
            ScanReport(
                scope="working-tree", findings=(), skipped=(ScanSkip("image.png", "binary"),)
            )
        )
    )
    validator.validate(partial)
    assert partial["complete"] is False
    assert partial["count"] == 0
    assert not (partial["count"] == 0 and partial["complete"] is True)
    partial_without_skipped = dict(partial)
    partial_without_skipped.pop("skipped")
    assert not validator.is_valid(partial_without_skipped)
    assert not validator.is_valid(dict(partial, skipped=[], skipped_count=0))


@pytest.mark.parametrize("byte", [0x81, 0x8D, 0x8F, 0x90, 0x9D])
def test_undefined_cp1252_bytes_are_never_replaced_silently(byte: int) -> None:
    data = SYNTHETIC[:15].encode() + bytes([byte]) + SYNTHETIC[15:].encode()
    assert decode_text(data, strict=False) is None
    with pytest.raises(ScanError):
        decode_text(data)


def test_trace_and_file_counts_are_explicit(repo: GitRepo) -> None:
    repo.write("payload.dat", "A" * 5000 + "\n")
    result = CliRunner().invoke(app, ["scan", "--ci", "--json", "--no-allowlist", str(repo.root)])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["skipped_count"] == 1
    assert len(payload["skipped"]) == 2
    assert "2 exclusion(s) de contenu, 1 fichier(s) concerné(s)" in result.stderr


def test_partial_human_report_ends_with_blocking_verdict(repo: GitRepo) -> None:
    repo.write_bytes("payload.dat", _payload("cp1252_split"))
    result = CliRunner().invoke(app, ["scan", "--no-allowlist", str(repo.root)])
    assert result.exit_code == 2
    assert result.stdout.splitlines()[-1] == "ANALYSE PARTIELLE : ne pas déployer (code 2)."
    assert SYNTHETIC not in result.output


@pytest.mark.parametrize("scope", ["tree", "staged", "diff"])
@pytest.mark.parametrize("trace_count", [1, 2])
def test_partial_files_are_not_counted_as_fully_scanned(
    repo: GitRepo, scope: str, trace_count: int,
) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write("partial.dat", "A" * 5000 + ("\n" if trace_count == 2 else ""))
    repo.write("complete.dat", "safe\n")
    repo.stage("partial.dat", "complete.dat")
    if scope == "diff":
        repo.git("commit", "-qm", "changes")
    report = collect(
        repo.root, staged=scope == "staged", diff=base if scope == "diff" else None,
        ci=True, allowlist=Allowlist.empty(), strict=False,
    )
    assert len(report.skipped) == trace_count
    assert {item.file for item in report.skipped} == {"partial.dat"}
    assert report.scanned_files == (2 if scope == "tree" else 1)
    assert not report.complete


@pytest.mark.parametrize("operation", ["long_token", "multiline_limit", "skip_file"])
def test_invalid_skip_paths_use_scan_error(operation: str) -> None:
    skipped: list[ScanSkip] = []
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        if operation == "skip_file":
            skip_file("../evil", "binary", strict=False, skipped=skipped)
        else:
            text = "x" * 5000 if operation == "long_token" else " " * 3000 + "\n" + " " * 3000
            prepare_text(text, "../evil", strict=False, skipped=skipped)
    assert skipped == []


def test_skip_budget_overflow_keeps_skipped_files_consistent(tmp_path: Path) -> None:
    (tmp_path / "payload.dat").write_text("A" * 5000 + "\n" + "B" * 5000, encoding="utf-8")
    skipped_files: list[str] = []
    scanner = Scanner(tmp_path, strict=False, max_files=1, skipped_files=skipped_files)
    with pytest.raises(ScanError):
        scanner.scan()
    assert skipped_files == []


@pytest.mark.parametrize("fallback", [False, True])
def test_tree_with_only_partial_file_counts_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool,
) -> None:
    (tmp_path / "partial.dat").write_text("A" * 5000, encoding="utf-8")
    if fallback:
        monkeypatch.setattr(detect_module, "_DIR_FD_SUPPORTED", False)
    scanner = Scanner(tmp_path, strict=False)
    assert scanner.scan() == []
    assert scanner.skipped == (ScanSkip("partial.dat", "long_token", 1),)
    assert scanner.files_scanned == 0
