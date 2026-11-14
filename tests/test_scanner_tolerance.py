"""Acceptation E-01 : tolérance visible, limites préservées et mode strict (#229)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.fake_secrets import fake_token
from support.git_repo import GitRepo
from test_cli_scan import _scan_validator
from typer.testing import CliRunner

from heimdall.cli.history import collect_history
from heimdall.cli.main import app
from heimdall.cli.scan import collect, render_json, render_text
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner import detect
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.detect import MAX_FILE_BYTES, Scanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text

SYNTHETIC = fake_token("ghp_", 36)
BINARY = b"\x89PNG\r\n\x1a\n" + b"\x00\xff" * 200


@pytest.fixture(autouse=True)
def _hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "00" * 32)


@pytest.fixture
def repo() -> Iterator[GitRepo]:
    repository = GitRepo("heimdall-t229-")
    try:
        repository.write("readme", "safe\n")
        repository.commit_all("base")
        yield repository
    finally:
        repository.close()


@pytest.mark.parametrize("mode", ["tree", "staged", "diff"])
def test_binary_is_reported_and_other_secrets_are_still_detected(repo: GitRepo, mode: str) -> None:
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.write_bytes("image.png", BINARY)
    repo.write("app.py", f'TOKEN = "{SYNTHETIC}"\n')
    repo.stage("image.png", "app.py")
    if mode == "diff":
        repo.git("commit", "-qm", "changes")
    options = {"diff": base, "ci": True} if mode == "diff" else {}
    report = collect(repo.root, staged=mode == "staged", allowlist=Allowlist.empty(), **options)
    assert any(item.file == "app.py" for item in report.findings)
    assert [(item.file, item.reason) for item in report.skipped] == [("image.png", "binary")]
    assert report.scanned_files == (2 if mode == "tree" else 1)
    assert not report.complete
    payload = json.loads(render_json(report))
    _scan_validator().validate(payload)
    assert payload["complete"] is False
    assert payload["skipped_count"] == 1
    assert SYNTHETIC not in render_text(report) + render_json(report)
    assert "image.png" in render_text(report)
    with pytest.raises(ScanError):
        collect(
            repo.root, staged=mode == "staged", allowlist=Allowlist.empty(), strict=True, **options
        )


@pytest.mark.parametrize("encoding", ["latin-1", "cp1252", "utf-16", "utf-32"])
@pytest.mark.parametrize("staged", [False, True])
def test_non_utf8_text_is_scanned(repo: GitRepo, encoding: str, staged: bool) -> None:
    repo.write_bytes("config.txt", f'# café\nTOKEN = "{SYNTHETIC}"\n'.encode(encoding))
    repo.stage("config.txt")
    report = collect(repo.root, staged=staged, allowlist=Allowlist.empty())
    assert any(item.file == "config.txt" and item.line == 2 for item in report.findings)
    assert report.complete


@pytest.mark.parametrize("data", [BINARY, b"\x00\x01\x02\x03" * 100, b"OTTO" + b"\x00\x01" * 50])
def test_unknown_and_known_binary_content_is_classified(data: bytes) -> None:
    assert decode_text(data) is None


@pytest.mark.parametrize("staged", [False, True])
def test_oversized_file_is_not_read(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch, staged: bool
) -> None:
    repo.write_bytes("large.dat", b"A" * (MAX_FILE_BYTES + 1))
    repo.stage("large.dat")
    if staged:
        monkeypatch.setattr(
            GitAccess, "blob_bytes", lambda *args, **kwargs: pytest.fail("large blob read")
        )
    report = collect(repo.root, staged=staged, allowlist=Allowlist.empty())
    assert [(item.file, item.reason) for item in report.skipped] == [("large.dat", "too_large")]
    assert not report.complete


@pytest.mark.parametrize("staged", [False, True])
def test_long_token_does_not_hide_a_separate_secret_on_the_same_line(
    repo: GitRepo, staged: bool
) -> None:
    repo.write("notebook.ipynb", '"image": "' + "A" * 8192 + f'", "token": "{SYNTHETIC}"\n')
    repo.stage("notebook.ipynb")
    report = collect(repo.root, staged=staged, allowlist=Allowlist.empty())
    assert any(item.file == "notebook.ipynb" for item in report.findings)
    assert any(item.reason == "long_token" and item.line == 1 for item in report.skipped)
    assert SYNTHETIC not in render_json(report)


@pytest.mark.parametrize("fallback", [False, True])
def test_symlinks_are_traced_without_resolving_or_reading_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(SYNTHETIC, encoding="utf-8")
    (root / "link.py").symlink_to(outside / "secret.py")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    if fallback:
        monkeypatch.setattr(detect, "_DIR_FD_SUPPORTED", False)
    real_resolve = Path.resolve

    def resolve(path: Path, *args: object, **kwargs: object) -> Path:
        assert path not in {root / "link.py", root / "linked"}, "link target was resolved"
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    scanner = Scanner(root)
    assert scanner.scan() == []
    assert {(item.file, item.reason) for item in scanner.skipped} == {
        ("link.py", "symlink"),
        ("linked", "symlink"),
    }
    with pytest.raises(ScanError):
        Scanner(root, strict=True).scan()


@pytest.mark.parametrize("strict", [False, True])
def test_cli_binary_only_report_has_explicit_coverage(repo: GitRepo, strict: bool) -> None:
    repo.write_bytes("image.png", BINARY)
    repo.stage("image.png")
    args = ["scan", "--ci", "--staged", "--no-allowlist", "--json", str(repo.root)]
    result = CliRunner().invoke(app, [*args, "--strict"] if strict else args)
    assert result.exit_code == (2 if strict else 0)
    if not strict:
        assert json.loads(result.stdout)["complete"] is False
        assert "partielle" in result.stderr


def test_history_preserves_findings_and_skip_traces_across_cached_blobs(repo: GitRepo) -> None:
    repo.write_bytes("image.png", BINARY)
    repo.write("notebook.ipynb", "A" * 8192 + f' TOKEN="{SYNTHETIC}"\n')
    repo.commit_all("first")
    repo.write("readme", "still safe\n")
    repo.commit_all("second")
    report = collect_history(repo.root, ci=True)
    assert any(item.finding.file == "notebook.ipynb" for item in report.findings)
    assert sum(item[0] == "image.png" and item[2] == "binary" for item in report.skipped) == 2
    assert (
        sum(item[0] == "notebook.ipynb" and item[2] == "long_token" for item in report.skipped) == 2
    )
    with pytest.raises(ScanError):
        collect_history(repo.root, ci=True, strict=True)


def test_latin1_named_like_an_image_is_not_excluded(repo: GitRepo) -> None:
    repo.write_bytes("looks-like-image.png", f'# café\nTOKEN="{SYNTHETIC}"'.encode("latin-1"))
    report = collect(repo.root, staged=False, allowlist=Allowlist.empty())
    assert any(item.file == "looks-like-image.png" for item in report.findings)
    assert report.complete
