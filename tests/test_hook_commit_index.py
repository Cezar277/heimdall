"""Régressions audit C-01/M-01 : vrais commits et index adverses (#228)."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GitRepo
from test_cli_hook import FAKE_AWS_KEY, _git, _run
from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess, trusted_git_path


@pytest.fixture
def git_repo() -> Iterator[GitRepo]:
    repo = GitRepo("heimdall-t228-")
    try:
        yield repo
    finally:
        repo.close()


@pytest.fixture(autouse=True)
def _hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "00" * 32)


COMMIT_MODES = [
    ("-a",),
    ("app.py",),
    ("-p",),
    ("--amend", "-a"),
    ("--only", "app.py"),
    ("--include", "app.py"),
]


@pytest.mark.parametrize("arguments", COMMIT_MODES)
def test_commit_scans_the_effective_index(git_repo: GitRepo, arguments: tuple[str, ...]) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    head = git_repo.git_output("rev-parse", "HEAD")
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    blocked = _git(git_repo, "commit", "-m", "blocked", *arguments, input_text="y\n")
    assert blocked.returncode != 0
    assert "1 secret(s) détecté(s)" in blocked.stdout + blocked.stderr
    assert FAKE_AWS_KEY not in blocked.stderr
    assert git_repo.git_output("rev-parse", "HEAD") == head

    # L'erreur ne doit pas simplement rendre tous les commits impossibles.
    git_repo.write("app.py", "x = 2\n")
    clean = _git(git_repo, "commit", "-m", "clean", *arguments, input_text="y\n")
    assert clean.returncode == 0, clean.stderr
    assert git_repo.git_output("show", "HEAD:app.py") == "x = 2\n"


@pytest.mark.parametrize("name", ["index", "index.lock", "next-index-123.lock"])
@pytest.mark.parametrize("relative", [True, False])
def test_staged_scan_uses_validated_index(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, name: str, relative: bool
) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    clean_index = (git_repo.root / ".git/index").read_bytes()
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    expected_blob = git_repo.git_output("rev-parse", ":app.py").strip()
    selected = git_repo.root / ".git" / name
    secret_index = (git_repo.root / ".git/index").read_bytes()
    (git_repo.root / ".git/index").write_bytes(clean_index)
    selected.write_bytes(secret_index)
    raw = selected.relative_to(git_repo.root).as_posix() if relative else str(selected)
    access = GitAccess(git_repo.root, index_file=raw)
    assert access.index_path() == selected
    assert access.index_entry("app.py") == ("100644", expected_blob)
    assert FAKE_AWS_KEY.encode() in access.staged_diff(65536)[0]
    monkeypatch.setenv("GIT_INDEX_FILE", raw)
    result = _run("scan", "--staged", str(git_repo.root))
    assert result.exit_code == 1, result.output
    assert FAKE_AWS_KEY not in result.output


@pytest.mark.parametrize(
    "kind", ["outside", "name", "missing", "directory", "symlink", "empty", "nul", "newline"]
)
def test_invalid_index_is_an_error(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, kind: str, tmp_path: Path
) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    path = git_repo.root / ".git/index.lock"
    if kind == "outside":
        path = tmp_path / "index"
        shutil.copyfile(git_repo.root / ".git/index", path)
    elif kind == "name":
        path = git_repo.root / ".git/evil-index"
        shutil.copyfile(git_repo.root / ".git/index", path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to(git_repo.root / ".git/index")
    raw = {"empty": "", "nul": "bad\x00index", "newline": "bad\nindex"}.get(kind, str(path))
    # NUL cannot be stored in a real process environment; exercise the API.
    if kind == "nul":
        with pytest.raises(ToolFailure):
            GitAccess(git_repo.root, index_file=raw)
        return
    monkeypatch.setenv("GIT_INDEX_FILE", raw)
    result = _run("scan", "--staged", str(git_repo.root))
    assert result.exit_code == 2
    assert str(path) not in result.output


def test_selected_index_replaced_with_symlink_is_refused(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    path = git_repo.root / ".git/index.lock"
    shutil.copyfile(git_repo.root / ".git/index", path)
    access = GitAccess(git_repo.root, index_file=str(path))
    path.unlink()
    path.symlink_to(git_repo.root / ".git/index")
    with pytest.raises(ToolFailure):
        access.staged_changes()


def test_default_git_access_ignores_inherited_index(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_INDEX_FILE", "/untrusted/index")
    assert GitAccess(git_repo.root).is_repository()


def test_temporary_index_cannot_attest_its_own_config(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.write("heimdall.toml", "# approved\n")
    git_repo.commit_all("base")
    git_repo.write("heimdall.toml", "# changed\n")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    blocked = _git(git_repo, "commit", "-am", "changed config")
    assert blocked.returncode != 0
    assert "scan impossible" in blocked.stdout + blocked.stderr


def test_config_approval_mode_keeps_secret_detection(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.write("heimdall.toml", "# approved\n")
    git_repo.commit_all("base")
    git_repo.write("heimdall.toml", "# changed\n")
    assert _run("hook", "install", "--no-allowlist", str(git_repo.root)).exit_code == 0
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    blocked = _git(git_repo, "commit", "-am", "blocked")
    assert blocked.returncode != 0
    assert "1 secret(s) détecté(s)" in blocked.stdout + blocked.stderr
    git_repo.write("app.py", "x = 2\n")
    clean = _git(git_repo, "commit", "-am", "approved config")
    assert clean.returncode == 0, clean.stderr


def test_config_guard_uses_the_selected_index(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.write("heimdall.toml", "# approved\n")
    git_repo.commit_all("base")
    selected = git_repo.root / ".git/next-index-123.lock"
    shutil.copyfile(git_repo.root / ".git/index", selected)
    # Le worktree semble propre dans l'index par défaut, mais ne correspond
    # pas à la configuration du commit effectif : ls-files doit le refuser.
    git_repo.write("heimdall.toml", "# unapproved\n")
    git_repo.stage("heimdall.toml")
    monkeypatch.setenv("GIT_INDEX_FILE", str(selected))
    refused = _run("scan", "--staged", str(git_repo.root))
    assert refused.exit_code == 2


def test_system_git_search_does_not_inherit_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/untrusted/tools")
    search = trusted_git_path().split(os.pathsep)
    assert "/untrusted/tools" not in search
    if os.name != "nt":
        assert "/opt/homebrew/bin" in search
        assert "/usr/local/bin" in search
        assert "/run/current-system/sw/bin" in search


def test_linked_worktree_uses_its_own_temporary_index(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    worktree = tmp_path / "linked"
    git_repo.git("worktree", "add", "-b", "linked", str(worktree))
    assert CliRunner().invoke(app, ["hook", "install", str(worktree)]).exit_code == 0
    (worktree / "app.py").write_text(f'AWS = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    # GitRepo's helper executes in root: temporarily select the linked worktree.
    original = git_repo.root
    try:
        git_repo.root = worktree
        blocked = _git(git_repo, "commit", "-am", "blocked")
        assert blocked.returncode != 0
        assert "1 secret(s) détecté(s)" in blocked.stdout + blocked.stderr
        (worktree / "app.py").write_text("x = 2\n", encoding="utf-8")
        clean = _git(git_repo, "commit", "-am", "clean")
        assert clean.returncode == 0, clean.stderr
    finally:
        git_repo.root = original
