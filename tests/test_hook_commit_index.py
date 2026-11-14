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

import heimdall.cli.hook as hook_module
from heimdall.cli.hook import HookError, apply_and_restage, assert_no_unstaged_changes
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


@pytest.mark.parametrize("value", ["index.lock", "next-index-123.lock", "index", ""])
def test_remediation_refuses_an_effective_index_before_applying(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    index = git_repo.root / ".git/index"
    selected = git_repo.root / ".git" / value if value else None
    if selected is not None and selected != index:
        shutil.copyfile(index, selected)
    original_index = index.read_bytes()
    original_selected = selected.read_bytes() if selected is not None else None
    monkeypatch.setenv("GIT_INDEX_FILE", str(selected) if selected is not None else "")
    applied = False

    def apply() -> None:
        nonlocal applied
        applied = True
        git_repo.write("app.py", "x = 2\n")

    with pytest.raises(HookError, match="index Git effectif imposé"):
        apply_and_restage(git_repo.root, ["app.py"], apply)
    with pytest.raises(HookError, match="index Git effectif imposé"):
        assert_no_unstaged_changes(git_repo.root, ["app.py"])
    with pytest.raises(HookError, match="index Git effectif imposé"):
        hook_module._restage_paths(git_repo.root, ["app.py"])
    assert not applied
    assert (git_repo.root / "app.py").read_text(encoding="utf-8") == "x = 1\n"
    assert index.read_bytes() == original_index
    if selected is not None:
        assert selected.read_bytes() == original_selected


@pytest.mark.parametrize("change", ["content", "mtime", "size"])
def test_selected_index_changed_on_the_same_inode_is_refused(
    git_repo: GitRepo, change: str
) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    index = git_repo.root / ".git/index"
    replacement: bytes | None = None
    if change == "content":
        # Deux index valides avec le même état d'extension cache-tree.
        git_repo.write("app.py", "x = 0\n")
        git_repo.stage("app.py")
        original = index.read_bytes()
        git_repo.write("app.py", "x = 2\n")
        git_repo.stage("app.py")
        replacement = index.read_bytes()
        assert len(replacement) == len(original)
        index.write_bytes(original)
    access = GitAccess(git_repo.root, index_file=str(index))
    before = index.stat()
    if change == "content":
        assert replacement is not None
        index.write_bytes(replacement)
        # Même inode, même taille et mtime restauré : seul ctime atteste
        # encore la réécriture. Pas besoin de provoquer un recyclage ext4.
        os.utime(index, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert index.stat().st_ctime_ns != before.st_ctime_ns
    elif change == "mtime":
        os.utime(index, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    else:
        with index.open("ab") as stream:
            stream.write(b"changed")
    assert index.stat().st_ino == before.st_ino
    with pytest.raises(ToolFailure):
        access.staged_changes()


def test_system_git_masks_an_added_prefix_and_repo_git_is_refused(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name == "nt":
        pytest.skip("préfixes POSIX uniquement")
    system = tmp_path / "system"
    added = tmp_path / "usr/local/bin"
    system.mkdir()
    added.mkdir(parents=True)
    system_git = system / "git"
    planted_git = added / "git"
    for binary in (system_git, planted_git):
        binary.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        binary.chmod(0o755)
    real_which = shutil.which
    monkeypatch.setattr(os, "defpath", str(system))

    def which(command: str, *, path: str) -> str | None:
        # Simule le préfixe ajouté sans écrire dans le vrai /usr/local/bin.
        mapped = path.replace("/usr/local/bin", str(added))
        return real_which(command, path=mapped)

    monkeypatch.setattr(shutil, "which", which)
    assert hook_module._git_binary(git_repo.root) == str(system_git)
    assert GitAccess(git_repo.root)._git == str(system_git)
    # Force le repli vers /usr/local/bin, dont git pointe dans le dépôt.
    system_git.unlink()
    planted_git.unlink()
    repo_git = git_repo.root / "git"
    repo_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    repo_git.chmod(0o755)
    planted_git.symlink_to(repo_git)
    with pytest.raises(HookError):
        hook_module._git_binary(git_repo.root)
    with pytest.raises(ToolFailure):
        GitAccess(git_repo.root)


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
