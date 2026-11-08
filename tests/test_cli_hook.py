"""Preuves T36 : hook pre-commit, index et commit partiel (#36, #103-#106)."""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GIT, GitRepo
from typer.testing import CliRunner, Result

import heimdall.cli.hook as hook_module
from heimdall.cli.hook import (
    HEIMDALL_IN_HOOK_ENV,
    HOOK_MARKER,
    HookError,
    UnstagedChangesError,
    _create_locked_index_copy,
    _git_binary,
    _launcher,
    _restage_paths,
    _verify_root,
    apply_and_restage,
    install_hook,
    uninstall_hook,
)
from heimdall.cli.main import app
from heimdall.mcp.gitdiff import GitAccess

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
TEST_HMAC_KEY = "00" * 32


@pytest.fixture(autouse=True)
def _cle_hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empreintes déterministes et aucune écriture hors du dépôt de test."""
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)


@pytest.fixture
def git_repo() -> Iterator[GitRepo]:
    """Dépôt git jetable (jamais le dépôt Heimdall lui-même)."""
    repo = GitRepo("heimdall-t36-")
    try:
        yield repo
    finally:
        repo.close()


def _run(*arguments: str) -> Result:
    return CliRunner().invoke(app, list(arguments))


def _hook(repo: GitRepo) -> Path:
    return repo.root / ".git" / "hooks" / "pre-commit"


def _legacy(repo: GitRepo) -> Path:
    hook = _hook(repo)
    return hook.with_name(hook.name + ".heimdall-legacy")


def _git(
    repo: GitRepo,
    *arguments: str,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    assert GIT is not None
    return subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(repo.root), *arguments],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _commit(repo: GitRepo, message: str) -> subprocess.CompletedProcess[str]:
    return _git(repo, "commit", "-m", message)


def _stage_first_hunk(repo: GitRepo, path: str) -> None:
    """Indexe uniquement le premier hunk d'un fichier (simule ``git add -p``)."""
    patch = _git(repo, "diff", "--", path).stdout
    kept: list[str] = []
    hunk_index = 0
    for line in patch.splitlines(keepends=True):
        if line.startswith("@@"):
            hunk_index += 1
        if hunk_index <= 1:
            kept.append(line)
    assert kept
    result = _git(repo, "apply", "--cached", "-", input_text="".join(kept))
    assert result.returncode == 0, result.stderr


def _write_foreign_hook(repo: GitRepo, content: str, *, executable: bool = True) -> Path:
    hook = _hook(repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(content, encoding="utf-8")
    hook.chmod(0o755 if executable else 0o644)
    return hook


def test_git_binary_refuses_a_binary_inside_the_repository(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = git_repo.root / "git"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(hook_module.shutil, "which", lambda *args, **kwargs: str(fake))

    with pytest.raises(HookError):
        _git_binary(git_repo.root)


def test_run_git_rejects_a_redirecting_environment(git_repo: GitRepo) -> None:
    with pytest.raises(HookError):
        hook_module._run_git(
            git_repo.root,
            ("rev-parse", "--git-dir"),
            extra_env={"GIT_DIR": "/nonexistent/heimdall-git-dir"},
        )


def test_run_git_rejects_an_unexpected_absolute_index_file(
    git_repo: GitRepo,
) -> None:
    with pytest.raises(HookError):
        hook_module._run_git(
            git_repo.root,
            ("rev-parse", "--git-dir"),
            extra_env={"GIT_INDEX_FILE": "/nonexistent/index"},
        )


def test_run_git_rejects_a_relative_index_file(git_repo: GitRepo) -> None:
    with pytest.raises(HookError):
        hook_module._run_git(
            git_repo.root,
            ("rev-parse", "--git-dir"),
            extra_env={"GIT_INDEX_FILE": "relative-index"},
        )


def test_launcher_refuses_a_console_script_inside_the_repository(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = git_repo.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    console = venv_bin / "heimdall"
    console.write_text("", encoding="utf-8")
    console.chmod(0o755)
    monkeypatch.setattr(hook_module.sys, "executable", str(python))

    if sys.version_info >= (3, 11):
        launcher = _launcher(git_repo.root)
        assert "-I -P -m heimdall.cli.main" in launcher
        assert str(console) not in launcher
    else:
        with pytest.raises(HookError):
            _launcher(git_repo.root)


def test_launcher_refuses_a_console_symlink_under_the_repository(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = git_repo.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    outside = tmp_path / "outside-heimdall"
    outside.write_text("", encoding="utf-8")
    outside.chmod(0o755)
    console = venv_bin / "heimdall"
    console.symlink_to(outside)
    monkeypatch.setattr(hook_module.sys, "executable", str(python))

    if sys.version_info >= (3, 11):
        launcher = _launcher(git_repo.root)
        assert "-I -P -m heimdall.cli.main" in launcher
        assert str(console) not in launcher
    else:
        with pytest.raises(HookError):
            _launcher(git_repo.root)


def test_launcher_requires_a_console_on_python_310(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = tmp_path / "outside-venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))
    monkeypatch.setattr(hook_module.sys, "version_info", (3, 10, 0))

    with pytest.raises(HookError):
        _launcher(git_repo.root)


def test_launcher_requires_python_311_on_windows(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_scripts = tmp_path / "outside-venv" / "Scripts"
    venv_scripts.mkdir(parents=True)
    python = venv_scripts / "python.exe"
    python.write_text("", encoding="utf-8")
    (venv_scripts / "heimdall.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))
    monkeypatch.setattr(hook_module.sys, "version_info", (3, 10, 0))
    monkeypatch.setattr(hook_module.os, "name", "nt")

    with pytest.raises(HookError):
        _launcher(git_repo.root)


def test_launcher_uses_safe_path_on_python_311(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = tmp_path / "outside-venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))
    monkeypatch.setattr(hook_module.sys, "version_info", (3, 11, 0))

    launcher = _launcher(git_repo.root)

    assert "-I -P -m heimdall.cli.main" in launcher


def test_install_refuses_an_interpreter_inside_the_repository(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = git_repo.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert not _hook(git_repo).exists()


def test_uninstall_works_when_the_interpreter_moved_inside_the_repository(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    venv_bin = git_repo.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 0
    assert not _hook(git_repo).exists()


def test_install_force_creates_missing_hooks_parents_privately(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    custom = tmp_path / "outside-a" / "b" / "hooks"
    git_repo.git("config", "core.hooksPath", str(custom))
    previous = os.umask(0o002)
    try:
        result = _run("hook", "install", str(git_repo.root), "--force")
    finally:
        os.umask(previous)

    assert result.exit_code == 0
    assert (custom / "pre-commit").is_file()
    for parent in (tmp_path / "outside-a", tmp_path / "outside-a" / "b"):
        assert stat.S_IMODE(parent.stat().st_mode) == 0o700


def test_install_on_python_310_without_console_leaves_a_foreign_hook_in_place(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = "#!/bin/sh\necho FOREIGN\n"
    hook = _write_foreign_hook(git_repo, original)
    venv_bin = tmp_path / "outside-venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(hook_module.sys, "executable", str(python))
    monkeypatch.setattr(hook_module.sys, "version_info", (3, 10, 0))

    with pytest.raises(HookError):
        hook_module.install_hook(git_repo.root)

    assert hook.read_text(encoding="utf-8") == original
    assert not _legacy(git_repo).exists()


def test_reads_and_index_writes_refuse_without_o_nofollow(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", "new\n")
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(HookError):
        hook_module._read_regular(git_repo.root / "app.py", 1024)
    with pytest.raises(HookError):
        hook_module._restage_paths(git_repo.root, ["app.py"])

    assert not (git_repo.root / ".git" / "index.lock").exists()


def test_install_force_refuses_a_group_writable_existing_parent(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o775)
    custom = shared / "hooks"
    git_repo.git("config", "core.hooksPath", str(custom))
    previous = os.umask(0o002)
    try:
        result = _run("hook", "install", str(git_repo.root), "--force")
    finally:
        os.umask(previous)

    assert result.exit_code == 2
    assert not custom.exists()
    shared.chmod(0o755)
    assert _run("hook", "install", str(git_repo.root), "--force").exit_code == 0


def test_atomic_write_refuses_a_temporary_swapped_for_a_symlink(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hooks = _hook(git_repo).parent
    hooks.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "target"
    target.write_text("do not touch", encoding="utf-8")
    real_fsync = os.fsync
    swapped: list[Path] = []

    def swapping_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if not swapped:
            for temporary in hooks.glob(".heimdall-hook-*"):
                temporary.unlink()
                temporary.symlink_to(target)
                swapped.append(temporary)

    monkeypatch.setattr(hook_module.os, "fsync", swapping_fsync)

    with pytest.raises(HookError):
        hook_module._atomic_write(_hook(git_repo), b"#!/bin/sh\n")

    assert swapped
    assert target.read_text(encoding="utf-8") == "do not touch"
    assert not _hook(git_repo).exists()


def test_install_creates_an_executable_managed_hook(git_repo: GitRepo) -> None:
    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 0
    hook = _hook(git_repo)
    assert hook.is_file()
    assert os.access(hook, os.X_OK)
    content = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in content
    assert HEIMDALL_IN_HOOK_ENV in content
    assert "unset PYTHONPATH PYTHONHOME" in content
    assert "scan --staged" in content
    assert '"$PWD"' in content
    assert "PYTHONSAFEPATH=1" in content
    console = Path(sys.executable).with_name("heimdall")
    if os.name != "nt" and console.is_file():
        assert str(console) in content
    else:
        assert os.path.abspath(sys.executable) in content
        assert "-I -m heimdall.cli.main" in content


@pytest.mark.parametrize("preinstalled", [False, True])
def test_install_rolls_back_if_root_check_fails_after_write(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, preinstalled: bool
) -> None:
    if preinstalled:
        hook_module.install_hook(git_repo.root)
    before = _hook(git_repo).read_bytes() if preinstalled else None
    calls = [0]
    real_verify = hook_module._verify_root

    def failing_verify(access):
        calls[0] += 1
        if calls[0] >= 3:
            raise HookError
        real_verify(access)

    monkeypatch.setattr(hook_module, "_verify_root", failing_verify)

    with pytest.raises(HookError):
        hook_module.install_hook(git_repo.root)

    if preinstalled:
        assert _hook(git_repo).read_bytes() == before
    else:
        assert not _hook(git_repo).exists()


@pytest.mark.parametrize("state", ["managed_with_legacy", "managed_alone", "legacy_alone"])
def test_uninstall_rolls_back_if_root_check_fails_after_replace(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    legacy_text = "#!/bin/sh\necho LEGACY\n"
    if state == "legacy_alone":
        _legacy(git_repo).write_text(legacy_text, encoding="utf-8")
        _legacy(git_repo).chmod(0o755)
    else:
        if state == "managed_with_legacy":
            _write_foreign_hook(git_repo, legacy_text)
        assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    before_hook = _hook(git_repo).read_bytes() if _hook(git_repo).exists() else None
    before_legacy = _legacy(git_repo).read_bytes() if _legacy(git_repo).exists() else None
    calls = [0]
    real_verify = hook_module._verify_root

    def failing_verify(access):
        calls[0] += 1
        if calls[0] >= 2:
            raise HookError
        real_verify(access)

    monkeypatch.setattr(hook_module, "_verify_root", failing_verify)

    with pytest.raises(HookError):
        hook_module.uninstall_hook(git_repo.root)

    after_hook = _hook(git_repo).read_bytes() if _hook(git_repo).exists() else None
    after_legacy = _legacy(git_repo).read_bytes() if _legacy(git_repo).exists() else None
    assert after_hook == before_hook
    assert after_legacy == before_legacy


def test_install_is_idempotent(git_repo: GitRepo) -> None:
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    first = _hook(git_repo).read_bytes()

    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    assert _hook(git_repo).read_bytes() == first
    assert not _legacy(git_repo).exists()


def test_install_preserves_and_chains_an_existing_hook(git_repo: GitRepo) -> None:
    original = "#!/bin/sh\necho LEGACY_RAN\n"
    hook = _write_foreign_hook(git_repo, original)

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 0
    legacy = _legacy(git_repo)
    assert legacy.read_text(encoding="utf-8") == original
    content = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in content
    assert "pre-commit.heimdall-legacy" in content
    assert 'hook_dir=$(dirname "$0")' in content

    completed = subprocess.run(  # noqa: S603 - hook local généré
        [str(hook)],
        cwd=git_repo.root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0
    assert "LEGACY_RAN" in completed.stdout


def test_chained_legacy_survives_repository_move(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    original = "#!/bin/sh\necho LEGACY_RAN\n"
    _write_foreign_hook(git_repo, original)
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    moved = tmp_path / "moved-repo"
    git_repo.root.rename(moved)

    completed = subprocess.run(  # noqa: S603 - hook local généré
        [str(moved / ".git" / "hooks" / "pre-commit")],
        cwd=moved,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0
    assert "LEGACY_RAN" in completed.stdout


def test_install_backs_up_a_non_executable_hook_without_chaining(
    git_repo: GitRepo,
) -> None:
    original = "#!/bin/sh\necho LEGACY_RAN\n"
    hook = _write_foreign_hook(git_repo, original, executable=False)

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 0
    assert "sauvegardé" in result.stdout
    assert _legacy(git_repo).read_text(encoding="utf-8") == original
    content = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in content
    assert str(_legacy(git_repo)) not in content


def test_install_refuses_to_overwrite_an_existing_backup(git_repo: GitRepo) -> None:
    hook = _write_foreign_hook(git_repo, "foreign\n")
    legacy = _legacy(git_repo)
    legacy.write_text("previous\n", encoding="utf-8")

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert hook.read_text(encoding="utf-8") == "foreign\n"
    assert legacy.read_text(encoding="utf-8") == "previous\n"


def test_uninstall_restores_the_previous_hook(git_repo: GitRepo) -> None:
    original = "#!/bin/sh\necho LEGACY_RAN\n"
    hook = _write_foreign_hook(git_repo, original)
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 0
    assert hook.read_text(encoding="utf-8") == original
    assert not _legacy(git_repo).exists()


def test_uninstall_removes_the_managed_hook(git_repo: GitRepo) -> None:
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 0
    assert not _hook(git_repo).exists()


def test_uninstall_without_a_hook_is_idempotent(git_repo: GitRepo) -> None:
    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 0
    assert "aucun hook" in result.stdout


def test_uninstall_leaves_a_foreign_hook_untouched(git_repo: GitRepo) -> None:
    hook = _write_foreign_hook(git_repo, "foreign\n")

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 0
    assert hook.read_text(encoding="utf-8") == "foreign\n"


def test_uninstall_restores_a_symlinked_legacy_hook(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    target = tmp_path / "legacy-target"
    target.write_text("#!/bin/sh\necho LEGACY\n", encoding="utf-8")
    target.chmod(0o755)
    hook = _hook(git_repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.symlink_to(target)

    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    assert _legacy(git_repo).is_symlink()
    assert _run("hook", "uninstall", str(git_repo.root)).exit_code == 0

    assert hook.is_symlink()
    assert os.readlink(hook) == str(target)


def test_foreign_hook_with_marker_in_body_is_not_ours(git_repo: GitRepo) -> None:
    original = "#!/bin/sh\necho LEGACY\n# heimdall-managed-hook: v1\n"
    hook = _write_foreign_hook(git_repo, original)

    untouched = _run("hook", "uninstall", str(git_repo.root))
    assert untouched.exit_code == 0
    assert hook.read_text(encoding="utf-8") == original

    installed = _run("hook", "install", str(git_repo.root))
    assert installed.exit_code == 0
    assert _legacy(git_repo).read_text(encoding="utf-8") == original

    restored = _run("hook", "uninstall", str(git_repo.root))
    assert restored.exit_code == 0
    assert hook.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("absolute", [False, True])
def test_install_respects_core_hooks_path(
    git_repo: GitRepo, tmp_path: Path, absolute: bool
) -> None:
    custom = tmp_path / "custom-hooks" if absolute else git_repo.root / "custom-hooks"
    git_repo.git("config", "core.hooksPath", str(custom) if absolute else "custom-hooks")
    arguments = ("hook", "install", str(git_repo.root))
    if absolute:
        arguments = (*arguments, "--force")

    result = _run(*arguments)

    assert result.exit_code == 0
    assert (custom / "pre-commit").is_file()
    assert not (git_repo.root / ".git" / "hooks" / "pre-commit").exists()


def test_install_refuses_an_absolute_hooks_path_outside_the_repository(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    custom = tmp_path / "outside-hooks"
    git_repo.git("config", "core.hooksPath", str(custom))

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert "--force" in result.stderr
    assert not (custom / "pre-commit").exists()


def test_install_accepts_an_absolute_hooks_path_outside_with_force(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    custom = tmp_path / "outside-hooks"
    git_repo.git("config", "core.hooksPath", str(custom))

    result = _run("hook", "install", str(git_repo.root), "--force")

    assert result.exit_code == 0
    assert (custom / "pre-commit").is_file()


def test_uninstall_requires_force_for_an_absolute_hooks_path_outside(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    custom = tmp_path / "outside-hooks"
    git_repo.git("config", "core.hooksPath", str(custom))
    assert _run("hook", "install", str(git_repo.root), "--force").exit_code == 0

    refused = _run("hook", "uninstall", str(git_repo.root))
    assert refused.exit_code == 2
    assert (custom / "pre-commit").is_file()

    forced = _run("hook", "uninstall", str(git_repo.root), "--force")
    assert forced.exit_code == 0
    assert not (custom / "pre-commit").exists()


def test_install_refuses_an_absolute_symlink_to_outside_without_force(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    target = tmp_path / "target-hooks"
    target.mkdir()
    link = tmp_path / "linked-hooks"
    link.symlink_to(target)
    git_repo.git("config", "core.hooksPath", str(link))

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert not (target / "pre-commit").exists()

    forced = _run("hook", "install", str(git_repo.root), "--force")
    assert forced.exit_code == 0
    assert (target / "pre-commit").is_file()


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_install_refuses_a_group_or_world_writable_hooks_directory(
    git_repo: GitRepo, tmp_path: Path, mode: int
) -> None:
    custom = tmp_path / "hooks"
    custom.mkdir()
    custom.chmod(mode)
    git_repo.git("config", "core.hooksPath", str(custom))

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert not (custom / "pre-commit").exists()


def test_install_refuses_a_relative_hooks_path_that_escapes_the_repository(
    git_repo: GitRepo,
) -> None:
    outside = git_repo.root.parent / "outside-hooks"
    git_repo.git("config", "core.hooksPath", "../outside-hooks")

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert not (outside / "pre-commit").exists()


@pytest.mark.parametrize("hooks_path", [".", ".git"])
def test_install_refuses_a_hooks_directory_that_is_the_repo_or_common_dir(
    git_repo: GitRepo, hooks_path: str
) -> None:
    git_repo.git("config", "core.hooksPath", hooks_path)

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert not (git_repo.root / "pre-commit").exists()
    assert not (git_repo.root / ".git" / "pre-commit").exists()


def test_install_refuses_a_directory_as_hook(git_repo: GitRepo) -> None:
    hook = _hook(git_repo)
    hook.mkdir(parents=True)

    result = _run("hook", "install", str(git_repo.root))

    assert result.exit_code == 2
    assert hook.is_dir()


def test_uninstall_refuses_a_directory_as_hook(git_repo: GitRepo) -> None:
    hook = _hook(git_repo)
    hook.mkdir(parents=True)

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 2
    assert hook.is_dir()


def test_uninstall_refuses_a_directory_legacy_without_overwriting(
    git_repo: GitRepo,
) -> None:
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    legacy = _legacy(git_repo)
    legacy.mkdir()

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 2
    assert _hook(git_repo).is_file()
    assert legacy.is_dir()


def test_uninstall_refuses_a_directory_legacy_when_hook_is_absent(
    git_repo: GitRepo,
) -> None:
    legacy = _legacy(git_repo)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.mkdir()

    result = _run("hook", "uninstall", str(git_repo.root))

    assert result.exit_code == 2
    assert not _hook(git_repo).exists()
    assert legacy.is_dir()


def test_install_uses_the_worktree_hooks_path(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    worktree = tmp_path / "linked"
    git_repo.git("worktree", "add", "-q", str(worktree), "HEAD")

    result = _run("hook", "install", str(worktree))

    assert result.exit_code == 0
    assert GIT is not None
    raw = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(worktree), "rev-parse", "--git-path", "hooks"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.strip()
    hooks = Path(raw)
    if not hooks.is_absolute():
        hooks = worktree / hooks
    assert (hooks / "pre-commit").is_file()


def test_install_outside_a_repository_fails_closed(tmp_path: Path) -> None:
    result = _run("hook", "install", str(tmp_path))

    assert result.exit_code == 2
    assert "installation impossible" in result.stderr


def test_hook_blocks_a_staged_secret(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    blocked = _commit(git_repo, "secret")

    assert blocked.returncode != 0
    assert FAKE_AWS_KEY not in blocked.stdout + blocked.stderr
    assert "secret" not in git_repo.git_output("log", "--oneline")

    git_repo.write("app.py", "x = 2\n")
    git_repo.stage("app.py")
    clean = _commit(git_repo, "clean")
    assert clean.returncode == 0, clean.stderr


def test_hook_blocks_a_secret_from_a_subdirectory_commit(
    git_repo: GitRepo,
) -> None:
    git_repo.write("sub/base.py", "x = 1\n")
    git_repo.stage("sub/base.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    assert GIT is not None

    completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(git_repo.root / "sub"), "commit", "-m", "sub"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode != 0
    assert FAKE_AWS_KEY not in completed.stdout + completed.stderr


def test_heimdall_in_hook_is_a_documented_bypass(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    environment = dict(os.environ)
    environment[HEIMDALL_IN_HOOK_ENV] = "1"
    assert GIT is not None

    completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(git_repo.root), "commit", "-m", "bypass"],
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0
    assert "scan ignoré" in completed.stderr
    assert FAKE_AWS_KEY in git_repo.git_output("show", "HEAD:app.py")


def test_hook_scans_only_the_index(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", "x = 2\n")
    git_repo.stage("app.py")
    git_repo.write("unstaged.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    completed = _commit(git_repo, "clean")

    assert completed.returncode == 0, completed.stderr
    assert "unstaged.py" not in git_repo.git_output("show", "--name-only", "HEAD")
    assert (git_repo.root / "unstaged.py").exists()


def test_partial_commit_keeps_the_index_coherent(git_repo: GitRepo) -> None:
    lines = [f"line{index}\n" for index in range(1, 21)]
    git_repo.write("app.py", "".join(lines))
    git_repo.stage("app.py")
    git_repo.commit_all("base")

    modified = list(lines)
    modified[1] = f'AWS = "{FAKE_AWS_KEY}"\n'
    modified[18] = f'OTHER = "{FAKE_AWS_KEY}"\n'
    git_repo.write("app.py", "".join(modified))
    _stage_first_hunk(git_repo, "app.py")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0

    blocked = _commit(git_repo, "partial")

    assert blocked.returncode != 0
    assert FAKE_AWS_KEY not in blocked.stdout + blocked.stderr
    staged = git_repo.git_output("show", ":app.py")
    assert FAKE_AWS_KEY in staged
    assert "line19" in staged
    worktree = (git_repo.root / "app.py").read_text(encoding="utf-8")
    assert "OTHER" in worktree
    assert "OTHER" in git_repo.git_output("diff", "--", "app.py")

    clean = list(lines)
    clean[1] = "line2_clean\n"
    clean[18] = f'OTHER = "{FAKE_AWS_KEY}"\n'
    git_repo.write("app.py", "".join(clean))
    _stage_first_hunk(git_repo, "app.py")
    committed = _commit(git_repo, "partial clean")

    assert committed.returncode == 0, committed.stderr
    committed_content = git_repo.git_output("show", "HEAD:app.py")
    assert "line2_clean" in committed_content
    assert "line19" in committed_content
    assert "OTHER" not in committed_content
    assert "OTHER" in (git_repo.root / "app.py").read_text(encoding="utf-8")


def test_apply_and_restage_stages_only_the_remediated_file(git_repo: GitRepo) -> None:
    git_repo.write("app.py", 'token = "old"\n')
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    observed: list[str | None] = []

    def apply() -> None:
        observed.append(os.environ.get(HEIMDALL_IN_HOOK_ENV))
        git_repo.write("app.py", 'token = os.getenv("APP_TOKEN")\n')

    count = apply_and_restage(git_repo.root, ["app.py"], apply)

    assert count == 1
    assert observed == ["1"]
    assert git_repo.git_output("show", ":app.py") == 'token = os.getenv("APP_TOKEN")\n'
    assert (git_repo.root / "app.py").read_text(encoding="utf-8") == (
        'token = os.getenv("APP_TOKEN")\n'
    )
    assert HEIMDALL_IN_HOOK_ENV not in os.environ


def test_apply_and_restage_refuses_unstaged_changes(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", "user change\n")
    called: list[bool] = []

    with pytest.raises(UnstagedChangesError, match="non indexées"):
        apply_and_restage(git_repo.root, ["app.py"], lambda: called.append(True))

    assert called == []
    assert git_repo.git_output("show", ":app.py") == "old\n"
    assert (git_repo.root / "app.py").read_text(encoding="utf-8") == "user change\n"


def test_apply_and_restage_refuses_a_deleted_tracked_file(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    (git_repo.root / "app.py").unlink()
    called: list[bool] = []

    with pytest.raises(UnstagedChangesError):
        apply_and_restage(git_repo.root, ["app.py"], lambda: called.append(True))

    assert called == []
    assert git_repo.git_output("show", ":app.py") == "old\n"


def test_apply_and_restage_restores_state_when_apply_fails(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    before = git_repo.git_output("show", ":app.py")

    def apply() -> None:
        assert os.environ.get(HEIMDALL_IN_HOOK_ENV) == "1"
        git_repo.write("app.py", "partial\n")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        apply_and_restage(git_repo.root, ["app.py"], apply)

    assert git_repo.git_output("show", ":app.py") == before
    assert HEIMDALL_IN_HOOK_ENV not in os.environ


def test_apply_and_restage_freezes_the_asserted_paths(git_repo: GitRepo) -> None:
    git_repo.write("a", "a\n")
    git_repo.write("b", "b\n")
    git_repo.stage("a", "b")
    git_repo.commit_all("base")
    before = git_repo.git_output("show", ":a")

    def apply() -> None:
        (git_repo.root / "a").unlink()
        (git_repo.root / "a").symlink_to(git_repo.root / "b")

    with pytest.raises(HookError):
        apply_and_restage(git_repo.root, ["a"], apply)

    assert git_repo.git_output("show", ":a") == before


def test_apply_and_restage_refuses_an_untracked_file(git_repo: GitRepo) -> None:
    git_repo.write("untracked.txt", "x\n")
    called: list[bool] = []

    with pytest.raises(HookError):
        apply_and_restage(git_repo.root, ["untracked.txt"], lambda: called.append(True))

    assert called == []
    assert not (git_repo.root / ".git" / "index.lock").exists()


def test_apply_and_restage_refuses_an_absent_file(git_repo: GitRepo) -> None:
    called: list[bool] = []

    with pytest.raises(HookError):
        apply_and_restage(git_repo.root, ["absent.txt"], lambda: called.append(True))

    assert called == []


@pytest.mark.parametrize(
    "path",
    [
        "../evil",
        "/etc/passwd",
        ".git/config",
        ".env",
        "a/.env/b",
        ".env.d/f",
        ".env.example/foo",
        "a/.env.example/f",
        ".ENV.EXAMPLE",
        ".Env.Example/foo",
        "a\\b",
        "a:b",
        "dir/",
        "-q",
        "--cacheinfo",
    ],
)
def test_restage_rejects_unsafe_paths(git_repo: GitRepo, path: str) -> None:
    with pytest.raises(HookError):
        _restage_paths(git_repo.root, [path])


def test_restage_requires_the_repository_root(git_repo: GitRepo) -> None:
    subdirectory = git_repo.root / "sub"
    subdirectory.mkdir()
    (subdirectory / "app.py").write_text("x\n", encoding="utf-8")

    with pytest.raises(HookError):
        _restage_paths(subdirectory, ["app.py"])


def test_restage_rejects_a_directory(git_repo: GitRepo) -> None:
    (git_repo.root / "dir").mkdir()

    with pytest.raises(HookError):
        _restage_paths(git_repo.root, ["dir"])


def test_restage_rejects_an_outgoing_symlink(git_repo: GitRepo, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (git_repo.root / "link.txt").symlink_to(outside)

    with pytest.raises(HookError):
        _restage_paths(git_repo.root, ["link.txt"])


def test_restage_does_not_run_filters_or_hooks(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    filter_canary = tmp_path / "filter-canary"
    hook_canary = tmp_path / "hook-canary"
    git_repo.git(
        "config",
        "filter.evil.clean",
        f"touch {shlex.quote(str(filter_canary))}",
    )
    git_repo.write(".gitattributes", "* filter=evil\n")
    hook = git_repo.root / ".git" / "hooks" / "post-index-change"
    hook.write_text(
        f"#!/bin/sh\ntouch {shlex.quote(str(hook_canary))}\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    git_repo.write("app.py", "new\n")

    count = _restage_paths(git_repo.root, ["app.py"])

    assert count == 1
    assert not filter_canary.exists()
    assert not hook_canary.exists()
    assert git_repo.git_output("show", ":app.py") == "new\n"


def test_restage_discards_the_temporary_index_on_failure(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    before = git_repo.git_output("show", ":app.py")
    git_repo.write("app.py", "new\n")
    real_run = hook_module._run_git

    def failing_run(root, arguments, **kwargs):
        if arguments and arguments[0] == "update-index":
            return subprocess.CompletedProcess(arguments, 1, b"", b"")
        return real_run(root, arguments, **kwargs)

    monkeypatch.setattr(hook_module, "_run_git", failing_run)

    with pytest.raises(HookError):
        hook_module._restage_paths(git_repo.root, ["app.py"])

    assert git_repo.git_output("show", ":app.py") == before


def test_restage_refuses_when_the_index_lock_exists(git_repo: GitRepo) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    before = git_repo.git_output("show", ":app.py")
    git_repo.write("app.py", "new\n")
    lock = git_repo.root / ".git" / "index.lock"
    lock.write_text("", encoding="utf-8")

    with pytest.raises(HookError):
        hook_module._restage_paths(git_repo.root, ["app.py"])

    assert git_repo.git_output("show", ":app.py") == before
    assert lock.exists()


def test_restage_refuses_a_symlink_index_lock(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.write("app.py", "new\n")
    target = tmp_path / "target"
    target.write_text("do not touch", encoding="utf-8")
    lock = git_repo.root / ".git" / "index.lock"
    lock.symlink_to(target)

    with pytest.raises(HookError):
        hook_module._restage_paths(git_repo.root, ["app.py"])

    assert target.read_text(encoding="utf-8") == "do not touch"
    assert lock.is_symlink()


def test_restage_refuses_a_lock_swapped_for_a_symlink_before_replace(
    git_repo: GitRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_repo.write("app.py", "old\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    before = git_repo.git_output("show", ":app.py")
    git_repo.write("app.py", "new\n")
    target = tmp_path / "target"
    target.write_text("do not touch", encoding="utf-8")
    lock = git_repo.root / ".git" / "index.lock"
    real_verify = hook_module._verify_index_entries

    def swap_then_verify(*args, **kwargs):
        real_verify(*args, **kwargs)
        lock.unlink()
        lock.symlink_to(target)

    monkeypatch.setattr(hook_module, "_verify_index_entries", swap_then_verify)

    with pytest.raises(HookError):
        hook_module._restage_paths(git_repo.root, ["app.py"])

    assert target.read_text(encoding="utf-8") == "do not touch"
    assert git_repo.git_output("show", ":app.py") == before
    assert not os.path.lexists(lock)


def test_locked_index_copy_refuses_a_symlink_source(
    tmp_path: Path,
) -> None:
    target = tmp_path / "real-index"
    target.write_text("do not read", encoding="utf-8")
    source = tmp_path / "index-link"
    source.symlink_to(target)
    lock = tmp_path / "index.lock"

    with pytest.raises(HookError):
        _create_locked_index_copy(source, lock)

    assert target.read_text(encoding="utf-8") == "do not read"
    assert not lock.exists()


def test_verify_root_detects_a_replaced_root(git_repo: GitRepo) -> None:
    access = GitAccess(git_repo.root)
    moved = git_repo.root.with_name("moved")
    git_repo.root.rename(moved)
    git_repo.root.mkdir()

    with pytest.raises(HookError):
        _verify_root(access)


def test_hook_skips_when_already_inside_a_hook(git_repo: GitRepo) -> None:
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    assert _run("hook", "install", str(git_repo.root)).exit_code == 0
    environment = dict(os.environ)
    environment[HEIMDALL_IN_HOOK_ENV] = "1"

    completed = subprocess.run(  # noqa: S603 - hook local généré
        [str(_hook(git_repo))],
        cwd=git_repo.root,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0
    assert "scan ignoré" in completed.stderr
    assert FAKE_AWS_KEY not in completed.stdout + completed.stderr


def test_install_hook_function_matches_the_cli(git_repo: GitRepo) -> None:
    outcome = install_hook(git_repo.root)

    assert outcome.value == "installed"
    assert _hook(git_repo).is_file()
    assert uninstall_hook(git_repo.root).value == "removed"
    assert not _hook(git_repo).exists()
