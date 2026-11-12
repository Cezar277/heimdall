"""Preuves T30.3 (#85) + T30.4 (#86) : application atomique + garde de chemin.

Valeurs entièrement synthétiques ; écritures confinées à ``tmp_path`` ;
aucun ``.env``, aucun secret réel.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from heimdall.mcp.paths import PathEscape, confine
from heimdall.remediation import (
    AppliedPatch,
    ApplyError,
    apply_replacement,
    build_replacement,
    undo_apply,
)
from heimdall.remediation import apply as apply_module
from heimdall.remediation.templates import ReplacementPlan

SECRET = "SYNTHETIC_ONLY_VALUE"  # noqa: S105 - valeur synthétique de test
ENV = "APP_KEY"


def _plan(source: str, line: int = 1, variable: str = ENV, file: str = "app.py") -> ReplacementPlan:
    return build_replacement(file, source, line, SECRET, variable)


def _write(path: Path, text: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def test_apply_patches_and_preserves_mode_and_backup(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source, file="nested/dir/app.py")
    receipt = apply_replacement(tmp_path, plan)
    assert isinstance(receipt, AppliedPatch)
    assert target.read_text(encoding="utf-8") == plan.after
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    backup = tmp_path / receipt.backup
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == source
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert receipt.file == "nested/dir/app.py"
    assert receipt.mode == 0o640
    assert receipt.after == plan.after
    assert SECRET not in repr(receipt)


def test_apply_refuses_manual_plan_without_touching_disk(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    source = f'TOKEN = f"{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)
    assert plan.manual_remediation is True
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)
    assert target.read_text(encoding="utf-8") == source
    assert list(tmp_path.glob("*.bak")) == []


def test_apply_refuses_missing_file(tmp_path: Path) -> None:
    plan = _plan(f'KEY = "{SECRET}"\n', file="ghost.py")
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)
    assert not (tmp_path / "ghost.py").exists()


def test_apply_refuses_stale_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    _write(target, f'KEY = "{SECRET}"\n')
    plan = _plan(f'KEY = "{SECRET}"\n')
    target.write_text('KEY = "changed"\n', encoding="utf-8")
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)
    assert target.read_text(encoding="utf-8") == 'KEY = "changed"\n'


def test_apply_leaves_no_temp_or_partial_file_on_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)

    _real_replace = os.replace

    def _boom_main_write_only(*args: object, **kwargs: object) -> None:
        if not str(args[1]).endswith(".bak"):
            raise OSError("coupure simulée")
        _real_replace(*args, **kwargs)

    monkeypatch.setattr(os, "replace", _boom_main_write_only)
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)
    assert target.read_text(encoding="utf-8") == source
    leftovers = [path.name for path in tmp_path.iterdir()]
    assert all(".tmp." not in name for name in leftovers)
    assert (tmp_path / "app.py.bak").is_file()


def test_undo_restores_backup_and_second_undo_fails(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)
    receipt = apply_replacement(tmp_path, plan)
    undo_apply(tmp_path, receipt)
    assert target.read_text(encoding="utf-8") == source
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    with pytest.raises(ApplyError):
        undo_apply(tmp_path, receipt)
    assert target.read_text(encoding="utf-8") == source


def test_undo_refuses_missing_backup_or_modified_file(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    receipt = apply_replacement(tmp_path, _plan(source))
    (tmp_path / receipt.backup).unlink()
    with pytest.raises(ApplyError):
        undo_apply(tmp_path, receipt)
    assert target.read_text(encoding="utf-8") == receipt.after

    target.write_text('KEY = "intrus"\n', encoding="utf-8")
    with pytest.raises(ApplyError):
        undo_apply(tmp_path, receipt)
    assert target.read_text(encoding="utf-8") == 'KEY = "intrus"\n'


def test_apply_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    real = outside / "real.py"
    real.write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(real)
    plan = _plan(f'X = "{SECRET}"\n', file="link.py")
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)
    assert real.read_text(encoding="utf-8") == "X = 1\n"


@pytest.mark.parametrize("evil", ["../evil.py", "/etc/passwd", "a/../../b.py"])
def test_confine_rejects_traversal_and_absolute(tmp_path: Path, evil: str) -> None:
    """Garde T27.3.1 réutilisée telle quelle (aucune copie locale)."""
    with pytest.raises(PathEscape):
        confine(tmp_path, evil)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO POSIX uniquement")
def test_read_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    """Une FIFO ne doit ni bloquer la lecture (O_NONBLOCK) ni être acceptée."""
    plan = _plan(f'KEY = "{SECRET}"\n')
    os.mkfifo(tmp_path / "app.py")
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, plan)


def test_read_refuses_parent_swapped_after_confine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un parent échangé contre un symlink entre confine() et open() est refusé."""
    source = f'KEY = "{SECRET}"\n'
    root = tmp_path / "repo"
    _write(root / "nested" / "app.py", source)
    outside = tmp_path / "outside"
    _write(outside / "app.py", source)
    plan = _plan(source, file="nested/app.py")

    real_confine = apply_module.confine

    def _confine_then_swap(base: Path, untrusted: object) -> object:
        confined = real_confine(base, untrusted)
        (base / "nested").rename(base / "nested_moved")
        (base / "nested").symlink_to(outside, target_is_directory=True)
        return confined

    monkeypatch.setattr(apply_module, "confine", _confine_then_swap)
    with pytest.raises(ApplyError):
        apply_replacement(root, plan)
    assert (outside / "app.py").read_text(encoding="utf-8") == source


@pytest.mark.parametrize(
    ("backup", "mode"),
    [
        ("/abs/outside.bak", 0o640),
        ("../escape.bak", 0o640),
        ("app.py.bak", True),
        ("app.py.bak", -1),
        ("app.py.bak", 0o1777),
        ("app.py.bak", "640"),
    ],
)
def test_undo_rejects_forged_receipt_without_writing(
    tmp_path: Path, backup: str, mode: object
) -> None:
    source = f'KEY = "{SECRET}"\n'
    _write(tmp_path / "app.py", source)
    receipt = apply_replacement(tmp_path, _plan(source))
    forged = AppliedPatch(
        file="app.py",
        backup=backup,
        mode=mode,  # type: ignore[arg-type]
        after=receipt.after,
    )
    with pytest.raises(ApplyError):
        undo_apply(tmp_path, forged)
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == receipt.after


def test_receipt_backup_is_relative(tmp_path: Path) -> None:
    source = f'KEY = "{SECRET}"\n'
    _write(tmp_path / "nested" / "app.py", source)
    receipt = apply_replacement(tmp_path, _plan(source, file="nested/app.py"))
    assert receipt.backup == "nested/app.py.bak"
    assert str(tmp_path) not in repr(receipt)


def test_apply_rejects_bad_types(tmp_path: Path) -> None:
    plan = _plan(f'KEY = "{SECRET}"\n')
    with pytest.raises(ApplyError):
        apply_replacement("not-a-path", plan)  # type: ignore[arg-type]
    with pytest.raises(ApplyError):
        apply_replacement(tmp_path, "not-a-plan")  # type: ignore[arg-type]
    _write(tmp_path / "ok.py", f'KEY = "{SECRET}"\n')
    receipt = apply_replacement(tmp_path, _plan(f'KEY = "{SECRET}"\n', file="ok.py"))
    with pytest.raises(ApplyError):
        undo_apply(tmp_path, "not-a-receipt")  # type: ignore[arg-type]
    assert isinstance(receipt, AppliedPatch)


def test_apply_backup_warns_when_bak_tracked_by_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un fichier .bak suivi par Git déclenche un avertissement runtime explicite."""
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)

    monkeypatch.setattr(apply_module, "is_git_tracked", lambda path: True)
    receipt = apply_replacement(tmp_path, plan)
    assert isinstance(receipt, AppliedPatch)
    err = capsys.readouterr().err
    assert "ATTENTION : Le fichier" in err
    assert "est suivi par Git !" in err
    assert "app.py.bak" in err


def test_apply_backup_quiet_when_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un fichier .bak ignoré par Git ne produit aucun avertissement."""
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)

    monkeypatch.setattr(apply_module, "is_git_tracked", lambda path: False)
    monkeypatch.setattr(apply_module, "is_git_ignored", lambda path: True)
    receipt = apply_replacement(tmp_path, plan)
    assert isinstance(receipt, AppliedPatch)
    assert capsys.readouterr().err == ""


def test_apply_backup_warns_indeterminate_git_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Hors dépôt Git, un avertissement de statut indéterminé est émis."""
    target = tmp_path / "app.py"
    source = f'KEY = "{SECRET}"\n'
    _write(target, source)
    plan = _plan(source)

    receipt = apply_replacement(tmp_path, plan)
    assert isinstance(receipt, AppliedPatch)
    err = capsys.readouterr().err
    assert "Avertissement : statut Git indéterminé pour" in err
    assert "app.py.bak" in err
