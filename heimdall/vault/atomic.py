"""Opérations de fichiers sécurisées et atomiques pour Heimdall (tickets #85, #100).

Fournit l'écriture atomique avec fsync, les permissions strictes 0600 (POSIX),
la gestion des sauvegardes et le contrôle de suivi Git.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Final

_DEFAULT_SECURE_MODE: Final[int] = 0o600


def write_file_atomic(path: Path, content: str | bytes, mode: int = _DEFAULT_SECURE_MODE) -> None:
    """Écrit un fichier de manière atomique avec fsync et permissions strictes.

    Utilise un fichier temporaire dans le même dossier pour garantir que
    `os.replace` reste sur le même système de fichiers (atomicité POSIX).
    """
    resolved_path = path.resolve()
    parent = resolved_path.parent
    parent.mkdir(parents=True, exist_ok=True)

    data = content.encode("utf-8") if isinstance(content, str) else content

    prefix = f".{resolved_path.name}.tmp."
    fd, temp_path_str = tempfile.mkstemp(prefix=prefix, dir=parent)
    temp_path = Path(temp_path_str)
    try:
        if os.name == "posix":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, resolved_path)
        if os.name == "posix":
            os.chmod(resolved_path, mode)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:  # noqa: S110
                pass
        raise


def backup_file(path: Path) -> Path | None:
    """Crée une copie de sauvegarde d'un fichier existant avec droits 0600."""
    if not path.is_file():
        return None
    backup_path = path.with_suffix(path.suffix + ".bak")
    content = path.read_bytes()
    write_file_atomic(backup_path, content, mode=_DEFAULT_SECURE_MODE)
    return backup_path


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse un fichier .env en extrayant les paires clé=valeur.

    Ignore les commentaires (#...) et les lignes vides.
    """
    if not path.is_file():
        return {}
    secrets: dict[str, str] = {}
    content = path.read_text(encoding="utf-8")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]
        if key:
            secrets[key] = val
    return secrets


def parse_example_names(path: Path) -> list[str]:
    """Extrait les noms de variables déclarés dans un .env.example."""
    if not path.is_file():
        return []
    names: list[str] = []
    content = path.read_text(encoding="utf-8")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.partition("=")[0].strip()
        if key and key not in names:
            names.append(key)
    return names


def is_git_tracked(path: Path) -> bool:
    """Vérifie si un fichier est actuellement suivi dans Git."""
    git_bin = shutil.which("git")
    if not git_bin:
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "ls-files", "--error-unmatch", str(path.name)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=path.parent.resolve(),
            check=False,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def is_git_ignored(path: Path) -> bool:
    """Vérifie si un chemin est ignoré par les règles .gitignore."""
    git_bin = shutil.which("git")
    if not git_bin:
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "check-ignore", "-q", str(path.name)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=path.parent.resolve(),
            check=False,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def check_file_mode_600(path: Path) -> bool:
    """Vérifie si un fichier a les permissions 0600 (POSIX)."""
    if os.name != "posix":
        return True
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        return (mode & 0o077) == 0
    except OSError:
        return False


__all__ = [
    "backup_file",
    "check_file_mode_600",
    "is_git_ignored",
    "is_git_tracked",
    "parse_env_file",
    "parse_example_names",
    "write_file_atomic",
]
