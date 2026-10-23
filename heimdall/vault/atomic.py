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


def write_file_atomic(  # noqa: PLR0912, PLR0915
    path: Path,
    content: str | bytes,
    mode: int = _DEFAULT_SECURE_MODE,
) -> None:
    """Écrit un fichier de manière atomique avec fsync et permissions strictes.

    Refuse strictement les liens symboliques (cible ou répertoire parent)
    afin de prévenir tout écrasement ou détournement de cible.
    """
    if os.path.islink(path):
        raise ValueError(f"Écriture refusée : la cible '{path}' est un lien symbolique.")

    parent = path.parent
    if os.path.islink(parent):
        raise ValueError(
            f"Écriture refusée : le répertoire parent '{parent}' est un lien symbolique."
        )

    parent.mkdir(parents=True, exist_ok=True)
    if os.path.islink(parent):
        raise ValueError(
            f"Écriture refusée : le répertoire parent '{parent}' est un lien symbolique."
        )

    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW

    try:
        parent_fd = os.open(parent, parent_flags)
    except OSError as exc:
        raise ValueError(f"Impossible d'ouvrir le répertoire parent : {exc}") from exc

    data = content.encode("utf-8") if isinstance(content, str) else content
    prefix = f".{path.name}.tmp."

    temp_fd, temp_path_str = tempfile.mkstemp(prefix=prefix, dir=parent)
    temp_path = Path(temp_path_str)

    try:
        if os.name == "posix":
            os.fchmod(temp_fd, mode)
        with os.fdopen(temp_fd, "wb") as f:
            temp_fd = -1  # Géré désormais par f
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        if os.path.islink(path):
            raise ValueError(f"Écriture refusée : la cible '{path}' est un lien symbolique.")

        os.replace(temp_path, path)

        if os.name == "posix":
            os.chmod(path, mode)

        try:
            os.fsync(parent_fd)
        except OSError:
            pass
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:  # noqa: S110
                pass
        raise
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:  # noqa: S110
                pass
        try:
            os.close(parent_fd)
        except OSError:  # noqa: S110
            pass


def backup_file(path: Path) -> Path | None:
    """Crée une copie de sauvegarde d'un fichier existant avec droits 0600."""
    if os.path.islink(path):
        raise ValueError(f"Sauvegarde refusée : '{path}' est un lien symbolique.")
    if not path.is_file():
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Impossible d'ouvrir le fichier à sauvegarder : {exc}") from exc

    try:
        with os.fdopen(fd, "rb") as f:
            fd = -1
            content = f.read()
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:  # noqa: S110
                pass

    backup_path = path.with_suffix(path.suffix + ".bak")
    if os.path.islink(backup_path):
        raise ValueError(
            f"Sauvegarde refusée : la cible backup '{backup_path}' est un lien symbolique."
        )

    write_file_atomic(backup_path, content, mode=_DEFAULT_SECURE_MODE)
    return backup_path


def _read_file_secure_no_follow(path: Path) -> str | None:
    """Lit un fichier de manière sécurisée sans suivre les liens symboliques (anti-TOCTOU)."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        fd = os.open(path, flags)
    except OSError:
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            return f.read()
    except Exception:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:  # noqa: S110
                pass
    return None


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse un fichier .env en extrayant les paires clé=valeur.

    Ignore les commentaires (#...) et les lignes vides.
    Refuse de suivre les liens symboliques (anti-exfiltration).
    """
    content = _read_file_secure_no_follow(path)
    if content is None:
        return {}
    secrets: dict[str, str] = {}
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
    """Extrait les noms de variables déclarés dans un .env.example.

    Refuse de suivre les liens symboliques.
    """
    content = _read_file_secure_no_follow(path)
    if content is None:
        return []
    names: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.partition("=")[0].strip()
        if key and key not in names:
            names.append(key)
    return names


def _get_git_toplevel(path: Path) -> Path | None:
    """Trouve la racine du dépôt Git contenant le chemin."""
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    parent_dir = path if path.is_dir() else path.parent
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=parent_dir,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            top = res.stdout.strip()
            if top:
                return Path(top)
    except Exception:  # noqa: S110
        pass
    return None


def is_git_tracked(path: Path) -> bool:
    """Vérifie si un fichier est actuellement suivi dans Git."""
    git_bin = shutil.which("git")
    if not git_bin:
        return False
    top = _get_git_toplevel(path)
    if top is None:
        return False
    try:
        rel = path.resolve().relative_to(top.resolve())
    except ValueError:
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "ls-files", "--error-unmatch", str(rel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=top,
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
    top = _get_git_toplevel(path)
    if top is None:
        return False
    try:
        rel = path.resolve().relative_to(top.resolve())
    except ValueError:
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "check-ignore", "-q", str(rel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=top,
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
