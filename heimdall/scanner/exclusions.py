"""Exclusions déterministes du scanner (#59).

Le périmètre est une politique explicite, pas une heuristique :

- fichiers de contrôle de version et d'outillage (``.gitignore``, ...) ;
- répertoires générés ou tiers (``.git``, ``vendor``, ``node_modules``, ...) ;
- lockfiles et sommes de contrôle générées ;
- binaires (extension connue ou octet NUL dans le contenu lu).

Un fichier exclu est ignoré **par politique**. Tout autre échec de lecture ou
de décodage est fail-closed : il remonte en ``ScanError``, jamais en verdict
propre. Le contenu n'est jamais exécuté.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Final

EXCLUDED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "bower_components",
        "build",
        "dist",
        "env",
        "htmlcov",
        "node_modules",
        "target",
        "third-party",
        "third_party",
        "vendor",
        "venv",
        "virtualenv",
    }
)

EXCLUDED_FILES: Final[frozenset[str]] = frozenset(
    {
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".npmignore",
        "bun.lockb",
        "composer.lock",
        "go.sum",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)

EXCLUDED_SUFFIXES: Final[tuple[str, ...]] = (
    # Lockfiles générés, quel que soit leur nom.
    ".lock",
    # Binaires et artefacts non analysables par des expressions de texte.
    ".7z",
    ".avi",
    ".bin",
    ".bmp",
    ".bz2",
    ".class",
    ".db",
    ".der",
    ".dll",
    ".dylib",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".pyc",
    ".pyo",
    ".rar",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".ttf",
    ".webp",
    ".whl",
    ".woff",
    ".woff2",
    ".xz",
    ".zip",
    ".zst",
)


def is_excluded_directory(name: str) -> bool:
    """Vrai si un nom de répertoire est hors périmètre (casse ignorée)."""
    return name.casefold() in EXCLUDED_DIRECTORIES


def is_excluded(relative_path: str | PurePosixPath) -> bool:
    """Vrai si le chemin relatif (séparateurs ``/``) est exclu du scan."""
    path = (
        relative_path
        if isinstance(relative_path, PurePosixPath)
        else PurePosixPath(relative_path)
    )
    if not path.parts:
        return False
    if any(is_excluded_directory(part) for part in path.parts[:-1]):
        return True
    name = path.parts[-1].casefold()
    if name in EXCLUDED_FILES:
        return True
    return any(name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES)


def is_binary(data: bytes) -> bool:
    """Détection binaire conservative : un octet NUL suffit à exclure."""
    return b"\x00" in data
