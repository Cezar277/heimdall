"""Périmètre et politique de contenu du scanner (#59).

Le périmètre n'est **jamais** décidé par le nom d'un fichier. Une exclusion
nominale est un contournement trivial : il suffit de renommer le fichier
(``evil.png``, ``package-lock.json``, ``vendor/secret.txt``…) pour qu'un
secret ne soit ni signalé ni refusé. Le **contenu** décide :

- un fichier **textuel** est décodé puis scanné ;
- un contenu non décodable lève ``ScanError`` : il n'est jamais ignoré
  silencieusement.

Dans le scanner, seule la base VCS (``.git/``, ``.hg/``, ``.svn/``) est
écartée : ce n'est pas le contenu du dépôt.

Le module expose aussi les familles d'exclusions historiques de #59
(``TECHNICAL_*`` / ``TEXT_*``) et ``is_excluded``. Ces helpers restent pour
compatibilité et tests de politique, mais **aucun scan ne les consulte pour
décider du périmètre** : le scanner bibliothèque comme la CLI lisent tout
contenu et c'est le **contenu** qui décide (voir ``classer_repertoire`` /
``classer_chemin``). Une exclusion nominale serait un contournement trivial.

Les fichiers texte UTF-8, UTF-16 et UTF-32 (avec ou sans BOM) sont décodés et
scannés. Le contenu n'est jamais exécuté.
"""

from __future__ import annotations

import codecs
import enum
from pathlib import PurePosixPath
from typing import Final

from heimdall.scanner.errors import ScanError


class Perimetre(enum.Enum):
    """Régime de périmètre d'un chemin (#59).

    Seule la base VCS est écartée ; tout le reste est scanné.
    """

    STRICT = "strict"
    HORS_PERIMETRE = "hors_perimetre"


#: Base VCS : ce n'est pas le contenu du dépôt, elle n'est pas parcourue.
ARBRES_HORS_PERIMETRE: Final[frozenset[str]] = frozenset({".git", ".hg", ".svn"})

#: Répertoires exclus pour raison **technique** : contenu binaire, cache ou
#: environnement non analysable. Les scanner n'apporterait rien (et lèverait
#: parfois un ``ScanError`` sur un binaire à signature inconnue) : ils restent
#: hors périmètre, y compris en mode strict (#29). Les sorties de build
#: (`build`, `dist`, `target`), `bower_components` et `htmlcov` sont
#: **textuelles** : elles rejoignent les répertoires tiers, donc scannées en
#: strict (un secret y est un secret), exclues par la politique #59 seule.
TECHNICAL_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
        "virtualenv",
    }
)

#: Répertoires tiers ou **générés textuels** : la politique #59 les exclut
#: pour limiter le bruit (ou les sorties de build), mais un secret y est un
#: secret. Le mode strict (#29) les scanne.
TEXT_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        "bower_components",
        "build",
        "dist",
        "htmlcov",
        "target",
        "third-party",
        "third_party",
        "vendor",
    }
)

#: Politique #59 par défaut : technique **et** contenu texte.
EXCLUDED_DIRECTORIES: Final[frozenset[str]] = TECHNICAL_DIRECTORIES | TEXT_DIRECTORIES

#: Fichiers exclus pour raison **technique** : format binaire connu
#: (``.coverage`` est une base SQLite, ``bun.lockb`` un blob binaire).
TECHNICAL_FILES: Final[frozenset[str]] = frozenset(
    {
        ".coverage",
        "bun.lockb",
    }
)

#: Fichiers de contrôle et lockfiles **textuels** : exclus par la politique
#: #59, scannés en mode strict (#29).
TEXT_FILES: Final[frozenset[str]] = frozenset(
    {
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".npmignore",
        "composer.lock",
        "go.sum",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)

#: Politique #59 par défaut : technique **et** contenu texte.
EXCLUDED_FILES: Final[frozenset[str]] = TECHNICAL_FILES | TEXT_FILES

#: Suffixes de fichiers **binaires** : jamais analysables par des expressions
#: de texte, donc exclus même en mode strict.
TECHNICAL_SUFFIXES: Final[tuple[str, ...]] = (
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

#: Suffixes de lockfiles **textuels** : exclus par la politique #59, scannés
#: en mode strict (#29).
TEXT_SUFFIXES: Final[tuple[str, ...]] = (
    # Lockfiles générés, quel que soit leur nom.
    ".lock",
)


def classer_repertoire(name: str) -> Perimetre:
    """Régime de périmètre d'un répertoire, d'après son nom (casse ignorée).

    Seule la base VCS est écartée ; le nom ne dispense jamais de lire un
    fichier.
    """
    folded = name.casefold()
    if folded in ARBRES_HORS_PERIMETRE:
        return Perimetre.HORS_PERIMETRE
    return Perimetre.STRICT


def classer_chemin(relative_path: str | PurePosixPath) -> Perimetre:
    """Régime de périmètre d'un chemin relatif (répertoires parents).

    Seule la base VCS est écartée.
    """
    path = (
        relative_path if isinstance(relative_path, PurePosixPath) else PurePosixPath(relative_path)
    )
    for part in path.parts[:-1]:
        if classer_repertoire(part) is Perimetre.HORS_PERIMETRE:
            return Perimetre.HORS_PERIMETRE
    return Perimetre.STRICT


#: Politique #59 par défaut : technique **et** contenu texte.
EXCLUDED_SUFFIXES: Final[tuple[str, ...]] = TEXT_SUFFIXES + TECHNICAL_SUFFIXES


def is_excluded_directory(name: str, *, strict: bool = False) -> bool:
    """Vrai si un nom de répertoire est hors périmètre (casse ignorée).

    En mode ``strict`` (#29), seules les exclusions **techniques** restent :
    ``vendor/``, ``third_party/``, ``build/``, ``dist/``, ``target/`` et les
    autres répertoires textuels sont alors parcourus, parce qu'un secret y
    est un secret.
    """
    folded = name.casefold()
    if folded in TECHNICAL_DIRECTORIES:
        return True
    return not strict and folded in TEXT_DIRECTORIES


def has_technical_suffix(name: str) -> bool:
    """Vrai si le nom (casse ignorée) porte un suffixe binaire connu."""
    folded = name.casefold()
    return any(folded.endswith(suffix) for suffix in TECHNICAL_SUFFIXES)


def is_excluded(relative_path: str | PurePosixPath, *, strict: bool = False) -> bool:
    """Vrai si le chemin relatif (séparateurs ``/``) est exclu du scan.

    En mode ``strict`` (#29), les exclusions de **contenu texte** (lockfiles,
    fichiers de contrôle) sont levées ; les exclusions techniques (binaires)
    restent. Un suffixe binaire n'est toutefois plus un verdict à lui seul en
    strict : le contenu est lu, et le suffixe ne sert de repli qu'après un
    échec de ``decode_text`` (un fichier texte mal nommé ``evil.png`` doit
    être scanné, comme en ``--staged``). Voir ``Scanner._read_text``.
    """
    path = (
        relative_path if isinstance(relative_path, PurePosixPath) else PurePosixPath(relative_path)
    )
    if not path.parts:
        return False
    if any(is_excluded_directory(part, strict=strict) for part in path.parts[:-1]):
        return True
    name = path.parts[-1].casefold()
    if name in TECHNICAL_FILES:
        return True
    if not strict and name in TEXT_FILES:
        return True
    if has_technical_suffix(name):
        # En strict, le contenu décide en premier ; le suffixe ne redevient
        # une exclusion qu'après échec de décodage (voir `_read_text`).
        return not strict
    return not strict and any(name.endswith(suffix) for suffix in TEXT_SUFFIXES)


_TEXT_RATIO_MIN: Final[float] = 0.95
_ASCII_RATIO_MIN: Final[float] = 0.05
_BINARY_RATIO_MIN: Final[float] = 0.50
_FIRST_CONTROL_BYTE: Final[int] = 0x20
_DELETE_BYTE: Final[int] = 0x7F
_HIGH_BIT: Final[int] = 0x80
_TEXT_BYTES: Final[frozenset[int]] = frozenset({0x09, 0x0A, 0x0D})
_DECODE_ERROR: Final[str] = "scan impossible : entrée non analysable"

# Signatures fortes de formats binaires connus. Un fichier sans extension qui
# porte l'une d'elles est ignoré par politique ; les autres contenus NUL non
# décodables lèvent ``ScanError`` (fail-closed).
_BINARY_MAGIC: Final[tuple[bytes, ...]] = (
    b"\x7fELF",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"SQLite format 3\x00",
    b"OggS",
    b"fLaC",
    b"RIFF",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\x00asm",
    b"wOFF",
    b"wOF2",
    b"II*\x00",
    b"MM\x00*",
    b"\x00\x00\x01\x00",
    b"OTTO",
    b"dex\n",
    b"\xca\xfe\xba\xbe",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for character in text if character.isprintable() or character in "\r\n\t")
    return printable / len(text)


def _ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for character in text if character.isascii()) / len(text)


def _binary_byte_ratio(data: bytes) -> float:
    """Part des octets qui ne sont pas du texte ASCII imprimable."""
    if not data:
        return 0.0
    binary = sum(
        1
        for byte in data
        if (
            (byte < _FIRST_CONTROL_BYTE and byte not in _TEXT_BYTES)
            or byte == _DELETE_BYTE
            or byte >= _HIGH_BIT
        )
    )
    return binary / len(data)


def _decode_exact(data: bytes, encoding: str) -> str:
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        raise ScanError(_DECODE_ERROR) from None
    if text == "":
        return text
    if "\x00" in text or _printable_ratio(text) < _TEXT_RATIO_MIN:
        raise ScanError(_DECODE_ERROR)
    return text


def _decode_utf16_or_32(data: bytes) -> str | None:
    """Décode un texte UTF-16/32 sans BOM, sinon ``None``.

    Le meilleur candidat est choisi par proportion d'ASCII puis de caractères
    imprimables : un texte UTF-16BE mal décodé en LE devient du CJK (ASCII 0)
    et perd face au bon décodage. Un binaire qui ne produit pas un texte
    plausible n'est jamais retenu.
    """
    best: tuple[tuple[float, float], str] | None = None
    for encoding, width in (
        ("utf-16-le", 2),
        ("utf-16-be", 2),
        ("utf-32-le", 4),
        ("utf-32-be", 4),
    ):
        if len(data) % width:
            continue
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        ratio = _printable_ratio(text)
        ascii_ratio = _ascii_ratio(text)
        if "\x00" in text or ratio < _TEXT_RATIO_MIN or ascii_ratio < _ASCII_RATIO_MIN:
            continue
        score = (ascii_ratio, ratio)
        if best is None or score > best[0]:
            best = (score, text)
    return None if best is None else best[1]


def is_known_binary(data: bytes) -> bool:
    """Vrai si le contenu est un binaire **connu** et majoritairement binaire.

    Même critère que ``decode_text`` pour rendre ``None`` : une signature
    magique connue **et** un ratio d'octets binaires ≥ 0,5. Sert de repli
    explicite au scanner pour un fichier à suffixe technique, sans transformer
    un binaire inconnu (NUL + texte) en skip silencieux.
    """
    return any(data.startswith(magic) for magic in _BINARY_MAGIC) and (
        _binary_byte_ratio(data) >= _BINARY_RATIO_MIN
    )


def decode_text(data: bytes) -> str | None:
    """Décode un fichier texte ou identifie un binaire connu.

    - BOM UTF-8/UTF-16/UTF-32 : décodage strict ;
    - UTF-16/UTF-32 sans BOM : heuristique bornée, jamais de remplacement ;
    - UTF-8 invalide sans NUL : ScanError statique (#23) ;
    - signature binaire **et** contenu majoritairement binaire : ignoré par
      politique (une simple signature suivie de texte clair ne suffit pas :
      ce serait un contournement) ;
    - NUL sans décodage possible : ``ScanError``.

    Le nom du fichier n'intervient jamais : un ``evil.png`` dont le contenu
    est du texte est décodé et scanné comme un ``.txt``.
    """
    if not data:
        return ""
    for bom, encoding in (
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
        (codecs.BOM_UTF8, "utf-8-sig"),
    ):
        if data.startswith(bom):
            return _decode_exact(data, encoding)
    if b"\x00" not in data:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            if is_known_binary(data):
                return None
            raise ScanError(_DECODE_ERROR) from None
    decoded = _decode_utf16_or_32(data)
    if decoded is not None:
        return decoded
    if is_known_binary(data):
        return None
    raise ScanError(_DECODE_ERROR)
