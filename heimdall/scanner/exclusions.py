"""Périmètre et politique de contenu du scanner (#59).

Le périmètre n'est **jamais** décidé par le nom d'un fichier. Une exclusion
nominale est un contournement trivial : il suffit de renommer le fichier
(``evil.png``, ``package-lock.json``, ``vendor/secret.txt``…) pour qu'un
secret ne soit ni signalé ni refusé. Le **contenu** décide :

- un fichier **textuel** est décodé puis scanné ;
- un contenu non décodable lève ``ScanError`` : il n'est jamais ignoré
  silencieusement.

Dans le scanner, seule la base VCS (``.git/``, ``.hg/``, ``.svn/``) est
écartée : ce n'est pas le contenu du dépôt. Aucune exclusion nominale n'est
appliquée : le nom d'un fichier ne décide jamais du périmètre, c'est le
**contenu** qui décide (voir ``classer_repertoire`` / ``classer_chemin`` et
``decode_text``). Une exclusion nominale serait un contournement trivial.

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
    """Régime de périmètre d'un chemin relatif (tous ses segments).

    Le nom du fichier lui-même est examiné comme ses répertoires parents :
    seule la base VCS est écartée, où qu'elle apparaisse dans le chemin.
    """
    path = (
        relative_path if isinstance(relative_path, PurePosixPath) else PurePosixPath(relative_path)
    )
    for part in path.parts:
        if classer_repertoire(part) is Perimetre.HORS_PERIMETRE:
            return Perimetre.HORS_PERIMETRE
    return Perimetre.STRICT


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
