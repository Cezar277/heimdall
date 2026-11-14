"""Périmètre et politique de contenu du scanner (#59).

Le périmètre n'est **jamais** décidé par le nom d'un fichier. Une exclusion
nominale est un contournement trivial : il suffit de renommer le fichier
(``evil.png``, ``package-lock.json``, ``vendor/secret.txt``…) pour qu'un
secret ne soit ni signalé ni refusé. Le **contenu** décide :

- un fichier **textuel** est décodé puis scanné ;
- un contenu sans décodage textuel plausible rend ``None`` : le scanner le
  trace comme binaire, ou le refuse en mode strict (#229) ;
- un texte non UTF-8 bénéficie d'un repli CP1252, sans exécution de contenu.

Dans le scanner, seule la base VCS (``.git/``, ``.hg/``, ``.svn/``) est
écartée : ce n'est pas le contenu du dépôt. Aucune exclusion nominale n'est
appliquée : le nom d'un fichier ne décide jamais du périmètre, c'est le
**contenu** qui décide (voir ``est_base_vcs`` /
``est_chemin_hors_perimetre`` et ``decode_text``). Une exclusion nominale
serait un contournement trivial.

Les fichiers texte UTF-8, UTF-16 et UTF-32 (avec ou sans BOM) sont décodés et
scannés. Le contenu n'est jamais exécuté.
"""

from __future__ import annotations

import codecs
import warnings
from pathlib import PurePosixPath
from typing import Final

from heimdall.scanner.errors import ScanError

#: Base VCS : ce n'est pas le contenu du dépôt, elle n'est pas parcourue.
ARBRES_HORS_PERIMETRE: Final[frozenset[str]] = frozenset({".git", ".hg", ".svn"})

#: Surface publique **volontairement fermée** : le helper déprécié
#: ``is_known_binary`` reste importable pour compatibilité historique, mais
#: n'est pas exporté. Aucun périmètre ne doit être branché sur ce nom.
__all__ = [
    "ARBRES_HORS_PERIMETRE",
    "decode_text",
    "est_base_vcs",
    "est_chemin_hors_perimetre",
]


def est_base_vcs(name: str) -> bool:
    """Vrai si ``name`` désigne une base VCS (casse ignorée).

    Seule la base VCS est écartée ; ce prédicat est la **seule** décision de
    périmètre par nom du scanner. Tous les autres noms sont parcourus, quel
    que soit leur contenu.
    """
    return name.casefold() in ARBRES_HORS_PERIMETRE


def est_chemin_hors_perimetre(relative_path: str | PurePosixPath) -> bool:
    """Vrai si un **parent** du chemin relatif est une base VCS.

    Seuls les répertoires parents décident : le dernier segment est un
    **fichier**, pas une base VCS. Un fichier régulier nommé ``.git`` est un
    gitlink légitime (worktree, sous-module : ``gitdir: …``) : il est lu
    comme n'importe quel contenu, jamais confondu avec le répertoire
    ``.git/`` qui, lui, est élagué par :func:`est_base_vcs`.
    """
    path = (
        relative_path if isinstance(relative_path, PurePosixPath) else PurePosixPath(relative_path)
    )
    return any(est_base_vcs(part) for part in path.parts[:-1])


_TEXT_RATIO_MIN: Final[float] = 0.95
_ASCII_RATIO_MIN: Final[float] = 0.05
_BINARY_RATIO_MIN: Final[float] = 0.50
_FIRST_CONTROL_BYTE: Final[int] = 0x20
_DELETE_BYTE: Final[int] = 0x7F
_HIGH_BIT: Final[int] = 0x80
_TEXT_BYTES: Final[frozenset[int]] = frozenset({0x09, 0x0A, 0x0D})
_DECODE_ERROR: Final[str] = "scan impossible : entrée non analysable"

# Signatures fortes de formats binaires connus. Un contenu qui porte l'une
# d'elles ET reste majoritairement binaire est reconnu comme non textuel par
# ``decode_text`` (retour ``None``) : le scanner d'arbre et la CLI ``--staged``
# le tracent ou le refusent selon la politique explicite, jamais silencieusement.
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


def _is_known_binary(data: bytes) -> bool:
    """Vrai si le contenu est un binaire **connu** et majoritairement binaire.

    Même critère que ``decode_text`` pour rendre ``None`` : une signature
    magique connue **et** un ratio d'octets binaires ≥ 0,5. Helper interne :
    il ne décide jamais du périmètre à lui seul et le scanner ne le consulte
    pas par son nom. Les binaires inconnus passent aussi par le décodeur.
    """
    return any(data.startswith(magic) for magic in _BINARY_MAGIC) and (
        _binary_byte_ratio(data) >= _BINARY_RATIO_MIN
    )


def is_known_binary(data: bytes) -> bool:
    """DEPRECATED — helper de politique, sans autorité dans le scanner.

    Conservé uniquement pour compatibilité d'import (documentation et tests
    historiques). Le scanner utilise :func:`decode_text`, qui appelle le
    helper **interne** ``_is_known_binary`` : remplacer ou instrumenter ce
    nom public ne change donc jamais le périmètre d'un scan. Aucun nouvel
    appelant ne doit s'en servir pour décider qu'un fichier est « ignorable
    par son nom » : le contenu décide, et un binaire non reconnu lève
    ``ScanError``. Tout appel émet un ``DeprecationWarning`` pour rendre la
    dépendance visible ; sa suppression est prévue dans un ticket dédié.
    """
    warnings.warn(
        "is_known_binary est déprécié et sans autorité : utiliser decode_text "
        "(le contenu décide, jamais le nom)",
        DeprecationWarning,
        stacklevel=2,
    )
    return _is_known_binary(data)


def decode_text(data: bytes, *, strict: bool = False) -> str | None:  # noqa: PLR0911 - encodages distincts
    """Décode un texte ou rend None pour un contenu non textuel (#229).

    - BOM UTF-8/UTF-16/UTF-32 : décodage strict ;
    - UTF-16/UTF-32 sans BOM : heuristique bornée, jamais de remplacement ;
    - UTF-8 invalide sans NUL : repli CP1252, ou refus avec strict=True ;
    - signature binaire **et** contenu majoritairement binaire : reconnu
      comme non textuel (``None``), l'appelant le trace ou le refuse (une simple signature
      suivie de texte clair ne suffit pas : ce serait un contournement) ;
    - NUL sans décodage possible : None, ou ScanError avec strict=True.

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
            try:
                return _decode_exact(data, encoding)
            except ScanError:
                if strict:
                    raise
                return None
    if b"\x00" not in data:
        try:
            text = data.decode("utf-8")
            # Du bruit de contrôle autour d'un candidat ASCII ne doit pas
            # transformer un texte UTF-8 valide en exclusion binaire.
            return text
        except UnicodeDecodeError:
            if _is_known_binary(data):
                return None
            if strict:
                raise ScanError(_DECODE_ERROR) from None
            # CP1252 préserve les secrets ASCII et les textes occidentaux.
            # Les octets non définis sont remplacés, jamais exécutés.
            text = data.decode("cp1252", errors="replace")
            return text
    decoded = _decode_utf16_or_32(data)
    if decoded is not None:
        return decoded
    if _is_known_binary(data):
        return None
    if strict:
        raise ScanError(_DECODE_ERROR)
    return None
