"""Exclusions de contenu explicites, bornées et sans extrait de secret (#229)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import partial
from typing import Literal

from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import validate_relative_path
from heimdall.scanner.limits import MAX_TOKEN_LENGTH, TEXT_WINDOW_BYTES

SkipReason = Literal["binary", "too_large", "symlink", "long_token", "multiline_limit"]
_TOKEN = re.compile(r"[A-Za-z0-9_+/-]+={0,2}")
#: Chevauchement des fenêtres d'un jeton hors borne : une signature qui
#: traverse une frontière reste entière dans la fenêtre suivante.
_LONG_TOKEN_OVERLAP = MAX_TOKEN_LENGTH // 2
_LONG_TOKEN_STEP = MAX_TOKEN_LENGTH - _LONG_TOKEN_OVERLAP


@dataclass(frozen=True)
class ScanSkip:
    file: str
    reason: SkipReason
    line: int | None = None

    def __post_init__(self) -> None:
        validate_relative_path(self.file)
        if self.reason not in {"binary", "too_large", "symlink", "long_token", "multiline_limit"}:
            raise ValueError("motif d'exclusion invalide")
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise ValueError("ligne d'exclusion invalide")

    def as_dict(self) -> dict[str, str | int | None]:
        return {"file": self.file, "reason": self.reason, "line": self.line}


def _window_long_token(token: str) -> str:
    """Découpe un jeton hors borne en fenêtres chevauchantes analysables.

    Chaque fenêtre reste dans la borne ``MAX_TOKEN_LENGTH`` ; le chevauchement
    de moitié évite qu'une signature à cheval sur deux fenêtres disparaisse.
    Les fenêtres sont séparées par une espace pour que le moteur les traite
    comme des jetons distincts, sans changer le numéro de ligne.
    """
    windows: list[str] = []
    start = 0
    length = len(token)
    while start < length:
        end = min(start + MAX_TOKEN_LENGTH, length)
        windows.append(token[start:end])
        start += _LONG_TOKEN_STEP
    return " ".join(windows)


def prepare_text(text: str, file: str, *, strict: bool, skipped: list[ScanSkip]) -> str:
    """Découpe les jetons hors borne en fenêtres ; conserve les autres candidats.

    Les fenêtres sont séparées par des espaces : les lignes et les numéros de
    ligne sont conservés, et une trace par motif et fichier borne le rapport
    même sur une longue ligne. Les fenêtres multilignes hors borne restent
    visibles sans masquer les signatures analysables sur chacune de leurs
    lignes.

    Un jeton hors borne est découpé en fenêtres chevauchantes de
    :data:`MAX_TOKEN_LENGTH` avant analyse ; l'intérieur n'est donc plus
    blanchi en bloc. Le rapport reste marqué incomplet par la trace
    ``long_token`` (une signature concaténée sans frontière peut encore
    échapper aux motifs) et un appelant ne doit jamais traiter
    ``complete is False`` comme propre.
    """
    if strict:
        return text
    long_line: int | None = None

    def replace(match: re.Match[str], *, line_number: int) -> str:
        nonlocal long_line
        token = match.group()
        if len(token) <= MAX_TOKEN_LENGTH:
            return token
        if long_line is None:
            long_line = line_number
        return _window_long_token(token)

    cleaned_lines: list[str] = []
    multiline_line: int | None = None
    previous_size = 0
    for line_number, line in enumerate(text.split("\n"), start=1):
        cleaned = _TOKEN.sub(partial(replace, line_number=line_number), line)
        size = len(cleaned.encode("utf-8"))
        if line_number > 1 and previous_size + size > TEXT_WINDOW_BYTES and multiline_line is None:
            multiline_line = line_number - 1
        previous_size = size
        cleaned_lines.append(cleaned)
    try:
        if long_line is not None:
            skipped.append(ScanSkip(file, "long_token", long_line))
        if multiline_line is not None:
            skipped.append(ScanSkip(file, "multiline_limit", multiline_line))
    except ValueError:
        raise ScanError("scan impossible : entrée non analysable") from None
    return "\n".join(cleaned_lines)


def skip_file(file: str, reason: SkipReason, *, strict: bool, skipped: list[ScanSkip]) -> None:
    if strict:
        raise ScanError("scan impossible : entrée non analysable")
    try:
        skipped.append(ScanSkip(file, reason))
    except ValueError:
        raise ScanError("scan impossible : entrée non analysable") from None
