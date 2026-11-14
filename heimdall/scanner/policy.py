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


def prepare_text(text: str, file: str, *, strict: bool, skipped: list[ScanSkip]) -> str:
    """Écarte seulement les jetons hors borne ; conserve les autres candidats.

    Le remplacement par des espaces conserve les lignes et les séparations.
    Une trace par motif et fichier borne le rapport même sur une longue ligne.
    Les fenêtres multilignes hors borne restent visibles sans masquer les
    signatures analysables sur chacune de leurs lignes.

    L'intérieur d'un jeton hors borne n'est **pas** analysé (limite
    documentée) : le rapport est marqué incomplet par la trace ``long_token``
    et un appelant ne doit jamais traiter ``complete is False`` comme propre.
    """
    if strict:
        return text
    long_line: int | None = None

    def replace(match: re.Match[str], *, line_number: int) -> str:
        nonlocal long_line
        if len(match.group()) <= MAX_TOKEN_LENGTH:
            return match.group()
        if long_line is None:
            long_line = line_number
        return " " * len(match.group())

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
