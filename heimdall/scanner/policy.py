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
#: Plafond de la sortie de ``prepare_text`` : ~2 Mio, expansion comprise.
#: Il borne la mémoire et le temps face à un fichier adversarial rempli de
#: jetons hors borne. Le budget de fenêtres est calculé à partir de la taille
#: d'origine pour que la sortie totale reste sous ce plafond.
_MAX_CLEANED_BYTES = 2 * 1024 * 1024
#: Budget maximal de fenêtres (une fenêtre + son séparateur ≈ 4097 octets).
_MAX_LONG_TOKEN_WINDOWS = _MAX_CLEANED_BYTES // (MAX_TOKEN_LENGTH + 1)


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


def _window_long_token(token: str, max_windows: int) -> tuple[str, int]:
    """Découpe un jeton hors borne en fenêtres chevauchantes analysables.

    Chaque fenêtre reste dans la borne ``MAX_TOKEN_LENGTH``. Le pas est choisi
    pour tenir dans ``max_windows`` : pas de 1 si le jeton est assez court,
    sinon pas élargi (garantie au moins 2048 pour un jeton d'1 Mio, 4079 pour
    un jeton de 8 Kio). Les fenêtres sont séparées par une espace pour que le
    moteur les traite comme des jetons distincts, sans changer le numéro de
    ligne.

    Retourne ``(texte, nombre_de_fenêtres_utilisées)``.
    """
    if max_windows <= 0:
        return " " * len(token), 0
    length = len(token)
    # Pas de 1 : une fenêtre par position de départ (0..length-1), donc toute
    # sous-chaîne ≤ MAX_TOKEN_LENGTH est entière dans une fenêtre.
    if length <= max_windows:
        step = 1
    else:
        step = max(1, (length + max_windows - 3) // max(1, max_windows - 1))
    windows: list[str] = []
    start = 0
    while start < length and len(windows) < max_windows:
        end = min(start + MAX_TOKEN_LENGTH, length)
        windows.append(token[start:end])
        start += step
    return " ".join(windows), len(windows)


def prepare_text(text: str, file: str, *, strict: bool, skipped: list[ScanSkip]) -> str:
    """Découpe les jetons hors borne en fenêtres ; conserve les autres candidats.

    Les fenêtres sont séparées par des espaces : les lignes et les numéros de
    ligne sont conservés, et une trace par motif et fichier borne le rapport
    même sur une longue ligne. Les fenêtres multilignes hors borne restent
    visibles sans masquer les signatures analysables sur chacune de leurs
    lignes.

    Un jeton hors borne est découpé en fenêtres chevauchantes de
    :data:`MAX_TOKEN_LENGTH` avant analyse ; l'intérieur n'est donc plus
    blanchi en bloc. La sortie est plafonnée à ~2 Mio : le pas est choisi pour
    tenir dans ce budget (garantie au moins 2048 pour un jeton d'1 Mio, 4079
    pour un jeton de 8 Kio). Au-delà du budget, le jeton est blanchi ; le
    rapport reste marqué incomplet par la trace ``long_token`` et un appelant
    ne doit jamais traiter ``complete is False`` comme propre.
    """
    if strict:
        return text
    long_line: int | None = None
    # Le texte d'origine occupe déjà une partie du plafond : ne réserver que
    # l'espace restant pour les fenêtres, afin que la sortie totale reste
    # bornée à ~2 Mio.
    window_budget = min(
        _MAX_LONG_TOKEN_WINDOWS,
        max(0, (_MAX_CLEANED_BYTES - len(text)) // (MAX_TOKEN_LENGTH + 1)),
    )

    def replace(match: re.Match[str], *, line_number: int) -> str:
        nonlocal long_line, window_budget
        token = match.group()
        if len(token) <= MAX_TOKEN_LENGTH:
            return token
        if long_line is None:
            long_line = line_number
        if window_budget <= 0:
            # Budget épuisé : le jeton reste non analysé et le rapport est
            # déjà marqué incomplet par la trace ``long_token``.
            return " " * len(token)
        cleaned, used = _window_long_token(token, window_budget)
        window_budget -= used
        return cleaned

    cleaned_lines: list[str] = []
    multiline_line: int | None = None
    previous_size = 0
    for line_number, line in enumerate(text.split("\n"), start=1):
        # La fenêtre multiligne se mesure sur les lignes d'origine, pas sur
        # le texte expansé : sinon une seule ligne à jeton long déclencherait
        # un ``multiline_limit`` trompeur.
        size = len(line.encode("utf-8"))
        cleaned = _TOKEN.sub(partial(replace, line_number=line_number), line)
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
