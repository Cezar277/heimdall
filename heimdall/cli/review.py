"""Validation humaine des propositions de T30, sans moteur de remplacement (#32).

Les contenus restent en mémoire et sont exclus des repr. Le backend de T30
reste responsable de la préparation et de l'application atomique des patches.
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Final

from heimdall.mcp.masking import mask_text
from heimdall.scanner.finding import Finding, validate_relative_path

MAX_CHANGES: Final[int] = 32
MAX_TEXT_CHARS: Final[int] = 100_000
MAX_SECRETS: Final[int] = 256
_VARIABLE: Final[re.Pattern[str]] = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
_ENV_REFERENCE: Final[re.Pattern[str]] = re.compile(
    r"(?:os\.getenv\([\"'][A-Z_][A-Z0-9_]{0,63}[\"']\)"
    r"|os\.environ\[[\"'][A-Z_][A-Z0-9_]{0,63}[\"']\]"
    r"|process\.env\.[A-Z_][A-Z0-9_]{0,63})"
)


class ReviewError(Exception):
    """Erreur statique : ne jamais refléter de contenu ou de réponse du backend."""

    def __init__(self) -> None:
        super().__init__("validation humaine impossible : proposition ou outillage invalide")


def validate_variable(value: str) -> str:
    """Grammaire d'affichage ; T30 doit aussi valider sa politique de remplacement."""
    if not isinstance(value, str) or _VARIABLE.fullmatch(value) is None:
        raise ReviewError
    return value


@dataclass(frozen=True)
class TextChange:
    """Snapshot avant/après, jamais un chemin à ouvrir depuis l'interface."""

    file: str
    before: str = field(repr=False)
    after: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            validate_relative_path(self.file)
        except ValueError:
            raise ReviewError from None
        # Le fichier .env contient les vraies valeurs et ne doit pas être rendu.
        if any(part == ".git" for part in self.file.split("/")) or (
            self.file.split("/")[-1].startswith(".env")
            and self.file.split("/")[-1] != ".env.example"
        ):
            raise ReviewError
        if any(
            not isinstance(text, str) or len(text) > MAX_TEXT_CHARS
            for text in (self.before, self.after)
        ):
            raise ReviewError


@dataclass(frozen=True)
class Proposal:
    """Un choix humain couvre tous les changements de cette proposition.

    Le producteur fournit toutes les valeurs sensibles connues, y compris
    celles du contexte. Le masque heuristique MCP ajoute un filet conservateur.
    """

    finding: Finding
    variable: str
    changes: tuple[TextChange, ...] = field(repr=False)
    secrets: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        validate_variable(self.variable)
        if (
            not isinstance(self.finding, Finding)
            or not isinstance(self.changes, tuple)
            or not 1 <= len(self.changes) <= MAX_CHANGES
            or not all(isinstance(change, TextChange) for change in self.changes)
            or not isinstance(self.secrets, tuple)
            or not 1 <= len(self.secrets) <= MAX_SECRETS
            or any(
                not isinstance(secret, str) or not 1 <= len(secret) <= MAX_TEXT_CHARS
                for secret in self.secrets
            )
        ):
            raise ReviewError
        names = [change.file for change in self.changes]
        if len(set(names)) != len(names) or self.finding.file not in names:
            raise ReviewError


def _visible(text: str) -> str:
    return "".join(
        character.encode("unicode_escape").decode("ascii")
        if unicodedata.category(character).startswith("C") or character in "\u2028\u2029"
        else character
        for character in text
    )


def _masked(text: str, secrets: tuple[str, ...]) -> str:
    # Un seul passage : une valeur courte ne peut altérer le marqueur d'une
    # valeur déjà masquée. Les valeurs qui se chevauchent sont triées par taille.
    pattern = re.compile(
        "|".join(re.escape(value) for value in sorted(set(secrets), key=len, reverse=True))
    )
    text = pattern.sub(lambda match: f"<MASKED_{len(match[0])}>", text)
    # Le masque MCP est volontairement très conservateur sur les appels.
    # Préserver uniquement la grammaire fermée des références d'environnement,
    # après suppression des valeurs connues, garde le remplacement lisible.
    chunks: list[str] = []
    start = 0
    for match in _ENV_REFERENCE.finditer(text):
        chunks.extend((mask_text(text[start : match.start()])[0], match[0]))
        start = match.end()
    chunks.append(mask_text(text[start:])[0])
    return "".join(chunks)


def render_diff(proposal: Proposal) -> str:
    """Diff unifié masqué AVANT calcul, sans contrôles terminal ni ANSI."""

    def label(text: str) -> str:
        return _visible(_masked(text, proposal.secrets))

    lines = [
        f"Proposition : {label(proposal.finding.file)}:{proposal.finding.line}",
        f"Variable : {label(proposal.variable)}",
    ]
    for change in proposal.changes:
        before = [_visible(line) for line in _masked(change.before, proposal.secrets).splitlines()]
        after = [_visible(line) for line in _masked(change.after, proposal.secrets).splitlines()]
        lines.extend(
            difflib.unified_diff(
                before,
                after,
                fromfile="a/" + label(change.file),
                tofile="b/" + label(change.file),
                lineterm="",
                n=3,
            )
        )
    return "\n".join(lines)
