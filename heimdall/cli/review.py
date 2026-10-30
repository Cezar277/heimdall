"""Validation humaine des propositions de T30, sans moteur de remplacement (#32).

Les contenus restent en mémoire et sont exclus des repr. Le backend de T30
reste responsable de la préparation et de l'application atomique des patches.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import sys
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Final

from heimdall.llm.rejections import (
    GENESIS,
    MAX_ENTRY_BYTES,
    MAX_JOURNAL_BYTES,
    JournalError,
    journal_digest,
    journal_encode,
    journal_locked,
)
from heimdall.mcp.masking import mask_text
from heimdall.scanner.finding import Finding, validate_relative_path

MAX_CHANGES: Final[int] = 32
MAX_TEXT_CHARS: Final[int] = 100_000
MAX_SECRETS: Final[int] = 256
#: Bornes de la boucle : aucune réponse par défaut, aucune boucle infinie.
MAX_PROMPTS: Final[int] = 16
MAX_EDITS: Final[int] = 8
#: Longueur maximale acceptée pour une réponse clavier (refus du bruit).
MAX_ANSWER_CHARS: Final[int] = 16
#: Longueur maximale d'une date ISO 8601 acceptée par le journal.
MAX_DATE_CHARS: Final[int] = 40
DECISION_SCHEMA: Final[str] = "heimdall.review-decision.v1"
PROMPT: Final[str] = "Valider (Y), ignorer (N) ou éditer (E) ? "
INVALID_CHOICE: Final[str] = "Réponse invalide : répondre Y, N ou E (aucune action par défaut)."
EDIT_CANCELLED: Final[str] = "Édition annulée : aucune modification, réponse attendue."
NON_INTERACTIVE: Final[str] = (
    "Mode non interactif : rapport seul, aucune écriture, aucune action appliquée."
)
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


class Choice(str, Enum):
    """Les trois actions humaines de #88 ; aucune n'est un défaut implicite."""

    VALIDATE = "y"
    IGNORE = "n"
    EDIT = "e"


_ALIASES: Final[dict[str, Choice]] = {
    "y": Choice.VALIDATE,
    "yes": Choice.VALIDATE,
    "o": Choice.VALIDATE,
    "oui": Choice.VALIDATE,
    "n": Choice.IGNORE,
    "no": Choice.IGNORE,
    "non": Choice.IGNORE,
    "e": Choice.EDIT,
    "edit": Choice.EDIT,
}


def parse_choice(raw: object) -> Choice:
    """Traduit une réponse clavier ; toute autre entrée est refusée.

    Le message d'erreur reste statique (invariant 8) : la réponse de
    l'opérateur n'est jamais reflétée.
    """
    if not isinstance(raw, str) or len(raw) > MAX_ANSWER_CHARS:
        raise ReviewError
    choice = _ALIASES.get(raw.strip().lower())
    if choice is None:
        raise ReviewError
    return choice


def _valid_date(value: object) -> bool:
    if not isinstance(value, str) or len(value) > MAX_DATE_CHARS:
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


@dataclass(frozen=True)
class Decision:
    """Choix humain journalisé : fichier, ligne, action, date (jamais de valeur)."""

    action: Choice
    finding: Finding
    date: str

    def __post_init__(self) -> None:
        if not isinstance(self.action, Choice) or not isinstance(self.finding, Finding):
            raise ReviewError
        if not _valid_date(self.date):
            raise ReviewError

    @classmethod
    def now(cls, action: Choice, finding: Finding) -> Decision:
        return cls(action, finding, datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": DECISION_SCHEMA,
            "action": self.action.value,
            "file": self.finding.file,
            "line": self.finding.line,
            "snippet_hash": self.finding.snippet_hash,
            "date": self.date,
        }


def decision_journal_path() -> Path:
    """État local opérateur, hors dépôt ; jamais un chemin choisi par un outil."""
    base = os.environ.get("XDG_STATE_HOME")
    return (
        (Path(base) if base else Path.home() / ".local" / "state")
        / "heimdall"
        / "review-decisions.jsonl"
    )


_DECISION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "sequence",
        "date",
        "action",
        "file",
        "line",
        "snippet_hash",
        "previous_hash",
    }
)
_CHOICE_VALUES: Final[frozenset[str]] = frozenset(choice.value for choice in Choice)


def _decision_entries(descriptor: int) -> list[dict[str, Any]]:
    """Relit la chaîne complète ; contrat fermé, aucune réparation implicite."""
    if os.fstat(descriptor).st_size > MAX_JOURNAL_BYTES:
        raise JournalError
    os.lseek(descriptor, 0, os.SEEK_SET)
    entries: list[dict[str, Any]] = []
    previous = GENESIS
    total = 0
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        while raw := stream.readline(MAX_ENTRY_BYTES + 1):
            total += len(raw)
            if total > MAX_JOURNAL_BYTES or len(raw) > MAX_ENTRY_BYTES or not raw.endswith(b"\n"):
                raise JournalError
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise JournalError
            digest = entry.pop("hash", None)
            if (
                entry.get("schema") != DECISION_SCHEMA
                or entry.get("previous_hash") != previous
                or entry.get("sequence") != len(entries) + 1
                or digest != journal_digest(entry)
                or journal_encode({**entry, "hash": digest}) + b"\n" != raw
            ):
                raise JournalError
            if (
                set(entry) != _DECISION_FIELDS
                or entry["action"] not in _CHOICE_VALUES
                or not _valid_date(entry["date"])
            ):
                raise JournalError
            previous = digest
            entries.append({**entry, "hash": digest})
    return entries


class DecisionJournal:
    """Journal local chaîné des choix humains (#88), sans valeur de secret."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = decision_journal_path() if path is None else path

    def read(self) -> list[dict[str, Any]]:
        """Relit et vérifie la chaîne ; un journal absent est vide."""
        try:
            with journal_locked(self.path, create=False) as descriptor:
                return [] if descriptor is None else _decision_entries(descriptor)
        except (OSError, ValueError, RuntimeError, RecursionError):
            raise JournalError from None

    def append(self, decision: Decision) -> None:
        """Append durable et vérifié ; une panne ne laisse pas de trace partielle."""
        try:
            if not isinstance(decision, Decision):
                raise JournalError
            with journal_locked(self.path) as descriptor:
                if descriptor is None:
                    raise JournalError
                entries = _decision_entries(descriptor)
                entry = {
                    **decision.as_dict(),
                    "sequence": len(entries) + 1,
                    "previous_hash": entries[-1]["hash"] if entries else GENESIS,
                }
                payload = journal_encode({**entry, "hash": journal_digest(entry)}) + b"\n"
                if len(payload) > MAX_ENTRY_BYTES or (
                    os.fstat(descriptor).st_size + len(payload) > MAX_JOURNAL_BYTES
                ):
                    raise JournalError
                while payload:
                    written = os.write(descriptor, payload)
                    if written <= 0:
                        raise JournalError
                    payload = payload[written:]
                os.fsync(descriptor)
        except (OSError, ValueError, RuntimeError, RecursionError):
            raise JournalError from None


AskFn = Callable[[str], str]
ApplyFn = Callable[[Proposal], None]
EditFn = Callable[[Proposal], "Proposal | None"]
NotifyFn = Callable[[str], None]


def _stderr_notify(message: str) -> None:
    """Avertissement best-effort : un stderr fermé ne doit pas lever."""
    try:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):  # pragma: no cover - canal déjà fermé
        pass


def _stdin_ask(prompt: str) -> str:
    """Lecture clavier ; une entrée fermée est une erreur, jamais un défaut."""
    try:
        return input(prompt)
    except EOFError:
        raise ReviewError from None


def is_interactive(*, ci: bool = False, stream: object | None = None) -> bool:
    """Refus par défaut : sans TTY sûr, aucune écriture n'est autorisée (#89)."""
    if not isinstance(ci, bool):
        raise ReviewError
    if ci:
        return False
    candidate = sys.stdin if stream is None else stream
    isatty = getattr(candidate, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


@dataclass(frozen=True)
class ReviewOutcome:
    """Résultat d'une proposition ; ``proposal`` exclu de ``repr``."""

    action: Choice | None
    applied: bool
    edits: int
    proposal: Proposal = field(repr=False)

    def as_dict(self) -> dict[str, object]:
        return {
            "file": self.proposal.finding.file,
            "line": self.proposal.finding.line,
            "action": None if self.action is None else self.action.value,
            "applied": self.applied,
            "edits": self.edits,
        }


@dataclass(frozen=True)
class ReviewReport:
    """Rapport de la session ; ``remaining`` alimente le code de sortie."""

    outcomes: tuple[ReviewOutcome, ...]
    interactive: bool

    @property
    def applied(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.applied)

    @property
    def remaining(self) -> int:
        return len(self.outcomes) - self.applied

    def render(self) -> str:
        lines: list[str] = []
        if not self.interactive:
            lines.append(NON_INTERACTIVE)
        for outcome in self.outcomes:
            lines.append(render_diff(outcome.proposal))
            lines.append(_status(outcome))
        lines.append(
            f"{len(self.outcomes)} proposition(s), {self.applied} appliquée(s), "
            f"{self.remaining} restante(s)."
        )
        return "\n".join(lines)


def _status(outcome: ReviewOutcome) -> str:
    if outcome.action is None:
        return "Statut : non validée (aucune écriture)."
    if outcome.action is Choice.IGNORE:
        return "Statut : ignorée par l'opérateur (secret laissé en place)."
    if outcome.applied:
        return "Statut : validée et appliquée."
    return "Statut : validée, application non confirmée."


def review_proposal(  # noqa: PLR0912, PLR0913 - boucle et injections explicites
    proposal: Proposal,
    *,
    ask: AskFn | None = None,
    apply: ApplyFn | None = None,
    edit: EditFn | None = None,
    journal: DecisionJournal | None = None,
    interactive: bool = True,
    notify: NotifyFn | None = None,
) -> ReviewOutcome:
    """Boucle Y/N/E (#88) ; aucune action par défaut, aucune écriture non tracée.

    ``apply`` et ``edit`` sont fournis par le backend T30 (#83–#86) : cette
    interface ne calcule ni ne pose aucun patch. Le journal est écrit
    **avant** l'application : sans trace, aucune modification.
    """
    if not isinstance(proposal, Proposal) or not isinstance(interactive, bool):
        raise ReviewError
    if not interactive:
        # #89 : rapport seul, ni backend, ni journal, ni écriture.
        return ReviewOutcome(None, False, 0, proposal)
    ask_fn = _stdin_ask if ask is None else ask
    notify_fn = _stderr_notify if notify is None else notify
    journal_fn = DecisionJournal() if journal is None else journal
    current = proposal
    edits = 0
    prompts = 0
    while True:
        prompts += 1
        if prompts > MAX_PROMPTS:
            raise ReviewError
        # Une lecture impossible (EOF, terminal fermé) interrompt la boucle :
        # ce n'est pas une réponse invalide, donc pas de redemande en aveugle.
        raw = ask_fn(render_diff(current) + "\n" + PROMPT)
        try:
            choice = parse_choice(raw)
        except ReviewError:
            # Entrée invalide : on redemande, on ne devine jamais.
            notify_fn(INVALID_CHOICE)
            continue
        if choice is Choice.IGNORE:
            journal_fn.append(Decision.now(choice, current.finding))
            return ReviewOutcome(choice, False, edits, current)
        if choice is Choice.VALIDATE:
            if apply is None:
                raise ReviewError
            journal_fn.append(Decision.now(choice, current.finding))
            apply(current)
            return ReviewOutcome(choice, True, edits, current)
        if edit is None:
            raise ReviewError
        journal_fn.append(Decision.now(choice, current.finding))
        edited = edit(current)
        if edited is None:
            notify_fn(EDIT_CANCELLED)
            continue
        if not isinstance(edited, Proposal):
            raise ReviewError
        edits += 1
        if edits > MAX_EDITS:
            raise ReviewError
        current = edited


def review_proposals(  # noqa: PLR0913 - boucle et injections explicites
    proposals: Iterable[Proposal],
    *,
    ci: bool = False,
    interactive: bool | None = None,
    ask: AskFn | None = None,
    apply: ApplyFn | None = None,
    edit: EditFn | None = None,
    journal: DecisionJournal | None = None,
    notify: NotifyFn | None = None,
) -> ReviewReport:
    """Session complète ; ``ci`` force le mode non interactif même si demandé."""
    items = tuple(proposals)
    if not all(isinstance(item, Proposal) for item in items):
        raise ReviewError
    if not isinstance(ci, bool) or (interactive is not None and not isinstance(interactive, bool)):
        raise ReviewError
    mode = False if ci else (is_interactive() if interactive is None else interactive)
    outcomes = tuple(
        review_proposal(
            item,
            ask=ask,
            apply=apply,
            edit=edit,
            journal=journal,
            interactive=mode,
            notify=notify,
        )
        for item in items
    )
    return ReviewReport(outcomes, mode)
