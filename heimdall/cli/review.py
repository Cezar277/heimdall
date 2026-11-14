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
from functools import partial
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
#: Taille totale des valeurs connues : borne le motif de masquage (DoS local).
MAX_SECRET_BYTES: Final[int] = 262_144
#: Bornes de la boucle : aucune réponse par défaut, aucune boucle infinie.
MAX_PROMPTS: Final[int] = 16
MAX_EDITS: Final[int] = 8
#: Nombre maximal de propositions par session (disponibilité locale).
MAX_PROPOSALS: Final[int] = 1024
#: Volume maximal retenu par session, en octets (disponibilité locale).
MAX_SESSION_BYTES: Final[int] = 64 * 1024 * 1024
#: Longueur maximale acceptée pour une réponse clavier (refus du bruit).
MAX_ANSWER_CHARS: Final[int] = 16
#: Longueur maximale d'une date ISO 8601 acceptée par le journal.
MAX_DATE_CHARS: Final[int] = 40
DECISION_SCHEMA: Final[str] = "heimdall.review-decision.v1"
#: Marqueur de masquage à longueur constante (aucun oracle de taille).
MASKED_MARKER: Final[str] = "<MASKED>"
PROMPT: Final[str] = "Valider (Y), ignorer (N) ou éditer (E) ? "
PROMPT_NO_EDIT: Final[str] = "Valider (Y) ou ignorer (N) ? "
INVALID_CHOICE: Final[str] = "Réponse invalide : répondre Y, N ou E (aucune action par défaut)."
INVALID_CHOICE_NO_EDIT: Final[str] = (
    "Réponse invalide : répondre Y ou N (aucune action par défaut)."
)
EDIT_CANCELLED: Final[str] = "Édition annulée : aucune modification, réponse attendue."
UNAPPLIED_TRACE: Final[str] = (
    "Modification appliquée mais non journalisée : trace d'audit incomplète."
)
NON_INTERACTIVE: Final[str] = (
    "Mode non interactif : rapport seul, aucune écriture, aucune action appliquée."
)
#: Invariant 2 : au moins deux caractères, commence par une lettre majuscule.
_VARIABLE: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_ENV_REFERENCE: Final[re.Pattern[str]] = re.compile(
    r"(?:os\.getenv\([\"'][A-Z][A-Z0-9_]{1,63}[\"']\)"
    r"|os\.environ\[[\"'][A-Z][A-Z0-9_]{1,63}[\"']\]"
    r"|process\.env\.[A-Z][A-Z0-9_]{1,63})"
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
        # Comparaison insensible à la casse : sur macOS/Windows, `.Git/config`
        # ou `.ENV.local` désignent les mêmes fichiers.
        parts = [part.lower() for part in self.file.split("/")]
        if any(part == ".git" for part in parts) or (
            parts[-1].startswith(".env") and parts[-1] != ".env.example"
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
        # Borne AVANT compilation : un motif géant serait un DoS local et
        # pourrait faire fuiter les valeurs dans un `re.error`.
        if sum(len(secret) for secret in self.secrets) > MAX_SECRET_BYTES:
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


def _net(text: str) -> str:
    """Filet MCP ramené au marqueur constant.

    ``mask_text`` émet ``<REDACTED:type:len=N>`` : le type et la longueur
    exacte seraient un oracle pour un candidat heuristique non listé dans
    ``secrets``. Ce rendu n'affiche donc qu'un marqueur de longueur fixe.
    """
    masked, _ = mask_text(text)
    masked = _REDACTION.sub(MASKED_MARKER, masked)
    if "<REDACTED:" in masked:
        # Marqueur non reconnu : refus plutôt que réaffichage d'un type ou
        # d'une longueur (fail-closed).
        raise ReviewError
    return masked


def _secret_pattern(secrets: tuple[str, ...]) -> re.Pattern[str] | None:
    """Motif unique, compilé une seule fois par rendu (jamais par ligne).

    La taille totale est déjà bornée par :class:`Proposal`
    (:data:`MAX_SECRET_BYTES`) ; un échec de compilation reste une erreur
    statique, jamais un ``re.error`` portant le motif (donc les valeurs).
    """
    values = sorted(set(secrets), key=len, reverse=True)
    if not values:
        return None
    try:
        return re.compile("|".join(re.escape(value) for value in values))
    except re.error:  # pragma: no cover - motif borné et échappé par construction
        raise ReviewError from None


def _masked(text: str, pattern: re.Pattern[str] | None) -> str:
    # Un seul passage : une valeur courte ne peut altérer le marqueur d'une
    # valeur déjà masquée. Les valeurs qui se chevauchent sont triées par taille.
    if pattern is not None:
        # Marqueur CONSTANT : révéler `len(valeur)` serait un oracle de
        # longueur (deux secrets de même famille deviendraient distincts
        # sur un écran partagé ou un journal de session).
        text = pattern.sub(MASKED_MARKER, text)
    # Le masque MCP est volontairement très conservateur sur les appels.
    # Préserver uniquement la grammaire fermée des références d'environnement,
    # après suppression des valeurs connues, garde le remplacement lisible.
    chunks: list[str] = []
    start = 0
    for match in _ENV_REFERENCE.finditer(text):
        chunks.extend((_net(text[start : match.start()]), match[0]))
        start = match.end()
    chunks.append(_net(text[start:]))
    return "".join(chunks)


def render_diff(proposal: Proposal) -> str:
    """Diff unifié masqué AVANT calcul, sans contrôles terminal ni ANSI.

    C'est le chemin **durci** : toute panne de masquage ou de ``difflib``
    (``MemoryError``, ``KeyboardInterrupt`` opérateur, ``re.error``…) devient
    une :class:`ReviewError` statique, donc un code d'outillage 2 chez
    l'appelant. Aucune valeur ne ressort avec une traceback (invariants 8
    et 11).
    """
    try:
        return _render_diff(proposal)
    except ReviewError:
        raise
    except BaseException:  # refus par défaut, jamais de traceback de rendu
        raise ReviewError from None


def _render_diff(proposal: Proposal) -> str:
    pattern = _secret_pattern(proposal.secrets)

    def label(text: str) -> str:
        return _visible(_masked(text, pattern))

    lines = [
        f"Proposition : {label(proposal.finding.file)}:{proposal.finding.line}",
        f"Variable : {label(proposal.variable)}",
    ]
    for change in proposal.changes:
        before = [_visible(line) for line in _masked(change.before, pattern).splitlines()]
        after = [_visible(line) for line in _masked(change.after, pattern).splitlines()]
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
    """Choix humain journalisé : fichier, ligne, action, date, résultat.

    ``applied`` dit ce qui s'est **réellement** passé : le journal ne
    prétend jamais qu'une tentative a abouti (audit non répudiable).
    """

    action: Choice
    finding: Finding
    date: str
    applied: bool

    def __post_init__(self) -> None:
        if not isinstance(self.action, Choice) or not isinstance(self.finding, Finding):
            raise ReviewError
        if not isinstance(self.applied, bool) or not _valid_date(self.date):
            raise ReviewError
        # Seul Y peut aboutir à une application ; N et E n'écrivent rien.
        if self.applied and self.action is not Choice.VALIDATE:
            raise ReviewError

    @classmethod
    def now(cls, action: Choice, finding: Finding, *, applied: bool = False) -> Decision:
        return cls(action, finding, datetime.now(timezone.utc).isoformat(), applied)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": DECISION_SCHEMA,
            "action": self.action.value,
            "applied": self.applied,
            "file": self.finding.file,
            "line": self.finding.line,
            "snippet_hash": self.finding.snippet_hash,
            "date": self.date,
        }


def decision_journal_path() -> Path:
    """État local opérateur, hors dépôt ; jamais un chemin choisi par un outil.

    ``XDG_STATE_HOME`` est un environnement opérateur : une valeur invalide
    (octet NUL) ou un ``HOME`` indisponible ne doit pas produire de traceback
    non statique (invariant 8).
    """
    try:
        base = os.environ.get("XDG_STATE_HOME")
        path = (
            (Path(base) if base else Path.home() / ".local" / "state")
            / "heimdall"
            / "review-decisions.jsonl"
        )
        # `Path` accepte un octet NUL ; il n'échouerait qu'au premier appel
        # système, hors du contrat d'erreur statique.
        if "\x00" in str(path):
            raise JournalError
        return path
    except JournalError:
        raise
    except BaseException:  # refus par défaut, jamais de message d'environnement
        raise JournalError from None


_DECISION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "sequence",
        "date",
        "action",
        "applied",
        "file",
        "line",
        "snippet_hash",
        "previous_hash",
    }
)
_CHOICE_VALUES: Final[frozenset[str]] = frozenset(choice.value for choice in Choice)


#: Empreinte Finding v1 : 64 caractères hexadécimaux minuscules.
_HASH: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
#: Marqueur du filet MCP, ramené à une longueur constante dans ce rendu.
#: Motif volontairement large : un futur type hors `[a-z_]` doit être
#: réécrit lui aussi, sinon `type` et `len` fuiraient à nouveau. Un marqueur
#: malformé (imbrication non fermée produite par ``mask_text``) est refusé
#: par la post-condition de :func:`_net`.
_REDACTION: Final[re.Pattern[str]] = re.compile(r"<REDACTED:[^<>]*>")


def _valid_target(entry: dict[str, Any]) -> bool:
    """Types du contrat fermé : `file`, `line` et `snippet_hash` relus.

    Une réécriture complète du fichier d'état avec une chaîne recalculée
    (modèle de menace non couvert, comme T33) ne doit pas pouvoir y placer
    des types arbitraires.
    """
    try:
        validate_relative_path(entry["file"])
    except (KeyError, ValueError):
        return False
    line = entry.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return False
    digest = entry.get("snippet_hash")
    return isinstance(digest, str) and _HASH.fullmatch(digest) is not None


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
                or not isinstance(entry["applied"], bool)
                or (entry["applied"] and entry["action"] != Choice.VALIDATE.value)
                or not _valid_date(entry["date"])
                or not _valid_target(entry)
            ):
                raise JournalError
            previous = digest
            entries.append({**entry, "hash": digest})
    return entries


class DecisionJournal:
    """Journal local chaîné des choix humains (#88), sans valeur de secret."""

    def __init__(self, path: Path | None = None) -> None:
        try:
            if path is not None and (not isinstance(path, Path) or "\x00" in str(path)):
                raise JournalError
            self.path = decision_journal_path() if path is None else path
        except JournalError:
            raise
        except BaseException:  # refus par défaut, jamais de traceback de chemin
            raise JournalError from None

    def read(self) -> list[dict[str, Any]]:
        """Relit et vérifie la chaîne ; un journal absent est vide."""
        try:
            with journal_locked(self.path, create=False) as descriptor:
                return [] if descriptor is None else _decision_entries(descriptor)
        except JournalError:
            raise
        except BaseException:  # `MemoryError`, `KeyboardInterrupt` compris
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
        except JournalError:
            raise
        except BaseException:  # `MemoryError`, `KeyboardInterrupt` compris
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
    except BaseException:  # noqa: S110 - canal déjà fermé : silence
        # Un `sys.stderr` exotique peut lever `SystemExit("<valeur>")` :
        # l'interpréteur l'imprimerait et choisirait le code de sortie.
        pass


def _stdin_ask(prompt: str, stream: object | None = None) -> str:
    """Lecture clavier **bornée** sur le flux vérifié par ``is_interactive``.

    Lire ``sys.stdin`` alors que le contrôle TTY a porté sur un autre objet
    permettrait une auto-validation (`stream` sûr + stdin pipé). Le même
    objet est donc contrôlé **et** lu.

    ``readline`` limite la lecture à :data:`MAX_ANSWER_CHARS` + 2 octets :
    un collage de plusieurs mégaoctets n'est pas matérialisé avant le refus.
    ``KeyboardInterrupt`` est converti aussi : Ctrl-C ne doit jamais sortir
    en code 1 (réservé aux secrets avérés) ni afficher de traceback.
    """
    try:
        candidate = sys.stdin if stream is None else stream
        output = sys.stdout
        reader = getattr(candidate, "readline", None)
        if output is None or not callable(reader):
            raise ReviewError
        output.write(prompt)
        output.flush()
        answer = reader(MAX_ANSWER_CHARS + 2)
    except ReviewError:
        raise
    except BaseException:  # refus par défaut, jamais de message d'entrée
        raise ReviewError from None
    if not isinstance(answer, str) or not answer:
        raise ReviewError
    return answer


def _ask(ask_fn: AskFn, prompt: str) -> str:
    """Défense en profondeur sur le point d'injection ``ask``.

    Un appelant (CLI T30) peut fournir son propre lecteur : son exception
    peut porter une valeur ou un chemin. Elle ne sort jamais telle quelle
    (invariant 8), seul le message statique de :class:`ReviewError` subsiste.

    ``BaseException`` est capturé volontairement : ``SystemExit("<valeur>")``
    ferait imprimer son message sur stderr par l'interpréteur, et
    ``KeyboardInterrupt`` sortirait en code 1 (réservé aux secrets avérés).
    Une lecture impossible est une erreur d'outillage statique, point.
    """
    try:
        return ask_fn(prompt)
    except ReviewError:
        raise
    except BaseException:  # refus par défaut, jamais de message d'entrée
        raise ReviewError from None


def _resolve_journal(journal: DecisionJournal | None) -> DecisionJournal:
    """Résout le journal par défaut sans traceback de chemin (invariant 8)."""
    try:
        return DecisionJournal() if journal is None else journal
    except JournalError:
        raise
    except BaseException:  # refus par défaut, jamais de traceback de chemin
        raise JournalError from None


def _journal_applied(
    journal_fn: DecisionJournal,
    choice: Choice,
    finding: Finding,
    notify_fn: NotifyFn,
) -> None:
    """Trace une application **réussie** ; une panne est signalée puis propagée.

    Le patch a déjà eu lieu : on ne peut pas le défaire. Le message statique
    prévient l'opérateur que la trace d'audit est incomplète, puis
    ``JournalError`` est levée pour que l'appelant sorte en code 2.
    """
    failed = False
    try:
        _journal(journal_fn, Decision.now(choice, finding, applied=True))
    except BaseException:
        failed = True
    if failed:
        _notify(notify_fn, UNAPPLIED_TRACE)
        raise JournalError from None


def _journal_failure(journal_fn: DecisionJournal, choice: Choice, finding: Finding) -> None:
    """Trace une tentative non aboutie, sans jamais chaîner l'erreur d'origine.

    Appelée depuis un `except` : une panne du journal ne doit ni masquer
    l'erreur principale, ni conserver une exception backend (valeur, chemin)
    dans la chaîne `__context__` de ce qui s'échappe ensuite.
    """
    try:
        _journal(journal_fn, Decision.now(choice, finding, applied=False))
    except BaseException:  # noqa: S110 - panne secondaire, erreur principale gardée
        pass


def _journal(journal_fn: DecisionJournal, decision: Decision) -> None:
    """Défense en profondeur sur le point d'injection ``journal``.

    ``DecisionJournal.append`` rend déjà un :class:`JournalError` statique ;
    un journal injecté par l'appelant (tests, futur CLI T30) peut lever
    n'importe quoi, y compris avec une valeur ou un chemin dans le message.
    Seules les erreurs déjà statiques sont réémises telles quelles.
    """
    try:
        journal_fn.append(decision)
    except (JournalError, ReviewError):
        raise
    except BaseException:  # refus par défaut, jamais de message d'entrée
        raise JournalError from None


def _notify(notify_fn: NotifyFn, message: str) -> None:
    """Avertissement best-effort : seul un message constant est transmis.

    L'avertissement ne doit jamais interrompre la boucle, et l'exception
    d'un notifieur injecté ne doit jamais ressortir avec son message.

    Contrat d'interruption, identique en appel solo et en session :

    - ``KeyboardInterrupt`` est **réémis** : Ctrl-C est une intention de
      l'opérateur, pas une panne d'outillage ;
    - ``SystemExit`` est absorbé : un composant ne choisit ni le code de
      sortie ni le message imprimé par l'interpréteur (invariant 8).
    """
    # Best-effort volontaire : le message est constant et l'exception d'un
    # notifieur injecté ne doit jamais ressortir ni interrompre la boucle.
    try:
        notify_fn(message)
    except KeyboardInterrupt:
        raise
    except (Exception, SystemExit):  # noqa: S110 - best-effort, message constant
        pass


def is_interactive(*, ci: bool = False, stream: object | None = None) -> bool:
    """Refus par défaut : sans TTY sûr, aucune écriture n'est autorisée (#89)."""
    if not isinstance(ci, bool):
        raise ReviewError
    if ci:
        return False
    candidate = sys.stdin if stream is None else stream
    try:
        # `getattr` avec défaut ne supprime que `AttributeError` : un flux
        # dont `__getattr__` lève doit aussi retomber sur le refus par défaut.
        isatty = getattr(candidate, "isatty", None)
        if not callable(isatty):
            return False
        return bool(isatty())
    except BaseException:  # refus par défaut, jamais de traceback
        # Un flux exotique (RuntimeError, fermeture, KeyboardInterrupt,
        # SystemExit) ne doit jamais produire de traceback ni passer pour un
        # terminal. Aucune valeur n'est en jeu ici.
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
        """Rapport masqué ; une panne de rendu reste une erreur statique."""
        try:
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
        except ReviewError:
            raise
        except BaseException:  # refus par défaut, jamais de traceback de rendu
            raise ReviewError from None


def _status(outcome: ReviewOutcome) -> str:
    if outcome.action is None:
        return "Statut : non validée (aucune écriture)."
    if outcome.action is Choice.IGNORE:
        return "Statut : ignorée par l'opérateur (secret laissé en place)."
    if outcome.applied:
        return "Statut : validée et appliquée."
    return "Statut : validée, application non confirmée."


def review_proposal(  # noqa: PLR0912, PLR0913, PLR0915 - boucle et injections explicites
    proposal: Proposal,
    *,
    ask: AskFn | None = None,
    apply: ApplyFn | None = None,
    edit: EditFn | None = None,
    journal: DecisionJournal | None = None,
    interactive: bool = True,
    allow_edit: bool = True,
    notify: NotifyFn | None = None,
    stream: object | None = None,
) -> ReviewOutcome:
    """Boucle Y/N/E (#88) ; aucune action par défaut, aucune écriture non tracée.

    ``interactive=True`` ne suffit **jamais** : il faut aussi un TTY sûr
    (:func:`is_interactive`). Un appelant qui force l'interactif sur un
    stdin pipé (`echo y | heimdall review`) retombe donc en mode non
    interactif au lieu d'y voir une validation humaine (#89).

    ``apply`` et ``edit`` sont fournis par le backend T30 (#83–#86) : cette
    interface ne calcule ni ne pose aucun patch. Toute exception du backend
    est convertie en :class:`ReviewError` statique (invariant 8), et le
    journal n'est écrit qu'**après** l'action, avec son résultat réel.

    ``allow_edit=False`` réserve le dialogue à Y/N : le prompt ne propose
    plus E et une réponse E est refusée avant tout journal ou toute écriture.
    """
    if (
        not isinstance(proposal, Proposal)
        or not isinstance(interactive, bool)
        or not isinstance(allow_edit, bool)
    ):
        raise ReviewError
    if not interactive or not is_interactive(stream=stream):
        # #89 : rapport seul, ni backend, ni journal, ni écriture.
        return ReviewOutcome(None, False, 0, proposal)
    ask_fn = partial(_stdin_ask, stream=stream) if ask is None else ask
    notify_fn = _stderr_notify if notify is None else notify
    journal_fn = _resolve_journal(journal)
    prompt = PROMPT if allow_edit else PROMPT_NO_EDIT
    invalid_choice = INVALID_CHOICE if allow_edit else INVALID_CHOICE_NO_EDIT
    current = proposal
    edits = 0
    prompts = 0
    while True:
        prompts += 1
        if prompts > MAX_PROMPTS:
            raise ReviewError
        # Une lecture impossible (EOF, terminal fermé) interrompt la boucle :
        # ce n'est pas une réponse invalide, donc pas de redemande en aveugle.
        raw = _ask(ask_fn, render_diff(current) + "\n" + prompt)
        try:
            choice = parse_choice(raw)
        except ReviewError:
            # Entrée invalide : on redemande, on ne devine jamais.
            _notify(notify_fn, invalid_choice)
            continue
        if choice is Choice.EDIT and not allow_edit:
            # E n'est pas proposé : refus fail-closed avant journal/écriture.
            raise ReviewError
        if choice is Choice.IGNORE:
            _journal(journal_fn, Decision.now(choice, current.finding))
            return ReviewOutcome(choice, False, edits, current)
        if choice is Choice.VALIDATE:
            if apply is None:
                raise ReviewError
            failed = False
            try:
                apply(current)
            except BaseException:
                # Le drapeau évite de lever DANS le `except` : l'erreur
                # statique n'hérite alors d'aucune `__context__` backend
                # (valeur, chemin), même si le journal échoue aussi.
                failed = True
            if failed:
                _journal_failure(journal_fn, choice, current.finding)
                raise ReviewError from None
            _journal_applied(journal_fn, choice, current.finding, notify_fn)
            return ReviewOutcome(choice, True, edits, current)
        if edit is None:
            raise ReviewError
        failed = False
        edited: Proposal | None = None
        try:
            edited = edit(current)
        except BaseException:
            failed = True
        if failed:
            _journal_failure(journal_fn, choice, current.finding)
            raise ReviewError from None
        _journal(journal_fn, Decision.now(choice, current.finding, applied=False))
        if edited is None:
            _notify(notify_fn, EDIT_CANCELLED)
            continue
        if not isinstance(edited, Proposal):
            raise ReviewError
        # Ré-ancrage : un éditeur ne change ni le finding (périmètre) ni le
        # jeu de valeurs connues. Sinon le ré-affichage suivant ne masquerait
        # plus qu'avec un sous-ensemble, et le seul filet restant serait
        # l'heuristique `mask_text`. Ajouter des valeurs reste permis.
        if edited.finding != current.finding:
            raise ReviewError
        if not set(current.secrets) <= set(edited.secrets):
            raise ReviewError
        edits += 1
        if edits > MAX_EDITS:
            raise ReviewError
        current = edited


def _proposal_bytes(proposal: Proposal) -> int:
    """Volume **UTF-8** retenu par une proposition (snapshots et valeurs).

    Compter les caractères sous-estimerait jusqu'à 4× la mémoire réelle :
    la borne porte donc sur les octets encodés.
    """
    total = 0
    for change in proposal.changes:
        total += len(change.before.encode("utf-8", "surrogatepass"))
        total += len(change.after.encode("utf-8", "surrogatepass"))
    for secret in proposal.secrets:
        total += len(secret.encode("utf-8", "surrogatepass"))
    return total


def _review_all(  # noqa: PLR0913 - injections explicites de la session
    proposals: Iterable[Proposal],
    *,
    mode: bool,
    allow_edit: bool,
    ask: AskFn | None,
    apply: ApplyFn | None,
    edit: EditFn | None,
    journal: DecisionJournal | None,
    notify: NotifyFn | None,
    stream: object | None,
) -> list[ReviewOutcome]:
    """Traite en **flux**, borné en nombre (`MAX_PROPOSALS`) et en volume.

    Aucune liste de propositions n'est matérialisée avant traitement : seule
    la liste des résultats est retenue (pour le rapport). Le volume retenu
    est plafonné par :data:`MAX_SESSION_BYTES`, sinon une erreur d'outillage
    statique est rendue au lieu d'un épuisement mémoire.
    """
    outcomes: list[ReviewOutcome] = []
    volume = 0
    try:
        for item in proposals:
            if len(outcomes) >= MAX_PROPOSALS:
                raise ReviewError
            if not isinstance(item, Proposal):
                raise ReviewError
            volume += _proposal_bytes(item)
            if volume > MAX_SESSION_BYTES:
                raise ReviewError
            outcomes.append(
                review_proposal(
                    item,
                    ask=ask,
                    apply=apply,
                    edit=edit,
                    journal=journal,
                    interactive=mode,
                    allow_edit=allow_edit,
                    notify=notify,
                    stream=stream,
                )
            )
        return outcomes
    except (ReviewError, JournalError):
        raise
    except KeyboardInterrupt:
        # Même contrat qu'en appel solo : Ctrl-C interrompt la session.
        raise
    except BaseException:  # noqa: S110 - producteur non itérable ou qui lève
        pass
    raise ReviewError from None


def review_proposals(  # noqa: PLR0913 - boucle et injections explicites
    proposals: Iterable[Proposal],
    *,
    ci: bool = False,
    interactive: bool | None = None,
    allow_edit: bool = True,
    ask: AskFn | None = None,
    apply: ApplyFn | None = None,
    edit: EditFn | None = None,
    journal: DecisionJournal | None = None,
    notify: NotifyFn | None = None,
    stream: object | None = None,
) -> ReviewReport:
    """Session complète ; ``ci`` et l'absence de TTY gagnent toujours.

    L'itérable est consommé **en flux** et borné par :data:`MAX_PROPOSALS`
    et :data:`MAX_SESSION_BYTES` : un producteur qui générerait des dizaines
    de milliers de propositions, ou des propositions démesurées, ne gonfle
    ni la mémoire ni le temps de réponse. Au-delà, c'est une erreur
    d'outillage (code 2), jamais une troncature silencieuse.
    """
    # Valider les options AVANT de consommer le producteur : un producteur
    # coûteux ou infini ne doit pas être parcouru pour rejeter `ci=1`.
    if (
        not isinstance(ci, bool)
        or (interactive is not None and not isinstance(interactive, bool))
        or not isinstance(allow_edit, bool)
    ):
        raise ReviewError
    # `interactive=True` explicite ne contourne ni `--ci` ni l'absence de TTY.
    mode = False if ci or interactive is False else is_interactive(stream=stream)
    outcomes = _review_all(
        proposals,
        mode=mode,
        allow_edit=allow_edit,
        ask=ask,
        apply=apply,
        edit=edit,
        journal=journal,
        notify=notify,
        stream=stream,
    )
    return ReviewReport(tuple(outcomes), mode)
