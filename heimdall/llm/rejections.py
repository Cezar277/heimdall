"""Journal local JSONL chaîné des propositions de rejet du LLM (#33).

La justification est un code fermé : aucune prose du modèle, aucun extrait.
Le chaînage détecte les modifications internes, pas une réécriture complète
ni la suppression de la fin par le propriétaire (voir docs/llm-rejections.md).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from heimdall.llm.qualify import (
    DEFAULT_MODEL,
    ChatFn,
    Qualification,
    QualifyError,
    qualify_candidate,
)
from heimdall.mcp.masking import REDACTION_MARKER
from heimdall.mcp.prompts import MAX_CANDIDATE_CHARS, PROMPT_NAME, prompt_digest
from heimdall.scanner.finding import Finding

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

SCHEMA: Final[str] = "heimdall.llm-rejection.v1"
GENESIS: Final[str] = "0" * 64
MAX_JOURNAL_BYTES: Final[int] = 16 * 1024 * 1024
MAX_ENTRY_BYTES: Final[int] = 32 * 1024
JUSTIFICATION: Final[str] = "faux_positif_propose_par_llm_validation_humaine_requise"
_ERROR: Final[str] = "journal des rejets indisponible ou invalide"
logger = logging.getLogger(__name__)


class JournalError(Exception):
    """Erreur statique, jamais le contenu du journal ou un chemin."""

    def __init__(self) -> None:
        super().__init__(_ERROR)


def journal_path() -> Path:
    """État local opérateur ; jamais un chemin choisi par le modèle."""
    base = os.environ.get("XDG_STATE_HOME")
    return (
        (Path(base) if base else Path.home() / ".local" / "state")
        / "heimdall"
        / ("llm-rejections.jsonl")
    )


def _encode(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_encode(value)).hexdigest()


def _check_file(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise JournalError
    if os.name == "posix" and (
        metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise JournalError


def _prepare_path(path: Path, *, create: bool) -> Path | None:
    """Vérifie les chemins ; seul append peut créer le répertoire privé."""
    if not path.is_absolute() or ".." in path.parts or path.resolve() != path:
        raise JournalError
    lock_path = path.with_suffix(".lock")
    if lock_path.resolve() != lock_path:
        raise JournalError
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
    if os.name == "posix":
        metadata = path.parent.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise JournalError
    return lock_path


@contextmanager
def _locked(path: Path, *, create: bool = True) -> Iterator[int | None]:
    """Verrou exclusif non bloquant ; seule la voie append crée des fichiers.

    En lecture, None représente un journal absent. Un journal existant sans
    sidecar est une erreur d'intégrité, jamais un historique vide.
    """
    lock_path = _prepare_path(path, create=create)
    if lock_path is None:
        yield None
        return
    flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    # Sidecar stable : le verrou protège aussi la vérification avant append.
    # Windows exige un descripteur inscriptible pour le verrou exclusif,
    # mais la consultation n'écrit aucun octet dans le sidecar.
    lock_flags = os.O_RDWR if create or sys.platform == "win32" else os.O_RDONLY
    if create:
        lock_flags |= os.O_CREAT
    lock = os.open(lock_path, flags | lock_flags, 0o600)
    try:
        _check_file(lock)
        if sys.platform == "win32":
            msvcrt.locking(lock, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal_flags = os.O_RDWR | os.O_CREAT | os.O_APPEND if create else os.O_RDONLY
        descriptor = os.open(path, flags | journal_flags, 0o600)
        try:
            _check_file(descriptor)
            if path.resolve() != path:
                raise JournalError
            yield descriptor
        finally:
            os.close(descriptor)
    finally:
        # La fermeture libère le verrou même après exception.
        os.close(lock)


def _entries(descriptor: int) -> list[dict[str, Any]]:
    if os.fstat(descriptor).st_size > MAX_JOURNAL_BYTES:
        raise JournalError
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        entries: list[dict[str, Any]] = []
        previous = GENESIS
        total = 0
        while raw := stream.readline(MAX_ENTRY_BYTES + 1):
            total += len(raw)
            if total > MAX_JOURNAL_BYTES or len(raw) > MAX_ENTRY_BYTES or not raw.endswith(b"\n"):
                raise JournalError
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise JournalError
            digest = entry.pop("hash", None)
            if (
                entry.get("schema") != SCHEMA
                or entry.get("previous_hash") != previous
                or entry.get("sequence") != len(entries) + 1
                or digest != _digest(entry)
                or _encode({**entry, "hash": digest}) + b"\n" != raw
            ):
                raise JournalError
            # Canonicalisation + contrat fermé : aucun champ libre affichable.
            expected = {
                "schema",
                "sequence",
                "date",
                "file",
                "line",
                "snippet_hash",
                "model",
                "prompt_version",
                "prompt_sha256",
                "justification",
                "previous_hash",
            }
            if set(entry) != expected or entry["justification"] != JUSTIFICATION:
                raise JournalError
            previous = digest
            entries.append({**entry, "hash": digest})
    return entries


class RejectionJournal:
    """Append durable après vérification intégrale, jamais de réparation implicite."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = journal_path() if path is None else path

    def read(self) -> list[dict[str, Any]]:
        """Relit et vérifie la chaîne ; un journal absent est vide."""
        try:
            with _locked(self.path, create=False) as descriptor:
                return [] if descriptor is None else _entries(descriptor)
        except (OSError, ValueError, RuntimeError, RecursionError):
            raise JournalError from None

    def append(self, finding: Finding, *, model: str) -> None:
        """N'accepte ni réponse brute, ni justification libre du modèle."""
        try:
            if not isinstance(model, str) or re.fullmatch(r"[a-zA-Z0-9._:/-]{1,64}", model) is None:
                raise JournalError
            with _locked(self.path) as descriptor:
                if descriptor is None:
                    raise JournalError
                entries = _entries(descriptor)
                entry = {
                    "schema": SCHEMA,
                    "sequence": len(entries) + 1,
                    "date": datetime.now(timezone.utc).isoformat(),
                    "file": finding.file,
                    "line": finding.line,
                    "snippet_hash": finding.snippet_hash,
                    "model": model,
                    "prompt_version": PROMPT_NAME,
                    "prompt_sha256": prompt_digest(),
                    "justification": JUSTIFICATION,
                    "previous_hash": entries[-1]["hash"] if entries else GENESIS,
                }
                payload = _encode({**entry, "hash": _digest(entry)}) + b"\n"
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


def qualify_finding(  # noqa: PLR0913 -- contexte, politique CI et transport injectable explicites.
    finding: Finding,
    masked_candidate: str,
    *,
    ci: bool = False,
    model: str = DEFAULT_MODEL,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
) -> Qualification:
    """Frontière d'orchestration pour #32 : avis audité, Finding jamais retiré.

    En CI, ne consulte ni le modèle ni le journal. Ailleurs, un avis
    faux_positif n'est rendu qu'après fsync ; toute panne du journal lève
    JournalError et doit devenir un code d'outillage 2 chez l'appelant.
    Le candidat doit être masqué AVANT cet appel (contrat MCP #16).
    """
    if ci:
        return Qualification(status="detecte", verdict=None, reason="unavailable")
    if not isinstance(masked_candidate, str) or REDACTION_MARKER not in masked_candidate:
        raise QualifyError("empty")
    if len(masked_candidate) > MAX_CANDIDATE_CHARS:
        raise QualifyError("too_large")
    result = qualify_candidate(masked_candidate, model=model, chat=chat)
    if result.verdict == "faux_positif":
        (journal if journal is not None else RejectionJournal()).append(finding, model=model)
        logger.warning(rejection_summary(1))
    return result


def rejection_summary(count: int) -> str:
    """Résumé explicite : propositions du LLM, pas autorisations de commit."""
    return (
        f"{count} candidat(s) proposé(s) comme faux positif(s) par le LLM "
        "(propositions uniquement, validation humaine requise) ; "
        "voir le détail : heimdall rejections --details."
    )


# --- Primitives génériques du journal, réutilisées par le journal des
# décisions humaines de T32 (#88). Alias publics ajoutés en **fin** de
# module : aucune ligne existante ne bouge, donc les permaliens T33
# (docs/t33-samm.md, module + ligne) restent valides.
journal_locked = _locked
journal_encode = _encode
journal_digest = _digest
