"""Journal d'audit du Vault Heimdall (ticket #113).

Chaque accès au Vault produit un événement, y compris les refus 401/403 et les
limitations 429. Le journal répond à « qui a lu quoi, et quand » après un
incident, sans jamais contenir de valeur de secret ni de clé API complète.

DÉFENSES ET INVARIANTS
- **Aucun secret** : le corps de requête, les en-têtes et la valeur d'un secret
  ne sont jamais lus par ce module. Seuls le pair réseau, la méthode, le chemin
  de route, le triplet public ``project/env/name`` et un **empreinte tronquée**
  de la clé (16 caractères hexadécimaux, jamais la clé) sont persistés.
- **Chaînage par hash** : chaque ligne contient ``previous_hash`` et
  ``entry_hash`` (HMAC-SHA-256 d'une charge canonique JSON, avec la clé
  ``HEIMDALL_VAULT_AUDIT_HMAC_KEY`` ou à défaut une sous-clé HKDF dédiée du
  chiffreur ; SHA-256 nu uniquement pour les journaux historiques pré-F-16). Modifier, insérer ou
  supprimer une ligne casse la chaîne ; ``verify_chain()`` localise la première
  ligne invalide. On parle de journal « résistant à l'altération », pas
  « inviolable » : un attaquant qui contrôle toute la base peut recalculer la
  chaîne. La protection contre la suppression totale relève de la sauvegarde
  externe.
- **Fail-closed** : si l'écriture d'audit échoue, la réponse devient un 503
  générique (aucun détail interne) au lieu de laisser passer un accès non
  journalisé.
- **Pas de log injection** : les champs texte sont filtrés (caractères non
  imprimables supprimés) et bornés avant persistance.
- **Backends** : ``SqliteAuditLog`` en production (table ``audit_events``,
  partagée entre workers) ; ``InMemoryAuditLog`` pour le backend mémoire de
  développement/test, strictement mono-processus et perdu au redémarrage.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from starlette.requests import Request
from starlette.responses import JSONResponse

from heimdall.vault.auth import validate_project_id
from heimdall.vault.database import DatabaseUnavailableError, get_iso_timestamp
from heimdall.vault.database import runtime_db_session as db_session

logger = logging.getLogger("heimdall.vault.audit")

GENESIS_HASH: Final[str] = "0" * 64
MAX_ACTION_LENGTH: Final[int] = 160
MAX_TARGET_LENGTH: Final[int] = 256
MAX_PEER_LENGTH: Final[int] = 64
MAX_KEY_ID_LENGTH: Final[int] = 64
MAX_LIST_LIMIT: Final[int] = 1_000
_FINGERPRINT_HEX_LENGTH: Final[int] = 16
DEFAULT_LIST_LIMIT: Final[int] = 50
# Rétention bornée : au-delà, les plus anciens événements sont purgés et un
# point de contrôle de chaîne est conservé. La valeur est volontairement
# généreuse ; les tests la réduisent par patch pour vérifier la purge.
MAX_AUDIT_EVENTS: Final[int] = 100_000
# Les rejets 401/429 ont leur propre flux et leur propre rétention : une
# inondation de rejets ne peut jamais purger les accès authentifiés (audit M-03).
MAX_REJECTION_EVENTS: Final[int] = 10_000
_AUDIT_STREAM_ACCESS: Final[str] = "access"
_AUDIT_STREAM_REJECTION: Final[str] = "rejection"
_REJECTION_STATUS_CODES: Final[frozenset[int]] = frozenset({401, 429})

# Requêtes des tables d'état de chaîne, écrites en toutes lettres pour chaque
# table : aucun nom de table n'est interpolé dans du SQL (bandit B608).
_CHECKPOINT_SELECT_SQL: Final[dict[str, str]] = {
    "audit_chain_state": (
        "SELECT checkpoint_hash, pruned_events FROM audit_chain_state WHERE id = 1"
    ),
    "audit_rejection_chain_state": (
        "SELECT checkpoint_hash, pruned_events FROM audit_rejection_chain_state WHERE id = 1"
    ),
}
_CHECKPOINT_UPSERT_SQL: Final[dict[str, str]] = {
    "audit_chain_state": (
        "INSERT INTO audit_chain_state (id, checkpoint_hash, pruned_events, updated_at) "
        "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
        "checkpoint_hash = excluded.checkpoint_hash, "
        "pruned_events = audit_chain_state.pruned_events + excluded.pruned_events, "
        "updated_at = excluded.updated_at"
    ),
    "audit_rejection_chain_state": (
        "INSERT INTO audit_rejection_chain_state "
        "(id, checkpoint_hash, pruned_events, updated_at) "
        "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
        "checkpoint_hash = excluded.checkpoint_hash, "
        "pruned_events = audit_rejection_chain_state.pruned_events + excluded.pruned_events, "
        "updated_at = excluded.updated_at"
    ),
}
# Purge par lots : chaque transaction ne supprime qu'un lot borné, pour ne pas
# tenir le verrou d'écriture SQLite pendant une purge massive (excess >> 1).
_PRUNE_BATCH_SIZE: Final[int] = 1_000

_AUDIT_TABLE_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream TEXT NOT NULL DEFAULT 'access',
    occurred_at TEXT NOT NULL,
    key_id TEXT,
    key_fingerprint TEXT,
    project TEXT,
    peer TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    status_code INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""
_AUDIT_INDEX_SQL: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at
    ON audit_events(occurred_at);
"""
_AUDIT_STREAM_INDEX_SQL: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_audit_events_stream_id
    ON audit_events(stream, id);
"""
_AUDIT_STATE_TABLE_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS audit_chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    checkpoint_hash TEXT NOT NULL,
    pruned_events INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""
_AUDIT_REJECTION_STATE_TABLE_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS audit_rejection_chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    checkpoint_hash TEXT NOT NULL,
    pruned_events INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""

_UNAVAILABLE_PAYLOAD: Final[dict[str, str]] = {
    "code": "unavailable",
    "message": "Service indisponible",
}
_INTERNAL_PAYLOAD: Final[dict[str, str]] = {
    "code": "internal_error",
    "message": "Erreur interne",
}


def _sanitize(value: str | None, max_length: int) -> str | None:
    """Filtre les caractères non imprimables et borne la longueur.

    Empêche l'injection de retours à la ligne ou de contrôles terminaux dans le
    journal, sans jamais refléter une entrée brute au-delà de la borne.
    """
    if value is None:
        return None
    # Tronque au premier caractère non imprimable : concaténer les morceaux
    # (« key_...\nINJECTED ») fabriquerait une valeur trompeuse.
    printable: list[str] = []
    for character in value:
        if not character.isprintable():
            break
        printable.append(character)
    cleaned = "".join(printable)[:max_length].strip()
    return cleaned or None


def key_fingerprint(key_hash: str | None) -> str | None:
    """Empreinte courte et non réversible d'une clé, pour corréler les accès.

    Le journal ne stocke jamais la clé brute ni son empreinte HMAC complète :
    16 caractères hexadécimaux suffisent à corréler les requêtes d'une même clé
    sans permettre de la reconstruire. L'empreinte est calculée par le serveur
    avec son pepper ; elle n'est pas portable entre déploiements.
    """
    if key_hash is None:
        return None
    candidate = key_hash.strip().lower()
    if len(candidate) < _FINGERPRINT_HEX_LENGTH:
        return None
    prefix = candidate[:_FINGERPRINT_HEX_LENGTH]
    if any(character not in "0123456789abcdef" for character in prefix):
        return None
    return prefix


def _outcome(status_code: int) -> str:  # noqa: PLR2004
    """Classe le résultat HTTP en catégorie stable pour l'audit."""
    if 200 <= status_code < 300:  # noqa: PLR2004
        return "allowed"
    if status_code == 401:  # noqa: PLR2004
        return "unauthenticated"
    if status_code == 403:  # noqa: PLR2004
        return "forbidden"
    if status_code == 429:  # noqa: PLR2004
        return "rate_limited"
    if 400 <= status_code < 500:  # noqa: PLR2004
        return "rejected"
    return "error"


def _canonical_payload(  # noqa: PLR0913
    *,
    occurred_at: str,
    key_id: str | None,
    key_fingerprint_value: str | None,
    project: str | None,
    peer: str,
    action: str,
    target: str | None,
    status_code: int,
    outcome: str,
    previous_hash: str,
) -> bytes:
    """Charge canonique JSON utilisée par le chaînage par hash."""
    return json.dumps(
        {
            "occurred_at": occurred_at,
            "key_id": key_id,
            "key_fingerprint": key_fingerprint_value,
            "project": project,
            "peer": peer,
            "action": action,
            "target": target,
            "status_code": status_code,
            "outcome": outcome,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _entry_hash(payload: bytes, hmac_key: bytes | None) -> str:
    """HMAC-SHA-256 (ou SHA-256 historique si aucune clé n'est configurée)."""
    if hmac_key is None:
        return hashlib.sha256(payload).hexdigest()
    return hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    """Événement d'audit immuable (aucune valeur de secret)."""

    id: int
    occurred_at: str
    key_id: str | None
    key_fingerprint: str | None
    project: str | None
    peer: str
    action: str
    target: str | None
    status_code: int
    outcome: str
    previous_hash: str
    entry_hash: str

    def as_dict(self) -> dict[str, Any]:
        """Représentation sérialisable, sans secret."""
        return {
            "id": self.id,
            "occurred_at": self.occurred_at,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "project": self.project,
            "peer": self.peer,
            "action": self.action,
            "target": self.target,
            "status_code": self.status_code,
            "outcome": self.outcome,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLog:
    """Interface commune aux backends d'audit (mémoire et SQLite)."""

    async def record(  # noqa: PLR0913
        self,
        *,
        peer: str,
        action: str,
        target: str | None,
        status_code: int,
        key_fingerprint_value: str | None = None,
        key_id: str | None = None,
        project: str | None = None,
    ) -> AuditEvent:
        """Ajoute un événement et retourne sa représentation persistée."""
        raise NotImplementedError

    def list_events(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        project: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retourne les derniers événements, du plus ancien au plus récent."""
        raise NotImplementedError

    def verify_chain(self) -> tuple[bool, int | None]:
        """Vérifie le chaînage ; retourne ``(valide, premier_id_invalide)``."""
        raise NotImplementedError


class InMemoryAuditLog(AuditLog):
    """Journal en mémoire, réservé au backend mémoire de développement/test.

    Deux flux indépendants (accès authentifiés et rejets 401/429) ont chacun
    leur chaîne et leur rétention : une inondation de rejets ne peut pas purger
    les accès authentifiés (audit M-03).
    """

    def __init__(self, *, hmac_key: bytes | None) -> None:
        # ``hmac_key`` obligatoire (F-16) : ``None`` = SHA-256 historique, choix
        # explicite réservé à la lecture des journaux pré-F-16.
        self._hmac_key = hmac_key
        self._events: list[AuditEvent] = []
        self._rejection_events: list[AuditEvent] = []
        self._checkpoint_hash = GENESIS_HASH
        self._rejection_checkpoint_hash = GENESIS_HASH
        self._pruned_events = 0
        self._rejection_pruned_events = 0
        self._next_id = 1
        self._lock = threading.Lock()

    @staticmethod
    def _stream_for(status_code: int) -> str:
        return (
            _AUDIT_STREAM_REJECTION
            if status_code in _REJECTION_STATUS_CODES
            else _AUDIT_STREAM_ACCESS
        )

    def _prune_locked(self, stream: str) -> None:
        """Purge le flux demandé et avance son point de contrôle."""
        events = self._rejection_events if stream == _AUDIT_STREAM_REJECTION else self._events
        limit = MAX_REJECTION_EVENTS if stream == _AUDIT_STREAM_REJECTION else MAX_AUDIT_EVENTS
        excess = len(events) - max(1, limit)
        if excess <= 0:
            return
        pruned = events[:excess]
        if stream == _AUDIT_STREAM_REJECTION:
            self._rejection_checkpoint_hash = pruned[-1].entry_hash
            self._rejection_pruned_events += len(pruned)
        else:
            self._checkpoint_hash = pruned[-1].entry_hash
            self._pruned_events += len(pruned)
        del events[:excess]

    async def record(  # noqa: PLR0913
        self,
        *,
        peer: str,
        action: str,
        target: str | None,
        status_code: int,
        key_fingerprint_value: str | None = None,
        key_id: str | None = None,
        project: str | None = None,
    ) -> AuditEvent:
        stream = self._stream_for(status_code)
        with self._lock:
            events = (
                self._rejection_events
                if stream == _AUDIT_STREAM_REJECTION
                else self._events
            )
            checkpoint = (
                self._rejection_checkpoint_hash
                if stream == _AUDIT_STREAM_REJECTION
                else self._checkpoint_hash
            )
            previous_hash = events[-1].entry_hash if events else checkpoint
            occurred_at = get_iso_timestamp()
            safe_peer = _sanitize(peer, MAX_PEER_LENGTH) or "unknown"
            safe_action = _sanitize(action, MAX_ACTION_LENGTH) or "UNKNOWN"
            safe_target = _sanitize(target, MAX_TARGET_LENGTH)
            safe_project = _sanitize(project, MAX_TARGET_LENGTH)
            safe_key_id = _sanitize(key_id, MAX_KEY_ID_LENGTH)
            safe_fingerprint = key_fingerprint(key_fingerprint_value)
            outcome = _outcome(status_code)
            payload = _canonical_payload(
                occurred_at=occurred_at,
                key_id=safe_key_id,
                key_fingerprint_value=safe_fingerprint,
                project=safe_project,
                peer=safe_peer,
                action=safe_action,
                target=safe_target,
                status_code=status_code,
                outcome=outcome,
                previous_hash=previous_hash,
            )
            event = AuditEvent(
                id=self._next_id,
                occurred_at=occurred_at,
                key_id=safe_key_id,
                key_fingerprint=safe_fingerprint,
                project=safe_project,
                peer=safe_peer,
                action=safe_action,
                target=safe_target,
                status_code=status_code,
                outcome=outcome,
                previous_hash=previous_hash,
                entry_hash=_entry_hash(payload, self._hmac_key),
            )
            self._next_id += 1
            events.append(event)
            self._prune_locked(stream)
            return event

    def list_events(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        project: str | None = None,
        stream: str | None = None,
    ) -> list[dict[str, Any]]:
        """Derniers événements ; ``stream`` filtre un flux (parité SQLite, M-03)."""
        if stream not in {None, _AUDIT_STREAM_ACCESS, _AUDIT_STREAM_REJECTION}:
            raise ValueError("flux d'audit invalide (access, rejection ou all).")
        bounded_limit = max(1, min(MAX_LIST_LIMIT, int(limit)))
        with self._lock:
            sources: tuple[AuditEvent, ...]
            if stream == _AUDIT_STREAM_ACCESS:
                sources = tuple(self._events)
            elif stream == _AUDIT_STREAM_REJECTION:
                sources = tuple(self._rejection_events)
            else:
                sources = (*self._events, *self._rejection_events)
            selected = [
                event
                for event in sorted(sources, key=lambda item: (item.occurred_at, item.id))
                if project is None or event.project == project
            ]
            return [event.as_dict() for event in selected[-bounded_limit:]]

    def _verify_stream(
        self, events: list[AuditEvent], checkpoint: str
    ) -> tuple[bool, int | None]:
        previous_hash = checkpoint
        for event in events:
            if event.previous_hash != previous_hash:
                return False, event.id
            payload = _canonical_payload(
                occurred_at=event.occurred_at,
                key_id=event.key_id,
                key_fingerprint_value=event.key_fingerprint,
                project=event.project,
                peer=event.peer,
                action=event.action,
                target=event.target,
                status_code=event.status_code,
                outcome=event.outcome,
                previous_hash=event.previous_hash,
            )
            if _entry_hash(payload, self._hmac_key) != event.entry_hash:
                return False, event.id
            previous_hash = event.entry_hash
        return True, None

    def verify_chain(self) -> tuple[bool, int | None]:
        with self._lock:
            valid, invalid = self._verify_stream(self._events, self._checkpoint_hash)
            if not valid:
                return valid, invalid
            return self._verify_stream(
                self._rejection_events, self._rejection_checkpoint_hash
            )

    def pruned_count(self) -> int:
        """Nombre d'événements purgés par la rétention (diagnostic)."""
        with self._lock:
            return self._pruned_events + self._rejection_pruned_events

    def clear(self) -> None:
        """Réinitialise le journal (tests isolés)."""
        with self._lock:
            self._events.clear()
            self._rejection_events.clear()
            self._checkpoint_hash = GENESIS_HASH
            self._rejection_checkpoint_hash = GENESIS_HASH
            self._pruned_events = 0
            self._rejection_pruned_events = 0
            self._next_id = 1


class SqliteAuditLog(AuditLog):
    """Journal d'audit persistant, partagé entre workers via SQLite.

    Deux flux indépendants (accès authentifiés et rejets 401/429) ont chacun
    leur chaîne et leur rétention : une inondation de rejets ne peut pas purger
    les accès authentifiés (audit M-03). L'ajout est sérialisé par
    ``BEGIN IMMEDIATE`` : deux workers ne peuvent pas lire le même
    ``previous_hash`` puis insérer deux lignes concurrentes. La lecture et la
    vérification ne prennent aucun verrou d'écriture.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        create: bool = True,
        hmac_key: bytes | None,
    ) -> None:
        self._db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._hmac_key = hmac_key
        if create:
            with db_session(self._db_path) as conn:
                conn.execute(_AUDIT_TABLE_SQL)
                conn.execute(_AUDIT_INDEX_SQL)
                conn.execute(_AUDIT_STREAM_INDEX_SQL)
                conn.execute(_AUDIT_STATE_TABLE_SQL)
                conn.execute(_AUDIT_REJECTION_STATE_TABLE_SQL)
                self._ensure_stream_column(conn)

    @staticmethod
    def _ensure_stream_column(conn: Any) -> None:
        """Ajoute ``audit_events.stream`` aux bases créées avant l'audit M-03.

        Pas de backfill volontaire : avant M-03, accès et rejets formaient une
        seule chaîne (chaque ``previous_hash`` pointe sur l'événement
        précédent, quel que soit son statut). Reclasser les anciens 401/429
        dans le flux ``rejection`` casserait les liens des deux flux et
        ``verify_chain`` signalerait une falsification. L'historique reste donc
        une chaîne continue dans ``access`` ; la séparation de rétention M-03
        ne vaut que pour les événements postérieurs à la migration (les
        anciens rejets comptent contre le quota ``access``).
        """
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(audit_events);").fetchall()
        }
        if "stream" in columns:
            return
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN stream TEXT NOT NULL DEFAULT 'access'"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_stream_id "
            "ON audit_events(stream, id)"
        )

    @property
    def db_path(self) -> Path | str:
        """Chemin de la base SQLite du journal."""
        return self._db_path

    @staticmethod
    def _state_table(stream: str) -> str:
        return (
            "audit_rejection_chain_state"
            if stream == _AUDIT_STREAM_REJECTION
            else "audit_chain_state"
        )

    @staticmethod
    def _stream_for(status_code: int) -> str:
        return (
            _AUDIT_STREAM_REJECTION
            if status_code in _REJECTION_STATUS_CODES
            else _AUDIT_STREAM_ACCESS
        )

    @classmethod
    def _checkpoint(cls, conn: Any, stream: str) -> tuple[str, int]:
        """Retourne le point de contrôle et le nombre d'événements purgés du flux."""
        # Requête constante par flux : aucun nom de table interpolé (B608).
        row = conn.execute(_CHECKPOINT_SELECT_SQL[cls._state_table(stream)]).fetchone()
        if row is None:
            return GENESIS_HASH, 0
        return str(row["checkpoint_hash"]), int(row["pruned_events"])

    @classmethod
    def _prune(cls, conn: Any, stream: str) -> bool:
        """Supprime au plus ``_PRUNE_BATCH_SIZE`` événements excédentaires du flux.

        Retourne ``True`` s'il reste des événements à purger. Chaque lot avance
        le point de contrôle de chaîne du flux avec le dernier ``entry_hash``
        supprimé : les événements retenus restent prouvables.
        """
        limit = MAX_REJECTION_EVENTS if stream == _AUDIT_STREAM_REJECTION else MAX_AUDIT_EVENTS
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE stream = ?", (stream,)
        ).fetchone()
        count = int(row[0]) if row is not None else 0
        excess = count - max(1, limit)
        if excess <= 0:
            return False
        batch = min(excess, _PRUNE_BATCH_SIZE)
        rows = conn.execute(
            "SELECT id, entry_hash FROM audit_events WHERE stream = ? "
            "ORDER BY id ASC LIMIT ?",
            (stream, batch),
        ).fetchall()
        if not rows:
            return False
        checkpoint_hash = str(rows[-1]["entry_hash"])
        conn.executemany(
            "DELETE FROM audit_events WHERE id = ?",
            [(int(item["id"]),) for item in rows],
        )
        conn.execute(
            _CHECKPOINT_UPSERT_SQL[cls._state_table(stream)],
            (checkpoint_hash, len(rows), get_iso_timestamp()),
        )
        return excess > len(rows)

    def _prune_batched(self, stream: str) -> None:
        """Purge les excédents du flux par lots, chaque lot dans sa transaction."""
        while True:
            with db_session(self._db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                more = self._prune(conn, stream)
            if not more:
                return

    async def record(  # noqa: PLR0913
        self,
        *,
        peer: str,
        action: str,
        target: str | None,
        status_code: int,
        key_fingerprint_value: str | None = None,
        key_id: str | None = None,
        project: str | None = None,
    ) -> AuditEvent:
        return await asyncio.to_thread(
            self._record_sync,
            peer=peer,
            action=action,
            target=target,
            status_code=status_code,
            key_fingerprint_value=key_fingerprint_value,
            key_id=key_id,
            project=project,
        )

    def _record_sync(  # noqa: PLR0913
        self,
        *,
        peer: str,
        action: str,
        target: str | None,
        status_code: int,
        key_fingerprint_value: str | None = None,
        key_id: str | None = None,
        project: str | None = None,
    ) -> AuditEvent:
        stream = self._stream_for(status_code)
        safe_peer = _sanitize(peer, MAX_PEER_LENGTH) or "unknown"
        safe_action = _sanitize(action, MAX_ACTION_LENGTH) or "UNKNOWN"
        safe_target = _sanitize(target, MAX_TARGET_LENGTH)
        safe_project = _sanitize(project, MAX_TARGET_LENGTH)
        safe_key_id = _sanitize(key_id, MAX_KEY_ID_LENGTH)
        safe_fingerprint = key_fingerprint(key_fingerprint_value)
        outcome = _outcome(status_code)
        occurred_at = get_iso_timestamp()
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            checkpoint_hash, _pruned = self._checkpoint(conn, stream)
            row = conn.execute(
                "SELECT entry_hash FROM audit_events WHERE stream = ? "
                "ORDER BY id DESC LIMIT 1",
                (stream,),
            ).fetchone()
            previous_hash = str(row[0]) if row is not None else checkpoint_hash
            payload = _canonical_payload(
                occurred_at=occurred_at,
                key_id=safe_key_id,
                key_fingerprint_value=safe_fingerprint,
                project=safe_project,
                peer=safe_peer,
                action=safe_action,
                target=safe_target,
                status_code=status_code,
                outcome=outcome,
                previous_hash=previous_hash,
            )
            entry_hash = _entry_hash(payload, self._hmac_key)
            cursor = conn.execute(
                "INSERT INTO audit_events ("
                "stream, occurred_at, key_id, key_fingerprint, project, peer, action, target, "
                "status_code, outcome, previous_hash, entry_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    stream,
                    occurred_at,
                    safe_key_id,
                    safe_fingerprint,
                    safe_project,
                    safe_peer,
                    safe_action,
                    safe_target,
                    status_code,
                    outcome,
                    previous_hash,
                    entry_hash,
                ),
            )
            event_id = int(cursor.lastrowid or 0)
            limit = (
                MAX_REJECTION_EVENTS
                if stream == _AUDIT_STREAM_REJECTION
                else MAX_AUDIT_EVENTS
            )
            row = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE stream = ?", (stream,)
            ).fetchone()
            needs_prune = int(row[0] if row is not None else 0) > max(1, limit)
        if needs_prune:
            self._prune_batched(stream)
        return AuditEvent(
            id=event_id,
            occurred_at=occurred_at,
            key_id=safe_key_id,
            key_fingerprint=safe_fingerprint,
            project=safe_project,
            peer=safe_peer,
            action=safe_action,
            target=safe_target,
            status_code=status_code,
            outcome=outcome,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

    def list_events(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        project: str | None = None,
        stream: str | None = None,
    ) -> list[dict[str, Any]]:
        """Derniers événements ; ``stream`` filtre un flux (``access``/``rejection``).

        Sans filtre, une inondation de rejets peut occuper les ``limit``
        dernières lignes : ``stream="access"`` garde les accès visibles (M-03).
        """
        if stream not in {None, _AUDIT_STREAM_ACCESS, _AUDIT_STREAM_REJECTION}:
            raise ValueError("flux d'audit invalide (access, rejection ou all).")
        bounded_limit = max(1, min(MAX_LIST_LIMIT, int(limit)))
        with db_session(self._db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM ("
                "SELECT * FROM audit_events "
                "WHERE (? IS NULL OR project = ?) AND (? IS NULL OR stream = ?) "
                "ORDER BY id DESC LIMIT ?"
                ") ORDER BY id ASC",
                (project, project, stream, stream, bounded_limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def _verify_stream(self, conn: Any, stream: str) -> tuple[bool, int | None]:
        previous_hash, _pruned = self._checkpoint(conn, stream)
        for row in conn.execute(
            "SELECT * FROM audit_events WHERE stream = ? ORDER BY id ASC", (stream,)
        ):
            event_id = int(row["id"])
            if str(row["previous_hash"]) != previous_hash:
                return False, event_id
            payload = _canonical_payload(
                occurred_at=str(row["occurred_at"]),
                key_id=row["key_id"],
                key_fingerprint_value=row["key_fingerprint"],
                project=row["project"],
                peer=str(row["peer"]),
                action=str(row["action"]),
                target=row["target"],
                status_code=int(row["status_code"]),
                outcome=str(row["outcome"]),
                previous_hash=str(row["previous_hash"]),
            )
            if _entry_hash(payload, self._hmac_key) != str(row["entry_hash"]):
                return False, event_id
            previous_hash = str(row["entry_hash"])
        return True, None

    def verify_chain(self) -> tuple[bool, int | None]:
        with db_session(self._db_path) as conn:
            valid, invalid = self._verify_stream(conn, _AUDIT_STREAM_ACCESS)
            if not valid:
                return valid, invalid
            return self._verify_stream(conn, _AUDIT_STREAM_REJECTION)

    def resign_chain(self, new_hmac_key: bytes) -> int:
        """Re-signe tout le journal avec ``new_hmac_key`` (migration F-16).

        Bascule dérivé → explicite : la chaîne est d'abord vérifiée avec la
        clé courante, puis chaque ``entry_hash`` est recalculé avec la nouvelle
        clé, flux par flux, dans une seule transaction ``BEGIN IMMEDIATE``. Les
        points de contrôle de purge restent inchangés (ils ne sont qu'une
        valeur de ``previous_hash``). Une chaîne invalide n'est jamais
        re-signée : ``ValueError`` et aucune écriture. Retourne le nombre
        d'événements re-signés.

        Limite documentée : après une purge, le point de contrôle
        (``checkpoint_hash`` = dernier ``entry_hash`` purgé) reste celui
        calculé sous l'ancienne clé. La chaîne reste vérifiable ``(True, None)``
        avec la seule nouvelle clé (le checkpoint est comparé, pas re-haché),
        mais le point de purge lui-même n'est authentifiable qu'avec l'ancienne
        clé. Recommandation : lancer ``rekey`` avant toute purge (continuité
        pure), et archiver l'ancienne clé si la base a déjà été purgée.
        """
        if not new_hmac_key:
            raise ValueError("nouvelle clé HMAC d'audit invalide.")
        resigned = 0
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            for stream in (_AUDIT_STREAM_ACCESS, _AUDIT_STREAM_REJECTION):
                valid, _invalid = self._verify_stream(conn, stream)
                if not valid:
                    raise ValueError(
                        "chaîne d'audit non vérifiable avec la clé actuelle : "
                        "re-signature refusée (vérifier la KEK courante et "
                        "HEIMDALL_VAULT_SERVER_HMAC_KEY si le serveur l'utilisait)."
                    )
            for stream in (_AUDIT_STREAM_ACCESS, _AUDIT_STREAM_REJECTION):
                previous_hash, _pruned = self._checkpoint(conn, stream)
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE stream = ? ORDER BY id ASC", (stream,)
                ).fetchall()
                for row in rows:
                    payload = _canonical_payload(
                        occurred_at=str(row["occurred_at"]),
                        key_id=row["key_id"],
                        key_fingerprint_value=row["key_fingerprint"],
                        project=row["project"],
                        peer=str(row["peer"]),
                        action=str(row["action"]),
                        target=row["target"],
                        status_code=int(row["status_code"]),
                        outcome=str(row["outcome"]),
                        previous_hash=previous_hash,
                    )
                    entry_hash = _entry_hash(payload, new_hmac_key)
                    conn.execute(
                        "UPDATE audit_events SET previous_hash = ?, entry_hash = ? WHERE id = ?",
                        (previous_hash, entry_hash, int(row["id"])),
                    )
                    previous_hash = entry_hash
                    resigned += 1
        self._hmac_key = new_hmac_key
        return resigned

    def needs_schema_migration(self) -> bool:
        """True si la base date d'avant l'audit M-03 (pas de colonne ``stream``).

        Une lecture en ``create=False`` ne migre pas le schéma : l'appelant
        doit annoncer « migration requise » plutôt qu'un échec générique.
        """
        with db_session(self._db_path) as conn:
            columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(audit_events);").fetchall()
            }
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        # Les deux tables d'état de chaîne sont lues par verify_chain/record :
        # leur absence est aussi une base à migrer (pas une OperationalError).
        if not {"audit_chain_state", "audit_rejection_chain_state"} <= tables:
            return True
        # Table absente (base très ancienne ou incomplète) : même diagnostic
        # « migration requise » plutôt qu'une OperationalError générique.
        return not columns or "stream" not in columns

    def is_legacy_sha256_chain(self) -> bool:
        """True si le journal est une chaîne SHA-256 historique valide (pré-F-16).

        Permet de distinguer « migration requise » d'une falsification quand
        la vérification HMAC échoue sur une base créée avant l'audit F-16.
        """
        if self._hmac_key is None or self.count() == 0:
            return False
        legacy = SqliteAuditLog(self._db_path, create=False, hmac_key=None)
        return legacy.verify_chain() == (True, None)

    def count(self) -> int:
        """Nombre d'événements persistés (diagnostic et tests)."""
        with db_session(self._db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
        return int(row[0]) if row is not None else 0

    def pruned_count(self) -> int:
        """Nombre d'événements purgés par la rétention (diagnostic)."""
        with db_session(self._db_path) as conn:
            _access_hash, access_pruned = self._checkpoint(conn, _AUDIT_STREAM_ACCESS)
            _rej_hash, rejection_pruned = self._checkpoint(
                conn, _AUDIT_STREAM_REJECTION
            )
        return access_pruned + rejection_pruned

    def clear(self) -> None:
        """Réinitialise le journal (tests isolés)."""
        with db_session(self._db_path) as conn:
            conn.execute(_AUDIT_TABLE_SQL)
            conn.execute(_AUDIT_STATE_TABLE_SQL)
            conn.execute(_AUDIT_REJECTION_STATE_TABLE_SQL)
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM audit_chain_state")
            conn.execute("DELETE FROM audit_rejection_chain_state")


class AuditMiddleware:
    """Middleware ASGI qui journalise chaque réponse, refus compris.

    L'événement est écrit **avant** la transmission de ``http.response.start`` :
    si l'audit échoue, une réponse 503 générique remplace la réponse originale
    (fail-closed). Aucun corps de requête, en-tête ou valeur de secret n'est lu.
    """

    def __init__(self, app: Any, audit_log: AuditLog) -> None:
        self.app = app
        self.audit_log = audit_log

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        response_started = False
        audit_failed = False

        async def send_wrapper(message: Any) -> None:
            nonlocal response_started, audit_failed
            if audit_failed:
                return
            if message["type"] == "http.response.start" and not response_started:
                response_started = True
                try:
                    await self._record(request, int(message["status"]))
                except Exception:
                    logger.error("Journal d'audit indisponible : réponse 503 fail-closed.")
                    audit_failed = True
                    await self._send_unavailable(scope, receive, send)
                    return
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except DatabaseUnavailableError:
            # Panne SQLite (contention, ouverture, commit) : le contrat exige
            # 503, jamais 500. DatabaseAvailabilityMiddleware le fait déjà pour
            # les routes ; cette garde couvre le cas où l'exception remonte
            # jusqu'au middleware d'audit (le plus externe).
            if audit_failed:
                return
            if response_started:
                raise
            await self._send_unavailable(scope, receive, send)
            return
        except Exception:
            if audit_failed:
                # La réponse 503 a déjà été envoyée : ne pas laisser le
                # ServerErrorMiddleware extérieur tenter une seconde réponse.
                return
            if response_started:
                raise
            try:
                await self._record(request, 500)
            except Exception:
                logger.error("Journal d'audit indisponible : réponse 503 fail-closed.")
                await self._send_unavailable(scope, receive, send)
                return
            response = JSONResponse(status_code=500, content=_INTERNAL_PAYLOAD)
            await response(scope, receive, send)

    async def _record(self, request: Request, status_code: int) -> None:
        """Construit et persiste l'événement d'audit d'une requête."""
        scope = request.scope
        route = scope.get("route")
        route_path = getattr(route, "path", None) if route is not None else None
        # Route inconnue : ne jamais recopier le chemin brut (contrôlé par le
        # client) dans le journal. Le couple méthode + UNMATCHED suffit.
        path = route_path if isinstance(route_path, str) else "UNMATCHED"
        method = str(scope.get("method", ""))
        action = f"{method} {path}".strip()

        target = getattr(request.state, "audit_target", None)
        if not isinstance(target, str) or not target:
            path_params = scope.get("path_params", {})
            if isinstance(path_params, dict):
                parts = [
                    path_params.get("project"),
                    path_params.get("env"),
                    path_params.get("name"),
                ]
                if all(isinstance(part, str) and part for part in parts):
                    target = "/".join(str(part) for part in parts)
        if (
            (not isinstance(target, str) or not target)
            and path == "/api/v1/secrets"
            and method == "GET"
        ):
            # 401 avant le handler : le projet demandé est un identifiant public
            # déjà validé par le contrat. On ne recopie jamais la query brute.
            query_project = request.query_params.get("project")
            if query_project is not None:
                try:
                    target = validate_project_id(query_project)
                except ValueError:
                    target = None

        fingerprint = getattr(request.state, "audit_key_hash", None)
        key_id = getattr(request.state, "audit_key_id", None)
        project = getattr(request.state, "audit_project", None)
        peer = request.client.host if request.client and request.client.host else "unknown"
        await self.audit_log.record(
            peer=peer,
            action=action,
            target=target if isinstance(target, str) else None,
            status_code=status_code,
            key_fingerprint_value=fingerprint if isinstance(fingerprint, str) else None,
            key_id=key_id if isinstance(key_id, str) else None,
            project=project if isinstance(project, str) else None,
        )

    @staticmethod
    async def _send_unavailable(scope: Any, receive: Any, send: Any) -> None:
        """Réponse 503 générique, sans détail interne, quand l'audit échoue."""
        response = JSONResponse(
            status_code=503,
            content=_UNAVAILABLE_PAYLOAD,
            headers={
                "Retry-After": "1",
                "Connection": "close",
                "Cache-Control": "no-store",
            },
        )
        await response(scope, receive, send)


__all__ = [
    "AuditEvent",
    "AuditLog",
    "AuditMiddleware",
    "DEFAULT_LIST_LIMIT",
    "GENESIS_HASH",
    "InMemoryAuditLog",
    "MAX_LIST_LIMIT",
    "SqliteAuditLog",
    "key_fingerprint",
]
