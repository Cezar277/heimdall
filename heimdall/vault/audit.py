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
  ``entry_hash`` (SHA-256 d'une charge canonique JSON). Modifier, insérer ou
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
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from starlette.requests import Request
from starlette.responses import JSONResponse

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

_AUDIT_TABLE_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
_AUDIT_STATE_TABLE_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS audit_chain_state (
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


def _entry_hash(payload: bytes) -> str:
    """SHA-256 hexadécimal de la charge canonique d'un événement."""
    return hashlib.sha256(payload).hexdigest()


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

    Il n'est pas partagé entre processus et disparaît au redémarrage : la
    production utilise ``SqliteAuditLog``.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._checkpoint_hash = GENESIS_HASH
        self._pruned_events = 0
        self._next_id = 1
        self._lock = threading.Lock()

    def _prune_locked(self) -> None:
        """Purge les plus anciens événements et avance le point de contrôle."""
        excess = len(self._events) - max(1, MAX_AUDIT_EVENTS)
        if excess <= 0:
            return
        pruned = self._events[:excess]
        self._checkpoint_hash = pruned[-1].entry_hash
        self._pruned_events += len(pruned)
        del self._events[:excess]

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
        with self._lock:
            previous_hash = (
                self._events[-1].entry_hash if self._events else self._checkpoint_hash
            )
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
                entry_hash=_entry_hash(payload),
            )
            self._next_id += 1
            self._events.append(event)
            self._prune_locked()
            return event

    def list_events(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        project: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            selected = [
                event for event in self._events if project is None or event.project == project
            ]
            return [event.as_dict() for event in selected[-limit:]]

    def verify_chain(self) -> tuple[bool, int | None]:
        with self._lock:
            previous_hash = self._checkpoint_hash
            for event in self._events:
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
                if _entry_hash(payload) != event.entry_hash:
                    return False, event.id
                previous_hash = event.entry_hash
            return True, None

    def pruned_count(self) -> int:
        """Nombre d'événements purgés par la rétention (diagnostic)."""
        with self._lock:
            return self._pruned_events

    def clear(self) -> None:
        """Réinitialise le journal (tests isolés)."""
        with self._lock:
            self._events.clear()
            self._checkpoint_hash = GENESIS_HASH
            self._pruned_events = 0
            self._next_id = 1


class SqliteAuditLog(AuditLog):
    """Journal d'audit persistant, partagé entre workers via SQLite.

    L'ajout est sérialisé par ``BEGIN IMMEDIATE`` : deux workers ne peuvent pas
    lire le même ``previous_hash`` puis insérer deux lignes concurrentes. La
    lecture et la vérification ne prennent aucun verrou d'écriture.
    """

    def __init__(self, db_path: Path | str, *, create: bool = True) -> None:
        self._db_path = Path(db_path) if isinstance(db_path, str) else db_path
        if create:
            with db_session(self._db_path) as conn:
                conn.execute(_AUDIT_TABLE_SQL)
                conn.execute(_AUDIT_INDEX_SQL)
                conn.execute(_AUDIT_STATE_TABLE_SQL)

    @property
    def db_path(self) -> Path | str:
        """Chemin de la base SQLite du journal."""
        return self._db_path

    @staticmethod
    def _checkpoint(conn: Any) -> tuple[str, int]:
        """Retourne le point de contrôle de chaîne et le nombre d'événements purgés."""
        row = conn.execute(
            "SELECT checkpoint_hash, pruned_events FROM audit_chain_state WHERE id = 1"
        ).fetchone()
        if row is None:
            return GENESIS_HASH, 0
        return str(row["checkpoint_hash"]), int(row["pruned_events"])

    @staticmethod
    def _prune(conn: Any) -> None:
        """Borne la table et avance le point de contrôle de chaîne.

        Les événements supprimés restent prouvables par leur dernier
        ``entry_hash`` conservé dans ``audit_chain_state`` : le premier
        événement retenu pointe dessus, donc ``verify_chain`` reste valide.
        """
        row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
        count = int(row[0]) if row is not None else 0
        excess = count - max(1, MAX_AUDIT_EVENTS)
        if excess <= 0:
            return
        rows = conn.execute(
            "SELECT id, entry_hash FROM audit_events ORDER BY id ASC LIMIT ?",
            (excess,),
        ).fetchall()
        if not rows:
            return
        checkpoint_hash = str(rows[-1]["entry_hash"])
        conn.executemany(
            "DELETE FROM audit_events WHERE id = ?",
            [(int(item["id"]),) for item in rows],
        )
        conn.execute(
            "INSERT INTO audit_chain_state ("
            "id, checkpoint_hash, pruned_events, updated_at"
            ") VALUES (1, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "checkpoint_hash = excluded.checkpoint_hash, "
            "pruned_events = audit_chain_state.pruned_events + excluded.pruned_events, "
            "updated_at = excluded.updated_at",
            (checkpoint_hash, len(rows), get_iso_timestamp()),
        )

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
            checkpoint_hash, _pruned = self._checkpoint(conn)
            row = conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
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
            entry_hash = _entry_hash(payload)
            cursor = conn.execute(
                "INSERT INTO audit_events ("
                "occurred_at, key_id, key_fingerprint, project, peer, action, target, "
                "status_code, outcome, previous_hash, entry_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
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
            self._prune(conn)
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
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(MAX_LIST_LIMIT, int(limit)))
        with db_session(self._db_path) as conn:
            if project is None:
                rows = conn.execute(
                    "SELECT * FROM ("
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?"
                    ") ORDER BY id ASC",
                    (bounded_limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ("
                    "SELECT * FROM audit_events WHERE project = ? ORDER BY id DESC LIMIT ?"
                    ") ORDER BY id ASC",
                    (project, bounded_limit),
                ).fetchall()
        return [dict(row) for row in rows]

    def verify_chain(self) -> tuple[bool, int | None]:
        with db_session(self._db_path) as conn:
            previous_hash, _pruned = self._checkpoint(conn)
            # Itération du curseur : la table est bornée par la rétention, donc
            # la vérification ne charge pas un historique illimité en mémoire.
            for row in conn.execute("SELECT * FROM audit_events ORDER BY id ASC"):
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
                if _entry_hash(payload) != str(row["entry_hash"]):
                    return False, event_id
                previous_hash = str(row["entry_hash"])
        return True, None

    def count(self) -> int:
        """Nombre d'événements persistés (diagnostic et tests)."""
        with db_session(self._db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
        return int(row[0]) if row is not None else 0

    def pruned_count(self) -> int:
        """Nombre d'événements purgés par la rétention (diagnostic)."""
        with db_session(self._db_path) as conn:
            _checkpoint_hash, pruned = self._checkpoint(conn)
        return pruned

    def clear(self) -> None:
        """Réinitialise le journal (tests isolés)."""
        with db_session(self._db_path) as conn:
            conn.execute(_AUDIT_TABLE_SQL)
            conn.execute(_AUDIT_STATE_TABLE_SQL)
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM audit_chain_state")


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
