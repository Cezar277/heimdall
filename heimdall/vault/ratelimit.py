"""Rate-limiting du Vault Heimdall — fenêtre glissante exacte (tickets #63/#111).

Trois budgets indépendants protègent l'API :

- par **clé API validée** (l'identifiant de bucket est l'empreinte HMAC, jamais
  la clé brute) ;
- par **pair réseau** (adresse du socket, jamais ``X-Forwarded-For`` sans proxy
  de confiance) ;
- **global** (toutes origines confondues).

La fenêtre est **glissante** : chaque admission est horodatée et seule la
fenêtre ``[now - window, now]`` est comptée. Un dépassement renvoie le délai
exact avant l'expiration de la plus ancienne admission, borné à
``Retry-After`` 1..3600 s. Contrairement à une fenêtre fixe, un attaquant ne
peut pas doubler son débit à cheval sur deux fenêtres.

Deux backends partagent la même interface :

- ``RateLimiter`` en mémoire, réservé au développement/tests et strictement
  mono-processus. Un cache mémoire ne suffit PAS avec plusieurs workers : chaque
  processus aurait son propre compteur et la limite effective serait multipliée
  par le nombre de processus ;
- ``SqliteRateLimiter`` pour le backend SQLite : les admissions sont persistées
  dans la base Vault et les décisions sont prises sous ``BEGIN IMMEDIATE``. La
  limite est donc partagée entre workers, sans multiplication du débit effectif.

Aucune valeur sensible n'est stockée : les buckets par clé ne contiennent que
l'empreinte HMAC et les horodatages d'admission.
"""

import math
import sqlite3
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from heimdall.vault.database import runtime_db_session as db_session

_MAX_RETRY_AFTER_SECONDS: int = 3_600
_MAX_TRACKED_BUCKETS: int = 100_000
_SQLITE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS rate_limit_hits (
    name TEXT NOT NULL,
    hit_at REAL NOT NULL
);
"""
_SQLITE_INDEX_SQL: str = """
CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_name_at
    ON rate_limit_hits(name, hit_at);
"""
_SQLITE_HITS_AT_INDEX_SQL: str = """
CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_at
    ON rate_limit_hits(hit_at);
"""


@dataclass
class _Bucket:
    """Admissions horodatées d'un budget (fenêtre glissante).

    ``count`` est conservé comme propriété pour les tests et les diagnostics :
    il représente le nombre d'admissions encore dans la fenêtre.
    """

    hits: deque[float] = field(default_factory=deque)

    @property
    def count(self) -> int:
        """Nombre d'admissions encore dans la fenêtre courante."""
        return len(self.hits)


def _retry_after(oldest_hit: float, now: float, window_seconds: int) -> int:
    """Délai entier avant l'expiration de la plus ancienne admission."""
    return max(
        1,
        min(
            _MAX_RETRY_AFTER_SECONDS,
            math.ceil(oldest_hit + window_seconds - now),
        ),
    )


class RateLimiter:
    """Fenêtre glissante en mémoire, sans stockage de valeur sensible.

    Le verrou protège les admissions concurrentes : le backend mémoire est
    strictement mono-processus, mais plusieurs threads (tests, appels
    synchrones) peuvent partager une instance.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        per_key: int,
        per_peer: int,
        global_limit: int,
        window_seconds: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if min(per_key, per_peer, global_limit) < 1:
            raise ValueError("Les limites de rate-limiting doivent être >= 1.")
        if not 1 <= window_seconds <= _MAX_RETRY_AFTER_SECONDS:
            raise ValueError("La fenêtre de rate-limiting doit être comprise entre 1 et 3600 s.")
        self._per_key = per_key
        self._per_peer = per_peer
        self._global_limit = global_limit
        self._window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._lock = Lock()
        self._buckets: dict[str, _Bucket] = {}

    def _prune_bucket(self, bucket: _Bucket, now: float) -> None:
        """Retire les admissions sorties de la fenêtre glissante."""
        cutoff = now - self._window_seconds
        while bucket.hits and bucket.hits[0] <= cutoff:
            bucket.hits.popleft()

    def _existing_bucket(self, name: str, now: float) -> _Bucket | None:
        """Retourne le bucket existant après purge, sans jamais en créer.

        Un rejet ne doit pas laisser d'entrée vide pour chaque nom évalué :
        les buckets sont créés uniquement quand une admission est réellement
        consommée (chemin autorisé ou pair/global consommés sur rejet clé).
        """
        bucket = self._buckets.get(name)
        if bucket is not None:
            self._prune_bucket(bucket, now)
        return bucket

    def _ensure_bucket(self, name: str) -> _Bucket:
        """Crée le bucket au moment de la première admission consommée."""
        bucket = self._buckets.get(name)
        if bucket is None:
            bucket = _Bucket()
            self._buckets[name] = bucket
        return bucket

    def _prune(self, now: float) -> None:
        """Borne la mémoire : purge les budgets vides au-delà du seuil."""
        if len(self._buckets) <= _MAX_TRACKED_BUCKETS:
            return
        cutoff = now - self._window_seconds
        self._buckets = {
            name: bucket
            for name, bucket in self._buckets.items()
            if bucket.hits and bucket.hits[-1] > cutoff
        }

    def _evaluate(
        self,
        specs: list[tuple[str, int]],
        now: float,
        *,
        consume_on_reject: frozenset[str] = frozenset(),
    ) -> tuple[bool, int]:
        """Évalue tous les budgets, puis consomme atomiquement.

        ``consume_on_reject`` permet de conserver la sémantique du middleware :
        pair/global sont consommés même quand le budget clé est plein, tandis
        qu'un rejet pair/global n'ajoute rien.
        """
        buckets: list[tuple[str, int, _Bucket | None]] = []
        full: tuple[_Bucket, int] | None = None
        for name, limit in specs:
            bucket = self._existing_bucket(name, now)
            buckets.append((name, limit, bucket))
            if full is None and bucket is not None and bucket.count >= limit:
                full = (bucket, limit)

        if full is not None:
            bucket, _limit = full
            if consume_on_reject:
                for name, spec_limit, candidate in buckets:
                    if name not in consume_on_reject:
                        continue
                    current = candidate.count if candidate is not None else 0
                    if current < spec_limit:
                        target = candidate if candidate is not None else self._ensure_bucket(name)
                        target.hits.append(now)
            # Purge aussi sur le chemin rejet : les budgets expirés ne doivent
            # pas survivre à un flot de rejets (parité avec le backend SQLite).
            self._prune(now)
            oldest = bucket.hits[0] if bucket.hits else now
            return False, _retry_after(oldest, now, self._window_seconds)

        for name, _limit, bucket in buckets:
            target = bucket if bucket is not None else self._ensure_bucket(name)
            target.hits.append(now)
        self._prune(now)
        return True, 0

    def check(self, peer: str, key_hash: str | None = None) -> tuple[bool, int]:
        """Consomme une unité ; retourne ``(autorisé, retry_after_secondes)``.

        Le nom de bucket d'une clé est son empreinte HMAC, jamais la clé brute.
        """
        specs: list[tuple[str, int]] = [
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ]
        if key_hash is not None:
            specs.append((f"key:{key_hash}", self._per_key))

        with self._lock:
            return self._evaluate(specs, self._clock())

    def check_key(self, key_hash: str) -> tuple[bool, int]:
        """Consomme seulement le budget clé après admission pair/global."""
        with self._lock:
            return self._evaluate([(f"key:{key_hash}", self._per_key)], self._clock())

    def peek(self, peer: str) -> tuple[bool, int]:
        """Contrôle sans consommation des budgets pair/global (rejet précoce).

        Utilisé avant tout hachage/lookup pour refuser sans coût CPU les
        rafales déjà limitées. Ne crée aucun bucket et ne consomme aucune
        admission (les entrées expirées peuvent être purgées).
        """
        with self._lock:
            now = self._clock()
            for name, limit in (
                ("global", self._global_limit),
                (f"peer:{peer}", self._per_peer),
            ):
                bucket = self._buckets.get(name)
                if bucket is None:
                    continue
                self._prune_bucket(bucket, now)
                if bucket.count >= limit:
                    oldest = bucket.hits[0] if bucket.hits else now
                    return False, _retry_after(oldest, now, self._window_seconds)
            return True, 0

    def check_authenticated(self, peer: str, key_hash: str) -> tuple[bool, int]:
        """Consomme pair/global + clé en une seule section critique.

        Sémantique préservée : pair/global sont consommés même quand le budget
        clé est plein, sans fenêtre inter-transactions.
        """
        with self._lock:
            return self._evaluate(
                [
                    ("global", self._global_limit),
                    (f"peer:{peer}", self._per_peer),
                    (f"key:{key_hash}", self._per_key),
                ],
                self._clock(),
                consume_on_reject=frozenset({"global", f"peer:{peer}"}),
            )

    def clear(self) -> None:
        """Réinitialise l'état partagé (tests isolés)."""
        with self._lock:
            self._buckets.clear()


class SqliteRateLimiter:
    """Fenêtre glissante partagée entre workers, persistée dans SQLite.

    Chaque admission est une ligne ``(name, hit_at)``. Les décisions sont prises
    sous ``BEGIN IMMEDIATE`` : le verrou d'écriture SQLite sérialise les
    comptages et les insertions, donc la limite n'est jamais multipliée par le
    nombre de processus. Le temps de référence est l'horloge murale (comparable
    entre processus), volontairement distinct du ``time.monotonic()`` du backend
    mémoire.
    """

    def __init__(  # noqa: PLR0913
        self,
        db_path: Path | str,
        *,
        per_key: int,
        per_peer: int,
        global_limit: int,
        window_seconds: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if min(per_key, per_peer, global_limit) < 1:
            raise ValueError("Les limites de rate-limiting doivent être >= 1.")
        if not 1 <= window_seconds <= _MAX_RETRY_AFTER_SECONDS:
            raise ValueError("La fenêtre de rate-limiting doit être comprise entre 1 et 3600 s.")
        self._db_path = db_path
        self._per_key = per_key
        self._per_peer = per_peer
        self._global_limit = global_limit
        self._window_seconds = window_seconds
        self._clock = clock or time.time
        with db_session(self._db_path) as conn:
            conn.execute(_SQLITE_TABLE_SQL)
            conn.execute(_SQLITE_INDEX_SQL)
            conn.execute(_SQLITE_HITS_AT_INDEX_SQL)

    @staticmethod
    def _prune_global(conn: sqlite3.Connection, cutoff: float) -> None:
        """Supprime toutes les admissions sorties de la fenêtre (index sur hit_at).

        Appelée à chaque évaluation, rejets compris : un rejet peut insérer une
        admission pour un pair neuf, et sans purge sur ce chemin la table ne se
        bornerait qu'aux admissions autorisées.
        """
        conn.execute("DELETE FROM rate_limit_hits WHERE hit_at <= ?", (cutoff,))

    @staticmethod
    def _count(conn: sqlite3.Connection, name: str, cutoff: float) -> int:
        """Compte les admissions encore dans la fenêtre pour un budget."""
        row = conn.execute(
            "SELECT COUNT(*) FROM rate_limit_hits WHERE name = ? AND hit_at > ?",
            (name, cutoff),
        ).fetchone()
        return int(row[0]) if row is not None else 0

    @staticmethod
    def _oldest(conn: sqlite3.Connection, name: str, cutoff: float) -> float | None:
        """Retourne l'horodatage de la plus ancienne admission de la fenêtre."""
        row = conn.execute(
            "SELECT MIN(hit_at) FROM rate_limit_hits WHERE name = ? AND hit_at > ?",
            (name, cutoff),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return float(row[0])

    def _evaluate(
        self,
        conn: sqlite3.Connection,
        specs: list[tuple[str, int]],
        now: float,
        *,
        consume_on_reject: frozenset[str] = frozenset(),
    ) -> tuple[bool, int]:
        """Évalue et consomme les budgets dans la transaction courante."""
        cutoff = now - self._window_seconds
        self._prune_global(conn, cutoff)
        states: list[tuple[str, int, int, float | None]] = []
        full: float | None = None
        for name, limit in specs:
            count = self._count(conn, name, cutoff)
            oldest = self._oldest(conn, name, cutoff)
            states.append((name, limit, count, oldest))
            if full is None and count >= limit:
                full = oldest

        if full is not None:
            oldest = full
            if consume_on_reject:
                for name, spec_limit, count, _oldest_hit in states:
                    if name in consume_on_reject and count < spec_limit:
                        conn.execute(
                            "INSERT INTO rate_limit_hits (name, hit_at) VALUES (?, ?)",
                            (name, now),
                        )
            return False, _retry_after(
                oldest if oldest is not None else now,
                now,
                self._window_seconds,
            )

        for name, _limit, _count_value, _oldest_hit in states:
            conn.execute(
                "INSERT INTO rate_limit_hits (name, hit_at) VALUES (?, ?)",
                (name, now),
            )
        return True, 0

    def check(self, peer: str, key_hash: str | None = None) -> tuple[bool, int]:
        """Consomme une unité de façon atomique entre workers, sans stocker la clé."""
        specs: list[tuple[str, int]] = [
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ]
        if key_hash is not None:
            specs.append((f"key:{key_hash}", self._per_key))

        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._evaluate(conn, specs, self._clock())

    def check_key(self, key_hash: str) -> tuple[bool, int]:
        """Consomme seulement le budget clé après admission pair/global."""
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._evaluate(
                conn,
                [(f"key:{key_hash}", self._per_key)],
                self._clock(),
            )

    def peek(self, peer: str) -> tuple[bool, int]:
        """Contrôle sans consommation des budgets pair/global (rejet précoce).

        Lecture seule sans ``BEGIN IMMEDIATE`` : aucun verrou d'écriture,
        aucun hachage ni lookup ne suit quand le pair/global est déjà plein.
        """
        with db_session(self._db_path) as conn:
            now = self._clock()
            cutoff = now - self._window_seconds
            for name, limit in (
                ("global", self._global_limit),
                (f"peer:{peer}", self._per_peer),
            ):
                count = self._count(conn, name, cutoff)
                if count >= limit:
                    oldest = self._oldest(conn, name, cutoff)
                    return False, _retry_after(
                        oldest if oldest is not None else now,
                        now,
                        self._window_seconds,
                    )
            return True, 0

    def check_authenticated(self, peer: str, key_hash: str) -> tuple[bool, int]:
        """Consomme pair/global + clé en une seule transaction ``BEGIN IMMEDIATE``.

        Sémantique préservée : pair/global sont consommés même quand le budget
        clé est plein (une seule transaction au lieu de deux, sans fenêtre
        inter-transactions ni double verrou d'écriture).
        """
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._evaluate(
                conn,
                [
                    ("global", self._global_limit),
                    (f"peer:{peer}", self._per_peer),
                    (f"key:{key_hash}", self._per_key),
                ],
                self._clock(),
                consume_on_reject=frozenset({"global", f"peer:{peer}"}),
            )

    def clear(self) -> None:
        """Réinitialise l'état partagé (tests isolés)."""
        with db_session(self._db_path) as conn:
            conn.execute(_SQLITE_TABLE_SQL)
            conn.execute("DELETE FROM rate_limit_hits")
