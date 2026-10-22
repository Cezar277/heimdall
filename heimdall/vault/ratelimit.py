"""Rate-limiting débit du Vault (livré dans le lot d'intégration #63).

Fenêtres fixes par clé API validée, par pair réseau et globale. Les 400 et 401
consomment le budget puisqu'ils traversent ce middleware avant le routage. Une
clé absente, invalide ou révoquée n'obtient pas de bucket arbitraire : seuls le
pair réseau et la limite globale s'appliquent.

Deux backends partagent la même interface : ``RateLimiter`` en mémoire pour le
mode développement/tests (strictement mono-processus) et
``SqliteRateLimiter`` pour le backend SQLite, qui persiste les buckets dans la
base Vault et sérialise les incréments sous ``BEGIN IMMEDIATE`` : la limite est
donc partagée entre workers, sans multiplication du débit effectif.
"""

import math
import time
from dataclasses import dataclass
from pathlib import Path

from heimdall.vault.database import runtime_db_session as db_session

_MAX_RETRY_AFTER_SECONDS: int = 3_600
_MAX_TRACKED_BUCKETS: int = 100_000
_SQLITE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    name TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at REAL NOT NULL
);
"""


@dataclass
class _Bucket:
    count: int
    reset_at: float


class RateLimiter:
    """Fenêtre fixe minimale, sans stockage de valeur sensible (hash de clé seulement)."""

    def __init__(
        self,
        *,
        per_key: int,
        per_peer: int,
        global_limit: int,
        window_seconds: int,
    ) -> None:
        if min(per_key, per_peer, global_limit) < 1:
            raise ValueError("Les limites de rate-limiting doivent être >= 1.")
        if not 1 <= window_seconds <= _MAX_RETRY_AFTER_SECONDS:
            raise ValueError("La fenêtre de rate-limiting doit être comprise entre 1 et 3600 s.")
        self._per_key = per_key
        self._per_peer = per_peer
        self._global_limit = global_limit
        self._window_seconds = window_seconds
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, name: str, now: float) -> _Bucket:
        bucket = self._buckets.get(name)
        if bucket is None or now >= bucket.reset_at:
            bucket = _Bucket(count=0, reset_at=now + self._window_seconds)
            self._buckets[name] = bucket
        return bucket

    def _prune(self, now: float) -> None:
        """Borne la mémoire : purge les fenêtres expirées au-delà du seuil."""
        if len(self._buckets) <= _MAX_TRACKED_BUCKETS:
            return
        self._buckets = {
            name: bucket for name, bucket in self._buckets.items() if bucket.reset_at > now
        }

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

        return self._check(specs)

    def check_key(self, key_hash: str) -> tuple[bool, int]:
        """Consomme seulement le bucket clé après admission pair/global."""
        return self._check([(f"key:{key_hash}", self._per_key)])

    def peek(self, peer: str) -> tuple[bool, int]:
        """Contrôle sans consommation des buckets pair/global (rejet précoce).

        Utilisé avant tout hachage/lookup pour refuser sans coût CPU les
        rafales déjà limitées. Ne crée ni ne mute aucun bucket.
        """
        now = time.monotonic()
        for name, limit in (
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ):
            bucket = self._buckets.get(name)
            if bucket is None or now >= bucket.reset_at:
                continue
            if bucket.count >= limit:
                retry = max(
                    1,
                    min(
                        _MAX_RETRY_AFTER_SECONDS,
                        math.ceil(bucket.reset_at - now),
                    ),
                )
                return False, retry
        return True, 0

    def check_authenticated(self, peer: str, key_hash: str) -> tuple[bool, int]:
        """Consomme pair/global + clé en une seule section critique.

        Sémantique préservée (test ``peer_global_are_consumed_once``) :
        pair/global sont consommés même quand le bucket clé est plein
        (sur-consommation volontaire, pas d'atomicité tout-ou-rien), mais
        l'ensemble est appliqué sans fenêtre entre deux transactions :
        une seule mutation pour une requête authentifiée.
        """
        now = time.monotonic()
        pending: list[_Bucket] = []
        for name, limit in (
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ):
            bucket = self._bucket(name, now)
            if bucket.count >= limit:
                retry = max(
                    1,
                    min(
                        _MAX_RETRY_AFTER_SECONDS,
                        math.ceil(bucket.reset_at - now),
                    ),
                )
                return False, retry
            pending.append(bucket)
        for bucket in pending:
            bucket.count += 1
        key_bucket = self._bucket(f"key:{key_hash}", now)
        if key_bucket.count >= self._per_key:
            retry = max(
                1,
                min(
                    _MAX_RETRY_AFTER_SECONDS,
                    math.ceil(key_bucket.reset_at - now),
                ),
            )
            return False, retry
        key_bucket.count += 1
        self._prune(now)
        return True, 0

    def _check(self, specs: list[tuple[str, int]]) -> tuple[bool, int]:
        now = time.monotonic()
        buckets: list[_Bucket] = []
        for name, limit in specs:
            bucket = self._bucket(name, now)
            if bucket.count >= limit:
                retry = max(
                    1,
                    min(
                        _MAX_RETRY_AFTER_SECONDS,
                        math.ceil(bucket.reset_at - now),
                    ),
                )
                return False, retry
            buckets.append(bucket)

        for bucket in buckets:
            bucket.count += 1
        self._prune(now)
        return True, 0

    def clear(self) -> None:
        """Réinitialise l'état (tests isolés)."""
        self._buckets.clear()


class SqliteRateLimiter:
    """Fenêtre fixe partagée entre workers via la base SQLite du Vault.

    Chaque ``check`` ouvre une transaction ``BEGIN IMMEDIATE`` : le verrou
    d'écriture SQLite sérialise la lecture et l'incrément des trois buckets
    (global, pair, clé validée). Deux workers partageant le même fichier
    appliquent donc une limite unique, jamais N × la limite. Aucune valeur de
    clé brute n'est stockée : le nom du bucket par clé reste son empreinte HMAC.
    Le temps de référence est l'horloge murale (comparable entre processus),
    volontairement distinct du ``time.monotonic()`` du backend mémoire.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        per_key: int,
        per_peer: int,
        global_limit: int,
        window_seconds: int,
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
        with db_session(self._db_path) as conn:
            conn.execute(_SQLITE_TABLE_SQL)

    def check(self, peer: str, key_hash: str | None = None) -> tuple[bool, int]:
        """Consomme une unité de façon atomique entre workers, sans stocker la clé."""
        specs: list[tuple[str, int]] = [
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ]
        if key_hash is not None:
            specs.append((f"key:{key_hash}", self._per_key))

        return self._check(specs)

    def check_key(self, key_hash: str) -> tuple[bool, int]:
        """Consomme seulement le bucket clé après admission pair/global."""
        return self._check([(f"key:{key_hash}", self._per_key)])

    def peek(self, peer: str) -> tuple[bool, int]:
        """Contrôle sans consommation des buckets pair/global (rejet précoce).

        Lecture seule sans ``BEGIN IMMEDIATE`` : aucun verrou d'écriture,
        aucun hachage ni lookup ne suit quand le pair/global est déjà plein.
        """
        with db_session(self._db_path) as conn:
            now = time.time()
            for name, limit in (
                ("global", self._global_limit),
                (f"peer:{peer}", self._per_peer),
            ):
                row = conn.execute(
                    "SELECT count, reset_at FROM rate_limit_buckets WHERE name = ?",
                    (name,),
                ).fetchone()
                if row is None or now >= float(row["reset_at"]):
                    continue
                if int(row["count"]) >= limit:
                    retry = max(
                        1,
                        min(
                            _MAX_RETRY_AFTER_SECONDS,
                            math.ceil(float(row["reset_at"]) - now),
                        ),
                    )
                    return False, retry
            return True, 0

    def check_authenticated(self, peer: str, key_hash: str) -> tuple[bool, int]:
        """Consomme pair/global + clé en une seule transaction ``BEGIN IMMEDIATE``.

        Sémantique préservée : pair/global sont consommés même quand le
        bucket clé est plein (une seule transaction au lieu de deux,
        sans fenêtre inter-transactions ni double verrou d'écriture).
        """
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            pending: list[tuple[str, int, float]] = []
            for name, limit in (
                ("global", self._global_limit),
                (f"peer:{peer}", self._per_peer),
            ):
                row = conn.execute(
                    "SELECT count, reset_at FROM rate_limit_buckets WHERE name = ?",
                    (name,),
                ).fetchone()
                if row is None or now >= float(row["reset_at"]):
                    count, reset_at = 0, now + self._window_seconds
                else:
                    count, reset_at = int(row["count"]), float(row["reset_at"])
                if count >= limit:
                    retry = max(
                        1,
                        min(
                            _MAX_RETRY_AFTER_SECONDS,
                            math.ceil(reset_at - now),
                        ),
                    )
                    return False, retry
                pending.append((name, count + 1, reset_at))
            key_name = f"key:{key_hash}"
            row = conn.execute(
                "SELECT count, reset_at FROM rate_limit_buckets WHERE name = ?",
                (key_name,),
            ).fetchone()
            if row is None or now >= float(row["reset_at"]):
                key_count, key_reset = 0, now + self._window_seconds
            else:
                key_count, key_reset = int(row["count"]), float(row["reset_at"])
            if key_count >= self._per_key:
                for name, count, reset_at in pending:
                    conn.execute(
                        "INSERT INTO rate_limit_buckets (name, count, reset_at) "
                        "VALUES (?, ?, ?) "
                        "ON CONFLICT(name) DO UPDATE SET count = excluded.count, "
                        "reset_at = excluded.reset_at",
                        (name, count, reset_at),
                    )
                retry = max(
                    1,
                    min(
                        _MAX_RETRY_AFTER_SECONDS,
                        math.ceil(key_reset - now),
                    ),
                )
                row = conn.execute("SELECT COUNT(*) FROM rate_limit_buckets").fetchone()
                if row is not None and int(row[0]) > _MAX_TRACKED_BUCKETS:
                    conn.execute(
                        "DELETE FROM rate_limit_buckets WHERE reset_at <= ?",
                        (now,),
                    )
                return False, retry
            pending.append((key_name, key_count + 1, key_reset))
            for name, count, reset_at in pending:
                conn.execute(
                    "INSERT INTO rate_limit_buckets (name, count, reset_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET count = excluded.count, "
                    "reset_at = excluded.reset_at",
                    (name, count, reset_at),
                )
            row = conn.execute("SELECT COUNT(*) FROM rate_limit_buckets").fetchone()
            if row is not None and int(row[0]) > _MAX_TRACKED_BUCKETS:
                conn.execute(
                    "DELETE FROM rate_limit_buckets WHERE reset_at <= ?",
                    (now,),
                )
            return True, 0

    def _check(self, specs: list[tuple[str, int]]) -> tuple[bool, int]:
        with db_session(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            pending: list[tuple[str, int, float]] = []
            for name, limit in specs:
                row = conn.execute(
                    "SELECT count, reset_at FROM rate_limit_buckets WHERE name = ?",
                    (name,),
                ).fetchone()
                if row is None or now >= float(row["reset_at"]):
                    count, reset_at = 0, now + self._window_seconds
                else:
                    count, reset_at = int(row["count"]), float(row["reset_at"])
                if count >= limit:
                    retry = max(
                        1,
                        min(
                            _MAX_RETRY_AFTER_SECONDS,
                            math.ceil(reset_at - now),
                        ),
                    )
                    return False, retry
                pending.append((name, count + 1, reset_at))

            for name, count, reset_at in pending:
                conn.execute(
                    "INSERT INTO rate_limit_buckets (name, count, reset_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET count = excluded.count, "
                    "reset_at = excluded.reset_at",
                    (name, count, reset_at),
                )
            row = conn.execute("SELECT COUNT(*) FROM rate_limit_buckets").fetchone()
            if row is not None and int(row[0]) > _MAX_TRACKED_BUCKETS:
                conn.execute(
                    "DELETE FROM rate_limit_buckets WHERE reset_at <= ?",
                    (now,),
                )
            return True, 0

    def clear(self) -> None:
        """Réinitialise l'état partagé (tests isolés)."""
        with db_session(self._db_path) as conn:
            conn.execute(_SQLITE_TABLE_SQL)
            conn.execute("DELETE FROM rate_limit_buckets")
