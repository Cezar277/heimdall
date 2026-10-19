"""Rate-limiting débit du Vault (ticket #65).

Fenêtres fixes par clé API validée, par pair réseau et globale. Les 400 et 401
consomment le budget puisqu'ils traversent ce middleware avant le routage. Une
clé absente, invalide ou révoquée n'obtient pas de bucket arbitraire : seuls le
pair réseau et la limite globale s'appliquent. L'état est volontairement
mono-processus ; un déploiement multi-worker doit soit partager un backend
(Redis/SQLite dédié), soit accepter une limite par worker (documenté #65).
"""

import math
import time
from dataclasses import dataclass

_MAX_RETRY_AFTER_SECONDS: int = 3_600
_MAX_TRACKED_BUCKETS: int = 100_000


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
        now = time.monotonic()
        specs: list[tuple[str, int]] = [
            ("global", self._global_limit),
            (f"peer:{peer}", self._per_peer),
        ]
        if key_hash is not None:
            specs.append((f"key:{key_hash}", self._per_key))

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
