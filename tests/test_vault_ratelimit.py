"""Tests du ticket #111 — rate-limiting en fenêtre glissante.

Le ticket demande une fenêtre glissante par clé et par IP, un 429 avec
``Retry-After`` et une documentation de la limite mémoire (mono-processus).
Ces tests utilisent une horloge injectée pour être déterministes : ils
distinguent une vraie fenêtre glissante d'une fenêtre fixe (qui autoriserait
deux fois le budget à cheval sur deux fenêtres).

Preuves SAMM : module + ligne (voir ``docs/t111-samm.md``).
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from heimdall.vault import ratelimit as ratelimit_module
from heimdall.vault.database import db_session
from heimdall.vault.ratelimit import RateLimiter, SqliteRateLimiter


class SlidingWindowMemoryTests(unittest.TestCase):
    def test_budget_is_not_doubled_at_a_fixed_window_boundary(self) -> None:
        """Deux admissions à t=0/5 bloquent t=9, puis une seule passe à t=10.1."""
        now = [0.0]
        limiter = RateLimiter(
            per_key=2,
            per_peer=100,
            global_limit=100,
            window_seconds=10,
            clock=lambda: now[0],
        )
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        now[0] = 5.0
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        now[0] = 9.0
        allowed, retry = limiter.check("127.0.0.1", "key")
        self.assertFalse(allowed)
        self.assertEqual(retry, 1)
        # t=10.1 : l'admission de t=0 est sortie, celle de t=5 reste.
        now[0] = 10.1
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        now[0] = 10.2
        allowed, retry = limiter.check("127.0.0.1", "key")
        self.assertFalse(allowed)
        self.assertEqual(retry, 5)

    def test_peek_is_read_only_and_returns_the_exact_retry_after(self) -> None:
        """``peek`` ne consomme rien et annonce le délai exact de la plus ancienne."""
        now = [0.0]
        limiter = RateLimiter(
            per_key=100,
            per_peer=2,
            global_limit=100,
            window_seconds=10,
            clock=lambda: now[0],
        )
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        now[0] = 1.0
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        now[0] = 2.0
        allowed, retry = limiter.peek("127.0.0.1")
        self.assertFalse(allowed)
        self.assertEqual(retry, 8)
        # Le peek n'a pas consommé : le budget pair est toujours à 2, pas 3.
        self.assertEqual(limiter._buckets["peer:127.0.0.1"].count, 2)

    def test_peer_and_global_are_consumed_even_when_key_is_full(self) -> None:
        """La sémantique du middleware est conservée : pair/global comptent."""
        now = [0.0]
        limiter = RateLimiter(
            per_key=1,
            per_peer=3,
            global_limit=100,
            window_seconds=10,
            clock=lambda: now[0],
        )
        self.assertTrue(limiter.check_authenticated("127.0.0.1", "key")[0])
        now[0] = 1.0
        self.assertFalse(limiter.check_authenticated("127.0.0.1", "key")[0])
        now[0] = 2.0
        self.assertFalse(limiter.check_authenticated("127.0.0.1", "key")[0])
        self.assertEqual(limiter._buckets["peer:127.0.0.1"].count, 3)
        now[0] = 3.0
        allowed, retry = limiter.check_authenticated("127.0.0.1", "key")
        self.assertFalse(allowed)
        self.assertEqual(retry, 7)

    def test_clear_resets_every_budget(self) -> None:
        limiter = RateLimiter(
            per_key=1,
            per_peer=1,
            global_limit=1,
            window_seconds=10,
            clock=lambda: 0.0,
        )
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])
        self.assertFalse(limiter.check("127.0.0.1", "key")[0])
        limiter.clear()
        self.assertTrue(limiter.check("127.0.0.1", "key")[0])

    def test_rejected_distinct_key_hashes_do_not_create_buckets(self) -> None:
        """Un rejet global/pair ne laisse pas un bucket vide par hash évalué."""
        now = [0.0]
        limiter = RateLimiter(
            per_key=1,
            per_peer=1,
            global_limit=1,
            window_seconds=10,
            clock=lambda: now[0],
        )
        self.assertTrue(limiter.check_authenticated("127.0.0.1", "key-0")[0])
        initial = set(limiter._buckets)
        for index in range(1, 500):
            now[0] = index * 0.001
            allowed, retry = limiter.check_authenticated("127.0.0.1", f"key-{index}")
            self.assertFalse(allowed)
            self.assertTrue(1 <= retry <= 10)
        self.assertEqual(set(limiter._buckets), initial)

    def test_rejected_request_prunes_expired_buckets(self) -> None:
        """La purge des budgets expirés a aussi lieu sur le chemin de rejet."""
        now = [0.0]
        limiter = RateLimiter(
            per_key=1,
            per_peer=100,
            global_limit=1,
            window_seconds=10,
            clock=lambda: now[0],
        )
        with patch.object(ratelimit_module, "_MAX_TRACKED_BUCKETS", 100):
            for index in range(10):
                self.assertTrue(limiter.check_key(f"key-{index}")[0])
            now[0] = 20.0
            self.assertTrue(limiter.check_authenticated("127.0.0.1", "key-new")[0])
            self.assertGreater(len(limiter._buckets), 5)
        with patch.object(ratelimit_module, "_MAX_TRACKED_BUCKETS", 5):
            allowed, _retry = limiter.check_authenticated("127.0.0.1", "key-other")
        self.assertFalse(allowed)
        self.assertLessEqual(len(limiter._buckets), 3)


class SlidingWindowSqliteTests(unittest.TestCase):
    def test_sqlite_budget_is_not_doubled_at_a_fixed_window_boundary(self) -> None:
        """La fenêtre glissante est aussi exacte avec le backend partagé SQLite."""
        with tempfile.TemporaryDirectory() as tmp:
            now = [0.0]
            limiter = SqliteRateLimiter(
                Path(tmp) / "vault.db",
                per_key=2,
                per_peer=100,
                global_limit=100,
                window_seconds=10,
                clock=lambda: now[0],
            )
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            now[0] = 5.0
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            now[0] = 9.0
            allowed, retry = limiter.check("127.0.0.1", "key")
            self.assertFalse(allowed)
            self.assertEqual(retry, 1)
            now[0] = 10.1
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            now[0] = 10.2
            allowed, retry = limiter.check("127.0.0.1", "key")
            self.assertFalse(allowed)
            self.assertEqual(retry, 5)

    def test_sqlite_peek_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            now = [0.0]
            limiter = SqliteRateLimiter(
                Path(tmp) / "vault.db",
                per_key=100,
                per_peer=2,
                global_limit=100,
                window_seconds=10,
                clock=lambda: now[0],
            )
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            self.assertTrue(limiter.peek("127.0.0.1")[0])
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            allowed, retry = limiter.peek("127.0.0.1")
            self.assertFalse(allowed)
            self.assertEqual(retry, 10)

    def test_sqlite_peer_and_global_are_consumed_on_key_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            now = [0.0]
            limiter = SqliteRateLimiter(
                Path(tmp) / "vault.db",
                per_key=1,
                per_peer=3,
                global_limit=100,
                window_seconds=10,
                clock=lambda: now[0],
            )
            self.assertTrue(limiter.check_authenticated("127.0.0.1", "key")[0])
            now[0] = 1.0
            self.assertFalse(limiter.check_authenticated("127.0.0.1", "key")[0])
            now[0] = 2.0
            self.assertFalse(limiter.check_authenticated("127.0.0.1", "key")[0])
            now[0] = 3.0
            allowed, retry = limiter.check_authenticated("127.0.0.1", "key")
            self.assertFalse(allowed)
            self.assertEqual(retry, 7)

    def test_sqlite_rejected_flood_from_distinct_peers_keeps_table_bounded(self) -> None:
        """Un flot de rejets de pairs neufs ne fait pas croître la table sans borne."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            now = [0.0]
            limiter = SqliteRateLimiter(
                db_path,
                per_key=1,
                per_peer=3,
                global_limit=5,
                window_seconds=10,
                clock=lambda: now[0],
            )
            self.assertTrue(limiter.check("10.0.0.0", "key")[0])
            rejected = 0
            for index in range(1, 2000):
                now[0] = index * 0.5
                allowed, retry = limiter.check(f"10.0.{index // 250}.{index % 250}", "key")
                if not allowed:
                    rejected += 1
                    self.assertTrue(1 <= retry <= 10)
            self.assertGreater(rejected, 1500)
            with db_session(db_path) as conn:
                rows = conn.execute("SELECT COUNT(*) FROM rate_limit_hits").fetchone()[0]
            self.assertLessEqual(rows, 40)

    def test_sqlite_clear_resets_every_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            limiter = SqliteRateLimiter(
                Path(tmp) / "vault.db",
                per_key=1,
                per_peer=1,
                global_limit=1,
                window_seconds=10,
                clock=lambda: 0.0,
            )
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
            self.assertFalse(limiter.check("127.0.0.1", "key")[0])
            limiter.clear()
            self.assertTrue(limiter.check("127.0.0.1", "key")[0])
