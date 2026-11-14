"""Tests du ticket #113 — journal d'audit du Vault.

Couvre les exigences du sous-ticket :

- un événement par accès, refus 401/403 et limitations 429 compris ;
- aucun secret, aucune clé API complète et aucun corps de requête dans le
  journal ;
- chaînage par hash et détection d'altération ;
- fail-closed si l'écriture d'audit échoue ;
- consultation et vérification par la CLI ``heimdall vault audit`` ;
- backend SQLite partagé entre workers et backend mémoire pour les tests.

Preuves SAMM : module + ligne (voir ``docs/t113-samm.md``).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from heimdall.cli.main import app as cli_app
from heimdall.vault import audit as audit_module
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.audit import SqliteAuditLog
from heimdall.vault.crypto import generate_api_key, generate_encryption_key
from heimdall.vault.database import DatabaseUnavailableError, db_session, init_db

PEPPER = "t113_pepper_value_0123456789abcdef"
CANARY_VALUE = "canary-secret-value-t113-never-in-audit"


def _memory_app(**settings: object):
    """Application mémoire isolée (journal d'audit en mémoire)."""
    return create_app(VaultSettings(api_key_pepper=PEPPER, **settings))


def _sqlite_app(tmp: str, name: str = "vault.db", **settings: object):
    """Application SQLite isolée (journal d'audit persistant)."""
    db_path = Path(tmp) / name
    return create_app(
        VaultSettings(
            db_path=str(db_path),
            storage_backend="sqlite",
            kek=generate_encryption_key(),
            api_key_pepper=PEPPER,
            **settings,
        )
    )


def _client(app):
    return AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 54321)),
        base_url="http://127.0.0.1:8443",
    )


class AuditTrailTests(unittest.IsolatedAsyncioTestCase):
    async def test_list_is_audited_with_its_requested_project_target(self) -> None:
        """GET /secrets?project= : la cible est le projet demandé, même en 401."""
        app = _memory_app()
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            allowed = await client.get(
                "/api/v1/secrets",
                params={"project": "demo"},
                headers={"X-Heimdall-API-Key": key},
            )
            forbidden = await client.get(
                "/api/v1/secrets",
                params={"project": "other"},
                headers={"X-Heimdall-API-Key": key},
            )
            anonymous = await client.get("/api/v1/secrets", params={"project": "demo"})
            anonymous_invalid = await client.get(
                "/api/v1/secrets", params={"project": "INVALID!"}
            )
        self.assertEqual(
            [
                allowed.status_code,
                forbidden.status_code,
                anonymous.status_code,
                anonymous_invalid.status_code,
            ],
            [200, 403, 401, 401],
        )
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual(
            [(event["status_code"], event["target"]) for event in events],
            [(200, "demo"), (403, "other"), (401, "demo"), (401, None)],
        )
        self.assertNotIn(key, json.dumps(events))
        self.assertNotIn("INVALID!", json.dumps(events))

    async def test_success_and_auth_rejections_are_audited(self) -> None:
        """Chaque accès produit un événement : 200, 404, 403 et 401 compris."""
        app = _memory_app()
        key = generate_api_key()
        key_id = app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            health = await client.get("/api/v1/health")
            allowed = await client.get(
                "/api/v1/secrets/demo/dev/TOKEN",
                headers={"X-Heimdall-API-Key": key},
            )
            forbidden = await client.get(
                "/api/v1/secrets/other/dev/TOKEN",
                headers={"X-Heimdall-API-Key": key},
            )
            missing = await client.get("/api/v1/secrets/demo/dev/TOKEN")
            unknown = await client.get(
                "/api/v1/secrets/demo/dev/TOKEN",
                headers={"X-Heimdall-API-Key": "unknown-key-value"},
            )

        self.assertEqual(
            [health.status_code, allowed.status_code, forbidden.status_code, missing.status_code,
             unknown.status_code],
            [200, 404, 403, 401, 401],
        )
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual([event["status_code"] for event in events], [200, 404, 403, 401, 401])
        self.assertEqual(events[0]["outcome"], "allowed")
        self.assertEqual(events[2]["outcome"], "forbidden")
        self.assertEqual(events[2]["project"], "demo")
        self.assertEqual(events[1]["key_id"], key_id)
        self.assertEqual(events[2]["key_id"], key_id)
        self.assertEqual(events[3]["outcome"], "unauthenticated")
        self.assertIsNone(events[3]["key_fingerprint"])
        self.assertIsNotNone(events[4]["key_fingerprint"])
        self.assertIsNone(events[4]["key_id"])
        self.assertNotIn(key, json.dumps(events))
        self.assertNotIn("unknown-key-value", json.dumps(events))

    async def test_health_with_key_is_correlated_without_consuming_key_budget(self) -> None:
        """Health reste public : la clé est corrélée dans l'audit, pas consommée."""
        app = _memory_app(
            rate_limit_per_key=1,
            rate_limit_per_peer=100,
            rate_limit_global=100,
        )
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            health = await client.get(
                "/api/v1/health", headers={"X-Heimdall-API-Key": key}
            )
            read = await client.get(
                "/api/v1/secrets/demo/dev/TOKEN",
                headers={"X-Heimdall-API-Key": key},
            )
        self.assertEqual(health.status_code, 200)
        self.assertEqual(read.status_code, 404)
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual([event["status_code"] for event in events], [200, 404])
        self.assertIsNotNone(events[0]["key_fingerprint"])
        self.assertEqual(len(events[0]["key_fingerprint"]), 16)
        self.assertNotIn(key, json.dumps(events))

    async def test_rate_limited_requests_are_audited(self) -> None:
        """Un 429 de débit est journalisé avec l'outcome ``rate_limited``."""
        app = _memory_app(
            rate_limit_per_key=1,
            rate_limit_per_peer=100,
            rate_limit_global=100,
        )
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            first = await client.get(
                "/api/v1/secrets/demo/dev/TOKEN",
                headers={"X-Heimdall-API-Key": key},
            )
            limited = await client.get(
                "/api/v1/secrets/demo/dev/TOKEN",
                headers={"X-Heimdall-API-Key": key},
            )
        self.assertEqual(first.status_code, 404)
        self.assertEqual(limited.status_code, 429)
        retry_after = int(limited.headers["Retry-After"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 3600)
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual([event["status_code"] for event in events], [404, 429])
        self.assertEqual(events[1]["outcome"], "rate_limited")

    async def test_audit_never_contains_a_secret_value_or_raw_key(self) -> None:
        """Le corps POST et la clé brute ne sont jamais persistés dans l'audit."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _sqlite_app(tmp)
            key = generate_api_key()
            app.state.register_api_key(key, "demo")
            async with _client(app) as client:
                created = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "AUDITED_TOKEN",
                        "value": CANARY_VALUE,
                    },
                    headers={"X-Heimdall-API-Key": key},
                )
                self.assertEqual(created.status_code, 201, created.text)
                read = await client.get(
                    "/api/v1/secrets/demo/dev/AUDITED_TOKEN",
                    headers={"X-Heimdall-API-Key": key},
                )
                self.assertEqual(read.status_code, 200, read.text)
            serialized = json.dumps(app.state.audit_log.list_events(limit=100))
        self.assertNotIn(CANARY_VALUE, serialized)
        self.assertNotIn(key, serialized)
        self.assertIn("AUDITED_TOKEN", serialized)

    async def test_sqlite_chain_detects_tampering(self) -> None:
        """Modifier une ligne casse la chaîne et localise l'événement altéré."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            app = _sqlite_app(tmp)
            async with _client(app) as client:
                for _ in range(3):
                    self.assertEqual((await client.get("/api/v1/health")).status_code, 200)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))
            with db_session(db_path) as conn:
                conn.execute("UPDATE audit_events SET status_code = 500 WHERE id = 2")
            self.assertEqual(app.state.audit_log.verify_chain(), (False, 2))

    async def test_audit_failure_is_fail_closed(self) -> None:
        """Si l'audit échoue, l'accès n'est pas servi : 503 générique."""
        app = _memory_app()

        async def failing_record(**kwargs: object) -> None:
            raise RuntimeError("journal indisponible")

        with patch.object(app.state.audit_log, "record", failing_record):
            async with _client(app) as client:
                response = await client.get("/api/v1/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"code": "unavailable", "message": "Service indisponible"},
        )
        self.assertEqual(response.headers["Retry-After"], "1")
        self.assertEqual(response.headers["Connection"], "close")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    async def test_audit_database_unavailable_is_503_not_500(self) -> None:
        """Une panne SQLite du journal est un 503 contractuel, jamais un 500."""
        app = _memory_app()

        async def failing_record(**kwargs: object) -> None:
            raise DatabaseUnavailableError("stockage indisponible")

        with patch.object(app.state.audit_log, "record", failing_record):
            async with _client(app) as client:
                response = await client.get("/api/v1/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"code": "unavailable", "message": "Service indisponible"},
        )
        self.assertEqual(response.headers["Retry-After"], "1")

    async def test_inner_database_unavailable_is_503_not_500(self) -> None:
        """Une panne du rate-limiter est traduite en 503 par la couche disponibilité."""
        app = _memory_app()

        def failing_peek(peer: str) -> tuple[bool, int]:
            raise DatabaseUnavailableError("stockage indisponible")

        with patch.object(app.state.rate_limiter, "peek", failing_peek):
            async with _client(app) as client:
                response = await client.get("/api/v1/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"code": "unavailable", "message": "Service indisponible"},
        )
        events = app.state.audit_log.list_events(limit=1)
        self.assertEqual(events[0]["status_code"], 503)

    async def test_sqlite_audit_log_is_shared_between_workers(self) -> None:
        """Deux instances sur la même base partagent le journal et sa chaîne."""
        with tempfile.TemporaryDirectory() as tmp:
            first = _sqlite_app(tmp, name="shared.db")
            second = _sqlite_app(tmp, name="shared.db")
            async with _client(first) as client:
                self.assertEqual((await client.get("/api/v1/health")).status_code, 200)
            async with _client(second) as client:
                self.assertEqual((await client.get("/api/v1/health")).status_code, 200)
            events = first.state.audit_log.list_events(limit=10)
            self.assertEqual(len(events), 2)
            self.assertEqual(first.state.audit_log.verify_chain(), (True, None))

    async def test_audit_sanitizes_control_characters(self) -> None:
        """Les retours à la ligne et contrôles ne peuvent pas injecter de lignes."""
        app = _memory_app()
        await app.state.audit_log.record(
            peer="127.0.0.1\nINJECTED",
            action="GET /x\r\nINJECTED",
            target="a\nb",
            status_code=200,
            key_fingerprint_value="0123456789abcdef",
            key_id="key_0123456789abcdef0123456789abcdef\nINJECTED",
            project="p\r\nq",
        )
        event = app.state.audit_log.list_events(limit=1)[0]
        for field in ("peer", "action", "target", "project", "key_id"):
            value = event[field]
            if value is not None:
                self.assertNotIn("\n", value)
                self.assertNotIn("\r", value)
        self.assertEqual(event["key_fingerprint"], "0123456789abcdef")
        self.assertEqual(event["key_id"], "key_0123456789abcdef0123456789abcdef")

    async def test_list_events_filters_and_bounds(self) -> None:
        """Le listage borne le nombre d'événements et filtre par projet."""
        app = _memory_app()
        for index in range(5):
            await app.state.audit_log.record(
                peer="127.0.0.1",
                action=f"GET /{index}",
                target=None,
                status_code=200,
                project="demo" if index % 2 == 0 else "other",
            )
        self.assertEqual(len(app.state.audit_log.list_events(limit=2)), 2)
        demo = app.state.audit_log.list_events(limit=10, project="demo")
        self.assertEqual([event["action"] for event in demo], ["GET /0", "GET /2", "GET /4"])

    async def test_list_events_limit_is_bounded_like_sqlite(self) -> None:
        """Mémoire : >MAX_LIST_LIMIT borné, <=0 normalisé à 1 (parité SQLite)."""
        app = _memory_app()
        for index in range(audit_module.MAX_LIST_LIMIT + 5):
            await app.state.audit_log.record(
                peer="127.0.0.1",
                action=f"GET /{index}",
                target=None,
                status_code=200,
            )
        events = app.state.audit_log.list_events(limit=100_000)
        self.assertEqual(len(events), audit_module.MAX_LIST_LIMIT)
        self.assertEqual(events[-1]["action"], f"GET /{audit_module.MAX_LIST_LIMIT + 4}")
        for limit in (0, -5):
            with self.subTest(limit=limit):
                bounded = app.state.audit_log.list_events(limit=limit)
                self.assertEqual(len(bounded), 1)
                self.assertEqual(bounded[0]["action"], f"GET /{audit_module.MAX_LIST_LIMIT + 4}")

    async def test_list_events_limit_parity_between_memory_and_sqlite(self) -> None:
        """Le bornage mémoire et SQLite reste identique, y compris aux extrêmes."""
        with tempfile.TemporaryDirectory() as tmp:
            memory = _memory_app()
            sqlite = _sqlite_app(tmp)
            for index in range(5):
                for app in (memory, sqlite):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /{index}",
                        target=None,
                        status_code=200,
                    )
            with patch.object(audit_module, "MAX_LIST_LIMIT", 3):
                for limit in (100, 3, 1, 0, -2):
                    with self.subTest(limit=limit):
                        memory_events = memory.state.audit_log.list_events(limit=limit)
                        sqlite_events = sqlite.state.audit_log.list_events(limit=limit)
                        self.assertEqual(
                            [event["action"] for event in memory_events],
                            [event["action"] for event in sqlite_events],
                        )
                        self.assertLessEqual(len(memory_events), 3)


class AuditRetentionTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_retention_bounds_growth_and_preserves_chain(self) -> None:
        """Au-delà du seuil, les plus anciens événements sont purgés, chaîne valide."""
        app = _memory_app()
        with patch.object(audit_module, "MAX_AUDIT_EVENTS", 5):
            for index in range(8):
                await app.state.audit_log.record(
                    peer="127.0.0.1",
                    action=f"GET /{index}",
                    target=None,
                    status_code=200,
                )
        events = app.state.audit_log.list_events(limit=100)
        self.assertEqual([event["action"] for event in events], [f"GET /{i}" for i in range(3, 8)])
        self.assertEqual(app.state.audit_log.pruned_count(), 3)
        self.assertEqual(app.state.audit_log.verify_chain(), (True, None))
        self.assertNotEqual(events[0]["previous_hash"], audit_module.GENESIS_HASH)

    async def test_memory_ids_stay_unique_and_monotonic_after_prune(self) -> None:
        """Après purge, les nouveaux ids ne réutilisent jamais un id déjà attribué."""
        app = _memory_app()
        with patch.object(audit_module, "MAX_AUDIT_EVENTS", 5):
            for index in range(8):
                await app.state.audit_log.record(
                    peer="127.0.0.1",
                    action=f"GET /{index}",
                    target=None,
                    status_code=200,
                )
        ids = [event["id"] for event in app.state.audit_log.list_events(limit=100)]
        self.assertEqual(ids, [4, 5, 6, 7, 8])
        self.assertEqual(app.state.audit_log.verify_chain(), (True, None))

    async def test_sqlite_retention_bounds_growth_and_preserves_chain(self) -> None:
        """La purge SQLite avance un point de contrôle et garde la chaîne vérifiable."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            app = _sqlite_app(tmp)
            with patch.object(audit_module, "MAX_AUDIT_EVENTS", 5):
                for index in range(8):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /{index}",
                        target=None,
                        status_code=200,
                    )
            events = app.state.audit_log.list_events(limit=100)
            self.assertEqual(
                [event["action"] for event in events],
                [f"GET /{i}" for i in range(3, 8)],
            )
            self.assertEqual(app.state.audit_log.count(), 5)
            self.assertEqual(app.state.audit_log.pruned_count(), 3)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))
            self.assertNotEqual(events[0]["previous_hash"], audit_module.GENESIS_HASH)
            with db_session(db_path) as conn:
                conn.execute("UPDATE audit_events SET status_code = 500 WHERE id = 5")
            self.assertEqual(app.state.audit_log.verify_chain(), (False, 5))

    async def test_sqlite_prune_handles_large_excess_in_batches(self) -> None:
        """Une purge avec ``excess >> 1`` reste bornée et préserve la chaîne."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _sqlite_app(tmp)
            with patch.object(audit_module, "MAX_AUDIT_EVENTS", 1_000):
                for index in range(50):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /{index}",
                        target=None,
                        status_code=200,
                    )
            with (
                patch.object(audit_module, "MAX_AUDIT_EVENTS", 5),
                patch.object(audit_module, "_PRUNE_BATCH_SIZE", 7),
            ):
                await app.state.audit_log.record(
                    peer="127.0.0.1",
                    action="GET /final",
                    target=None,
                    status_code=200,
                )
            self.assertEqual(app.state.audit_log.count(), 5)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))

    async def test_sqlite_tampering_first_retained_row_is_located_after_prune(self) -> None:
        """Après purge, le premier événement retenu est ancré au point de contrôle."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            app = _sqlite_app(tmp)
            with patch.object(audit_module, "MAX_AUDIT_EVENTS", 5):
                for index in range(8):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /{index}",
                        target=None,
                        status_code=200,
                    )
            with db_session(db_path) as conn:
                checkpoint = conn.execute(
                    "SELECT checkpoint_hash, pruned_events FROM audit_chain_state WHERE id = 1"
                ).fetchone()
                first_retained = conn.execute(
                    "SELECT id FROM audit_events ORDER BY id ASC LIMIT 1"
                ).fetchone()
            self.assertEqual(int(checkpoint["pruned_events"]), 3)
            self.assertNotEqual(checkpoint["checkpoint_hash"], audit_module.GENESIS_HASH)
            self.assertEqual(first_retained["id"], 4)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE audit_events SET previous_hash = ? WHERE id = 4",
                    (audit_module.GENESIS_HASH,),
                )
            self.assertEqual(app.state.audit_log.verify_chain(), (False, 4))

    async def test_rejection_flood_does_not_prune_authenticated_events(self) -> None:
        """Audit M-03 : les 401/429 ont leur rétention et ne purgent pas les accès."""
        app = _memory_app()
        with (
            patch.object(audit_module, "MAX_AUDIT_EVENTS", 2),
            patch.object(audit_module, "MAX_REJECTION_EVENTS", 2),
        ):
            for index in range(2):
                await app.state.audit_log.record(
                    peer="127.0.0.1",
                    action=f"GET /auth/{index}",
                    target=None,
                    status_code=200,
                )
            for index in range(10):
                await app.state.audit_log.record(
                    peer="127.0.0.1",
                    action=f"GET /rejection/{index}",
                    target=None,
                    status_code=401,
                )
        actions = [event["action"] for event in app.state.audit_log.list_events(limit=100)]
        self.assertIn("GET /auth/0", actions)
        self.assertIn("GET /auth/1", actions)
        self.assertNotIn("GET /rejection/0", actions)
        self.assertEqual(app.state.audit_log.verify_chain(), (True, None))

    async def test_sqlite_rejection_flood_does_not_prune_authenticated_events(self) -> None:
        """Même séparation de rétention sur le backend SQLite."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _sqlite_app(tmp)
            with (
                patch.object(audit_module, "MAX_AUDIT_EVENTS", 2),
                patch.object(audit_module, "MAX_REJECTION_EVENTS", 2),
            ):
                for index in range(2):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /auth/{index}",
                        target=None,
                        status_code=200,
                    )
                for index in range(10):
                    await app.state.audit_log.record(
                        peer="127.0.0.1",
                        action=f"GET /rejection/{index}",
                        target=None,
                        status_code=401,
                    )
            actions = [
                event["action"] for event in app.state.audit_log.list_events(limit=100)
            ]
            self.assertIn("GET /auth/0", actions)
            self.assertIn("GET /auth/1", actions)
            self.assertNotIn("GET /rejection/0", actions)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))

    async def test_sqlite_chain_is_hmac_keyed(self) -> None:
        """Audit F-16 : une autre clé HMAC invalide la vérification de chaîne."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            app = _sqlite_app(tmp)
            await app.state.audit_log.record(
                peer="127.0.0.1",
                action="GET /auth",
                target=None,
                status_code=200,
            )
            other = SqliteAuditLog(
                db_path, create=False, hmac_key=b"x" * 32
            )
            self.assertEqual(other.verify_chain(), (False, 1))

    def test_init_db_recreates_audit_tables_on_pre_t39_database(self) -> None:
        """Une base antérieure à #39 reçoit les tables de débit, d'audit et d'état."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                conn.execute("DROP TABLE audit_chain_state")
                conn.execute("DROP TABLE audit_events")
                conn.execute("DROP TABLE rate_limit_hits")
            init_db(db_path)
            with db_session(db_path) as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
        self.assertTrue(
            {"rate_limit_hits", "audit_events", "audit_chain_state"}.issubset(tables)
        )


class AuditCliTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "vault.db"
        self.app = _sqlite_app(self._tmp.name)
        self.key = generate_api_key()
        self.app.state.register_api_key(self.key, "demo")
        async with _client(self.app) as client:
            self.assertEqual((await client.get("/api/v1/health")).status_code, 200)
            self.assertEqual(
                (
                    await client.get(
                        "/api/v1/secrets/demo/dev/TOKEN",
                        headers={"X-Heimdall-API-Key": self.key},
                    )
                ).status_code,
                404,
            )
            self.assertEqual(
                (await client.get("/api/v1/secrets/demo/dev/TOKEN")).status_code,
                401,
            )
        self.runner = CliRunner()

    async def asyncTearDown(self) -> None:
        self._tmp.cleanup()

    def test_list_displays_events_without_secret_or_raw_key(self) -> None:
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "list", "--db-path", str(self.db_path), "--limit", "10"],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("allowed", result.output)
        self.assertIn("unauthenticated", result.output)
        self.assertIn("cle_id=key_", result.output)
        self.assertNotIn(self.key, result.output)

    def test_list_json_is_machine_readable(self) -> None:
        result = self.runner.invoke(
            cli_app,
            [
                "vault",
                "audit",
                "list",
                "--db-path",
                str(self.db_path),
                "--json",
            ],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        events = json.loads(result.output)
        self.assertEqual([event["status_code"] for event in events], [200, 404, 401])
        self.assertNotIn(self.key, result.output)

    def test_verify_reports_a_valid_chain(self) -> None:
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "verify", "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("valide", result.output)

    def test_verify_without_resolvable_key_exits_2_explicitly(self) -> None:
        """Sans clé d'audit résolvable : code 2 explicite, jamais « chaîne invalide »."""
        env = {
            "HEIMDALL_VAULT_AUDIT_HMAC_KEY": None,
            "HEIMDALL_VAULT_KEK": None,
            "HEIMDALL_VAULT_MASTER_KEY": None,
            "HEIMDALL_VAULT_KEK_SALT": None,
        }
        for command in ("verify", "list"):
            with self.subTest(command=command):
                result = self.runner.invoke(
                    cli_app,
                    ["vault", "audit", command, "--db-path", str(self.db_path)],
                    env=env,
                )
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("clé HMAC d'audit indisponible", result.output)
                self.assertNotIn("invalide", result.output.replace("indisponible", ""))

    def test_verify_reports_tampering(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("UPDATE audit_events SET status_code = 500 WHERE id = 1")
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "verify", "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("invalide", result.output)

    def test_missing_database_fails_without_creating_it(self) -> None:
        missing = Path(self._tmp.name) / "absent.db"
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "list", "--db-path", str(missing)],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("introuvable", result.output)
        self.assertFalse(missing.exists())

    def test_verify_on_deleted_database_fails_without_creating_it(self) -> None:
        missing = Path(self._tmp.name) / "absent.db"
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "verify", "--db-path", str(missing)],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("introuvable", result.output)
        self.assertFalse(missing.exists())

    def test_verify_on_corrupt_database_fails_generically(self) -> None:
        corrupt = Path(self._tmp.name) / "corrupt.db"
        corrupt.write_bytes(b"corrupt-audit-canary" * 50)
        result = self.runner.invoke(
            cli_app,
            ["vault", "audit", "verify", "--db-path", str(corrupt)],
        )
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("échec de la vérification", result.output)
        self.assertNotIn("corrupt-audit-canary", result.output)
        self.assertNotIn(str(corrupt), result.output)
        self.assertNotIn("sqlite", result.output.lower())
        self.assertNotIn(self.key, result.output)

    def test_invalid_project_filter_is_a_usage_error(self) -> None:
        result = self.runner.invoke(
            cli_app,
            [
                "vault",
                "audit",
                "list",
                "--db-path",
                str(self.db_path),
                "--project",
                "INVALID!",
            ],
        )
        self.assertEqual(result.exit_code, 2)
