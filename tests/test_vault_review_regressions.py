"""Régressions de la revue #63 : admission, SQLite async et empreintes uniques."""

import ast
import asyncio
import os
import secrets
import site
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

import heimdall.vault.app as app_module
import heimdall.vault.auth as auth_module
import heimdall.vault.ratelimit as ratelimit_module
import heimdall.vault.store as store_module
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import (
    VaultCipher,
    generate_api_key,
    generate_encryption_key,
    hash_api_key,
)
from heimdall.vault.database import (
    DatabaseUnavailableError,
    count_secrets,
    create_api_key,
    db_session,
    ensure_project,
    init_db,
)
from heimdall.vault.ratelimit import RateLimiter
from heimdall.vault.store import InMemorySecretStore, QuotaExceededError, SqliteSecretStore


class VaultReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_sqlite_sessions_leave_event_loop_available(self) -> None:
        """Chaque chemin DB laisse un GET concurrent finir avant de libérer l'I/O."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, VaultCipher.generate())
            settings = VaultSettings(
                db_path=str(db_path),
                storage_backend="sqlite",
                kek=generate_encryption_key(),
                api_key_pepper="p" * 32,
            )
            target = create_app(settings, secret_store=store)
            key = generate_api_key()
            target.state.register_api_key(key, "demo")
            health_app = create_app(VaultSettings(api_key_pepper="h" * 32))
            transport = ASGITransport(app=health_app, client=("127.0.0.1", 54321))
            operations = (
                (store_module, lambda: store.get("demo", "dev", "TOKEN"), 1),
                (store_module, lambda: store.create("demo", "dev", "TOKEN", "value"), 1),
                (store_module, store.clear, 1),
                (auth_module, lambda: self._authenticated_get(target, key), 1),
                (ratelimit_module, lambda: self._authenticated_get(target, key), 1),
            )
            async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                for module, operation, blocked_call in operations:
                    with self.subTest(module=module.__name__, operation=operation):
                        started, release, timed_out = (
                            threading.Event(),
                            threading.Event(),
                            threading.Event(),
                        )

                        calls = [0]

                        @contextmanager
                        def slow_session(
                            path: Path | str,
                            state=(started, release, timed_out, calls, blocked_call),
                        ) -> Iterator[sqlite3.Connection]:
                            started, release, timed_out, calls, blocked_call = state
                            calls[0] += 1
                            if calls[0] == blocked_call:
                                started.set()
                                if not release.wait(timeout=2):
                                    timed_out.set()
                            with db_session(path) as conn:
                                yield conn

                        with patch.object(module, "db_session", slow_session):
                            task = asyncio.create_task(operation())
                            try:

                                async def wait_started(started=started) -> None:
                                    while not started.is_set():
                                        await asyncio.sleep(0.001)

                                await asyncio.wait_for(wait_started(), timeout=3)
                                response = await client.get("/api/v1/health")
                                self.assertEqual(response.status_code, 200)
                                self.assertFalse(
                                    timed_out.is_set(), "La boucle a bloqué sur SQLite"
                                )
                                self.assertFalse(task.done())
                            finally:
                                release.set()
                                await task

    async def _authenticated_get(self, target, key):
        transport = ASGITransport(app=target, client=("127.0.0.1", 54321))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            return await client.get(
                "/api/v1/secrets/demo/dev/TOKEN", headers={"X-Heimdall-API-Key": key}
            )

    async def test_global_rejection_precedes_hash_and_lookup(self) -> None:
        """Le budget global authentifié est contrôlé avant HMAC et parcours d'empreintes."""
        with tempfile.TemporaryDirectory():
            for backend in ("memory", "sqlite"):
                with self.subTest(backend=backend):
                    with tempfile.TemporaryDirectory() as tmp2:
                        settings = VaultSettings(
                            db_path=str(Path(tmp2) / f"{backend}.db"),
                            storage_backend=backend,
                            kek=generate_encryption_key(),
                            api_key_pepper="p" * 32,
                            rate_limit_per_key=100,
                            rate_limit_global=1,
                        )
                        target = create_app(settings)
                        key = generate_api_key()
                        target.state.register_api_key(key, "demo")
                        first = await self._authenticated_get(target, key)
                        self.assertEqual(first.status_code, 404)
                        with (
                            patch.object(auth_module, "hash_project_api_key") as hashing,
                            patch.object(auth_module, "find_api_key_project") as lookup,
                        ):
                            second = await self._authenticated_get(target, key)
                            self.assertEqual(second.status_code, 429)
                            self.assertIn("Retry-After", second.headers)
                            hashing.assert_not_called()
                            lookup.assert_not_called()

    async def test_auth_peer_rejection_precedes_hash_and_lookup(self) -> None:
        """Le budget auth_peer est contrôlé avant HMAC et parcours d'empreintes."""
        for backend in ("memory", "sqlite"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
                target = create_app(
                    VaultSettings(
                        db_path=str(Path(tmp) / f"{backend}.db"),
                        storage_backend=backend,
                        kek=generate_encryption_key(),
                        api_key_pepper="p" * 32,
                        rate_limit_per_key=100,
                        rate_limit_per_peer=1,
                        rate_limit_global=100,
                    )
                )
                first_key, second_key = generate_api_key(), generate_api_key()
                target.state.register_api_key(first_key, "demo")
                target.state.register_api_key(second_key, "demo")
                first = await self._authenticated_get(target, first_key)
                self.assertEqual(first.status_code, 404)
                with (
                    patch.object(auth_module, "hash_project_api_key") as hashing,
                    patch.object(auth_module, "find_api_key_project") as lookup,
                ):
                    second = await self._authenticated_get(target, second_key)
                    self.assertEqual(second.status_code, 429)
                    hashing.assert_not_called()
                    lookup.assert_not_called()

    async def test_key_rejection_does_not_consume_global_and_anonymous_has_own_budget(
        self,
    ) -> None:
        """Une clé pleine ne consomme pas le global ; les anonymes ont leur budget."""
        with tempfile.TemporaryDirectory() as tmp:
            for backend in ("memory", "sqlite"):
                with self.subTest(backend=backend):
                    target = create_app(
                        VaultSettings(
                            db_path=str(Path(tmp) / f"{backend}.db"),
                            storage_backend=backend,
                            kek=generate_encryption_key(),
                            api_key_pepper="p" * 32,
                            rate_limit_per_key=1,
                            rate_limit_per_peer=2,
                            rate_limit_global=100,
                        )
                    )
                    key = generate_api_key()
                    target.state.register_api_key(key, "demo")
                    self.assertEqual((await self._authenticated_get(target, key)).status_code, 404)
                    self.assertEqual((await self._authenticated_get(target, key)).status_code, 429)
                    self.assertEqual(
                        (await self._authenticated_get(target, "unknown")).status_code, 401
                    )
                    self.assertEqual(
                        (await self._authenticated_get(target, "unknown")).status_code, 401
                    )
                    self.assertEqual(
                        (await self._authenticated_get(target, "unknown")).status_code, 429
                    )

    async def test_concurrent_persistence_keeps_one_hash_and_preserves_revocation(self) -> None:
        """Des insertions concurrentes sont idempotentes et ne réactivent pas la clé."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            target = create_app(
                VaultSettings(
                    db_path=str(db_path),
                    storage_backend="sqlite",
                    kek=generate_encryption_key(),
                    api_key_pepper="p" * 32,
                )
            )
            fingerprint = hash_api_key(generate_api_key(), pepper="p" * 32)
            registry = target.state.api_key_registry
            await asyncio.gather(
                *(
                    asyncio.to_thread(registry.register_hash, fingerprint, "demo")
                    for _ in range(5)
                )
            )
            with db_session(db_path) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0], 1)
                conn.execute("UPDATE api_keys SET revoked_at = '2026-01-01'")
            with self.assertRaisesRegex(ValueError, "déjà associée"):
                registry.register_hash(fingerprint, "other")
            with db_session(db_path) as conn:
                row = conn.execute("SELECT project_id, revoked_at FROM api_keys").fetchone()
                self.assertEqual(tuple(row), ("demo", "2026-01-01"))

    async def test_existing_schema_gets_unique_hash_index(self) -> None:
        """Une base antérieure reçoit l'index UNIQUE à la réinitialisation."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                conn.execute("DROP INDEX uq_api_keys_key_hash")
                conn.execute("CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash)")
            init_db(db_path)
            with db_session(db_path) as conn:
                indexes = conn.execute("PRAGMA index_list(api_keys)").fetchall()
                self.assertTrue(any(row[1] == "uq_api_keys_key_hash" and row[2] for row in indexes))

    async def test_existing_duplicate_hashes_fail_closed(self) -> None:
        """Une ancienne base ambiguë n'est ni acceptée ni dédupliquée silencieusement."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                conn.execute("DROP INDEX uq_api_keys_key_hash")
                ensure_project(conn, "demo")
                create_api_key(conn, "first", "demo", "duplicate-hash")
                create_api_key(conn, "second", "demo", "duplicate-hash")
            with self.assertRaises(sqlite3.IntegrityError):
                init_db(db_path)
            with db_session(db_path) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0], 2)

    async def test_sqlite_revocation_deletion_and_failure_override_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = create_app(
                VaultSettings(
                    db_path=str(Path(tmp) / "vault.db"),
                    storage_backend="sqlite",
                    kek=generate_encryption_key(),
                    api_key_pepper="p" * 32,
                )
            )
            key = generate_api_key()
            target.state.register_api_key(key, "demo")
            fingerprint = hash_api_key(key, pepper="p" * 32)
            with patch.object(
                auth_module, "lookup_db_api_key", wraps=auth_module.lookup_db_api_key
            ) as lookup:
                self.assertEqual((await self._authenticated_get(target, key)).status_code, 404)
                self.assertEqual(lookup.call_count, 1)
                self.assertEqual(
                    (await self._authenticated_get(target, "unknown")).status_code, 401
                )
                self.assertEqual(lookup.call_count, 2)
            with db_session(target.state.db_path) as conn:
                conn.execute("UPDATE api_keys SET revoked_at = ?", ("2026-01-01",))
            self.assertIn(fingerprint, target.state.api_keys)
            self.assertEqual((await self._authenticated_get(target, key)).status_code, 401)
            target.state.register_api_key(key, "demo")
            self.assertEqual((await self._authenticated_get(target, key)).status_code, 401)
            with db_session(target.state.db_path) as conn:
                conn.execute("DELETE FROM api_keys")
            self.assertEqual((await self._authenticated_get(target, key)).status_code, 401)
            with patch.object(
                auth_module, "db_session", side_effect=DatabaseUnavailableError
            ):
                self.assertEqual((await self._authenticated_get(target, key)).status_code, 503)

    async def test_key_cannot_be_reassigned_to_another_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for backend in ("memory", "sqlite"):
                with self.subTest(backend=backend):
                    settings = VaultSettings(
                        db_path=str(Path(tmp) / f"{backend}.db"),
                        storage_backend=backend,
                        kek=generate_encryption_key(),
                        api_key_pepper="p" * 32,
                    )
                    target = create_app(settings)
                    key = generate_api_key()
                    target.state.register_api_key(key, "demo")
                    target.state.register_api_key(key, "demo")
                    with self.assertRaisesRegex(ValueError, "déjà associée") as error:
                        target.state.register_api_key(key, "other")
                    self.assertNotIn(key, str(error.exception))
                    fingerprint = hash_api_key(key, pepper="p" * 32)
                    self.assertEqual(target.state.api_keys[fingerprint], "demo")
                    self.assertEqual((await self._authenticated_get(target, key)).status_code, 404)
                    if backend == "sqlite":
                        other_worker = create_app(settings)
                        with self.assertRaisesRegex(ValueError, "déjà associée"):
                            other_worker.state.register_api_key(key, "other")
                        self.assertNotIn(fingerprint, other_worker.state.api_keys)
                        with self.assertRaisesRegex(ValueError, "déjà associée"):
                            create_app(settings, api_key_hashes={fingerprint: "other"})

    async def test_registration_db_io_does_not_block_read_path(self) -> None:
        """L'E/S SQLite d'enregistrement ne bloque pas la lecture des empreintes.

        Correction de la remarque de revue « ``api_keys_lock`` (threading.Lock)
        tenu pendant l'I/O DB au register » : l'enregistrement sérialise ses
        écritures avec un verrou de PERSISTANCE distinct, et ne tient le verrou
        de SNAPSHOT (qui protège la copie en mémoire lue par le chemin de
        requête) que pendant les microsecondes de mise à jour du dictionnaire.
        Le parcours exhaustif d'authentification reste donc servi pendant
        l'enregistrement.
        """
        target = create_app(VaultSettings(api_key_pepper="p" * 32))
        first_key = generate_api_key()
        target.state.register_api_key(first_key, "demo")
        key = generate_api_key()
        started = threading.Event()
        release = threading.Event()

        def blocking_persist(
            key_id: str, key_hash: str, project_id: str, created_at: str
        ) -> tuple[str, bool]:
            started.set()
            release.wait(timeout=10)
            return key_id, False

        registry = target.state.api_key_registry
        with patch.object(registry, "_persist_hash", blocking_persist):
            worker = threading.Thread(
                target=lambda: target.state.register_api_key(key, "demo"),
                daemon=True,
            )
            worker.start()
            self.assertTrue(started.wait(timeout=10))

            # La lecture concurrente aboutit malgré l'E/S base en cours : le
            # parcours exhaustif voit la clé déjà enregistrée et n'attend pas.
            project, evaluated = auth_module.find_api_key_project(target, "0" * 64)
            self.assertIsNone(project)
            self.assertEqual(evaluated, 1)

            release.set()
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())

    async def test_oversized_key_is_rejected_before_hashing(self) -> None:
        target = create_app(VaultSettings(api_key_pepper="p" * 32))
        for length in (513, 65536):
            with self.subTest(length=length), patch.object(app_module, "hash_api_key") as hashing:
                response = await self._authenticated_get(target, "A" * length)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), app_module._ERROR_PAYLOADS[401])
                self.assertEqual(response.headers["connection"], "close")
                hashing.assert_not_called()
        key = secrets.token_urlsafe(384)
        self.assertEqual(len(key), 512)
        target.state.register_api_key(key, "demo")
        self.assertEqual((await self._authenticated_get(target, key)).status_code, 404)
        with self.assertRaises(ValueError):
            target.state.register_api_key(key + "A", "demo")

    async def test_authenticated_burst_is_bounded_single_transaction(self) -> None:
        """Rafale clé valide : exactement per_key admissions, sans dépassement.

        Verrouille LOW n°1 : ``peek`` + ``check_authenticated`` unique ne
        laissent aucune fenêtre inter-transactions (5×404 + 5×429 exacts,
        mémoire comme SQLite partagé).

        Le busy-timeout SQLite de production (250 ms) est volontairement
        fail-fast : sous 10 requêtes concurrentes, il peut produire des 503
        transitoires avant même d'atteindre la décision de débit. Ce test
        mesure l'atomicité du rate-limit, pas cette politique d'indisponibilité
        (couverte par ``test_vault_availability``). On allonge donc uniquement
        le busy-timeout ici pour rendre la rafale déterministe : les écritures
        SQLite se sérialisent, puis les 5 admissions et les 5 refus sont exacts.
        """
        for backend in ("memory", "sqlite"):
            with (
                self.subTest(backend=backend),
                tempfile.TemporaryDirectory() as tmp,
                patch("heimdall.vault.database.SQLITE_TIMEOUT_SECONDS", 5.0),
            ):
                target = create_app(
                    VaultSettings(
                        db_path=str(Path(tmp) / f"{backend}.db"),
                        storage_backend=backend,
                        kek=generate_encryption_key(),
                        api_key_pepper="p" * 32,
                        rate_limit_per_key=5,
                        rate_limit_per_peer=1_000,
                        rate_limit_global=1_000,
                    )
                )
                key = generate_api_key()
                target.state.register_api_key(key, "demo")
                responses = await asyncio.gather(
                    *(self._authenticated_get(target, key) for _ in range(10))
                )
                codes = sorted(response.status_code for response in responses)
                self.assertEqual(codes.count(404), 5)
                self.assertEqual(codes.count(429), 5)

    def test_peek_does_not_consume_or_create_buckets(self) -> None:
        """``peek`` est lecture seule : ni consommation ni création de bucket."""
        limiter = RateLimiter(per_key=1, per_peer=1, global_limit=1, window_seconds=60)
        allowed, _ = limiter.peek("127.0.0.1")
        self.assertTrue(allowed)
        self.assertEqual(limiter._buckets, {})
        allowed, _ = limiter.check("127.0.0.1")
        self.assertTrue(allowed)
        allowed, _ = limiter.peek("127.0.0.1")
        self.assertFalse(allowed)
        self.assertEqual(limiter._buckets["anon_peer:127.0.0.1"].count, 1)

    async def test_store_create_refuses_nul_even_off_http_path(self) -> None:
        """Garde anti-contournement : le store refuse NUL même hors validation HTTP.

        La route refuse déjà NUL (400) ; un appelant direct ne doit pas pouvoir
        y stocker un NUL (tronque les outils texte en aval). Les deux backends
        lèvent `ValueError` sans écho de la valeur.
        """
        with tempfile.TemporaryDirectory() as tmp:
            stores = [
                InMemorySecretStore(),
                SqliteSecretStore(Path(tmp) / "nul.db", VaultCipher.generate()),
            ]
            for store in stores:
                with self.subTest(store=type(store).__name__):
                    with self.assertRaises(ValueError) as ctx:
                        await store.create("demo", "dev", "NUL_KEY", "a\x00b")
                    self.assertNotIn("a\x00b", str(ctx.exception))

    async def test_full_scan_cost_is_pinned_at_bounded_cardinality(self) -> None:
        """Verrouille LOW n°2 (full-scan O(N)) : à cardinalité bornée, coût pinné.

        Le parcours exhaustif à coût comparable est conservé (anti-oracle) ;
        ce test pince le plafond : N=25 empreintes → exactement 25 évaluations
        par parcours (connue comme inconnue), et la requête HTTP aboutit
        (404, ni 429 ni 500) à cette cardinalité, sur les deux backends.
        """
        for backend in ("memory", "sqlite"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
                target = create_app(
                    VaultSettings(
                        db_path=str(Path(tmp) / f"{backend}.db"),
                        storage_backend=backend,
                        kek=generate_encryption_key(),
                        api_key_pepper="p" * 32,
                    )
                )
                keys = [generate_api_key() for _ in range(25)]
                for key in keys:
                    target.state.register_api_key(key, "demo")
                wanted = hash_api_key(keys[0], pepper="p" * 32)
                project, evaluated = auth_module.find_api_key_project(target, wanted)
                self.assertEqual(project, "demo")
                self.assertEqual(evaluated, 25)
                unknown, evaluated_unknown = auth_module.find_api_key_project(
                    target, "f" * 64
                )
                self.assertIsNone(unknown)
                self.assertEqual(evaluated_unknown, 25)
                self.assertEqual(
                    (await self._authenticated_get(target, keys[0])).status_code, 404
                )

    def test_indexed_lookup_is_banned_from_auth_path(self) -> None:
        """Verrouille LOW n°3 : `get_api_key_by_hash` jamais utilisé dans `app.py`.

        L'égalité SQL n'est pas à temps constant (oracle temporel) : seul le
        full-scan à coût comparable sert l'authentification. La fonction reste
        disponible pour l'admin/outils et les tests DB.
        """
        app_source = (
            Path(__file__).resolve().parents[1] / "heimdall" / "vault" / "app.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("get_api_key_by_hash", app_source)

    async def test_quota_429_is_permanent_while_rate_429_is_transient(self) -> None:
        """Distingue quota (capacité) et débit : seul le débit se résorbe.

        Verrouille LOW n°3 (quota best-effort documenté) : un 429 de débit
        disparaît après la fenêtre, un 429 de capacité (sans route DELETE)
        persiste malgré l'attente — le retry y est inutile.
        """
        rate_target = create_app(
            VaultSettings(
                api_key_pepper="p" * 32,
                rate_limit_per_key=1,
                rate_limit_per_peer=1_000,
                rate_limit_global=1_000,
                rate_limit_window_seconds=1,
            )
        )
        rate_key = generate_api_key()
        rate_target.state.register_api_key(rate_key, "demo")
        self.assertEqual((await self._authenticated_get(rate_target, rate_key)).status_code, 404)
        self.assertEqual((await self._authenticated_get(rate_target, rate_key)).status_code, 429)
        await asyncio.sleep(1.2)
        self.assertEqual((await self._authenticated_get(rate_target, rate_key)).status_code, 404)

        with tempfile.TemporaryDirectory() as tmp:
            quota_target = create_app(
                VaultSettings(
                    db_path=str(Path(tmp) / "quota.db"),
                    storage_backend="sqlite",
                    kek=generate_encryption_key(),
                    api_key_pepper="p" * 32,
                    rate_limit_per_key=1_000,
                    rate_limit_per_peer=1_000,
                    rate_limit_global=1_000,
                ),
                secret_store=SqliteSecretStore(
                    Path(tmp) / "quota.db",
                    VaultCipher.generate(),
                    max_secrets=1,
                    max_secrets_per_project=1,
                ),
            )
            quota_key = generate_api_key()
            quota_target.state.register_api_key(quota_key, "demo")
            transport = ASGITransport(app=quota_target, client=("127.0.0.1", 54321))
            async with AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1",
                headers={"X-Heimdall-API-Key": quota_key},
            ) as client:
                first = await client.post(
                    "/api/v1/secrets",
                    json={"project": "demo", "env": "dev", "name": "ONLY", "value": "v"},
                )
                self.assertEqual(first.status_code, 201)
                full = await client.post(
                    "/api/v1/secrets",
                    json={"project": "demo", "env": "dev", "name": "EXTRA", "value": "v"},
                )
                self.assertEqual(full.status_code, 429)
                await asyncio.sleep(1.2)
                still_full = await client.post(
                    "/api/v1/secrets",
                    json={"project": "demo", "env": "dev", "name": "EXTRA", "value": "v"},
                )
                self.assertEqual(still_full.status_code, 429)


class VaultSecretValueHygieneTests(unittest.TestCase):
    def test_secret_value_is_never_logged(self) -> None:
        """Verrouille LOW n°4 (SecretValue à ne jamais journaliser).

        Décision #62 (finale, ticket fermé) : NFC + refus ``\\x00``, valeur
        multiligne contractuelle, NOTE anti-log conservée. Tout log futur de
        la valeur = log injection / fuite en clair : ce test échoue si un
        appel ``logger.*`` de ``heimdall/vault/app.py`` référence un
        identifiant sensible (valeur, plaintext, secret) dans ses arguments.
        """
        source = (
            Path(__file__).resolve().parents[1] / "heimdall" / "vault" / "app.py"
        ).read_text(encoding="utf-8")
        self.assertIn("Ne jamais journaliser SecretValue", source)
        tree = ast.parse(source)
        sensitive = ("value", "plaintext", "secret_value", "secretvalue")
        violations: list[str] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"
            ):
                for arg in node.args:
                    for child in ast.walk(arg):
                        if isinstance(child, ast.Name) and child.id.lower() in sensitive:
                            violations.append(
                                f"logger.{node.func.attr} référence {child.id!r} "
                                f"(ligne {getattr(child, 'lineno', '?')})"
                            )
                        if isinstance(child, ast.Constant) and isinstance(child.value, str):
                            lowered = child.value.lower()
                            if "secretvalue" in lowered or "plaintext" in lowered:
                                violations.append(
                                    f"logger.{node.func.attr} mentionne une valeur "
                                    f"sensible (ligne {getattr(child, 'lineno', '?')})"
                                )
        self.assertEqual(violations, [])

    def test_cli_never_handles_secret_values(self) -> None:
        """Verrouille LOW n°4 (SecretValue) côté CLI : aucun affichage brut.

        La CLI ne manipule que des références (triplet), jamais de valeurs
        déchiffrées ; `init_db --verbose` n'imprime que des chemins assainis.
        Ce test échoue si `cli/main.py`, `vault/init_db.py` ou `vault/client.py`
        référence un jour `SecretRead`, un chiffré ou un plaintext (fuite et
        injection terminal via `\\r`/`\\x1b` rejoués).
        """
        root = Path(__file__).resolve().parents[1]
        modules = [
            root / "heimdall" / "cli" / "main.py",
            root / "heimdall" / "vault" / "init_db.py",
            root / "heimdall" / "vault" / "client.py",
        ]
        tokens = ("SecretRead", "encrypted_value", "secret_value", "plaintext")
        for module in modules:
            with self.subTest(module=module.name):
                source = module.read_text(encoding="utf-8")
                for token in tokens:
                    self.assertNotIn(token, source)


class VaultImportSideEffectTests(unittest.TestCase):
    def _production_env_without_secrets(self, home: str, xdg: str) -> dict[str, str]:
        """Environnement production isolé, sans pepper/KEK, user-site préservé."""
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("HEIMDALL_VAULT_")
        }
        env["HEIMDALL_ENV"] = "production"
        env["HOME"] = home
        env["XDG_DATA_HOME"] = xdg
        # HOME override déplace le user-site (``~/.local``) : sans ceci,
        # une install ``--user`` (ex. CI sous ``/home/runner/.local``)
        # devient invisible et le test échoue en faux rouge
        # (``ModuleNotFoundError: uvicorn``). On fige donc la vraie base
        # utilisateur du parent, indépendante de HOME.
        env["PYTHONUSERBASE"] = site.getuserbase()
        return env

    def _run_isolated(self, code: str, env: dict[str, str]) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_plain_import_creates_no_file_even_in_production(self) -> None:
        """Verrouille la factory explicite : l'import seul ne crée rien.

        Même avec ``HEIMDALL_ENV=production`` (backend SQLite par défaut),
        le simple import ne crée ni répertoire ni ``vault.db`` et ne lève
        pas (le fail-closed n'a lieu qu'à l'appel explicite de ``get_app()``).
        """
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as xdg:
            env = self._production_env_without_secrets(home, xdg)
            code = "import heimdall.vault.app; print('import-ok')"
            result = self._run_isolated(code, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("import-ok", result.stdout)
            self.assertEqual(list(Path(xdg).rglob("*")), [])
            self.assertEqual(list(Path(home).rglob("*")), [])

    def test_from_import_app_fails_without_disk_effect(self) -> None:
        """``from heimdall.vault.app import app`` n'existe plus : ImportError sans effet disque.

        La factory est explicite (`get_app()`) : aucun import, même attributif,
        ne doit créer `vault.db` ni générer de pepper.
        """
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as xdg:
            env = self._production_env_without_secrets(home, xdg)
            code = "from heimdall.vault.app import app"
            result = self._run_isolated(code, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ImportError", result.stderr)
            self.assertNotIn("vault.db", result.stderr)
            self.assertEqual(list(Path(xdg).rglob("*")), [])
            self.assertEqual(list(Path(home).rglob("*")), [])

    def test_get_app_is_fail_closed_before_any_disk_effect(self) -> None:
        """`get_app()` en production sans pepper/KEK échoue AVANT tout effet disque."""
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as xdg:
            env = self._production_env_without_secrets(home, xdg)
            code = "from heimdall.vault.app import get_app; get_app()"
            result = self._run_isolated(code, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ValidationError", result.stderr)
            self.assertEqual(list(Path(xdg).rglob("*")), [])
            self.assertEqual(list(Path(home).rglob("*")), [])


def test_sqlite_quota_never_exceeded_with_two_workers_tmp_path(tmp_path: Path) -> None:
    """Pin suggestion revue : deux stores, même fichier `tmp_path`, `max_secrets=2`.

    Verrouille le quota atomique inter-workers (`BEGIN IMMEDIATE`) : jamais de
    dépassement, troisième création refusée sur les deux stores, sans corruption.
    """
    db_path = tmp_path / "vault.db"
    cipher = VaultCipher.generate()
    max_secrets = 2
    store_one = SqliteSecretStore(
        db_path, cipher, max_secrets=max_secrets, max_secrets_per_project=10
    )
    store_two = SqliteSecretStore(
        db_path, cipher, max_secrets=max_secrets, max_secrets_per_project=10
    )
    start = threading.Barrier(2)
    created: list[str] = []
    refused: list[Exception] = []

    def create_in_worker(store: SqliteSecretStore, name: str) -> None:
        # Sous contention, le perdant du BEGIN IMMEDIATE lève une erreur
        # transitoire (database is locked → DatabaseUnavailableError, 0.25 s
        # de busy-timeout) : retry court, sans jamais dépasser le quota.
        # Seule une erreur non transitoire est un vrai refus.
        start.wait(timeout=5)
        for _ in range(20):
            try:
                asyncio.run(store.create(project="demo", env="dev", name=name, value="v"))
                created.append(name)
                return
            except DatabaseUnavailableError:
                time.sleep(0.05)
            except Exception as exc:  # pragma: no cover - diagnostic
                refused.append(exc)
                return
        refused.append(DatabaseUnavailableError("verrou persistant après retries"))

    threads = [
        threading.Thread(target=create_in_worker, args=(store_one, "TMP_PATH_A")),
        threading.Thread(target=create_in_worker, args=(store_two, "TMP_PATH_B")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not [thread.name for thread in threads if thread.is_alive()]
    assert refused == []
    assert len(created) == max_secrets
    with db_session(db_path) as conn:
        assert count_secrets(conn) == max_secrets
    for store in (store_one, store_two):
        try:
            asyncio.run(store.create("demo", "dev", "TMP_PATH_C", "v"))
        except QuotaExceededError:
            pass
        else:
            raise AssertionError("quota non appliqué après saturation")
    with db_session(db_path) as conn:
        assert count_secrets(conn) == max_secrets
