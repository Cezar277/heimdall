"""Régressions de la revue #63 : admission, SQLite async et empreintes uniques."""

import asyncio
import os
import secrets
import site
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

import heimdall.vault.app as app_module
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
    create_api_key,
    db_session,
    ensure_project,
    init_db,
)
from heimdall.vault.ratelimit import RateLimiter
from heimdall.vault.store import SqliteSecretStore


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
                (app_module, lambda: self._authenticated_get(target, key), 1),
                (ratelimit_module, lambda: self._authenticated_get(target, key), 1),
                (ratelimit_module, lambda: self._authenticated_get(target, key), 2),
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

    async def test_peer_and_global_rejection_precede_hash_and_lookup(self) -> None:
        """Une requête refusée avant auth ne paie ni HMAC ni parcours d'empreintes."""
        with tempfile.TemporaryDirectory() as tmp:
            for backend in ("memory", "sqlite"):
                for bucket in ("peer", "global"):
                    with self.subTest(backend=backend, bucket=bucket):
                        settings = VaultSettings(
                            db_path=str(Path(tmp) / f"{backend}-{bucket}.db"),
                            storage_backend=backend,
                            kek=generate_encryption_key(),
                            api_key_pepper="p" * 32,
                            rate_limit_per_peer=1 if bucket == "peer" else 100,
                            rate_limit_global=1 if bucket == "global" else 100,
                        )
                        target = create_app(settings)
                        key = generate_api_key()
                        target.state.register_api_key(key, "demo")
                        first = await self._authenticated_get(target, key)
                        self.assertEqual(first.status_code, 404)
                        with (
                            patch.object(app_module, "hash_api_key") as hashing,
                            patch.object(app_module, "_find_api_key_project") as lookup,
                        ):
                            second = await self._authenticated_get(target, key)
                            self.assertEqual(second.status_code, 429)
                            self.assertIn("Retry-After", second.headers)
                            hashing.assert_not_called()
                            lookup.assert_not_called()

    async def test_peer_global_are_consumed_once_even_when_key_is_rejected(self) -> None:
        """La phase clé ne recompte pas pair/global et ses 429 restent comptés."""
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
                            rate_limit_per_peer=3,
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
            await asyncio.gather(
                *(
                    asyncio.to_thread(app_module._persist_api_key_hash, target, fingerprint, "demo")
                    for _ in range(5)
                )
            )
            with db_session(db_path) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0], 1)
                conn.execute("UPDATE api_keys SET revoked_at = '2026-01-01'")
            with self.assertRaisesRegex(ValueError, "déjà associée"):
                app_module._persist_api_key_hash(target, fingerprint, "other")
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
                app_module, "_lookup_db_api_key", wraps=app_module._lookup_db_api_key
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
            with patch.object(app_module, "db_session", side_effect=DatabaseUnavailableError):
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

        def blocking_persist(app: object, key_hash: str, project_id: str) -> None:
            started.set()
            release.wait(timeout=10)

        with patch.object(app_module, "_persist_api_key_hash", blocking_persist):
            worker = threading.Thread(
                target=lambda: target.state.register_api_key(key, "demo"),
                daemon=True,
            )
            worker.start()
            self.assertTrue(started.wait(timeout=10))

            # La lecture concurrente aboutit malgré l'E/S base en cours : le
            # parcours exhaustif voit la clé déjà enregistrée et n'attend pas.
            project, evaluated = app_module._find_api_key_project(target, "0" * 64)
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
        """
        for backend in ("memory", "sqlite"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
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
        self.assertEqual(limiter._buckets["peer:127.0.0.1"].count, 1)


class VaultImportSideEffectTests(unittest.TestCase):
    def test_plain_import_creates_no_file_even_in_production(self) -> None:
        """Verrouille LOW n°2 : ``import heimdall.vault.app`` sans accès à ``app``.

        Même avec ``HEIMDALL_ENV=production`` (backend SQLite par défaut),
        le simple import ne crée ni répertoire ni ``vault.db`` et ne lève
        pas (le fail-closed n'a lieu qu'au premier accès à ``app``).
        """
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as xdg:
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
            code = "import heimdall.vault.app; print('import-ok')"
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("import-ok", result.stdout)
            self.assertEqual(list(Path(xdg).rglob("*")), [])
            self.assertEqual(list(Path(home).rglob("*")), [])
