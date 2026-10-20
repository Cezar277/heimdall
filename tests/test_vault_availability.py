"""Contention et panne SQLite : refus temporaires explicites, sans divulgation."""

import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

from heimdall.vault import database
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import generate_api_key, generate_encryption_key
from heimdall.vault.database import db_session
from heimdall.vault.ratelimit import RateLimiter


def memory_limiter() -> RateLimiter:
    return RateLimiter(per_key=100, per_peer=100, global_limit=100, window_seconds=60)


class DatabaseAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    def make_app(self, path: Path):
        return create_app(
            VaultSettings(
                db_path=str(path),
                storage_backend="sqlite",
                kek=generate_encryption_key(),
                api_key_pepper="p" * 32,
                require_auth=False,
            )
        )

    def client(self, app):
        return AsyncClient(
            transport=ASGITransport(app=app, client=("127.0.0.1", 12345)),
            base_url="http://127.0.0.1",
        )

    def assert_unavailable(self, response) -> None:
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(), {"code": "unavailable", "message": "Service indisponible"}
        )
        self.assertEqual(response.headers["Retry-After"], "1")
        self.assertEqual(response.headers["Connection"], "close")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    async def test_real_writer_contention_returns_503_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.db"
            apps = [self.make_app(path), self.make_app(path)]
            for stage in ("peer", "key", "store"):
                with self.subTest(stage=stage):
                    key = generate_api_key()
                    for app in apps:
                        app.state.register_api_key(key, "demo")
                    if stage == "store":
                        for app in apps:
                            app.state.rate_limiter = memory_limiter()
                    async with self.client(apps[0]) as first, self.client(apps[1]) as second:
                        # Un vrai écrivain externe maintient le verrou plus longtemps
                        # que le busy_timeout explicite, sans bloquer la boucle asyncio.
                        with db_session(path) as blocker:
                            self.assertEqual(
                                blocker.execute("PRAGMA busy_timeout").fetchone()[0], 250
                            )
                            blocker.execute("BEGIN IMMEDIATE")

                            async def request(client, stage=stage, key=key):
                                if stage == "store":
                                    return await client.post(
                                        "/api/v1/secrets",
                                        json={
                                            "project": "demo",
                                            "env": "dev",
                                            "name": "TOKEN",
                                            "value": "canary-secret-value",
                                        },
                                    )
                                return await client.get(
                                    "/api/v1/secrets/demo/dev/TOKEN",
                                    headers={
                                        "X-Heimdall-API-Key": key,
                                    },
                                )

                            if stage == "key":
                                # L'admission pair/global (peek) est déjà passée ; exercer
                                # la transaction consommatrice unique (pair/global + clé).
                                with (
                                    patch.object(
                                        apps[0].state.rate_limiter, "peek", return_value=(True, 0)
                                    ),
                                    patch.object(
                                        apps[1].state.rate_limiter, "peek", return_value=(True, 0)
                                    ),
                                ):
                                    responses = await asyncio.gather(
                                        request(first), request(second)
                                    )
                            else:
                                responses = await asyncio.gather(request(first), request(second))
                            for response in responses:
                                self.assert_unavailable(response)
                        # Le même serveur accepte à nouveau les requêtes après libération.
                        self.assertEqual((await first.get("/api/v1/health")).status_code, 200)
            async with self.client(apps[0]) as client:
                created = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "TOKEN",
                        "value": "value",
                    },
                )
                self.assertEqual(created.status_code, 201)
                duplicate = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "TOKEN",
                        "value": "other",
                    },
                )
                self.assertEqual(duplicate.status_code, 409)

    async def test_corrupt_database_is_503_for_rate_auth_and_store(self) -> None:
        for stage in ("rate", "auth", "store"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "vault.db"
                app = self.make_app(path)
                key = generate_api_key()
                app.state.register_api_key(key, "demo")
                if stage != "rate":
                    app.state.rate_limiter = memory_limiter()
                path.write_bytes(b"corrupt-database-canary" * 50)
                async with self.client(app) as client:
                    response = await client.get(
                        "/api/v1/secrets/demo/dev/TOKEN",
                        headers=({"X-Heimdall-API-Key": key} if stage == "auth" else {}),
                    )
                self.assert_unavailable(response)

    async def test_auth_access_error_is_503_but_unknown_key_is_401(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.db"
            app = self.make_app(path)
            key = generate_api_key()
            app.state.register_api_key(key, "demo")
            app.state.rate_limiter = memory_limiter()
            async with self.client(app) as client:
                for error in (
                    PermissionError("private-path-canary"),
                    sqlite3.OperationalError("disk-canary"),
                ):
                    with (
                        self.subTest(error=type(error).__name__),
                        patch.object(database, "get_connection", side_effect=error),
                    ):
                        response = await client.get(
                            "/api/v1/secrets/demo/dev/TOKEN",
                            headers={
                                "X-Heimdall-API-Key": key,
                            },
                        )
                    self.assert_unavailable(response)
                unknown = await client.get(
                    "/api/v1/secrets/demo/dev/TOKEN",
                    headers={
                        "X-Heimdall-API-Key": "unknown",
                    },
                )
                self.assertEqual(unknown.status_code, 401)
