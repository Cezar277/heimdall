"""Tests d'abus et de rejeu du Vault — ticket #114.

Attaques exécutées contre NOTRE propre serveur, en mémoire ou sur une base
temporaire :

- force brute de clés API : les 401 deviennent des 429 avec ``Retry-After`` ;
- rejeu d'une requête capturée : un POST rejoué ne écrase jamais (409), un GET
  rejoué est idempotent, et le rejeu après révocation est refusé (401) ;
- charge simple : quelques centaines de requêtes sans plantage ni 500 ;
- ``X-Forwarded-For`` falsifié : le budget pair n'est pas réinitialisé.

Ces tests ne contactent aucun serveur externe : uniquement l'application ASGI
locale et des bases temporaires.

Preuves SAMM : module + ligne (voir ``docs/t114-samm.md``).
"""

import asyncio
import tempfile
import unittest
from pathlib import Path

from httpx import ASGITransport, AsyncClient

from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import generate_api_key, generate_encryption_key

PEPPER = "t114_pepper_value_0123456789abcdef"
COLLECTION_PATH = "/api/v1/secrets"
SECRET_PATH = f"{COLLECTION_PATH}/demo/dev/TOKEN"


def _memory_app(**settings: object):
    return create_app(VaultSettings(api_key_pepper=PEPPER, **settings))


def _sqlite_app(tmp: str, **settings: object):
    return create_app(
        VaultSettings(
            db_path=str(Path(tmp) / "vault.db"),
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


class BruteforceAbuseTests(unittest.IsolatedAsyncioTestCase):
    async def test_bruteforce_is_bounded_by_peer_budget(self) -> None:
        """Dix clés fausses : cinq 401, puis cinq 429 avec Retry-After borné."""
        app = _memory_app(
            rate_limit_per_key=100,
            rate_limit_per_peer=5,
            rate_limit_global=100,
        )
        async with _client(app) as client:
            responses = [
                await client.get(
                    SECRET_PATH,
                    headers={"X-Heimdall-API-Key": f"wrong-key-{index}"},
                )
                for index in range(10)
            ]
        statuses = [response.status_code for response in responses]
        self.assertEqual(statuses, [401] * 5 + [429] * 5)
        for response in responses[5:]:
            retry_after = int(response.headers["Retry-After"])
            self.assertGreaterEqual(retry_after, 1)
            self.assertLessEqual(retry_after, 3600)
            self.assertEqual(
                response.json(),
                {"code": "rate_limited", "message": "Trop de requêtes"},
            )
        events = app.state.audit_log.list_events(limit=20)
        self.assertEqual([event["status_code"] for event in events], statuses)
        self.assertEqual(
            [event["outcome"] for event in events],
            ["unauthenticated"] * 5 + ["rate_limited"] * 5,
        )

    async def test_spoofed_forwarded_for_does_not_reset_the_peer_budget(self) -> None:
        """Un X-Forwarded-For différent à chaque requête ne remet pas le compteur à zéro."""
        app = _memory_app(
            rate_limit_per_key=100,
            rate_limit_per_peer=2,
            rate_limit_global=100,
        )
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            first = await client.get(
                SECRET_PATH,
                headers={"X-Heimdall-API-Key": key, "X-Forwarded-For": "203.0.113.1"},
            )
            second = await client.get(
                SECRET_PATH,
                headers={"X-Heimdall-API-Key": key, "X-Forwarded-For": "203.0.113.2"},
            )
            third = await client.get(
                SECRET_PATH,
                headers={"X-Heimdall-API-Key": key, "X-Forwarded-For": "203.0.113.3"},
            )
        self.assertEqual(
            [first.status_code, second.status_code, third.status_code],
            [404, 404, 429],
        )


class ReplayAbuseTests(unittest.IsolatedAsyncioTestCase):
    async def test_replayed_post_is_rejected_without_overwrite(self) -> None:
        """Rejouer un POST capturé renvoie 409 et ne modifie jamais le secret."""
        app = _memory_app()
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "TOKEN",
            "value": "original-value",
        }
        async with _client(app) as client:
            created = await client.post(
                COLLECTION_PATH,
                json=payload,
                headers={"X-Heimdall-API-Key": key},
            )
            replayed = await client.post(
                COLLECTION_PATH,
                json={**payload, "value": "attacker-value"},
                headers={"X-Heimdall-API-Key": key},
            )
            current = await client.get(
                SECRET_PATH, headers={"X-Heimdall-API-Key": key}
            )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(replayed.status_code, 409)
        self.assertEqual(
            replayed.json(),
            {"code": "conflict", "message": "Secret déjà existant"},
        )
        self.assertEqual(current.status_code, 200)
        self.assertEqual(current.json()["value"], "original-value")
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual([event["status_code"] for event in events], [201, 409, 200])

    async def test_replayed_request_after_revocation_is_rejected(self) -> None:
        """Une requête capturée rejouée avec une clé révoquée obtient 401."""
        app = _memory_app()
        key = generate_api_key()
        key_id = app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            created = await client.post(
                "/api/v1/secrets",
                json={
                    "project": "demo",
                    "env": "dev",
                    "name": "TOKEN",
                    "value": "value",
                },
                headers={"X-Heimdall-API-Key": key},
            )
            self.assertEqual(created.status_code, 201)
            app.state.api_key_registry.revoke(key_id)
            replayed = await client.get(
                SECRET_PATH, headers={"X-Heimdall-API-Key": key}
            )
        self.assertEqual(replayed.status_code, 401)
        self.assertEqual(
            replayed.json(),
            {"code": "unauthorized", "message": "Authentification requise"},
        )
        events = app.state.audit_log.list_events(limit=10)
        self.assertEqual(events[-1]["status_code"], 401)
        self.assertEqual(events[-1]["outcome"], "unauthenticated")


class LoadAbuseTests(unittest.IsolatedAsyncioTestCase):
    async def test_three_hundred_requests_do_not_crash_the_memory_backend(self) -> None:
        """Charge simple : 300 requêtes concurrentes, aucun 500, serveur toujours sain."""
        app = _memory_app(
            rate_limit_per_key=1_000,
            rate_limit_per_peer=1_000,
            rate_limit_global=1_000,
        )
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        async with _client(app) as client:
            responses = await asyncio.gather(
                *(
                    client.get(SECRET_PATH, headers={"X-Heimdall-API-Key": key})
                    for _ in range(300)
                )
            )
            health = await client.get("/api/v1/health")
        self.assertEqual([response.status_code for response in responses], [404] * 300)
        self.assertEqual(health.status_code, 200)
        events = app.state.audit_log.list_events(limit=400)
        self.assertEqual(len(events), 301)
        self.assertNotIn(500, [event["status_code"] for event in events])
        self.assertEqual(app.state.audit_log.verify_chain(), (True, None))

    async def test_fifty_requests_do_not_crash_the_sqlite_backend(self) -> None:
        """Charge SQLite séquentielle : journal persistant et chaîne intacte."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _sqlite_app(
                tmp,
                rate_limit_per_key=1_000,
                rate_limit_per_peer=1_000,
                rate_limit_global=1_000,
            )
            key = generate_api_key()
            app.state.register_api_key(key, "demo")
            async with _client(app) as client:
                for _ in range(50):
                    response = await client.get(
                        SECRET_PATH, headers={"X-Heimdall-API-Key": key}
                    )
                    self.assertEqual(response.status_code, 404)
                health = await client.get("/api/v1/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(app.state.audit_log.count(), 51)
            self.assertEqual(app.state.audit_log.verify_chain(), (True, None))
