"""Tests du ticket #112 — comparaison en temps constant et absence d'oracle.

Le ticket exige ``hmac.compare_digest`` et le même travail pour une clé
inconnue et une clé invalide : même réponse, même code, hachage et parcours
exhaustif exécutés dans les deux cas.

Preuves SAMM : module + ligne (voir ``docs/t112-samm.md``).
"""

import unittest
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

import heimdall.vault.auth as auth_module
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import generate_api_key

PEPPER = "t112_pepper_value_0123456789abcdef"
_UNAUTHORIZED_BODY = {"code": "unauthorized", "message": "Authentification requise"}


def _client(app):
    return AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 54321)),
        base_url="http://127.0.0.1:8443",
    )


class ConstantTimeAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_and_malformed_keys_do_the_same_work(self) -> None:
        """Clé inconnue, blanche ou vide : hachage + parcours exhaustif identiques."""
        app = create_app(VaultSettings(api_key_pepper=PEPPER))
        for index in range(4):
            app.state.register_api_key(generate_api_key(), f"project{index}")

        hash_calls: list[str] = []
        scan_calls: list[str] = []
        real_hash = auth_module.hash_project_api_key
        real_scan = auth_module.find_api_key_project

        def counting_hash(raw_key: str, pepper: str | bytes) -> str:
            hash_calls.append(raw_key)
            return real_hash(raw_key, pepper)

        def counting_scan(target_app, provided_hash: str):
            scan_calls.append(provided_hash)
            return real_scan(target_app, provided_hash)

        cases = {
            "unknown": "unknown-key-value",
            "whitespace": "   ",
            "empty": "",
        }
        with (
            patch.object(auth_module, "hash_project_api_key", counting_hash),
            patch.object(auth_module, "find_api_key_project", counting_scan),
        ):
            for name, candidate in cases.items():
                with self.subTest(case=name):
                    hash_calls.clear()
                    scan_calls.clear()
                    async with _client(app) as client:
                        response = await client.get(
                            "/api/v1/secrets/demo/dev/TOKEN",
                            headers={"X-Heimdall-API-Key": candidate},
                        )
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json(), _UNAUTHORIZED_BODY)
                    # Un seul hachage (middleware de débit), réutilisé par
                    # l'authentification ; un seul parcours exhaustif mémoïsé.
                    self.assertEqual(len(hash_calls), 1)
                    self.assertEqual(len(scan_calls), 1)

    async def test_every_registered_hash_is_compared_without_early_exit(self) -> None:
        """Le parcours évalue toutes les empreintes, même après une correspondance."""
        app = create_app(VaultSettings(api_key_pepper=PEPPER))
        keys = [generate_api_key() for _ in range(5)]
        for key in keys:
            app.state.register_api_key(key, "demo")

        comparisons: list[tuple[str, str]] = []
        real_compare = auth_module.constant_time_equal

        def counting_compare(left: str, right: str) -> bool:
            comparisons.append((left, right))
            return real_compare(left, right)

        with patch.object(auth_module, "constant_time_equal", counting_compare):
            async with _client(app) as client:
                response = await client.get(
                    "/api/v1/secrets/demo/dev/TOKEN",
                    headers={"X-Heimdall-API-Key": keys[0]},
                )
        self.assertEqual(response.status_code, 404)
        self.assertGreaterEqual(len(comparisons), 5)

    async def test_key_id_lookup_is_performed_once_for_valid_and_invalid_keys(self) -> None:
        """Le lookup d'identifiant a le même coût (une requête) dans les deux cas."""
        app = create_app(VaultSettings(api_key_pepper=PEPPER))
        key = generate_api_key()
        app.state.register_api_key(key, "demo")
        calls: list[str] = []
        real_lookup = app.state.api_key_registry.key_id_for_hash

        def counting_lookup(key_hash: str) -> str | None:
            calls.append(key_hash)
            return real_lookup(key_hash)

        with patch.object(app.state.api_key_registry, "key_id_for_hash", counting_lookup):
            async with _client(app) as client:
                valid = await client.get(
                    "/api/v1/secrets/demo/dev/TOKEN",
                    headers={"X-Heimdall-API-Key": key},
                )
            self.assertEqual(valid.status_code, 404)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0], auth_module.hash_project_api_key(key, PEPPER))

            calls.clear()
            async with _client(app) as client:
                invalid = await client.get(
                    "/api/v1/secrets/demo/dev/TOKEN",
                    headers={"X-Heimdall-API-Key": "unknown-key-value"},
                )
            self.assertEqual(invalid.status_code, 401)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0], auth_module.DUMMY_HASH)

    async def test_missing_unknown_revoked_and_malformed_share_the_same_401(self) -> None:
        """Même corps et même code pour toutes les causes d'échec d'authentification."""
        app = create_app(VaultSettings(api_key_pepper=PEPPER))
        revoked_key = generate_api_key()
        key_id = app.state.register_api_key(revoked_key, "demo")
        app.state.api_key_registry.revoke(key_id)

        cases = {
            "missing": None,
            "unknown": "unknown-key-value",
            "revoked": revoked_key,
            "malformed": "   ",
        }
        async with _client(app) as client:
            for name, candidate in cases.items():
                with self.subTest(case=name):
                    headers = (
                        {} if candidate is None else {"X-Heimdall-API-Key": candidate}
                    )
                    response = await client.get(
                        "/api/v1/secrets/demo/dev/TOKEN", headers=headers
                    )
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json(), _UNAUTHORIZED_BODY)
                    self.assertEqual(response.headers.get("content-type"), "application/json")
