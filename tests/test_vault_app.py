"""Tests unitaires et d'intégration du squelette Vault FastAPI (ticket #25).

Vérifie l'application FastAPI, la configuration via variables d'environnement
(pydantic-settings), l'absence de fuite d'informations sur `/health` et `/api/v1/health`,
la désactivation par défaut de la documentation OpenAPI (/docs, /openapi.json),
la conformité contractuelle du schéma OpenAPI sur `/api/v1/health`,
la gestion d'erreurs contractuelle (400, 401, 403, 404, 405, 409, 429, 503)
sans enveloppe framework, et l'allowlist alignée sur VaultClient (127.0.0.1, ::1, localhost).
"""

import os
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ValidationError

from heimdall.vault.app import (
    HealthResponse,
    Settings,
    VaultSettings,
    app,
    create_app,
    get_settings,
    run_server,
)


class VaultAppTests(unittest.IsolatedAsyncioTestCase):
    """Tests du comportement HTTP du serveur Vault."""

    async def asyncSetUp(self) -> None:
        self.transport = ASGITransport(app=app)
        self.client = AsyncClient(transport=self.transport, base_url="http://127.0.0.1:8443")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def test_health_returns_200_ok(self) -> None:
        """Critère d'acceptation : `/health` répond 200 avec {'status': 'ok'}."""
        response = await self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_api_v1_health_returns_200_ok(self) -> None:
        """Conformité OpenAPI v1 (#15) : `/api/v1/health` répond également 200."""
        response = await self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_health_does_not_leak_version_or_configuration(self) -> None:
        """Mitigation Information Disclosure (STRIDE) : pas de version ni de config."""
        for endpoint in ("/health", "/api/v1/health"):
            with self.subTest(endpoint=endpoint):
                response = await self.client.get(endpoint)
                data = response.json()
                self.assertEqual(list(data.keys()), ["status"])
                for forbidden in ("version", "config", "port", "host", "env", "debug"):
                    self.assertNotIn(forbidden, data)

    async def test_docs_and_openapi_disabled_by_default(self) -> None:
        """Mitigation reconnaissance pentest : /docs et /openapi.json renvoient 404."""
        for path in ("/docs", "/openapi.json", "/redoc", "/docs/oauth2-redirect"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(
                    response.json(),
                    {"code": "not_found", "message": "Ressource introuvable"},
                )

    async def test_docs_enabled_explicitly_in_dev_declares_contractual_responses(self) -> None:
        """En mode dev, le schéma OpenAPI déclare toutes les réponses contractuelles."""
        dev_app = create_app(VaultSettings(enable_docs=True))
        async with AsyncClient(
            transport=ASGITransport(app=dev_app), base_url="http://127.0.0.1:8443"
        ) as dev_client:
            docs_resp = await dev_client.get("/docs")
            self.assertEqual(docs_resp.status_code, 200)
            openapi_resp = await dev_client.get("/openapi.json")
            self.assertEqual(openapi_resp.status_code, 200)
            schema = openapi_resp.json()

            # La route /api/v1/health est présente et conforme
            self.assertIn("/api/v1/health", schema["paths"])
            responses = schema["paths"]["/api/v1/health"]["get"]["responses"]
            for expected_code in ("200", "405", "429", "500", "503", "default"):
                self.assertIn(expected_code, responses)

            # Retry-After est obligatoire sur 429 et 503
            for code in ("429", "503"):
                headers = responses[code]["headers"]
                self.assertIn("Retry-After", headers)
                self.assertTrue(headers["Retry-After"]["required"])

            # La route de confort /health est exclue du schéma (include_in_schema=False)
            self.assertNotIn("/health", schema["paths"])

    async def test_not_found_returns_contractual_json_without_fingerprint(self) -> None:
        """Le routeur ne doit pas fuir l'enveloppe {detail: ...} du framework."""
        response = await self.client.get("/unknown-route")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"code": "not_found", "message": "Ressource introuvable"},
        )

    async def test_method_not_allowed_returns_contractual_json(self) -> None:
        """Méthode POST interdite sur /api/v1/health -> 405 sans fuite."""
        for endpoint in ("/health", "/api/v1/health"):
            with self.subTest(endpoint=endpoint):
                response = await self.client.post(endpoint)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(
                    response.json(),
                    {"code": "method_not_allowed", "message": "Méthode non autorisée"},
                )

    async def test_validation_error_returns_contractual_400_without_detail(self) -> None:
        """RequestValidationError est converti en 400 bad_request sans écho d'entrée."""
        test_app = create_app()

        class DummyInput(BaseModel):
            num: int

        @test_app.post("/test-validation")
        async def dummy_endpoint(body: DummyInput) -> dict[str, str]:
            return {"status": "ok"}

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://127.0.0.1:8443"
        ) as c:
            response = await c.post("/test-validation", json={"num": "not-an-int"})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.json(),
                {"code": "bad_request", "message": "Requête invalide"},
            )
            self.assertNotIn("detail", response.json())
            self.assertNotIn("not-an-int", response.text)

    async def test_contractual_http_error_codes_preserved(self) -> None:
        """Les codes d'erreur contractuels sont préservés avec leur payload sans dérive vers 500."""
        test_app = create_app()

        @test_app.get("/trigger-error/{code}")
        async def trigger_error(code: int) -> None:
            headers = {"Retry-After": "30"} if code == 429 else None
            raise HTTPException(status_code=code, headers=headers)

        expected_errors = {
            400: {"code": "bad_request", "message": "Requête invalide"},
            401: {"code": "unauthorized", "message": "Authentification requise"},
            403: {"code": "forbidden", "message": "Accès interdit"},
            404: {"code": "not_found", "message": "Ressource introuvable"},
            405: {"code": "method_not_allowed", "message": "Méthode non autorisée"},
            409: {"code": "conflict", "message": "Secret déjà existant"},
            429: {"code": "rate_limited", "message": "Trop de requêtes"},
            503: {"code": "unavailable", "message": "Service indisponible"},
        }

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://127.0.0.1:8443"
        ) as c:
            for code, expected_body in expected_errors.items():
                with self.subTest(code=code):
                    resp = await c.get(f"/trigger-error/{code}")
                    self.assertEqual(resp.status_code, code)
                    self.assertEqual(resp.json(), expected_body)
                    if code == 429:
                        self.assertEqual(resp.headers.get("retry-after"), "30")

    async def test_unmapped_and_unhandled_errors_return_500_internal_error(self) -> None:
        """Un statut imprévu ou une exception non gérée retourne 500 internal_error."""
        test_app = create_app()

        @test_app.get("/trigger-crash")
        async def trigger_crash() -> None:
            raise RuntimeError("Secret crash detail that must not leak")

        @test_app.get("/trigger-unknown-http")
        async def trigger_unknown() -> None:
            raise HTTPException(status_code=418)

        async with AsyncClient(
            transport=ASGITransport(app=test_app, raise_app_exceptions=False),
            base_url="http://127.0.0.1:8443",
        ) as c:
            for endpoint in ("/trigger-crash", "/trigger-unknown-http"):
                with self.subTest(endpoint=endpoint):
                    resp = await c.get(endpoint)
                    self.assertEqual(resp.status_code, 500)
                    self.assertEqual(
                        resp.json(),
                        {"code": "internal_error", "message": "Erreur interne"},
                    )
                    self.assertNotIn("Secret crash detail", resp.text)

    async def test_non_loopback_client_rejected_by_middleware(self) -> None:
        """Défense en profondeur : une requête d'une IP distante/LAN est bloquée en 403."""
        test_app = create_app()
        # Simule un appel ASGI avec un client non local (192.168.1.50)
        transport = ASGITransport(app=test_app, client=("192.168.1.50", 54321))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8443") as c:
            response = await c.get("/health")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                response.json(),
                {"code": "forbidden", "message": "Accès interdit"},
            )


class VaultSettingsTests(unittest.TestCase):
    """Tests de la configuration et des garde-fous pydantic-settings."""

    def test_default_settings_bind_to_loopback_only(self) -> None:
        """Garde-fou : écoute par défaut strictement sur localhost (127.0.0.1:8443)."""
        settings = VaultSettings()
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 8443)
        self.assertFalse(settings.enable_docs)

    def test_loopback_allowlist_accepts_valid_loopback_hosts(self) -> None:
        """L'allowlist accepte localhost, 127.0.0.1 et ::1 (aligné sur VaultClient)."""
        valid_hosts = (
            "127.0.0.1",
            "::1",
            "localhost",
            "  127.0.0.1  ",
            "LOCALHOST",
        )
        allowed = {"127.0.0.1", "::1", "localhost"}
        for valid_host in valid_hosts:
            with self.subTest(host=valid_host):
                cfg = VaultSettings(host=valid_host)
                self.assertIn(cfg.host, allowed)

    def test_host_allowlist_rejects_non_loopback_addresses(self) -> None:
        """Rejette toute tentative d'exposition réseau (LAN, WAN, 0.0.0.0, vide)."""
        invalid_hosts = (
            "192.168.1.10",
            "10.0.0.5",
            "8.8.8.8",
            "",
            "   ",
            "0.0.0.00",
            "0.0.0.0",  # noqa: S104
            "::",
            "::ffff:0.0.0.0",
            "localhost.evil.com",
            "evil.example.com",
            "127.0.0.2",  # Hors allowlist canonique {127.0.0.1, ::1, localhost}
        )
        for invalid_host in invalid_hosts:
            with self.subTest(host=invalid_host):
                with self.assertRaises(ValidationError):
                    VaultSettings(host=invalid_host)

    def test_port_validation_bounds(self) -> None:
        """Ports valides : 1 à 65535."""
        for invalid_port in (0, -1, 65536, 99999):
            with self.subTest(port=invalid_port):
                with self.assertRaises(ValidationError):
                    VaultSettings(port=invalid_port)

        valid = VaultSettings(port=443)
        self.assertEqual(valid.port, 443)

    def test_load_settings_from_environment_variables(self) -> None:
        """La configuration doit lire les variables d'environnement préfixées HEIMDALL_VAULT_."""
        env = {
            "HEIMDALL_VAULT_HOST": "localhost",
            "HEIMDALL_VAULT_PORT": "9443",
            "HEIMDALL_VAULT_ENABLE_DOCS": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            loaded = VaultSettings()
            self.assertEqual(loaded.host, "localhost")
            self.assertEqual(loaded.port, 9443)
            self.assertTrue(loaded.enable_docs)

    def test_get_settings_singleton_and_aliases(self) -> None:
        """get_settings retourne l'instance et Settings est un alias valide."""
        self.assertIs(Settings, VaultSettings)
        s1 = get_settings()
        s2 = get_settings()
        self.assertIs(s1, s2)

    def test_create_app_factory_applies_settings_parameter(self) -> None:
        """create_app applique les paramètres transmis et ne les ignore pas."""
        custom_settings = VaultSettings(host="::1", port=8445, enable_docs=True)
        custom_app = create_app(custom_settings)
        self.assertIsInstance(custom_app, FastAPI)
        self.assertEqual(custom_app.title, "Heimdall Vault API")
        self.assertIs(custom_app.state.settings, custom_settings)
        self.assertEqual(custom_app.docs_url, "/docs")
        self.assertEqual(custom_app.openapi_url, "/openapi.json")

    def test_health_response_model_rejects_extra_fields(self) -> None:
        """Le modèle de santé interdit tout champ supplémentaire."""
        with self.assertRaises(ValidationError):
            HealthResponse(status="ok", extra="unauthorized")  # type: ignore[call-arg]

    def test_run_server_is_callable(self) -> None:
        """run_server est défini et appelable comme point d'entrée."""
        self.assertTrue(callable(run_server))


if __name__ == "__main__":
    unittest.main()
