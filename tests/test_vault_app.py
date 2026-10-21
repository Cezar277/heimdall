"""Tests unitaires et d'intégration du squelette Vault FastAPI (ticket #25).

Vérifie l'application FastAPI, la configuration via variables d'environnement
(pydantic-settings), l'absence de fuite d'informations sur `/api/v1/health`,
la désactivation par défaut de la documentation OpenAPI (/docs, /openapi.json),
la conformité contractuelle du schéma OpenAPI sur `/api/v1/health`,
l'absence d'alias non contractuel `/health` (404),
la gestion d'erreurs contractuelle (400, 401, 403, 404, 405, 409, 429, 503)
sans enveloppe framework, l'allowlist d'en-têtes d'erreurs, l'immunité au spoofing
X-Forwarded-For, et le middleware fail-closed sur la boucle locale.
"""

import ast
import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import patch

import uvicorn  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ValidationError

import heimdall.vault.auth as vault_auth_module
from heimdall.vault.app import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    HealthResponse,
    InMemorySecretStore,
    NotFoundError,
    QuotaExceededError,
    SecretCreate,
    SecretMetadata,
    SecretRead,
    Settings,
    VaultSettings,
    create_app,
    generate_api_key,
    get_app,
    get_settings,
    hash_api_key,
    run_server,
)
from heimdall.vault.crypto import VaultCipher, generate_encryption_key
from heimdall.vault.database import DatabaseUnavailableError, count_secrets, db_session
from heimdall.vault.ratelimit import SqliteRateLimiter
from heimdall.vault.store import SqliteSecretStore


class VaultAppTests(unittest.IsolatedAsyncioTestCase):
    """Tests du comportement HTTP du serveur Vault."""

    async def asyncSetUp(self) -> None:
        # Construction paresseuse (LOW revue) : aucun `get_app()` à la collecte ;
        # sous HEIMDALL_ENV=production sans pepper/KEK, seule l'exécution échoue.
        self.app = get_app()
        if hasattr(self.app.state, "secret_store"):
            await self.app.state.secret_store.clear()
        self.test_api_key = generate_api_key()
        self.app.state.register_api_key(self.test_api_key, "demo")
        self.transport = ASGITransport(app=self.app, client=("127.0.0.1", 54321))
        self.client = AsyncClient(
            transport=self.transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": self.test_api_key},
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def test_health_returns_200_ok(self) -> None:
        """Critère d'acceptation : `/api/v1/health` répond 200 avec {'status': 'ok'}."""
        response = await self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_root_health_returns_404_not_found(self) -> None:
        """Le contrat OpenAPI ne définit que /api/v1/health ; /health renvoie 404."""
        response = await self.client.get("/health")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"code": "not_found", "message": "Ressource introuvable"},
        )

    async def test_health_does_not_leak_version_or_configuration(self) -> None:
        """Mitigation Information Disclosure (STRIDE) : pas de version ni de config."""
        response = await self.client.get("/api/v1/health")
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
            transport=ASGITransport(app=dev_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as dev_client:
            docs_resp = await dev_client.get("/docs")
            self.assertEqual(docs_resp.status_code, 200)
            openapi_resp = await dev_client.get("/openapi.json")
            self.assertEqual(openapi_resp.status_code, 200)
            schema = openapi_resp.json()

            # La route /api/v1/health est présente et conforme au contrat openapi.yaml
            self.assertIn("/api/v1/health", schema["paths"])
            responses = schema["paths"]["/api/v1/health"]["get"]["responses"]
            for expected_code in ("200", "405", "429", "500", "503", "default"):
                self.assertIn(expected_code, responses)
            # 403 est un rejet fail-closed de niveau transport, maintenu hors du contrat applicatif
            self.assertNotIn("403", responses)

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
        response = await self.client.post("/api/v1/health")
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
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
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
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
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
            transport=ASGITransport(
                app=test_app, client=("127.0.0.1", 54321), raise_app_exceptions=False
            ),
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

    async def test_exception_headers_allowlist_filtering(self) -> None:
        """Seuls Allow, Retry-After (1-3600) et Connection: close sont retransmis."""
        test_app = create_app()

        @test_app.get("/trigger-headers")
        async def trigger_headers() -> None:
            raise HTTPException(
                status_code=429,
                headers={
                    "Retry-After": "60",
                    "X-Injected-Header": "forbidden_data",
                },
            )

        @test_app.get("/trigger-bad-retry/{val}")
        async def trigger_bad_retry(val: str) -> None:
            raise HTTPException(
                status_code=429,
                headers={"Retry-After": val},  # Hors borne 1-3600 (ex: 9999, 0, -5)
            )

        @test_app.get("/trigger-connection-close")
        async def trigger_connection_close() -> None:
            raise HTTPException(status_code=503, headers={"Connection": "close"})

        @test_app.get("/trigger-connection-injected")
        async def trigger_connection_injected() -> None:
            raise HTTPException(
                status_code=503,
                headers={"Connection": "keep-alive, X-Injected: 1"},
            )

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as c:
            resp = await c.get("/trigger-headers")
            self.assertEqual(resp.headers.get("retry-after"), "60")
            self.assertNotIn("x-injected-header", resp.headers)

            for bad_retry_val in ("9999", "0", "-5"):
                with self.subTest(bad_retry=bad_retry_val):
                    resp_bad = await c.get(f"/trigger-bad-retry/{bad_retry_val}")
                    self.assertEqual(resp_bad.status_code, 429)
                    self.assertNotIn("retry-after", resp_bad.headers)

            # Connection: close admis tel quel ; toute autre valeur reste filtrée.
            resp_close = await c.get("/trigger-connection-close")
            self.assertEqual(resp_close.headers.get("connection"), "close")
            resp_injected = await c.get("/trigger-connection-injected")
            self.assertNotIn("connection", resp_injected.headers)

    async def test_exception_headers_retry_after_non_integer_types(self) -> None:
        """Garde-fou : un Retry-After non convertible (None, liste, etc.) ne lève pas 500."""
        test_app = create_app()

        @test_app.get("/trigger-none-retry")
        async def trigger_none_retry() -> None:
            raise HTTPException(
                status_code=429,
                headers={"Retry-After": None},  # type: ignore[dict-item]
            )

        @test_app.get("/trigger-list-retry")
        async def trigger_list_retry() -> None:
            raise HTTPException(
                status_code=429,
                headers={"Retry-After": [1, 2]},  # type: ignore[dict-item]
            )

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as c:
            for endpoint in ("/trigger-none-retry", "/trigger-list-retry"):
                with self.subTest(endpoint=endpoint):
                    resp = await c.get(endpoint)
                    self.assertEqual(resp.status_code, 429)
                    self.assertEqual(
                        resp.json(),
                        {"code": "rate_limited", "message": "Trop de requêtes"},
                    )
                    self.assertNotIn("retry-after", resp.headers)

    async def test_non_loopback_client_rejected_by_middleware(self) -> None:
        """Défense en profondeur : une requête d'une IP distante/LAN est bloquée en 403."""
        test_app = create_app()
        transport = ASGITransport(app=test_app, client=("192.168.1.50", 54321))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8443") as c:
            response = await c.get("/api/v1/health")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                response.json(),
                {"code": "forbidden", "message": "Accès interdit"},
            )

    async def test_loopback_middleware_rejects_127_0_0_2_and_non_loopback(self) -> None:
        """Le middleware applique la même allowlist stricte que validate_host."""
        test_app = create_app()
        for forbidden_client in (
            ("127.0.0.2", 54321),
            ("192.168.1.10", 54321),
            ("10.0.0.1", 54321),
            ("8.8.8.8", 54321),
        ):
            with self.subTest(client=forbidden_client):
                transport = ASGITransport(app=test_app, client=forbidden_client)
                async with AsyncClient(
                    transport=transport, base_url="http://127.0.0.1:8443"
                ) as c:
                    resp = await c.get("/api/v1/health")
                    self.assertEqual(resp.status_code, 403)
                    self.assertEqual(
                        resp.json(),
                        {"code": "forbidden", "message": "Accès interdit"},
                    )

    async def test_loopback_middleware_accepts_valid_loopback_clients(self) -> None:
        """Le middleware autorise 127.0.0.1, ::1 et ::ffff:127.0.0.1."""
        test_app = create_app()
        for valid_client in (
            ("127.0.0.1", 54321),
            ("::1", 54321),
            ("::ffff:127.0.0.1", 54321),
        ):
            with self.subTest(client=valid_client):
                transport = ASGITransport(app=test_app, client=valid_client)
                async with AsyncClient(
                    transport=transport, base_url="http://127.0.0.1:8443"
                ) as c:
                    resp = await c.get("/api/v1/health")
                    self.assertEqual(resp.status_code, 200)
                    self.assertEqual(resp.json(), {"status": "ok"})

    async def test_middleware_fail_closed_when_client_missing_or_empty(self) -> None:
        """Garde fail-closed : client absent ou vide rejeté en 403."""
        test_app = create_app()
        for bad_client in (None, ("", 0)):
            with self.subTest(client=bad_client):
                transport = ASGITransport(app=test_app, client=bad_client)  # type: ignore[arg-type]
                async with AsyncClient(
                    transport=transport, base_url="http://127.0.0.1:8443"
                ) as c:
                    response = await c.get("/api/v1/health")
                    self.assertEqual(response.status_code, 403)

    async def test_spoofed_x_forwarded_for_is_ignored(self) -> None:
        """Invariant 6 : X-Forwarded-For falsifié ne permet pas de contourner le 403."""
        test_app = create_app()
        # Client externe 192.168.1.50 prétendant être 127.0.0.1
        transport = ASGITransport(app=test_app, client=("192.168.1.50", 54321))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8443") as c:
            response = await c.get(
                "/api/v1/health",
                headers={"X-Forwarded-For": "127.0.0.1", "Forwarded": "for=127.0.0.1"},
            )
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
            "127.0.0.2",
        )
        for invalid_host in invalid_hosts:
            with self.subTest(host=invalid_host):
                with self.assertRaises(ValidationError):
                    VaultSettings(host=invalid_host)

        # Invariant anti-reflet : l'entrée opérateur ne doit pas fuiter dans le message d'erreur
        for canary in ("192.168.1.10", "CANARY_SECRET_HOST", "localhost.evil.com"):
            with self.subTest(canary=canary):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(host=canary)
                self.assertNotIn(canary, ctx.exception.errors()[0]["msg"])

    def test_port_validation_bounds(self) -> None:
        """Ports valides : 1 à 65535."""
        for invalid_port in (0, -1, 65536, 99999):
            with self.subTest(port=invalid_port):
                with self.assertRaises(ValidationError):
                    VaultSettings(port=invalid_port)

        valid = VaultSettings(port=443)
        self.assertEqual(valid.port, 443)

    def test_tls_settings_require_absolute_existing_pair(self) -> None:
        """TLS : certificat et clé vont ensemble, en chemins absolus existants."""
        with tempfile.TemporaryDirectory() as tmp:
            certfile = Path(tmp) / "server.crt"
            keyfile = Path(tmp) / "server.key"
            certfile.write_text("dummy-cert", encoding="utf-8")
            keyfile.write_text("dummy-key", encoding="utf-8")

            valid = VaultSettings(
                ssl_certfile=str(certfile),
                ssl_keyfile=str(keyfile),
            )
            self.assertEqual(valid.ssl_certfile, str(certfile))
            self.assertEqual(valid.ssl_keyfile, str(keyfile))

            with self.assertRaises(ValidationError):
                VaultSettings(ssl_certfile=str(certfile))
            with self.assertRaises(ValidationError):
                VaultSettings(ssl_keyfile=str(keyfile))
            with self.assertRaises(ValidationError):
                VaultSettings(
                    ssl_certfile="relative-server.crt",
                    ssl_keyfile=str(keyfile),
                )
            with self.assertRaises(ValidationError):
                VaultSettings(
                    ssl_certfile=str(Path(tmp) / "missing.crt"),
                    ssl_keyfile=str(keyfile),
                )

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
        pinned_target = Path(tempfile.gettempdir()) / "heimdall_factory_test_vault.db"
        custom_settings = VaultSettings(
            host="::1", port=8445, enable_docs=True, db_path=str(pinned_target)
        )
        custom_app = create_app(custom_settings)
        self.assertIsInstance(custom_app, FastAPI)
        self.assertEqual(custom_app.title, "Heimdall Vault API")
        self.assertIs(custom_app.state.settings, custom_settings)
        self.assertEqual(custom_app.state.db_path, pinned_target)
        self.assertEqual(custom_app.docs_url, "/docs")
        self.assertEqual(custom_app.openapi_url, "/openapi.json")

    def test_create_app_refuses_memory_db_path(self) -> None:
        """Remarque 2 (v4) — create_app refuse ':memory:' (base éphémère, fail-closed).

        Couvre le vecteur `HEIMDALL_VAULT_DB_PATH=:memory:` : pydantic-settings le
        mappe sur `settings.db_path`, le refus intervient au figeage du chemin.
        """
        with self.assertRaises(ValueError) as ctx:
            create_app(VaultSettings(db_path=":memory:"))
        self.assertIn(":memory:", str(ctx.exception))
        self.assertIn("fail-closed", str(ctx.exception))

    def test_create_app_refuses_relative_db_path(self) -> None:
        """Revue v5 (double source) — create_app refuse un chemin relatif (fail-closed).

        Un chemin relatif dépend du CWD : le serveur et la CLI lancés depuis deux
        répertoires ouvriraient deux bases différentes sans erreur. Le message reste
        générique : il ne reflète jamais le chemin fourni.
        """
        for relative in ("relative_app_vault.db", "subdir/../pinned_vault.db"):
            with self.subTest(relative=relative):
                with self.assertRaises(ValueError) as ctx:
                    create_app(VaultSettings(db_path=relative))
                self.assertIn("absolu", str(ctx.exception))
                self.assertNotIn(relative, str(ctx.exception))

    def test_create_app_normalizes_dotdot_segments_lexically(self) -> None:
        """`..` absolu normalisé lexicalement avant figeage (sans suivre de symlink).

        Les gardes `lstat` de la couche DB continuent de refuser tout ancêtre lié à
        l'ouverture (`database._assert_not_symlink`).
        """
        base = Path(tempfile.gettempdir())
        custom_settings = VaultSettings(db_path=str(base / "subdir" / ".." / "pinned_vault.db"))
        custom_app = create_app(custom_settings)
        pinned = custom_app.state.db_path
        self.assertIsInstance(pinned, Path)
        assert isinstance(pinned, Path)
        self.assertTrue(pinned.is_absolute())
        self.assertNotIn("..", pinned.parts)
        self.assertEqual(pinned, base / "pinned_vault.db")

    def test_health_response_model_rejects_extra_fields(self) -> None:
        """Le modèle de santé interdit tout champ supplémentaire."""
        with self.assertRaises(ValidationError):
            HealthResponse(status="ok", extra="unauthorized")  # type: ignore[call-arg]

    def test_forbidden_error_model(self) -> None:
        """Le modèle ForbiddenError est conforme au contrat d'erreur.

        `code` et `message` sont OBLIGATOIRES (aucune valeur par défaut) : le
        schéma OpenAPI publié doit donc exposer `required: [code, message]`,
        comme l'exige `openapi.yaml`.
        """
        err = ForbiddenError(code="forbidden", message="Accès interdit")
        self.assertEqual(err.code, "forbidden")
        self.assertEqual(err.message, "Accès interdit")
        with self.assertRaises(ValidationError):
            ForbiddenError(extra="unauthorized")  # type: ignore[call-arg]
        # Sans `code` ni `message` : le modèle refuse (champs obligatoires).
        with self.assertRaises(ValidationError):
            ForbiddenError()  # type: ignore[call-arg]
        with self.assertRaises(ValidationError):
            ForbiddenError(code="forbidden")  # type: ignore[call-arg]

    def test_run_server_is_callable(self) -> None:
        """run_server est défini et appelable comme point d'entrée."""
        self.assertTrue(callable(run_server))

    @patch("uvicorn.run")
    def test_run_server_passes_hardened_uvicorn_arguments(
        self, mock_uvicorn_run: unittest.mock.MagicMock
    ) -> None:
        """run_server configure uvicorn avec anti-spoofing et sans fingerprinting.

        Factory explicite : l'instance FastAPI construite (singleton `get_app`)
        est passée en objet, jamais via une chaîne d'import (aucune création
        différée par uvicorn).
        """
        with patch.dict(os.environ, {"HEIMDALL_ENV": "test"}, clear=False):
            run_server()
        mock_uvicorn_run.assert_called_once()
        positional, keywords = mock_uvicorn_run.call_args
        self.assertIs(positional[0], get_app())
        self.assertEqual(
            keywords,
            {
                "host": "127.0.0.1",
                "port": 8443,
                # Un seul worker : le backend mémoire est mono-processus (#65).
                "workers": 1,
                "ssl_certfile": None,
                "ssl_keyfile": None,
                "proxy_headers": False,
                "forwarded_allow_ips": "",
                "server_header": False,
                "date_header": False,
            },
        )

    @patch("uvicorn.run")
    def test_run_server_requires_tls_in_production(
        self, mock_uvicorn_run: unittest.mock.MagicMock
    ) -> None:
        """En production, le lanceur refuse le HTTP en clair (fail-closed)."""
        settings = VaultSettings(api_key_pepper="p" * 32)
        with (
            patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=False),
            patch("heimdall.vault.app.get_settings", return_value=settings),
        ):
            with self.assertRaises(ValueError) as ctx:
                run_server()
        self.assertIn("TLS", str(ctx.exception))
        mock_uvicorn_run.assert_not_called()

    @patch("uvicorn.run")
    def test_run_server_checks_tls_before_any_app_construction(
        self, mock_uvicorn_run: unittest.mock.MagicMock
    ) -> None:
        """Ordre fail-closed : le refus TLS précède toute construction d'app/disque.

        Suggestion revue (optionnelle) : en production sans TLS, `run_server`
        lève avant `get_app()` — aucun backend résolu, aucun `vault.db`, aucun
        pepper généré. Verrouille l'ordre TLS-avant-disque.
        """
        settings = VaultSettings(api_key_pepper="p" * 32)
        with (
            patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=False),
            patch("heimdall.vault.app.get_settings", return_value=settings),
            patch(
                "heimdall.vault.app.get_app",
                side_effect=AssertionError("get_app() ne doit pas être appelé avant le garde TLS"),
            ) as mock_get_app,
        ):
            with self.assertRaises(ValueError) as ctx:
                run_server()
        self.assertIn("TLS", str(ctx.exception))
        mock_get_app.assert_not_called()
        mock_uvicorn_run.assert_not_called()

    @patch("uvicorn.run")
    def test_run_server_passes_tls_files_in_production(
        self, mock_uvicorn_run: unittest.mock.MagicMock
    ) -> None:
        """Le lanceur transmet certificat et clé TLS à uvicorn en production."""
        with tempfile.TemporaryDirectory() as tmp:
            certfile = Path(tmp) / "server.crt"
            keyfile = Path(tmp) / "server.key"
            certfile.write_text("dummy-cert", encoding="utf-8")
            keyfile.write_text("dummy-key", encoding="utf-8")
            settings = VaultSettings(
                api_key_pepper="p" * 32,
                ssl_certfile=str(certfile),
                ssl_keyfile=str(keyfile),
            )
            with (
                patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=False),
                patch("heimdall.vault.app.get_settings", return_value=settings),
            ):
                run_server()
        mock_uvicorn_run.assert_called_once()
        positional, keywords = mock_uvicorn_run.call_args
        self.assertIs(positional[0], get_app())
        self.assertEqual(
            keywords,
            {
                "host": "127.0.0.1",
                "port": 8443,
                "workers": 1,
                "ssl_certfile": str(certfile),
                "ssl_keyfile": str(keyfile),
                "proxy_headers": False,
                "forwarded_allow_ips": "",
                "server_header": False,
                "date_header": False,
            },
        )

    def test_documented_launch_command_uses_dedicated_runner(self) -> None:
        """La documentation doit recommander exclusivement python -m heimdall.vault.app."""
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("python -m heimdall.vault.app", readme)
        self.assertNotIn("uvicorn heimdall.vault.app:app", readme)

        app_code = (root / "heimdall" / "vault" / "app.py").read_text(encoding="utf-8")
        self.assertIn("python -m heimdall.vault.app", app_code)
        self.assertNotIn("uvicorn heimdall.vault.app:app", app_code)
        # Factory explicite (LOW revue : pas de test sur chaîne fragile) :
        # run_server passe l'objet construit par get_app() à uvicorn.run,
        # vérifié par AST (insensible au reformatage).
        tree = ast.parse(app_code)
        run_server_def = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "run_server"
        )
        uvicorn_calls = [
            node
            for node in ast.walk(run_server_def)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and node.args
            and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Name)
            and node.args[0].func.id == "get_app"
        ]
        self.assertEqual(len(uvicorn_calls), 1)

    def test_health_schema_response_codes_match_openapi_yaml(self) -> None:
        """Le schéma OpenAPI runtime de /api/v1/health correspond au contrat openapi.yaml."""
        spec_file = Path(__file__).resolve().parents[1] / "openapi.yaml"
        spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
        expected_responses = set(spec["paths"]["/api/v1/health"]["get"]["responses"].keys())

        dev_app = create_app(VaultSettings(enable_docs=True))
        actual_responses = set(
            dev_app.openapi()["paths"]["/api/v1/health"]["get"]["responses"].keys()
        )
        self.assertEqual(actual_responses, expected_responses)

    def test_state_schema_response_codes_match_openapi_yaml(self) -> None:
        """Le schéma OpenAPI runtime de .../state correspond au contrat (getSecretState).

        Ferme l'écart contrat/implémentation LOW revue : la route expose
        exactement les réponses du contrat (200 SecretMetadata + no-store,
        mêmes erreurs que la lecture).
        """
        spec_file = Path(__file__).resolve().parents[1] / "openapi.yaml"
        spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
        state_path = "/api/v1/secrets/{project}/{env}/{name}/state"
        expected_responses = set(spec["paths"][state_path]["get"]["responses"].keys())

        dev_app = create_app(VaultSettings(enable_docs=True))
        actual_paths = dev_app.openapi()["paths"]
        self.assertIn(state_path, actual_paths)
        actual_responses = set(actual_paths[state_path]["get"]["responses"].keys())
        self.assertEqual(actual_responses, expected_responses)
        self.assertEqual(
            actual_paths[state_path]["get"]["operationId"], "getSecretState"
        )


class VaultSecretStateRouteTests(unittest.IsolatedAsyncioTestCase):
    """Tests contractuels de GET .../state : métadonnées sans la valeur."""

    async def asyncSetUp(self) -> None:
        self.test_app = create_app(VaultSettings(api_key_pepper="state_pepper_" + "s" * 20))
        self.test_api_key = generate_api_key()
        self.test_app.state.register_api_key(self.test_api_key, "demo")
        self.transport = ASGITransport(app=self.test_app, client=("127.0.0.1", 54321))
        self.client = AsyncClient(
            transport=self.transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": self.test_api_key},
        )
        created = await self.client.post(
            "/api/v1/secrets",
            json={"project": "demo", "env": "dev", "name": "STATE_KEY", "value": "v"},
        )
        self.assertEqual(created.status_code, 201)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def test_state_returns_metadata_without_value_and_no_store(self) -> None:
        """200 avec métadonnées seules, Cache-Control: no-store, sans `value`."""
        response = await self.client.get("/api/v1/secrets/demo/dev/STATE_KEY/state")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        body = response.json()
        self.assertEqual(
            body, {"project": "demo", "env": "dev", "name": "STATE_KEY", "status": "vaulte"}
        )
        self.assertNotIn("value", body)

    async def test_state_unauthorized_without_key(self) -> None:
        """401 sans clé (le contrat exigeait 401, l'app répondait 404 routeur)."""
        async with AsyncClient(
            transport=ASGITransport(app=self.test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as anonymous:
            response = await anonymous.get("/api/v1/secrets/demo/dev/STATE_KEY/state")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(), {"code": "unauthorized", "message": "Authentification requise"}
        )

    async def test_state_forbidden_for_other_project(self) -> None:
        """403 quand la clé appartient à un autre projet (même contrôle que lecture)."""
        other_key = generate_api_key()
        self.test_app.state.register_api_key(other_key, "other")
        async with AsyncClient(
            transport=ASGITransport(app=self.test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": other_key},
        ) as other_client:
            response = await other_client.get("/api/v1/secrets/demo/dev/STATE_KEY/state")
        self.assertEqual(response.status_code, 403)

    async def test_state_not_found_for_unknown_secret(self) -> None:
        """404 quand le secret n'existe pas (pas de fuite d'existence)."""
        response = await self.client.get("/api/v1/secrets/demo/dev/MISSING_KEY/state")
        self.assertEqual(response.status_code, 404)

    async def test_state_rejects_invalid_path(self) -> None:
        """400 sur paramètre de chemin invalide, sans écho."""
        response = await self.client.get("/api/v1/secrets/BAD!/dev/STATE_KEY/state")
        self.assertEqual(response.status_code, 400)

class VaultSecretsRouteTests(unittest.IsolatedAsyncioTestCase):
    """Tests contractuels des routes POST et GET secrets (ticket #63)."""

    async def asyncSetUp(self) -> None:
        # Construction paresseuse (LOW revue) : voir VaultAppTests.
        self.app = get_app()
        if hasattr(self.app.state, "secret_store"):
            await self.app.state.secret_store.clear()
        self.test_api_key = generate_api_key()
        self.app.state.register_api_key(self.test_api_key, "demo")
        self.transport = ASGITransport(app=self.app, client=("127.0.0.1", 54321))
        self.client = AsyncClient(
            transport=self.transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": self.test_api_key},
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def test_models_instantiation_and_validation(self) -> None:
        """Les modèles Pydantic de secret et d'erreur s'instancient et valident conformément."""
        create_m = SecretCreate(
            project="demo", env="dev", name="KEY_NAME", value="secret_val"
        )
        self.assertEqual(create_m.project, "demo")

        meta_m = SecretMetadata(
            project="demo", env="dev", name="KEY_NAME", status="vaulte"
        )
        self.assertEqual(meta_m.status, "vaulte")

        read_m = SecretRead(
            project="demo", env="dev", name="KEY_NAME", status="vaulte", value="secret_val"
        )
        self.assertEqual(read_m.value, "secret_val")

        err400 = BadRequestError(code="bad_request", message="Requête invalide")
        self.assertEqual(err400.code, "bad_request")

        err404 = NotFoundError(code="not_found", message="Ressource introuvable")
        self.assertEqual(err404.code, "not_found")

        err409 = ConflictError(code="conflict", message="Secret déjà existant")
        self.assertEqual(err409.code, "conflict")

    async def test_post_secret_success_201(self) -> None:
        """POST /api/v1/secrets crée un secret, répond 201 avec Cache-Control: no-store."""
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "DEMO_KEY",
            "value": "super_secret_value",
        }
        response = await self.client.post("/api/v1/secrets", json=payload)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        body = response.json()
        self.assertEqual(body["project"], "demo")
        self.assertEqual(body["env"], "dev")
        self.assertEqual(body["name"], "DEMO_KEY")
        self.assertEqual(body["status"], "vaulte")
        self.assertNotIn("value", body)

    async def test_get_secret_success_200(self) -> None:
        """GET /api/v1/secrets/{project}/{env}/{name} répond 200 avec Cache-Control: no-store."""
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "MY_SECRET",
            "value": "secret_data_123",
        }
        post_res = await self.client.post("/api/v1/secrets", json=payload)
        self.assertEqual(post_res.status_code, 201)

        get_res = await self.client.get("/api/v1/secrets/demo/dev/MY_SECRET")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.headers.get("cache-control"), "no-store")
        body = get_res.json()
        self.assertEqual(
            body,
            {
                "project": "demo",
                "env": "dev",
                "name": "MY_SECRET",
                "status": "vaulte",
                "value": "secret_data_123",
            },
        )

    async def test_post_secret_conflict_409(self) -> None:
        """POST d'un secret déjà existant retourne 409 conflict sans écrasement."""
        payload = {
            "project": "demo",
            "env": "prod",
            "name": "API_TOKEN",
            "value": "initial_token",
        }
        res1 = await self.client.post("/api/v1/secrets", json=payload)
        self.assertEqual(res1.status_code, 201)

        conflict_payload = {
            "project": "demo",
            "env": "prod",
            "name": "API_TOKEN",
            "value": "overwritten_attempt",
        }
        res2 = await self.client.post("/api/v1/secrets", json=conflict_payload)
        self.assertEqual(res2.status_code, 409)
        self.assertEqual(
            res2.json(),
            {"code": "conflict", "message": "Secret déjà existant"},
        )

        # Vérifie que la valeur initiale n'a pas été écrasée
        get_res = await self.client.get("/api/v1/secrets/demo/prod/API_TOKEN")
        self.assertEqual(get_res.json()["value"], "initial_token")

    async def test_get_secret_not_found_404(self) -> None:
        """GET d'un secret inexistant retourne 404 not_found contractuel."""
        response = await self.client.get("/api/v1/secrets/demo/dev/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"code": "not_found", "message": "Ressource introuvable"},
        )

    async def test_post_secret_validation_errors_400(self) -> None:
        """POST avec entrée invalide retourne 400 bad_request normalisé."""
        valid_base = {
            "project": "demo",
            "env": "dev",
            "name": "SECRET_KEY",
            "value": "valid_value",
        }
        invalid_cases = [
            ({**valid_base, "project": "Demo"}, "majuscule dans project"),
            ({**valid_base, "project": "1demo"}, "chiffre au début de project"),
            ({**valid_base, "project": ""}, "project vide"),
            ({**valid_base, "project": "a" * 65}, "project trop long (> 64)"),
            ({**valid_base, "project": "demo$"}, "caractère spécial dans project"),
            ({**valid_base, "env": "Dev"}, "majuscule dans env"),
            ({**valid_base, "env": "1dev"}, "chiffre au début de env"),
            ({**valid_base, "env": ""}, "env vide"),
            ({**valid_base, "env": "a" * 33}, "env trop long (> 32)"),
            ({**valid_base, "name": "secret_key"}, "minuscules dans name"),
            ({**valid_base, "name": "A"}, "name trop court (< 2)"),
            ({**valid_base, "name": "A" * 65}, "name trop long (> 64)"),
            ({**valid_base, "name": "_KEY"}, "name débutant par underscore"),
            ({**valid_base, "name": "1KEY"}, "name débutant par chiffre"),
            ({**valid_base, "value": ""}, "value vide"),
            ({**valid_base, "value": "a" * 65537}, "value trop longue (> 65536)"),
            ({**valid_base, "extra": "forbidden"}, "propriété supplémentaire"),
        ]

        for payload, description in invalid_cases:
            with self.subTest(case=description):
                res = await self.client.post("/api/v1/secrets", json=payload)
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

    async def test_post_secret_invalid_json_400(self) -> None:
        """POST avec JSON mal formé retourne 400 bad_request sans écho."""
        res = await self.client.post(
            "/api/v1/secrets",
            content=b"invalid json {{{",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_get_secret_path_validation_errors_400(self) -> None:
        """GET avec paramètre d'URL non conforme au pattern retourne 400 bad_request."""
        invalid_paths = [
            "/api/v1/secrets/Demo/dev/KEY_NAME",
            "/api/v1/secrets/demo/Dev/KEY_NAME",
            "/api/v1/secrets/demo/dev/key_name",
            "/api/v1/secrets/demo/dev/K",
            f"/api/v1/secrets/{'a'*65}/dev/KEY",
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                res = await self.client.get(path)
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

    async def test_post_secret_body_size_limit_content_length_400(self) -> None:
        """Corps > 1 Mio (1 048 576 octets) via Content-Length est rejeté avec HTTP 400."""
        oversized = b"x" * 1_048_577
        res = await self.client.post(
            "/api/v1/secrets",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_post_secret_body_size_limit_stream_chunked_400(self) -> None:
        """Corps > 1 Mio en flux/chunked est interrompu et rejeté avec HTTP 400."""
        async def chunk_generator() -> AsyncGenerator[bytes, None]:
            yield b"x" * 600_000
            yield b"x" * 600_000

        res = await self.client.post(
            "/api/v1/secrets",
            content=chunk_generator(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_secrets_routes_method_not_allowed_405(self) -> None:
        """Méthodes non déclarées sur /api/v1/secrets retournent 405 avec en-tête Allow."""
        res_get = await self.client.get("/api/v1/secrets")
        self.assertEqual(res_get.status_code, 405)
        self.assertEqual(
            res_get.json(),
            {"code": "method_not_allowed", "message": "Méthode non autorisée"},
        )
        self.assertIn("Allow", res_get.headers)

        res_delete = await self.client.delete("/api/v1/secrets")
        self.assertEqual(res_delete.status_code, 405)

        res_post_item = await self.client.post("/api/v1/secrets/demo/dev/KEY_NAME")
        self.assertEqual(res_post_item.status_code, 405)
        self.assertIn("Allow", res_post_item.headers)

    def test_secrets_schema_response_codes_match_openapi_yaml(self) -> None:
        """Les schémas OpenAPI runtime de POST et GET secrets correspondent à openapi.yaml."""
        spec_file = Path(__file__).resolve().parents[1] / "openapi.yaml"
        spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))

        dev_app = create_app(VaultSettings(enable_docs=True))
        openapi_paths = dev_app.openapi()["paths"]

        expected_post = set(spec["paths"]["/api/v1/secrets"]["post"]["responses"].keys())
        actual_post = set(openapi_paths["/api/v1/secrets"]["post"]["responses"].keys())
        self.assertEqual(actual_post, expected_post)

        expected_get = set(
            spec["paths"]["/api/v1/secrets/{project}/{env}/{name}"]["get"]["responses"].keys()
        )
        actual_get = set(
            openapi_paths["/api/v1/secrets/{project}/{env}/{name}"]["get"]["responses"].keys()
        )
        self.assertEqual(actual_get, expected_get)

    async def test_identifiers_reject_newlines_and_carriage_returns(self) -> None:
        """Les identifiants avec saut de ligne ou retour chariot sont rejetés avec HTTP 400."""
        valid_base = {
            "project": "demo",
            "env": "dev",
            "name": "MY_KEY",
            "value": "secret_val",
        }
        invalid_posts = [
            ({**valid_base, "project": "demo\n"}, "saut de ligne dans project"),
            ({**valid_base, "project": "demo\r"}, "retour chariot dans project"),
            ({**valid_base, "env": "dev\n"}, "saut de ligne dans env"),
            ({**valid_base, "env": "dev\r"}, "retour chariot dans env"),
            ({**valid_base, "name": "MY_KEY\n"}, "saut de ligne dans name"),
            ({**valid_base, "name": "MY_KEY\r"}, "retour chariot dans name"),
        ]
        for payload, description in invalid_posts:
            with self.subTest(post_case=description):
                res = await self.client.post("/api/v1/secrets", json=payload)
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

        invalid_gets = [
            "/api/v1/secrets/demo%0A/dev/MY_KEY",
            "/api/v1/secrets/demo%0D/dev/MY_KEY",
            "/api/v1/secrets/demo/dev%0A/MY_KEY",
            "/api/v1/secrets/demo/dev%0D/MY_KEY",
            "/api/v1/secrets/demo/dev/MY_KEY%0A",
            "/api/v1/secrets/demo/dev/MY_KEY%0D",
        ]
        for path in invalid_gets:
            with self.subTest(get_case=path):
                res = await self.client.get(path)
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

    async def test_post_secret_rejects_nul_bytes_in_value(self) -> None:
        """La valeur secrète ne doit pas contenir d'octet NUL (\\x00)."""
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "NUL_KEY",
            "value": "valeur\x00corrompue",
        }
        res = await self.client.post("/api/v1/secrets", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_secret_value_is_nfc_normalized_and_nul_rejected(self) -> None:
        """Décision #62 : la valeur est canonisée en NFC, le NUL reste refusé.

        La remarque de revue « SecretValue multiligne : refus ``\\x00`` seul OU
        normalisation NFC » est tranchée : les DEUX règles s'appliquent. La forme
        Unicode canonique (NFC) est stockée, donc deux écritures visuellement
        identiques d'un même secret ne peuvent plus diverger en base ni produire
        deux empreintes d'intégrité différentes. La valeur reste multiligne
        (retours à la ligne autorisés par le contrat) et n'est jamais journalisée.
        """
        composed = "caf\u00e9"  # « café » en NFC
        decomposed = "cafe\u0301"  # « café » en NFD (e + accent combinant)
        self.assertNotEqual(composed, decomposed)

        created = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "NFC_KEY",
                "value": decomposed,
            },
        )
        self.assertEqual(created.status_code, 201)
        self.assertNotIn("value", created.json())

        read = await self.client.get("/api/v1/secrets/demo/dev/NFC_KEY")
        self.assertEqual(read.status_code, 200)
        self.assertEqual(read.json()["value"], composed)

        # La valeur multiligne reste acceptée et restituée à l'identique.
        multiline = "première ligne\nseconde ligne\n"
        created_multiline = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "MULTILINE_KEY",
                "value": multiline,
            },
        )
        self.assertEqual(created_multiline.status_code, 201)
        read_multiline = await self.client.get("/api/v1/secrets/demo/dev/MULTILINE_KEY")
        self.assertEqual(read_multiline.status_code, 200)
        self.assertEqual(read_multiline.json()["value"], multiline)

        # Le NUL reste refusé après normalisation.
        rejected = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "NFC_NUL_KEY",
                "value": "cafe\u0301\x00",
            },
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(
            rejected.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

        # Défense en profondeur : le store canonise aussi, hors chemin HTTP.
        direct_store = InMemorySecretStore()
        await direct_store.create("demo", "dev", "DIRECT_NFC", decomposed)
        direct = await direct_store.get("demo", "dev", "DIRECT_NFC")
        assert direct is not None
        self.assertEqual(direct["value"], composed)

    async def test_post_secret_body_size_limit_exact_boundaries(self) -> None:
        """Exactement 1 Mio (1 048 576 octets) est accepté (201), 1 048 577 octets rejeté (400)."""
        base_doc = {
            "project": "demo",
            "env": "dev",
            "name": "BOUNDARY_TEST",
            "value": "val",
        }
        raw_json = json.dumps(base_doc).encode("utf-8")
        padding_len = 1_048_576 - len(raw_json)
        self.assertGreater(padding_len, 0)
        exact_1mb = raw_json + (b" " * padding_len)
        self.assertEqual(len(exact_1mb), 1_048_576)

        # 1 048 576 octets : accepté
        res_exact = await self.client.post(
            "/api/v1/secrets",
            content=exact_1mb,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res_exact.status_code, 201)

        # 1 048 577 octets : rejeté
        oversized_1byte = exact_1mb + b" "
        self.assertEqual(len(oversized_1byte), 1_048_577)
        res_over = await self.client.post(
            "/api/v1/secrets",
            content=oversized_1byte,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res_over.status_code, 400)
        self.assertEqual(
            res_over.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_post_secret_chunked_stream_interruption_verifies_aborted_read(self) -> None:
        """L'interruption de flux s'arrête net dès dépassement sans lire les tronçons suivants."""
        third_chunk_read = False

        async def chunk_generator() -> AsyncGenerator[bytes, None]:
            nonlocal third_chunk_read
            yield b"x" * 600_000
            yield b"x" * 600_000
            third_chunk_read = True
            yield b"x" * 600_000

        res = await self.client.post(
            "/api/v1/secrets",
            content=chunk_generator(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )
        self.assertFalse(third_chunk_read)

    async def test_post_secret_concurrent_race_condition(self) -> None:
        """Des dépôts concurrents identiques aboutissent à exactement 1x 201 et Nx 409."""
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "CONCURRENT_KEY",
            "value": "initial_concurrent_secret",
        }

        async def send_post() -> int:
            res = await self.client.post("/api/v1/secrets", json=payload)
            return res.status_code

        statuses = await asyncio.gather(*[send_post() for _ in range(5)])
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 4)

        get_res = await self.client.get("/api/v1/secrets/demo/dev/CONCURRENT_KEY")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["value"], "initial_concurrent_secret")

    async def test_canary_secret_never_reflected_in_error_responses(self) -> None:
        """Aucune chaîne secrète ne doit transparaître dans les erreurs (400, 404, 409)."""
        canary = "canary_sk_live_SECRET_VALUE_12345"

        # 400 : champ invalide dans le payload
        res_400 = await self.client.post(
            "/api/v1/secrets",
            json={"project": "InvalidProject", "env": "dev", "name": "KEY", "value": canary},
        )
        self.assertEqual(res_400.status_code, 400)
        self.assertNotIn(canary, res_400.text)

        # 400 : octet NUL dans la valeur
        res_nul = await self.client.post(
            "/api/v1/secrets",
            json={"project": "demo", "env": "dev", "name": "KEY", "value": f"{canary}\x00leak"},
        )
        self.assertEqual(res_nul.status_code, 400)
        self.assertNotIn(canary, res_nul.text)

        # 201 puis 409 conflict
        await self.client.post(
            "/api/v1/secrets",
            json={"project": "demo", "env": "dev", "name": "CANARY_KEY", "value": canary},
        )
        conflict_canary = "second_canary_attempt_99999"
        res_409 = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "CANARY_KEY",
                "value": conflict_canary,
            },
        )
        self.assertEqual(res_409.status_code, 409)
        self.assertNotIn(canary, res_409.text)
        self.assertNotIn(conflict_canary, res_409.text)

        # 404 GET
        res_404 = await self.client.get("/api/v1/secrets/demo/dev/CANARY_NOT_FOUND")
        self.assertEqual(res_404.status_code, 404)
        self.assertNotIn(canary, res_404.text)

    def test_secrets_schema_headers_match_openapi_yaml(self) -> None:
        """Les en-têtes déclarés dans OpenAPI runtime incluent Cache-Control et Retry-After."""
        dev_app = create_app(VaultSettings(enable_docs=True))
        openapi_paths = dev_app.openapi()["paths"]

        post_responses = openapi_paths["/api/v1/secrets"]["post"]["responses"]
        self.assertIn("headers", post_responses["201"])
        self.assertIn("Cache-Control", post_responses["201"]["headers"])
        self.assertIn("headers", post_responses["429"])
        self.assertIn("Retry-After", post_responses["429"]["headers"])

        get_responses = (
            openapi_paths["/api/v1/secrets/{project}/{env}/{name}"]["get"]["responses"]
        )
        self.assertIn("headers", get_responses["200"])
        self.assertIn("Cache-Control", get_responses["200"]["headers"])
        self.assertIn("headers", get_responses["429"])
        self.assertIn("Retry-After", get_responses["429"]["headers"])

    async def test_get_secret_encoded_path_traversal_and_slash_rejected(self) -> None:
        """Les traversées encodées (%2e%2e) et slashs (%2F) sont rejetés sans fuite."""
        invalid_encoded_paths = [
            "/api/v1/secrets/%2e%2e/dev/MY_KEY",
            "/api/v1/secrets/%2E%2E/dev/MY_KEY",
            "/api/v1/secrets/demo/%2e%2e/MY_KEY",
            "/api/v1/secrets/demo/dev/%2e%2e",
            "/api/v1/secrets/demo%2Fevil/dev/MY_KEY",
            "/api/v1/secrets/demo/dev%2Fevil/MY_KEY",
            "/api/v1/secrets/demo/dev/MY%2FKEY",
        ]
        for path in invalid_encoded_paths:
            with self.subTest(path=path):
                res = await self.client.get(path)
                self.assertIn(res.status_code, (400, 404))
                body = res.json()
                self.assertIn(body.get("code"), ("bad_request", "not_found"))
                self.assertNotIn("value", body)
                self.assertNotIn("%2e", res.text.lower())
                self.assertNotIn("%2f", res.text.lower())

    async def test_in_memory_secret_store_mutation_defensive_copy(self) -> None:
        """La mutation d'un dict retourné par store.get() ne corrompt pas le store."""
        store = InMemorySecretStore()
        await store.create(project="demo", env="dev", name="SAFE_KEY", value="original_value")
        record = await store.get(project="demo", env="dev", name="SAFE_KEY")
        self.assertIsNotNone(record)
        assert record is not None
        record["value"] = "tampered_value"
        record["status"] = "corrupted"

        re_fetched = await store.get(project="demo", env="dev", name="SAFE_KEY")
        self.assertIsNotNone(re_fetched)
        assert re_fetched is not None
        self.assertEqual(re_fetched["value"], "original_value")
        self.assertEqual(re_fetched["status"], "vaulte")

    def test_single_worker_documented_for_memory_store(self) -> None:
        """La documentation de InMemorySecretStore et run_server affirme workers=1."""
        self.assertIn("workers=1", InMemorySecretStore.__doc__ or "")
        self.assertIn("workers=1", run_server.__doc__ or "")

    async def test_in_memory_secret_store_saturation_quota_rejected(self) -> None:
        """La saturation des quotas par projet et globaux lève QuotaExceededError (anti-DoS)."""
        # Quota par projet
        project_store = InMemorySecretStore(max_secrets=10, max_secrets_per_project=2)
        await project_store.create(project="p1", env="dev", name="K1", value="v1")
        await project_store.create(project="p1", env="dev", name="K2", value="v2")
        with self.assertRaises(QuotaExceededError) as ctx:
            await project_store.create(project="p1", env="dev", name="K3", value="v3")
        self.assertIn("Quota maximal", str(ctx.exception))

        # Un autre projet n'est pas affamé
        await project_store.create(project="p2", env="dev", name="K1", value="v1")

        # Quota global
        global_store = InMemorySecretStore(max_secrets=2, max_secrets_per_project=10)
        await global_store.create(project="p1", env="dev", name="K1", value="v1")
        await global_store.create(project="p2", env="dev", name="K1", value="v1")
        with self.assertRaises(QuotaExceededError) as ctx_global:
            await global_store.create(project="p3", env="dev", name="K1", value="v1")
        self.assertIn("Capacité maximale", str(ctx_global.exception))

    async def test_sqlite_backend_persists_ciphertext_and_shares_state(self) -> None:
        """SQLite chiffré : ciphertext en base, lecture inter-workers et 409 partagé."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            settings = VaultSettings(
                storage_backend="sqlite",
                kek=generate_encryption_key(),
                db_path=str(db_path),
                api_key_pepper="sqlite_shared_pepper_" + "x" * 24,
            )
            canary = "SQLITE_CANARY_VALUE_91b7"
            payload = {
                "project": "demo",
                "env": "dev",
                "name": "SHARED_KEY",
                "value": canary,
            }
            api_key = generate_api_key()

            app1 = create_app(settings)
            self.assertIsInstance(app1.state.rate_limiter, SqliteRateLimiter)
            app1.state.register_api_key(api_key, "demo")
            transport1 = ASGITransport(app=app1, client=("127.0.0.1", 54321))
            async with AsyncClient(
                transport=transport1,
                base_url="http://127.0.0.1:8443",
                headers={"X-Heimdall-API-Key": api_key},
            ) as client1:
                created = await client1.post("/api/v1/secrets", json=payload)
                self.assertEqual(created.status_code, 201)

            with db_session(db_path) as conn:
                row = conn.execute(
                    "SELECT encrypted_value FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "SHARED_KEY"),
                ).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            self.assertNotIn(canary, row["encrypted_value"])
            self.assertNotIn(canary, db_path.read_bytes().decode("utf-8", errors="ignore"))

            # Second "worker" : même base, même KEK, clé API retrouvée en SQLite.
            app2 = create_app(settings)
            transport2 = ASGITransport(app=app2, client=("127.0.0.1", 54322))
            async with AsyncClient(
                transport=transport2,
                base_url="http://127.0.0.1:8443",
                headers={"X-Heimdall-API-Key": api_key},
            ) as client2:
                read = await client2.get("/api/v1/secrets/demo/dev/SHARED_KEY")
                self.assertEqual(read.status_code, 200)
                self.assertEqual(read.json()["value"], canary)
                duplicate = await client2.post("/api/v1/secrets", json=payload)
                self.assertEqual(duplicate.status_code, 409)
                self.assertNotIn(canary, duplicate.text)

    async def test_rate_limiting_by_validated_key_with_retry_after(self) -> None:
        """Le débit d'une clé validée est borné (429 + Retry-After borné)."""
        settings = VaultSettings(
            api_key_pepper="rate_limit_key_pepper_" + "k" * 20,
            rate_limit_per_key=2,
            rate_limit_per_peer=1_000,
            rate_limit_global=1_000,
            rate_limit_window_seconds=60,
        )
        rate_app = create_app(settings)
        api_key = generate_api_key()
        rate_app.state.register_api_key(api_key, "demo")
        transport = ASGITransport(app=rate_app, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": api_key},
        ) as client:
            for index in range(2):
                res = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": f"RATE_KEY_{index}",
                        "value": "v",
                    },
                )
                self.assertEqual(res.status_code, 201)
            limited = await client.post(
                "/api/v1/secrets",
                json={
                    "project": "demo",
                    "env": "dev",
                    "name": "RATE_KEY_LIMITED",
                    "value": "v",
                },
            )
            self.assertEqual(limited.status_code, 429)
            self.assertEqual(limited.headers.get("retry-after"), "60")
            self.assertEqual(
                limited.json(),
                {"code": "rate_limited", "message": "Trop de requêtes"},
            )
            # La santé relève des limites publiques pair/global, pas du bucket clé.
            health = await client.get("/api/v1/health")
            self.assertEqual(health.status_code, 200)

    async def test_rate_limiting_counts_400_against_validated_key_bucket(self) -> None:
        """Une requête 400 portant une clé validée consomme aussi le bucket de cette clé."""
        settings = VaultSettings(
            api_key_pepper="rate_limit_400_key_pepper_" + "r" * 20,
            rate_limit_per_key=1,
            rate_limit_per_peer=100,
            rate_limit_global=100,
            rate_limit_window_seconds=60,
        )
        rate_app = create_app(settings)
        api_key = generate_api_key()
        rate_app.state.register_api_key(api_key, "demo")
        transport = ASGITransport(app=rate_app, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": api_key},
        ) as client:
            invalid = await client.post("/api/v1/secrets", json={})
            self.assertEqual(invalid.status_code, 400)
            limited = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "AFTER_400", "value": "v"},
            )
            self.assertEqual(limited.status_code, 429)

    async def test_rate_limiting_counts_invalid_requests(self) -> None:
        """Les 400 et 401 consomment le budget pair avant tout routage."""
        settings_400 = VaultSettings(
            api_key_pepper="rate_limit_400_pepper_" + "p" * 20,
            require_auth=False,
            rate_limit_per_key=1_000,
            rate_limit_per_peer=2,
            rate_limit_global=1_000,
            rate_limit_window_seconds=60,
        )
        app_400 = create_app(settings_400)
        transport_400 = ASGITransport(app=app_400, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport_400,
            base_url="http://127.0.0.1:8443",
        ) as client:
            for _ in range(2):
                res = await client.post("/api/v1/secrets", json={})
                self.assertEqual(res.status_code, 400)
            limited = await client.get("/api/v1/health")
            self.assertEqual(limited.status_code, 429)
            self.assertEqual(limited.headers.get("retry-after"), "60")

        settings_401 = VaultSettings(
            api_key_pepper="rate_limit_401_pepper_" + "q" * 20,
            rate_limit_per_key=1_000,
            rate_limit_per_peer=1,
            rate_limit_global=1_000,
            rate_limit_window_seconds=60,
        )
        app_401 = create_app(settings_401)
        transport_401 = ASGITransport(app=app_401, client=("127.0.0.1", 54322))
        async with AsyncClient(
            transport=transport_401,
            base_url="http://127.0.0.1:8443",
        ) as client:
            unauthorized = await client.get("/api/v1/secrets/demo/dev/KEY")
            self.assertEqual(unauthorized.status_code, 401)
            limited = await client.get("/api/v1/health")
            self.assertEqual(limited.status_code, 429)

    async def test_sqlite_rate_limiter_is_shared_between_workers(self) -> None:
        """Deux instances SqliteRateLimiter partagent les buckets (pas de N × limite)."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            kwargs = {
                "per_key": 1,
                "per_peer": 100,
                "global_limit": 100,
                "window_seconds": 60,
            }
            worker_one = SqliteRateLimiter(db_path, **kwargs)
            worker_two = SqliteRateLimiter(db_path, **kwargs)

            allowed, retry = worker_one.check("127.0.0.1", "a" * 64)
            self.assertTrue(allowed)
            self.assertEqual(retry, 0)

            allowed, retry = worker_two.check("127.0.0.1", "a" * 64)
            self.assertFalse(allowed)
            self.assertGreaterEqual(retry, 1)
            self.assertLessEqual(retry, 60)

            # Le même bucket est réinitialisé pour tous les workers.
            worker_two.clear()
            allowed, _ = worker_one.check("127.0.0.1", "a" * 64)
            self.assertTrue(allowed)

    async def test_post_secret_capacity_exhaustion_returns_429(self) -> None:
        """Le dépassement de quota retourne HTTP 429 trop de requêtes avec Retry-After."""
        bounded_store = InMemorySecretStore(max_secrets=1, max_secrets_per_project=1)
        test_app = create_app(secret_store=bounded_store)
        test_key = generate_api_key()
        test_app.state.register_api_key(test_key, "demo")
        transport = ASGITransport(app=test_app, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": test_key},
        ) as client:
            res1 = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "FIRST_KEY", "value": "val1"},
            )
            self.assertEqual(res1.status_code, 201)

            res2 = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "OVERFLOW_KEY", "value": "val2"},
            )
            self.assertEqual(res2.status_code, 429)
            self.assertEqual(res2.headers.get("retry-after"), "60")
            self.assertEqual(
                res2.json(),
                {"code": "rate_limited", "message": "Trop de requêtes"},
            )

    async def test_capacity_429_retry_is_useless_until_capacity_freed(self) -> None:
        """Le 429 de CAPACITÉ n'est pas transitoire : le retry échoue (documenté #62).

        Le contrat impose `Retry-After` sur tout 429, mais la saturation du
        quota de stockage ne se résorbe pas : sans route DELETE dans le contrat
        #63, aucun emplacement ne peut être libéré. Le client qui réessaie
        (même après le délai annoncé) reçoit donc à nouveau 429. Cette sémantique
        est documentée dans le code (store + handler) et pinnée ici.
        """
        bounded_store = InMemorySecretStore(max_secrets=1, max_secrets_per_project=1)
        test_app = create_app(secret_store=bounded_store)
        test_key = generate_api_key()
        test_app.state.register_api_key(test_key, "demo")
        transport = ASGITransport(app=test_app, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": test_key},
        ) as client:
            first = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "CAPACITY_KEY", "value": "val1"},
            )
            self.assertEqual(first.status_code, 201)

            for attempt in ("RETRY_1", "RETRY_2"):
                retry = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": attempt,
                        "value": "val2",
                    },
                )
                self.assertEqual(retry.status_code, 429)
                self.assertEqual(retry.headers.get("retry-after"), "60")
                self.assertEqual(
                    retry.json(),
                    {"code": "rate_limited", "message": "Trop de requêtes"},
                )

        # La sémantique « retry inutile » est documentée dans le code lui-même.
        store_doc = SqliteSecretStore.__doc__ or ""
        self.assertIn("INUTILE", store_doc)
        self.assertIn("TODO(#156)", store_doc)
        self.assertIn("transitoire", store_doc)

    async def test_post_secret_malformed_content_length_rejected_400(self) -> None:
        """Un en-tête Content-Length malformé, négatif ou dupliqué est rejeté avec HTTP 400."""
        valid_payload = json.dumps(
            {"project": "demo", "env": "dev", "name": "VALID_KEY", "value": "secret"}
        ).encode("utf-8")

        # Valeurs individuelles malformées
        malformed_dict_headers = [
            {"Content-Length": "not_a_number"},
            {"Content-Length": "-50"},
            {"Content-Length": "10, 20"},
        ]
        for headers in malformed_dict_headers:
            with self.subTest(malformed_header=headers):
                res = await self.client.post(
                    "/api/v1/secrets",
                    content=valid_payload,
                    headers={"Content-Type": "application/json", **headers},
                )
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

        # En-têtes dupliqués (anti-smuggling : même avec petites valeurs)
        duplicate_header_cases = [
            [
                ("Content-Type", "application/json"),
                ("Content-Length", "10"),
                ("Content-Length", "20"),
            ],
            [
                ("Content-Type", "application/json"),
                ("Content-Length", "10"),
                ("Content-Length", "10"),
            ],
        ]
        for headers_list in duplicate_header_cases:
            with self.subTest(duplicate_headers=headers_list):
                res = await self.client.post(
                    "/api/v1/secrets",
                    content=valid_payload,
                    headers=headers_list,
                )
                self.assertEqual(res.status_code, 400)
                self.assertEqual(
                    res.json(),
                    {"code": "bad_request", "message": "Requête invalide"},
                )

    async def test_in_memory_secret_store_never_keeps_plaintext(self) -> None:
        """Le dict interne ne contient que du ciphertext AES-GCM, jamais la valeur brute."""
        store = InMemorySecretStore()
        canary = "CANARY_IN_MEMORY_PLAINTEXT_8f3a"
        await store.create(project="demo", env="dev", name="CANARY_KEY", value=canary)
        internal = next(iter(store._secrets.values()))
        self.assertNotEqual(internal.get("encrypted_value"), canary)
        self.assertNotIn(canary, json.dumps(internal))
        self.assertNotIn(canary, repr(store._secrets))
        fetched = await store.get("demo", "dev", "CANARY_KEY")
        self.assertIsNotNone(fetched)
        assert fetched is not None
        self.assertEqual(fetched["value"], canary)

    async def test_in_memory_secret_store_create_returns_metadata_only(self) -> None:
        """store.create() ne retourne jamais le plaintext, seulement les métadonnées."""
        store = InMemorySecretStore()
        created = await store.create(
            project="demo", env="dev", name="SAFE_CREATE", value="initial"
        )
        self.assertNotIn("value", created)
        self.assertEqual(
            created,
            {"project": "demo", "env": "dev", "name": "SAFE_CREATE", "status": "vaulte"},
        )
        created["status"] = "tampered_status"

        re_fetched = await store.get(project="demo", env="dev", name="SAFE_CREATE")
        self.assertIsNotNone(re_fetched)
        assert re_fetched is not None
        self.assertEqual(re_fetched["value"], "initial")
        self.assertEqual(re_fetched["status"], "vaulte")

    async def test_in_memory_secret_store_clear_releases_quota(self) -> None:
        """Après saturation, clear() libère la capacité (quota de stockage, pas débit)."""
        store = InMemorySecretStore(max_secrets=1, max_secrets_per_project=1)
        await store.create(project="demo", env="dev", name="FIRST_KEY", value="v1")
        with self.assertRaises(QuotaExceededError):
            await store.create(project="demo", env="dev", name="SECOND_KEY", value="v2")
        await store.clear()
        created = await store.create(project="demo", env="dev", name="SECOND_KEY", value="v2")
        self.assertNotIn("value", created)
        re_fetched = await store.get("demo", "dev", "SECOND_KEY")
        self.assertIsNotNone(re_fetched)
        assert re_fetched is not None
        self.assertEqual(re_fetched["value"], "v2")

    def test_in_memory_secret_store_documents_quota_followup(self) -> None:
        """Le docstring de InMemorySecretStore documente le suivi quota/pagination (#156)."""
        doc = InMemorySecretStore.__doc__ or ""
        self.assertIn("TODO(#156)", doc)
        self.assertIn("quota", doc)

    async def test_body_size_limit_rejections_close_connection(self) -> None:
        """Tout rejet du middleware de taille porte Connection: close (keep-alive sûr).

        Les octets non consommés resteraient sinon dans le tampon de la connexion
        réutilisée (risque de désynchronisation/smuggling, RFC 9112). La requête
        suivante est servie normalement, preuve d'absence d'état corrompu.
        """
        oversized = b"x" * 1_048_577
        res_oversized = await self.client.post(
            "/api/v1/secrets",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res_oversized.status_code, 400)
        self.assertEqual(res_oversized.headers.get("connection"), "close")
        self.assertEqual(
            res_oversized.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

        async def chunk_generator() -> AsyncGenerator[bytes, None]:
            yield b"x" * 600_000
            yield b"x" * 600_000

        res_chunked = await self.client.post(
            "/api/v1/secrets",
            content=chunk_generator(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res_chunked.status_code, 400)
        self.assertEqual(res_chunked.headers.get("connection"), "close")

        # Transfer-Encoding + Content-Length simultanés (anti-smuggling).
        res_smuggle = await self.client.post(
            "/api/v1/secrets",
            content=b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Transfer-Encoding", "chunked"),
                ("Content-Length", "2"),
            ],
        )
        self.assertEqual(res_smuggle.status_code, 400)
        self.assertEqual(res_smuggle.headers.get("connection"), "close")

        # Content-Length dupliqué (anti-smuggling).
        res_duplicated = await self.client.post(
            "/api/v1/secrets",
            content=b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Length", "2"),
            ],
        )
        self.assertEqual(res_duplicated.status_code, 400)
        self.assertEqual(res_duplicated.headers.get("connection"), "close")

        # Requête suivante : toujours servie correctement.
        follow_up = await self.client.get("/api/v1/health")
        self.assertEqual(follow_up.status_code, 200)

    async def test_sqlite_secret_store_refuses_memory_mode(self) -> None:
        """:memory: est refusé fail-closed par le store SQLite (base éphémère silencieuse)."""
        cipher = VaultCipher(b"k" * 32)
        for memory_path in (":memory:", "  :memory:  ", Path(":memory:")):
            with self.subTest(db_path=memory_path):
                with self.assertRaises(ValueError) as ctx:
                    SqliteSecretStore(memory_path, cipher)
                self.assertIn(":memory:", str(ctx.exception))

    def test_sqlite_secret_store_documents_atomic_quota(self) -> None:
        """Le quota SQLite est documenté comme atomique inter-workers."""
        doc = SqliteSecretStore.__doc__ or ""
        self.assertIn("BEGIN IMMEDIATE", doc)
        self.assertIn("quota", doc)
        self.assertIn("inter-workers", doc)

    async def test_sqlite_quota_is_atomic_inter_workers(self) -> None:
        """Quota SQLite atomique : aucun dépassement entre workers concurrents.

        Trois instances ``SqliteSecretStore`` partagent le même fichier et
        démarrent ensemble avec ``max_secrets=2``. ``BEGIN IMMEDIATE`` acquiert
        le verrou d'écriture avant ``count_secrets()`` : deux créations
        réussissent au maximum, la troisième obtient ``QuotaExceededError``.
        Les valeurs restent déchiffrables et l'unicité SQLite intacte.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"Q" * 32)
            worker_count = 3
            max_secrets = 2
            stores = [
                SqliteSecretStore(
                    db_path,
                    cipher,
                    max_secrets=max_secrets,
                    max_secrets_per_project=10,
                )
                for _ in range(worker_count)
            ]

            start = threading.Barrier(worker_count)
            results: list[dict[str, str]] = []
            errors: list[Exception] = []

            def create_in_worker(store: SqliteSecretStore, index: int) -> None:
                # Sous contention, le perdant du BEGIN IMMEDIATE lève une erreur
                # transitoire (database is locked → DatabaseUnavailableError) :
                # retry court pour laisser la sérialisation trancher entre
                # succès et refus de quota. Seule une erreur non transitoire
                # est enregistrée comme refus définitif.
                start.wait(timeout=5)
                for _ in range(20):
                    try:
                        results.append(
                            asyncio.run(
                                store.create(
                                    project="demo",
                                    env="dev",
                                    name=f"SECRET_{index}",
                                    value=f"value-{index}",
                                )
                            )
                        )
                        return
                    except DatabaseUnavailableError:
                        time.sleep(0.05)
                    except Exception as exc:  # pragma: no cover - diagnostic
                        errors.append(exc)
                        return
                errors.append(DatabaseUnavailableError("verrou persistant après retries"))

            threads = [
                threading.Thread(target=create_in_worker, args=(store, index))
                for index, store in enumerate(stores)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
            self.assertFalse([thread.name for thread in threads if thread.is_alive()])

            # Exactement deux créations acceptées, la troisième refusée par le quota.
            self.assertEqual(len(results), max_secrets)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], QuotaExceededError)
            for result in results:
                self.assertNotIn("value", result)
            with db_session(db_path) as conn:
                self.assertEqual(count_secrets(conn), max_secrets)
                rows = conn.execute(
                    "SELECT name FROM secrets ORDER BY name"
                ).fetchall()
            created_names = [row["name"] for row in rows]
            self.assertEqual(len(created_names), max_secrets)
            allowed_names = {f"SECRET_{index}" for index in range(worker_count)}
            self.assertTrue(set(created_names) <= allowed_names)

            # Les valeurs acceptées restent déchiffrables par une nouvelle instance.
            reader = SqliteSecretStore(
                db_path,
                cipher,
                max_secrets=max_secrets,
                max_secrets_per_project=10,
            )
            for name in created_names:
                index = name.rsplit("_", 1)[1]
                record = await reader.get("demo", "dev", name)
                self.assertIsNotNone(record)
                assert record is not None
                self.assertEqual(record["value"], f"value-{index}")

            # Le quota reste appliqué après la transaction concurrente.
            with self.assertRaises(QuotaExceededError):
                await reader.create("demo", "dev", "SECRET_AFTER", "value-after")

    async def test_sqlite_quota_never_exceeded_with_two_workers(self) -> None:
        """Deux workers sur le même fichier, ``max_secrets=2`` : jamais de dépassement.

        Scénario explicitement demandé par la revue : deux ``SqliteSecretStore``
        partagent un fichier SQLite de ``tmp/`` avec une capacité de 2. Les
        créations concurrentes sont sérialisées par ``BEGIN IMMEDIATE`` (verrou
        d'écriture acquis AVANT ``count_secrets()``) : la base ne contient
        jamais plus de 2 secrets et la troisième création est refusée par le
        quota, sans corruption.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"W" * 32)
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
                # transitoire (database is locked → DatabaseUnavailableError) :
                # retry court, sans jamais dépasser le quota.
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
                threading.Thread(target=create_in_worker, args=(store_one, "SECRET_A")),
                threading.Thread(target=create_in_worker, args=(store_two, "SECRET_B")),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
            self.assertFalse([thread.name for thread in threads if thread.is_alive()])
            self.assertEqual(refused, [])
            self.assertEqual(len(created), 2)

            with db_session(db_path) as conn:
                self.assertEqual(count_secrets(conn), max_secrets)

            # La capacité est pleine : toute création supplémentaire est refusée.
            for store in (store_one, store_two):
                with self.assertRaises(QuotaExceededError):
                    await store.create("demo", "dev", "SECRET_C", "v")
            with db_session(db_path) as conn:
                self.assertEqual(count_secrets(conn), max_secrets)

    def test_cipher_fingerprint_uses_dedicated_subkey_bound_to_triplet(self) -> None:
        """L'empreinte n'utilise jamais la KEK comme clé HMAC et lie le triplet.

        Invariant 5 : clé HMAC distincte de la clé maîtresse. Deux valeurs
        identiques sous des triplets distincts produisent des empreintes
        distinctes, non corrélables depuis la seule base.
        """
        cipher = VaultCipher(b"K" * 32)
        other_cipher = VaultCipher(b"L" * 32)
        aad_one = VaultCipher.aad("demo", "dev", "SECRET_ONE")
        aad_two = VaultCipher.aad("demo", "dev", "SECRET_TWO")
        plaintext = b"same-secret-value"

        fp_one = cipher.fingerprint(plaintext, aad=aad_one)
        fp_two = cipher.fingerprint(plaintext, aad=aad_two)
        self.assertEqual(len(fp_one), 64)
        self.assertNotEqual(fp_one, fp_two)

        # Déterministe pour un même (KEK, triplet, valeur).
        self.assertEqual(cipher.fingerprint(plaintext, aad=aad_one), fp_one)

        # KEK distincte -> empreinte distincte.
        self.assertNotEqual(other_cipher.fingerprint(plaintext, aad=aad_one), fp_one)

        # La KEK utilisée directement en HMAC ne reproduit pas l'empreinte.
        kek_direct_hmac = hmac.new(b"K" * 32, plaintext, hashlib.sha256).hexdigest()
        self.assertNotEqual(fp_one, kek_direct_hmac)

    async def test_sqlite_store_fingerprints_do_not_correlate_equal_values(self) -> None:
        """Les empreintes persistées diffèrent pour une même valeur sur deux triplets."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, VaultCipher(b"F" * 32))
            await store.create("demo", "dev", "SECRET_ONE", "shared-value")
            await store.create("demo", "dev", "SECRET_TWO", "shared-value")
            with db_session(db_path) as conn:
                rows = conn.execute(
                    "SELECT name, encrypted_value, fingerprint FROM secrets "
                    "WHERE project_id = ? ORDER BY name",
                    ("demo",),
                ).fetchall()
            self.assertEqual([row["name"] for row in rows], ["SECRET_ONE", "SECRET_TWO"])
            fingerprints = {row["name"]: row["fingerprint"] for row in rows}
            self.assertNotEqual(fingerprints["SECRET_ONE"], fingerprints["SECRET_TWO"])
            # Ni la valeur en clair, ni un HMAC KEK direct ne sont persistés.
            self.assertNotIn("shared-value", rows[0]["encrypted_value"])
            kek_direct_hmac = hmac.new(b"F" * 32, b"shared-value", hashlib.sha256).hexdigest()
            self.assertNotIn(kek_direct_hmac, set(fingerprints.values()))


    async def test_invalid_api_key_returns_401_unauthorized(self) -> None:
        """Une clé API invalide ou vide retourne 401 sans exposer d'oracle."""
        invalid_cases = [
            "invalid-key-token",
            "   ",
            "wrong_key_12345",
        ]
        for bad_key in invalid_cases:
            with self.subTest(bad_key=bad_key):
                headers = {"X-Heimdall-API-Key": bad_key}
                post_resp = await self.client.post(
                    "/api/v1/secrets",
                    json={"project": "demo", "env": "dev", "name": "AUTH_KEY", "value": "val"},
                    headers=headers,
                )
                self.assertEqual(post_resp.status_code, 401)
                self.assertEqual(
                    post_resp.json(),
                    {"code": "unauthorized", "message": "Authentification requise"},
                )
                get_resp = await self.client.get(
                    "/api/v1/secrets/demo/dev/AUTH_KEY",
                    headers=headers,
                )
                self.assertEqual(get_resp.status_code, 401)
                self.assertEqual(
                    get_resp.json(),
                    {"code": "unauthorized", "message": "Authentification requise"},
                )

    async def test_unhashable_api_key_returns_generic_401_without_echo(self) -> None:
        """Une clé non hachable (ex. surrogate) reste un 401 générique, jamais un 500."""
        canary = "CANARY_UNENCODABLE_API_KEY"
        test_app = create_app()
        with patch.object(
            vault_auth_module,
            "hash_project_api_key",
            side_effect=ValueError(f"clé invalide : {canary}"),
        ):
            transport = ASGITransport(app=test_app, client=("127.0.0.1", 54321))
            async with AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1:8443",
                headers={"X-Heimdall-API-Key": canary},
            ) as client:
                response = await client.get("/api/v1/secrets/demo/dev/UNHASHABLE")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {"code": "unauthorized", "message": "Authentification requise"},
        )
        self.assertNotIn(canary, response.text)

    async def test_api_key_full_scan_is_memoized_once_per_request(self) -> None:
        """Le full-scan d'empreintes est mémoïsé par requête (anti-amplification CPU).

        Le middleware de débit réalise le parcours complet pour choisir le bucket ;
        l'authentification réutilise ce résultat : un seul parcours mémoire par
        requête, que la clé soit connue ou inconnue. Le backend mémoire ne lit
        aucune base SQLite.
        """
        settings = VaultSettings(api_key_pepper="single_scan_pepper_" + "s" * 24)
        scan_app = create_app(settings)
        raw_key = generate_api_key()
        scan_app.state.register_api_key(raw_key, "demo")

        lookup_calls: list[str] = []
        db_calls: list[str] = []
        real_lookup = vault_auth_module.find_api_key_project
        real_db_lookup = vault_auth_module.lookup_db_api_key

        def counting_lookup(target_app, provided_hash):
            lookup_calls.append(provided_hash)
            return real_lookup(target_app, provided_hash)

        def counting_db_lookup(db_path, provided_hash):
            db_calls.append(provided_hash)
            return real_db_lookup(db_path, provided_hash)

        with patch.object(
            vault_auth_module, "find_api_key_project", counting_lookup
        ), patch.object(vault_auth_module, "lookup_db_api_key", counting_db_lookup):
            transport = ASGITransport(app=scan_app, client=("127.0.0.1", 54321))
            async with AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1:8443",
                headers={"X-Heimdall-API-Key": raw_key},
            ) as client:
                known = await client.get("/api/v1/secrets/demo/dev/ABSENT_KEY")
                self.assertEqual(known.status_code, 404)
                self.assertEqual(len(lookup_calls), 1)
                self.assertEqual(len(db_calls), 0)

                lookup_calls.clear()
                db_calls.clear()
                unknown = await client.get(
                    "/api/v1/secrets/demo/dev/ABSENT_KEY",
                    headers={"X-Heimdall-API-Key": "unknown-key-value"},
                )
                self.assertEqual(unknown.status_code, 401)
                self.assertEqual(len(lookup_calls), 1)
                self.assertEqual(len(db_calls), 0)

    async def test_valid_api_key_allows_secret_creation_and_reading(self) -> None:
        """Une clé API valide autorise la création (201) et la lecture (200) de secrets."""
        test_app = create_app()
        raw_key = generate_api_key()
        test_app.state.register_api_key(raw_key, "demo")

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            headers = {"X-Heimdall-API-Key": raw_key}
            create_resp = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "VALID_AUTH", "value": "topsecret"},
                headers=headers,
            )
            self.assertEqual(create_resp.status_code, 201)
            self.assertEqual(create_resp.headers.get("cache-control"), "no-store")

            read_resp = await client.get(
                "/api/v1/secrets/demo/dev/VALID_AUTH",
                headers=headers,
            )
            self.assertEqual(read_resp.status_code, 200)
            self.assertEqual(read_resp.headers.get("cache-control"), "no-store")
            self.assertEqual(read_resp.json()["value"], "topsecret")

    async def test_cross_project_api_key_returns_403_forbidden(self) -> None:
        """Une clé API valide pour un projet A est rejetée avec 403 sur le projet B."""
        test_app = create_app()
        raw_key = generate_api_key()
        test_app.state.register_api_key(raw_key, "project_alpha")

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            headers = {"X-Heimdall-API-Key": raw_key}
            # Tentative de création sur project_beta avec la clé de project_alpha
            create_resp = await client.post(
                "/api/v1/secrets",
                json={
                    "project": "project_beta",
                    "env": "dev",
                    "name": "CROSS_AUTH",
                    "value": "hacked",
                },
                headers=headers,
            )
            self.assertEqual(create_resp.status_code, 403)
            self.assertEqual(
                create_resp.json(),
                {"code": "forbidden", "message": "Accès interdit"},
            )

            # Tentative de lecture sur project_beta avec la clé de project_alpha
            read_resp = await client.get(
                "/api/v1/secrets/project_beta/dev/CROSS_AUTH",
                headers=headers,
            )
            self.assertEqual(read_resp.status_code, 403)
            self.assertEqual(
                read_resp.json(),
                {"code": "forbidden", "message": "Accès interdit"},
            )

    async def test_require_auth_setting_rejects_missing_key_with_401(self) -> None:
        """Quand require_auth=True, toute requête sans clé est rejetée avec 401."""
        test_app = create_app(VaultSettings(require_auth=True))
        raw_key = generate_api_key()
        test_app.state.register_api_key(raw_key, "demo")

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            # Sans en-tête -> 401
            resp_missing = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "REQ_AUTH", "value": "secret"},
            )
            self.assertEqual(resp_missing.status_code, 401)
            self.assertEqual(
                resp_missing.json(),
                {"code": "unauthorized", "message": "Authentification requise"},
            )

            # Avec clé valide -> 201
            resp_valid = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "REQ_AUTH", "value": "secret"},
                headers={"X-Heimdall-API-Key": raw_key},
            )
            self.assertEqual(resp_valid.status_code, 201)

    def test_generate_api_key_has_adequate_entropy(self) -> None:
        """La clé générée dispose d'au moins 256 bits d'entropie (token_urlsafe(32))."""
        key1 = generate_api_key()
        key2 = generate_api_key()
        self.assertNotEqual(key1, key2)
        # 32 octets encodés en base64 url-safe donnent 43 caractères
        self.assertGreaterEqual(len(key1), 43)

    def test_hash_api_key_uses_hmac_sha256_with_server_pepper(self) -> None:
        """hash_api_key utilise HMAC-SHA256 avec pepper serveur (openapi.yaml:197-200)."""
        custom_pepper = "custom_secret_pepper_value_999_0123456789"
        expected = hmac.new(
            custom_pepper.encode("utf-8"),
            b"my-api-key",
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(hash_api_key("my-api-key", pepper=custom_pepper), expected)

    def test_hash_api_key_distinct_peppers_produce_different_hashes(self) -> None:
        """Deux clés identiques sur des déploiements distincts ne donnent pas le même hash."""
        key = "my-api-key-test"
        hash_1 = hash_api_key(key, pepper="deployment_alpha_pepper_0123456789")
        hash_2 = hash_api_key(key, pepper="deployment_beta_pepper_0123456789")
        self.assertNotEqual(hash_1, hash_2)

    def test_hash_api_key_differs_from_bare_sha256(self) -> None:
        """Le hachage n'est jamais un SHA-256 nu (anti-corrélation inter-déploiements)."""
        key = "my-api-key-test"
        bare_sha = hashlib.sha256(key.encode("utf-8")).hexdigest()
        self.assertNotEqual(hash_api_key(key, pepper="test_pepper_value_123_0123456789"), bare_sha)

    def test_hash_api_key_requires_an_explicit_pepper(self) -> None:
        """Aucun pepper public par défaut : None/vide/blanc est refusé (pas de repli silencieux)."""
        for bad_pepper in (None, "", "   ", b"", b"   ", b"\t\n"):
            with self.subTest(pepper=bad_pepper):
                with self.assertRaises(ValueError):
                    hash_api_key("any-key", pepper=bad_pepper)  # type: ignore[arg-type]

    def test_hash_api_key_accepts_bytes_pepper(self) -> None:
        """Un pepper bytes non vide est accepté et produit le même HMAC que sa forme str."""
        pepper = "pepper_bytes_equivalence_456_0123456789"
        self.assertEqual(
            hash_api_key("any-key", pepper=pepper),
            hash_api_key("any-key", pepper=pepper.encode("utf-8")),
        )

    def test_hash_api_key_rejects_unencodable_key_without_echo(self) -> None:
        """Une clé non encodable UTF-8 lève ValueError générique, sans écho du secret."""
        pepper = "surrogate_pepper_" + "s" * 20
        canary = "\ud800"
        for bad_key in (canary, canary + "a" * 42):
            with self.subTest(length=len(bad_key)):
                with self.assertRaises(ValueError) as ctx:
                    hash_api_key(bad_key, pepper=pepper)
                message = str(ctx.exception)
                self.assertIn("encodage UTF-8 impossible", message)
                self.assertNotIn(canary, message)
                self.assertNotIn(bad_key, message)

    async def test_require_auth_by_default_rejects_missing_key_with_401(self) -> None:
        """create_app() sans argument exige l'auth par défaut (fail-closed, 401)."""
        default_app = create_app()
        async with AsyncClient(
            transport=ASGITransport(app=default_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            resp = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "FAIL_CLOSED", "value": "val"},
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(
                resp.json(),
                {"code": "unauthorized", "message": "Authentification requise"},
            )

    async def test_require_auth_explicit_false_allows_unauthenticated_test_mode(self) -> None:
        """create_app(require_auth=False) permet le bypass pour fixtures de test isolées."""
        test_app = create_app(VaultSettings(require_auth=False))
        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            resp = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "EXPLICIT_TEST", "value": "val"},
            )
            self.assertEqual(resp.status_code, 201)

    def test_create_app_rejects_raw_keys_in_api_key_hashes_dict(self) -> None:
        """create_app refuse les clés brutes sans jamais refléter le secret dans le message."""
        raw_token = generate_api_key()
        with self.assertRaises(ValueError) as ctx:
            create_app(api_key_hashes={raw_token: "demo"})
        self.assertIn("Format d'empreinte de clé API invalide", str(ctx.exception))
        # Mitigation fuite de secret : le candidat brut ne doit JAMAIS fuiter dans le message
        self.assertNotIn(raw_token, str(ctx.exception))

        with self.assertRaises(ValueError) as ctx_deprecated:
            create_app(api_keys={raw_token: "demo"})
        self.assertIn("Format d'empreinte de clé API invalide", str(ctx_deprecated.exception))
        self.assertNotIn(raw_token, str(ctx_deprecated.exception))

        # Passage d'un hash HMAC valide (même pepper que les settings) -> accepté
        pepper = "test_hash_pepper_value_789_0123456789"
        valid_hash = hash_api_key(raw_token, pepper=pepper)
        app_with_hash = create_app(
            settings=VaultSettings(api_key_pepper=pepper),
            api_key_hashes={valid_hash: "demo"},
        )
        self.assertEqual(app_with_hash.state.api_keys[valid_hash], "demo")

        # Ancrage strict : un saut de ligne final ne doit pas être accepté ($ nu le tolère).
        with self.assertRaises(ValueError):
            create_app(
                settings=VaultSettings(api_key_pepper=pepper),
                api_key_hashes={f"{valid_hash}\n": "demo"},
            )

    def test_create_app_rejects_simultaneous_api_key_hashes_and_api_keys(self) -> None:
        """create_app refuse l'usage simultané de api_key_hashes et api_keys (fail-closed)."""
        valid_hash = hash_api_key("some-key", pepper="test_pepper_value_321_0123456789")
        with self.assertRaises(ValueError) as ctx:
            create_app(
                api_key_hashes={valid_hash: "demo"},
                api_keys={valid_hash: "demo"},
            )
        self.assertIn("pas les deux simultanément", str(ctx.exception))

    def test_create_app_rejects_invalid_project_id_for_prehashed_keys(self) -> None:
        """Un project_id hors contrat est refusé (fail-fast) sans refléter la valeur."""
        pepper = "test_project_validation_pepper_0123456789"
        valid_hash = hash_api_key("some-key", pepper=pepper)
        settings = VaultSettings(api_key_pepper=pepper)
        for bad_project in ("../..", "Demo", "demo!", "a" * 65, ""):
            with self.subTest(project=bad_project):
                with self.assertRaises(ValueError) as ctx:
                    create_app(
                        settings=settings,
                        api_key_hashes={valid_hash: bad_project},
                    )
                message = str(ctx.exception)
                self.assertIn("Identifiant de projet invalide", message)
                if bad_project:
                    self.assertNotIn(bad_project, message)

    def test_register_api_key_rejects_invalid_project_id_without_echo(self) -> None:
        """register_api_key valide le project_id contre PROJECT_PATTERN, sans écho."""
        test_app = create_app()
        raw_key = generate_api_key()
        for bad_project in ("../..", "Demo", "demo!", ""):
            with self.subTest(project=bad_project):
                with self.assertRaises(ValueError) as ctx:
                    test_app.state.register_api_key(raw_key, bad_project)
                message = str(ctx.exception)
                self.assertIn("Identifiant de projet invalide", message)
                if bad_project:
                    self.assertNotIn(bad_project, message)
        # Un identifiant conforme est accepté (fail-fast uniquement sur l'invalide).
        test_app.state.register_api_key(raw_key, "demo")
        self.assertEqual(len(test_app.state.api_keys), 1)

    def test_register_api_key_rejects_weak_caller_key(self) -> None:
        """Politique #64 : longueur et diversité alignées sur generate_api_key().

        Le seuil de 43 caractères aligne l'enregistrement manuel sur
        ``secrets.token_urlsafe(32)`` (256 bits), mais ne suffit pas : les motifs
        triviaux de 43 caractères comme ``"a" * 43`` sont aussi refusés, sinon
        ils seraient brute-forçables hors ligne si les empreintes et le pepper
        fuyaient.
        """
        test_app = create_app()
        weak_keys = (
            "a",
            "short-key",
            " " * 32,
            "a" * 32,
            "a" * 42,
            "a" * 43,
            "ab" * 21 + "a",
            "0123456789" * 4 + "012",
        )
        for weak_key in weak_keys:
            with self.subTest(key=weak_key):
                with self.assertRaises(ValueError):
                    test_app.state.register_api_key(weak_key, "demo")
        self.assertEqual(len(test_app.state.api_keys), 0)
        # Une clé générée (43 caractères, diversité suffisante) reste acceptée.
        test_app.state.register_api_key(generate_api_key(), "demo")
        self.assertEqual(len(test_app.state.api_keys), 1)

    def test_register_api_key_rejects_trivial_patterns(self) -> None:
        """Politique opérateur durcie (#64) : alphabet, diversité, motif, suite, clavier.

        Correction de la remarque de revue « seuil de diversité documenté comme
        garde-fou trivial » : le contrôle ne se limite plus à
        ``len(set(...)) >= 12`` (qui acceptait ``"abcdefghijkl" * 4``). Une clé
        doit être un token base64url, d'au moins 43 caractères, avec au moins 16
        caractères distincts, sans aucune période répétitive, sans suite monotone
        de 8+ et sans ligne de clavier connue (motifs ``"abcdefghijkl" * 4``,
        ``"ab" * 21 + "a"``, ``"0123456789" * 4 + "012"``, suites séquentielles
        ``"abcdefgh…"``/``"0123456789…"`` et lignes ``"qwertyuiop…"``/``"azerty…"``
        sont refusés).
        """
        test_app = create_app()
        trivial_keys = (
            # 12 caractères distincts, période 12 : motif prévisible.
            "abcdefghijkl" * 4,
            # 16 caractères distincts mais bloc répété : prévisible aussi.
            "abcdefghijklmnop" * 3,
            # Bloc répété long, alphabet respecté.
            "aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_",
            # Suites monotones longues : alphabet/longueur/diversité OK,
            # ni répétition, mais devinables (seuil 8+).
            "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE",
            "0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYghijklmn",
            "zyxwvutsrqponmlkjihgfedcba9876543210_-ABCab",
            # Exemple revue (5e contrôle) : suite de 8 répétée, refusée
            # (diversité 8 < 16, période 8 et suite monotone cumulés).
            "abcdefgh" * 6,
            # Lignes de clavier (6e contrôle) : ni monotones ni répétitives,
            # mais devinables — y compris en milieu de clé et en sens inverse.
            "qwertyuiopZx9-plQv2Mw4Rt6Yb8Nd3Ff7Hg5Jj1Kk0Ll",
            "azertyuiopZx9-plQv2Mw4Rt6Yb8Nd3Ff7Hg5Jj1Kk0Ll",
            "poiuytrewqZx9-plQv2Mw4Rt6Yb8Nd3Ff7Hg5Jj1Kk0Ll",
            "Zx9-plQv2Mw4qwertyuiopRt6Yb8Nd3Ff7Hg5Jj1Kk0Ll",
        )
        for trivial_key in trivial_keys:
            with self.subTest(key=trivial_key):
                with self.assertRaises(ValueError) as ctx:
                    test_app.state.register_api_key(trivial_key, "demo")
                self.assertNotIn(trivial_key, str(ctx.exception))
        self.assertEqual(len(test_app.state.api_keys), 0)

    def test_register_api_key_rejects_non_base64url_alphabet(self) -> None:
        """L'alphabet de la clé est strict : ni espaces, ni contrôles, ni ponctuation."""
        test_app = create_app()
        forbidden_keys = (
            "abc def ghi jkl mno pqr stu vwx yz0 12345 6789",
            "abc+def/ghi=jkl?mno&pqr#stu@uvw%xyz0123456789ABCD",
            "abc\x00def\x01ghi\x1fjkl\x7fmno\x1bpqr stu vwx yz012345",
            "abc.def.ghi.jkl.mno.pqr.stu.vwx.yz0123456789ABCDEFGH",
            # `\n` final : refusé par le garde strip() ET par le motif (fullmatch).
            "A" * 42 + "\n",
            "\n" + "A" * 42,
        )
        for forbidden_key in forbidden_keys:
            with self.subTest(key=forbidden_key):
                with self.assertRaises(ValueError):
                    test_app.state.register_api_key(forbidden_key, "demo")
        self.assertEqual(len(test_app.state.api_keys), 0)
        # Une clé générée (base64url) reste acceptée.
        test_app.state.register_api_key(generate_api_key(), "demo")
        self.assertEqual(len(test_app.state.api_keys), 1)

    def test_api_key_alphabet_uses_fullmatch_not_dollar(self) -> None:
        """Pin LOW revue : `$` accepterait un `\\n` final via `match`, pas via `fullmatch`.

        Aujourd'hui le garde `strip()` refuse déjà ces clés en amont ; `fullmatch`
        lève l'ambiguïté au niveau du motif (défense en profondeur).
        """
        pattern = vault_auth_module.API_KEY_ALPHABET_PATTERN
        # L'ambiguïté documentée : `match` + `$` laisse passer le `\n` final.
        self.assertIsNotNone(pattern.match("abc\n"))
        # Le contrôle effectif ne le laisse plus passer, sans casser le valide.
        self.assertIsNone(pattern.fullmatch("abc\n"))
        self.assertIsNotNone(pattern.fullmatch("abc"))
        self.assertIsNone(pattern.fullmatch("ab\ncd"))

    def test_vault_settings_and_hash_reject_empty_pepper(self) -> None:
        """Un pepper vide ou blanc est rejeté par VaultSettings et hash_api_key."""
        for empty_val in ("", "   "):
            with self.subTest(empty_val=empty_val):
                with self.assertRaises(ValidationError):
                    VaultSettings(api_key_pepper=empty_val)
                with self.assertRaises(ValueError):
                    hash_api_key("any-key", pepper=empty_val)

    def test_vault_settings_and_hash_reject_short_pepper(self) -> None:
        """Un pepper sous 32 octets (256 bits) est refusé, en settings comme au hachage."""
        for short_pepper in ("x", "x" * 31):
            with self.subTest(pepper_length=len(short_pepper)):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(api_key_pepper=short_pepper)
                self.assertIn("32 octets", str(ctx.exception))
                with self.assertRaises(ValueError) as hash_ctx:
                    hash_api_key("any-key", pepper=short_pepper)
                self.assertIn("32 octets", str(hash_ctx.exception))
        # Exactement 32 octets reste accepté (borne inclusive).
        boundary = "b" * 32
        self.assertEqual(VaultSettings(api_key_pepper=boundary).api_key_pepper, boundary)
        self.assertEqual(len(hash_api_key("any-key", pepper=boundary)), 64)

    def test_vault_settings_rejects_pepper_with_leading_or_trailing_whitespace(self) -> None:
        """Le pepper n'est jamais normalisé silencieusement (pas de perte d'entropie)."""
        for padded in ("  secret_pepper_value  ", "\tsecret_pepper_value", "secret_pepper_value\n"):
            with self.subTest(pepper=padded):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(api_key_pepper=padded)
                self.assertIn("espaces de début ou de fin", str(ctx.exception))

    def test_vault_settings_validates_kek_and_requires_distinct_pepper(self) -> None:
        """La KEK doit être base64 32 octets, sans espaces, distincte du pepper."""
        kek = generate_encryption_key()
        settings = VaultSettings(kek=kek, api_key_pepper="distinct_pepper_" + "y" * 20)
        self.assertEqual(settings.kek, kek)

        for invalid_kek in ("", "  " + kek + "  ", "not-base64", generate_encryption_key()[:-4]):
            with self.subTest(kek=invalid_kek):
                with self.assertRaises(ValidationError):
                    VaultSettings(kek=invalid_kek, api_key_pepper="distinct_pepper")

        with self.assertRaises(ValidationError):
            VaultSettings(kek=kek, api_key_pepper=kek)

    def test_vault_settings_rejects_kek_entropy_reused_as_pepper_under_another_encoding(
        self,
    ) -> None:
        """Deux représentations d'une même entropie KEK/pepper sont refusées (invariant 5).

        Le pepper UTF-8 dont le base64 32 octets est la KEK contournerait une garde
        limitée à l'égalité des chaînes : la comparaison porte sur les octets décodés.
        """
        raw_entropy = b"Z" * 32
        kek = base64.urlsafe_b64encode(raw_entropy).decode("ascii")
        with self.assertRaises(ValidationError) as ctx:
            VaultSettings(kek=kek, api_key_pepper=raw_entropy.decode("ascii"))
        self.assertIn("distincts", str(ctx.exception))

        # Deux entropies distinctes restent acceptées.
        accepted = VaultSettings(kek=kek, api_key_pepper="distinct_pepper_" + "w" * 20)
        self.assertEqual(accepted.kek, kek)

    def test_sqlite_backend_requires_explicit_kek(self) -> None:
        """Aucune KEK éphémère pour des données persistées : échec fail-closed."""
        with tempfile.TemporaryDirectory() as tmp:
            settings = VaultSettings(
                storage_backend="sqlite",
                db_path=str(Path(tmp) / "vault.db"),
                api_key_pepper="sqlite_kek_required_" + "z" * 20,
            )
            with self.assertRaises(ValueError) as ctx:
                create_app(settings)
            self.assertIn("HEIMDALL_VAULT_KEK", str(ctx.exception))

    def test_memory_backend_forbidden_in_production(self) -> None:
        """Le backend mémoire mono-processus est refusé en production, même explicite."""
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "HEIMDALL_ENV": "production",
                "HEIMDALL_VAULT_API_KEY_PEPPER": "production_pepper_" + "m" * 20,
            },
            clear=True,
        ):
            settings = VaultSettings(
                storage_backend="memory",
                db_path=str(Path(tmp) / "vault.db"),
            )
            with self.assertRaises(ValueError) as ctx:
                create_app(settings)
            self.assertIn("memory", str(ctx.exception))

    def test_explicit_in_memory_store_forbidden_in_production(self) -> None:
        """Un store mémoire explicite ne contourne pas l'interdiction prod (fail-closed)."""
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "HEIMDALL_ENV": "production",
                "HEIMDALL_VAULT_API_KEY_PEPPER": "production_pepper_" + "m" * 20,
            },
            clear=True,
        ):
            settings = VaultSettings(db_path=str(Path(tmp) / "vault.db"))
            with self.assertRaises(ValueError) as ctx:
                create_app(settings, secret_store=InMemorySecretStore())
            self.assertIn("InMemorySecretStore", str(ctx.exception))
            self.assertIn("production", str(ctx.exception))

    def test_vault_settings_rejects_default_pepper_in_production(self) -> None:
        """En production, le pepper public commité au repo est refusé avec erreur explicite."""
        _public_default = "heimdall_default_vault_pepper_dev_only"
        with patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=True):
            with self.assertRaises(ValidationError) as ctx:
                VaultSettings(api_key_pepper=_public_default)
            self.assertIn("HEIMDALL_VAULT_API_KEY_PEPPER", str(ctx.exception))
            self.assertIn("refusé", str(ctx.exception))

        # Avec un vrai pepper en production -> accepté
        with patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=True):
            settings = VaultSettings(api_key_pepper="production_hardened_secret_pepper_12345")
            self.assertEqual(settings.api_key_pepper, "production_hardened_secret_pepper_12345")

    def test_vault_settings_rejects_public_default_pepper_outside_explicit_test_env(self) -> None:
        """Hors HEIMDALL_ENV=test explicite, la constante publique partagée est refusée."""
        _public_default = "heimdall_default_vault_pepper_dev_only"
        for env_mode in ("", "development", "staging"):
            with self.subTest(env_mode=env_mode):
                with patch.dict(os.environ, {"HEIMDALL_ENV": env_mode}, clear=True):
                    with self.assertRaises(ValidationError) as ctx:
                        VaultSettings(api_key_pepper=_public_default)
                    self.assertIn("HEIMDALL_VAULT_API_KEY_PEPPER", str(ctx.exception))
        # Seul un HEIMDALL_ENV=test explicite l'autorise (fixtures déterministes).
        with patch.dict(os.environ, {"HEIMDALL_ENV": "test"}, clear=True):
            settings = VaultSettings(api_key_pepper=_public_default)
            self.assertEqual(settings.api_key_pepper, _public_default)

    def test_vault_settings_requires_explicit_pepper_in_production(self) -> None:
        """En production, l'absence de pepper est une erreur fail-closed (aucun défaut public)."""
        with patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=True):
            with self.assertRaises(ValidationError) as ctx:
                VaultSettings()
            self.assertIn("obligatoire en production", str(ctx.exception))
        with patch.dict(os.environ, {"HEIMDALL_ENV": "prod"}, clear=True):
            with self.assertRaises(ValidationError):
                VaultSettings()

    def test_require_auth_false_forbidden_in_production(self) -> None:
        """Fail-closed : require_auth=False est refusé en production (vault ouvert sinon).

        `HEIMDALL_VAULT_REQUIRE_AUTH=false` ne doit jamais démarrer sous
        `HEIMDALL_ENV=production/prod` ; la valeur par défaut True reste acceptée
        et le mode test isolé reste disponible hors production.
        """
        for env_mode in ("production", "prod"):
            with self.subTest(env_mode=env_mode), patch.dict(
                os.environ,
                {
                    "HEIMDALL_ENV": env_mode,
                    "HEIMDALL_VAULT_API_KEY_PEPPER": "production_pepper_" + "r" * 20,
                },
                clear=True,
            ):
                # Le défaut fail-closed (True) reste accepté en production.
                self.assertTrue(VaultSettings().require_auth)
                # La désactivation explicite via l'environnement est refusée.
                with patch.dict(os.environ, {"HEIMDALL_VAULT_REQUIRE_AUTH": "false"}):
                    with self.assertRaises(ValidationError) as ctx:
                        VaultSettings()
                self.assertIn("REQUIRE_AUTH", str(ctx.exception))

        with patch.dict(os.environ, {"HEIMDALL_ENV": "test"}, clear=True):
            self.assertFalse(VaultSettings(require_auth=False).require_auth)

    def test_enable_docs_refused_in_production(self) -> None:
        """Fail-closed : enable_docs=True est refusé en production (fingerprinting).

        LOW revue : `/docs` + `/openapi.json` sans auth exposeraient le schéma,
        comme `require_auth=False` et le backend `memory` déjà refusés en prod.
        Le défaut False reste accepté ; l'ouverture reste possible hors prod.
        """
        for env_mode in ("production", "prod"):
            with self.subTest(env_mode=env_mode), patch.dict(
                os.environ,
                {"HEIMDALL_ENV": env_mode},
                clear=True,
            ):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(
                        enable_docs=True,
                        api_key_pepper="production_docs_pepper_" + "d" * 20,
                    )
                self.assertIn("ENABLE_DOCS", str(ctx.exception))
                closed = VaultSettings(api_key_pepper="production_docs_pepper_" + "e" * 20)
                self.assertFalse(closed.enable_docs)

        with patch.dict(os.environ, {"HEIMDALL_ENV": "test"}, clear=True):
            opened = VaultSettings(
                enable_docs=True,
                api_key_pepper="test_docs_pepper_" + "d" * 20,
            )
            self.assertTrue(opened.enable_docs)

    def test_vault_settings_generates_ephemeral_pepper_outside_production(self) -> None:
        """Hors production, un pepper aléatoire éphémère remplace l'ancien défaut public."""
        with patch.dict(os.environ, {"HEIMDALL_ENV": "development"}, clear=True):
            first = VaultSettings()
            second = VaultSettings()
        for generated in (first.api_key_pepper, second.api_key_pepper):
            self.assertIsNotNone(generated)
            assert generated is not None
            self.assertGreaterEqual(len(generated), 43)  # token_urlsafe(32)
            self.assertNotEqual(generated, "heimdall_default_vault_pepper_dev_only")
        self.assertNotEqual(first.api_key_pepper, second.api_key_pepper)
        # Le pepper résolu est utilisable directement par le hachage.
        assert first.api_key_pepper is not None
        self.assertEqual(
            first.effective_api_key_pepper,
            first.api_key_pepper,
        )

    async def test_api_key_with_whitespace_rejected_401(self) -> None:
        """Une clé API avec espaces en début/fin est rejetée avec 401 sans normalisation strip()."""
        raw_key = generate_api_key()
        test_app = create_app()
        test_app.state.register_api_key(raw_key, "demo")

        async with AsyncClient(
            transport=ASGITransport(app=test_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as client:
            resp = await client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "STRIP_TEST", "value": "val"},
                headers={"X-Heimdall-API-Key": f"  {raw_key}  "},
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(
                resp.json(),
                {"code": "unauthorized", "message": "Authentification requise"},
            )

    async def test_post_secret_transfer_encoding_and_content_length_simultaneous_rejected_400(
        self,
    ) -> None:
        """Transfer-Encoding et Content-Length simultanés sont rejetés avec HTTP 400."""
        valid_payload = json.dumps(
            {"project": "demo", "env": "dev", "name": "SMUGGLE_KEY", "value": "val"}
        ).encode("utf-8")
        headers = [
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", str(len(valid_payload))),
            ("X-Heimdall-API-Key", self.test_api_key),
        ]
        res = await self.client.post(
            "/api/v1/secrets",
            content=valid_payload,
            headers=headers,
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            res.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_post_secret_content_length_whitespace_rejected_400(self) -> None:
        """Content-Length avec espaces (' 10 ') est rejeté avec HTTP 400 (RFC 9110 §8.6)."""
        valid_payload = json.dumps(
            {"project": "demo", "env": "dev", "name": "WS_CL_KEY", "value": "val"}
        ).encode("utf-8")
        res_ws = await self.client.post(
            "/api/v1/secrets",
            content=valid_payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": f" {len(valid_payload)} ",
                "X-Heimdall-API-Key": self.test_api_key,
            },
        )
        self.assertEqual(res_ws.status_code, 400)
        self.assertEqual(
            res_ws.json(),
            {"code": "bad_request", "message": "Requête invalide"},
        )

    async def test_large_html_payload_never_reflected_in_errors(self) -> None:
        """Valeur de 64 Ko avec HTML/JS jamais reflétée dans les erreurs (400, 409, 429)."""
        html_canary = "<script>alert('xss_canary_injection_test');</script>"
        large_html_value = html_canary * 1200  # ~63 Ko
        self.assertGreater(len(large_html_value), 60_000)
        self.assertLessEqual(len(large_html_value), 65536)

        # 1. Erreur 400 : payload invalide (nom de projet incorrect)
        res_400 = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "InvalidProjectCase",
                "env": "dev",
                "name": "HTML_CANARY",
                "value": large_html_value,
            },
        )
        self.assertEqual(res_400.status_code, 400)
        self.assertNotIn("xss_canary", res_400.text)
        self.assertNotIn("<script>", res_400.text)

        # 2. Succès 201 puis 409 conflict avec payload HTML
        res_201 = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "HTML_CONFLICT_KEY",
                "value": "initial_value",
            },
        )
        self.assertEqual(res_201.status_code, 201)

        res_409 = await self.client.post(
            "/api/v1/secrets",
            json={
                "project": "demo",
                "env": "dev",
                "name": "HTML_CONFLICT_KEY",
                "value": large_html_value,
            },
        )
        self.assertEqual(res_409.status_code, 409)
        self.assertNotIn("xss_canary", res_409.text)
        self.assertNotIn("<script>", res_409.text)

        # 3. Erreur 429 quota de stockage avec payload HTML
        quota_app = create_app(
            secret_store=InMemorySecretStore(max_secrets=1, max_secrets_per_project=1)
        )
        quota_key = generate_api_key()
        quota_app.state.register_api_key(quota_key, "demo")
        async with AsyncClient(
            transport=ASGITransport(app=quota_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": quota_key},
        ) as quota_client:
            # Remplit le quota
            r1 = await quota_client.post(
                "/api/v1/secrets",
                json={"project": "demo", "env": "dev", "name": "FIRST", "value": "ok"},
            )
            self.assertEqual(r1.status_code, 201)

            # Provoque 429 avec la valeur HTML 64 Ko
            r_429 = await quota_client.post(
                "/api/v1/secrets",
                json={
                    "project": "demo",
                    "env": "dev",
                    "name": "OVERFLOW_HTML",
                    "value": large_html_value,
                },
            )
            self.assertEqual(r_429.status_code, 429)
            self.assertNotIn("xss_canary", r_429.text)
            self.assertNotIn("<script>", r_429.text)

    async def test_openapi_schema_declares_project_api_key_security(self) -> None:
        """Le schéma OpenAPI déclare ProjectApiKey et l'associe aux routes secrets."""
        dev_app = create_app(VaultSettings(enable_docs=True))
        async with AsyncClient(
            transport=ASGITransport(app=dev_app, client=("127.0.0.1", 54321)),
            base_url="http://127.0.0.1:8443",
        ) as dev_client:
            openapi_resp = await dev_client.get("/openapi.json")
            self.assertEqual(openapi_resp.status_code, 200)
            schema = openapi_resp.json()

            # Schéma de sécurité ProjectApiKey
            security_schemes = schema["components"]["securitySchemes"]
            self.assertIn("ProjectApiKey", security_schemes)
            self.assertEqual(security_schemes["ProjectApiKey"]["type"], "apiKey")
            self.assertEqual(security_schemes["ProjectApiKey"]["in"], "header")
            self.assertEqual(security_schemes["ProjectApiKey"]["name"], "X-Heimdall-API-Key")

            # Route POST /api/v1/secrets
            post_op = schema["paths"]["/api/v1/secrets"]["post"]
            self.assertEqual(post_op.get("security"), [{"ProjectApiKey": []}])

            # Route GET /api/v1/secrets/{project}/{env}/{name}
            get_op = schema["paths"]["/api/v1/secrets/{project}/{env}/{name}"]["get"]
            self.assertEqual(get_op.get("security"), [{"ProjectApiKey": []}])

            # Route GET /api/v1/health (publique, sans sécurité requise)
            health_op = schema["paths"]["/api/v1/health"]["get"]
            self.assertNotIn("security", health_op)


class VaultSizedRejectionKeepAliveTests(unittest.TestCase):
    """Preuve socket : un rejet 400 de taille ferme la connexion sans désynchroniser.

    Complète les assertions ASGI : démarre un vrai serveur uvicorn sur la boucle
    locale et vérifie au niveau HTTP/1.1 que la réponse porte ``Connection:
    close``, que le serveur ferme effectivement la connexion (aucun octet de
    corps non drainé réutilisable) et qu'une connexion neuve reste fonctionnelle.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = uvicorn.Server(
            uvicorn.Config(
                app=get_app(),
                host="127.0.0.1",
                port=0,
                log_level="error",
                proxy_headers=False,
                server_header=False,
                date_header=False,
            )
        )
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 15
        while not cls.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Serveur uvicorn de test non démarré à temps.")
            time.sleep(0.05)
        cls.port = cls.server.servers[0].sockets[0].getsockname()[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.should_exit = True
        cls.thread.join(timeout=15)

    @staticmethod
    def _read_response(sock: socket.socket) -> bytes:
        """Lit une réponse HTTP/1.1 complète (en-têtes + corps Content-Length)."""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        headers, _, body = data.partition(b"\r\n\r\n")
        content_length = 0
        for line in headers.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
        while len(body) < content_length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return headers + b"\r\n\r\n" + body

    def test_oversized_content_length_closes_connection(self) -> None:
        """POST annoncé > 1 Mio : 400 + Connection: close, socket fermé, puis 200 sain."""
        request_head = (
            "POST /api/v1/secrets HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {2 * 1024 * 1024}\r\n"
            "\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            # Corps volontairement partiel : le rejet doit porter sur l'en-tête.
            sock.sendall(request_head + b"x" * 128)
            response = self._read_response(sock)
            self.assertTrue(response.startswith(b"HTTP/1.1 400"), response[:64])
            self.assertIn(b"connection: close", response.lower())
            # Le serveur ferme la connexion : EOF, aucun octet résiduel réutilisable.
            sock.settimeout(10)
            self.assertEqual(sock.recv(65536), b"")

        # Le serveur reste sain pour une connexion neuve.
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(
                (
                    "GET /api/v1/health HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{self.port}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            health = self._read_response(sock)
            self.assertTrue(health.startswith(b"HTTP/1.1 200"), health[:64])
            self.assertIn(b'"status":"ok"', health)

    def test_streamed_oversized_body_closes_connection(self) -> None:
        """POST chunked > 1 Mio : 400 + Connection: close, socket fermé, pas de désync.

        Couvre le chemin ``_PayloadTooLargeError`` (lecture interrompue en plein
        flux), converti par FastAPI en ``HTTPException`` : l'en-tête de fermeture
        doit survivre à la conversion pour éviter tout octet résiduel.
        """
        chunk = b"x" * 600_000
        chunked_body = b"%x\r\n" % len(chunk) + chunk + b"\r\n"
        request_head = (
            "POST /api/v1/secrets HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            # 2 x 600 000 octets > 1 Mio : le deuxième tronçon interrompt la lecture.
            sock.sendall(request_head + chunked_body + chunked_body)
            response = self._read_response(sock)
            self.assertTrue(response.startswith(b"HTTP/1.1 400"), response[:64])
            self.assertIn(b"connection: close", response.lower())
            # Le serveur ferme la connexion : EOF, aucun octet résiduel réutilisable.
            sock.settimeout(10)
            self.assertEqual(sock.recv(65536), b"")


if __name__ == "__main__":
    unittest.main()
