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

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ValidationError

from heimdall.vault.app import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    HealthResponse,
    NotFoundError,
    SecretCreate,
    SecretMetadata,
    SecretRead,
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
        if hasattr(app.state, "secret_store"):
            app.state.secret_store.clear()
        self.transport = ASGITransport(app=app, client=("127.0.0.1", 54321))
        self.client = AsyncClient(transport=self.transport, base_url="http://127.0.0.1:8443")

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
        """Seuls Allow et Retry-After (1-3600) sont retransmis, les autres sont filtrés."""
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
        """Le modèle ForbiddenError est conforme au contrat d'erreur."""
        err = ForbiddenError()
        self.assertEqual(err.code, "forbidden")
        self.assertEqual(err.message, "Accès interdit")
        with self.assertRaises(ValidationError):
            ForbiddenError(extra="unauthorized")  # type: ignore[call-arg]

    def test_run_server_is_callable(self) -> None:
        """run_server est défini et appelable comme point d'entrée."""
        self.assertTrue(callable(run_server))

    @patch("uvicorn.run")
    def test_run_server_passes_hardened_uvicorn_arguments(
        self, mock_uvicorn_run: unittest.mock.MagicMock
    ) -> None:
        """run_server configure uvicorn avec anti-spoofing et sans fingerprinting."""
        run_server()
        mock_uvicorn_run.assert_called_once_with(
            "heimdall.vault.app:app",
            host="127.0.0.1",
            port=8443,
            proxy_headers=False,
            forwarded_allow_ips="",
            server_header=False,
            date_header=False,
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

class VaultSecretsRouteTests(unittest.IsolatedAsyncioTestCase):
    """Tests contractuels des routes POST et GET secrets (ticket #63)."""

    async def asyncSetUp(self) -> None:
        if hasattr(app.state, "secret_store"):
            app.state.secret_store.clear()
        self.transport = ASGITransport(app=app, client=("127.0.0.1", 54321))
        self.client = AsyncClient(transport=self.transport, base_url="http://127.0.0.1:8443")

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

        err400 = BadRequestError()
        self.assertEqual(err400.code, "bad_request")

        err404 = NotFoundError()
        self.assertEqual(err404.code, "not_found")

        err409 = ConflictError()
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
        async def chunk_generator():
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


if __name__ == "__main__":
    unittest.main()
