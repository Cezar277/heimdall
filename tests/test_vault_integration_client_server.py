"""Tests d'intégration client/serveur Vault (ticket #102).

Vérifie l'échange complet entre le client HTTP / CLI et le serveur Vault
FastAPI sur une base temporaire SQLite dédiée.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport
from typer.testing import CliRunner

from heimdall.cli.main import app as cli_app
from heimdall.vault import auth as vault_auth
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.atomic import check_file_mode_600, parse_env_file
from heimdall.vault.client import (
    VaultAuthError,
    VaultClient,
    VaultForbiddenError,
)
from heimdall.vault.crypto import generate_api_key, generate_encryption_key
from heimdall.vault.database import init_db

_PEPPER = "test_integration_pepper_at_least_32_bytes_long"
_PROJECT = "testproject"
_OTHER_PROJECT = "otherproject"


class SyncASGITransport(httpx.BaseTransport):
    """Adaptateur synchrone permettant à VaultClient d'interagir avec l'application ASGI."""

    def __init__(self, application: Any) -> None:
        self._async_transport = ASGITransport(app=application)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def _do() -> tuple[int, httpx.Headers, bytes]:
            resp = await self._async_transport.handle_async_request(request)
            content = await resp.aread()
            return resp.status_code, resp.headers, content

        status_code, headers, content = asyncio.run(_do())
        return httpx.Response(
            status_code=status_code,
            headers=headers,
            content=content,
            request=request,
        )

    def close(self) -> None:
        pass


class VaultClientServerIntegrationTests(unittest.TestCase):
    """Scénarios d'intégration complets entre VaultClient / CLI et FastAPI."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-integ-")
        self.tmp_dir = Path(self._tmp.name)
        self.db_path = self.tmp_dir / "vault.db"

        # Configuration isolée avec SQLite temporaire
        init_db(self.db_path)
        self.settings = VaultSettings(
            db_path=str(self.db_path),
            storage_backend="sqlite",
            kek=generate_encryption_key(),
            api_key_pepper=_PEPPER,
        )
        self.app = create_app(self.settings)

        # Émission d'une vraie clé pour le projet testproject
        issued = vault_auth.issue_api_key(self.db_path, _PROJECT, _PEPPER)
        self.valid_api_key = issued.raw_key

        # Émission d'une vraie clé pour un autre projet
        issued_other = vault_auth.issue_api_key(self.db_path, _OTHER_PROJECT, _PEPPER)
        self.other_project_api_key = issued_other.raw_key

        self.transport = SyncASGITransport(self.app)
        self.client = VaultClient.create_for_tests(
            "https://127.0.0.1:8443",
            self.valid_api_key,
            transport=self.transport,
        )
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self.client.close()
        self._tmp.cleanup()

    def test_health_check(self) -> None:
        """Vérifie la réponse 200 de santé du serveur."""
        res = self.client.health()
        self.assertEqual(res, {"status": "ok"})

    def test_push_then_pull_roundtrip_integrity(self) -> None:
        """Scénario nominal : push puis pull, on retrouve la même valeur."""
        secret_name = "STRIPE_API_KEY"  # noqa: S105
        secret_value = "sk_test_synthetic_token_value_xyz"  # noqa: S105

        # 1. Push
        created = self.client.create_secret(_PROJECT, "dev", secret_name, secret_value)
        self.assertEqual(created["status"], "vaulte")
        self.assertEqual(created["name"], secret_name)

        # 2. Pull
        read = self.client.get_secret(_PROJECT, "dev", secret_name)
        self.assertEqual(read["name"], secret_name)
        self.assertEqual(read["value"], secret_value)
        self.assertEqual(read["status"], "vaulte")

        # 3. State
        state = self.client.get_secret_state(_PROJECT, "dev", secret_name)
        self.assertEqual(state["status"], "vaulte")
        self.assertNotIn("value", state)

    def test_invalid_api_key_returns_401(self) -> None:
        """Une clé API invalide déclenche HTTP 401 (VaultAuthError)."""
        invalid_key = generate_api_key()  # clé non enregistrée
        unauthorized_client = VaultClient.create_for_tests(
            "https://127.0.0.1:8443",
            invalid_key,
            transport=self.transport,
        )
        with unauthorized_client:
            with self.assertRaises(VaultAuthError):
                unauthorized_client.create_secret(_PROJECT, "dev", "ANY_VAR", "val")
            with self.assertRaises(VaultAuthError):
                unauthorized_client.get_secret(_PROJECT, "dev", "ANY_VAR")

    def test_cross_project_access_returns_403(self) -> None:
        """Une clé valide d'un autre projet reçoit HTTP 403 (VaultForbiddenError)."""
        other_client = VaultClient.create_for_tests(
            "https://127.0.0.1:8443",
            self.other_project_api_key,
            transport=self.transport,
        )
        with other_client:
            with self.assertRaises(VaultForbiddenError):
                other_client.create_secret(_PROJECT, "dev", "FORBIDDEN_VAR", "val")

    def test_cli_end_to_end_push_pull_and_run(self) -> None:
        """Scénario de bout en bout CLI : push depuis .env, pull vers .env, et run."""
        # Préparation du .env source
        src_env = self.tmp_dir / "source.env"
        src_env.write_text("DATABASE_URL=postgres://localhost:5432/app\n", encoding="utf-8")

        # Configuration de l'environnement pour la CLI
        with patch.dict(
            os.environ,
            {
                "HEIMDALL_API_KEY": self.valid_api_key,
                "HEIMDALL_PROJECT": _PROJECT,
            },
        ):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                mock_init.return_value = self.client

                # 1. Exécution de `heimdall vault push`
                push_res = self.runner.invoke(
                    cli_app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(src_env),
                        "--project",
                        _PROJECT,
                        "--env",
                        "dev",
                    ],
                )
                self.assertEqual(push_res.exit_code, 0)
                self.assertIn("vaulte", push_res.output)
                self.assertNotIn("postgres://", push_res.output)

                # 2. Exécution de `heimdall vault pull`
                dest_env = self.tmp_dir / "destination.env"
                pull_res = self.runner.invoke(
                    cli_app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        _PROJECT,
                        "--env",
                        "dev",
                        "--name",
                        "DATABASE_URL",
                        "--output",
                        str(dest_env),
                    ],
                )
                self.assertEqual(pull_res.exit_code, 0)
                self.assertTrue(dest_env.is_file())
                self.assertTrue(check_file_mode_600(dest_env))
                self.assertEqual(
                    parse_env_file(dest_env),
                    {"DATABASE_URL": "postgres://localhost:5432/app"},
                )

                # 3. Exécution de `heimdall run -- <cmd>`
                run_res = self.runner.invoke(
                    cli_app,
                    [
                        "run",
                        "--project",
                        _PROJECT,
                        "--env",
                        "dev",
                        "--name",
                        "DATABASE_URL",
                        "--",
                        sys.executable,
                        "-c",
                        (
                            "import os, sys\n"
                            "val = os.environ.get('DATABASE_URL')\n"
                            "sys.exit(0 if val == 'postgres://localhost:5432/app' else 1)\n"
                        ),
                    ],
                )
                self.assertEqual(run_res.exit_code, 0)


@pytest.fixture
def vault_test_server(tmp_path: Path):
    """Fixture pytest fournissant une instance Vault et une clé API de projet."""
    db_file = tmp_path / "fixture_vault.db"
    init_db(db_file)
    settings = VaultSettings(
        db_path=str(db_file),
        storage_backend="sqlite",
        kek=generate_encryption_key(),
        api_key_pepper=_PEPPER,
    )
    application = create_app(settings)
    issued = vault_auth.issue_api_key(db_file, "fixtureproj", _PEPPER)
    transport = SyncASGITransport(application)
    client = VaultClient.create_for_tests(
        "https://127.0.0.1:8443", issued.raw_key, transport=transport
    )
    yield client
    client.close()


def test_pytest_fixture_scenario(vault_test_server: VaultClient) -> None:
    """Vérification via la fixture pytest (checklist ticket #102)."""
    # 1. Push
    vault_test_server.create_secret("fixtureproj", "dev", "SECRET_KEY", "fixture_val_888")
    # 2. Pull
    secret = vault_test_server.get_secret("fixtureproj", "dev", "SECRET_KEY")
    assert secret["value"] == "fixture_val_888"


if __name__ == "__main__":
    unittest.main()
