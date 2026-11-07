"""Chasse aux fuites de clés (ticket #72, T26.5).

Preuves que la clé maîtresse, la KEK, le pepper, les clés API et les valeurs
de secrets ne fuitent ni dans les logs, ni dans les exceptions, ni dans les
``repr()`` des objets qui les portent.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from heimdall.cli.main import app as cli_app
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.auth import ApiKeyRegistry
from heimdall.vault.client import VaultClient
from heimdall.vault.crypto import (
    VaultCipher,
    generate_api_key,
    generate_encryption_key,
    generate_kek_salt,
)
from heimdall.vault.database import db_session, rotate_secrets_kek

REPO_ROOT = Path(__file__).resolve().parents[1]

# Canaris volontairement factices : aucune valeur réelle, uniquement des
# marqueurs uniques pour prouver l'absence de fuite dans les sorties.
_MASTER_KEY = "leak-hunt-master-key-0123456789abcdef"  # noqa: S105
_PEPPER = "leak-hunt-pepper-0123456789abcdef0123456789abcdef"  # noqa: S105
_SECRET_VALUE = "CANARY_SECRET_VALUE_LEAK_HUNT_0123456789"  # noqa: S105


class VaultKeyLeakHuntTests(unittest.TestCase):
    """Vérifie logs, exceptions et repr() sur les objets porteurs de clés."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-leak-hunt-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        self.salt = generate_kek_salt()
        self.kek = generate_encryption_key()
        self.api_key = generate_api_key()
        self.wrong_api_key = generate_api_key()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _assert_no_canaries(self, text: str, canaries: list[str]) -> None:
        for canary in canaries:
            self.assertNotIn(canary, text)

    def _settings(self) -> VaultSettings:
        return VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=self.salt,
            api_key_pepper=_PEPPER,
            storage_backend="sqlite",
            db_path=str(self.db_path),
        )

    def test_settings_repr_and_serialization_redact_secrets(self) -> None:
        """repr/model_dump/model_dump_json n'exposent ni clé maîtresse, ni sel, ni pepper."""
        settings = self._settings()
        rendered = "\n".join(
            (repr(settings), str(settings.model_dump()), settings.model_dump_json())
        )
        self._assert_no_canaries(rendered, [_MASTER_KEY, self.salt, _PEPPER])

        legacy = VaultSettings(kek=self.kek, api_key_pepper=_PEPPER)
        legacy_rendered = "\n".join(
            (repr(legacy), str(legacy.model_dump()), legacy.model_dump_json())
        )
        self._assert_no_canaries(legacy_rendered, [self.kek, _PEPPER])

    def test_settings_validation_errors_do_not_echo_secret_inputs(self) -> None:
        """Les ValidationError restent génériques, même avec un secret en entrée."""
        cases: list[tuple[dict[str, str], str]] = [
            (
                {"master_key": "short-canary", "kek_salt": self.salt, "api_key_pepper": _PEPPER},
                "short-canary",
            ),
            ({"kek": "invalid-kek-canary", "api_key_pepper": _PEPPER}, "invalid-kek-canary"),
            (
                {
                    "master_key": _MASTER_KEY,
                    "kek_salt": "invalid-salt-canary",
                    "api_key_pepper": _PEPPER,
                },
                "invalid-salt-canary",
            ),
            ({"api_key_pepper": "short-pepper-canary"}, "short-pepper-canary"),
        ]
        for kwargs, canary in cases:
            with self.subTest(canary=canary):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(**kwargs)
                self.assertNotIn(canary, str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            VaultSettings(kek=self.kek, api_key_pepper=self.kek)
        self.assertNotIn(self.kek, str(ctx.exception))

    def test_cipher_repr_and_errors_redact_keys(self) -> None:
        """VaultCipher ne divulgue jamais la KEK, ni dans repr ni dans une erreur."""
        cipher = VaultCipher.from_master_key(_MASTER_KEY, self.salt)
        self._assert_no_canaries(repr(cipher), [_MASTER_KEY, self.salt])

        legacy = VaultCipher.from_encoded_key(self.kek)
        self._assert_no_canaries(repr(legacy), [self.kek])

        with self.assertRaises(ValueError) as ctx:
            VaultCipher.from_encoded_key("invalid-kek-canary")
        self.assertNotIn("invalid-kek-canary", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            VaultCipher.from_master_key("short-canary", self.salt)
        self.assertNotIn("short-canary", str(ctx.exception))

    def test_client_repr_and_errors_redact_api_key(self) -> None:
        """VaultClient masque la clé API dans repr/str et dans les erreurs d'entrée."""
        with VaultClient("https://127.0.0.1:8443", self.api_key) as client:
            self._assert_no_canaries(repr(client) + str(client), [self.api_key])

        with self.assertRaises(ValueError) as ctx:
            VaultClient("https://127.0.0.1:8443", self.api_key + "\n")
        self.assertNotIn(self.api_key, str(ctx.exception))

    def test_issued_key_and_registry_repr_redact_raw_key(self) -> None:
        """IssuedApiKey et ApiKeyRegistry ne laissent jamais fuiter la clé brute."""
        registry = ApiKeyRegistry(pepper=_PEPPER)
        issued = registry.issue("demo")
        self._assert_no_canaries(repr(issued), [issued.raw_key, _PEPPER])
        self._assert_no_canaries(repr(registry), [issued.raw_key, _PEPPER])
        self._assert_no_canaries(repr(registry.list_entries()), [issued.raw_key])
        self._assert_no_canaries(repr(registry.active_hashes), [issued.raw_key])

    def test_runtime_logs_do_not_contain_master_key_or_secret_values(self) -> None:
        """Scénarios nominaux et d'erreur : aucun secret dans les logs capturés."""
        with self.assertLogs("heimdall", level="DEBUG") as captured:
            app = create_app(self._settings())
            app.state.register_api_key(self.api_key, "demo")
            headers = {"X-Heimdall-API-Key": self.api_key}

            with TestClient(
                app, base_url="http://127.0.0.1:8443", client=("127.0.0.1", 50000)
            ) as client:
                created = client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "LEAK_HUNT",
                        "value": _SECRET_VALUE,
                    },
                    headers=headers,
                )
                self.assertEqual(created.status_code, 201)
                read = client.get("/api/v1/secrets/demo/dev/LEAK_HUNT", headers=headers)
                self.assertEqual(read.status_code, 200)
                self.assertEqual(read.json()["value"], _SECRET_VALUE)

                unauthorized = client.get(
                    "/api/v1/secrets/demo/dev/LEAK_HUNT",
                    headers={"X-Heimdall-API-Key": self.wrong_api_key},
                )
                self.assertEqual(unauthorized.status_code, 401)
                self._assert_no_canaries(unauthorized.text, [_SECRET_VALUE, self.api_key])

                invalid = client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "LEAK_HUNT",
                        "value": _SECRET_VALUE,
                        "extra": "refusé",
                    },
                    headers=headers,
                )
                self.assertEqual(invalid.status_code, 400)
                self._assert_no_canaries(
                    invalid.text, [_SECRET_VALUE, self.api_key, _MASTER_KEY, _PEPPER]
                )

            result = CliRunner().invoke(
                cli_app,
                [
                    "vault",
                    "key",
                    "create",
                    "--project",
                    "demo",
                    "--db-path",
                    str(self.db_path),
                ],
                env={"HEIMDALL_VAULT_API_KEY_PEPPER": _PEPPER},
            )
            self.assertEqual(result.exit_code, 0, result.output)
            lines = result.output.splitlines()
            raw_key = ""
            for index, line in enumerate(lines):
                if line.startswith("Clé API de projet émise"):
                    raw_key = lines[index + 1].strip()
                    break
            self.assertTrue(raw_key)

            old_cipher = VaultCipher.from_master_key(_MASTER_KEY, self.salt)
            new_cipher = VaultCipher.from_encoded_key(self.kek)
            with db_session(self.db_path) as conn:
                rotate_secrets_kek(conn, old_cipher, new_cipher)

        log_text = "\n".join(captured.output)
        self._assert_no_canaries(
            log_text,
            [_MASTER_KEY, self.salt, _PEPPER, _SECRET_VALUE, self.api_key, raw_key, self.kek],
        )
        self.assertNotIn(raw_key, log_text)

    def test_static_logging_calls_do_not_reference_sensitive_names(self) -> None:
        """Garde statique : aucun logger.* ne référence une variable de secret."""
        sensitive = {
            "value",
            "plaintext",
            "secret",
            "secret_value",
            "master_key",
            "kek",
            "api_key",
            "raw_key",
            "pepper",
            "password",
            "token",
        }
        violations: list[str] = []
        paths = list((REPO_ROOT / "heimdall" / "vault").glob("*.py"))
        paths.append(REPO_ROOT / "heimdall" / "cli" / "vault_keys.py")
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "logger"
                ):
                    continue
                for arg in node.args:
                    for child in ast.walk(arg):
                        if isinstance(child, ast.Name) and child.id.lower() in sensitive:
                            violations.append(
                                f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                                f"logger.{node.func.attr} référence {child.id!r}"
                            )
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
