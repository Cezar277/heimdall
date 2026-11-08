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

_LOGGING_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)
_LOGGER_NAMES = frozenset({"logger", "log", "LOG", "logging"})
_SENSITIVE_MARKERS = (
    "value",
    "plaintext",
    "secret",
    "password",
    "passphrase",
    "private_key",
    "master_key",
    "master",
    "api_key",
    "raw_key",
    "pepper",
    "kek",
    "dek",
    "salt",
    "seed",
    "token",
    "key",
)
_ALLOWED_NAMES = frozenset(
    {
        "encrypted_value",
        "kek_version",
        "max_kek_version",
        "new_version",
        "current_max",
        "key_id",
        "key_hash",
        "key_file",
        "key_path",
        "key_name",
        "key_count",
        "key_size",
        "key_type",
        "key_version",
        "key_len",
        "key_prefix",
        "key_suffix",
        "key_algorithm",
        "env_master",
        "env_salt",
    }
)
_SENSITIVE_ATTRIBUTES = frozenset(
    {"_key", "_pepper", "_api_key", "_entries", "_active", "__dict__"}
)
_SENSITIVE_OBJECTS = frozenset({"settings", "cipher", "registry", "client", "issued"})
_SENSITIVE_CALLS = frozenset({"locals", "globals", "vars", "dir"})
_SENSITIVE_METHODS = frozenset({"model_dump", "model_dump_json"})
_SAFE_ATTRIBUTES = frozenset(
    {
        "db_path",
        "key_id",
        "key_hash",
        "project_id",
        "created_at",
        "name",
        "path",
        "status",
        "storage_backend",
        "host",
        "port",
        "enable_docs",
        "require_auth",
        "rate_limit_per_key",
        "rate_limit_per_peer",
        "rate_limit_global",
        "rate_limit_window_seconds",
        "ssl_certfile",
        "ssl_keyfile",
        "ssl_ca_file",
        "min_tls_version",
        "max_request_body_bytes",
        "max_secrets",
        "max_secrets_per_project",
        "_base_url",
        "_timeout",
        "_ca_cert",
        "_transport",
        "_client",
        "_db_path",
    }
)


def _is_sensitive_name(name: str) -> bool:
    """Détection conservatrice par sous-chaîne, avec allowlist des métadonnées."""
    normalized = name.lower()
    if normalized in _ALLOWED_NAMES:
        return False
    return any(marker in normalized for marker in _SENSITIVE_MARKERS)


def _is_logging_call(node: ast.Call) -> bool:
    """Reconnaît logger.*, log.*, logging.* et getLogger(...).*."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _LOGGING_METHODS:
        return False
    base = node.func.value
    if isinstance(base, ast.Name):
        return base.id in _LOGGER_NAMES
    if isinstance(base, ast.Attribute):
        return base.attr in _LOGGER_NAMES
    if isinstance(base, ast.Call):
        func = base.func
        if isinstance(func, ast.Name) and func.id == "getLogger":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "getLogger":
            return True
    return False


def _sensitive_reference(value: ast.AST) -> str | None:  # noqa: PLR0911, PLR0912
    """Retourne le premier nom/attribut/appel sensible trouvé dans une expression.

    Gère les accès attributs (``settings.master_key``, ``cipher._key``), les
    subscripts ``model_dump()``, les objets porteurs loggés entiers et les
    introspections ``locals()``/``globals()``/``vars()``/``dir()``.
    """
    if isinstance(value, ast.Name):
        if value.id in _SENSITIVE_OBJECTS:
            return value.id
        if value.id.endswith(("Error", "Exception")) or value.id.isupper():
            return None
        return value.id if _is_sensitive_name(value.id) else None
    if isinstance(value, ast.Attribute):
        attr = value.attr
        if attr in _SENSITIVE_OBJECTS or attr.lower() in _SENSITIVE_ATTRIBUTES:
            return attr
        if not attr.isupper() and _is_sensitive_name(attr):
            return attr
        if attr in _SENSITIVE_METHODS:
            return f"{attr}()"
        if attr in _SAFE_ATTRIBUTES:
            return None
        return _sensitive_reference(value.value)
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Name) and func.id in _SENSITIVE_CALLS:
            return f"{func.id}()"
        if isinstance(func, ast.Attribute):
            name = _sensitive_reference(func.value)
            if name is not None:
                return name
            if func.attr in _SENSITIVE_METHODS:
                return f"{func.attr}()"
        for child in list(value.args) + [keyword.value for keyword in value.keywords]:
            name = _sensitive_reference(child)
            if name is not None:
                return name
        return None
    if isinstance(value, ast.Subscript):
        if (
            isinstance(value.value, ast.Call)
            and isinstance(value.value.func, ast.Attribute)
            and value.value.func.attr in _SENSITIVE_METHODS
        ):
            slice_node = value.slice
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                return slice_node.value if _is_sensitive_name(slice_node.value) else None
            if isinstance(slice_node, ast.Name):
                return slice_node.id if _is_sensitive_name(slice_node.id) else None
            return None
        name = _sensitive_reference(value.value)
        if name is not None:
            return name
        slice_node = value.slice
        if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
            return slice_node.value if _is_sensitive_name(slice_node.value) else None
        if isinstance(slice_node, ast.Name):
            return slice_node.id if _is_sensitive_name(slice_node.id) else None
        return _sensitive_reference(slice_node)
    for child in ast.iter_child_nodes(value):
        name = _sensitive_reference(child)
        if name is not None:
            return name
    return None


def _is_allowed_echo(value: ast.AST) -> bool:
    """Seul ``typer.echo(issued.raw_key)`` est autorisé (affichage unique CLI)."""
    return (
        isinstance(value, ast.Attribute)
        and value.attr == "raw_key"
        and isinstance(value.value, ast.Name)
        and value.value.id == "issued"
    )


def _static_logging_violations(paths: list[Path]) -> list[str]:  # noqa: PLR0912
    """Inspecte logs, ``print``, ``echo`` et ``raise`` : args, keywords, attributs.

    Les blobs chiffrés ``encrypted_value`` restent autorisés (ciphertext, pas de
    clair) ; ``encrypted_dek`` est marqué sensible par défense en profondeur.
    """
    violations: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if _is_logging_call(node):
                    label = f"logger.{node.func.attr}"
                elif (
                    isinstance(node.func, ast.Name) and node.func.id == "print"
                ) or (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "print"
                ):
                    label = "print"
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "echo":
                    label = "echo"
                else:
                    continue
                values = list(node.args) + [keyword.value for keyword in node.keywords]
                for value in values:
                    if label == "echo" and _is_allowed_echo(value):
                        continue
                    name = _sensitive_reference(value)
                    if name is not None:
                        violations.append(
                            f"{path.name}:{node.lineno}: {label} référence {name!r}"
                        )
            elif isinstance(node, ast.Raise) and (
                node.exc is not None or node.cause is not None
            ):
                name = _sensitive_reference(node.exc) if node.exc is not None else None
                if name is None and node.cause is not None:
                    name = _sensitive_reference(node.cause)
                if name is not None:
                    violations.append(
                        f"{path.name}:{node.lineno}: raise référence {name!r}"
                    )
    return violations


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
            [
                _MASTER_KEY,
                self.salt,
                _PEPPER,
                _SECRET_VALUE,
                self.api_key,
                raw_key,
                self.kek,
                old_cipher._key.hex(),
                new_cipher._key.hex(),
            ],
        )
        self.assertNotIn(raw_key, log_text)

    def test_static_logging_calls_do_not_reference_sensitive_names(self) -> None:
        """Garde statique : aucun logger.* ne référence une variable de secret."""
        paths = list((REPO_ROOT / "heimdall" / "vault").glob("*.py"))
        paths.append(REPO_ROOT / "heimdall" / "cli" / "vault_keys.py")
        self.assertEqual(_static_logging_violations(paths), [])

    def test_static_logging_guard_detects_known_violations(self) -> None:
        """La garde détecte args, keywords, alias et getLogger(...).*."""
        with tempfile.TemporaryDirectory(prefix="heimdall-log-guard-") as tmp:
            path = Path(tmp) / "bad_logging.py"
            path.write_text(
                "import logging\n"
                "logger = logging.getLogger(__name__)\n"
                "log = logging.getLogger('alias')\n"
                "secret_value = 'x'\n"
                "logger.info(secret_value)\n"
                "logger.info('x', extra={'secret': secret_value})\n"
                "log.info(secret_value)\n"
                "logging.getLogger('x').info(secret_value)\n"
                "logger.info(registry._pepper)\n"
                "logger.info(settings.master_key)\n"
                "logger.info(cipher._key)\n"
                "logger.info(settings.model_dump()['master_key'])\n"
                "logger.info(key)\n"
                "logger.info(cipher.key)\n"
                "print(secret_value)\n"
                "raise ValueError(f'bad {secret_value}')\n"
                "logger.info(settings)\n"
                "logger.info(cipher)\n"
                "logger.info(registry)\n"
                "logger.info(client)\n"
                "logger.info(issued)\n"
                "raise ValueError('x') from secret_exc\n"
                "logger.info(locals())\n"
                "typer.echo(secret_value)\n"
                "logger.info(settings.model_dump())\n"
                "logger.info(settings.model_dump_json())\n"
                "logger.info(settings.__dict__)\n"
                "typer.echo(issued.raw_key)\n"
                "logger.info(settings.db_path)\n"
                "logger.info(issued.key_id)\n"
                "typer.echo(f'Identifiant : {issued.key_id}')\n"
                "logger.info(secret_value.hex())\n"
                "logger.info(data[secret_value])\n"
                "logger.info(registry.active_hashes)\n"
                "logger.info(d['master_key'])\n"
                "logger.info(settings.host)\n"
                "logger.info(client._base_url)\n",
                encoding="utf-8",
            )
            violations = _static_logging_violations([path])
        self.assertEqual(len(violations), 27)


if __name__ == "__main__":
    unittest.main()
