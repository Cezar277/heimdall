"""Tests unitaires du client Vault et des opérations atomiques (tickets #98, #99, #100, #101).

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import copy
import os
import pickle
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

import httpx

from heimdall.vault.atomic import (
    backup_file,
    check_file_mode_600,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    parse_example_names,
    write_file_atomic,
)
from heimdall.vault.client import (
    VaultAuthError,
    VaultClient,
    VaultClientError,
    VaultConflictError,
    VaultForbiddenError,
    VaultNotFoundError,
    VaultRateLimitError,
    VaultUnavailableError,
    detect_project,
    resolve_api_key,
)

_VALID_URL = "https://127.0.0.1:8443"
_VALID_KEY = "test_synthetic_api_key_for_client_unit_tests"


class VaultClientUnitTests(unittest.TestCase):
    """Tests unitaires du client HTTP Vault."""

    def test_client_init_and_slots(self) -> None:
        """Initialisation nominale et validation des slots anti-__dict__."""
        client = VaultClient(_VALID_URL, _VALID_KEY, timeout=15.0)
        self.assertEqual(client._base_url, _VALID_URL)
        self.assertEqual(client._api_key, _VALID_KEY)
        self.assertEqual(client._timeout, 15.0)
        with self.assertRaises(TypeError):
            vars(client)
        with self.assertRaises(TypeError):
            pickle.dumps(client)
        with self.assertRaises(TypeError):
            copy.copy(client)

    def test_client_repr_redaction(self) -> None:
        """La clé API ne doit jamais être exposée dans __repr__."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        text = repr(client)
        self.assertNotIn(_VALID_KEY, text)
        self.assertIn("<REDACTED>", text)

    def test_client_subclassing_forbidden(self) -> None:
        """Le sous-classement est interdit pour protéger la clé en mémoire."""
        with self.assertRaises(TypeError):

            class EvilClient(VaultClient):
                pass

    def test_client_url_validation(self) -> None:
        """Validation stricte de l'URL : HTTPS et boucle locale obligatoires."""
        for bad_url in (
            "http://127.0.0.1:8443",
            "https://evil.example:8443",
            "https://127.0.0.1:8443/",
            "https://127.0.0.1:8443?query=1",
            "https://127.0.0.1:8443#frag",
            "https://user:pass@127.0.0.1:8443",
            "https://127.0.0.1:0",
            "https://127.0.0.1:99999",
            "",
        ):
            with self.subTest(bad_url=bad_url):
                with self.assertRaises(ValueError):
                    VaultClient(bad_url, _VALID_KEY)

    def test_client_timeout_and_ca_cert_validation(self) -> None:
        """Validation du délai maximal et du chemin CA cert."""
        with self.assertRaises(ValueError):
            VaultClient(_VALID_URL, _VALID_KEY, timeout=-1)
        with self.assertRaises(ValueError):
            VaultClient(_VALID_URL, _VALID_KEY, timeout=500)
        with self.assertRaises(ValueError):
            VaultClient(_VALID_URL, _VALID_KEY, ca_cert="/nonexistent/path/ca.crt")

    def test_health_success(self) -> None:
        """GET /api/v1/health nominal."""

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/v1/health")
            return httpx.Response(HTTPStatus.OK, json={"status": "ok"})

        transport = httpx.MockTransport(handler)
        with VaultClient(_VALID_URL, _VALID_KEY, transport=transport) as client:
            res = client.health()
            self.assertEqual(res, {"status": "ok"})

    def test_create_secret_success(self) -> None:
        """POST /api/v1/secrets nominal."""

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/v1/secrets")
            self.assertEqual(request.headers.get("X-Heimdall-API-Key"), _VALID_KEY)
            return httpx.Response(
                HTTPStatus.CREATED,
                json={"project": "demo", "env": "dev", "name": "DB_PASS", "status": "vaulte"},
            )

        transport = httpx.MockTransport(handler)
        with VaultClient(_VALID_URL, _VALID_KEY, transport=transport) as client:
            res = client.create_secret("demo", "dev", "DB_PASS", "secret_val")
            self.assertEqual(res["status"], "vaulte")
            self.assertEqual(res["name"], "DB_PASS")

    def test_create_secret_input_validation(self) -> None:
        """Validation des entrées de création de secret."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        # Nom invalide (doit correspondre à ^[A-Z][A-Z0-9_]{1,63}$)
        with self.assertRaises(ValueError):
            client.create_secret("demo", "dev", "lowercase", "val")
        # Projet invalide
        with self.assertRaises(ValueError):
            client.create_secret("Bad_Project", "dev", "DB_PASS", "val")
        # Environnement invalide
        with self.assertRaises(ValueError):
            client.create_secret("demo", "Dev!", "DB_PASS", "val")
        # Valeur vide
        with self.assertRaises(ValueError):
            client.create_secret("demo", "dev", "DB_PASS", "")

    def test_get_secret_success(self) -> None:
        """GET /api/v1/secrets/{project}/{env}/{name} nominal."""

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/v1/secrets/demo/dev/DB_PASS")
            self.assertEqual(request.headers.get("X-Heimdall-API-Key"), _VALID_KEY)
            return httpx.Response(
                HTTPStatus.OK,
                json={
                    "project": "demo",
                    "env": "dev",
                    "name": "DB_PASS",
                    "status": "vaulte",
                    "value": "super_secret_42",
                },
            )

        transport = httpx.MockTransport(handler)
        with VaultClient(_VALID_URL, _VALID_KEY, transport=transport) as client:
            res = client.get_secret("demo", "dev", "DB_PASS")
            self.assertEqual(res["value"], "super_secret_42")

    def test_get_secret_state_success(self) -> None:
        """GET /api/v1/secrets/{project}/{env}/{name}/state nominal."""

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/v1/secrets/demo/dev/DB_PASS/state")
            return httpx.Response(
                HTTPStatus.OK,
                json={"project": "demo", "env": "dev", "name": "DB_PASS", "status": "vaulte"},
            )

        transport = httpx.MockTransport(handler)
        with VaultClient(_VALID_URL, _VALID_KEY, transport=transport) as client:
            res = client.get_secret_state("demo", "dev", "DB_PASS")
            self.assertEqual(res["status"], "vaulte")
            self.assertNotIn("value", res)

    def test_error_mappings(self) -> None:
        """Conversion fidèle des codes HTTP en exceptions spécialisées."""
        cases = [
            (HTTPStatus.BAD_REQUEST, VaultClientError, {}),
            (HTTPStatus.UNAUTHORIZED, VaultAuthError, {}),
            (HTTPStatus.FORBIDDEN, VaultForbiddenError, {}),
            (HTTPStatus.NOT_FOUND, VaultNotFoundError, {}),
            (HTTPStatus.CONFLICT, VaultConflictError, {}),
            (HTTPStatus.TOO_MANY_REQUESTS, VaultRateLimitError, {"retry-after": "42"}),
            (HTTPStatus.INTERNAL_SERVER_ERROR, VaultUnavailableError, {}),
            (HTTPStatus.SERVICE_UNAVAILABLE, VaultUnavailableError, {}),
        ]
        for status_code, expected_exc, extra_headers in cases:
            with self.subTest(status_code=status_code):

                def handler(
                    request: httpx.Request,
                    sc: int = status_code,
                    eh: dict[str, str] = extra_headers,
                ) -> httpx.Response:
                    return httpx.Response(
                        sc,
                        headers=eh,
                        json={"code": "err", "message": "error"},
                    )

                transport = httpx.MockTransport(handler)
                with VaultClient(_VALID_URL, _VALID_KEY, transport=transport) as client:
                    with self.assertRaises(expected_exc) as ctx:
                        client.get_secret("demo", "dev", "DB_PASS")
                    if status_code == HTTPStatus.TOO_MANY_REQUESTS:
                        self.assertEqual(ctx.exception.retry_after, 42)


class ResolveApiKeyTests(unittest.TestCase):
    """Tests de résolution de la clé API (variable d'environnement ou fichier 0600)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-key-")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_resolve_from_environment_variable(self) -> None:
        """La variable HEIMDALL_API_KEY a la priorité."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "env_api_key_123"}):
            self.assertEqual(resolve_api_key(), "env_api_key_123")

    def test_resolve_from_secure_file(self) -> None:
        """Lecture depuis un fichier protégé en droits 0600."""
        key_file = self.tmp_dir / "vault.key"
        key_file.write_text("file_api_key_456\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            key = resolve_api_key(key_file)
            self.assertEqual(key, "file_api_key_456")

    def test_reject_insecure_file_permissions(self) -> None:
        """Rejet immédiat d'un fichier en droits trop permissifs (ex. 0644 ou 0777)."""
        key_file = self.tmp_dir / "insecure.key"
        key_file.write_text("secret_leaked\n", encoding="utf-8")
        os.chmod(key_file, 0o644)
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(key_file)
            self.assertIn("0600", str(ctx.exception))

    def test_reject_symlink_key_file(self) -> None:
        """Rejet fail-closed si le fichier de clé est un lien symbolique."""
        target = self.tmp_dir / "target.key"
        target.write_text("target_key\n", encoding="utf-8")
        os.chmod(target, 0o600)
        symlink = self.tmp_dir / "symlink.key"
        symlink.symlink_to(target)
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(symlink)
            self.assertIn("lien symbolique", str(ctx.exception))

    def test_missing_key_raises_informative_error(self) -> None:
        """En l'absence de variable ou de fichier, l'erreur guide l'utilisateur."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key()
            self.assertIn("HEIMDALL_API_KEY", str(ctx.exception))

    def test_empty_key_file_raises_error(self) -> None:
        """Un fichier de clé API vide est refusé."""
        empty_key = self.tmp_dir / "empty.key"
        empty_key.write_text("   \n", encoding="utf-8")
        os.chmod(empty_key, 0o600)
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(empty_key)
            self.assertIn("vide", str(ctx.exception))

    def test_key_file_is_directory_raises_error(self) -> None:
        """Un répertoire passé comme fichier de clé est refusé."""
        dir_key = self.tmp_dir / "dir_key"
        dir_key.mkdir()
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(dir_key)
            self.assertIn("fichier régulier", str(ctx.exception))


class AtomicFileOperationsTests(unittest.TestCase):
    """Tests des opérations de fichiers atomiques et sécurisées."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-atomic-")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_write_file_atomic_permissions(self) -> None:
        """L'écriture atomique produit un fichier en droits 0600."""
        target = self.tmp_dir / ".env"
        write_file_atomic(target, "KEY=VAL\n", mode=0o600)
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding="utf-8"), "KEY=VAL\n")
        self.assertTrue(check_file_mode_600(target))

    def test_backup_file_creation(self) -> None:
        """backup_file crée une copie .bak en droits 0600."""
        target = self.tmp_dir / ".env"
        write_file_atomic(target, "INITIAL=1\n")
        bak = backup_file(target)
        self.assertIsNotNone(bak)
        assert bak is not None
        self.assertEqual(bak.name, ".env.bak")
        self.assertEqual(bak.read_text(encoding="utf-8"), "INITIAL=1\n")
        self.assertTrue(check_file_mode_600(bak))

    def test_backup_file_nonexistent_returns_none(self) -> None:
        """backup_file retourne None si le fichier n'existe pas."""
        nonexistent = self.tmp_dir / "inexistant.env"
        self.assertIsNone(backup_file(nonexistent))

    def test_write_file_atomic_cleans_up_on_failure(self) -> None:
        """En cas d'erreur pendant l'écriture, le fichier temporaire est nettoyé."""
        target = self.tmp_dir / "fail.env"
        with patch("os.fsync", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                write_file_atomic(target, "content")
        # Aucun fichier résiduel .tmp
        tmp_files = [f for f in self.tmp_dir.iterdir() if ".tmp." in f.name]
        self.assertEqual(tmp_files, [])

    def test_git_tracked_and_ignored_helpers(self) -> None:
        """Vérification des helpers git avec mock."""
        target = self.tmp_dir / ".env"
        target.write_text("x=1\n", encoding="utf-8")
        with patch("shutil.which", return_value=None):
            self.assertFalse(is_git_tracked(target))
            self.assertFalse(is_git_ignored(target))

    def test_parse_env_file(self) -> None:
        """Parsing correct des paires clé=valeur en ignorant commentaires et vides."""
        content = """
        # Commentaire
        FOO=bar
        BAZ="qux"
        SPACED = 'value with spaces'

        INVALID_LINE_WITHOUT_EQUALS
        """
        env_file = self.tmp_dir / ".env"
        env_file.write_text(content, encoding="utf-8")
        parsed = parse_env_file(env_file)
        self.assertEqual(parsed["FOO"], "bar")
        self.assertEqual(parsed["BAZ"], "qux")
        self.assertEqual(parsed["SPACED"], "value with spaces")
        self.assertNotIn("INVALID_LINE_WITHOUT_EQUALS", parsed)

    def test_parse_example_names(self) -> None:
        """Extraction des identifiants depuis .env.example."""
        content = """
        # Modèle de variables
        DATABASE_URL=
        API_TOKEN=placeholder
        EMPTY_VAR=
        """
        example_file = self.tmp_dir / ".env.example"
        example_file.write_text(content, encoding="utf-8")
        names = parse_example_names(example_file)
        self.assertEqual(names, ["DATABASE_URL", "API_TOKEN", "EMPTY_VAR"])

    def test_detect_project_fallback(self) -> None:
        """detect_project utilise le nom de dossier si rien d'autre."""
        with patch.dict(os.environ, {"HEIMDALL_PROJECT": "custom-proj"}):
            self.assertEqual(detect_project(), "custom-proj")


if __name__ == "__main__":
    unittest.main()
