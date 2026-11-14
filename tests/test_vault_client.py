"""Tests unitaires du client Vault et des opérations atomiques (tickets #98, #99, #100, #101).

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import copy
import inspect
import json
import os
import pickle
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import httpx

from heimdall.vault.atomic import (
    _bounded_error_message,
    _get_git_toplevel,
    _open_file_read_fd,
    _write_file_atomic_fallback,
    backup_file,
    check_file_mode_600,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    parse_example_names,
    read_file_secure_no_follow,
    write_file_atomic,
)
from heimdall.vault.client import (
    _MAX_API_KEY_FILE_BYTES,
    _MAX_RESPONSE_HEADER_COUNT,
    _PROJECT_ID_PATTERN,
    _STREAM_CHUNK_SIZE,
    VaultAuthError,
    VaultClient,
    VaultClientError,
    VaultConflictError,
    VaultForbiddenError,
    VaultNotFoundError,
    VaultRateLimitError,
    VaultUnavailableError,
    _check_localhost_resolution,
    _detect_from_git,
    _find_key_file,
    _measure_response_headers,
    _pin_loopback_ip,
    _read_and_check_key_file,
    _validate_identifier,
    detect_project,
    resolve_api_key,
    resolve_vault_url,
)

_VALID_URL = "https://127.0.0.1:8443"
_VALID_KEY = "test_synthetic_api_key_for_client_unit_tests"


class VaultClientUnitTests(unittest.TestCase):
    """Tests unitaires du client HTTP Vault."""

    def test_client_init_and_slots(self) -> None:
        """Initialisation nominale et validation des slots anti-__dict__."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        self.assertFalse(hasattr(client, "__dict__"))
        self.assertEqual(
            client.__slots__,
            ("_base_url", "_api_key", "_timeout", "_ca_cert", "_transport", "_client"),
        )

    def test_client_repr_and_str_redaction(self) -> None:
        """__repr__ et __str__ masquent strictement la clé API."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        r = repr(client)
        s = str(client)
        self.assertEqual(r, s)
        self.assertNotIn(_VALID_KEY, r)
        self.assertIn("api_key=<REDACTED>", r)
        self.assertIn(_VALID_URL, r)

    def test_client_subclassing_forbidden(self) -> None:
        """Le sous-classement est strictement interdit (invariant non-héritable)."""
        with self.assertRaises(TypeError):

            class SubVaultClient(VaultClient):
                pass

    def test_client_not_serializable(self) -> None:
        """Interdiction totale de sérialisation pickle / copy (invariant mémoire)."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with self.assertRaises(TypeError):
            pickle.dumps(client)
        with self.assertRaises(TypeError):
            copy.copy(client)
        with self.assertRaises(TypeError):
            copy.deepcopy(client)

    def test_reject_remote_and_non_loopback(self) -> None:
        """Refus strict des adresses distantes et protocoles non HTTPS."""
        bad_urls = [
            "http://127.0.0.1:8443",
            "https://10.0.0.1:8443",
            "https://192.168.1.1:8443",
            "https://example.com:8443",
            "ftp://127.0.0.1:8443",
            "https://localhost:8443/?query=1",
            "https://localhost:8443/#frag",
            "https://user:pass@127.0.0.1:8443",
            "https://127.0.0.1:8443/extra_path",
            "https://127.0.0.1:99999",
            "https://127.0.0.1:0",
            "https://127.0.0.1:8443%2f",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    VaultClient(url, _VALID_KEY)

    def test_allowed_loopback_hosts(self) -> None:
        """Acceptation des trois variantes de boucle locale contractuelles."""
        c1 = VaultClient("https://127.0.0.1:8443", _VALID_KEY)
        c2 = VaultClient("https://localhost:8443", _VALID_KEY)
        c3 = VaultClient("https://[::1]:8443", _VALID_KEY)
        self.assertIsNotNone(c1)
        self.assertIsNotNone(c2)
        self.assertIsNotNone(c3)

    def test_localhost_is_pinned_to_loopback_ip_at_construction(self) -> None:
        """`localhost` est stocké épinglé : plus aucun nom à résoudre à la connexion."""
        client = VaultClient("https://localhost:8443", _VALID_KEY)
        pinned_host = urlparse(client._base_url).hostname
        self.assertIn(pinned_host, ("127.0.0.1", "::1"))
        self.assertNotIn("localhost", client._base_url)
        client.close()

    def test_pin_loopback_ip_prefers_ipv4_and_rejects_outsiders(self) -> None:
        """Épinglage déterministe : 127.0.0.1 préféré, hors-boucle et pannes refusés."""

        def entry(ip: str) -> tuple:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            return (family, socket.SOCK_STREAM, 6, "", (ip, 0))

        with patch("socket.getaddrinfo", return_value=[entry("::1"), entry("127.0.0.1")]):
            self.assertEqual(_pin_loopback_ip("localhost"), "127.0.0.1")
        with patch("socket.getaddrinfo", return_value=[entry("::1")]):
            self.assertEqual(_pin_loopback_ip("localhost"), "::1")
        with patch("socket.getaddrinfo", return_value=[entry("127.0.0.1")]):
            self.assertEqual(_pin_loopback_ip("localhost"), "127.0.0.1")
        with patch(
            "socket.getaddrinfo", return_value=[entry("127.0.0.1"), entry("93.184.216.34")]
        ):
            with self.assertRaises(ValueError):
                _pin_loopback_ip("localhost")
        with patch("socket.getaddrinfo", return_value=[]):
            with self.assertRaises(ValueError):
                _pin_loopback_ip("localhost")
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with self.assertRaises(ValueError):
                _pin_loopback_ip("localhost")
        # Les littéraux sont retournés inchangés, sans résolution.
        self.assertEqual(_pin_loopback_ip("127.0.0.1"), "127.0.0.1")
        self.assertEqual(_pin_loopback_ip("::1"), "::1")

    def test_localhost_resolution_hang_fails_closed_within_timeout(self) -> None:
        """Résolveur bloqué → `ValueError` en ~2 s, jamais de pendaison."""

        def hanging_resolve(*args: object, **kwargs: object) -> object:
            time.sleep(30)
            return []

        with patch("socket.getaddrinfo", side_effect=hanging_resolve):
            start = time.monotonic()
            try:
                with self.assertRaises(ValueError) as ctx:
                    VaultClient("https://localhost:8443", _VALID_KEY)
            finally:
                elapsed = time.monotonic() - start
            self.assertLess(elapsed, 10)
            self.assertIn("localhost", str(ctx.exception))

    def test_ca_cert_symlink_is_rejected(self) -> None:
        """Un bundle CA pointé par un lien symbolique est refusé (invariant 3)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-ca-") as tmp:
            real_ca = Path(tmp) / "real-ca.pem"
            real_ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
            symlink_ca = Path(tmp) / "ca.pem"
            try:
                os.symlink(real_ca, symlink_ca)
            except OSError:
                self.skipTest("Symlinks non supportés")

            with self.assertRaises(ValueError) as ctx:
                VaultClient(_VALID_URL, _VALID_KEY, ca_cert=symlink_ca)
            self.assertIn("non sécurisé", str(ctx.exception))

    def test_reject_empty_or_whitespace_api_key(self) -> None:
        """Refus d'une clé API vide ou constituée d'espaces."""
        with self.assertRaises(ValueError):
            VaultClient(_VALID_URL, "")
        with self.assertRaises(ValueError):
            VaultClient(_VALID_URL, "   ")

    def test_health_success(self) -> None:
        """health() effectue un appel GET /api/v1/health."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        mock_resp = httpx.Response(
            HTTPStatus.OK,
            json={"status": "pass", "version": "0.1.0"},
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        with patch.object(httpx.Client, "send", return_value=mock_resp):
            data = client.health()
            self.assertEqual(data["status"], "pass")

    def test_create_secret_success(self) -> None:
        """create_secret() envoie le POST /api/v1/secrets avec payload correct."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        mock_resp = httpx.Response(
            HTTPStatus.CREATED,
            json={"project": "demo", "env": "dev", "name": "DB_PASS", "status": "vaulte"},
            request=httpx.Request("POST", f"{_VALID_URL}/api/v1/secrets"),
        )
        with patch.object(httpx.Client, "send", return_value=mock_resp) as mock_send:
            res = client.create_secret("demo", "dev", "DB_PASS", "secret_value")
            self.assertEqual(res["status"], "vaulte")
            mock_send.assert_called_once()
            _, kwargs = mock_send.call_args
            request = kwargs["request"]
            self.assertEqual(request.method, "POST")
            self.assertEqual(str(request.url), f"{_VALID_URL}/api/v1/secrets")
            self.assertEqual(
                json.loads(request.content),
                {"project": "demo", "env": "dev", "name": "DB_PASS", "value": "secret_value"},
            )
            self.assertEqual(request.headers["X-Heimdall-API-Key"], _VALID_KEY)
            self.assertTrue(kwargs["stream"])

    def test_get_secret_success(self) -> None:
        """get_secret() récupère et valide le secret."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        mock_resp = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "value": "super_secret",
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS"),
        )
        with patch.object(httpx.Client, "send", return_value=mock_resp):
            res = client.get_secret("demo", "dev", "DB_PASS")
            self.assertEqual(res["value"], "super_secret")

    def test_get_secret_schema_validation_failures(self) -> None:
        """get_secret() rejette les réponses malformées ou hors limites."""
        client = VaultClient(_VALID_URL, _VALID_KEY)

        # 1. Non-string value
        resp_non_str = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "value": 12345,
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_non_str):
            with self.assertRaises(VaultClientError):
                client.get_secret("demo", "dev", "DB_PASS")

        # 2. Extra unpermitted field
        resp_extra = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "value": "valid",
                "evil_extra": True,
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_extra):
            with self.assertRaises(VaultClientError):
                client.get_secret("demo", "dev", "DB_PASS")

        # 3. Huge value > 65536
        resp_huge = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "value": "x" * 70000,
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_huge):
            with self.assertRaises(VaultClientError):
                client.get_secret("demo", "dev", "DB_PASS")

    def test_get_secret_state_success(self) -> None:
        """get_secret_state() récupère l'état sans valeur."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        mock_resp = httpx.Response(
            HTTPStatus.OK,
            json={"project": "demo", "env": "dev", "name": "DB_PASS", "status": "vaulte"},
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS/state"),
        )
        with patch.object(httpx.Client, "send", return_value=mock_resp):
            res = client.get_secret_state("demo", "dev", "DB_PASS")
            self.assertEqual(res["status"], "vaulte")
            self.assertNotIn("value", res)

    def test_http_error_mappings(self) -> None:
        """Mapping précis des codes HTTP vers exceptions typées."""
        client = VaultClient(_VALID_URL, _VALID_KEY)

        cases = [
            (HTTPStatus.BAD_REQUEST, VaultClientError),
            (HTTPStatus.UNAUTHORIZED, VaultAuthError),
            (HTTPStatus.FORBIDDEN, VaultForbiddenError),
            (HTTPStatus.NOT_FOUND, VaultNotFoundError),
            (HTTPStatus.CONFLICT, VaultConflictError),
            (HTTPStatus.SERVICE_UNAVAILABLE, VaultUnavailableError),
            (HTTPStatus.INTERNAL_SERVER_ERROR, VaultUnavailableError),
        ]
        for status, exc_class in cases:
            with self.subTest(status=status):
                resp = httpx.Response(
                    status,
                    request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
                )
                with patch.object(httpx.Client, "send", return_value=resp):
                    with self.assertRaises(exc_class):
                        client.health()

    def test_rate_limit_with_retry_after(self) -> None:
        """429 Too Many Requests extrait le header standard Retry-After."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        resp = httpx.Response(
            HTTPStatus.TOO_MANY_REQUESTS,
            headers={"retry-after": "15"},
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        with patch.object(httpx.Client, "send", return_value=resp):
            with self.assertRaises(VaultRateLimitError) as ctx:
                client.health()
            self.assertEqual(ctx.exception.retry_after, 15)
            self.assertIn("15 secondes", str(ctx.exception))

    def test_rate_limit_with_aberrant_retry_after_ignores_value(self) -> None:
        """Retry-After négatif ou géant → ignoré, message sans valeur aberrante."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        for header_value in ("-5", "-1", "999999999"):
            with self.subTest(header_value=header_value):
                resp = httpx.Response(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    headers={"retry-after": header_value},
                    request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
                )
                with patch.object(httpx.Client, "send", return_value=resp):
                    with self.assertRaises(VaultRateLimitError) as ctx:
                        client.health()
                    self.assertIsNone(ctx.exception.retry_after)
                    self.assertIn("Trop de requêtes", str(ctx.exception))
                    self.assertNotIn(header_value, str(ctx.exception))

    def test_error_path_giant_headers_is_bounded_before_retry_after(self) -> None:
        """429 + 2 Mio d'en-têtes : erreur bornée, Retry-After et corps jamais lus."""

        class _GiantErrorHeadersResponse:
            status_code = HTTPStatus.TOO_MANY_REQUESTS
            headers = {"retry-after": "30", "x-pad": "y" * (2 * 1024 * 1024)}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(
            httpx.Client, "send", return_value=_GiantErrorHeadersResponse()
        ):
            with self.assertRaises(VaultRateLimitError) as ctx:
                client.health()
        # VaultRateLimitError est un VaultClientError : les deux contrats
        # d'erreur restent satisfaits, sans valeur d'en-tête non bornée.
        self.assertIsNone(ctx.exception.retry_after)
        self.assertIn("en-têtes", str(ctx.exception))
        self.assertNotIn("y" * 1024, str(ctx.exception))

    def test_error_path_giant_headers_on_non_429_is_generic_bounded_error(self) -> None:
        """401 + 2 Mio d'en-têtes : VaultClientError bornée, statut seul conservé."""

        class _GiantErrorHeadersResponse:
            status_code = HTTPStatus.UNAUTHORIZED
            headers = {"x-pad": "y" * (2 * 1024 * 1024)}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(
            httpx.Client, "send", return_value=_GiantErrorHeadersResponse()
        ):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
        self.assertIn("en-têtes", str(ctx.exception).lower())
        self.assertNotIn("y" * 1024, str(ctx.exception))

    def test_network_unavailable_error(self) -> None:
        """Une panne de communication réseau lève VaultUnavailableError."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        connect_err = httpx.ConnectError("Connection refused")
        with patch.object(httpx.Client, "send", side_effect=connect_err):
            with self.assertRaises(VaultUnavailableError):
                client.health()

    def test_client_context_manager_closes(self) -> None:
        """Le context manager ferme proprement la session HTTP."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with client as c:
            self.assertIs(c, client)
        self.assertIsNone(client._client)


class VaultConfigResolutionTests(unittest.TestCase):
    """Tests de résolution de la configuration (clé API, URL, projet)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-cfg-")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_resolve_api_key_from_env(self) -> None:
        """Priorité à HEIMDALL_API_KEY si définie."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "env_secret_key"}):
            self.assertEqual(resolve_api_key(), "env_secret_key")

    def test_resolve_api_key_rejects_oversized_env_key(self) -> None:
        """Clé env > 4096 o. refusée comme le fichier, jamais reflétée."""
        giant_key = "K" * (_MAX_API_KEY_FILE_BYTES + 1)
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": giant_key}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key()
            self.assertIn("trop volumineuse", str(ctx.exception))
            self.assertNotIn(giant_key, str(ctx.exception))

    def test_find_key_file_survives_null_byte_in_env_paths(self) -> None:
        """Octet nul / HOME indéterminé → pas de traceback, erreur « clé requise »."""
        real_get = os.environ.get

        def fake_get_factory(overrides: dict[str, str]) -> object:
            def fake_get(key: str, default: str | None = None) -> str | None:
                if key in overrides:
                    return overrides[key]
                return real_get(key, default)

            return fake_get

        cases = [
            # HEIMDALL_API_KEY_FILE à octet nul : jamais de traceback, quelle
            # que soit la version Python (Path() ou exists() peuvent lever).
            {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": "a\x00b", "XDG_CONFIG_HOME": ""},
            # XDG_CONFIG_HOME à octet nul : recherche impossible → None.
            {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": "", "XDG_CONFIG_HOME": "c\x00d"},
        ]
        for env in cases:
            with self.subTest(xdg=env["XDG_CONFIG_HOME"] != ""):
                with patch("os.environ.get", side_effect=fake_get_factory(env)):
                    try:
                        _find_key_file(None)
                    except Exception as exc:
                        self.fail(f"_find_key_file a levé {type(exc).__name__}")
                    # Contrat : jamais de traceback, toujours l'erreur « clé requise ».
                    with self.assertRaises(VaultClientError) as ctx:
                        resolve_api_key()
                    self.assertIn("Clé API", str(ctx.exception))

    def test_resolve_api_key_from_file_0600(self) -> None:
        """Lecture de la clé depuis un fichier avec permissions strictes 0600."""
        key_file = self.tmp_dir / "vault.key"
        key_file.write_text("file_secret_key\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(key_file, 0o600)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            self.assertEqual(resolve_api_key(key_file), "file_secret_key")

    def test_reject_permissive_key_file(self) -> None:
        """Refus immédiat si le fichier de clé a des droits trop permissifs (>0600)."""
        if os.name != "posix":
            self.skipTest("Contrôle de permissions spécifique POSIX")

        key_file = self.tmp_dir / "vault.key"
        key_file.write_text("file_secret_key\n", encoding="utf-8")
        os.chmod(key_file, 0o644)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(key_file)
            self.assertIn("0600 requis", str(ctx.exception))

    def test_reject_oversized_key_file(self) -> None:
        """Un fichier de clé > 4096 octets est refusé avant lecture complète."""
        key_file = self.tmp_dir / "vault.key"
        key_file.write_bytes(b"k" * 5000)
        if os.name == "posix":
            os.chmod(key_file, 0o600)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(key_file)
            self.assertIn("trop volumineux", str(ctx.exception))

    def test_reject_symlink_key_file(self) -> None:
        """Refus strict si le fichier de clé est un lien symbolique (anti-TOCTOU)."""
        real_file = self.tmp_dir / "real.key"
        real_file.write_text("secret_key_content\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(real_file, 0o600)

        symlink_file = self.tmp_dir / "symlink.key"
        try:
            os.symlink(real_file, symlink_file)
        except OSError:
            self.skipTest("Impossible de créer des liens symboliques")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": ""}):
            with self.assertRaises(VaultClientError):
                resolve_api_key(symlink_file)

    def test_atomic_open_key_file_toctou(self) -> None:
        """Vérifie que _read_and_check_key_file ouvre avec O_NOFOLLOW de façon atomique."""
        real_file = self.tmp_dir / "real2.key"
        real_file.write_text("key_content\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(real_file, 0o600)
        symlink_file = self.tmp_dir / "sym2.key"
        try:
            os.symlink(real_file, symlink_file)
        except OSError:
            self.skipTest("Impossible de créer des liens symboliques")

        with self.assertRaises(VaultClientError):
            _read_and_check_key_file(symlink_file)

    def test_missing_api_key_raises_error(self) -> None:
        """Erreur explicite si aucune clé n'est fournie (ni env ni fichier)."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": ""}):
            with self.assertRaises(VaultClientError) as ctx:
                resolve_api_key(self.tmp_dir / "nonexistent.key")
            self.assertIn("Clé API du Vault requise", str(ctx.exception))

    def test_detect_project_from_pyproject_toml(self) -> None:
        """Détection propre depuis pyproject.toml via parsing toml structuré."""
        pyproject = self.tmp_dir / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "my-special-project"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        with patch.dict(os.environ, {"HEIMDALL_PROJECT": ""}):
            detected = detect_project(self.tmp_dir)
            self.assertEqual(detected, "my-special-project")

    def test_detect_project_ignores_pyproject_symlink(self) -> None:
        """pyproject.toml sous forme de lien symbolique est ignoré."""
        real_pyproject = self.tmp_dir / "real_pyproject.toml"
        real_pyproject.write_text(
            '[project]\nname = "my-special-project"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        symlink_pyproject = self.tmp_dir / "pyproject.toml"
        symlink_pyproject.symlink_to(real_pyproject)

        with patch.dict(os.environ, {"HEIMDALL_PROJECT": ""}):
            detected = detect_project(self.tmp_dir)
            self.assertNotEqual(detected, "my-special-project")

    def test_detect_project_survives_deleted_cwd(self) -> None:
        """cwd supprimé → VaultClientError mappée (jamais de traceback FileNotFoundError)."""
        doomed = self.tmp_dir / "doomed"
        doomed.mkdir()
        previous = os.getcwd()
        os.chdir(doomed)
        try:
            os.rmdir(doomed)
            with patch.dict(os.environ, {"HEIMDALL_PROJECT": ""}):
                with self.assertRaises(VaultClientError):
                    detect_project()
        finally:
            os.chdir(previous)


class VaultAtomicOperationsTests(unittest.TestCase):
    """Tests des fonctions atomiques et sécurisées de manipulation de fichiers."""

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

    def test_write_file_atomic_rejects_symlink(self) -> None:
        """Refus strict d'écraser une cible qui est un lien symbolique (§HIGH 1)."""
        victim = self.tmp_dir / "victim.txt"
        victim.write_text("VICTIM_ORIGINAL_CONTENT\n", encoding="utf-8")

        symlink_target = self.tmp_dir / ".env"
        try:
            os.symlink(victim, symlink_target)
        except OSError:
            self.skipTest("Symlinks non supportés")

        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(symlink_target, "EVIL_CONTENT\n")

        self.assertIn("lien symbolique", str(ctx.exception))
        # La cible originale n'a PAS été écrasée
        self.assertEqual(victim.read_text(encoding="utf-8"), "VICTIM_ORIGINAL_CONTENT\n")

    def test_write_file_atomic_rejects_parent_symlink(self) -> None:
        """Refus strict d'écrire dans un répertoire parent qui est un lien symbolique."""
        real_dir = self.tmp_dir / "real_dir"
        real_dir.mkdir()
        symlink_dir = self.tmp_dir / "sym_dir"
        try:
            os.symlink(real_dir, symlink_dir)
        except OSError:
            self.skipTest("Symlinks non supportés")

        target = symlink_dir / ".env"
        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(target, "DATA\n")
        self.assertIn("répertoire parent", str(ctx.exception))

    def test_write_file_atomic_resists_parent_directory_swap(self) -> None:
        """Un échange du parent après ouverture est détecté par fstat/stat (TOCTOU)."""
        parent = self.tmp_dir / "work"
        parent.mkdir()
        moved_parent = self.tmp_dir / "work-moved"
        outside = self.tmp_dir / "outside"
        outside.mkdir()
        target = parent / ".env"

        real_stat = os.stat
        swapped = False
        parent_abs = os.path.abspath(str(parent))

        def fake_stat(path: object, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            nonlocal swapped
            if not swapped and os.fspath(path) == parent_abs:
                swapped = True
                parent.rename(moved_parent)
                os.symlink(outside, parent)
            return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

        with patch("heimdall.vault.atomic.os.stat", side_effect=fake_stat):
            with self.assertRaises(ValueError) as ctx:
                write_file_atomic(target, "SECRET=1\n")
            self.assertIn("TOCTOU", str(ctx.exception))

        self.assertTrue(swapped)
        self.assertFalse((outside / ".env").exists())

    def test_write_file_atomic_rejects_intermediate_parent_symlink_swap(self) -> None:
        """Un échange d'un parent intermédiaire pendant le marcheur est refusé (ELOOP)."""
        base = self.tmp_dir / "inter_base"
        base.mkdir()
        inter_dir = base / "component"
        inter_dir.mkdir()
        parent = inter_dir / "leaf"
        parent.mkdir()
        target = parent / ".env"

        outside = self.tmp_dir / "outside_hijack"
        outside.mkdir()
        outside_leaf = outside / "leaf"
        outside_leaf.mkdir()

        real_open = os.open
        swapped = False

        def fake_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal swapped
            if (
                not swapped
                and isinstance(path, str)
                and path == "component"
                and (flags & getattr(os, "O_NOFOLLOW", 0))
            ):
                swapped = True
                # Remplacement du parent intermédiaire par un symlink vers outside
                inter_moved = base / "component_moved"
                inter_dir.rename(inter_moved)
                os.symlink(outside, inter_dir)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        with patch("heimdall.vault.atomic.os.open", side_effect=fake_open):
            with self.assertRaises(ValueError) as ctx:
                write_file_atomic(target, "SECRET=1\n")
            self.assertIn("lien symbolique", str(ctx.exception))

        self.assertTrue(swapped)
        self.assertFalse((outside_leaf / ".env").exists())

    def test_backup_file_creation_and_mode_600(self) -> None:
        """backup_file crée une copie .bak en droits 0600 avec assertion de mode."""
        target = self.tmp_dir / ".env"
        write_file_atomic(target, "INITIAL=1\n")
        bak = backup_file(target)
        self.assertIsNotNone(bak)
        assert bak is not None
        self.assertEqual(bak.name, ".env.bak")
        self.assertEqual(bak.read_text(encoding="utf-8"), "INITIAL=1\n")
        self.assertTrue(check_file_mode_600(bak))
        if os.name == "posix":
            mode = stat.S_IMODE(bak.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_backup_file_rejects_symlink(self) -> None:
        """backup_file refuse de lire un lien symbolique."""
        victim = self.tmp_dir / "victim.txt"
        victim.write_text("VICTIM\n", encoding="utf-8")
        symlink_target = self.tmp_dir / ".env"
        try:
            os.symlink(victim, symlink_target)
        except OSError:
            self.skipTest("Symlinks non supportés")

        with self.assertRaises(ValueError):
            backup_file(symlink_target)

    def test_backup_file_nonexistent_returns_none(self) -> None:
        """backup_file retourne None si le fichier n'existe pas."""
        nonexistent = self.tmp_dir / "inexistant.env"
        self.assertIsNone(backup_file(nonexistent))

    def test_backup_file_rejects_oversized_file(self) -> None:
        """Un fichier > 1 Mio est refusé sans être lu intégralement."""
        target = self.tmp_dir / ".env"
        target.write_bytes(b"x" * (2 * 1024 * 1024))

        with self.assertRaises(ValueError) as ctx:
            backup_file(target)
        self.assertIn("taille maximale", str(ctx.exception))
        self.assertFalse((self.tmp_dir / ".env.bak").exists())

    def test_read_file_secure_no_follow_bounds_growth_after_fstat(self) -> None:
        """Un fichier grossi après fstat est rejeté par la lecture bornée."""
        target = self.tmp_dir / "grow.env"
        target.write_bytes(b"A" * (2 * 1024 * 1024))
        # fstat menteur : annonce un petit fichier régulier alors que le
        # fichier réel dépasse largement max_bytes.
        fake_stat = os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))

        with patch("heimdall.vault.atomic.os.fstat", return_value=fake_stat):
            self.assertIsNone(read_file_secure_no_follow(target, max_bytes=1024))

    def test_validate_identifier_truncates_huge_value(self) -> None:
        """Un identifiant de 1 Mio ne produit pas un message d'erreur géant."""
        huge_value = "A" * 1_000_000

        with self.assertRaises(ValueError) as ctx:
            _validate_identifier(huge_value, "projet", _PROJECT_ID_PATTERN)

        message = str(ctx.exception)
        self.assertLess(len(message), 200)
        self.assertNotIn("A" * 1000, message)

    def test_write_file_atomic_cleans_up_on_failure(self) -> None:
        """En cas d'erreur d'écriture, le fichier temporaire est nettoyé (ValueError)."""
        target = self.tmp_dir / "fail.env"
        with patch("os.fsync", side_effect=OSError("disk error")):
            with self.assertRaises(ValueError):
                write_file_atomic(target, "content")
        # Aucun fichier résiduel .tmp
        tmp_files = [f for f in self.tmp_dir.iterdir() if ".tmp." in f.name]
        self.assertEqual(tmp_files, [])

    def test_git_tracked_and_ignored_helpers(self) -> None:
        """Vérification des helpers git avec mock et chemins relatifs."""
        target = self.tmp_dir / ".env"
        target.write_text("x=1\n", encoding="utf-8")
        with patch("shutil.which", return_value=None):
            self.assertFalse(is_git_tracked(target))
            self.assertFalse(is_git_ignored(target))

        # Test quand le fichier est en dehors du dépôt
        top_mock = Path("/some/other/repo")
        with patch("heimdall.vault.atomic._get_git_toplevel", return_value=top_mock):
            self.assertFalse(is_git_tracked(target))
            self.assertFalse(is_git_ignored(target))

    def test_git_helpers_return_false_on_symlink_loop(self) -> None:
        """Boucle symlink : `resolve()` en échec → `False` fail-closed, sans traceback."""
        loop = self.tmp_dir / "loop"
        try:
            os.symlink(loop, loop)
        except OSError:
            self.skipTest("Symlinks non supportés")
        # Boucle réelle : ne doit jamais lever (couvre ELOOP/OSError/RuntimeError
        # selon la version Python, `strict=False` ne lève pas toujours).
        with patch(
            "heimdall.vault.atomic._get_git_toplevel", return_value=self.tmp_dir
        ):
            self.assertFalse(is_git_tracked(loop))
            self.assertFalse(is_git_ignored(loop))
        # Injection directe du cas revue : `resolve()` lève RuntimeError
        # (boucle symlink) ou OSError (ELOOP strict=True) → `False`.
        target = self.tmp_dir / ".env"
        target.write_text("x=1\n", encoding="utf-8")
        with patch(
            "heimdall.vault.atomic._get_git_toplevel", return_value=self.tmp_dir
        ):
            with patch.object(Path, "resolve", side_effect=RuntimeError("Symlink loop")):
                self.assertFalse(is_git_tracked(target))
                self.assertFalse(is_git_ignored(target))
            with patch.object(
                Path, "resolve", side_effect=OSError(40, "Too many levels of symbolic links")
            ):
                self.assertFalse(is_git_tracked(target))
                self.assertFalse(is_git_ignored(target))

    def test_git_toplevel_does_not_follow_symlinked_dir(self) -> None:
        """Répertoire symlinké → cwd = parent réel (lstat), jamais la cible suivie."""
        real_dir = self.tmp_dir / "real_repo"
        real_dir.mkdir()
        link_dir = self.tmp_dir / "link_repo"
        try:
            os.symlink(real_dir, link_dir)
        except OSError:
            self.skipTest("Symlinks non supportés")
        with patch("heimdall.vault.atomic.GitAccess") as mock_access_cls:
            mock_access = mock_access_cls.return_value
            mock_access.execute.return_value = MagicMock(returncode=1, stdout=b"")
            self.assertIsNone(_get_git_toplevel(link_dir))
            # Remontée des ancêtres : le premier cwd est le parent réel du lien.
            self.assertEqual(mock_access_cls.call_args_list[0].args, (link_dir.parent,))
            for call in mock_access_cls.call_args_list:
                self.assertNotEqual(call.args[0], real_dir)

    def test_git_helpers_refuse_symlink_output_without_following(self) -> None:
        """Output symlink (fichier ou répertoire) → False fail-closed, git jamais consulté.

        Non-régression : ``path.resolve()`` suivait le lien final et pouvait
        attribuer à l'output le statut Git de sa cible (avertissement tu).
        """
        victim_file = self.tmp_dir / "git_victim.env"
        victim_file.write_text("X=1\n", encoding="utf-8")
        victim_dir = self.tmp_dir / "git_victim_dir"
        victim_dir.mkdir()
        for victim in (victim_file, victim_dir):
            with self.subTest(victim=victim.name):
                link = self.tmp_dir / f"output_{victim.name}"
                try:
                    os.symlink(victim, link)
                except OSError:
                    self.skipTest("Symlinks non supportés")
                with patch(
                    "heimdall.vault.atomic._get_git_toplevel", return_value=self.tmp_dir
                ):
                    with patch("heimdall.mcp.gitdiff.subprocess.run") as mock_run:
                        self.assertFalse(is_git_tracked(link))
                        self.assertFalse(is_git_ignored(link))
                        mock_run.assert_not_called()

    def test_git_helpers_resolve_parent_but_never_final_symlink(self) -> None:
        """Un parent réel est résolu, mais un lien final reste refusé sans suivre."""
        repo = self.tmp_dir / "repo"
        repo.mkdir()
        target = repo / "tracked.env"
        target.write_text("X=1\n", encoding="utf-8")
        link = repo / "tracked_link.env"
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest("Symlinks non supportés")
        with patch("heimdall.vault.atomic._get_git_toplevel", return_value=repo):
            with patch("heimdall.vault.atomic.GitAccess") as mock_access_cls:
                mock_access = mock_access_cls.return_value
                mock_access.execute.return_value = MagicMock(returncode=0)
                # Le chemin régulier continue d'interroger Git (comportement conservé).
                self.assertTrue(is_git_tracked(target))
                self.assertEqual(mock_access.execute.call_args.args[0][-1], "tracked.env")
                mock_access.execute.reset_mock()
                # Le lien final, lui, est refusé avant toute invocation de Git.
                self.assertFalse(is_git_tracked(link))
                self.assertFalse(is_git_ignored(link))
                mock_access.execute.assert_not_called()

    def test_git_helpers_survive_hanging_git_binary(self) -> None:
        """Binaire `git` bloqué : `TimeoutExpired` → statut inconnu, jamais de pendaison."""
        target = self.tmp_dir / ".env"
        target.write_text("x=1\n", encoding="utf-8")
        with patch("heimdall.mcp.gitdiff.shutil.which", return_value="/usr/bin/git"):
            with patch(
                "heimdall.mcp.gitdiff.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["git"], 5),
            ) as mock_run:
                self.assertFalse(is_git_tracked(target))
                self.assertFalse(is_git_ignored(target))
                for call in mock_run.call_args_list:
                    self.assertEqual(call.kwargs.get("timeout"), 5)

    def test_git_toplevel_returns_before_timeout_with_blocked_binary(self) -> None:
        """Binaire `git` réel qui dort 30 s : retour en < 10 s grâce au timeout."""
        shim_dir = self.tmp_dir / "fakebin"
        shim_dir.mkdir()
        shim = shim_dir / "git"
        shim.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
        shim.chmod(0o700)
        with patch.dict(
            os.environ, {"PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
        ):
            start = time.monotonic()
            self.assertIsNone(_get_git_toplevel(self.tmp_dir))
            self.assertLess(time.monotonic() - start, 10)

    def test_detect_from_git_survives_hanging_git_binary(self) -> None:
        """Détection projet : `TimeoutExpired` → None, jamais de pendaison."""
        with patch("heimdall.mcp.gitdiff.shutil.which", return_value="/usr/bin/git"):
            with patch(
                "heimdall.mcp.gitdiff.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["git"], 5),
            ) as mock_check:
                self.assertIsNone(_detect_from_git(self.tmp_dir))
                self.assertEqual(mock_check.call_args.kwargs.get("timeout"), 5)

    def test_fallback_refuses_symlink_target_and_reverifies_after_replace(self) -> None:
        """Repli Windows (best-effort) : symlink avant/après `replace` → refus."""
        parent = self.tmp_dir / "fallback_parent"
        parent.mkdir()
        victim = self.tmp_dir / "fallback_victim.txt"
        victim.write_text("VICTIM\n", encoding="utf-8")
        # Cible symlink pré-replace → refus, victime intacte.
        link_target = parent / ".env"
        try:
            os.symlink(victim, link_target)
        except OSError:
            self.skipTest("Symlinks non supportés")
        with self.assertRaises(ValueError) as ctx:
            _write_file_atomic_fallback(parent, link_target, b"EVIL\n", 0o600)
        self.assertIn("lien symbolique", str(ctx.exception))
        self.assertEqual(victim.read_text(encoding="utf-8"), "VICTIM\n")
        link_target.unlink()
        # Nominal : le repli écrit puis revérifie via lstat (fichier régulier).
        plain_target = parent / "plain.env"
        _write_file_atomic_fallback(parent, plain_target, b"OK=1\n", 0o600)
        self.assertEqual(plain_target.read_bytes(), b"OK=1\n")

    @unittest.skipUnless(os.name == "posix", "POSIX requis")
    def test_write_file_atomic_never_uses_windows_fallback_on_posix(self) -> None:
        """POSIX : la voie forte dir_fd reste la seule utilisée, repli jamais appelé."""
        target = self.tmp_dir / ".env"
        with patch(
            "heimdall.vault.atomic._write_file_atomic_fallback",
            side_effect=AssertionError("repli Windows interdit sur POSIX"),
        ):
            write_file_atomic(target, "A=1\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "A=1\n")

    def test_fallback_refuses_symlink_replanted_after_replace(self) -> None:
        """Repli Windows : un symlink replanté juste après `replace` est détecté (lstat)."""
        parent = self.tmp_dir / "fallback_race_parent"
        parent.mkdir()
        victim = self.tmp_dir / "fallback_race_victim.txt"
        victim.write_text("VICTIM\n", encoding="utf-8")
        target = parent / ".env"
        real_replace = os.replace

        def replace_then_swap(src: Path, dst: Path) -> None:
            real_replace(src, dst)
            # Simule la course : la cible redevient un symlink après replace.
            os.unlink(dst)
            os.symlink(victim, dst)

        with patch(
            "heimdall.vault.atomic.os.replace", side_effect=replace_then_swap
        ):
            with self.assertRaises(ValueError) as ctx:
                _write_file_atomic_fallback(parent, target, b"EVIL\n", 0o600)
        self.assertIn("lien symbolique", str(ctx.exception))
        self.assertEqual(victim.read_text(encoding="utf-8"), "VICTIM\n")

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
        API_TOKEN=duplicate
        """
        example_file = self.tmp_dir / ".env.example"
        example_file.write_text(content, encoding="utf-8")
        names = parse_example_names(example_file)
        self.assertEqual(names, ["DATABASE_URL", "API_TOKEN", "EMPTY_VAR"])

    def test_parse_env_file_rejects_symlink(self) -> None:
        """parse_env_file refuse les symlinks avec O_NOFOLLOW (anti-exfiltration)."""
        victim = self.tmp_dir / "victim.env"
        victim.write_text("SENSITIVE_LEAKED_VAR=stolen\n", encoding="utf-8")
        symlink_env = self.tmp_dir / "symlink.env"
        try:
            os.symlink(victim, symlink_env)
        except OSError:
            self.skipTest("Symlinks non supportés")
        # Refuse de lire la cible du symlink (distinction None erreur/symlink vs {} vide)
        self.assertIsNone(parse_env_file(symlink_env))

    def test_parse_example_names_rejects_symlink(self) -> None:
        """parse_example_names refuse les symlinks avec O_NOFOLLOW."""
        victim = self.tmp_dir / "victim.example"
        victim.write_text("SENSITIVE_VAR=\n", encoding="utf-8")
        symlink_example = self.tmp_dir / "symlink.example"
        try:
            os.symlink(victim, symlink_example)
        except OSError:
            self.skipTest("Symlinks non supportés")
        self.assertIsNone(parse_example_names(symlink_example))

    def test_get_secret_schema_validation_never_leaks_value(self) -> None:
        """La validation du schéma ne divulgue jamais la valeur fautive (Invariant 8)."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        canary_probe = "TOP_SECRET_CANARY_VALUE_MUST_NEVER_LEAK"  # noqa: S105
        resp_invalid = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "SECRET_PASS",
                "status": "vaulte",
                "value": canary_probe * 2000,  # Dépasse 65536
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/SECRET_PASS"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_invalid):
            with self.assertRaises(VaultClientError) as ctx:
                client.get_secret("demo", "dev", "SECRET_PASS")
            # Invariant 8 absolu : la valeur secrète ne doit JAMAIS figurer dans le message d'erreur
            self.assertNotIn(canary_probe, str(ctx.exception))
            self.assertIn("champs rejetés", str(ctx.exception))

    def test_health_and_create_secret_reject_giant_json_response(self) -> None:
        """health et create_secret rejettent les charges > 1 Mo sans DoS mémoire."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        giant_content = b"{" + b'"status":"ok",' * 100_000 + b'"end":true}'
        resp_giant = httpx.Response(
            HTTPStatus.OK,
            content=giant_content,
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_giant):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

    def test_streaming_response_without_content_length_is_bounded(self) -> None:
        """Le compteur d'octets rejette un corps infini même sans Content-Length."""

        class _EndlessResponse:
            status_code = HTTPStatus.OK
            headers: dict[str, str] = {}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                while True:
                    yield b"x" * 65_536

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_EndlessResponse()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

    def test_streaming_read_uses_bounded_chunks(self) -> None:
        """Aucun chunk géant alloué avant contrôle : chunk_size exigé, 2 Mo rejeté."""
        seen: dict[str, object] = {}

        class _SingleGiantChunkResponse:
            status_code = HTTPStatus.OK
            headers: dict[str, str] = {}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                seen["chunk_size"] = chunk_size
                yield b"y" * (2 * 1024 * 1024)

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_SingleGiantChunkResponse()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))
        self.assertEqual(seen.get("chunk_size"), _STREAM_CHUNK_SIZE)
        self.assertEqual(_STREAM_CHUNK_SIZE, 64 * 1024)

    def test_streaming_response_with_giant_headers_rejected_without_reading_body(self) -> None:
        """En-têtes de 2 Mo sans corps → rejet borné, corps jamais lu."""

        class _GiantHeadersResponse:
            status_code = HTTPStatus.OK
            headers = {"x-pad": "y" * (2 * 1024 * 1024)}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_GiantHeadersResponse()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("En-têtes", str(ctx.exception))

    def test_streaming_response_with_too_many_headers_rejected(self) -> None:
        """300 mini en-têtes → rejet par le plafond de nombre, sans lecture du corps."""

        class _ManyHeadersResponse:
            status_code = HTTPStatus.OK
            headers = {f"x-h{i:04d}": "v" for i in range(300)}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_ManyHeadersResponse()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("En-têtes", str(ctx.exception))

    def test_streaming_real_httpx_response_with_giant_headers_rejected(self) -> None:
        """Vrai `httpx.Response` 2 Mo d'en-têtes → rejet via `.raw`, corps jamais lu."""
        resp_giant_headers = httpx.Response(
            HTTPStatus.OK,
            headers={"x-pad": "y" * (2 * 1024 * 1024)},
            content=b'{"status": "ok"}',
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=resp_giant_headers):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("En-têtes", str(ctx.exception))

    def test_streaming_items_only_headers_without_raw_rejected_early(self) -> None:
        """En-têtes sans `.raw` (`.items()` seul) de 2 Mio → rejet borné, sans liste."""

        class _NoRawHeaders:
            """Headers-like minimal : `.items()`/`.get()`/comptage, sans `.raw`."""

            def __init__(self, mapping: dict[str, str]) -> None:
                self._mapping = dict(mapping)

            def get(self, key: str, default: str | None = None) -> str | None:
                lowered = {k.lower(): v for k, v in self._mapping.items()}
                return lowered.get(key.lower(), default)

            def items(self) -> object:
                return self._mapping.items()

            def __len__(self) -> int:
                return len(self._mapping)

        class _ItemsOnlyGiantHeaders:
            status_code = HTTPStatus.OK
            headers = _NoRawHeaders({"x-pad": "y" * (2 * 1024 * 1024)})

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        assert not hasattr(_ItemsOnlyGiantHeaders.headers, "raw")
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_ItemsOnlyGiantHeaders()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("En-têtes", str(ctx.exception))

    def test_measure_headers_stops_early_without_materializing(self) -> None:
        """Comptage paresseux : rejet après ~256 tirages, jamais de liste géante."""

        class _CountingHeaders:
            """Headers-like infini dont chaque tirage est compté."""

            def __init__(self) -> None:
                self.pulls = 0

            def get(self, key: str, default: object = None) -> object:
                return default

            def items(self) -> object:
                return self._stream()

            def _stream(self) -> object:
                index = 0
                while True:
                    self.pulls += 1
                    index += 1
                    yield (f"x-{index}", "v")

        headers = _CountingHeaders()
        with self.assertRaises(ValueError):
            _measure_response_headers(headers)
        # Sortie anticipée : une fraction du flux suffit, pas de matérialisation.
        self.assertLessEqual(headers.pulls, _MAX_RESPONSE_HEADER_COUNT + 2)

    def test_resolve_api_key_survives_undeterminable_home(self) -> None:
        """`HOME` indéterminé → `VaultClientError` (clé requise), jamais de traceback."""
        with patch.dict(
            os.environ,
            {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": "", "XDG_CONFIG_HOME": ""},
        ):
            with patch.object(
                Path, "home", side_effect=RuntimeError("Could not determine home")
            ):
                with self.assertRaises(VaultClientError) as ctx:
                    resolve_api_key()
                self.assertIn("Clé API", str(ctx.exception))

    def test_ca_cert_path_is_truncated_in_errors(self) -> None:
        """Le chemin --ca-cert n'est jamais recopié en entier (messages bornés)."""
        long_path = "A" * 200
        with self.assertRaises(ValueError) as ctx:
            VaultClient(_VALID_URL, _VALID_KEY, ca_cert=long_path)
        message = str(ctx.exception)
        self.assertIn("A" * 32, message)
        self.assertNotIn("A" * 200, message)

    def test_response_content_length_header_rejection(self) -> None:
        """Rejet précoce si Content-Length dépasse 1 Mo."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        resp = httpx.Response(
            HTTPStatus.OK,
            headers={"Content-Length": "2000000"},
            content=b'{"status":"ok"}',
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        with patch.object(httpx.Client, "send", return_value=resp):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

    def test_health_and_create_reject_100mb_before_reading_body(self) -> None:
        """Content-Length 100 Mo : rejet sans jamais lire le corps (health et create)."""

        class _HeaderOnlyResponse:
            def __init__(self, status_code: int) -> None:
                self.status_code = status_code
                self.headers = {"content-length": str(100 * 1024 * 1024)}

            def iter_bytes(self, chunk_size: int | None = None) -> object:
                raise AssertionError("le corps ne doit pas être lu")

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(
            httpx.Client,
            "send",
            return_value=_HeaderOnlyResponse(HTTPStatus.OK),
        ):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

        with patch.object(
            httpx.Client,
            "send",
            return_value=_HeaderOnlyResponse(HTTPStatus.CREATED),
        ):
            with self.assertRaises(VaultClientError) as ctx:
                client.create_secret("demo", "dev", "DB_PASS", "val")
            self.assertIn("trop volumineuse", str(ctx.exception))

    def test_health_and_create_secret_schema_validation(self) -> None:
        """Validation stricte Pydantic extra=forbid sur endpoints Vault."""
        client = VaultClient(_VALID_URL, _VALID_KEY)

        # Health : rejet si champ inattendu
        resp_bad_health = httpx.Response(
            HTTPStatus.OK,
            json={"status": "ok", "extra_bad": "malicious"},
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/health"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_bad_health):
            with self.assertRaises(VaultClientError):
                client.health()

        # Create secret : rejet si champ inattendu
        resp_bad_create = httpx.Response(
            HTTPStatus.CREATED,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "extra": 123,
            },
            request=httpx.Request("POST", f"{_VALID_URL}/api/v1/secrets"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_bad_create):
            with self.assertRaises(VaultClientError):
                client.create_secret("demo", "dev", "DB_PASS", "val")

        # Get secret state : rejet si 'value' renvoyée
        resp_state_with_value = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "DB_PASS",
                "status": "vaulte",
                "value": "leak",
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/DB_PASS/state"),
        )
        with patch.object(httpx.Client, "send", return_value=resp_state_with_value):
            with self.assertRaises(VaultClientError):
                client.get_secret_state("demo", "dev", "DB_PASS")

    def test_detect_project_fallback(self) -> None:
        """detect_project utilise le nom de dossier si rien d'autre."""
        with patch.dict(os.environ, {"HEIMDALL_PROJECT": "custom-proj"}):
            self.assertEqual(detect_project(), "custom-proj")

    def test_backup_file_on_directory_or_fifo_raises_value_error(self) -> None:
        """backup_file refuse un répertoire ou une FIFO échangée avec fstat."""
        target_dir = self.tmp_dir / "dir_target"
        target_dir.mkdir()
        with patch("pathlib.Path.is_file", return_value=True):
            with self.assertRaises(ValueError) as ctx:
                backup_file(target_dir)
            self.assertIn("n'est pas un fichier régulier", str(ctx.exception))

        if hasattr(os, "mkfifo"):
            fifo_path = self.tmp_dir / "test_fifo"
            try:
                os.mkfifo(fifo_path)
            except OSError:
                return
            with patch("pathlib.Path.is_file", return_value=True):
                with self.assertRaises(ValueError) as ctx:
                    backup_file(fifo_path)
                self.assertIn("n'est pas un fichier régulier", str(ctx.exception))

    def test_get_secret_without_pydantic_truncates_huge_status(self) -> None:
        """En mode dégradé sans Pydantic, un statut géant est tronqué à 32 car. (< 200 car.)."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        huge_status = "s" * 500_000
        resp_bad_status = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "demo",
                "env": "dev",
                "name": "MY_KEY",
                "status": huge_status,
                "value": "secret",
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/MY_KEY"),
        )
        with patch("heimdall.vault.client.BaseModel", None):
            with patch.object(httpx.Client, "send", return_value=resp_bad_status):
                with self.assertRaises(VaultClientError) as ctx:
                    client.get_secret("demo", "dev", "MY_KEY")
                err_msg = str(ctx.exception)
                self.assertLess(len(err_msg), 200)
                self.assertNotIn("s" * 100, err_msg)

    def test_read_file_secure_no_follow_on_fifo_returns_none(self) -> None:
        """read_file_secure_no_follow ne bloque pas sur un FIFO (O_NONBLOCK) et retourne None."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo non supporté")
        fifo_path = self.tmp_dir / "secure_fifo"
        try:
            os.mkfifo(fifo_path)
        except OSError:
            self.skipTest("Impossible de créer un FIFO")
        self.assertIsNone(read_file_secure_no_follow(fifo_path))

    def test_read_and_check_key_file_on_fifo_raises_vault_client_error(self) -> None:
        """_read_and_check_key_file ne bloque pas sur un FIFO et lève VaultClientError."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo non supporté")
        fifo_path = self.tmp_dir / "key_fifo"
        try:
            os.mkfifo(fifo_path)
        except OSError:
            self.skipTest("Impossible de créer un FIFO")
        with self.assertRaises(VaultClientError) as ctx:
            _read_and_check_key_file(fifo_path)
        self.assertIn("fichier régulier", str(ctx.exception))

    def test_open_file_read_fd_bounds_long_path_in_error(self) -> None:
        """Un nom de 4096 caractères ne produit pas un message géant."""
        long_path = self.tmp_dir / ("K" * 4096)
        with self.assertRaises(ValueError) as ctx:
            _open_file_read_fd(long_path)
        message = str(ctx.exception)
        self.assertLessEqual(len(message), 220)
        self.assertNotIn("K" * 200, message)

    def test_open_file_read_fd_escapes_controls_in_open_error(self) -> None:
        """Un chemin non fiable (`\\n`, ESC/ANSI) est échappé dans l'erreur `openat`."""
        control_path = self.tmp_dir / ("A\nB\x1b[2J" + "K" * 300)
        with self.assertRaises(ValueError) as ctx:
            _open_file_read_fd(control_path)
        message = str(ctx.exception)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("\\n", message)
        self.assertIn("\\x1b", message)
        self.assertLessEqual(len(message), 220)

    def test_bounded_error_message_escapes_controls_and_truncates(self) -> None:
        """Helper commun : contrôles échappés, longueur bornée, idempotence."""
        message = _bounded_error_message("a\nb\rc\td\x1b[2J" + "K" * 5000)
        self.assertLessEqual(len(message), 150)
        self.assertTrue(message.endswith("..."))
        self.assertNotIn("\n", message)
        self.assertNotIn("\r", message)
        self.assertNotIn("\t", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("\\n", message)
        self.assertIn("\\x1b", message)
        self.assertEqual(_bounded_error_message(message), message)

    def test_read_and_check_key_file_bounds_wrapped_error(self) -> None:
        """Toute erreur d'ouverture de clé est tronquée avant d'être relayée."""
        long_error = "Lecture refusée : '" + "P" * 5000 + "' est un lien symbolique."
        with patch(
            "heimdall.vault.client._open_file_read_fd",
            side_effect=ValueError(long_error),
        ):
            with self.assertRaises(VaultClientError) as ctx:
                _read_and_check_key_file(self.tmp_dir / "vault.key")
        message = str(ctx.exception)
        self.assertLessEqual(len(message), 220)
        self.assertNotIn("P" * 200, message)

    def test_read_and_check_key_file_bounds_read_error(self) -> None:
        """Une `OSError` géante et piégée de `os.read` est bornée et échappée."""
        key_file = self.tmp_dir / "vault.key"
        key_file.write_text("synthetic_key_value", encoding="utf-8")
        key_file.chmod(0o600)

        with patch(
            "heimdall.vault.client.os.read",
            side_effect=OSError("A\n\x1b[2J" + "R" * 5000),
        ):
            with self.assertRaises(VaultClientError) as ctx:
                _read_and_check_key_file(key_file)

        message = str(ctx.exception)
        self.assertLessEqual(len(message), 220)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("\\n", message)
        self.assertIn("\\x1b", message)
        self.assertNotIn("R" * 200, message)

    def test_write_file_atomic_rejects_symlinked_intermediate_parent(self) -> None:
        """write_file_atomic refuse d'écrire si un parent intermédiaire est un symlink."""
        sub_dir = self.tmp_dir / "real_dir" / "nested"
        sub_dir.mkdir(parents=True)
        link_dir = self.tmp_dir / "link_dir"
        try:
            os.symlink(self.tmp_dir / "real_dir", link_dir)
        except OSError:
            self.skipTest("Symlinks non supportés")
        target = link_dir / "nested" / "output.env"
        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(target, "SECRET=1\n")
        self.assertIn("lien symbolique", str(ctx.exception))

    def test_write_file_atomic_refuses_file_as_intermediate_component(self) -> None:
        """Un composant parent qui est un fichier régulier → refus (pas un répertoire)."""
        base = self.tmp_dir / "file_base"
        base.mkdir()
        blocking_file = base / "sub"
        blocking_file.write_text("je suis un fichier, pas un dossier\n", encoding="utf-8")
        target = blocking_file / "output.env"
        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(target, "SECRET=1\n")
        self.assertIn("pas un répertoire", str(ctx.exception))
        self.assertFalse((base / "sub").is_dir())

    def test_write_file_atomic_refuses_world_writable_parent(self) -> None:
        """Parent 0777 sans sticky bit → refus fail-closed (rename par un autre UID)."""
        if os.name != "posix":
            self.skipTest("Contrôle de permissions POSIX requis")
        base = self.tmp_dir / "ww_base"
        base.mkdir()
        lax_dir = base / "lax"
        lax_dir.mkdir()
        os.chmod(lax_dir, 0o777)  # noqa: S103 - permissions volontairement laxistes pour le test
        target = lax_dir / ".env"
        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(target, "SECRET=1\n")
        self.assertIn("trop permissives", str(ctx.exception))
        self.assertFalse(target.exists())

    def test_write_file_atomic_accepts_sticky_world_writable_parent(self) -> None:
        """Parent 1777 (sticky, ex. /tmp) → autorisé, rename réservé au propriétaire."""
        if os.name != "posix":
            self.skipTest("Contrôle de permissions POSIX requis")
        base = self.tmp_dir / "sticky_base"
        base.mkdir()
        sticky_dir = base / "shared"
        sticky_dir.mkdir()
        os.chmod(sticky_dir, 0o1777)  # noqa: S103 - sticky bit volontaire pour le test
        target = sticky_dir / ".env"
        write_file_atomic(target, "SECRET=1\n", mode=0o600)
        self.assertEqual(target.read_text(encoding="utf-8"), "SECRET=1\n")

    def test_read_file_secure_no_follow_refuses_symlinked_intermediate(self) -> None:
        """Lecture insensible aux symlinks intermédiaires : `out/sub` → lien → None."""
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW requis")
        base = self.tmp_dir / "read_out"
        base.mkdir()
        outside = self.tmp_dir / "read_evil"
        outside.mkdir()
        (outside / "secret.env").write_text("OUTSIDE_SECRET=1\n", encoding="utf-8")
        inter = base / "sub"
        try:
            os.symlink(outside, inter)
        except OSError:
            self.skipTest("Symlinks non supportés")
        # Sans marcheur, l'ouverture suivrait le lien et lirait le fichier externe.
        self.assertIsNone(read_file_secure_no_follow(inter / "secret.env"))

    def test_key_file_reader_refuses_symlinked_intermediate(self) -> None:
        """`_read_and_check_key_file` refuse un parent intermédiaire symlinké."""
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW requis")
        base = self.tmp_dir / "key_out"
        base.mkdir()
        outside = self.tmp_dir / "key_evil"
        outside.mkdir()
        (outside / "vault.key").write_text("attacker_key\n", encoding="utf-8")
        inter = base / "sub"
        try:
            os.symlink(outside, inter)
        except OSError:
            self.skipTest("Symlinks non supportés")
        with self.assertRaises(VaultClientError):
            _read_and_check_key_file(inter / "vault.key")

    def test_check_file_mode_600_refuses_symlink(self) -> None:
        """`check_file_mode_600` ne suit jamais les liens (oracle fail-closed)."""
        if os.name != "posix":
            self.skipTest("POSIX requis")
        victim = self.tmp_dir / "victim.env"
        victim.write_text("X=1\n", encoding="utf-8")
        os.chmod(victim, 0o600)
        self.assertTrue(check_file_mode_600(victim))
        link = self.tmp_dir / "link.env"
        try:
            os.symlink(victim, link)
        except OSError:
            self.skipTest("Symlinks non supportés")
        self.assertFalse(check_file_mode_600(link))

    def test_default_vault_url_avoids_dns_and_rebinding_is_documented(self) -> None:
        """Non-régression : défaut `127.0.0.1` (aucune résolution) + risque documenté."""
        with patch.dict(os.environ, {}, clear=False):
            with patch.dict(os.environ, {"HEIMDALL_VAULT_URL": ""}):
                self.assertEqual(resolve_vault_url(None), "https://127.0.0.1:8443")
        host = urlparse(resolve_vault_url(None)).hostname
        self.assertEqual(host, "127.0.0.1")
        # Si le défaut change vers `localhost`, ce test casse volontairement :
        # le risque de rebinding doit rester documenté.
        doc = _check_localhost_resolution.__doc__ or ""
        self.assertIn("127.0.0.1", doc)
        self.assertIn("localhost", doc)

    def test_windows_fallback_posix_only_guarantee_is_documented(self) -> None:
        """Non-régression : le repli check-then-use reste documenté POSIX-only."""
        doc = _write_file_atomic_fallback.__doc__ or ""
        self.assertIn("POSIX", doc)
        self.assertIn("lstat", doc)

    def test_get_secret_without_pydantic_raises_vault_client_error_on_invalid_identifiers(
        self,
    ) -> None:
        """get_secret sans pydantic (BaseModel=None) lève VaultClientError (pas ValueError)."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        resp_invalid_id = httpx.Response(
            HTTPStatus.OK,
            json={
                "project": "INVALID/PROJECT!",
                "env": "dev",
                "name": "MY_KEY",
                "status": "vaulte",
                "value": "secret",
            },
            request=httpx.Request("GET", f"{_VALID_URL}/api/v1/secrets/demo/dev/MY_KEY"),
        )
        with patch("heimdall.vault.client.BaseModel", None):
            with patch.object(httpx.Client, "send", return_value=resp_invalid_id):
                with self.assertRaises(VaultClientError) as ctx:
                    client.get_secret("demo", "dev", "MY_KEY")
                self.assertIn("Identifiant non conforme", str(ctx.exception))

    def test_stream_closed_raises_vault_unavailable_error(self) -> None:
        """httpx.StreamError (RuntimeError) est converti en VaultUnavailableError sans traceback."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "stream", side_effect=httpx.StreamClosed()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("Erreur de communication avec le Vault", str(ctx.exception))

    def test_request_json_without_httpx_raises_vault_unavailable_error(self) -> None:
        """_get_client sans httpx (RuntimeError) est mappée en VaultUnavailableError."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch("heimdall.vault.client.httpx", None):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("Erreur de communication avec le Vault", str(ctx.exception))

    def test_transport_parameter_rejected_outside_test_environment(self) -> None:
        """Le constructeur prod n'expose aucun hook transport (fail-closed)."""
        fake_transport = MagicMock()
        # Même avec PYTEST_CURRENT_TEST posée, le constructeur refuse tout
        # transport : seule la fabrique test-only l'autorise.
        with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": "1"}):
            with self.assertRaises(TypeError):
                VaultClient(_VALID_URL, _VALID_KEY, transport=fake_transport)  # type: ignore[call-arg]
        # Sans variable d'environnement non plus.
        with patch.dict(os.environ, {}, clear=False):
            with self.assertRaises(TypeError):
                VaultClient(_VALID_URL, _VALID_KEY, transport=fake_transport)  # type: ignore[call-arg]

    def test_create_for_tests_accepts_transport_hook(self) -> None:
        """La fabrique test-only injecte le transport sans contournement env."""
        fake_transport = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            client = VaultClient.create_for_tests(
                _VALID_URL, _VALID_KEY, transport=fake_transport
            )
        self.assertIs(client._transport, fake_transport)
        client.close()

    def test_prod_constructor_exposes_no_transport_hook(self) -> None:
        """Garde anti-contournement env : transport absent de prod, présent en test-only."""
        self.assertNotIn("transport", inspect.signature(VaultClient.__init__).parameters)
        self.assertIn(
            "transport", inspect.signature(VaultClient.create_for_tests).parameters
        )
        # Aucun appelant prod ne renseigne transport (discipline d'appel).
        cli_path = Path(__file__).resolve().parent.parent / "heimdall" / "cli" / "vault_client.py"
        cli_source = cli_path.read_text(encoding="utf-8")
        self.assertNotIn("transport=", cli_source)

    def test_write_file_atomic_refuses_symlinked_intermediate_with_missing_leaf(self) -> None:
        """mkdir intermédiaire ne doit jamais suivre un symlink (LOW revue).

        ``out/sub`` est un symlink vers ``outside`` et ``leaf`` n'existe pas :
        l'ancien ``mkdir(parents=True)`` suivait le lien et créait
        ``outside/leaf/.env`` (détournement). Le marcheur ``openat`` doit
        refuser (ELOOP) sans rien créer côté cible.
        """
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW requis")
        base = self.tmp_dir / "out"
        base.mkdir()
        outside = self.tmp_dir / "evil_target"
        outside.mkdir()
        inter = base / "sub"
        try:
            os.symlink(outside, inter)
        except OSError:
            self.skipTest("Symlinks non supportés")
        target = inter / "leaf" / ".env"
        with self.assertRaises(ValueError) as ctx:
            write_file_atomic(target, "SECRET=1\n")
        self.assertIn("lien symbolique", str(ctx.exception))
        self.assertFalse((outside / "leaf" / ".env").exists())
        self.assertFalse((outside / "leaf").exists())

    def test_write_file_atomic_refuses_concurrent_intermediate_swap(self) -> None:
        """Échange concurrent d'un composant intermédiaire juste avant openat → refus.

        Simule un attaquant local avec écriture sur ``base`` qui remplace
        ``victim_mid`` (répertoire réel) par un symlink vers ``outside``
        entre deux pas du marcheur sécurisé. L'``openat`` suivant avec
        ``O_NOFOLLOW`` lève ``ELOOP`` → ``ValueError`` fail-closed, aucune
        écriture détournée.
        """
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW requis")
        base = self.tmp_dir / "race_base"
        victim_mid = base / "victim_mid"
        leaf = victim_mid / "leaf"
        leaf.mkdir(parents=True)
        outside = self.tmp_dir / "race_outside"
        outside.mkdir()
        target = leaf / ".env"

        real_open = os.open
        swapped = False

        def fake_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal swapped
            if (
                not swapped
                and isinstance(path, str)
                and path == "victim_mid"
                and (flags & getattr(os, "O_NOFOLLOW", 0))
            ):
                swapped = True
                moved = base / "victim_mid_moved"
                victim_mid.rename(moved)
                try:
                    os.symlink(outside, victim_mid)
                except OSError:
                    pass
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        with patch("heimdall.vault.atomic.os.open", side_effect=fake_open):
            with self.assertRaises(ValueError) as ctx:
                write_file_atomic(target, "SECRET=1\n")
            self.assertIn("lien symbolique", str(ctx.exception))

        self.assertTrue(swapped)
        self.assertFalse((outside / "leaf" / ".env").exists())
        self.assertFalse((outside / ".env").exists())


if __name__ == "__main__":
    unittest.main()
