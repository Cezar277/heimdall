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
import stat
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from heimdall.vault.atomic import (
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
    _PROJECT_ID_PATTERN,
    VaultAuthError,
    VaultClient,
    VaultClientError,
    VaultConflictError,
    VaultForbiddenError,
    VaultNotFoundError,
    VaultRateLimitError,
    VaultUnavailableError,
    _read_and_check_key_file,
    _validate_identifier,
    detect_project,
    resolve_api_key,
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
                "status": "actif",
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
                "status": "actif",
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
                "status": "actif",
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
                "status": "actif",
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
                "status": "actif",
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

            def iter_bytes(self) -> object:
                while True:
                    yield b"x" * 65_536

            def close(self) -> None:
                pass

        client = VaultClient(_VALID_URL, _VALID_KEY)
        with patch.object(httpx.Client, "send", return_value=_EndlessResponse()):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

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

            def iter_bytes(self) -> object:
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
                "status": "actif",
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
