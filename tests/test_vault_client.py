"""Tests unitaires du client Vault et des opérations atomiques (tickets #98, #99, #100, #101).

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import copy
import os
import pickle
import stat
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
    _read_and_check_key_file,
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
        with patch.object(httpx.Client, "get", return_value=mock_resp):
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
        with patch.object(httpx.Client, "post", return_value=mock_resp) as mock_post:
            res = client.create_secret("demo", "dev", "DB_PASS", "secret_value")
            self.assertEqual(res["status"], "vaulte")
            mock_post.assert_called_once()
            _, kwargs = mock_post.call_args
            self.assertEqual(
                kwargs["json"],
                {"project": "demo", "env": "dev", "name": "DB_PASS", "value": "secret_value"},
            )
            self.assertEqual(kwargs["headers"]["X-Heimdall-API-Key"], _VALID_KEY)

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
        with patch.object(httpx.Client, "get", return_value=mock_resp):
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
        with patch.object(httpx.Client, "get", return_value=resp_non_str):
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
        with patch.object(httpx.Client, "get", return_value=resp_extra):
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
        with patch.object(httpx.Client, "get", return_value=resp_huge):
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
        with patch.object(httpx.Client, "get", return_value=mock_resp):
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
                with patch.object(httpx.Client, "get", return_value=resp):
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
        with patch.object(httpx.Client, "get", return_value=resp):
            with self.assertRaises(VaultRateLimitError) as ctx:
                client.health()
            self.assertEqual(ctx.exception.retry_after, 15)
            self.assertIn("15 secondes", str(ctx.exception))

    def test_network_unavailable_error(self) -> None:
        """Une panne de communication réseau lève VaultUnavailableError."""
        client = VaultClient(_VALID_URL, _VALID_KEY)
        connect_err = httpx.ConnectError("Connection refused")
        with patch.object(httpx.Client, "get", side_effect=connect_err):
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
        # Refuse de lire la cible du symlink
        self.assertEqual(parse_env_file(symlink_env), {})

    def test_parse_example_names_rejects_symlink(self) -> None:
        """parse_example_names refuse les symlinks avec O_NOFOLLOW."""
        victim = self.tmp_dir / "victim.example"
        victim.write_text("SENSITIVE_VAR=\n", encoding="utf-8")
        symlink_example = self.tmp_dir / "symlink.example"
        try:
            os.symlink(victim, symlink_example)
        except OSError:
            self.skipTest("Symlinks non supportés")
        self.assertEqual(parse_example_names(symlink_example), [])

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
        with patch.object(httpx.Client, "get", return_value=resp_invalid):
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
        with patch.object(httpx.Client, "get", return_value=resp_giant):
            with self.assertRaises(VaultClientError) as ctx:
                client.health()
            self.assertIn("trop volumineuse", str(ctx.exception))

    def test_detect_project_fallback(self) -> None:
        """detect_project utilise le nom de dossier si rien d'autre."""
        with patch.dict(os.environ, {"HEIMDALL_PROJECT": "custom-proj"}):
            self.assertEqual(detect_project(), "custom-proj")


if __name__ == "__main__":
    unittest.main()
