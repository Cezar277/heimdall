"""Tests CLI pour le client Vault : push, pull et run (tickets #35, #98, #99, #100, #101).

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.vault.atomic import check_file_mode_600
from heimdall.vault.client import (
    VaultAuthError,
    VaultForbiddenError,
    VaultNotFoundError,
    VaultRateLimitError,
)

_TEST_API_KEY = "test_synthetic_cli_api_key_42"


class VaultCliProofTests(unittest.TestCase):
    """Preuves contractuelles et règles de sécurité de la CLI."""

    def test_no_command_accepts_api_key_argument(self) -> None:
        """Preuve DoD ticket #98 : aucun argument ou option --api-key n'existe dans la CLI.

        La clé API ne doit jamais être passée en argument pour éviter toute fuite
        dans l'historique du shell ou la table des processus (`ps`).
        """

        def check_command(cmd_name: str, cmd_obj: object) -> None:
            params = getattr(cmd_obj, "params", [])
            for param in params:
                param_opts = getattr(param, "opts", [])
                for opt in param_opts:
                    self.assertNotIn(
                        "api-key",
                        opt.lower(),
                        f"Option interdite --api-key trouvée sur la commande {cmd_name} ({opt})",
                    )
            subcommands = getattr(cmd_obj, "commands", {})
            for sub_name, sub_obj in subcommands.items():
                check_command(f"{cmd_name} {sub_name}", sub_obj)

        check_command("heimdall", app)


class VaultPushCliTests(unittest.TestCase):
    """Tests de la commande `heimdall vault push` (ticket #99)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-push-")
        self.tmp_dir = Path(self._tmp.name)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_push_fails_when_api_key_missing(self) -> None:
        """Exit 2 avec message clair si aucune clé API n'est disponible."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("DB_PASS=secret123\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": ""}):
            result = self.runner.invoke(
                app,
                ["vault", "push", "--file", str(env_file), "--project", "demo"],
            )
            self.assertEqual(result.exit_code, 2)
            self.assertIn("Clé API", result.output)

    def test_push_fails_when_file_not_found(self) -> None:
        """Exit 2 si le fichier source n'existe pas."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            result = self.runner.invoke(
                app,
                ["vault", "push", "--file", str(self.tmp_dir / "inexistant.env")],
            )
            self.assertEqual(result.exit_code, 2)
            self.assertIn("introuvable", result.output)

    def test_push_rejects_invalid_project_or_env(self) -> None:
        """Validation fail-closed des formats de projet et d'environnement."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            res1 = self.runner.invoke(app, ["vault", "push", "--project", "INVALID_NAME"])
            self.assertEqual(res1.exit_code, 2)
            self.assertIn("invalide", res1.output)

            res2 = self.runner.invoke(app, ["vault", "push", "--project", "valid", "--env", "DEV!"])
            self.assertEqual(res2.exit_code, 2)
            self.assertIn("invalide", res2.output)

    def test_push_skips_invalid_secret_names(self) -> None:
        """Les noms non conformes à ^[A-Z][A-Z0-9_]{1,63}$ sont ignorés avec avertissement."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("invalid_lower=val\nVALID_KEY=val2\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("invalid_lower", result.output)
                client_instance.create_secret.assert_called_once_with(
                    "demo", "dev", "VALID_KEY", "val2"
                )

    def test_push_success_never_leaks_secret_values(self) -> None:
        """Envoi nominal : état marqué 'vaulté', valeur secrète ABSENTE de la sortie."""
        env_file = self.tmp_dir / ".env"
        secret_val = "SUPER_SECRET_VALUE_TO_NEVER_SHOW"  # noqa: S105
        env_file.write_text(f"API_TOKEN={secret_val}\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "API_TOKEN",
                    "status": "vaulte",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo", "--env", "dev"],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("vaulte", result.output)
                self.assertNotIn(secret_val, result.output)

    def test_push_handles_401_403_429(self) -> None:
        """Gestion distincte des erreurs 401, 403 et 429."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("API_TOKEN=secret\n", encoding="utf-8")

        cases = [
            (VaultAuthError("401"), "401"),
            (VaultForbiddenError("403"), "403"),
            (VaultRateLimitError("429", retry_after=30), "429"),
        ]

        for exc, expected_text in cases:
            with self.subTest(exc=exc):
                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        client_instance.create_secret.side_effect = exc
                        mock_init.return_value = client_instance

                        result = self.runner.invoke(
                            app,
                            ["vault", "push", "--file", str(env_file), "--project", "demo"],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertIn(expected_text, result.output)


class VaultPullCliTests(unittest.TestCase):
    """Tests de la commande `heimdall vault pull` (ticket #100)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-pull-")
        self.tmp_dir = Path(self._tmp.name)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pull_writes_env_with_0600_permissions(self) -> None:
        """Pull récupère les secrets et écrit .env en droits 0600."""
        output_file = self.tmp_dir / ".env"
        example_file = self.tmp_dir / ".env.example"
        example_file.write_text("DATABASE_PASSWORD=\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "DATABASE_PASSWORD",
                    "status": "vaulte",
                    "value": "db_secret_pass",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--env",
                        "dev",
                        "--output",
                        str(output_file),
                        "--example-file",
                        str(example_file),
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertTrue(output_file.is_file())
                self.assertTrue(check_file_mode_600(output_file))
                content = output_file.read_text(encoding="utf-8")
                self.assertIn("DATABASE_PASSWORD=db_secret_pass", content)
                self.assertNotIn("db_secret_pass", result.output)

    def test_pull_creates_backup_when_env_already_exists(self) -> None:
        """Si un fichier .env existe déjà, un .bak est créé avec droits 0600."""
        output_file = self.tmp_dir / ".env"
        output_file.write_text("OLD_KEY=old_val\n", encoding="utf-8")
        os.chmod(output_file, 0o600)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "NEW_KEY",
                    "status": "vaulte",
                    "value": "new_val",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "NEW_KEY",
                        "--output",
                        str(output_file),
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                bak_file = self.tmp_dir / ".env.bak"
                self.assertTrue(bak_file.is_file())
                self.assertEqual(bak_file.read_text(encoding="utf-8"), "OLD_KEY=old_val\n")
                self.assertTrue(check_file_mode_600(bak_file))

    def test_pull_rejects_invalid_project_or_env(self) -> None:
        """Validation fail-closed des formats de projet et d'environnement pour pull."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            res1 = self.runner.invoke(app, ["vault", "pull", "--project", "INVALID_NAME"])
            self.assertEqual(res1.exit_code, 2)
            res2 = self.runner.invoke(app, ["vault", "pull", "--project", "valid", "--env", "DEV!"])
            self.assertEqual(res2.exit_code, 2)

    def test_pull_resolves_from_existing_dot_env_when_no_example(self) -> None:
        """Découverte des variables depuis le .env existant si .env.example n'existe pas."""
        output_file = self.tmp_dir / ".env"
        output_file.write_text("FROM_EXISTING=val\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "FROM_EXISTING",
                    "status": "vaulte",
                    "value": "pulled_val",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--output",
                        str(output_file),
                        "--example-file",
                        str(self.tmp_dir / "inexistant.example"),
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("FROM_EXISTING=pulled_val", output_file.read_text(encoding="utf-8"))

    def test_pull_handles_no_secrets_found_in_vault(self) -> None:
        """Exit 1 si aucun secret demandé n'a pu être récupéré (tous 404)."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.side_effect = VaultNotFoundError("404")
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "NOT_IN_VAULT",
                        "--output",
                        str(output_file),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("Aucun secret récupéré", result.output)

    def test_pull_warns_if_env_not_ignored_by_git(self) -> None:
        """Avertissement si .env n'est pas dans .gitignore."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "TEST_KEY",
                    "status": "vaulte",
                    "value": "val",
                }
                mock_init.return_value = client_instance

                with (
                    patch("heimdall.cli.vault_client.is_git_tracked", return_value=False),
                    patch("heimdall.cli.vault_client.is_git_ignored", return_value=False),
                ):
                    result = self.runner.invoke(
                        app,
                        [
                            "vault",
                            "pull",
                            "--project",
                            "demo",
                            "--name",
                            "TEST_KEY",
                            "--output",
                            str(output_file),
                        ],
                    )
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn("n'est pas ignoré par Git", result.output)


class VaultRunCliTests(unittest.TestCase):
    """Tests de la commande `heimdall run -- <cmd>` (ticket #101)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-run-")
        self.tmp_dir = Path(self._tmp.name)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_run_requires_command(self) -> None:
        """Exit 2 si aucune commande n'est passée après run."""
        result = self.runner.invoke(app, ["run"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Aucune commande spécifiée", result.output)

    def test_run_rejects_invalid_project_or_env(self) -> None:
        """Validation fail-closed des formats de projet et d'environnement pour run."""
        res1 = self.runner.invoke(app, ["run", "--project", "INVALID_NAME", "--", "echo", "1"])
        self.assertEqual(res1.exit_code, 2)
        res2 = self.runner.invoke(
            app,
            ["run", "--project", "valid", "--env", "DEV!", "--", "echo", "1"],
        )
        self.assertEqual(res2.exit_code, 2)

    def test_run_command_not_found(self) -> None:
        """Exit 2 avec message d'erreur si la commande est introuvable."""
        result = self.runner.invoke(
            app,
            ["run", "--project", "demo", "--", "nonexistent_binary_xyz_12345"],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("introuvable", result.output)

    def test_run_permission_error(self) -> None:
        """Exit 2 si l'exécution déclenche une PermissionError."""
        with patch("subprocess.run", side_effect=PermissionError):
            result = self.runner.invoke(app, ["run", "--project", "demo", "--", "echo", "hello"])
            self.assertEqual(result.exit_code, 2)
            self.assertIn("permission refusée", result.output)

    def test_run_resolves_names_from_dot_env(self) -> None:
        """Récupération des variables depuis .env si ni --name ni .env.example ne sont fournis."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                # On écrit un .env local
                dot_env = Path(".env")
                created_here = False
                if not dot_env.exists():
                    dot_env.write_text("RESOLVED_FROM_ENV=val\n", encoding="utf-8")
                    created_here = True
                try:
                    result = self.runner.invoke(
                        app,
                        [
                            "run",
                            "--project",
                            "demo",
                            "--example-file",
                            str(self.tmp_dir / "inexistant.example"),
                            "--",
                            "echo",
                            "ok",
                        ],
                    )
                    self.assertEqual(result.exit_code, 0)
                finally:
                    if created_here and dot_env.exists():
                        dot_env.unlink()

    def test_run_injects_secrets_in_memory_without_writing_to_disk(self) -> None:
        """Les secrets sont injectés dans l'environnement du sous-processus sans trace disque."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "INJECTED_SECRET_VAR",
                    "status": "vaulte",
                    "value": "injected_secret_value_999",
                }
                mock_init.return_value = client_instance

                files_before = set(self.tmp_dir.iterdir())

                py_code = (
                    "import os, sys\n"
                    "val = os.environ.get('INJECTED_SECRET_VAR')\n"
                    "sys.exit(0 if val == 'injected_secret_value_999' else 1)\n"
                )

                result = self.runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--name",
                        "INJECTED_SECRET_VAR",
                        "--",
                        "python",
                        "-c",
                        py_code,
                    ],
                )
                self.assertEqual(result.exit_code, 0)

                files_after = set(self.tmp_dir.iterdir())
                self.assertEqual(files_before, files_after)

    def test_run_propagates_child_exit_code(self) -> None:
        """Le code de sortie du sous-processus est fidèlement retourné."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--",
                        "python",
                        "-c",
                        "import sys; sys.exit(42)",
                    ],
                )
                self.assertEqual(result.exit_code, 42)


if __name__ == "__main__":
    unittest.main()
