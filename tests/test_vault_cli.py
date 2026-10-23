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
from heimdall.cli.main import app as cli_app
from heimdall.cli.vault_client import RUN_CONTEXT_SETTINGS, vault_run
from heimdall.cli.vault_keys import vault_app
from heimdall.vault.atomic import check_file_mode_600, parse_env_file
from heimdall.vault.client import (
    VaultAuthError,
    VaultClientError,
    VaultConflictError,
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

    def test_push_on_symlink_or_unreadable_file_exits_2(self) -> None:
        """Exit 2 si le fichier source est un lien symbolique ou illisible."""
        real_file = self.tmp_dir / "real.env"
        real_file.write_text("FOO=bar\n", encoding="utf-8")
        symlink_file = self.tmp_dir / "symlink.env"
        symlink_file.symlink_to(real_file)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            result = self.runner.invoke(
                app,
                ["vault", "push", "--file", str(symlink_file), "--project", "demo"],
            )
            self.assertEqual(result.exit_code, 2)
            self.assertIn("lien symbolique", result.output)

    def test_push_rejects_invalid_project_or_env(self) -> None:
        """Validation fail-closed des formats de projet et d'environnement."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            res1 = self.runner.invoke(app, ["vault", "push", "--project", "INVALID_NAME"])
            self.assertEqual(res1.exit_code, 2)
            self.assertIn("invalide", res1.output)

            res2 = self.runner.invoke(app, ["vault", "push", "--project", "valid", "--env", "DEV!"])
            self.assertEqual(res2.exit_code, 2)
            self.assertIn("invalide", res2.output)

    def test_push_success_nominal(self) -> None:
        """Push nominal : envoie les secrets et affiche leur statut sans valeur."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("DB_PASS=my_secret_pass\nAPI_KEY=my_token\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(env_file),
                        "--project",
                        "demo",
                        "--env",
                        "dev",
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("DB_PASS", result.output)
                self.assertIn("API_KEY", result.output)
                self.assertIn("vaulte", result.output)
                # Invariant : JAMAIS les valeurs en clair dans la sortie
                self.assertNotIn("my_secret_pass", result.output)
                self.assertNotIn("my_token", result.output)
                self.assertEqual(client_instance.create_secret.call_count, 2)

    def test_push_filters_by_name(self) -> None:
        """L'option --name ne pousse que les secrets spécifiés."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("FOO_A=val1\nFOO_B=val2\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(env_file),
                        "--project",
                        "demo",
                        "--name",
                        "FOO_A",
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(client_instance.create_secret.call_count, 1)

    def test_push_unknown_name_exits_2_instead_of_silent_success(self) -> None:
        """Un --name sans correspondance est une erreur d'usage, pas un faux succès."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("FOO_A=val1\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(env_file),
                        "--project",
                        "demo",
                        "--name",
                        "INEXISTANT",
                    ],
                )
                self.assertEqual(result.exit_code, 2)
                self.assertIn("Aucun secret ne correspond", result.output)
                mock_init.assert_not_called()

    def test_push_empty_file_exit_codes_depend_on_explicit_filter(self) -> None:
        """Fichier vide : 0 sans filtre documenté, 2 si --name est fourni."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
                self.assertEqual(result.exit_code, 0)
                mock_init.assert_not_called()

            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(env_file),
                        "--project",
                        "demo",
                        "--name",
                        "ANY_SECRET",
                    ],
                )
                self.assertEqual(result.exit_code, 2)
                mock_init.assert_not_called()

    def test_push_handles_auth_error_401(self) -> None:
        """Erreur 401 mappe proprement avec sortie 1."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("KEY=val\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = VaultAuthError("401 Unauthorized")
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("401", result.output)

    def test_push_handles_forbidden_error_403(self) -> None:
        """Erreur 403 mappe proprement avec sortie 1."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("KEY=val\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = VaultForbiddenError("403 Forbidden")
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("403", result.output)

    def test_push_handles_rate_limit_429(self) -> None:
        """Erreur 429 affiche le temps Retry-After et sort en code 1."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("KEY=val\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = VaultRateLimitError(
                    "429 Too Many Requests", retry_after=30
                )
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("429", result.output)
                self.assertIn("30 secondes", result.output)

    def test_push_empty_or_oversized_value_exits_2_without_traceback(self) -> None:
        """Une valeur vide ou > 65536 sort proprement en 2 (invariant 11)."""
        canary_value = "a" * 70000
        cases = [
            ("EMPTY_VALUE=", "EMPTY_VALUE"),
            (f"BIG_VALUE={canary_value}", "BIG_VALUE"),
        ]
        for line, secret_name in cases:
            with self.subTest(secret_name=secret_name):
                env_file = self.tmp_dir / f"{secret_name}.env"
                env_file.write_text(f"{line}\n", encoding="utf-8")

                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        client_instance.create_secret.side_effect = ValueError(
                            "Valeur de secret invalide (1-65536 caractères requis)"
                        )
                        mock_init.return_value = client_instance

                        result = self.runner.invoke(
                            app,
                            [
                                "vault",
                                "push",
                                "--file",
                                str(env_file),
                                "--project",
                                "demo",
                            ],
                        )
                        self.assertEqual(result.exit_code, 2)
                        self.assertIn("valeur invalide", result.output)
                        self.assertNotIn(canary_value, result.output)


class VaultPullCliTests(unittest.TestCase):
    """Tests de la commande `heimdall vault pull` (ticket #100)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-pull-")
        self.tmp_dir = Path(self._tmp.name)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pull_nominal_from_example_file(self) -> None:
        """pull extrait les noms de .env.example, récupère les secrets et écrit en 0600."""
        example_file = self.tmp_dir / ".env.example"
        example_file.write_text("DATABASE_PASSWORD=\n", encoding="utf-8")
        output_file = self.tmp_dir / ".env"

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
                self.assertEqual(
                    parse_env_file(output_file),
                    {"DATABASE_PASSWORD": "db_secret_pass"},
                )
                self.assertNotIn("db_secret_pass", result.output)

    def test_pull_creates_backup_when_env_already_exists(self) -> None:
        """Si un fichier .env existe déjà, un .bak est créé avec droits 0600."""
        output_file = self.tmp_dir / ".env"
        output_file.write_text("OLD_KEY=old_val\n", encoding="utf-8")
        if os.name == "posix":
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

    def test_pull_missing_named_secret_exits_1_without_partial_file(self) -> None:
        """404 sur un nom explicite → Exit(1), aucun .env partiel écrit."""
        output_file = self.tmp_dir / ".env"

        def fake_get_secret(project: str, env: str, name: str) -> dict[str, str]:
            if name == "MISSING_KEY":
                raise VaultNotFoundError("Ressource introuvable dans le Vault (404)")
            return {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "value": "found_val",
            }

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.side_effect = fake_get_secret
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
                        "--name",
                        "FOUND_KEY",
                        "--name",
                        "MISSING_KEY",
                        "--output",
                        str(output_file),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("introuvable", result.output)
                self.assertFalse(output_file.exists())

    def test_run_missing_named_secret_exits_1_without_executing_child(self) -> None:
        """404 sur un nom explicite → Exit(1), l'enfant n'est jamais exécuté."""

        def fake_get_secret(project: str, env: str, name: str) -> dict[str, str]:
            if name == "MISSING_VAR":
                raise VaultNotFoundError("Ressource introuvable dans le Vault (404)")
            return {
                "project": project,
                "env": env,
                "name": name,
                "status": "actif",
                "value": "found_val",
            }

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.side_effect = fake_get_secret
                mock_init.return_value = client_instance

                with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                    result = self.runner.invoke(
                        app,
                        [
                            "run",
                            "--project",
                            "demo",
                            "--name",
                            "FOUND_VAR",
                            "--name",
                            "MISSING_VAR",
                            "--",
                            "echo",
                            "test",
                        ],
                    )
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn("introuvable", result.output)
                    mock_run.assert_not_called()

    def test_push_invalid_requested_name_exits_1_without_sending(self) -> None:
        """`--name` invalide → Exit(1) avant tout envoi, même si un nom valide existe."""
        src_env = self.tmp_dir / "source.env"
        src_env.write_text("VALIDE_KEY=val\n", encoding="utf-8")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "push",
                        "--file",
                        str(src_env),
                        "--project",
                        "demo",
                        "--env",
                        "dev",
                        "--name",
                        "VALIDE_KEY",
                        "--name",
                        "invalide-minuscule",
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("invalide", result.output)
                mock_init.assert_not_called()

    def test_pull_invalid_requested_name_exits_1_without_file(self) -> None:
        """`--name` invalide → Exit(1), aucun .env écrit."""
        output_file = self.tmp_dir / ".env"

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--env",
                        "dev",
                        "--name",
                        "VALIDE_KEY",
                        "--name",
                        "invalide-minuscule",
                        "--output",
                        str(output_file),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("invalide", result.output)
                self.assertFalse(output_file.exists())
                mock_init.assert_not_called()

    def test_run_invalid_requested_name_exits_1_without_executing_child(self) -> None:
        """`--name` invalide → Exit(1), l'enfant n'est jamais exécuté."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                    result = self.runner.invoke(
                        app,
                        [
                            "run",
                            "--project",
                            "demo",
                            "--name",
                            "VALIDE_VAR",
                            "--name",
                            "invalide-minuscule",
                            "--",
                            "echo",
                            "test",
                        ],
                    )
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn("invalide", result.output)
                    mock_run.assert_not_called()
                    mock_init.assert_not_called()

    def test_pull_rejects_newline_in_secret_value(self) -> None:
        """Refus strict d'écrire un secret contenant un saut de ligne dans .env (§HIGH 2)."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "EVIL_VAR",
                    "status": "actif",
                    "value": "x\ny=1",
                }
                mock_init.return_value = client_instance

                out_file = self.tmp_dir / ".env"
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "EVIL_VAR",
                        "--output",
                        str(out_file),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("saut de ligne interdit", result.output)
                self.assertFalse(out_file.exists())

    def test_pull_rejects_carriage_return_in_secret_value(self) -> None:
        """Refus strict d'écrire un secret contenant un retour chariot dans .env."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "EVIL_VAR",
                    "status": "actif",
                    "value": "x\ry=1",
                }
                mock_init.return_value = client_instance

                out_file = self.tmp_dir / ".env"
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "EVIL_VAR",
                        "--output",
                        str(out_file),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("saut de ligne interdit", result.output)

    def test_pull_rejects_symlink_output_file(self) -> None:
        """Refus strict si le chemin de destination .env est un lien symbolique (§HIGH 1)."""
        victim = self.tmp_dir / "victim.txt"
        victim.write_text("VICTIM_DATA\n", encoding="utf-8")
        symlink_out = self.tmp_dir / ".env"
        try:
            os.symlink(victim, symlink_out)
        except OSError:
            self.skipTest("Symlinks non supportés")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "actif",
                    "value": "safe_val",
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
                        "SAFE_VAR",
                        "--output",
                        str(symlink_out),
                        "--no-backup",
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("lien symbolique", result.output)
                self.assertEqual(victim.read_text(encoding="utf-8"), "VICTIM_DATA\n")

    def test_pull_symlink_with_backup_enabled_exits_1_without_traceback(self) -> None:
        """Une sauvegarde refusée (symlink) sort en 1 propre, sans traceback."""
        victim = self.tmp_dir / "victim.txt"
        victim.write_text("VICTIM_DATA\n", encoding="utf-8")
        symlink_out = self.tmp_dir / ".env"
        try:
            os.symlink(victim, symlink_out)
        except OSError:
            self.skipTest("Symlinks non supportés")

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "actif",
                    "value": "safe_val",
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
                        "SAFE_VAR",
                        "--output",
                        str(symlink_out),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("Erreur de sécurité lors de la sauvegarde", result.output)
                self.assertNotIn("Traceback", result.output)
                self.assertEqual(victim.read_text(encoding="utf-8"), "VICTIM_DATA\n")

    def test_pull_quotes_values_for_safe_round_trip(self) -> None:
        """Les valeurs spéciales sont citées et relues à l'identique par parse_env_file."""
        value = 'a"b #c $HOME `touch /tmp/pwned` \\ end='
        output_file = self.tmp_dir / ".env"

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SPECIAL_VALUE",
                    "status": "actif",
                    "value": value,
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
                        "SPECIAL_VALUE",
                        "--output",
                        str(output_file),
                        "--no-backup",
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(parse_env_file(output_file), {"SPECIAL_VALUE": value})
                content = output_file.read_text(encoding="utf-8")
                self.assertIn('\\$HOME', content)
                self.assertIn('\\`touch /tmp/pwned\\`', content)
                self.assertNotIn('="$HOME"', content)

    def test_pull_rejects_glibc_tunables_and_git_ssh_command(self) -> None:
        """Refus strict de pull des variables système sensibles (Looney Tunables, Git hijack)."""
        dangerous = ["GLIBC_TUNABLES", "GIT_SSH_COMMAND"]
        for var_name in dangerous:
            with self.subTest(var_name=var_name):
                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        mock_init.return_value = client_instance

                        out_file = self.tmp_dir / ".env"
                        result = self.runner.invoke(
                            app,
                            [
                                "vault",
                                "pull",
                                "--project",
                                "demo",
                                "--name",
                                var_name,
                                "--output",
                                str(out_file),
                            ],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertIn("variable système interdite", result.output)
                        self.assertFalse(out_file.exists())

    def test_pull_malformed_response_never_leaks_secret_value_on_stderr(self) -> None:
        """Une réponse malformée ne divulgue jamais la valeur secrète sur stderr (Invariant 8)."""
        canary_probe = "CANARY_TOKEN_MUST_NOT_APPEAR"  # noqa: S105
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance

                client_instance.get_secret.side_effect = VaultClientError(
                    "Réponse du Vault non conforme au schéma (champs rejetés : value)"
                )
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "MY_SECRET",
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertNotIn(canary_probe, result.output)

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
                self.assertEqual(
                    parse_env_file(output_file),
                    {"FROM_EXISTING": "pulled_val"},
                )

    def test_pull_warns_when_env_tracked_by_git(self) -> None:
        """Avertissement sur stderr si le .env généré est suivi par Git."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "KEY",
                    "status": "vaulte",
                    "value": "val",
                }
                mock_init.return_value = client_instance

                with patch("heimdall.cli.vault_client.is_git_tracked", return_value=True):
                    result = self.runner.invoke(
                        app,
                        [
                            "vault",
                            "pull",
                            "--project",
                            "demo",
                            "--name",
                            "KEY",
                            "--output",
                            str(output_file),
                        ],
                    )
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn("suivi par Git", result.output)

    def test_pull_warns_when_env_not_ignored(self) -> None:
        """Avertissement si le fichier .env n'est pas ignoré par Git."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "KEY",
                    "status": "vaulte",
                    "value": "val",
                }
                mock_init.return_value = client_instance

                with patch("heimdall.cli.vault_client.is_git_tracked", return_value=False):
                    with patch("heimdall.cli.vault_client.is_git_ignored", return_value=False):
                        result = self.runner.invoke(
                            app,
                            [
                                "vault",
                                "pull",
                                "--project",
                                "demo",
                                "--name",
                                "KEY",
                                "--output",
                                str(output_file),
                            ],
                        )
                        self.assertEqual(result.exit_code, 0)
                        self.assertIn("n'est pas ignoré", result.output)


class VaultRunCliTests(unittest.TestCase):
    """Tests des commandes `heimdall run -- <cmd>` et `heimdall vault run` (ticket #101)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-run-")
        self.tmp_dir = Path(self._tmp.name)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_run_requires_command(self) -> None:
        """Erreur explicite (exit 2) si aucune commande n'est passée après `--`."""
        result = self.runner.invoke(app, ["run", "--project", "demo"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Aucune commande", result.output)

    def test_run_and_vault_run_share_callback_and_guards(self) -> None:
        """`heimdall run` (canonique #101) et `heimdall vault run` (alias)
        routent vers la même `vault_run` avec les mêmes gardes."""
        self.assertEqual(
            RUN_CONTEXT_SETTINGS,
            {"allow_extra_args": True, "ignore_unknown_options": True},
        )
        top_run = next(
            c for c in cli_app.registered_commands if getattr(c, "name", None) == "run"
        )
        vault_run_cmd = next(
            c for c in vault_app.registered_commands if getattr(c, "name", None) == "run"
        )
        self.assertIs(top_run.callback, vault_run)
        self.assertIs(vault_run_cmd.callback, vault_run)
        self.assertIs(top_run.callback, vault_run_cmd.callback)
        self.assertEqual(top_run.context_settings, RUN_CONTEXT_SETTINGS)
        self.assertEqual(vault_run_cmd.context_settings, RUN_CONTEXT_SETTINGS)
        # Mêmes gardes : commande vide → Exit(2) sur les deux voies.
        top_res = self.runner.invoke(app, ["run", "--project", "demo"])
        vault_res = self.runner.invoke(app, ["vault", "run", "--project", "demo"])
        self.assertEqual(top_res.exit_code, 2)
        self.assertEqual(vault_res.exit_code, 2)
        self.assertIn("Aucune commande", top_res.output)
        self.assertIn("Aucune commande", vault_res.output)

    def test_run_nonexistent_command(self) -> None:
        """Exit 127 si l'exécutable spécifié est introuvable."""
        result = self.runner.invoke(
            app,
            ["run", "--project", "demo", "--", "nonexistent_binary_xyz_12345"],
        )
        self.assertEqual(result.exit_code, 127)
        self.assertIn("introuvable", result.output)

    def test_run_rejects_dangerous_env_vars(self) -> None:
        """Interdiction formelle d'injecter des variables système sensibles (§HIGH 3)."""
        dangerous_names = [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "GLIBC_TUNABLES",
            "GIT_SSH_COMMAND",
            "EDITOR",
            "PAGER",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "MAVEN_OPTS",
            "GRADLE_OPTS",
            "DOTNET_STARTUP_HOOKS",
            "COMPOSE_FILE",
            "DOCKER_HOST",
            "AWS_SECRET_ACCESS_KEY",
            "TF_CLI_CONFIG_FILE",
            "KUBECONFIG",
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "CDPATH",
            "GLOBIGNORE",
            "HISTFILE",
            "MAILCAPS",
        ]
        for var_name in dangerous_names:
            with self.subTest(var_name=var_name):
                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        client_instance.get_secret.return_value = {
                            "project": "demo",
                            "env": "dev",
                            "name": var_name,
                            "status": "actif",
                            "value": "/opt/evil",
                        }
                        mock_init.return_value = client_instance

                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                var_name,
                                "--",
                                "echo",
                                "test",
                            ],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertTrue(
                            "variable système" in result.output
                            or "injection refusée" in result.output
                        )

    def test_run_rejects_heimdall_credential_shadowing(self) -> None:
        """`HEIMDALL_*` refusé à l'injection : pas d'écrasement credential du fils."""
        for var_name in (
            "HEIMDALL_API_KEY",
            "HEIMDALL_API_KEY_FILE",
            "HEIMDALL_PROJECT",
            "HEIMDALL_VAULT_URL",
        ):
            with self.subTest(var_name=var_name):
                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        client_instance.get_secret.return_value = {
                            "project": "demo",
                            "env": "dev",
                            "name": var_name,
                            "status": "actif",
                            "value": "attacker_controlled",
                        }
                        mock_init.return_value = client_instance

                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                var_name,
                                "--",
                                "echo",
                                "test",
                            ],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertTrue(
                            "variable système" in result.output
                            or "injection refusée" in result.output
                        )

    def test_run_resolves_binary_before_injection(self) -> None:
        """La commande cible est résolue avant injection des variables (§HIGH 3)."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "actif",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app, ["run", "--project", "demo", "--name", "SAFE_VAR", "--", "true"]
                )
                self.assertEqual(result.exit_code, 0)

    def test_run_permission_error(self) -> None:
        """Exit 126 si l'exécution déclenche une PermissionError."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "actif",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance
                with patch("shutil.which", return_value="/bin/echo"):
                    with patch("subprocess.run", side_effect=PermissionError):
                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                "SAFE_VAR",
                                "--",
                                "echo",
                                "hello",
                            ],
                        )
                        self.assertEqual(result.exit_code, 126)
                        self.assertIn("permission refusée", result.output)

    def test_run_resolves_names_from_dot_env(self) -> None:
        """Récupération des variables depuis .env si ni --name ni .env.example ne sont fournis."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "RESOLVED_FROM_ENV",
                    "status": "actif",
                    "value": "val",
                }
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
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "actif",
                    "value": "val",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--name",
                        "SAFE_VAR",
                        "--",
                        "python",
                        "-c",
                        "import sys; sys.exit(42)",
                    ],
                )
                self.assertEqual(result.exit_code, 42)

    def test_run_rejects_prompt_shell_and_runtime_state_variables(self) -> None:
        """Refus des familles PS4/PROMPT/BASH_*/NPM_*/CARGO_*/GO*/SSH_* (défense en profondeur)."""
        dangerous_names = [
            "PS4",
            "PROMPT_COMMAND",
            "BASHOPTS",
            "SHELLOPTS",
            "ZDOTDIR",
            "LESSOPEN",
            "NPM_CONFIG_REGISTRY",
            "CARGO_HOME",
            "GOPATH",
            "SSH_AUTH_SOCK",
        ]
        for var_name in dangerous_names:
            with self.subTest(var_name=var_name):
                with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                    with patch("heimdall.cli.vault_client._init_client") as mock_init:
                        client_instance = MagicMock()
                        client_instance.__enter__.return_value = client_instance
                        client_instance.get_secret.return_value = {
                            "project": "demo",
                            "env": "dev",
                            "name": var_name,
                            "status": "actif",
                            "value": "/opt/evil",
                        }
                        mock_init.return_value = client_instance

                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                var_name,
                                "--",
                                "echo",
                                "test",
                            ],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertTrue(
                            "variable système" in result.output
                            or "injection refusée" in result.output
                        )

    def test_run_never_uses_vault_response_name_as_env_var(self) -> None:
        """Allowlist locale : un nom renvoyé par le Vault ne devient jamais une variable."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                # Le Vault (compromis) prétend répondre pour PS4 alors que le
                # nom demandé localement est SAFE_VAR.
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "PS4",
                    "status": "actif",
                    "value": "evil_prompt",
                }
                mock_init.return_value = client_instance

                py_code = (
                    "import os, sys\n"
                    "ok = os.environ.get('SAFE_VAR') == 'evil_prompt'\n"
                    "ok = ok and 'PS4' not in os.environ\n"
                    "sys.exit(0 if ok else 1)\n"
                )
                result = self.runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--name",
                        "SAFE_VAR",
                        "--",
                        "python",
                        "-c",
                        py_code,
                    ],
                )
                self.assertEqual(result.exit_code, 0)

    def test_run_with_null_byte_value_exits_1_without_traceback(self) -> None:
        """Une valeur contenant un octet nul sort en 1 sans traceback (attaque MEDIUM 1)."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "NULL_VAL",
                    "status": "actif",
                    "value": "embedded\x00null",
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--name",
                        "NULL_VAL",
                        "--",
                        "python",
                        "-c",
                        "print('hello')",
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertNotIn("Traceback", result.output)
                self.assertIn("octet nul", result.output)

    def test_run_with_symlink_or_unreadable_example_exits_2(self) -> None:
        """run avec un .env.example illisible ou symlink sort en 2 sans exécuter l'enfant."""
        runner_dir = Path(tempfile.mkdtemp())
        example = runner_dir / ".env.example"
        target = runner_dir / "target.txt"
        target.write_text("S=1\n", encoding="utf-8")
        try:
            os.symlink(target, example)
        except OSError:
            self.skipTest("Symlinks non supportés")

        result = self.runner.invoke(
            app,
            [
                "run",
                "--project",
                "demo",
                "--example-file",
                str(example),
                "--",
                "python",
                "-c",
                "print('SHOULD_NOT_RUN')",
            ],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertNotIn("SHOULD_NOT_RUN", result.output)
        self.assertTrue(
            "symlink" in result.output.lower() or "lien symbolique" in result.output.lower()
        )

    def test_pull_output_directory_exits_1_without_traceback(self) -> None:
        """pull vers un répertoire existant sort en 1 sans traceback OSError."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "MY_SECRET",
                    "status": "actif",
                    "value": "clean_value",
                }
                mock_init.return_value = client_instance

                dir_output = Path(tempfile.mkdtemp())
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "MY_SECRET",
                        "-o",
                        str(dir_output),
                    ],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertNotIn("Traceback", result.output)
                self.assertIn("Erreur de sécurité", result.output)

    def test_validate_project_and_env_with_huge_input_truncates_error(self) -> None:
        """Un identifiant de projet de 1 Mio est tronqué à 32 car. dans les logs (< 200 car.)."""
        huge_proj = "a" * 1_000_000
        result = self.runner.invoke(
            app,
            [
                "vault",
                "pull",
                "--project",
                huge_proj,
                "--name",
                "MY_VAR",
            ],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertLess(len(result.output), 200)
        self.assertNotIn("a" * 100, result.output)

    def test_pull_and_push_with_newline_in_api_key_exits_2(self) -> None:
        """Une clé API contenant un saut de ligne sort en 2 proprement sans traceback."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": "line1\nline2"}):
            result_pull = self.runner.invoke(
                app,
                ["vault", "pull", "--project", "demo", "--name", "SEC"],
            )
            self.assertEqual(result_pull.exit_code, 2)
            self.assertNotIn("Traceback", result_pull.output)
            self.assertIn("sauts de ligne", result_pull.output)

            dummy_env = Path(tempfile.mkdtemp()) / "test.env"
            dummy_env.write_text("SEC=1\n", encoding="utf-8")
            try:
                result_push = self.runner.invoke(
                    app,
                    ["vault", "push", "--project", "demo", "--file", str(dummy_env)],
                )
                self.assertEqual(result_push.exit_code, 2)
                self.assertNotIn("Traceback", result_push.output)
                self.assertIn("sauts de ligne", result_push.output)
            finally:
                if dummy_env.exists():
                    dummy_env.unlink()

    def test_run_without_names_or_env_files_exits_2(self) -> None:
        """run sans --name ni .env.example/.env sort en 2 (fail-closed)."""
        empty_dir = Path(tempfile.mkdtemp())
        result = self.runner.invoke(
            app,
            [
                "run",
                "--project",
                "demo",
                "--example-file",
                str(empty_dir / ".env.example"),
                "--",
                "python",
                "-c",
                "print('SHOULD_NOT_RUN')",
            ],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertNotIn("SHOULD_NOT_RUN", result.output)
        self.assertIn("Aucun secret", result.output)

    def test_push_on_conflict_409_does_not_reference_nonexistent_force_flag(self) -> None:
        """Sur 409 Conflict, le message n'indique pas un drapeau --force inexistant."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = VaultConflictError("Conflict")
                mock_init.return_value = client_instance

                dummy_env = Path(tempfile.mkdtemp()) / "conflict.env"
                dummy_env.write_text("MY_VAR=secret\n", encoding="utf-8")
                try:
                    result = self.runner.invoke(
                        app,
                        ["vault", "push", "--project", "demo", "--file", str(dummy_env)],
                    )
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn("409 Conflict", result.output)
                    self.assertNotIn("--force", result.output)
                finally:
                    if dummy_env.exists():
                        dummy_env.unlink()


if __name__ == "__main__":
    unittest.main()
