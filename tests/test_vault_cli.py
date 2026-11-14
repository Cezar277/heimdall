"""Tests CLI pour le client Vault : push, pull et run (tickets #35, #98, #99, #100, #101).

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer import Exit
from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.cli.main import app as cli_app
from heimdall.cli.vault_client import (
    RUN_CONTEXT_SETTINGS,
    _filter_secrets,
    _pull_secrets_from_vault,
    _push_single_secret,
    _validate_requested_names,
    preview_name,
    vault_run,
)
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

    def test_push_rejects_too_many_secrets_before_any_post(self) -> None:
        """> 1024 entrées → Exit(1) avant `_init_client`, donc aucun POST partiel."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text(
            "\n".join(f"SECRET_{index:04d}=value" for index in range(2000)) + "\n",
            encoding="utf-8",
        )

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
                    ],
                )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("trop de secrets", result.output)
        mock_init.assert_not_called()

    def test_push_rejects_cumulative_secret_volume_before_any_post(self) -> None:
        """Volume cumulé > 1 Mio → Exit(1) avant `_init_client`, aucun POST."""
        secrets = {f"BIG_{index:02d}": "x" * 65_536 for index in range(17)}
        self.assertGreater(sum(len(value) for value in secrets.values()), 1_048_576)

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch(
                "heimdall.cli.vault_client._read_input_secrets",
                return_value=secrets,
            ):
                with patch("heimdall.cli.vault_client._init_client") as mock_init:
                    result = self.runner.invoke(
                        app,
                        ["vault", "push", "--project", "demo"],
                    )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("volume cumulé", result.output)
        mock_init.assert_not_called()

    def test_push_rejects_dangerous_env_names_before_send(self) -> None:
        """`push --name PATH` (ou équivalents) → Exit(2), aucun envoi."""
        for bad_name in ("PATH", "LD_PRELOAD", "HEIMDALL_API_KEY"):
            with self.subTest(bad_name=bad_name):
                env_file = self.tmp_dir / f"{bad_name}.env"
                env_file.write_text(f"{bad_name}=poison\n", encoding="utf-8")
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
                                bad_name,
                            ],
                        )
                self.assertEqual(result.exit_code, 2)
                self.assertIn("interdite", result.output)
                mock_init.assert_not_called()

    def test_push_missing_requested_dangerous_name_exits_2_without_send(self) -> None:
        """`push --name PATH` absent du fichier → Exit(2), jamais un succès silencieux."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("SAFE_VAR=value\n", encoding="utf-8")

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
                        "PATH",
                    ],
                )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Aucun secret ne correspond", result.output)
        mock_init.assert_not_called()

    def test_init_client_bounds_long_config_error(self) -> None:
        """Une erreur de configuration géante et piégée est bornée et échappée."""
        env_file = self.tmp_dir / ".env"
        env_file.write_text("SAFE_VAR=value\n", encoding="utf-8")
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch(
                "heimdall.cli.vault_client.resolve_api_key",
                side_effect=VaultClientError("P\n\x1b[2J" + "P" * 5000),
            ):
                result = self.runner.invoke(
                    app,
                    ["vault", "push", "--file", str(env_file), "--project", "demo"],
                )
        self.assertEqual(result.exit_code, 2)
        self.assertLessEqual(len(result.output), 300)
        self.assertNotIn("P" * 1000, result.output)
        self.assertNotIn("\x1b", result.output)
        self.assertNotIn("P\n", result.output)
        self.assertIn("\\x1b", result.output)

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

    def test_pull_rejects_too_many_names_before_fetch_or_write(self) -> None:
        """Plus de 1024 noms → Exit(1) avant toute requête et sans .env partiel."""
        output_file = self.tmp_dir / ".env"
        names = [f"SECRET_{index:04d}" for index in range(1025)]
        args = ["vault", "pull", "--project", "demo", "--output", str(output_file)]
        for name in names:
            args.extend(["--name", name])

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                mock_init.return_value = client_instance

                result = self.runner.invoke(app, args)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("trop de secrets", result.output)
        client_instance.get_secret.assert_not_called()
        self.assertFalse(output_file.exists())

    def test_pull_rejects_too_many_names_from_example_file_before_fetch(self) -> None:
        """Gros `.env.example` (> 1024 noms) → Exit(1) avant fetch et sans .env."""
        example_file = self.tmp_dir / ".env.example"
        example_file.write_text(
            "\n".join(f"S{index:05d}=" for index in range(65_536)) + "\n",
            encoding="utf-8",
        )
        output_file = self.tmp_dir / ".env"

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
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
                        str(example_file),
                    ],
                )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("trop de secrets", result.output)
        client_instance.get_secret.assert_not_called()
        self.assertFalse(output_file.exists())

    def test_pull_rejects_cumulative_secret_volume_before_write(self) -> None:
        """17 valeurs de 64 Kio (> 1 Mio cumulé) → Exit(1), aucun .env partiel."""
        output_file = self.tmp_dir / ".env"
        names = [f"BIG_{index:02d}" for index in range(17)]
        args = ["vault", "pull", "--project", "demo", "--output", str(output_file)]
        for name in names:
            args.extend(["--name", name])

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "BIG_00",
                    "status": "vaulte",
                    "value": "x" * 65_536,
                }
                mock_init.return_value = client_instance

                result = self.runner.invoke(app, args)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("volume cumulé", result.output)
        self.assertEqual(client_instance.get_secret.call_count, 17)
        self.assertFalse(output_file.exists())

    def test_pull_maps_value_error_identifier_to_exit_1(self) -> None:
        """`ValueError` d'identifiant du client → Exit(1) propre, sans traceback."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.side_effect = ValueError(
                    "Identifiant de secret invalide"
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
                        "SAFE_VAR",
                        "--output",
                        str(output_file),
                    ],
                )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("identifiant invalide", result.output.lower())
        self.assertNotIn("Traceback", result.output)
        self.assertFalse(output_file.exists())

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

    def test_push_rejects_null_byte_value_without_sending(self) -> None:
        """Valeur à octet nul → `Exit(2)` franc avant tout envoi (symétrique pull/run)."""
        src_env = self.tmp_dir / "poisoned.env"
        src_env.write_bytes(b"POISONED_KEY=abc\x00def\n")
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
                        "POISONED_KEY",
                    ],
                )
                self.assertEqual(result.exit_code, 2)
                self.assertIn("valeur invalide", result.output)
                mock_init.assert_not_called()

    def test_pull_backup_error_message_is_bounded(self) -> None:
        """Échec de sauvegarde : stderr < 200 car., pas de recopie intégrale."""
        output_file = self.tmp_dir / ".env"
        output_file.write_bytes(b"OLD=1\n")
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
                with patch(
                    "heimdall.cli.vault_client.backup_file",
                    side_effect=ValueError("z\n\x1b[2J" + "z" * 5000),
                ):
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
                    self.assertEqual(result.exit_code, 1)
                    self.assertLess(len(result.output), 200)
                    self.assertNotIn("z" * 5000, result.output)
                    self.assertNotIn("\x1b", result.output)
                    self.assertNotIn("z\n", result.output)
                    self.assertIn("\\x1b", result.output)

    def test_pull_write_error_message_is_bounded(self) -> None:
        """Échec d'écriture : stderr < 200 car., pas de recopie intégrale."""
        output_file = self.tmp_dir / "fresh.env"
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
                with patch(
                    "heimdall.cli.vault_client.write_file_atomic",
                    side_effect=ValueError("w\n\x1b[2J" + "w" * 5000),
                ):
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
                    self.assertEqual(result.exit_code, 1)
                    self.assertLess(len(result.output), 200)
                    self.assertNotIn("w" * 5000, result.output)

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
                "status": "vaulte",
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

    def test_run_execution_error_message_is_bounded(self) -> None:
        """`OSError` géante → message stderr < 200 car., `Exit(1)` propre."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "vaulte",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance
                with patch(
                    "heimdall.cli.vault_client.subprocess.run",
                    side_effect=OSError("x\n\x1b[2J" + "x" * 5000),
                ):
                    result = self.runner.invoke(
                        app,
                        ["run", "--project", "demo", "--name", "SAFE_VAR", "--", "true"],
                    )
                    self.assertEqual(result.exit_code, 1)
                    self.assertLess(len(result.output), 200)
                    self.assertNotIn("x" * 5000, result.output)
                    self.assertIn("...", result.output)
                    self.assertNotIn("\x1b", result.output)
                    self.assertNotIn("x\n", result.output)
                    self.assertIn("\\x1b", result.output)

    def test_run_refuses_resolved_binary_divergence(self) -> None:
        """`which` A avant fetch puis B après → refus, pas d'exécution du binaire périmé."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "vaulte",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance
                with patch(
                    "heimdall.cli.vault_client.shutil.which",
                    side_effect=["/usr/bin/tool", "/opt/evil/tool"],
                ):
                    with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                "SAFE_VAR",
                                "--",
                                "tool",
                                "--do",
                            ],
                        )
                        self.assertEqual(result.exit_code, 1)
                        self.assertIn("modifiée", result.output)
                        mock_run.assert_not_called()

    def test_run_rejects_which_same_path_with_changed_inode(self) -> None:
        """`which` renvoie la même chaîne mais l'inode change → refus, pas d'exec."""
        real_stat = os.stat
        calls = 0
        first = os.stat_result((stat.S_IFREG | 0o755, 111, 222, 1, 0, 0, 0, 0, 0, 0))
        second = os.stat_result((stat.S_IFREG | 0o755, 333, 444, 1, 0, 0, 0, 0, 0, 0))

        def fake_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            nonlocal calls
            if str(path) == "/usr/bin/tool":
                calls += 1
                return first if calls == 1 else second
            return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "vaulte",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance
                with patch(
                    "heimdall.cli.vault_client.shutil.which",
                    return_value="/usr/bin/tool",
                ):
                    with patch(
                        "heimdall.cli.vault_client.os.stat", side_effect=fake_stat
                    ):
                        with patch(
                            "heimdall.cli.vault_client.subprocess.run"
                        ) as mock_run:
                            result = self.runner.invoke(
                                app,
                                [
                                    "run",
                                    "--project",
                                    "demo",
                                    "--name",
                                    "SAFE_VAR",
                                    "--",
                                    "tool",
                                    "--do",
                                ],
                            )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("modifiée", result.output)
        self.assertEqual(calls, 2)
        mock_run.assert_not_called()

    def test_run_rejects_cumulative_secret_volume_before_exec(self) -> None:
        """17 valeurs de 64 Kio en `run` → Exit(1), aucune exécution enfant."""
        names = [f"BIG_{index:02d}" for index in range(17)]
        args = ["run", "--project", "demo"]
        for name in names:
            args.extend(["--name", name])
        args.extend(["--", "true"])

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "BIG_00",
                    "status": "vaulte",
                    "value": "x" * 65_536,
                }
                mock_init.return_value = client_instance
                with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                    result = self.runner.invoke(app, args)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("volume cumulé", result.output)
        mock_run.assert_not_called()

    def test_push_single_secret_rejects_dangerous_name(self) -> None:
        """Défense en profondeur : `_push_single_secret` refuse aussi les noms interdits."""
        client = MagicMock()
        with self.assertRaises(Exit) as ctx:
            _push_single_secret(client, "demo", "dev", "PATH", "value")
        self.assertEqual(ctx.exception.exit_code, 2)
        client.create_secret.assert_not_called()

    def test_push_single_secret_bounds_and_escapes_dangerous_name(self) -> None:
        """Nom dangereux de 5000 car. : reflet borné à 32 car. et échappé."""
        client = MagicMock()
        # Préfixe dangereux + saut de ligne dans les 32 premiers caractères :
        # le message doit être court et ne jamais contenir de saut brut.
        long_name = "HEIMDALL_\n" + "K" * 5000

        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            with self.assertRaises(Exit) as ctx:
                _push_single_secret(client, "demo", "dev", long_name, "value")

        self.assertEqual(ctx.exception.exit_code, 2)
        message = mock_echo.call_args.args[0]
        self.assertLessEqual(len(message), 150)
        self.assertNotIn("\n", message)
        self.assertIn("\\n", message)
        self.assertNotIn("K" * 100, message)
        client.create_secret.assert_not_called()

    def test_push_single_secret_bounds_and_escapes_send_error(self) -> None:
        """Erreur d'envoi géante et piégée : message borné, sans contrôle brut."""
        client = MagicMock()
        client.create_secret.side_effect = VaultClientError("E\n\x1b[2J" + "X" * 5000)

        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            with self.assertRaises(Exit) as ctx:
                _push_single_secret(client, "demo", "dev", "SAFE_VAR", "value")

        self.assertEqual(ctx.exception.exit_code, 1)
        message = mock_echo.call_args.args[0]
        self.assertLessEqual(len(message), 200)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("\\n", message)
        self.assertIn("\\x1b", message)
        self.assertNotIn("X" * 200, message)

    def test_push_single_secret_distinguishes_identifier_from_value_errors(self) -> None:
        """`ValueError` client : message identifiant vs valeur, jamais la valeur reflétée."""
        client = MagicMock()
        client.create_secret.side_effect = ValueError("Identifiant de nom invalide")
        with self.assertRaises(Exit) as ctx:
            _push_single_secret(client, "demo", "dev", "bad-name", "val")
        self.assertEqual(ctx.exception.exit_code, 2)

        client.create_secret.side_effect = ValueError("Valeur de secret invalide")
        with self.assertRaises(Exit) as ctx:
            _push_single_secret(client, "demo", "dev", "GOOD_NAME", "x" * 70000)
        self.assertEqual(ctx.exception.exit_code, 2)

    def test_filter_secrets_with_non_str_key_exits_2_cleanly(self) -> None:
        """_filter_secrets avec clé non-str sort en Exit(2) fail-closed sans traceback."""
        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            with self.assertRaises(Exit) as ctx:
                _filter_secrets({123: "x"})  # type: ignore[dict-item]
        self.assertEqual(ctx.exception.exit_code, 2)
        message = mock_echo.call_args.args[0]
        self.assertIn("Erreur de sécurité", message)
        self.assertIn("'int'", message)

    def test_pull_secrets_from_vault_with_non_str_name_exits_1_cleanly(self) -> None:
        """La boucle pull avec nom non-str sort proprement en Exit(1) fail-closed sans traceback."""
        client = MagicMock()
        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            with self.assertRaises(Exit) as ctx:
                _pull_secrets_from_vault(client, "demo", "dev", [123])  # type: ignore[list-item]
        self.assertEqual(ctx.exception.exit_code, 1)
        message = mock_echo.call_args.args[0]
        self.assertIn("Erreur de sécurité", message)
        self.assertIn("'int'", message)
        client.get_secret.assert_not_called()

    def test_preview_name_safe_reflections(self) -> None:
        """preview_name borne à 32 car. les str et reflète type(name).__name__ pour non-str."""
        self.assertEqual(preview_name("SAFE_VAR"), "SAFE_VAR")
        self.assertEqual(preview_name("A" * 50), "A" * 32)
        self.assertEqual(preview_name(123), "int")
        self.assertEqual(preview_name(None), "NoneType")
        self.assertEqual(preview_name([1, 2]), "list")

    def test_filter_secrets_ignores_trailing_newline_key_cleanly(self) -> None:
        """_filter_secrets avec clé se terminant par \n ignore la clé (format invalide)."""
        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            filtered = _filter_secrets({"AB\n": "x"})
        self.assertEqual(filtered, {})
        message = mock_echo.call_args.args[0]
        self.assertIn("Avertissement", message)
        self.assertIn("format invalide", message)

    def test_pull_secrets_ignores_trailing_newline_name_cleanly(self) -> None:
        """La boucle pull avec nom se terminant par \n ignore le nom (format invalide)."""
        client = MagicMock()
        with patch("heimdall.cli.vault_client.typer.echo") as mock_echo:
            res = _pull_secrets_from_vault(client, "demo", "dev", ["AB\n"])
        self.assertEqual(res, {})
        message = mock_echo.call_args.args[0]
        self.assertIn("Avertissement", message)
        self.assertIn("format invalide", message)
        client.get_secret.assert_not_called()

    def test_validate_requested_names_rejects_trailing_newline_and_non_str(self) -> None:
        """_validate_requested_names refuse 'AB\n' et les non-str en Exit(1) sans TypeError."""
        with self.assertRaises(Exit) as ctx:
            _validate_requested_names(["AB\n"])
        self.assertEqual(ctx.exception.exit_code, 1)

        with self.assertRaises(Exit) as ctx:
            _validate_requested_names([123])  # type: ignore[list-item]
        self.assertEqual(ctx.exception.exit_code, 1)

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
                    "status": "vaulte",
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
                    "status": "vaulte",
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
                    "status": "vaulte",
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
                    "status": "vaulte",
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
                    "status": "vaulte",
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
                        with patch(
                            "heimdall.cli.vault_client._get_git_toplevel",
                            return_value=self.tmp_dir,
                        ):
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

    def test_pull_warns_indeterminate_git_status_outside_repo(self) -> None:
        """Hors dépôt : statut « indéterminé » distinct, jamais de silence."""
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
                self.assertIn("indéterminé", result.output)

    def test_pull_without_api_key_and_broken_home_exits_2_cleanly(self) -> None:
        """`HOME` indéterminé + pas de clé → `Exit(2)` propre, pas de traceback."""
        output_file = self.tmp_dir / ".env"
        with patch.dict(
            os.environ,
            {"HEIMDALL_API_KEY": "", "HEIMDALL_API_KEY_FILE": "", "XDG_CONFIG_HOME": ""},
        ):
            with patch.object(
                Path, "home", side_effect=RuntimeError("Could not determine home")
            ):
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
                self.assertEqual(result.exit_code, 2)
                self.assertIn("Erreur de configuration", result.output)
                self.assertFalse(output_file.exists())

    def test_pull_without_api_key_and_null_byte_key_file_exits_2_cleanly(self) -> None:
        """`HEIMDALL_API_KEY_FILE` à octet nul → `Exit(2)` propre, pas de traceback."""
        output_file = self.tmp_dir / ".env"
        real_get = os.environ.get

        def fake_get(key: str, default: str | None = None) -> str | None:
            if key == "HEIMDALL_API_KEY":
                return ""
            if key == "HEIMDALL_API_KEY_FILE":
                return "kb\x00b"
            if key == "XDG_CONFIG_HOME":
                return ""
            return real_get(key, default)

        with patch("os.environ.get", side_effect=fake_get):
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
            self.assertEqual(result.exit_code, 2)
            self.assertIn("Erreur de configuration", result.output)
            self.assertFalse(output_file.exists())


    def test_pull_without_project_and_deleted_cwd_exits_2_cleanly(self) -> None:
        """cwd supprimé + pas de --project → `Exit(2)` propre, pas de traceback."""
        output_file = self.tmp_dir / ".env"
        doomed = self.tmp_dir / "doomed_cli"
        doomed.mkdir()
        previous = os.getcwd()
        saved_project = os.environ.get("HEIMDALL_PROJECT")
        if "HEIMDALL_PROJECT" in os.environ:
            del os.environ["HEIMDALL_PROJECT"]
        os.chdir(doomed)
        try:
            os.rmdir(doomed)
            with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
                result = self.runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--name",
                        "KEY",
                        "--output",
                        str(output_file),
                    ],
                )
                self.assertEqual(result.exit_code, 2)
                self.assertIn("Erreur de configuration", result.output)
                self.assertFalse(output_file.exists())
                self.assertNotIsInstance(result.exception, FileNotFoundError)
        finally:
            os.chdir(previous)
            if saved_project is not None:
                os.environ["HEIMDALL_PROJECT"] = saved_project

    def test_pull_warns_indeterminate_git_status_without_git_binary(self) -> None:
        """Sans binaire git : statut « indéterminé », jamais de silence."""
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

                with patch("heimdall.mcp.gitdiff.shutil.which", return_value=None):
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
                    self.assertIn("indéterminé", result.output)

    def test_pull_backup_warns_for_bak_git_status(self) -> None:
        """La garde Git couvre aussi le `.bak` (secrets) : 2 avertissements, 0 silence."""
        output_file = self.tmp_dir / ".env"
        output_file.write_text("OLD_KEY=old_val\n", encoding="utf-8")
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
                self.assertEqual(result.output.count("indéterminé"), 2)
                self.assertIn(".bak", result.output)


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
                            "status": "vaulte",
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
                            "status": "vaulte",
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

    def test_run_rejects_runtime_manager_and_shell_state_vars(self) -> None:
        """Runtimes/état shell refusés : BUN_/DENO_/UV_/PIP_/BUNDLE_/GEM_/CONDA_,
        TERMINFO/TERMPATH/VIRTUAL_ENV (PYTHONHOME couvert par le préfixe PYTHON)."""
        for var_name in (
            "BUN_INSTALL",
            "DENO_DIR",
            "UV_PYTHON",
            "PIP_INDEX_URL",
            "BUNDLE_GEMFILE",
            "GEM_HOME",
            "CONDA_ENVS_PATH",
            "TERMINFO",
            "TERMPATH",
            "VIRTUAL_ENV",
            "PYTHONHOME",
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
                            "status": "vaulte",
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

    def test_run_rejects_shell_input_and_module_path_vars(self) -> None:
        """readline/terminal/fuseau/modules refusés : INPUTRC/TERM/TZ/TERMCAP/LUA_*."""
        for var_name in (
            "INPUTRC",
            "TERM",
            "TZ",
            "TERMCAP",
            "LUA_PATH",
            "LUA_CPATH",
            "LUA_INIT",
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
                            "status": "vaulte",
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

    def test_run_refuses_path_command_substituted_before_exec(self) -> None:
        """Chemin avec slash substitué après résolution → Exit(127), pas d'exécution."""
        tool = self.tmp_dir / "tool.sh"
        tool.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.return_value = {
                    "project": "demo",
                    "env": "dev",
                    "name": "SAFE_VAR",
                    "status": "vaulte",
                    "value": "secret_val",
                }
                mock_init.return_value = client_instance
                with patch(
                    "heimdall.cli.vault_client.os.lstat",
                    side_effect=FileNotFoundError(2, "No such file or directory"),
                ):
                    with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                        result = self.runner.invoke(
                            app,
                            [
                                "run",
                                "--project",
                                "demo",
                                "--name",
                                "SAFE_VAR",
                                "--",
                                str(tool),
                                "--do",
                            ],
                        )
                        self.assertEqual(result.exit_code, 127)
                        self.assertIn("introuvable", result.output)
                        mock_run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX requis")
    def test_run_refuses_path_command_rewritten_in_place_before_exec(self) -> None:
        """Voie slash : même inode, contenu/taille changés pendant le fetch → refus."""
        tool = self.tmp_dir / "tool.sh"
        tool.write_text("#!/bin/sh\necho safe\n", encoding="utf-8")
        os.chmod(tool, 0o600)  # Non exécutable : `which` renvoie None (voie slash).
        inode_before = tool.stat().st_ino

        def rewrite_in_place(*args: object, **kwargs: object) -> dict[str, str]:
            # Réécriture O_TRUNC : même inode, contenu/taille/mtime/ctime changés.
            tool.write_text("#!/bin/sh\necho pwned-with-more-bytes\n", encoding="utf-8")
            return {
                "project": "demo",
                "env": "dev",
                "name": "SAFE_VAR",
                "status": "vaulte",
                "value": "secret_val",
            }

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.get_secret.side_effect = rewrite_in_place
                mock_init.return_value = client_instance
                with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                    result = self.runner.invoke(
                        app,
                        [
                            "run",
                            "--project",
                            "demo",
                            "--name",
                            "SAFE_VAR",
                            "--",
                            str(tool),
                            "--do",
                        ],
                    )

        self.assertEqual(tool.stat().st_ino, inode_before)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("modifiée", result.output)
        mock_run.assert_not_called()

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
                    "status": "vaulte",
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
                    "status": "vaulte",
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
                    "status": "vaulte",
                    "value": "val",
                }
                mock_init.return_value = client_instance

                # On écrit un .env dans un répertoire isolé : le test ne doit
                # dépendre ni du .env de la racine du dépôt ni du cwd du runner.
                dot_env = self.tmp_dir / ".env"
                dot_env.write_text("RESOLVED_FROM_ENV=val\n", encoding="utf-8")
                previous = Path.cwd()
                try:
                    os.chdir(self.tmp_dir)
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
                    os.chdir(previous)
                    dot_env.unlink(missing_ok=True)

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
                        sys.executable,
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
                    "status": "vaulte",
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
                        sys.executable,
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
                            "status": "vaulte",
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
                    "status": "vaulte",
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
                        sys.executable,
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
                    "status": "vaulte",
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
                        sys.executable,
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
                sys.executable,
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
                    "status": "vaulte",
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
                sys.executable,
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
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn("409 Conflict", result.output)
                    self.assertIn("non écrasé", result.output)
                    self.assertNotIn("--force", result.output)
                finally:
                    if dummy_env.exists():
                        dummy_env.unlink()

    def test_push_all_conflict_exits_1_without_claiming_success(self) -> None:
        """Tout-conflit → Exit(1), aucun message de succès affiché."""
        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = VaultConflictError("Conflict")
                mock_init.return_value = client_instance

                dummy_env = Path(tempfile.mkdtemp()) / "allconflict.env"
                dummy_env.write_text("AAA=1\nBBB=2\n", encoding="utf-8")
                try:
                    result = self.runner.invoke(
                        app,
                        ["vault", "push", "--project", "demo", "--file", str(dummy_env)],
                    )
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn("Aucun secret créé", result.output)
                    self.assertNotIn("traité", result.output)
                finally:
                    if dummy_env.exists():
                        dummy_env.unlink()

    def test_push_mixed_created_and_conflict_reports_honest_counts(self) -> None:
        """Partiel réel (1 créé + 1 conflit) → Exit(0) avec compteurs honnêtes."""

        def fake_create(project: str, env: str, name: str, value: str) -> dict[str, str]:
            if name == "TAKEN_VAR":
                raise VaultConflictError("Conflict")
            return {"project": project, "env": env, "name": name, "status": "vaulte"}

        with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
            with patch("heimdall.cli.vault_client._init_client") as mock_init:
                client_instance = MagicMock()
                client_instance.__enter__.return_value = client_instance
                client_instance.create_secret.side_effect = fake_create
                mock_init.return_value = client_instance

                dummy_env = Path(tempfile.mkdtemp()) / "mixed.env"
                dummy_env.write_text("NEW_VAR=v\nTAKEN_VAR=w\n", encoding="utf-8")
                try:
                    result = self.runner.invoke(
                        app,
                        ["vault", "push", "--project", "demo", "--file", str(dummy_env)],
                    )
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn("1 secret(s) créé(s)", result.output)
                    self.assertIn("1 déjà existant(s)", result.output)
                finally:
                    if dummy_env.exists():
                        dummy_env.unlink()


if __name__ == "__main__":
    unittest.main()
