"""Fumée du paquet #17 : imports, version, CLI fail-closed. (#17, DoD)"""

import unittest

from typer.testing import CliRunner

import heimdall
import heimdall.cli.main
import heimdall.mcp
import heimdall.mcp.server
import heimdall.scanner
import heimdall.scanner.detect
import heimdall.vault
import heimdall.vault.client
import heimdall.vault.crypto


class PackageSmokeTests(unittest.TestCase):
    def test_version_exposed(self) -> None:
        self.assertEqual(heimdall.__version__, "0.1.0")

    def test_subpackages_importable(self) -> None:
        for module in (
            heimdall.scanner,
            heimdall.scanner.detect,
            heimdall.mcp,
            heimdall.mcp.server,
            heimdall.vault,
            heimdall.vault.client,
            heimdall.vault.crypto,
            heimdall.cli.main,
        ):
            self.assertTrue(module.__name__.startswith("heimdall."))

    def test_cli_help_and_version(self) -> None:
        runner = CliRunner()
        self.assertEqual(runner.invoke(heimdall.cli.main.app, ["--help"]).exit_code, 0)
        version = runner.invoke(heimdall.cli.main.app, ["--version"])
        self.assertEqual(version.exit_code, 0)
        self.assertIn(heimdall.__version__, version.output)

    def test_scan_is_fail_closed_until_22(self) -> None:
        """Sans scanner (#22), `scan` bloque au lieu d'inventer un verdict."""
        runner = CliRunner()
        for argv in (["scan"], ["scan", "--ci"]):
            with self.subTest(argv=argv):
                result = runner.invoke(heimdall.cli.main.app, argv)
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("#22", result.output)

    def test_stubs_raise_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            heimdall.scanner.detect.find_candidates(".")
        with self.assertRaises(NotImplementedError):
            heimdall.mcp.server.run_stdio(".")
        with self.assertRaises(NotImplementedError):
            heimdall.vault.crypto.encrypt_at_rest(b"x", "k")
        with self.assertRaises(ValueError):
            heimdall.vault.client.VaultClient("http://127.0.0.1:8443", "PLACEHOLDER")


if __name__ == "__main__":
    unittest.main()
