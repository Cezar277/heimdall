"""Fumée du paquet #17 : imports, version, CLI fail-closed. (#17, DoD)"""

import os
import tempfile
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
        """Sans scanner (#22), `scan` bloque en erreur d'outillage (exit 2)."""
        runner = CliRunner()
        previous = os.getcwd()
        for argv in (["scan"], ["scan", "--ci"]):
            with self.subTest(argv=argv):
                with tempfile.TemporaryDirectory(prefix="heimdall-scan-") as tmp:
                    os.chdir(tmp)
                    try:
                        result = runner.invoke(heimdall.cli.main.app, argv)
                    finally:
                        os.chdir(previous)
                    self.assertEqual(result.exit_code, 2)
                    self.assertIn("#22", result.output)
                    # Invariant 11 : 2 = panne d'outillage, jamais 1 (secrets).
                    # Le stub n'écrit aucun fichier.
                    self.assertEqual(os.listdir(tmp), [])

    def test_scan_reports_on_stderr(self) -> None:
        result = CliRunner().invoke(heimdall.cli.main.app, ["scan"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("#22", result.stderr)

    def test_stubs_raise_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            heimdall.scanner.detect.find_candidates(".")
        with self.assertRaises(NotImplementedError):
            heimdall.mcp.server.run_stdio(".")
        with self.assertRaises(NotImplementedError):
            heimdall.vault.crypto.encrypt_at_rest(b"x", "k")
        with self.assertRaises(ValueError):
            heimdall.vault.client.VaultClient("http://127.0.0.1:8443", "PLACEHOLDER")

    def test_vault_client_allows_loopback_https_only(self) -> None:
        """HIGH : tout hôte non local est rejeté (exfiltration impossible)."""
        client = heimdall.vault.client.VaultClient("https://127.0.0.1:8443", "PLACEHOLDER")
        self.assertIsInstance(client, heimdall.vault.client.VaultClient)
        for base_url in (
            "https://evil.example",
            "https://127.0.0.1.evil.example",
            "https://localhost.evil.example:8443/api",
            "http://127.0.0.1:8443",  # HTTPS obligatoire même en local.
            "https://user:PLACEHOLDER@127.0.0.1:8443/",  # jamais de credential en URL.
            "https://[::1.evil.example]/",
            "https://127.0.0.1:8443\nInjected: x",  # CRLF : concaténation dangereuse en #25.
            "https://127.0.0.1:8443\tx",
            "https://127.0.0.1:8443 x",
            "https://127.0.0.1:8443\u00a0x",  # NBSP U+00A0 (escape explicite).
            "https://127.0.0.1:8443\u2007x",  # figure space U+2007.
            "https://127.0.0.1:8443?x=1",  # query avalerait le path en #25.
            "https://127.0.0.1:8443#frag",  # fragment tronquerait l'URL en #25.
            "",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    heimdall.vault.client.VaultClient(base_url, "PLACEHOLDER")

    def test_vault_client_repr_never_leaks_api_key(self) -> None:
        """LOW : un log de l'objet ne doit jamais exposer la clé."""
        key = "PLACEHOLDER_NOT_A_KEY_VAULT_REPR"
        client = heimdall.vault.client.VaultClient("https://127.0.0.1:8443", key)
        text = repr(client)
        self.assertNotIn(key, text)
        self.assertIn("<REDACTED>", text)
        # La clé reste nécessaire en mémoire pour s'authentifier : la
        # mitigation est de ne jamais journaliser l'objet ni __dict__.
        self.assertEqual(client._api_key, key)

    def test_vault_client_rejects_empty_key_and_non_canonical_url(self) -> None:
        """LOW : refus local précoce + URL stockée canonique (concaténation sûre)."""
        for key in ("", None):
            with self.subTest(key=repr(key)):
                with self.assertRaises(ValueError):
                    heimdall.vault.client.VaultClient(
                        "https://127.0.0.1:8443",
                        key,  # type: ignore[arg-type]
                    )
        for base_url in (
            "https://127.0.0.1:8443/",  # / final : f"{base_url}/api/..." doublerait le slash.
            "HTTPS://127.0.0.1:8443",  # casse non normalisée.
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    heimdall.vault.client.VaultClient(base_url, "PLACEHOLDER")
        client = heimdall.vault.client.VaultClient("https://127.0.0.1:8443", "PLACEHOLDER")
        self.assertEqual(client._base_url, "https://127.0.0.1:8443")

    def test_vault_client_rejects_non_string_url_and_blank_key(self) -> None:
        """LOW : TypeError interdit (ValueError contractuel) + clé blanche refusée."""
        for base_url in (None, 123, b"https://127.0.0.1:8443"):
            with self.subTest(base_url=repr(base_url)):
                with self.assertRaises(ValueError):
                    heimdall.vault.client.VaultClient(
                        base_url,  # type: ignore[arg-type]
                        "PLACEHOLDER",
                    )
        for key in ("   ", "\t", " \n "):
            with self.subTest(key=repr(key)):
                with self.assertRaises(ValueError):
                    heimdall.vault.client.VaultClient("https://127.0.0.1:8443", key)

    def test_stubs_never_reflect_input(self) -> None:
        """Invariant 8 : aucune entrée reflétée en exception (pattern #22/#27)."""
        marker = "SENTINELLE_ENTREE_NON_FIABLE"
        with self.assertRaises(NotImplementedError) as ctx:
            heimdall.scanner.detect.find_candidates(marker)
        self.assertNotIn(marker, str(ctx.exception))
        with self.assertRaises(NotImplementedError) as ctx:
            heimdall.mcp.server.run_stdio(marker)
        self.assertNotIn(marker, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
