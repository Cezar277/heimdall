"""Tests du serveur MCP — sous-ticket #73 (SDK, stdio, outil ``ping``).

Ces tests passent par un vrai client MCP (``mcp.client.stdio``) qui
démarre le serveur en sous-processus : c'est la seule façon de prouver le
canal de bout en bout (sérialisation JSON-RPC comprise), et pas seulement
la logique Python.

Le client est un outil de test, jamais une dépendance du produit : le
serveur ne connaît que le SDK officiel (``mcp``, voir ADR-002).
"""

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import mcp_contract
from support.mcp_client import REPO_ROOT, call_tool, list_tools, tool_payload
from typer.testing import CliRunner

import heimdall.cli.main
from heimdall.mcp import server as mcp_server


class PingToolTests(unittest.TestCase):
    def test_ping_answers_pong(self) -> None:
        """Fait quand (#73) : un client MCP appelle ping et obtient une réponse."""
        result = call_tool("ping", {})
        self.assertFalse(result.is_error)
        self.assertEqual(tool_payload(result), {"pong": True})

    def test_ping_is_declared_to_the_client(self) -> None:
        """L'outil doit apparaître dans tools/list, avec sa description."""
        listed = list_tools()
        # Registre fermé : la liste annoncée est exactement SERVER_TOOLS,
        # dans l'ordre, et rien d'autre n'est appelable (contrat #16, I8).
        self.assertEqual(listed, list(mcp_server.SERVER_TOOLS))
        self.assertEqual(listed, ["ping", "read_diff", "sanitize_file"])

    def test_ping_needs_neither_git_nor_repository(self) -> None:
        """La sonde de vie marche hors dépôt : aucun appel à git pour ping."""
        with tempfile.TemporaryDirectory(prefix="heimdall-mcp-") as tmp:
            result = call_tool("ping", {}, root=Path(tmp))
            self.assertEqual(tool_payload(result), {"pong": True})


class ContractGapTests(unittest.TestCase):
    """Écart assumé au contrat #16 : `ping` est exposé hors contrat (ADR-003 §2).

    Ce test **verrouille** l'écart, il ne l'approuve pas. Tant que `ping` n'a
    pas été intégré au schéma figé, aucun AUTRE nom hors contrat ne doit être
    exposé ; le jour où le contrat l'intègre, ce test échoue et on le
    supprime — c'est le signal qui évite que la dérogation serve de
    précédent (« on ajoute, on documentera plus tard »).
    """

    def test_only_ping_is_exposed_outside_the_contract(self) -> None:
        contract_tools = set(mcp_contract.contract()["x-tools"])
        outside = [name for name in mcp_server.SERVER_TOOLS if name not in contract_tools]
        self.assertEqual(outside, ["ping"])

    def test_contract_tools_delivered_later_are_registered_but_not_exposed(self) -> None:
        """`MCP_TOOLS` reste la référence figée des 4 outils du contrat."""
        delivered = set(mcp_server.SERVER_TOOLS) - set(mcp_server.MCP_TOOLS)
        self.assertEqual(delivered, {"ping"})
        self.assertEqual(
            set(mcp_server.MCP_TOOLS) - set(mcp_server.SERVER_TOOLS),
            {"list_candidates", "propose_patch"},
        )


class ArgumentGateTests(unittest.TestCase):
    def test_unknown_field_is_refused_not_ignored(self) -> None:
        """Invariant 11 (#16) : pas de champ « bonus » accepté en douce.

        Le SDK MCP 2.3.0 écarte silencieusement les clés qu'aucun paramètre
        ne déclare ; sans la garde, ``{"root": "/etc"}`` serait ignoré au
        lieu d'être refusé.
        """
        result = call_tool("ping", {"root": "/etc", "path": "../.."})
        self.assertTrue(result.is_error)
        self.assertEqual(tool_payload(result)["error"]["code"], "INVALID_INPUT")

    def test_failure_envelopes_are_flagged(self) -> None:
        """Toute enveloppe d'échec est marquée ``isError`` (contrat 3.1)."""
        result = call_tool("read_diff", {"max_bytes": 1})
        self.assertTrue(result.is_error)
        self.assertEqual(tool_payload(result)["error"]["code"], "INVALID_INPUT")

    def test_oversized_meta_is_refused(self) -> None:
        """`_meta` de 100 Ko via un client modifié : refusé, pas propagé."""
        result = call_tool("ping", {"_meta": "x" * 100_000})
        self.assertTrue(result.is_error)
        self.assertEqual(tool_payload(result)["error"]["code"], "INVALID_INPUT")

    def test_small_meta_is_tolerated(self) -> None:
        """Compatibilité protocole : une petite `_meta` passe (ignorée)."""
        result = call_tool("ping", {"_meta": {"progressToken": 1}})
        self.assertFalse(result.is_error)
        self.assertEqual(tool_payload(result), {"pong": True})

    def test_success_is_never_flagged_as_an_error(self) -> None:
        """Exclusivité des deux formes : un succès n'est jamais isError."""
        result = call_tool("ping", {})
        self.assertFalse(result.is_error)

    def test_refusal_message_is_static(self) -> None:
        """Invariant 8 : la valeur reçue n'est jamais reflétée au LLM."""
        marker = "SENTINELLE_ENTREE_NON_FIABLE"
        result = call_tool("ping", {"root": marker, marker: 1})
        self.assertTrue(result.is_error)
        self.assertNotIn(marker, json.dumps(tool_payload(result)))

    def test_unknown_tool_is_refused(self) -> None:
        """Registre fermé : aucun nom hors liste n'est appelable (I8).

        La réponse est notre enveloppe `{"error": …}` (contrat 3.1), pas le
        texte brut « Unknown tool » du SDK — y compris pour un outil du
        contrat pas encore livré (`propose_patch`) : non exposé = refusé.
        """
        for name in ("exec_shell", "propose_patch", "ping2"):
            with self.subTest(tool=name):
                result = call_tool(name, {})
                self.assertTrue(result.is_error)
                payload = tool_payload(result)
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")
                self.assertNotIn("Unknown tool", json.dumps(payload))

    def test_bool_is_not_an_integer(self) -> None:
        """Un booléen ne doit pas passer pour un entier (type exact)."""
        result = call_tool("ping", {"max_bytes": True})
        self.assertTrue(result.is_error)
        self.assertEqual(tool_payload(result)["error"]["code"], "INVALID_INPUT")


class StdoutIsProtocolOnlyTests(unittest.TestCase):
    def test_server_writes_nothing_but_json_rpc_on_stdout(self) -> None:
        """Piège du #73 : un print() sur stdout casserait le protocole.

        On envoie une requête JSON-RPC sur stdin et on exige que chaque
        ligne de stdout soit un message JSON-RPC valide.
        """
        request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [sys.executable, "-m", "heimdall.mcp", "--root", str(REPO_ROOT)],
            input=request + "\n",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, "aucune réponse du serveur")
        for line in lines:
            with self.subTest(line=line[:80]):
                self.assertIn("jsonrpc", json.loads(line))


class LaunchCommandTests(unittest.TestCase):
    def test_python_dash_m_refuses_a_missing_root_statically(self) -> None:
        """Une racine absente est refusée (code 2) sans refléter l'entrée."""
        marker = "SENTINELLE_RACINE_INCONNUE"
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [sys.executable, "-m", "heimdall.mcp", "--root", marker],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 2, msg=completed.stderr[-2000:])
        self.assertNotIn(marker, completed.stdout + completed.stderr)
        self.assertIn("racine", completed.stderr)

    def test_build_server_requires_an_existing_directory(self) -> None:
        for bad in ("", "/definitely/not/here"):
            with self.subTest(root=bad):
                with self.assertRaises(ValueError):
                    mcp_server._resolve_root(bad)

    def test_cli_mcp_command_refuses_a_missing_root(self) -> None:
        """La CLI relaie le refus statique (code 2, message sur stderr)."""
        result = CliRunner().invoke(heimdall.cli.main.app, ["mcp", "--root", "/not/here"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("racine", result.stderr)

    def test_tool_arguments_never_include_the_root(self) -> None:
        """Aucun outil n'expose la racine en paramètre (contrat, invariant 2)."""
        for name, tool in mcp_server._tools(Path("/")).items():
            with self.subTest(tool=name):
                parameters = list(inspect.signature(tool).parameters)
                self.assertNotIn("root", parameters)
                self.assertNotIn("root", parameters)


if __name__ == "__main__":
    unittest.main()
