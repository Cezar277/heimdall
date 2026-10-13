"""Tests du serveur MCP — sous-ticket #73 (SDK, stdio, outil ``ping``).

Ces tests passent par un vrai client MCP (``mcp.client.stdio``) qui
démarre le serveur en sous-processus : c'est la seule façon de prouver le
canal de bout en bout (sérialisation JSON-RPC comprise), et pas seulement
la logique Python.

Le client est un outil de test, jamais une dépendance du produit : le
serveur ne connaît que le SDK officiel (``mcp``, voir ADR-002).
"""

import asyncio
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from heimdall.mcp import server as mcp_server

ROOT = Path(__file__).resolve().parents[1]


def run_async(coro: Any) -> Any:
    """Exécute une coroutine de test (le SDK MCP est asynchrone)."""
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


def tool_payload(result: Any) -> dict[str, Any]:
    """Extrait et décode la charge utile JSON d'un appel d'outil."""
    texts = [block.text for block in result.content if getattr(block, "type", None) == "text"]
    assert len(texts) == 1, f"une seule réponse texte attendue, obtenu {texts!r}"
    return json.loads(texts[0])  # type: ignore[no-any-return]


class ServerProcessTestCase(unittest.TestCase):
    """Lance le serveur réel en sous-processus, comme le fera la CLI."""

    def call_tool(self, name: str, arguments: dict[str, Any], root: Path | None = None) -> Any:
        """Appelle un outil via un client MCP standard sur stdio."""
        server_root = ROOT if root is None else root
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "heimdall.mcp", "--root", str(server_root)],
            cwd=str(server_root),
        )

        async def session_call() -> Any:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(name, arguments)

        return run_async(session_call())


class PingToolTests(ServerProcessTestCase):
    def test_ping_answers_pong(self) -> None:
        """Fait quand (#73) : un client MCP appelle ping et obtient une réponse."""
        result = self.call_tool("ping", {})
        self.assertFalse(result.is_error)
        self.assertEqual(tool_payload(result), {"pong": True})

    def test_ping_is_declared_to_the_client(self) -> None:
        """L'outil doit apparaître dans tools/list, avec sa description."""

        async def session_call() -> Any:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "heimdall.mcp", "--root", str(ROOT)],
                cwd=str(ROOT),
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.list_tools()

        listed = [tool.name for tool in run_async(session_call()).tools]
        # Registre fermé : la liste annoncée est exactement SERVER_TOOLS,
        # dans l'ordre, et rien d'autre n'est appelable (contrat #16, I8).
        self.assertEqual(listed, list(mcp_server.SERVER_TOOLS))
        self.assertEqual(listed, ["ping"])
        described = {tool.name: tool.description for tool in run_async(session_call()).tools}
        self.assertTrue(described["ping"])


class ArgumentGateTests(ServerProcessTestCase):
    def test_unknown_field_is_refused_not_ignored(self) -> None:
        """Invariant 11 (#16) : pas de champ « bonus » accepté en douce.

        Le SDK MCP 2.3.0 écarte silencieusement les clés qu'aucun
        paramètre ne déclare ; sans la garde, ``{"root": "/etc"}`` serait
        ignoré au lieu d'être refusé.
        """
        result = self.call_tool("ping", {"root": "/etc", "path": "../.."})
        self.assertTrue(result.is_error)
        self.assertEqual(tool_payload(result)["error"]["code"], "INVALID_INPUT")

    def test_refusal_message_is_static(self) -> None:
        """Invariant 8 : la valeur reçue n'est jamais reflétée au LLM."""
        marker = "SENTINELLE_ENTREE_NON_FIABLE"
        result = self.call_tool("ping", {"root": marker, marker: 1})
        self.assertTrue(result.is_error)
        self.assertNotIn(marker, json.dumps(tool_payload(result)))

    def test_unknown_tool_is_refused(self) -> None:
        """Registre fermé : aucun nom hors liste n'est appelable (I8)."""
        result = self.call_tool("exec_shell", {})
        self.assertTrue(result.is_error)
        self.assertIn("Unknown tool", [block.text for block in result.content][0])

    def test_bool_is_not_an_integer(self) -> None:
        """Un booléen ne doit pas passer pour un entier (type exact)."""
        result = self.call_tool("ping", {"max_bytes": True})
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
            [sys.executable, "-m", "heimdall.mcp", "--root", str(ROOT)],
            input=request + "\n",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=str(ROOT),
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, "aucune réponse du serveur")
        for line in lines:
            with self.subTest(line=line[:80]):
                self.assertIn("jsonrpc", json.loads(line))


class LaunchCommandTests(ServerProcessTestCase):
    def test_python_dash_m_refuses_a_missing_root_statically(self) -> None:
        """Une racine absente est refusée (code 2) sans refléter l'entrée."""
        marker = "SENTINELLE_RACINE_INCONNUE"
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [sys.executable, "-m", "heimdall.mcp", "--root", marker],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=str(ROOT),
        )
        self.assertEqual(completed.returncode, 2, msg=completed.stderr[-2000:])
        self.assertNotIn(marker, completed.stdout + completed.stderr)
        self.assertIn("racine", completed.stderr)

    def test_build_server_requires_an_existing_directory(self) -> None:
        for bad in ("", "/definitely/not/here"):
            with self.subTest(root=bad):
                with self.assertRaises(ValueError):
                    mcp_server._resolve_root(bad)

    def test_ping_needs_neither_git_nor_repository(self) -> None:
        """La sonde de vie marche hors dépôt : aucun appel à git pour ping."""
        with tempfile.TemporaryDirectory(prefix="heimdall-mcp-") as tmp:
            result = self.call_tool("ping", {}, root=Path(tmp))
            self.assertEqual(tool_payload(result), {"pong": True})


if __name__ == "__main__":
    unittest.main()
