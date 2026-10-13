"""Client MCP de test : vrai serveur, vrai protocole, aucun mock.

Les tests du serveur MCP passent tous par ici : le serveur est démarré en
sous-processus (``python -m heimdall.mcp --root <dépôt>``), comme le fera la
CLI, et les appels utilisent le client officiel du SDK. C'est la seule façon
de prouver le canal de bout en bout — sérialisation JSON-RPC, garde d'entrée
 et marquage ``isError`` compris.

Ce module est un outil de test : il n'est pas importé par le produit.
"""

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]

# Délai généreux : un sous-processus Python + une poignée de commandes git.
TIMEOUT_SECONDS = 60.0


def server_parameters(root: Path) -> StdioServerParameters:
    """Paramètres de lancement du serveur, identiques à ceux de la CLI."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "heimdall.mcp", "--root", str(root)],
        cwd=str(root),
    )


async def with_session(root: Path, body: Callable[[ClientSession], Awaitable[Any]]) -> Any:
    """Ouvre une session MCP sur un serveur fraîchement démarré."""
    async with stdio_client(server_parameters(root)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await body(session)


def call_tool(name: str, arguments: dict[str, Any], root: Path = REPO_ROOT) -> Any:
    """Appelle un outil et renvoie le résultat brut du client."""

    async def body(session: ClientSession) -> Any:
        return await session.call_tool(name, arguments)

    return asyncio.run(asyncio.wait_for(with_session(root, body), timeout=TIMEOUT_SECONDS))


def list_tools(root: Path = REPO_ROOT) -> list[str]:
    """Noms des outils annoncés par le serveur (tools/list)."""

    async def body(session: ClientSession) -> Any:
        return [tool.name for tool in (await session.list_tools()).tools]

    return asyncio.run(asyncio.wait_for(with_session(root, body), timeout=TIMEOUT_SECONDS))  # type: ignore[no-any-return]


def tool_payload(result: Any) -> dict[str, Any]:
    """Extrait et décode la charge utile JSON d'un appel d'outil."""
    texts = [block.text for block in result.content if getattr(block, "type", None) == "text"]
    assert len(texts) == 1, f"une seule réponse texte attendue, obtenu {texts!r}"
    return json.loads(texts[0])  # type: ignore[no-any-return]
