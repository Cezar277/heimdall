"""Serveur MCP stdio — outils en lecture seule exposés au LLM.

Implémentation : ticket #27 (sous-tickets #73, #74, #75, #78).
Contrat : #16 (``schemas/mcp-tools.schema.json``,
``docs/contracts/mcp-tools.md``). Lancement : ``docs/mcp-server.md``.

Invariants rappelés ici car structurants :
transport stdio uniquement (sous-processus de la CLI, aucun port),
racine du dépôt fixée au démarrage et absente de toutes les entrées,
garde de chemin unique (``resolve()`` + ``is_relative_to`` + refus des
chemins absolus et des liens sortants),
aucun secret en clair (masquage ``<REDACTED:type:len=N>`` avant
sérialisation),
tout échec renvoyé sous forme d'enveloppe ``{"error": {…}}``.
"""

from heimdall.mcp.errors import ERROR_MESSAGES, ErrorCode, ToolFailure, dumps, failure
from heimdall.mcp.server import MCP_TOOLS, SERVER_TOOLS, build_server, run_stdio

__all__ = [
    "ERROR_MESSAGES",
    "MCP_TOOLS",
    "SERVER_TOOLS",
    "ErrorCode",
    "ToolFailure",
    "build_server",
    "dumps",
    "failure",
    "run_stdio",
]
