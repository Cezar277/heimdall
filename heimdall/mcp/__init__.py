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

import importlib
from typing import Any, Final

from heimdall.mcp.errors import ERROR_MESSAGES, ErrorCode, ToolFailure, dumps, failure

#: Exports du serveur MCP, chargés à la demande. Le SDK ``mcp`` n'est requis
#: que pour ces symboles : importer ``heimdall.mcp.gitdiff`` (client Vault,
#: scanner, hook) ne doit pas tirer le serveur ni sa dépendance lourde.
_SERVER_EXPORTS: Final[frozenset[str]] = frozenset(
    {"MCP_TOOLS", "SERVER_TOOLS", "build_server", "run_stdio"}
)


def __getattr__(name: str) -> Any:
    """Import paresseux des exports serveur (PEP 562), sans dépendance ``mcp``."""
    if name in _SERVER_EXPORTS:
        server = importlib.import_module("heimdall.mcp.server")
        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _SERVER_EXPORTS)


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
