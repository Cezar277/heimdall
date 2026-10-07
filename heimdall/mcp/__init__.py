"""Serveur MCP stdio — 4 outils en lecture seule.

Implémentation : ticket #27. Contrat : #16
(``schemas/mcp-tools.schema.json``, ``docs/contracts/mcp-tools.md``).

Invariants rappelés ici car structurants :
transport stdio uniquement (sous-processus de la CLI, aucun port),
racine du dépôt fixée au démarrage, garde de chemin unique
(``resolve()`` + ``is_relative_to`` + refus des liens sortants),
aucun secret en clair (masquage ``<REDACTED:…>`` avant sérialisation).
"""

from heimdall.mcp.server import MCP_TOOLS, run_stdio

__all__ = ["MCP_TOOLS", "run_stdio"]
