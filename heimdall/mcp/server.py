"""Serveur MCP minimal — squelette du ticket #27.

Exposera exactement les 4 outils du contrat #16 (``read_diff``,
``sanitize_file``, ``list_candidates``, ``propose_patch``), en stdio,
sans outil d'écriture, d'exécution ou réseau.
"""

from typing import Final

MCP_TOOLS: Final[tuple[str, ...]] = (
    "read_diff",
    "sanitize_file",
    "list_candidates",
    "propose_patch",
)


def run_stdio(root: str) -> None:
    """Démarre le serveur MCP sur stdio, confiné à ``root``.

    Lève ``NotImplementedError`` tant que #27 n'est pas livré. Message
    statique : aucune entrée n'est reflétée (invariant 8).
    """
    del root  # #27 utilisera ce paramètre ; en attendant, rien n'est reflété.
    raise NotImplementedError("serveur MCP non implémenté (voir #27)")
