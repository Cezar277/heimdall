"""Scanner déterministe (regex + entropie de Shannon).

Implémentation : ticket #22. Contrat des résultats : #14
(``schemas/finding.schema.json``, états ``detecte → confirme → vaulte/rote``).

Règle d'architecture : ce module ne fait AUCUN appel réseau et n'importe
AUCUNE dépendance LLM ou crypto. Le LLM (via MCP) ne fait que trier les
candidats ; en CI il n'a aucun pouvoir et un secret en clair bloque.
"""

from heimdall.scanner.detect import FindingStatus, find_candidates

__all__ = ["FindingStatus", "find_candidates"]
