"""Scanner déterministe (regex de signatures + exclusions).

Implémentation : ticket #22. Contrat des résultats : #14
(``schemas/finding.schema.json``, états ``detecte → confirme → vaulte/rote``).

Règle d'architecture : ce module ne fait AUCUN appel réseau et n'importe
AUCUNE dépendance LLM ou crypto. Le LLM (via MCP) ne fait que trier les
candidats ; en CI il n'a aucun pouvoir et un secret en clair bloque.

L'entropie de Shannon est exposée comme métadonnée du Finding ; la détection
par seuil d'entropie appartient au ticket #23.
"""

from heimdall.scanner.detect import (
    Finding,
    FindingSource,
    FindingStatus,
    Scanner,
    find_candidates,
    scan,
)
from heimdall.scanner.errors import ScanError
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signatures import SIGNATURES, Signature, SignatureMatch

__all__ = [
    "SIGNATURES",
    "Finding",
    "FindingSource",
    "FindingStatus",
    "ScanError",
    "Scanner",
    "Signature",
    "SignatureMatch",
    "SnippetHasher",
    "find_candidates",
    "scan",
]
