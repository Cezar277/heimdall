"""Scanner déterministe (regex + entropie de Shannon).

Implémentation : ticket #22. Interface et sortie : #53
(``heimdall.scanner.interface`` et ``heimdall.scanner.finding``), contrat des
résultats : #14 (``schemas/finding.schema.json``, états
``detecte → confirme → vaulte/rote``).

Règle d'architecture : ce module ne fait AUCUN appel réseau et n'importe
AUCUNE dépendance LLM ou crypto. Le LLM (via MCP) ne fait que trier les
candidats ; en CI il n'a aucun pouvoir et un secret en clair bloque.
"""

from heimdall.scanner.detect import find_candidates
from heimdall.scanner.errors import (
    InvalidFinding,
    InvalidTarget,
    ScanError,
    ScannerNotImplemented,
)
from heimdall.scanner.finding import (
    FINDING_FIELDS,
    Finding,
    FindingSource,
    FindingStatus,
)
from heimdall.scanner.interface import (
    DiffTarget,
    FileTarget,
    Moteur,
    Scanner,
    ScanTarget,
)

__all__ = [
    "FINDING_FIELDS",
    "DiffTarget",
    "FileTarget",
    "Finding",
    "FindingSource",
    "FindingStatus",
    "InvalidFinding",
    "InvalidTarget",
    "Moteur",
    "ScanError",
    "ScanTarget",
    "Scanner",
    "ScannerNotImplemented",
    "find_candidates",
]
