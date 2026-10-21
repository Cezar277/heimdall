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
from heimdall.scanner.errors import InvalidFinding, InvalidTarget, ScanError
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
from heimdall.scanner.signature_engine import MoteurSignatures, SignatureEngine
from heimdall.scanner.signatures import (
    SIGNATURES,
    Rule,
    Signature,
    SignatureMatch,
    find_signature_matches,
)

__all__ = [
    "FINDING_FIELDS",
    "SIGNATURES",
    "DiffTarget",
    "FileTarget",
    "Finding",
    "FindingSource",
    "FindingStatus",
    "InvalidFinding",
    "InvalidTarget",
    "Moteur",
    "MoteurSignatures",
    "Rule",
    "ScanError",
    "ScanTarget",
    "Scanner",
    "Signature",
    "SignatureEngine",
    "SignatureMatch",
    "find_candidates",
    "find_signature_matches",
]
