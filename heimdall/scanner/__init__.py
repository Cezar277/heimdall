"""Scanner déterministe (regex + entropie de Shannon).

Implémentation : ticket #22. Interface et sortie : #53
(``heimdall.scanner.interface`` et ``heimdall.scanner.finding``), contrat des
résultats : #14 (``schemas/finding.schema.json``, états
``detecte → confirme → vaulte/rote``).

Règle d'architecture : ce module ne fait AUCUN appel réseau et n'importe
AUCUNE dépendance LLM ou crypto. Le LLM (via MCP) ne fait que trier les
candidats ; en CI il n'a aucun pouvoir et un secret en clair bloque.
"""

from heimdall.scanner.detect import (
    RapportScan,
    ScannerRacine,
    exiger_complet,
    find_candidates,
    scan,
    scan_complet,
    scan_rapport,
)
from heimdall.scanner.errors import InvalidFinding, InvalidTarget, ScanError, ScanIncomplet
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
)

# ``find_signature_matches`` n'est **pas** réexportée ici : son retour porte
# la **valeur brute** des candidats (surface sensible). Elle reste importable
# explicitement depuis ``heimdall.scanner.signatures``, et la seule surface
# publique du paquet est celle de ``__all__`` ci-dessous.

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
    "RapportScan",
    "Rule",
    "ScanError",
    "ScanIncomplet",
    "ScanTarget",
    "Scanner",
    "ScannerRacine",
    "Signature",
    "SignatureEngine",
    "SignatureMatch",
    "exiger_complet",
    "find_candidates",
    "scan",
    "scan_complet",
    "scan_rapport",
]
