"""Abuse cases contournement du scanner et du hook — REQ-SEC-07 / REQ-SEC-08 (#19).

Le scanner #22 est livré : ce test vérifie son comportement fail-closed réel.
Un fichier illisible, trop gros ou une racine invalide lève ``ScanError`` et ne
produit JAMAIS une liste vide ou partielle. Le corpus d'obfuscations reste
formellement posé ; le décodage base64 et l'analyse du flux des variables sont
des limites connues du scanner de signatures T21/T22 (tickets #23/#24).
"""

import base64
from pathlib import Path

from heimdall.scanner.detect import MAX_FILE_BYTES, ScanError, find_candidates

REPO = Path(__file__).resolve().parents[2]
CLI_MAIN = REPO / "heimdall" / "cli" / "main.py"
SCANNER_SRC = REPO / "heimdall" / "scanner" / "detect.py"
REQUIREMENTS = REPO / "docs" / "security" / "requirements.md"
RISKS = REPO / "docs" / "security" / "risks.md"

# Marqueur synthetique unique du corpus (aucune valeur reelle).
CANARY = "SYNTHETIC_CANARY_7f3a"
CANARY_B64 = base64.b64encode(CANARY.encode()).decode()  # U1lOVEhFVElDX0NBTkFSWV83ZjNh
OBFUSCATED_CORPUS = [
    CANARY_B64,  # base64
    '"SYNTHETIC_" + "CANARY_7f3a"',  # concatenation
    'f"SYNTHETIC_{SYNTHETIC_MIDDLE}7f3a"',  # f-string / interpolation
    '"SYNTHETIC_" "CANARY_7f3a"',  # juxtaposition implicite
]


def test_incomplete_scan_never_clean(tmp_path: Path) -> None:
    """REQ-SEC-07 : incomplet/erreur/tronque => jamais 0 ; ``ScanError``."""
    # 1. Un dépôt vide est réellement propre : liste vide, pas d'exception.
    assert find_candidates(str(tmp_path)) == []

    # 2. Fichier au-delà de la borne de lecture : erreur, jamais un scan
    #    partiel silencieux.
    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"A" * (MAX_FILE_BYTES + 1))
    try:
        find_candidates(str(tmp_path))
    except ScanError as exc:
        assert str(exc) == "scan impossible : entrée non analysable"
    else:
        raise AssertionError("scan tronqué : verdict propre inventé")

    # 3. Racine inexistante : erreur statique, aucune entrée reflétée.
    marker = "SENTINELLE_RACINE_NON_FIABLE"
    try:
        find_candidates(str(tmp_path / marker))
    except ScanError as exc:
        assert marker not in str(exc)
        assert str(exc) == "scan impossible : entrée non analysable"
    else:
        raise AssertionError("racine absente : verdict propre inventé")

    # 4. Le scanner ne reflète jamais une entrée dans son message (invariant 8).
    src = SCANNER_SRC.read_text(encoding="utf-8")
    assert "ScanError" in src
    assert "fail-closed" in src
    assert "NotImplementedError" not in src

    # 5. CLI : codes 0 propre / 1 secret / 2 erreur ; non branché (#29) => 2.
    cli_src = CLI_MAIN.read_text(encoding="utf-8")
    assert "0 propre, 1 secrets détectés, 2 erreur" in cli_src
    assert "raise typer.Exit(code=2)" in cli_src
    assert "jamais 1, réservé aux secrets avérés" in cli_src

    # 6. Le corpus d'obfuscations reste exigé dans requirements.md.
    req = REQUIREMENTS.read_text(encoding="utf-8")
    assert CANARY_B64 in req
    assert "concaténation" in req
    assert "JAMAIS 0" in req


def test_obfuscation_corpus_is_mandatory() -> None:
    """REQ-SEC-07 (complement) : risques T18 et contrats imposent le corpus."""
    risks = RISKS.read_text(encoding="utf-8")
    assert "obfusqué" in risks or "obfuscation" in risks
    assert "ne DOIT jamais produire un verdict propre" in risks
    finding_doc = (REPO / "docs" / "contracts" / "finding.md").read_text(encoding="utf-8")
    assert "En CI" in finding_doc and "bloque" in finding_doc
    mcp_doc = (REPO / "docs" / "contracts" / "mcp-tools.md").read_text(encoding="utf-8")
    assert "truncated: true" in mcp_doc
    assert "jamais « diff vide »" in mcp_doc or "jamais comme un diff vide" in mcp_doc
    # Les obfuscations restent synthetiques et ne contiennent aucun secret reel.
    for sample in OBFUSCATED_CORPUS:
        assert "AKIA" not in sample and "BEGIN" not in sample


def test_hook_bypass_requires_trusted_ci() -> None:
    """REQ-SEC-08 : hook contournable => scan CI de confiance du SHA requis."""
    risks = RISKS.read_text(encoding="utf-8")
    stride = (REPO / "docs" / "security" / "stride.md").read_text(encoding="utf-8")
    assert "--no-verify" in risks
    assert "job requis refuse" in risks
    assert "hook seulement aide locale" in stride
    req = REQUIREMENTS.read_text(encoding="utf-8")
    assert "REQ-SEC-08" in req
    assert "--no-verify" in req
    # La CLI expose --ci et refuse par defaut au lieu de se fier au hook.
    cli_src = CLI_MAIN.read_text(encoding="utf-8")
    assert '"--ci"' in cli_src
    assert "code=2" in cli_src
    # Le DFD distingue le hook local (P1) du runner CI (E3) et de son scan.
    dfd = (REPO / "docs" / "security" / "dfd.md").read_text(encoding="utf-8")
    assert "F15" in dfd and "scan --ci" in dfd
    assert "sans LLM" in dfd
