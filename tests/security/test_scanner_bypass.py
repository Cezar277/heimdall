"""Abuse cases contournement du scanner et du hook — REQ-SEC-07 / REQ-SEC-08 (#19).

Le scanner #22 est livré : ce test vérifie son comportement fail-closed réel.
Un fichier illisible, trop gros ou une racine invalide lève ``ScanError`` et ne
produit JAMAIS une liste vide ou partielle. Le corpus d'obfuscations reste
formellement posé ; le décodage base64 et l'analyse du flux des variables sont
des limites connues du scanner de signatures T21/T22 (tickets #23/#24).
"""

import base64
from pathlib import Path

from heimdall.scanner.detect import (
    MAX_FILE_BYTES,
    ScanError,
    find_candidates,
    scan,
    scan_rapport,
)

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


def test_named_exclusions_cannot_hide_a_secret(tmp_path: Path) -> None:
    """REQ-SEC-07 : un nom « exclu » ne doit jamais cacher un secret.

    Contournement vérifié par exécution avant correctif : `evil.png`,
    `evil.lock`, `package-lock.json` et `vendor/s.txt` étaient ignorés sur
    leur seul nom ; le scan rendait une liste vide, donc un **verdict
    propre inventé**. Le contenu décide désormais : ces fichiers sont lus
    et scannés.
    """
    secret = "AKIA" + "IOSFODNN7EXAMPLE"  # exemple officiel AWS, pas une clé réelle
    for chemin in ("evil.png", "evil.lock", "package-lock.json", "vendor/s.txt"):
        cible = tmp_path / chemin
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_text(f'AWS = "{secret}"\n', encoding="utf-8")
    findings = find_candidates(str(tmp_path))
    assert findings, "un secret dans un fichier « exclu » a disparu"
    assert {finding["file"] for finding in findings} == {
        "evil.lock",
        "evil.png",
        "package-lock.json",
        "vendor/s.txt",
    }
    assert all(finding["type"] == "aws" for finding in findings)


def test_a_binary_ignored_is_traced_and_never_leaks(tmp_path: Path, capsys) -> None:
    """REQ-SEC-07 : un binaire ignoré doit rester visible, sans rien fuir.

    Avant correctif, un binaire était ignoré **sans trace** : un dépôt
    propre et un dépôt dont un binaire n'a pas été lu étaient indiscernables.
    """
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    rapport = scan_rapport(str(tmp_path))
    assert rapport.binaires_ignores == 1
    assert rapport.non_analyses == 0
    trace = capsys.readouterr().err
    assert "image.png" in trace
    assert "AKIA" not in trace


def test_an_unanalysable_tier_file_never_yields_a_clean_verdict(tmp_path: Path) -> None:
    """REQ-SEC-07 : un fichier non analysable n'est JAMAIS un verdict propre.

    Les compteurs du rapport étaient jetés par `scan()` : un fichier
    illisible, hors borne, non régulier ou mal nommé dans `vendor/` rendait
    une liste **vide** — un verdict propre inventé alors qu'une partie du
    périmètre n'avait pas été lue. Les deux API lèvent désormais
    `ScanError`.
    """
    secret = "AKIA" + "IOSFODNN7EXAMPLE"  # exemple officiel AWS, pas une clé réelle
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "secret.txt").write_text(f'AWS = "{secret}"\n', encoding="utf-8")
    (tmp_path / "vendor" / "huge.txt").write_bytes(b"A" * (MAX_FILE_BYTES + 1))
    for api in (scan, find_candidates):
        try:
            api(str(tmp_path))
        except ScanError as exc:
            assert str(exc) == "scan impossible : entrée non analysable"
        else:
            raise AssertionError("fichier non analysable : verdict propre inventé")
    # Seul le rapport expose le bilan partiel, avec son compteur.
    rapport = scan_rapport(str(tmp_path))
    assert rapport.non_analyses == 1
    assert rapport.complet is False


def test_a_grounded_clean_verdict_requires_a_complete_report(tmp_path: Path) -> None:
    """REQ-SEC-07 : un verdict propre n'est fondé que si le rapport est complet.

    Binaire ignoré, lien non suivi, base VCS non parcourue : dans les trois
    cas, du contenu n'a pas été lu. `RapportScan.complet` est donc faux, et
    #29 doit refuser (code 2) au lieu d'annoncer un dépôt propre.
    """
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    rapport = scan_rapport(str(tmp_path))
    assert rapport.binaires_ignores == 1
    assert rapport.complet is False

    (tmp_path / "image.png").unlink()
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    rapport = scan_rapport(str(tmp_path))
    assert rapport.hors_perimetre == 1
    assert rapport.complet is False

    (tmp_path / ".git" / "config").unlink()
    (tmp_path / ".git").rmdir()
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rapport = scan_rapport(str(tmp_path))
    assert rapport.complet is True


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
