"""Tracabilite T19 : chaque exigence a un test ; bugs revue T18 corriges.

Couvre REQ-SEC-09 (engagement H1/H4, bug LOW F09/F14 vs invariant 12) et
REQ-SEC-10 (preuve visuelle DFD, bug LOW PNG en-tete seul), plus les gardes
meta : pas d'exigence vague, pas de vrai secret dans les fixtures.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REQUIREMENTS = REPO / "docs" / "security" / "requirements.md"
SECURITY_DIR = REPO / "docs" / "security"
CHECKER = SECURITY_DIR / "check_model.py"
REVIEW = SECURITY_DIR / "review-and-evidence.md"

# Table de correspondance exigence -> (fichier de test, fonction de test).
TRACEABILITY = {
    "REQ-SEC-01": ("test_prompt_injection.py", "test_llm_rejection_never_silent"),
    "REQ-SEC-02": ("test_prompt_injection.py", "test_no_llm_in_ci"),
    "REQ-SEC-03": ("test_path_traversal.py", "test_write_stays_inside_root"),
    "REQ-SEC-04": ("test_path_traversal.py", "test_mcp_read_only_surface"),
    "REQ-SEC-05": ("test_vault_replay_bruteforce.py", "test_replay_without_overwrite"),
    "REQ-SEC-06": (
        "test_vault_replay_bruteforce.py",
        "test_bruteforce_rate_limit_and_constant_errors",
    ),
    "REQ-SEC-07": ("test_scanner_bypass.py", "test_incomplete_scan_never_clean"),
    "REQ-SEC-08": ("test_scanner_bypass.py", "test_hook_bypass_requires_trusted_ci"),
    "REQ-SEC-09": ("test_requirements_traceability.py", "test_h1_h4_loopback_engagement"),
    "REQ-SEC-10": (
        "test_requirements_traceability.py",
        "test_visual_proof_required_not_script_green",
    ),
}

VAGUE_PATTERNS = [
    "le système est sécurisé",
    "système sécurisé",
    "sécurité maximale",
    "protection totale",
]


def test_all_requirements_have_tests() -> None:
    """Chaque REQ-SEC du document renvoie a un test qui existe vraiment."""
    req = REQUIREMENTS.read_text(encoding="utf-8")
    found = re.findall(r"REQ-SEC-(\d{2})", req)
    assert sorted(set(found)) == [f"{n:02}" for n in range(1, 11)], sorted(set(found))
    for req_id, (filename, func) in TRACEABILITY.items():
        # L'exigence est detaillee dans sa propre section.
        assert f"### {req_id}" in req, req_id
        # Le document cite le test associe au format impose par le ticket.
        ref = f"tests/security/{filename}::{func}"
        assert ref in req, ref
        # Le test existe dans le fichier indique.
        test_src = (REPO / "tests" / "security" / filename).read_text(encoding="utf-8")
        assert f"def {func}(" in test_src, ref
        # Chaque section contient un risque Rn et un renvoi STRIDE.
        section = req.split(f"### {req_id}", 1)[1].split("### REQ-SEC-", 1)[0]
        assert re.search(r"\bR\d{1,2}\b", section), req_id
        assert "stride.md#" in section, req_id


def test_no_vague_requirements() -> None:
    """Piege du ticket : aucune exigence vague sans test qui tranche."""
    req = REQUIREMENTS.read_text(encoding="utf-8")
    # Les contre-exemples cites entre guillemets (« ... ») sont la definition
    # du piege, pas des exigences : on les exclut avant le controle.
    unquoted = re.sub(r"«[^»]*»", "", req)
    lowered = unquoted.lower()
    for pattern in VAGUE_PATTERNS:
        assert pattern not in lowered, pattern
    for req_id in TRACEABILITY:
        section = req.split(f"### {req_id}", 1)[1].split("### REQ-SEC-", 1)[0]
        assert "DOIT" in section or "JAMAIS" in section, req_id
        assert "Échec" in section, req_id


def test_h1_h4_loopback_engagement() -> None:
    """REQ-SEC-09 : engagement ecrit loopback + TLS verifie (bug LOW #1)."""
    req = REQUIREMENTS.read_text(encoding="utf-8")
    for token in ("127.0.0.1", "::1", "localhost", "TLS vérifié", "PR dédiée", "H1", "H4"):
        assert token in req, token
    assert "verify=False" in req
    assert "F09" in req and "F14" in req
    # Le client applique deja l'allowlist : preuve executable de l'engagement.
    from heimdall.vault.client import VaultClient

    VaultClient("https://localhost:8443", "SYNTHETIC_API_KEY_09")
    VaultClient("https://[::1]:8443", "SYNTHETIC_API_KEY_09")
    for bad in (
        "https://10.0.0.8:8443",
        "http://localhost:8443",
        "https://localhost:8443/?next=SYNTHETIC",
    ):
        try:
            VaultClient(bad, "SYNTHETIC_API_KEY_09")
        except ValueError:
            continue
        raise AssertionError(f"distant/non-TLS accepte : {bad}")
    # Non-heritable, non serialisable, cle jamais journalisee.
    try:
        VaultClient("https://127.0.0.1:8443", "SYNTHETIC_API_KEY_09").__reduce__()
    except TypeError:
        pass
    else:
        raise AssertionError("client serialisable")
    assert "REDACTED" in repr(VaultClient("https://127.0.0.1:8443", "SYNTHETIC_API_KEY_09"))


def test_visual_proof_required_not_script_green() -> None:
    """REQ-SEC-10 : vert script != preuve visuelle (bug LOW #2)."""
    req = REQUIREMENTS.read_text(encoding="utf-8")
    checker_src = CHECKER.read_text(encoding="utf-8")
    review_src = REVIEW.read_text(encoding="utf-8")
    # Le verificateur dit honnetement sa limite (en-tete seul).
    assert "Header sanity only" in checker_src
    assert "ne prouve pas" in checker_src or "no claim" in checker_src
    # La procedure exige la comparaison manuelle du relecteur C.
    for token in ("relecteur C", "capture datée", "sha256sum", "git rev-parse HEAD"):
        assert token in review_src, token
        assert token in req, token
    # REQ-SEC-10 interdit de scorer SAMM sur le seul vert script.
    section = req.split("### REQ-SEC-10", 1)[1]
    assert "SAMM" in section
    assert "ne prouve" in section
    # L'en-tete PNG actuel reste valide (signature + plage lisible), sans
    # que cela constitue une preuve de contenu.
    png = (SECURITY_DIR / "dfd.png").read_bytes()[:33]
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert png[8:16] == b"\x00\x00\x00\rIHDR"


def test_no_real_secrets_in_fixtures() -> None:
    """Garde DoD : aucun vrai secret dans les fichiers livres par CETTE PR.

    Perimetre exact (`git diff main...HEAD --name-only`) : balayer tout
    l'arbre echouerait sur les faux realistes volontaires et documentes des
    tickets geles #14/#16 (ADR-002 : le faux `sk_live_*` et le marqueur
    `AKIA...EXAMPLE` de la fixture de masquage), qui appartiennent a leurs
    tickets. Chaque PR etend sa propre garde ; celle-ci couvre les 7
    fichiers T19, ni plus ni moins.
    """
    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"sk_live_[0-9A-Za-z]+",
        r"ghp_[0-9A-Za-z]{20,}",
        r"xox[bap]-[0-9A-Za-z-]+",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"AIza[0-9A-Za-z_-]{20,}",
    ]
    pr_files = [
        REPO / "docs/security/requirements.md",
        REPO / "tests/security/test_prompt_injection.py",
        REPO / "tests/security/test_path_traversal.py",
        REPO / "tests/security/test_vault_replay_bruteforce.py",
        REPO / "tests/security/test_scanner_bypass.py",
        REPO / "tests/security/test_requirements_traceability.py",
        REPO / ".github/workflows/security-model.yml",
    ]
    assert len(pr_files) == 7
    for path in pr_files:
        assert path.is_file(), path  # perimetre non vide et non reductible
        text = path.read_text(encoding="utf-8")
        for pattern in secret_patterns:
            assert re.search(pattern, text) is None, f"{path.relative_to(REPO)}: {pattern}"
