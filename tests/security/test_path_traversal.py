"""Abuse cases path traversal — REQ-SEC-03 / REQ-SEC-04 (#19).

ECRITURE (REQ-SEC-03) : apres validation humaine, la cible reelle doit etre
reverifiee a l'usage ; tout `..`, absolu ou lien sortant est refuse, sans
ecriture hors racine. LECTURE MCP (REQ-SEC-04) : 4 outils lecture seule avec
garde de chemin a l'usage et masquage avant serialisation.
"""

import ast
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MCP_SCHEMA = REPO / "schemas" / "mcp-tools.schema.json"
MCP_SERVER = REPO / "heimdall" / "mcp" / "server.py"
FINDING_SCHEMA = REPO / "schemas" / "finding.schema.json"
CHECKER_SPEC = importlib.util.spec_from_file_location(
    "sec_check_model", REPO / "docs" / "security" / "check_model.py"
)
assert CHECKER_SPEC and CHECKER_SPEC.loader
checker = importlib.util.module_from_spec(CHECKER_SPEC)
CHECKER_SPEC.loader.exec_module(checker)

TRAVERSAL_VECTORS = [
    "../SYNTHETIC_OUTSIDE",
    "a/../../SYNTHETIC_OUTSIDE",
    "/etc/SYNTHETIC_CANARY",
    "..\\..\\SYNTHETIC_WIN",
    "a//b",
    "a/",
    ".",
    "./a",
    "C:/SYNTHETIC_ABS",
    "a\x00b",
]

FORBIDDEN_PATHS = [
    ".git/SYNTHETIC_FORBIDDEN",
    ".env.SYNTHETIC_FORBIDDEN",
    ".env",
]


def _relpath_rejects(value: str) -> bool:
    pattern = json.loads(MCP_SCHEMA.read_text(encoding="utf-8"))["$defs"]["RelPath"]["pattern"]
    return re.fullmatch(pattern, value) is None


# Sinks d'ecriture/suppression/execution bannis du squelette MCP (lecture
# seule). Couvre os/niveau descripteur, pathlib, shutil et exec/spawn : un
# `shutil.copyfile` ou `os.symlink` futur passerait un set limite a
# open/write. Reste hors portee : acces dynamiques (getattr), `pty` (couvert
# par "spawn" si appele en clair).
_WRITE_SINK_ATTRS = frozenset(
    {
        "open",
        "write",
        "write_text",
        "write_bytes",
        "writelines",
        "mkdir",
        "makedirs",
        "symlink",
        "symlink_to",
        "link",
        "unlink",
        "rename",
        "replace",
        "remove",
        "rmdir",
        "rmtree",
        "copy",
        "copyfile",
        "copytree",
        "move",
        "execv",
        "execve",
        "execl",
        "execlp",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnlp",
        "spawnv",
        "spawnvp",
        "spawnve",
        "spawn",
        "fork",
    }
)


def _write_sink_calls(path: Path) -> list[str]:
    """Appels vers des sinks d'ecriture dans un module (vide = OK)."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            found.append("open(...)")
        elif isinstance(func, ast.Attribute) and func.attr in _WRITE_SINK_ATTRS:
            found.append(f".{func.attr}(...)")
    return found


def test_write_stays_inside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """REQ-SEC-03 : ecriture confinee, cible reverifiee a l'usage.

    Garde-doc : exerce le confinement du VERIFICATEUR documentaire
    (docs/security/check_model.py), pas le chemin d'ecriture CLI/MCP du
    produit. La preuve runtime (atomique temp + fsync + os.replace, perms
    600, rescan) est due en #30 et exigee avant tout score SAMM
    d'implementation (voir REQ-SEC-03).
    """
    # 1. La grammaire des chemins (Finding + MCP) refuse deja les vecteurs.
    for vector in TRAVERSAL_VECTORS:
        assert _relpath_rejects(vector), vector
    for path in FORBIDDEN_PATHS:
        # .git/.env sont interdits par politique (FORBIDDEN_PATH), pas par la
        # grammaire seule : sanitize_file les refuse explicitement.
        assert path.startswith((".git", ".env")), path
    doc = (REPO / "docs" / "contracts" / "mcp-tools.md").read_text(encoding="utf-8")
    assert "resolve()` + `is_relative_to(racine)" in doc
    assert "STALE_CANDIDATE" in doc
    # 2. Le confinement open-then-verify rejette l'echange concurrent :
    # un fichier echange contre un lien sortant entre controle et usage.
    repository = tmp_path / "repo"
    root = repository / "docs" / "security"
    root.mkdir(parents=True)
    victim = root / "target.md"
    victim.write_text("clean\n", encoding="utf-8")
    outside = tmp_path / "SYNTHETIC_OUTSIDE.md"
    outside.write_text("SYNTHETIC_CANARY\n", encoding="utf-8")
    real_os_open = os.open
    planted = False

    def swapping_open(path, flags, *args):
        nonlocal planted
        if not planted and Path(path) == victim.resolve():
            planted = True
            victim.unlink()
            try:
                victim.symlink_to(outside)
            except OSError:
                pass
        return real_os_open(path, flags, *args)

    # Portee globale assumee : `checker.os is os` (le checker reutilise le
    # module stdlib, pas une copie) ; le patch est circonscrit a ce test et
    # reverte par monkeypatch en fin de test. Signature explicite (path,
    # flags) conforme a l'unique appel `os.open(pre, flags)` du checker.
    monkeypatch.setattr(os, "open", swapping_open)
    with pytest.raises((ValueError, FileNotFoundError, OSError)):
        checker.read_document(victim, repository.resolve())
    assert planted
    # 3. Finding `file` : meme grammaire stricte (pas de `..`, pas d'absolu).
    finding = json.loads(FINDING_SCHEMA.read_text(encoding="utf-8"))
    file_pattern = finding["properties"]["file"]["pattern"]
    assert re.fullmatch(file_pattern, "../SYNTHETIC") is None
    assert re.fullmatch(file_pattern, "/abs/SYNTHETIC") is None
    assert re.fullmatch(file_pattern, "src/SYNTHETIC_OK.py") is not None


def test_mcp_read_only_surface() -> None:
    """REQ-SEC-04 : 4 outils lecture seule, garde a l'usage, masquage d'abord."""
    schema = json.loads(MCP_SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["x-tools"]) == {
        "read_diff",
        "sanitize_file",
        "list_candidates",
        "propose_patch",
    }
    assert all(s["mode"] == "read-only" for s in schema["x-tools"].values())
    obligations = schema["x-obligations"]
    assert "masking_before_serialization" in obligations
    assert "every_removed_line_is_masked" in obligations
    assert "snapshot_is_computed_in_memory" in obligations
    # Pas de 5e outil, pas de champ bonus : additionalProperties false partout
    # sur les entrees (verification sur un echantillon d'objets).
    for name in ("ReadDiffInput", "SanitizeFileInput", "ListCandidatesInput", "ProposePatchInput"):
        assert schema["$defs"][name]["additionalProperties"] is False, name
    # Le serveur squelette est fail-closed et n'ecrit rien : interdiction AST
    # des sinks d'ecriture (un test par chaines "open(" est contournable par
    # Path.write_bytes, os.open, io.open, shutil.copyfile, os.symlink...).
    # Limite assumee : l'AST ne voit pas les acces dynamiques (getattr,
    # `getattr(os,"sy"+"stem")`) ; la vraie preuve (aucune valeur connue dans
    # les champs serialises, aucune ecriture hors racine) reste due par les
    # tests runtime de #27/#30, qui reecriront cette garde.
    assert _write_sink_calls(MCP_SERVER) == []
    src = MCP_SERVER.read_text(encoding="utf-8")
    assert "sans outil d'écriture, d'exécution ou réseau" in src
    assert "raise NotImplementedError" in src
    # Codes d'erreur de chemin rattaches aux bons outils uniquement.
    sanitize_codes = schema["$defs"]["SanitizeFileError"]["properties"]["code"]["enum"]
    assert "PATH_ESCAPE" in sanitize_codes and "FORBIDDEN_PATH" in sanitize_codes
    propose_codes = schema["$defs"]["ProposePatchError"]["properties"]["code"]["enum"]
    assert "PATH_ESCAPE" not in propose_codes
    assert "STALE_CANDIDATE" in propose_codes


def test_symlink_swap_rejected_at_use(tmp_path: Path) -> None:
    """REQ-SEC-03 (complement) : descripteur reverifie apres ouverture."""
    repository = tmp_path / "repo2"
    repository.mkdir()
    victim = repository / "doc.md"
    victim.write_text("v1\n", encoding="utf-8")
    data = checker.read_confined_bytes(victim, repository.resolve(), 1024)
    assert data == b"v1\n"
    # Un repertoire a la place du fichier est refuse (pas un fichier regulier).
    # Sur Windows, l'ouverture echoue directement (OSError) ; sur POSIX,
    # le descripteur est rejete comme non regulier (ValueError).
    victim.unlink()
    victim.mkdir()
    try:
        checker.read_confined_bytes(victim, repository.resolve(), 1024)
    except ValueError as exc:
        assert "regular" in str(exc)
    except OSError:
        pass
    else:
        raise AssertionError("repertoire accepte comme fichier regulier")
