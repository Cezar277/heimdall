"""Garde statique du workflow CI (#20) : les invariants de sécurité de
`.github/workflows/ci.yml` ne peuvent pas régresser silencieusement.

Pas de dépendance YAML ici : le fichier est lu en texte et seules des
propriétés simples sont vérifiées — épinglage SHA des actions, moindre
privilège, séparation des privilèges entre le job qui exécute le code de PR
(`test`) et ceux qui publient le check `CI (/ci)` (`resolve`, `report`).
"""

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[2]
CI = REPO / ".github" / "workflows" / "ci.yml"
TEXT = CI.read_text(encoding="utf-8")

# Lignes actives uniquement : un commentaire pleine ligne ne compte pas.
ACTIVE = "\n".join(
    line for line in TEXT.splitlines() if not line.lstrip().startswith("#")
)

# Bloc `jobs:` seul (les clés de déclencheurs sont aussi à 2 espaces).
JOBS = ACTIVE.split("\njobs:\n", 1)[1]
JOB_KEY = re.compile(r"^  ([a-z][a-z0-9-]*):$", re.MULTILINE)


def _jobs() -> dict[str, str]:
    """Découpe `jobs:` en {nom: bloc} (clés à 2 espaces, blocs successifs)."""
    jobs: dict[str, str] = {}
    keys = list(JOB_KEY.finditer(JOBS))
    for index, key in enumerate(keys):
        end = keys[index + 1].start() if index + 1 < len(keys) else len(JOBS)
        jobs[key.group(1)] = JOBS[key.start() : end]
    return jobs


def test_actions_epinglees_par_sha() -> None:
    uses = re.findall(r"uses:\s*(\S+)", ACTIVE)
    assert uses, "le workflow n'utilise aucune action ?"
    for action in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action
    expected = [
        "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
    ]
    assert sorted(uses) == sorted(expected)


def test_pas_de_pull_request_target_ni_pull_request() -> None:
    # pull_request_target exécuterait du code de PR avec un token en écriture.
    assert "pull_request_target" not in ACTIVE
    assert not re.search(r"^  pull_request:$", ACTIVE, re.MULTILINE)


def test_runner_self_hosted_pour_tous_les_jobs() -> None:
    assert set(re.findall(r"runs-on:\s*(\S+)", ACTIVE)) == {"self-hosted"}


def test_separation_des_privileges_entre_check_et_code_de_pr() -> None:
    jobs = _jobs()
    assert {"resolve", "test", "report"} <= set(jobs)
    # Le job qui exécute le code de la PR n'a aucun droit d'écriture.
    assert "write" not in jobs["test"]
    assert "contents: read" in jobs["test"]
    # Les jobs qui écrivent le check ne checkout jamais le code de la PR.
    for trusted in ("resolve", "report"):
        assert "checks: write" in jobs[trusted]
        assert "actions/checkout" not in jobs[trusted]
        assert not re.search(r"^\s*run\s*:", jobs[trusted], re.MULTILINE)


def test_integrite_du_check_publie() -> None:
    # Check publié sur le commit de merge, puis comparaison du HEAD réellement
    # checkouté à ce SHA (anti-TOCTOU) passée au job de test via `needs`.
    assert "checks.create" in ACTIVE
    assert "rev-parse HEAD" in ACTIVE
    assert "needs.resolve.outputs.check_sha" in ACTIVE
    assert "EXPECTED_SHA: ${{ needs.resolve.outputs.check_sha }}" in ACTIVE
    assert '[ "$tested" != "$EXPECTED_SHA" ]' in ACTIVE
    assert '"${{ needs.resolve.outputs.check_sha }}"' not in ACTIVE
    assert "github.paginate(" in ACTIVE
    assert "response.data.check_runs" in ACTIVE
    assert "per_page: 100" in ACTIVE


def test_installation_verrouillee() -> None:
    assert "--require-hashes" in ACTIVE
    assert "persist-credentials: false" in ACTIVE
    # Pas de mise à jour de pip hors verrou : casserait la chaîne de hashes.
    assert "--upgrade pip" not in ACTIVE


def test_seuils_de_couverture() -> None:
    assert "--cov-fail-under=85" in ACTIVE
    assert "--fail-under=70" in ACTIVE
    for module in ("vault", "scanner", "mcp"):
        assert f"heimdall/{module}/*" in ACTIVE


def test_pins_directs_pyproject_synchronises_avec_le_lock() -> None:
    """Toute dépendance directe `==` doit avoir la même version dans le lock."""
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    requirements = list(project["dependencies"])
    for group in project["optional-dependencies"].values():
        requirements.extend(group)

    declared: dict[str, str] = {}
    for requirement in requirements:
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^;\s]+)", requirement)
        assert match, f"dépendance directe non épinglée par == : {requirement}"
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        declared[name] = match.group(2)

    lock_text = (REPO / "requirements.lock").read_text(encoding="utf-8")
    locked = {
        re.sub(r"[-_.]+", "-", name).lower(): version
        for name, version in re.findall(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)",
            lock_text,
            re.MULTILINE,
        )
    }
    drift = {
        name: {"pyproject.toml": version, "requirements.lock": locked.get(name)}
        for name, version in declared.items()
        if locked.get(name) != version
    }
    assert not drift, f"pyproject.toml et requirements.lock divergent : {drift}"


def test_commande_ci_en_debut_de_commentaire() -> None:
    assert "startsWith(github.event.comment.body, '/ci')" in ACTIVE
    assert "contains(github.event.comment.body, '/ci')" not in ACTIVE
    # Le corps du commentaire n'est exploité que dans la garde d'expression
    # (startsWith) — jamais interpolé dans un step shell.
    for line in ACTIVE.splitlines():
        if "github.event.comment.body" in line:
            assert "startsWith" in line, line


def test_gardes_abus_du_declencheur() -> None:
    # Seuls OWNER/MEMBER/COLLABORATOR passent, et la garde est présente sur
    # les deux chemins (approbation et commentaire /ci).
    assert ACTIVE.count("author_association") == 2
    assert '"OWNER","MEMBER","COLLABORATOR"' in ACTIVE
    assert '"NONE"' not in ACTIVE
    assert "CONTRIBUTOR" not in ACTIVE
    assert "github.event.review.state == 'approved'" in ACTIVE
    # merge_commit_sha absent (conflits) : échec fail-closed, pas de check.
    assert "if (!pr.merge_commit_sha)" in ACTIVE
    assert "Commit de merge indisponible" in ACTIVE
