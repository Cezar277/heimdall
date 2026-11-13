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
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
    ]
    assert sorted(uses) == sorted(expected)


def test_all_workflows_pin_actions_by_sha() -> None:
    """Aucun workflow ne consomme d'action via tag mutable (revue #144).

    `test_actions_epinglees_par_sha` ne lit que `ci.yml` : sans ce garde,
    `vault-contract.yml` est repassé à `actions/checkout@v7` sans être
    détecté. Ici on itère sur tous les `*.yml` de `.github/workflows/`
    avec la même regex : chaque `uses:` doit être `nom@sha40`.
    Seule la forme est exigée (pas la liste exacte par fichier, qui
    évolue avec Dependabot, ex. `actions/cache` en #143).
    """
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    assert workflows, "aucun workflow ?"
    for workflow in workflows:
        active = "\n".join(
            line
            for line in workflow.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        uses = re.findall(r"uses:\s*(\S+)", active)
        for action in uses:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), (
                f"{workflow.name}: {action}"
            )


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
    assert "external_id: externalId" in ACTIVE
    assert "matchingChecks.find(run => run?.external_id === externalId)?.id" in ACTIVE
    assert "let checkId = created?.data?.id" in ACTIVE
    assert "if (!checkId)" in ACTIVE
    assert "String(checkId)" in ACTIVE
    assert "issues: write" not in ACTIVE
    assert "createForIssueComment" not in ACTIVE


def test_installation_verrouillee() -> None:
    assert "--require-hashes" in ACTIVE
    assert "--no-build-isolation" in ACTIVE
    assert "persist-credentials: false" in ACTIVE
    # Pas de mise à jour de pip hors verrou : casserait la chaîne de hashes.
    assert "--upgrade pip" not in ACTIVE
    lock_text = (REPO / "requirements.lock").read_text(encoding="utf-8")
    assert re.search(r"^pip==[^\n]+\\\n\s+--hash=sha256:[0-9a-f]{64}", lock_text, re.MULTILINE)


def test_seuils_de_couverture() -> None:
    assert "--cov-fail-under=85" in ACTIVE
    includes = re.findall(r'--include="([^"]+)"', ACTIVE)
    assert sorted(includes) == sorted(
        ["heimdall/vault/*", "heimdall/scanner/*", "heimdall/mcp/*"]
    )
    assert ACTIVE.count("--fail-under=70") == 3


def test_pins_directs_pyproject_synchronises_avec_le_lock() -> None:
    """Toute dépendance directe `==` doit avoir la même version dans le lock."""
    document = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]
    requirements = list(document["build-system"]["requires"])
    requirements.extend(project["dependencies"])
    for group in project["optional-dependencies"].values():
        requirements.extend(group)

    # Les extras PEP 508 (`coverage[toml]`) font partie de la spécification :
    # ils ne changent ni le nom du paquet ni la version à comparer.
    exigence = r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^;\s]+)"

    declared: dict[str, str] = {}
    for requirement in requirements:
        match = re.match(exigence, requirement)
        assert match, f"dépendance directe non épinglée par == : {requirement}"
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        assert name not in declared or declared[name] == match.group(2), (
            f"épinglages contradictoires pour {name}"
        )
        declared[name] = match.group(2)

    lock_text = (REPO / "requirements.lock").read_text(encoding="utf-8")
    locked = {
        re.sub(r"[-_.]+", "-", name).lower(): version
        for name, version in re.findall(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\\;]+)",
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
    valid = ("/ci", "/ci extra", "  /ci", "/ci\nextra")
    invalid = ("/ciX", "/ci-malveillant", "texte /ci", " /cix")
    command = re.compile(r"^/ci(?:$|\s)")
    assert all(command.match(body.strip()) for body in valid)
    assert not any(command.match(body.strip()) for body in invalid)
    # Les expressions GitHub n'ont pas trim : le job de contexte filtre le
    # résultat exact après trim avant d'autoriser `test`.
    assert "context.payload.comment.body.trim()" in ACTIVE
    assert r"if (!/^\/ci(?:$|\s)/.test(command))" in ACTIVE
    assert "run_tests: ${{ steps.ctx.outputs.run_tests }}" in ACTIVE
    assert "if: needs.resolve.outputs.run_tests == 'true'" in ACTIVE


def test_forks_et_dispatch_ne_lancent_pas_de_code_non_revu() -> None:
    # Les reviews de forks sont filtrées avant d'allouer un runner ; le chemin
    # /ci vérifie aussi head.repo via l'API (l'event issue_comment ne l'expose pas).
    assert "github.event.pull_request.head.repo.fork == false" in ACTIVE
    assert "if (!pr.head.repo || pr.head.repo.fork)" in ACTIVE
    assert "core.setOutput('run_tests', 'false')" in ACTIVE
    # Dispatch de debug uniquement sur main, sans PR/check publié.
    assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'" in ACTIVE
    assert "core.setOutput('run_tests', 'true')" in ACTIVE
    assert "core.setOutput('has_pr', 'false')" in ACTIVE


def test_lock_filelock_couvre_python_310_et_311_plus() -> None:
    """Le lock doit servir 3.10 **et** les Python corrigés (≥ 3.11).

    Six CVE filelock sont corrigées en 4.2.1, qui exige Python ≥ 3.11.
    Un lock régénéré sous 3.10 ne peut donc sélectionner que 4.1.0
    vulnérable : le pin marqué 3.11+ est réinséré par
    ``scripts/regen_lock.py``. Sans ce garde, une régénération manuelle
    réintroduit silencieusement les CVE sur la CI (Python 3.13).
    """
    lock_text = (REPO / "requirements.lock").read_text(encoding="utf-8")
    filelock_lines = [
        line for line in lock_text.splitlines() if line.startswith("filelock==")
    ]
    assert len(filelock_lines) == 2, filelock_lines
    assert all("python_version" in line for line in filelock_lines), filelock_lines
    for requirement in (
        'filelock==4.1.0 ; python_version < "3.11"',
        'filelock==4.2.4 ; python_version >= "3.11"',
    ):
        assert re.search(
            rf"^{re.escape(requirement)} \\\n(?:    --hash=sha256:[0-9a-f]{{64}} \\\n)+",
            lock_text,
            re.MULTILINE,
        ), requirement

    # Le script de régénération doit lui-même porter les deux pins : c'est la
    # seule façon de reproduire ce lock depuis un pip-compile sous 3.10.
    script = (REPO / "scripts" / "regen_lock.py").read_text(encoding="utf-8")
    assert 'filelock==4.1.0 ; python_version < "3.11"' in script
    assert 'filelock==4.2.4 ; python_version >= "3.11"' in script


def test_gardes_abus_du_declencheur() -> None:
    # Seuls OWNER/MEMBER/COLLABORATOR passent, et la garde est présente sur
    # les deux chemins (approbation et commentaire /ci).
    assert ACTIVE.count("author_association") == 2
    assert '"OWNER","MEMBER","COLLABORATOR"' in ACTIVE
    assert '"NONE"' not in ACTIVE
    assert "CONTRIBUTOR" not in ACTIVE
    assert "github.event.review.state == 'approved'" in ACTIVE
    assert "github.event.pull_request.head.repo.fork == false" in ACTIVE
    # merge_commit_sha absent (conflits) : échec fail-closed, pas de check.
    assert "if (!pr.merge_commit_sha)" in ACTIVE
    assert "Commit de merge indisponible" in ACTIVE
