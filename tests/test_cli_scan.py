"""CLI ``heimdall scan`` (#29) — codes de sortie, périmètres, absence de fuite.

Preuves demandées par la revue de #165 (point HIGH) :

- le mode ``--staged`` analyse **tout** blob ajouté ou modifié dans l'index,
  **sans exclusion de chemin** : ``vendor/evil.py`` et ``package-lock.json``
  sont donc détectés (la politique #59 les excluait) ;
- e2e : dépôt propre => 0, secret avéré => 1, racine absente => 2, et
  **aucune écriture** dans le dépôt scanné.

Toutes les valeurs sont synthétiques : ``AKIAIOSFODNN7EXAMPLE`` est la clé
d'exemple de la documentation AWS, jamais une clé fonctionnelle.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from support.git_repo import GIT, GitRepo
from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.cli.scan import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    JSON_SCHEMA,
    ScanReport,
    _verify_root_unchanged,
    collect,
)
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess, StagedChange, parse_staged_raw
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import FileTarget
from heimdall.scanner.signature_engine import SignatureEngine

#: Racine du dépôt (les schémas vivent dans `schemas/`, hors paquet).
REPO = Path(__file__).resolve().parents[1]

#: Contrat de sortie `--json`, résolu avec le contrat Finding v1 (#14).
SCAN_SCHEMA = json.loads((REPO / "schemas/scan.schema.json").read_text(encoding="utf-8"))
FINDING_SCHEMA = json.loads((REPO / "schemas/finding.schema.json").read_text(encoding="utf-8"))


def _scan_validator() -> Draft202012Validator:
    """Validateur du contrat `heimdall.scan.v1`, Finding v1 résolu par registre.

    `findings[].items` référence `finding.schema.json` par `$ref` relatif :
    le registre fournit les deux documents, sans toucher au réseau ni
    dupliquer le contrat #14 (toute dérive du Finding casse ce test).
    """
    registry = Registry().with_resources(
        [
            (
                "https://github.com/Cezar277/heimdall/schemas/finding.schema.json",
                Resource(contents=FINDING_SCHEMA, specification=DRAFT202012),
            ),
            (
                "https://github.com/Cezar277/heimdall/schemas/scan.schema.json",
                Resource(contents=SCAN_SCHEMA, specification=DRAFT202012),
            ),
        ]
    )
    return Draft202012Validator(SCAN_SCHEMA, registry=registry)


def _retrieve_local(uri: str) -> Resource[object]:
    """Récupération filesystem des schémas Heimdall, sans aucun réseau.

    Tout `$id` sous `https://github.com/Cezar277/heimdall/schemas/` est servi
    par le fichier homonyme de `schemas/` ; toute autre URI est refusée
    (fail-closed : jamais de fetch, même si un `$ref` devenait distant).
    C'est ce qui rend le `$ref` relatif de `scan.schema.json` résolvable par
    un outillage standard muni d'un miroir local, sans registre câblé.
    """
    prefix = "https://github.com/Cezar277/heimdall/schemas/"
    if not uri.startswith(prefix):
        raise ValueError(f"schéma hors périmètre : {uri}")
    name = uri[len(prefix):]
    if "/" in name or not name.endswith(".schema.json"):
        raise ValueError(f"schéma hors périmètre : {uri}")
    document = json.loads((REPO / "schemas" / name).read_text(encoding="utf-8"))
    return Resource(contents=document, specification=DRAFT202012)


def _validate_scan_document(document: dict[str, object]) -> None:
    """Validation recommandée aux parseurs : schéma **puis** cohérence `count`.

    L'égalité `count == len(findings)` est inexprimable en JSON Schema ; un
    parseur qui ne valide que le schéma accepte un document incohérent.
    """
    _scan_validator().validate(document)
    findings = document["findings"]
    if not isinstance(findings, list) or document["count"] != len(findings):
        raise ValueError("count incohérent avec findings")


def _scan_validator_from_filesystem() -> Draft202012Validator:
    """Validateur résolu depuis l'arborescence, sans contenu câblé en dur.

    Seul le document racine est chargé explicitement ; `finding.schema.json`
    est atteint par son `$id` déclaré, via `_retrieve_local`. Si les deux
    `$id` divergeaient ou si le `$ref` ne suivait plus, ce test casserait.
    """
    registry = Registry(retrieve=_retrieve_local)
    return Draft202012Validator(SCAN_SCHEMA, registry=registry)


def _refuse_non_finite(value: str) -> object:
    """Refuse les constantes non finies d'un document JSON (`allow_nan`).

    `render_json` sérialise avec `allow_nan=False` : un NaN ne doit jamais
    arriver jusqu'ici. Relire en refusant `NaN`/`Infinity` fige ce contrat
    sur la sortie réelle.
    """
    raise ValueError(f"constante non finie refusée : {value}")


class _HasherCompteur(SnippetHasher):
    """SnippetHasher qui compte les hachages : preuve du refus fail-fast.

    Un compteur qui s'arrête au plafond + 1 prouve que le refus coupe le
    travail en cours, au lieu d'accumuler puis trier avant de refuser.
    """

    def __init__(self) -> None:
        super().__init__(key=bytes(32))
        self.compte = 0

    def hash(self, candidate: str) -> str:
        self.compte += 1
        return super().hash(candidate)


def _cles_denses(nombre: int) -> str:
    """`nombre` clés AWS distinctes sur UNE ligne : un seul blob dense.

    Chaque clé donne exactement un match (vérifié) : `nombre` clés sur une
    ligne = `nombre` Findings, sans l'artefact de la fenêtre multi-ligne.
    """
    return " ".join(f'"AKIA{chr(65 + (i % 26))}{i:015d}"' for i in range(nombre))


#: Exemple de clé AWS (documentation AWS) : jamais une clé fonctionnelle.
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

#: Clé HMAC locale de test : empreinte déterministe, aucun fichier créé.
TEST_HMAC_KEY = "00" * 32

#: Libellé unique du code 2 : panne anticipée et panne inattendue ne sont
#: pas distinguables sur stderr (revue, oracle minimal).
SCAN_ERROR_MESSAGE = "heimdall scan : scan impossible (erreur d'outillage)."


@pytest.fixture(autouse=True)
def _cle_hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empreintes déterministes et **aucune** écriture hors du dépôt."""
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)


@pytest.fixture
def git_repo() -> Iterator[GitRepo]:
    """Dépôt git jetable (jamais le dépôt Heimdall lui-même)."""
    repo = GitRepo("heimdall-t29-")
    try:
        yield repo
    finally:
        repo.close()


def _run(*arguments: str) -> object:
    return CliRunner().invoke(app, list(arguments))


def _git(cible: Path, *arguments: str) -> None:
    """Commande git d'aide au test (dépôt jetable, argv figé, sans shell)."""
    assert GIT is not None
    termine = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(cible), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert termine.returncode == 0, termine.stderr


def _arbre(tmp_path: Path, contenu: dict[str, str]) -> Path:
    """Écrit un petit dépôt git (hors dépôt Heimdall) et rend sa racine.

    Le mode arbre exige une racine de dépôt (#29) : chaque arbre de test
    est donc initialisé (`git init`, sans commit — `is_repository` n'en
    demande pas). Sans git : `skip`, jamais de repli.
    """
    if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
        pytest.skip("git requis")
    racine = tmp_path / "repo"
    racine.mkdir()
    for relatif, texte in contenu.items():
        chemin = racine / relatif
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text(texte, encoding="utf-8")
    _git(racine, "init", "-q")
    _git(racine, "config", "user.email", "test@example.invalid")
    _git(racine, "config", "user.name", "Heimdall Test")
    return racine


# --- codes de sortie (invariant 11, REQ-SEC-07) ---------------------------


def test_scan_clean_repository_exits_zero(tmp_path: Path) -> None:
    """Dépôt réellement propre => 0 (et rien n'est écrit)."""
    racine = _arbre(tmp_path, {"app.py": "print('coucou')\n"})
    avant = sorted(p.name for p in racine.iterdir())
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    assert "Aucun secret détecté" in resultat.stdout
    # Lecture seule : le dépôt est inchangé.
    assert sorted(p.name for p in racine.iterdir()) == avant


def test_scan_detected_secret_exits_one(tmp_path: Path) -> None:
    """Secret avéré => 1, et le secret n'est jamais affiché en clair."""
    racine = _arbre(tmp_path, {"config.py": f'AWS = "{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in resultat.stdout
    assert "config.py:1" in resultat.stdout
    # Le secret ne doit apparaître ni dans la sortie, ni dans stderr.
    assert FAKE_AWS_KEY not in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.stderr


def test_scan_missing_root_exits_two(tmp_path: Path) -> None:
    """Racine absente => 2 (erreur d'outillage), jamais 0 ni 1."""
    resultat = _run("scan", str(tmp_path / "absent-29"))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE
    # L'entrée refusée n'est jamais reflétée (invariant 8).
    assert "absent-29" not in resultat.output


def test_scan_does_not_write_anything(tmp_path: Path) -> None:
    """Un scan n'écrit rien : ni dans le dépôt, ni à côté."""
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    avant = sorted(p.name for p in tmp_path.iterdir())
    assert _run("scan", str(racine)).exit_code == EXIT_CLEAN
    assert sorted(p.name for p in tmp_path.iterdir()) == avant


def test_scan_render_failure_exits_two_not_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue #166 (LOW) : un échec de **rendu** sort en 2, jamais en 1.

    L'exit 1 est réservé aux secrets avérés (invariant 11) : une panne de
    rendu ne doit pas faire croire à une détection.
    """
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})

    def rendu_casse(_report: object) -> str:
        raise RuntimeError("panne de rendu")

    monkeypatch.setattr("heimdall.cli.main.render_text", rendu_casse)
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    # Même libellé que `ScanError`/`ToolFailure` : un observateur ne peut
    # pas distinguer une panne anticipée d'une panne inattendue.
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_tool_failure_uses_the_same_static_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `ToolFailure` et panne inattendue ont le même stderr.

    Le test de rendu couvre `Exception`, celui-ci `ToolFailure` : les deux
    chemins doivent produire exactement le libellé de `ScanError`.
    """
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})

    def collecte_en_panne(*_arguments: object, **_options: object) -> None:
        raise ToolFailure("INTERNAL")

    monkeypatch.setattr("heimdall.cli.main.collect", collecte_en_panne)
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


@pytest.mark.parametrize(
    "bad_scope",
    [
        "invalide",
        [],
        {},
        None,
        42,
    ],
)
def test_scan_report_refuses_an_unknown_scope(bad_scope: object) -> None:
    """Revue (LOW) : le `Literal` est doublé d'une garde runtime.

    Un appelant non typé ne doit pas fabriquer un rapport hors contrat qui
    ferait un `KeyError` ou un `TypeError` (si non hashable comme liste/dict)
    dans `_SCOPE_LABELS` : `ScanReport(scope=[], ...)` et `scope=None` lèvent
    `ScanError`, jamais `TypeError` ni `KeyError`.
    """
    with pytest.raises(ScanError):
        ScanReport(scope=bad_scope, findings=())  # type: ignore[arg-type]


def test_scan_report_refuses_an_invalid_vcs_ignored_count() -> None:
    """Le champ ``vcs_ignored`` reste un entier positif ou nul au runtime."""
    for invalid in (-1, True, 1.0, "1"):
        with pytest.raises(ScanError):
            ScanReport(scope="working-tree", findings=(), vcs_ignored=invalid)  # type: ignore[arg-type]


def test_scan_report_refuses_an_invalid_git_ignored_count() -> None:
    """Le champ ``git_ignored`` reste un entier positif ou nul au runtime."""
    for invalid in (-1, True, 1.0, "1"):
        with pytest.raises(ScanError):
            ScanReport(scope="working-tree", findings=(), git_ignored=invalid)  # type: ignore[arg-type]


def test_scan_broken_stderr_still_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue #166 (LOW) : stderr fermé -> 2 garanti, jamais 1 ni traceback.

    Tout ``echo(..., err=True)`` lève ``BrokenPipeError``, y compris dans
    les handlers d'erreur : l'écriture de secours est best-effort, et le
    code 2 reste garanti (invariant 11).
    """
    original_echo = typer.echo

    def echo_sans_stderr(message: object, err: bool = False, **kwargs: object) -> None:
        if err:
            raise BrokenPipeError("stderr fermé")
        original_echo(message, err=err, **kwargs)

    monkeypatch.setattr(typer, "echo", echo_sans_stderr)
    # 1. Chemin d'erreur : racine absente -> handler best-effort -> 2.
    resultat = _run("scan", str(tmp_path / "absent-epipe"))
    assert resultat.exit_code == EXIT_ERROR
    # 2. Chemin nominal --ci : le résumé stderr échoue -> 2, pas 0. Le
    # verdict n'a pas pu être consigné : fail-closed, pas de 0.
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--ci", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    # 3. Sans --ci, stdout suffit : stderr cassé n'empêche pas le 0.
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_CLEAN


def test_scan_tree_refuses_global_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : l'arbre est aussi borné en temps, pas seulement en volume.

    Un dépôt adverse de petits fichiers ne doit pas faire durer la CI sans
    verdict : deadline déjà expirée -> refus 2, comme en `--staged`.
    """
    monkeypatch.setattr("heimdall.cli.scan.MAX_TREE_SECONDS", -1.0)
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_tree_refuses_too_many_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue #166 (LOW) : l'arbre est borné en **nombre de fichiers**.

    Un dépôt adverse avec des milliers de petits fichiers ne doit pas faire
    durer la CI sans verdict : au-delà du plafond, refus (code 2).
    """
    monkeypatch.setattr("heimdall.scanner.detect.MAX_FILES", 1)
    racine = _arbre(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n"})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_refuses_too_many_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue #166 (LOW) : l'arbre est borné en **volume total lu**.

    La borne par fichier (1 Mio) ne suffit pas : 50 000 fichiers feraient
    50 Gio. Au-delà du plafond total, refus (code 2).
    """
    monkeypatch.setattr("heimdall.scanner.detect.MAX_TOTAL_BYTES", 10)
    racine = _arbre(tmp_path, {"a.py": "x = 1\n" * 10})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR


def test_collect_tree_uses_the_pinned_root(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `TreeScanner` reçoit `access.root`, pas l'entrée brute.

    Une entrée avec ``..`` prouve qu'une seule résolution est faite : le
    scanner ne re-résout pas le chemin demandé après la garde de `GitAccess`.
    """
    git_repo.write("app.py", "x = 1\n")
    seen: list[tuple[Path, bool]] = []

    class ScannerEspion:
        def __init__(self, root: Path, *, strict: bool, **kwargs: object) -> None:
            seen.append((Path(root), strict))
            self.traces: tuple[object, ...] = ()
            self.vcs_ignored = 0
            self.git_ignored = 0
            self.files_scanned = 0
            self.skipped = ()

        def scan(self, *, deadline: float | None = None) -> list[object]:
            assert deadline is not None
            return []

    monkeypatch.setattr("heimdall.cli.scan.TreeScanner", ScannerEspion)
    racine = git_repo.root / ".." / git_repo.root.name
    resultat = _run("scan", "--strict", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    assert seen == [(git_repo.root.resolve(), True)]


def test_tree_scanner_resolves_the_same_root_from_raw_or_pinned(
    git_repo: GitRepo,
) -> None:
    """Revue (LOW) : `access.root` et l'entrée brute convergent.

    La seconde résolution est idempotente ; une substitution entre les deux
    est couverte par le re-contrôle d'identité final.
    """
    access = GitAccess(git_repo.root)
    raw = git_repo.root / ".." / git_repo.root.name
    assert (
        TreeScanner(access.root, strict=True)._root
        == TreeScanner(raw, strict=True)._root
        == git_repo.root.resolve()
    )


@pytest.mark.parametrize("borne", ["max_files", "max_bytes", "max_findings"])
@pytest.mark.parametrize("valeur", [0, -1, 10**12])
def test_scanner_refuses_invalid_explicit_bounds(
    tmp_path: Path, borne: str, valeur: int
) -> None:
    """Revue (LOW) : une surcharge explicite ne relève pas les bornes.

    ``None`` retombe sur le défaut ; zéro, négatif ou entier géant sont
    refusés à la construction (``ValueError``), jamais acceptés en silence.
    """
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    with pytest.raises(ValueError):
        TreeScanner(racine, **{borne: valeur})


# --- mode strict : les exclusions de contenu texte tombent -----------------


def test_scan_tree_scans_vendor_and_lockfiles(tmp_path: Path) -> None:
    """L'arbre de travail est scanné en mode strict : ``vendor/`` compris."""
    racine = _arbre(
        tmp_path,
        {
            "vendor/evil.py": f'KEY = "{FAKE_AWS_KEY}"\n',
            "package-lock.json": f'{{"token": "{FAKE_AWS_KEY}"}}\n',
        },
    )
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "vendor/evil.py:1" in resultat.stdout
    assert "package-lock.json:1" in resultat.stdout


def test_scan_tree_scans_node_modules(tmp_path: Path) -> None:
    """Même ``node_modules/`` est un arbre de tiers parcouru : un secret y est un secret."""
    racine = _arbre(tmp_path, {"node_modules/pkg/evil.js": f'"{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "node_modules/pkg/evil.js:1" in resultat.stdout


def test_scan_tree_strict_scans_build_outputs(tmp_path: Path) -> None:
    """Revue (LOW) : les sorties de build textuelles ne sont plus un angle mort.

    ``build/``, ``dist/``, ``target/``, ``bower_components/`` et ``htmlcov/``
    sont exclus par la politique #59 seule ; en strict, un secret y est un
    secret, comme en ``--staged``.
    """
    contenu = {
        "build/output.js": f'AWS = "{FAKE_AWS_KEY}"\n',
        "dist/bundle.js": f'AWS = "{FAKE_AWS_KEY}"\n',
        "target/app.js": f'AWS = "{FAKE_AWS_KEY}"\n',
        "bower_components/lib.js": f'AWS = "{FAKE_AWS_KEY}"\n',
        "htmlcov/index.html": f'AWS = "{FAKE_AWS_KEY}"\n',
    }
    racine = _arbre(tmp_path, contenu)
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    for chemin in contenu:
        assert f"{chemin}:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output
    _git(racine, "add", "-A")
    resultat = _run("scan", "--staged", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    for chemin in contenu:
        assert f"{chemin}:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_tree_reports_the_vcs_skip_in_json_and_ci(tmp_path: Path) -> None:
    """Revue (MEDIUM) : ``vcs_ignored`` est observable jusqu'à la CLI.

    Un dépôt dont le seul contenu caché est sa base VCS rend ``[]`` : le
    rapport doit dire combien de bases ont été élaguées, en bibliothèque, en
    JSON et dans le résumé ``--ci``. Un ``[]`` ne doit jamais être lu comme
    « historique propre ».
    """
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    (racine / ".git" / "config-secret").write_text(
        f'AWS = "{FAKE_AWS_KEY}"\n', encoding="utf-8"
    )

    report = collect(racine, staged=False, allowlist=Allowlist.empty())
    assert report.findings == ()
    assert report.vcs_ignored == 1

    resultat_json = _run("scan", "--json", "--no-allowlist", str(racine))
    assert resultat_json.exit_code == EXIT_CLEAN
    document = json.loads(resultat_json.stdout)
    assert document["vcs_ignored"] == 1
    _validate_scan_document(document)

    resultat_ci = _run("scan", "--ci", "--no-allowlist", str(racine))
    assert resultat_ci.exit_code == EXIT_CLEAN
    assert "1 base(s) VCS élaguée(s)" in resultat_ci.stderr
    assert FAKE_AWS_KEY not in resultat_ci.output

    resultat_texte = _run("scan", "--no-allowlist", str(racine))
    assert resultat_texte.exit_code == EXIT_CLEAN
    assert "Base VCS : 1 base(s) élaguée(s)" in resultat_texte.stdout
    assert FAKE_AWS_KEY not in resultat_texte.output


def test_scan_tree_vcs_only_is_policy_and_staged_covers_content(
    git_repo: GitRepo,
) -> None:
    """Revue (LOW) : un arbre réduit à ``.git/`` est refusé en CI stricte.

    La politique d'élagage VCS est figée : la bibliothèque rend ``[]`` avec
    ``vcs_ignored == 1`` et ``files_scanned == 0``, la CLI locale rend 0 (un
    dépôt réellement vide est propre, pas illisible). En ``--ci``, le même
    arbre rend **2** : aucune automatisation ne peut confondre « propre » et
    « non parcouru » en ne lisant que le code de sortie. Le compteur reste
    observable en JSON et sur stderr. Le test rejoue ensuite ``--staged`` :
    un secret indexé est bien détecté (code 1), ce qui prouve que seul
    ``--staged`` couvre le contenu commité — l'arbre ne prétend jamais
    couvrir l'historique.
    """
    git_repo.write(".git/description", f'AWS = "{FAKE_AWS_KEY}"\n')

    scanner = TreeScanner(git_repo.root)
    assert scanner.scan() == []
    assert scanner.vcs_ignored == 1
    assert scanner.files_scanned == 0

    report = collect(git_repo.root, staged=False, allowlist=Allowlist.empty())
    assert report.findings == ()
    assert report.vcs_ignored == 1

    resultat = _run("scan", "--no-allowlist", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN
    assert "Base VCS : 1 base(s) élaguée(s)" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output

    resultat_ci = _run("scan", "--ci", "--no-allowlist", str(git_repo.root))
    assert resultat_ci.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat_ci.stderr
    assert FAKE_AWS_KEY not in resultat_ci.output

    resultat_json = _run("scan", "--json", "--no-allowlist", str(git_repo.root))
    assert resultat_json.exit_code == EXIT_CLEAN
    document = json.loads(resultat_json.stdout)
    assert document["vcs_ignored"] == 1
    _validate_scan_document(document)
    assert FAKE_AWS_KEY not in resultat_json.output

    # Le contenu indexé, lui, est analysé par --staged : ce que le commit
    # va contenir est couvert, même si l'arbre ne contient que le VCS.
    git_repo.write("app.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    resultat_staged = _run("scan", "--staged", "--no-allowlist", str(git_repo.root))
    assert resultat_staged.exit_code == EXIT_FINDINGS
    assert "app.py:1" in resultat_staged.stdout
    assert FAKE_AWS_KEY not in resultat_staged.output


def test_scan_tree_strict_scans_text_with_binary_suffix(git_repo: GitRepo) -> None:
    """Revue (LOW) : en strict, le contenu prime sur le suffixe binaire.

    ``evil.png`` est du texte clair portant un candidat : l'arbre strict doit
    le signaler comme ``--staged``, au lieu de le sauter sur l'extension.
    """
    git_repo.write("evil.png", f'AWS = "{FAKE_AWS_KEY}"\n')
    resultat = _run("scan", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "evil.png:1" in resultat.stdout
    git_repo.stage("evil.png")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "evil.png:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_tree_skips_a_gitignored_untracked_secret(git_repo: GitRepo) -> None:
    """#59 : un fichier non suivi et ignoré est écarté et **compté**.

    Le compteur ``git_ignored`` rend l'exclusion observable dans le JSON, le
    texte et le résumé ``--ci``. ``--no-gitignore`` rétablit le parcours
    intégral : le secret ignoré est alors détecté (code 1), pas un faux 0.
    """
    git_repo.write(".gitignore", ".env\n")
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage(".gitignore", "app.py")
    git_repo.commit_all("base")
    git_repo.write(".env", f'AWS = "{FAKE_AWS_KEY}"\n')

    resultat = _run("scan", "--json", "--no-allowlist", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN
    document = json.loads(resultat.stdout)
    assert document["findings"] == []
    assert document["git_ignored"] == 1
    _validate_scan_document(document)
    assert FAKE_AWS_KEY not in resultat.output

    resultat_texte = _run("scan", "--no-allowlist", str(git_repo.root))
    assert resultat_texte.exit_code == EXIT_CLEAN
    assert "Gitignore : 1 entrée(s)" in resultat_texte.stdout

    resultat_ci = _run("scan", "--ci", "--no-allowlist", str(git_repo.root))
    assert resultat_ci.exit_code == EXIT_CLEAN
    assert "1 entrée(s) ignorée(s) par .gitignore" in resultat_ci.stderr

    resultat_integral = _run(
        "scan",
        "--json",
        "--no-allowlist",
        "--no-gitignore",
        str(git_repo.root),
    )
    assert resultat_integral.exit_code == EXIT_FINDINGS
    document_integral = json.loads(resultat_integral.stdout)
    assert document_integral["git_ignored"] == 0
    assert [finding["file"] for finding in document_integral["findings"]] == [".env"]
    assert FAKE_AWS_KEY not in resultat_integral.output


def test_collect_tree_propagates_respect_gitignore_to_the_scanner(
    git_repo: GitRepo,
) -> None:
    """Non-régression du câblage CLI -> collect -> TreeScanner (#59).

    Le merge qui a écrasé ``respect_gitignore`` dans ``collect()`` levait un
    ``TypeError`` sur **chaque** ``heimdall scan``. Ce test appelle le chemin
    réel ``collect(..., respect_gitignore=False)``, pas seulement ``Scanner``
    directement, pour que la régression soit impossible à réintroduire.
    """
    git_repo.write(".gitignore", ".env\n")
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage(".gitignore", "app.py")
    git_repo.commit_all("base")
    git_repo.write(".env", f'AWS = "{FAKE_AWS_KEY}"\n')

    strict = collect(git_repo.root, staged=False, allowlist=Allowlist.empty())
    assert strict.findings == ()
    assert strict.git_ignored == 1

    integral = collect(
        git_repo.root,
        staged=False,
        allowlist=Allowlist.empty(),
        respect_gitignore=False,
    )
    assert [finding.file for finding in integral.findings] == [".env"]
    assert integral.git_ignored == 0
    assert FAKE_AWS_KEY not in repr(integral)


@pytest.mark.parametrize("invalid", ["false", 1, 0, None, object()])
def test_collect_refuses_an_invalid_respect_gitignore_policy(
    git_repo: GitRepo, invalid: object
) -> None:
    """Une valeur non booléenne est une erreur d'outillage, jamais un skip."""
    with pytest.raises(ScanError, match="politique d'exclusions Git invalide"):
        collect(
            git_repo.root,
            staged=False,
            allowlist=Allowlist.empty(),
            respect_gitignore=invalid,  # type: ignore[arg-type]
        )


def test_collect_ci_refuses_a_tree_reduced_to_gitignored_entries(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La garde ``--ci`` observe aussi ``git_ignored``, pas seulement le VCS.

    Un scanner qui n'aurait élagué aucune base VCS mais aurait sauté toutes
    les entrées ``.gitignore`` ne doit jamais rendre un faux « propre » en
    CI : la condition couvre les deux compteurs, même si ``.git`` est
    aujourd'hui toujours rencontré en pratique.
    """
    git_repo.write("app.py", "x = 1\n")

    class ScannerSansContenu:
        def __init__(self, root: Path, **kwargs: object) -> None:
            self.traces: tuple[object, ...] = ()
            self.vcs_ignored = 0
            self.git_ignored = 1
            self.files_scanned = 0
            self.skipped = ()

        def scan(self, *, deadline: float | None = None) -> list[object]:
            assert deadline is not None
            return []

    monkeypatch.setattr("heimdall.cli.scan.TreeScanner", ScannerSansContenu)
    with pytest.raises(ScanError, match="scan impossible"):
        collect(
            git_repo.root,
            staged=False,
            ci=True,
            allowlist=Allowlist.empty(),
        )


def test_scan_tree_always_scans_a_tracked_file_matching_gitignore(
    git_repo: GitRepo,
) -> None:
    """#59 : ``git add -f`` rend le fichier suivi ; le motif ne le cache pas."""
    git_repo.write(".gitignore", "config.py\n")
    git_repo.stage(".gitignore")
    git_repo.commit_all("base")
    git_repo.write("config.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.git("add", "-f", "config.py")
    git_repo.commit_all("tracked")

    resultat = _run("scan", "--json", "--no-allowlist", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    document = json.loads(resultat.stdout)
    assert document["git_ignored"] == 0
    assert [finding["file"] for finding in document["findings"]] == ["config.py"]
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_tree_ignored_binary_is_skipped_without_code_two(
    git_repo: GitRepo,
) -> None:
    """#59 : un binaire ignoré n'est pas ouvert ; ``--no-gitignore`` le refuse."""
    git_repo.write(".gitignore", "image.png\n")
    git_repo.stage(".gitignore")
    git_repo.commit_all("base")
    git_repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)

    resultat = _run("scan", "--strict", "--no-allowlist", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN
    assert "Gitignore : 1 entrée(s)" in resultat.stdout

    resultat_integral = _run(
        "scan", "--strict", "--no-allowlist", "--no-gitignore", str(git_repo.root)
    )
    assert resultat_integral.exit_code == EXIT_ERROR
    assert resultat_integral.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_ci_refuses_a_tree_with_only_gitignored_content(
    git_repo: GitRepo,
) -> None:
    """#59 : aucune entrée lue => code 2 en CI, jamais un faux « propre ».

    Le ``.gitignore`` s'ignore lui-même : l'arbre ne contient que des entrées
    non suivies et ignorées. En local, il reste un arbre vide (0) ; en CI, le
    verdict serait indistinguable d'un dépôt propre sans contenu analysé.
    """
    git_repo.write(".gitignore", ".gitignore\n.env\n")
    git_repo.write(".env", f'AWS = "{FAKE_AWS_KEY}"\n')
    resultat_local = _run("scan", "--json", "--no-allowlist", str(git_repo.root))
    assert resultat_local.exit_code == EXIT_CLEAN
    document = json.loads(resultat_local.stdout)
    assert document["git_ignored"] == 2
    assert document["count"] == 0

    resultat_ci = _run("scan", "--ci", "--no-allowlist", str(git_repo.root))
    assert resultat_ci.exit_code == EXIT_ERROR
    assert resultat_ci.stderr.strip() == SCAN_ERROR_MESSAGE
    assert FAKE_AWS_KEY not in resultat_ci.output


def test_scan_staged_scans_a_gitignored_secret(git_repo: GitRepo) -> None:
    """#59 : ``.gitignore`` ne réduit jamais le périmètre ``--staged``.

    Le fichier ignoré est ajouté de force dans l'index : c'est exactement ce
    que le commit va contenir, donc il doit être analysé, options comprises.
    """
    git_repo.write(".gitignore", ".env\n")
    git_repo.stage(".gitignore")
    git_repo.commit_all("base")
    git_repo.write(".env", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.git("add", "-f", ".env")

    for options in ((), ("--no-gitignore",)):
        resultat = _run("scan", "--staged", "--no-allowlist", *options, str(git_repo.root))
        assert resultat.exit_code == EXIT_FINDINGS
        assert ".env:1" in resultat.stdout
        assert FAKE_AWS_KEY not in resultat.output


def test_scan_tree_strict_refuses_real_binary_suffix(git_repo: GitRepo) -> None:
    """Un vrai binaire interrompt le scan (code 2), jamais un verdict propre."""
    git_repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)
    resultat = _run("scan", "--strict", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_tree_strict_refuses_unknown_binary_suffix(git_repo: GitRepo) -> None:
    """Revue (LOW) : un binaire inconnu à suffixe technique reste fail-closed.

    NUL + magie inconnue + candidat ASCII : le suffixe ne doit pas convertir
    le doute en skip silencieux. L'arbre strict et ``--staged`` refusent tous
    deux (code 2), pas 0 d'un côté et 2 de l'autre.
    """
    git_repo.write_bytes("evil.png", b"\x00\x01" + f'AWS = "{FAKE_AWS_KEY}"\n'.encode())
    resultat = _run("scan", "--strict", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE
    git_repo.stage("evil.png")
    resultat = _run("scan", "--strict", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


# --- mode ``--staged`` : les blobs de l'index, sans exclusion --------------


def test_scan_staged_detects_secret_in_vendor_path(git_repo: GitRepo) -> None:
    """Revue #165 (HIGH) : ``vendor/evil.py`` n'est PLUS exclu."""
    git_repo.write("vendor/evil.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("vendor/evil.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "vendor/evil.py:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_staged_detects_secret_in_lockfile(git_repo: GitRepo) -> None:
    """Revue #165 (HIGH) : ``package-lock.json`` n'est PLUS exclu."""
    git_repo.write("package-lock.json", f'{{"token": "{FAKE_AWS_KEY}"}}\n')
    git_repo.stage("package-lock.json")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "package-lock.json:1" in resultat.stdout


def test_scan_staged_accepts_space_and_unicode_paths(git_repo: GitRepo) -> None:
    """Un chemin légitime (espace, unicode) est analysé et publié tel quel."""
    chemin = "dossier avec espace/éàü.py"
    git_repo.write(chemin, f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.stage(chemin)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert f"{chemin}:1" in resultat.stdout


def test_scan_staged_accepts_a_long_path(git_repo: GitRepo) -> None:
    """Revue #166 (LOW) : au-delà de 1024 caractères, le contrat #14 fait foi.

    ``Finding.file`` autorise 4096 caractères ; l'ancienne garde ``is_rel_path``
    (1024, contrat MCP) refusait un chemin pourtant représentable. Le chemin
    est désormais validé par ``validate_relative_path`` (4096).
    """
    chemin = "/".join(["d" * 200] * 6) + "/secret.py"  # ~1216 caractères
    assert len(chemin) > 1024
    git_repo.write(chemin, f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.stage(chemin)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert f"{chemin}:1" in resultat.stdout


@pytest.mark.skipif(os.name != "posix", reason="noms non-UTF8 POSIX")
def test_scan_refuses_non_utf8_paths_in_both_scopes(git_repo: GitRepo) -> None:
    """Revue (LOW) : un nom non-UTF8 refuse le scan, en arbre comme en index.

    En arbre, `os.walk` rend des surrogates ; la garde unique
    `validate_relative_path` les refuse désormais explicitement. En index,
    le décodage UTF-8 strict de `git diff --raw -z` fait déjà échouer le
    parseur. Les deux périmètres sortent en 2, jamais 0/1 partiel.
    """
    raw = os.fsencode(git_repo.root) + b"/bad-\xff.py"
    descriptor = os.open(raw, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(descriptor)
    resultat = _run("scan", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE
    git_repo.git("add", "-A")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_staged_with_a_sha256_repository() -> None:
    """Revue #166 (LOW) : un dépôt SHA-256 (blobs de 64 hexa) est supporté."""
    try:
        repo = GitRepo("heimdall-t29-sha256-", object_format="sha256")
    except AssertionError:  # pragma: no cover - git sans support SHA-256.
        pytest.skip("git ne supporte pas --object-format=sha256")
    try:
        repo.write("vendor/evil.py", f'KEY = "{FAKE_AWS_KEY}"\n')
        repo.stage("vendor/evil.py")
        resultat = _run("scan", "--staged", str(repo.root))
        assert resultat.exit_code == EXIT_FINDINGS
        assert "vendor/evil.py:1" in resultat.stdout
    finally:
        repo.close()


def test_scan_staged_clean_repository_exits_zero(git_repo: GitRepo) -> None:
    """Index propre => 0."""
    git_repo.write("app.py", "print('coucou')\n")
    git_repo.stage("app.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN
    assert "Aucun secret détecté" in resultat.stdout


def test_scan_staged_scans_the_whole_modified_blob(git_repo: GitRepo) -> None:
    """Le blob indexé est lu en entier, pas seulement ses lignes modifiées.

    Un secret déjà présent dans le fichier et laissé tel quel par la
    modification reste dans le blob indexé : il doit être signalé.
    """
    git_repo.write("config.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("config.py")
    git_repo.commit_all("base")
    # Modification d'une autre ligne : le secret n'est pas dans le diff.
    git_repo.write("config.py", f'AWS = "{FAKE_AWS_KEY}"\nOTHER = 1\n')
    git_repo.stage("config.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "config.py:1" in resultat.stdout


def test_scan_staged_ignores_deleted_file(git_repo: GitRepo) -> None:
    """Un fichier supprimé n'a plus de blob à scanner."""
    git_repo.write("app.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    git_repo.git("rm", "-q", "app.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN


def test_scan_staged_outside_a_repository_exits_two(tmp_path: Path) -> None:
    """Hors dépôt git, le mode ``--staged`` est une erreur, pas un verdict."""
    racine = tmp_path / "plaine"
    racine.mkdir()
    (racine / "app.py").write_text("x = 1\n", encoding="utf-8")
    resultat = _run("scan", "--staged", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_outside_a_repository_exits_two(tmp_path: Path) -> None:
    """Revue (LOW) : le mode arbre exige lui aussi une racine de dépôt.

    Une CI mal configurée (mauvais chemin, répertoire vide) obtient un 2
    loud, jamais un 0 « propre » silencieux. Idem pour un fichier isolé :
    le scan unitaire reste possible en bibliothèque, hors contrat hook/CI.
    """
    plaine = tmp_path / "plaine"
    plaine.mkdir()
    (plaine / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert _run("scan", str(plaine)).exit_code == EXIT_ERROR
    isole = tmp_path / "isole.py"
    isole.write_text("x = 1\n", encoding="utf-8")
    assert _run("scan", str(isole)).exit_code == EXIT_ERROR


def test_scan_staged_with_unmerged_index_exits_two(git_repo: GitRepo) -> None:
    """Conflit de fusion : l'index ne correspond à aucun commit => 2."""
    git_repo.write("conflit.txt", "base\n")
    git_repo.stage("conflit.txt")
    git_repo.commit_all("base")
    git_repo.git("checkout", "-q", "-b", "branche-conflit")
    git_repo.write("conflit.txt", "autre\n")
    git_repo.stage("conflit.txt")
    git_repo.commit_all("autre")
    git_repo.git("checkout", "-q", "-")
    git_repo.write("conflit.txt", "moi\n")
    git_repo.stage("conflit.txt")
    git_repo.commit_all("moi")
    # La fusion entre en conflit : l'index est non résolu.
    assert git_repo.git_allow_failure("merge", "branche-conflit") != 0
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR


def test_scan_staged_rejects_oversized_blob(git_repo: GitRepo) -> None:
    """Un blob au-delà de la borne de lecture est une erreur (jamais 0)."""
    git_repo.write("gros.txt", "A" * (1024 * 1024 + 1))
    git_repo.stage("gros.txt")
    resultat = _run("scan", "--strict", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR


def test_scan_staged_caps_blob_bytes_before_buffering(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `blob_bytes` est lu en flux borné, jamais bufferisé entier.

    L'oracle `cat-file -s` annonce 1 octet alors que le blob réel dépasse
    1 Mio : `_read_capped` tue le processus au-delà de ``MAX_FILE_BYTES``
    et rend 2, sans attendre le contrôle `len(data) != size`.
    """
    git_repo.write("gros.txt", "A" * (MAX_FILE_BYTES + 1))
    git_repo.stage("gros.txt")

    def taille_mensongere(
        self: GitAccess, blob: str, **_options: object
    ) -> int:
        return 1

    monkeypatch.setattr(GitAccess, "blob_size", taille_mensongere)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_staged_refuses_a_binary_blob(git_repo: GitRepo) -> None:
    """Un blob binaire est refusé (code 2), comme un fichier binaire en arbre.

    Un secret placé dans un commentaire PNG/ZIP ne doit jamais produire un
    verdict propre : sans texte analysable, le blob est une erreur
    d'outillage, pas un skip silencieux.
    """
    git_repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("image.png", "app.py")
    resultat = _run("scan", "--strict", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_staged_skips_a_staged_gitlink(git_repo: GitRepo) -> None:
    """Revue (LOW) : un gitlink stagé (sous-module) ne fait pas échouer le scan.

    Le SHA indexé d'une entrée 160000 désigne un commit, pas un blob :
    aucun texte à scanner. Ignoré (documenté), pas une erreur — sinon tout
    `submodule add` sortirait en 2.
    """
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    head = git_repo.git_output("rev-parse", "HEAD").strip()
    git_repo.git("update-index", "--add", "--cacheinfo", f"160000,{head},sub")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN


def test_scan_staged_symlinked_root_exits_two(git_repo: GitRepo) -> None:
    """Revue (LOW) : racine symlinkée refusée en `--staged` comme en arbre.

    Parité avec `Scanner._resolve_root` : les deux périmètres disent la
    même chose sur la même entrée (code 2, jamais de scan de la cible).
    """
    git_repo.write("app.py", "x = 1\n")
    lien = git_repo.root.parent / "lien-29"
    lien.symlink_to(git_repo.root, target_is_directory=True)
    assert _run("scan", "--staged", str(lien)).exit_code == EXIT_ERROR
    assert _run("scan", str(lien)).exit_code == EXIT_ERROR


def test_scan_staged_gitlink_does_not_hide_other_secrets(git_repo: GitRepo) -> None:
    """Le gitlink est sauté, mais un secret voisin reste signalé."""
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    git_repo.commit_all("base")
    head = git_repo.git_output("rev-parse", "HEAD").strip()
    git_repo.git("update-index", "--add", "--cacheinfo", f"160000,{head},sub")
    git_repo.write("config.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("config.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "config.py:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_staged_polyglot_binary_header_is_fail_closed(git_repo: GitRepo) -> None:
    """T23 : faux PNG avec UTF-8 invalide -> erreur, jamais propre."""
    git_repo.write_bytes("faux.png", b"\x89PNG\r\n\x1a\n" + f'AWS = "{FAKE_AWS_KEY}"\n'.encode())
    git_repo.stage("faux.png")
    resultat = _run("scan", "--strict", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert FAKE_AWS_KEY not in resultat.output


@pytest.mark.parametrize("staged", [False, True])
def test_benign_minified_json_multiline_overflow_exits_two(git_repo: GitRepo, staged: bool) -> None:
    """T23 : le refus conservateur peut aussi bloquer un JSON bénin, sans secret."""
    line = json.dumps({"a": [0] * 2500}, separators=(",", ":"))
    git_repo.write("data.jsonl", line + "\n{}\n")
    git_repo.stage("data.jsonl")
    options = ("--staged",) if staged else ()
    resultat = _run("scan", "--strict", *options, str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert line not in resultat.output


@pytest.mark.parametrize("staged", [False, True])
@pytest.mark.parametrize(
    "wrapper",
    [
        "sha256-{}",
        "sha384-{}",
        "prefix-{}",
        "prefix.{}",
        "x{}",
        "x_{}",
        "x+{}",
        "x/{}",
        "{}-suffix",
    ],
)
def test_ci_scan_rejects_hex_secret_with_affixes(
    git_repo: GitRepo, staged: bool, wrapper: str
) -> None:
    """Le mode CI local ne doit jamais rendre propre un secret hex affixé."""
    value = hashlib.sha256(b"heimdall-t23-synthetic-only").hexdigest()
    git_repo.write("config.py", 'credential = "' + wrapper.format(value) + '"\n')
    git_repo.stage("config.py")
    options = ("--staged",) if staged else ()
    resultat = _run("scan", "--ci", *options, str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "high_entropy_hex" in resultat.output
    assert value not in resultat.output


def test_scan_staged_concurrent_index_change_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue #166 (LOW) : index modifié pendant le scan -> 2, jamais 0/1.

    Un ``git add`` concurrent après le snapshot ne figure pas dans la liste
    mais sera committé : le re-contrôle final refuse le verdict périmé.
    """
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    original = GitAccess.staged_changes
    appels = 0

    def snapshot_changeant(
        self: GitAccess, **_options: object
    ) -> list[StagedChange]:
        nonlocal appels
        appels += 1
        changes = original(self)
        if appels > 1:
            # Fichier ajouté après le snapshot : la liste finale diverge.
            return [*changes, StagedChange(path="concurrent.py", blob="e" * 40)]
        return changes

    monkeypatch.setattr(GitAccess, "staged_changes", snapshot_changeant)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_nested_file_mutation_between_walk_and_read_text(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : swap fichier imbriqué énumération->lecture : 0 vs 2 en staged.

    Fige le comportement documenté dans docs/cli.md :
    - En mode arbre : un fichier imbriqué nettoyé **en place** entre
      l'énumération et l'ouverture est relu tel quel ; le scan lit le contenu
      propre et rend 0 (best-effort non atomique assumé). Le parcours est ancré
      sur des descripteurs de répertoire : seul le contenu du fichier change,
      jamais le répertoire parcouru.
    - En `--staged` : l'index modifié après le snapshot refuse en code 2 (atomique).
    """
    nested = git_repo.root / "sub"
    nested.mkdir()
    target_file = nested / "app.py"
    target_file.write_text(f'AWS = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    git_repo.stage("sub/app.py")

    # 1. En mode arbre : substitution en place entre l'énumération et la lecture
    original_iter = TreeScanner._iter_files_at

    def iter_puis_nettoie(self: TreeScanner, dir_fd: int, prefix: str) -> Any:
        for rel, lecteur in original_iter(self, dir_fd, prefix):
            if rel == "sub/app.py":
                # Le fichier est nettoyé avant son ouverture par le lecteur.
                target_file.write_text("x = 1\n", encoding="utf-8")
            yield rel, lecteur

    monkeypatch.setattr(TreeScanner, "_iter_files_at", iter_puis_nettoie)
    resultat_tree = _run("scan", str(git_repo.root))
    assert resultat_tree.exit_code == EXIT_CLEAN

    # 2. En mode --staged : si l'index mute pendant le scan -> code 2
    original_staged = GitAccess.staged_changes
    tours = 0

    def staged_changeant(self: GitAccess, **options: Any) -> list[StagedChange]:
        nonlocal tours
        tours += 1
        res = original_staged(self, **options)
        if tours > 1:
            # Simulation d'index restagé pendant le scan
            return []
        return res

    monkeypatch.setattr(GitAccess, "staged_changes", staged_changeant)
    resultat_staged = _run("scan", "--staged", str(git_repo.root))
    assert resultat_staged.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat_staged.stderr


def test_scan_staged_accepts_a_reordered_second_enumeration(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : l'ordre de `diff --cached --raw` n'est pas contractuel.

    Une seconde énumération identique sur le fond mais permutée doit rendre
    le verdict normal (0), pas un faux 2 d'instabilité.
    """
    git_repo.write("a.py", "x = 1\n")
    git_repo.write("b.py", "y = 2\n")
    git_repo.stage("a.py", "b.py")
    original = GitAccess.staged_changes
    appels = 0

    def snapshot_permute(
        self: GitAccess, **options: object
    ) -> list[StagedChange]:
        nonlocal appels
        appels += 1
        changes = original(self, **options)
        return list(reversed(changes)) if appels > 1 else changes

    monkeypatch.setattr(GitAccess, "staged_changes", snapshot_permute)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN
    assert appels == 2


def test_scan_staged_root_swapped_mid_scan_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : racine échangée pendant le scan -> 2 (re-contrôle final).

    L'index de remplacement est IDENTIQUE (même blob) : le re-contrôle
    d'index passe, seul le re-contrôle racine refuse. Sans lui, ce serait 0
    sur un périmètre qui n'est plus celui demandé.
    """
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    evil = GitRepo("heimdall-t29-evil-")
    try:
        evil.write("app.py", "x = 1\n")
        evil.stage("app.py")
        original_octets = GitAccess.blob_bytes
        appels = 0

        def lit_puis_echange(
            self: GitAccess, blob: str, **_options: object
        ) -> bytes:
            nonlocal appels
            appels += 1
            data = original_octets(self, blob)
            if appels == 1:
                cache = git_repo.root.parent / "orig-29"
                git_repo.root.rename(cache)
                git_repo.root.symlink_to(evil.root, target_is_directory=True)
            return data

        monkeypatch.setattr(GitAccess, "blob_bytes", lit_puis_echange)
        resultat = _run("scan", "--staged", str(git_repo.root))
    finally:
        evil.close()
    assert appels == 1
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_staged_root_replaced_same_path_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : dossier remplacé à chemin identique -> 2 (identité).

    Le sosie porte un index IDENTIQUE (même blob) : le re-contrôle d'index
    passe, seul le re-contrôle d'identité (`st_dev`, `st_ino`) refuse. Sans
    lui, le résolu serait le même et ce serait 0 sur un périmètre échangé.
    """
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    sosie = git_repo.root.parent / "sosie-29"
    sosie.mkdir()
    (sosie / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(sosie, "init", "-q")
    _git(sosie, "add", "app.py")
    original_octets = GitAccess.blob_bytes
    appels = 0

    def lit_puis_remplace(
        self: GitAccess, blob: str, **_options: object
    ) -> bytes:
        nonlocal appels
        appels += 1
        data = original_octets(self, blob)
        if appels == 1:
            cache = git_repo.root.parent / "orig-29"
            git_repo.root.rename(cache)
            sosie.rename(git_repo.root)
        return data

    monkeypatch.setattr(GitAccess, "blob_bytes", lit_puis_remplace)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert appels == 1
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_root_swapped_mid_scan_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : idem en mode arbre — le re-contrôle final refuse.

    Sans re-contrôle, le verdict serait 0 (dépôt propre) sur un périmètre
    échangé après l'entrée. L'échange a lieu après l'analyse (sinon c'est
    le refus à l'usage, déjà couvert) : seule la reconstruction fraîche
    du re-contrôle lève, donc 2.
    """
    git_repo.write("app.py", "x = 1\n")
    original_scan = TreeScanner.scan
    echange = [False]

    def scan_puis_echange(
        self: TreeScanner, **options: object
    ) -> list[object]:
        trouvailles = original_scan(self, **options)
        if not echange[0]:
            echange[0] = True
            cache = git_repo.root.parent / "orig-29"
            git_repo.root.rename(cache)
            git_repo.root.symlink_to(cache, target_is_directory=True)
        return trouvailles

    monkeypatch.setattr(TreeScanner, "scan", scan_puis_echange)
    resultat = _run("scan", str(git_repo.root))
    assert echange[0]
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_root_replaced_same_path_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : idem en mode arbre — même chemin, autre dossier -> 2.

    Ici le sosie est un dossier vide quelconque : le résolu est identique,
    seule l'identité diffère. Sans le re-contrôle d'identité, le verdict
    serait 0 sur un périmètre mélangé.
    """
    git_repo.write("app.py", "x = 1\n")
    original_scan = TreeScanner.scan
    echange = [False]

    def scan_puis_remplace(
        self: TreeScanner, **options: object
    ) -> list[object]:
        trouvailles = original_scan(self, **options)
        if not echange[0]:
            echange[0] = True
            cache = git_repo.root.parent / "orig-29"
            git_repo.root.rename(cache)
            git_repo.root.mkdir()
        return trouvailles

    monkeypatch.setattr(TreeScanner, "scan", scan_puis_remplace)
    resultat = _run("scan", str(git_repo.root))
    assert echange[0]
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_recycled_inode_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un dossier neuf qui réobtient (dev, ino) -> 2.

    `rm -rf` puis `mkdir` peut réattribuer le même inode (ext4) : sans ctime,
    le re-contrôle croirait au même dossier. Simulé par `os.stat` : même
    (dev, ino) pour la racine, ctime postérieur (celui du dossier neuf).
    """
    git_repo.write("app.py", "x = 1\n")
    racine = git_repo.root.resolve()
    stat_reel = os.stat
    recyclage = [False]

    def stat_recycle(path: object, *args: object, **options: object) -> object:
        resultat = stat_reel(path, *args, **options)
        if recyclage[0] and Path(str(path)) == racine:
            return SimpleNamespace(
                st_dev=resultat.st_dev,
                st_ino=resultat.st_ino,
                st_ctime_ns=resultat.st_ctime_ns + 1,
            )
        return resultat

    original_scan = TreeScanner.scan

    def scan_puis_recycle(self: TreeScanner, **options: object) -> list[object]:
        trouvailles = original_scan(self, **options)
        recyclage[0] = True
        return trouvailles

    monkeypatch.setattr(TreeScanner, "scan", scan_puis_recycle)
    monkeypatch.setattr(os, "stat", stat_recycle)
    resultat = _run("scan", str(git_repo.root))
    assert recyclage[0]
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def _instantane(racine: Path) -> dict[str, bytes | None]:
    """Chemins et contenus sous `racine` (répertoires à `None`), `.git` compris."""
    return {
        chemin.relative_to(racine).as_posix(): (chemin.read_bytes() if chemin.is_file() else None)
        for chemin in sorted(racine.rglob("*"))
    }


@pytest.mark.parametrize("arguments", [[], ["--staged"]], ids=["arbre", "index"])
def test_scan_never_reads_or_writes_a_hostile_repository_config(
    git_repo: GitRepo, arguments: list[str]
) -> None:
    """Revue (LOW) : `.config/git/` piégé dans le dépôt n'influe pas le scan.

    Le dépôt tente de se masquer (`ignore`) et de fausser le diff (`-diff`).
    Le scan ne crée ni ne modifie rien dans la racine (instantané identique,
    `.git` compris), et le secret reste signalé : verdict 1.
    """
    git_repo.write("secret.txt", f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.write(".config/git/ignore", "secret.txt\n")
    git_repo.write(".config/git/attributes", "* -diff\n")
    git_repo.stage("secret.txt")
    avant = _instantane(git_repo.root)
    resultat = _run("scan", *arguments, str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "secret.txt:1" in resultat.stdout
    assert _instantane(git_repo.root) == avant


def test_scan_unresolvable_toplevel_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un top que `resolve()` ne sait pas lire -> 2, message statique.

    Le contrat `is_repository` reste un bool ou une `ToolFailure` : l'exception
    brute ne doit jamais sortir (le `except Exception` de la CLI la masquerait
    en code 2 sans rien prouver). Le test unitaire, lui, distingue les deux.
    """
    git_repo.write("app.py", "x = 1\n")
    boucle = git_repo.root.parent / "boucle-29"
    execute_reel = GitAccess.execute
    resolve_reel = Path.resolve

    def execute_boucle(self: GitAccess, arguments: object, **options: object) -> object:
        if tuple(arguments) == ("rev-parse", "--show-toplevel"):
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=f"{boucle}\n".encode(), stderr=b""
            )
        return execute_reel(self, arguments, **options)

    def resolve_boucle(self: Path, *args: object, **options: object) -> Path:
        if self == boucle:
            raise RuntimeError("Symlink loop")
        return resolve_reel(self, *args, **options)

    monkeypatch.setattr(GitAccess, "execute", execute_boucle)
    monkeypatch.setattr(Path, "resolve", resolve_boucle)
    resultat = _run("scan", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_git_binary_or_cwd_resolve_error_exits_two(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : resolve() du binaire git ou cwd qui échoue -> 2 garanti.

    Dans `GitAccess.__init__`, l'échec de résolution de git ou de cwd est
    mappé en ToolFailure("INTERNAL"), ce qui donne code 2 et message statique.
    """
    git_repo.write("app.py", "x = 1\n")
    resolve_reel = Path.resolve

    def resolve_piege(self: Path, *args: object, **options: object) -> Path:
        if self.name.startswith("git"):
            raise RuntimeError("Symlink loop")
        return resolve_reel(self, *args, **options)

    monkeypatch.setattr(Path, "resolve", resolve_piege)
    resultat = _run("scan", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


@pytest.mark.parametrize(
    ("caractere", "echappe"),
    [("\u202e", "\\u202e"), ("\u200f", "\\u200f"), ("\u2066", "\\u2066")],
    ids=["rlo", "rlm", "lri"],
)
@pytest.mark.parametrize("arguments", [[], ["--staged"]], ids=["arbre", "index"])
def test_scan_shows_bidi_paths_escaped_never_raw(
    git_repo: GitRepo, arguments: list[str], caractere: str, echappe: str
) -> None:
    """Revue (LOW) : un nom à contrôle bidi ne s'affiche jamais brut.

    Affiché brut, U+202E inverse l'ordre visuel du chemin et fait croire que le
    secret est dans un autre fichier. Le contrat autorise ces noms : le scan
    les analyse et les rend échappés. Le caractère brut n'apparaît ni dans
    stdout ni dans stderr, dans les deux périmètres.
    """
    chemin = f"vendor/evil{caractere}gp.yvne"
    git_repo.write(chemin, f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.stage(chemin)
    resultat = _run("scan", *arguments, str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert caractere not in resultat.output
    assert f"vendor/evil{echappe}gp.yvne:1" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


def test_verify_root_unchanged_refuses_divergent_resolution(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le re-contrôle compare, pas seulement construit : divergence -> 2."""
    access = GitAccess(git_repo.root)
    ailleurs = git_repo.root.parent / "ailleurs-29"
    monkeypatch.setattr(
        "heimdall.cli.scan.GitAccess", lambda racine: SimpleNamespace(root=ailleurs)
    )
    with pytest.raises(ScanError):
        _verify_root_unchanged(access, git_repo.root)


def test_scan_staged_refuses_too_many_files(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Au-delà du plafond de fichiers, le scan est **refusé** (jamais tronqué)."""
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_FILES", 1)
    git_repo.write("a.py", "x = 1\n")
    git_repo.write("b.py", "y = 2\n")
    git_repo.stage("a.py", "b.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR


def test_scan_staged_refuses_too_many_bytes(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le volume total des blobs relus reste borné (refus, jamais tronqué)."""
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_BYTES", 1)
    git_repo.write("a.py", "x = 1\n")
    git_repo.stage("a.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_staged_refuses_global_deadline(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : une deadline globale borne les lectures séquentielles.

    Sans elle, 1 000 blobs × 2 `git cat-file` pouvaient enchaîner 2 000
    processus avant verdict. Deadline déjà expirée -> refus 2, pas de scan.
    """
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_SECONDS", -1.0)
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_staged_checks_deadline_before_the_final_enumeration(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : la deadline couvre aussi la seconde énumération.

    L'horloge expire juste après le blob : le re-contrôle d'index ne doit
    pas être lancé (30 s de timeout unitaire en plus de la deadline), et le
    scan refuse en 2 sans verdict.
    """
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")
    original_changes = GitAccess.staged_changes
    appels: list[dict[str, object]] = []

    def changes_espion(self: GitAccess, **options: object) -> list[StagedChange]:
        appels.append(options)
        return original_changes(self, **options)

    clock = [0.0]
    monkeypatch.setattr("heimdall.cli.scan.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(GitAccess, "staged_changes", changes_espion)
    original_bytes = GitAccess.blob_bytes

    def bytes_puis_expire(
        self: GitAccess, blob: str, **options: object
    ) -> bytes:
        data = original_bytes(self, blob, **options)
        clock[0] = 121.0  # deadline = 120, expirée après le blob
        return data

    monkeypatch.setattr(GitAccess, "blob_bytes", bytes_puis_expire)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE
    assert len(appels) == 1


def test_scan_staged_refuses_blob_size_mismatch(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : taille annoncée != taille relue -> 2, jamais de scan.

    Le blob porte un secret et l'oracle (`cat-file -s`) l'annonce un octet
    trop court : le contenu relu dépasse la taille annoncée. Sans
    re-contrôle après lecture, ce surplus serait scanné et le verdict
    serait 1 ; le re-contrôle refuse avant tout décodage.
    """
    git_repo.write("config.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("config.py")
    original_taille = GitAccess.blob_size

    def taille_mensongere(
        self: GitAccess, blob: str, **_options: object
    ) -> int:
        return original_taille(self, blob) - 1

    monkeypatch.setattr(GitAccess, "blob_size", taille_mensongere)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE
    assert FAKE_AWS_KEY not in resultat.output


def test_scan_staged_refuses_negative_blob_size(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : une taille négative simulée -> 2, `total` ne recule pas."""
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("app.py")

    def taille_negative(
        self: GitAccess, blob: str, **_options: object
    ) -> int:
        return -1

    monkeypatch.setattr(GitAccess, "blob_size", taille_negative)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_blob_size_refuses_negative_git_output(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : `blob_size` refuse une sortie git négative.

    La garde vit dans `GitAccess` (bibliothèque), pas seulement dans la CLI.
    """
    access = GitAccess(git_repo.root)

    def read_negatif(
        self: GitAccess,
        arguments: object,
        max_bytes: int,
        **_options: object,
    ) -> bytes:
        return b"-1\n"

    monkeypatch.setattr(GitAccess, "_read_capped", read_negatif)
    with pytest.raises(ToolFailure):
        access.blob_size("a" * 40)


def test_blob_size_accepts_empty_blob(git_repo: GitRepo) -> None:
    """Revue (LOW) : un blob vide (taille 0) reste valide et ne fait pas 2.

    Le plancher refuse le négatif, pas zéro : un blob vide ne porte aucun
    candidat et le scan rend un verdict propre.
    """
    git_repo.write("vide.py", "")
    git_repo.stage("vide.py")
    access = GitAccess(git_repo.root)
    changes = access.staged_changes()
    assert len(changes) == 1
    assert access.blob_size(changes[0].blob) == 0
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN


def test_scan_staged_raw_output_capped(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : le flux d'énumération est coupé avant d'être bufferisé.

    Plafond ridicule (50 octets) pour 2 fichiers (~200 octets de sortie) :
    le sous-processus est tué et c'est 2, sans jamais parser la sortie.
    Sans ce flux borné, un index de 100 000 entrées serait bufferisé en
    entier avant le contrôle du nombre de fichiers.
    """
    monkeypatch.setattr("heimdall.mcp.gitdiff.MAX_STAGED_RAW_BYTES", 50)
    git_repo.write("a.py", "x = 1\n")
    git_repo.write("b.py", "y = 2\n")
    git_repo.stage("a.py", "b.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_staged_many_entries_refuses(git_repo: GitRepo) -> None:
    """Revue (LOW) : 1 100 entrées stagées -> 2 (compteur, sortie < 8 Mio).

    La sortie brute (~120 Kio) tient sous le plafond de flux : c'est le
    contrôle du nombre de fichiers qui refuse, après parse complet.
    """
    for i in range(1100):
        git_repo.write(f"f{i:04d}.py", "x = 1\n")
    git_repo.git("add", "-A")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_staged_refuses_too_many_findings(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : rafale de candidats -> refus 2, jamais de rapport tronqué.

    Les bornes d'entrée ne suffisent pas : des blobs denses en candidats
    feraient gonfler la liste et le tri final. Au-delà du plafond, refus.
    """
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_FINDINGS", 1)
    git_repo.write("a.py", f'A = "{FAKE_AWS_KEY}"\n')
    git_repo.write("b.py", f'B = "{FAKE_AWS_KEY}"\n')
    git_repo.stage("a.py", "b.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_refuses_too_many_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Idem en mode arbre : le compteur coupe fail-fast pendant la boucle."""
    monkeypatch.setattr("heimdall.scanner.detect.MAX_FINDINGS", 1)
    racine = _arbre(
        tmp_path,
        {"a.py": f'A = "{FAKE_AWS_KEY}"\n', "b.py": f'B = "{FAKE_AWS_KEY}"\n'},
    )
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_scan_tree_dense_single_file_refuses_fast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un seul fichier dense coupe fail-fast, sans tout hacher.

    300 candidats sur une seule ligne pour un plafond à 100 : le compteur
    `_append` refuse au 101e hachage. L'ancien contrôle (après `extend`)
    aurait haché les 300 puis trié avant de refuser.
    """
    monkeypatch.setattr("heimdall.scanner.detect.MAX_FINDINGS", 100)
    racine = _arbre(tmp_path, {"dense.py": _cles_denses(300) + "\n"})
    compteur = _HasherCompteur()
    with pytest.raises(ScanError):
        TreeScanner(racine, hasher=compteur).scan()
    assert compteur.compte == 101


def test_signature_engine_stops_at_cap() -> None:
    """Même compteur côté moteur `--staged` : refus au 6e candidat (plafond 5)."""
    compteur = _HasherCompteur()
    moteur = SignatureEngine(hasher=compteur, max_findings=5)
    cible = FileTarget(path="dense.py", text=_cles_denses(50) + "\n")
    with pytest.raises(ScanError):
        moteur.analyser(cible)
    assert compteur.compte == 6


def test_signature_engine_bounded_by_default() -> None:
    """Revue (LOW) : `SignatureEngine()` et `max_findings=None` sont bornés.

    Le défaut est le plafond partagé : un appelant qui analyserait un blob
    dense sans renseigner `max_findings` refuse au-delà de 10 000 au lieu
    d'accumuler sans borne. `None` explicite ne rouvre **pas** l'ancien
    mode non borné : il retombe sur ce même défaut, comme `Scanner`.
    """
    charge = FileTarget(path="dense.py", text=_cles_denses(11_000) + "\n")
    for moteur in (
        SignatureEngine(hasher=_HasherCompteur()),
        SignatureEngine(hasher=_HasherCompteur(), max_findings=None),
    ):
        with pytest.raises(ScanError):
            moteur.analyser(charge)


@pytest.mark.parametrize("valeur", [0, -1, 10**12])
def test_signature_engine_refuses_invalid_explicit_cap(valeur: int) -> None:
    """Revue (LOW) : un plafond explicite hors `1..MAX_FINDINGS` est refusé."""
    with pytest.raises(ValueError):
        SignatureEngine(max_findings=valeur)


def test_scan_staged_dense_blob_refuses(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un seul blob dense en `--staged` -> 2 (le moteur coupe, pas la boucle)."""
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_FINDINGS", 10)
    git_repo.write("dense.py", _cles_denses(50) + "\n")
    git_repo.stage("dense.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


def test_signature_engine_checks_deadline_inside_one_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : la deadline est vue **dans** une cible, pas seulement entre cibles.

    L'horloge n'expire qu'au second contrôle : une cible de 600 lignes vides
    (contrôle tous les 256 lignes) doit être refusée pendant la boucle.
    """
    appels = [0]

    def monotonic() -> float:
        appels[0] += 1
        return 0.0 if appels[0] == 1 else 2.0

    monkeypatch.setattr("heimdall.scanner.signature_engine.time.monotonic", monotonic)
    moteur = SignatureEngine(max_findings=10, deadline=1.0)
    with pytest.raises(ScanError):
        moteur.analyser(FileTarget(path="vide.py", text="\n" * 600))
    assert appels[0] >= 2


def test_signature_engine_deadline_refuses_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : sur un blob dense, le refus précède le HMAC du premier candidat.

    Même motif que le test arbre `test_scan_text_checks_deadline_intra_file` :
    le compteur de hachages doit rester à zéro quand la deadline expire.
    """
    appels = [0]

    def monotonic() -> float:
        appels[0] += 1
        return 0.0 if appels[0] == 1 else 2.0

    monkeypatch.setattr("heimdall.scanner.signature_engine.time.monotonic", monotonic)
    compteur = _HasherCompteur()
    moteur = SignatureEngine(hasher=compteur, max_findings=10_000, deadline=1.0)
    with pytest.raises(ScanError):
        moteur.analyser(FileTarget(path="dense.py", text=_cles_denses(300) + "\n"))
    assert compteur.compte == 0


def test_scan_staged_dense_blob_stops_at_the_deadline_inside_the_blob(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : un blob `--staged` dense n'échappe pas à la deadline globale.

    1 Mio de lignes dont 9 000 candidats (sous le plafond de 10 000, donc aucun
    refus par compteur) : le moteur met plusieurs secondes, la deadline 1,5 s.
    Sans contrôle intra-blob, le moteur rend son résultat après l'échéance et
    seule la relecture finale refuse. Preuve : c'est le moteur qui lève, à
    l'intérieur du blob.
    """
    monkeypatch.setattr("heimdall.cli.scan.MAX_STAGED_SECONDS", 1.5)
    corps = f'K = "{FAKE_AWS_KEY}"\n' * 9000
    corps += "\n" * (MAX_FILE_BYTES - len(corps))
    git_repo.write("dense.py", corps)
    git_repo.stage("dense.py")
    levees: list[ScanError] = []
    analyser_reel = SignatureEngine.analyser

    def analyser_espion(self: SignatureEngine, cible: object) -> object:
        try:
            return analyser_reel(self, cible)
        except ScanError as exc:
            levees.append(exc)
            raise

    monkeypatch.setattr(SignatureEngine, "analyser", analyser_espion)
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR
    assert len(levees) == 1
    assert FAKE_AWS_KEY not in resultat.output


def test_blob_access_refuses_a_name_that_is_not_a_sha(git_repo: GitRepo) -> None:
    """Un nom d'objet qui n'est pas un SHA est refusé avant l'argv.

    Sans cette garde, une chaîne venue d'une sortie git pourrait être
    interprétée comme une option par git (``--upload-pack=…``).
    """
    access = GitAccess(git_repo.root)
    for invalide in ("--upload-pack=touch /tmp/x", "zz" * 20, ""):
        with pytest.raises(ToolFailure):
            access.blob_size(invalide)
        with pytest.raises(ToolFailure):
            access.blob_bytes(invalide)


# --- sortie JSON et mode CI ------------------------------------------------


def test_scan_json_output_follows_the_contract(tmp_path: Path) -> None:
    """``--json`` rend le document ``heimdall.scan.v1``."""
    racine = _arbre(tmp_path, {"config.py": f'AWS = "{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", "--json", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    document = json.loads(resultat.stdout)
    assert document["schema"] == JSON_SCHEMA
    assert document["scope"] == "working-tree"
    assert document["count"] == 1
    finding = document["findings"][0]
    # Les sept champs du contrat Finding v1 (#14).
    assert set(finding) == {
        "file",
        "line",
        "type",
        "entropy",
        "snippet_hash",
        "status",
        "source",
    }
    assert finding["file"] == "config.py"
    assert finding["line"] == 1
    assert finding["status"] == "detecte"
    assert finding["source"] == "regex"
    # Jamais la valeur du secret.
    assert FAKE_AWS_KEY not in resultat.stdout


def test_scan_json_output_on_a_clean_repository(tmp_path: Path) -> None:
    """Un dépôt propre rend un document JSON valide, sans finding."""
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--json", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    document = json.loads(resultat.stdout)
    assert document["count"] == 0
    assert document["findings"] == []


def test_scan_schema_is_a_valid_draft_2020_12_schema() -> None:
    """Revue (LOW) : `schemas/scan.schema.json` est un schéma 2020-12 valide."""
    assert SCAN_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCAN_SCHEMA)


def test_scan_json_output_validates_against_the_schema(tmp_path: Path) -> None:
    """Revue (LOW) : la sortie `--json` est valide contre son schéma.

    Champs exacts, `count` cohérent avec `findings`, et aucun NaN : le
    document est relu en refusant les constantes non finies (`allow_nan`
    refusé, figé ici sur la sortie réelle). La résolution passe par les
    `$id` déclarés et le filesystem, pas par un registre câblé.
    """
    racine = _arbre(tmp_path, {"config.py": f'AWS = "{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", "--json", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    document = json.loads(resultat.stdout, parse_constant=_refuse_non_finite)
    _scan_validator().validate(document)
    _scan_validator_from_filesystem().validate(document)
    assert SCAN_SCHEMA["$id"] == "https://github.com/Cezar277/heimdall/schemas/scan.schema.json"
    assert FINDING_SCHEMA["$id"] == (
        "https://github.com/Cezar277/heimdall/schemas/finding.schema.json"
    )
    assert document["count"] == len(document["findings"]) == 1
    assert set(document) == {
        "complete",
        "skipped",
        "skipped_count",
        "schema",
        "scope",
        "count",
        "findings",
        "ignored_count",
        "traces",
        "config_hash",
        "vcs_ignored",
        "git_ignored",
    }


def test_scan_schema_refuses_invalid_documents() -> None:
    """Le schéma fige le contrat : valeur, enum, fermeture et items Finding."""
    validator = _scan_validator()
    # #229 : complete est requis ; un ancien document sans complete est refusé.
    legacy_base = {
        "schema": "heimdall.scan.v1",
        "scope": "staged",
        "count": 0,
        "findings": [],
    }
    assert not validator.is_valid(legacy_base)
    base = {
        "schema": "heimdall.scan.v1",
        "scope": "staged",
        "count": 0,
        "findings": [],
        "complete": True,
        "skipped_count": 0,
        "skipped": [],
        "ignored_count": 0,
        "traces": [],
        "config_hash": None,
        "vcs_ignored": 0,
        "git_ignored": 0,
    }
    assert validator.is_valid(base)
    partial = dict(
        base,
        complete=False,
        skipped_count=1,
        skipped=[{"file": "image.png", "reason": "binary", "line": None}],
    )
    assert validator.is_valid(partial)
    for invalide in (
        dict(base, complete=False),
        dict(base, complete=False, skipped_count=1, skipped=[]),
        dict(
            base,
            complete=False,
            skipped_count=0,
            skipped=[{"file": "image.png", "reason": "binary", "line": None}],
        ),
        dict(base, schema="heimdall.scan.v2"),
        dict(base, scope="historique"),
        dict(base, count="1"),
        dict(base, count=-1),
        dict(base, findings=[{"file": "x.py"}]),  # Finding incomplet
        dict(base, extra=True),  # contrat fermé
        dict(base, vcs_ignored=-1),
        dict(base, vcs_ignored="1"),
        dict(base, git_ignored=-1),
        dict(base, git_ignored="1"),
    ):
        assert not validator.is_valid(invalide), invalide
    # `count` cohérent avec `findings` : inexprimable en JSON Schema pur,
    # vérifié côté test (`test_scan_json_output_validates_against_the_schema`).
    assert base["count"] == len(base["findings"])


def test_scan_count_mismatch_is_refused_by_the_recommended_validator(
    tmp_path: Path,
) -> None:
    """Revue (LOW) : le schéma seul laisse passer un `count` incohérent.

    Le helper recommandé aux parseurs valide le schéma puis refuse
    `count != len(findings)` ; ce test fige les deux étages.
    """
    racine = _arbre(tmp_path, {"config.py": f'AWS = "{FAKE_AWS_KEY}"\n'})
    document = json.loads(_run("scan", "--json", str(racine)).stdout)
    _validate_scan_document(document)
    document["count"] = 0
    assert _scan_validator().is_valid(document)
    with pytest.raises(ValueError):
        _validate_scan_document(document)


def test_scan_ci_summarises_on_stderr(tmp_path: Path) -> None:
    """``--ci`` : verdict porté par le code de sortie, résumé sur stderr."""
    racine = _arbre(tmp_path, {"config.py": f'AWS = "{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", "--ci", str(racine))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in resultat.stderr
    assert FAKE_AWS_KEY not in resultat.stderr


def test_scan_ci_on_a_clean_repository_exits_zero(tmp_path: Path) -> None:
    """``--ci`` sur un dépôt propre => 0."""
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--ci", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    assert "1 fichier(s) analysé(s)" in resultat.stderr
    assert "0 secret(s) détecté(s)" in resultat.stderr


def test_scan_ci_creates_the_local_key_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : la seule écriture est la clé HMAC hors dépôt.

    Un premier scan sur un HOME/XDG inscriptible crée
    ``$XDG_DATA_HOME/heimdall/snippet-hmac.key`` en 0600, jamais dans le
    dépôt scanné.
    """
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY", raising=False)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--ci", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    key_path = xdg / "heimdall" / "snippet-hmac.key"
    assert key_path.is_file()
    assert not (racine / "snippet-hmac.key").exists()


def test_scan_ci_fails_closed_when_the_local_key_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revue (LOW) : HOME/XDG en lecture seule -> 2, jamais un 0 silencieux."""
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY", raising=False)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)
    blocked = tmp_path / "xdg-bloque"
    blocked.write_text("pas un répertoire", encoding="utf-8")
    monkeypatch.setenv("XDG_DATA_HOME", str(blocked))
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--ci", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert resultat.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_ci_json_staged_combines(git_repo: GitRepo) -> None:
    """Revue #166 : ``--ci --json --staged`` combinés.

    stdout doit rester un document JSON **parseable** (rien d'autre), le
    résumé déterministe va sur stderr, et le code de sortie porte le verdict.
    """
    git_repo.write("vendor/evil.py", f'KEY = "{FAKE_AWS_KEY}"\n')
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("vendor/evil.py", "app.py")
    resultat = _run("scan", "--ci", "--json", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    document = json.loads(resultat.stdout)
    assert document["schema"] == JSON_SCHEMA
    assert document["scope"] == "staged"
    assert document["count"] == 1
    assert document["findings"][0]["file"] == "vendor/evil.py"
    assert "2 fichier(s) analysé(s)" in resultat.stderr
    assert "1 secret(s) détecté(s)" in resultat.stderr
    assert FAKE_AWS_KEY not in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.stderr


def test_scan_ci_json_diff_matches_the_schema(git_repo: GitRepo) -> None:
    """Le document ``--json --diff`` valide le contrat ``heimdall.scan.v1`` (#37)."""
    git_repo.write("app.py", "x = 1\n")
    git_repo.commit_all("base")
    git_repo.git("branch", "-M", "main")
    git_repo.git("update-ref", "refs/remotes/origin/main", "main")
    git_repo.git("checkout", "-q", "-b", "feature")
    git_repo.write("new.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    git_repo.commit_all("feature")

    resultat = _run(
        "scan",
        "--ci",
        "--json",
        "--diff",
        "origin/main",
        "--no-allowlist",
        str(git_repo.root),
    )

    assert resultat.exit_code == EXIT_FINDINGS
    document = json.loads(resultat.stdout)
    _validate_scan_document(document)
    assert document["scope"] == "diff"
    assert document["count"] == 1
    assert FAKE_AWS_KEY not in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.stderr


# --- lecture de l'index : analyse de la sortie « raw » ----------------------


def test_parse_staged_raw_reads_added_and_modified() -> None:
    """En-tête ``raw`` : mode, SHA source, SHA indexé, statut, chemin."""
    brut = (
        b":000000 100644 0000000 " + b"a" * 40 + b" A\x00vendor/evil.py\x00"
        b":100644 100644 " + b"b" * 40 + b" " + b"c" * 40 + b" M\x00config.py\x00"
        b":100644 100644 " + b"d" * 40 + b" " + b"0" * 40 + b" D\x00old.py\x00"
    )
    changements = parse_staged_raw(brut)
    assert [(c.path, c.blob) for c in changements] == [
        ("vendor/evil.py", "a" * 40),
        ("config.py", "c" * 40),
    ]


def test_parse_staged_raw_accepts_sha256_objects() -> None:
    """Revue #166 (LOW) : un dépôt SHA-256 utilise des noms de 64 hexa."""
    brut = b":000000 100644 " + b"0" * 64 + b" " + b"a" * 64 + b" A\x00vendor/x.py\x00"
    changements = parse_staged_raw(brut)
    assert [(c.path, c.blob) for c in changements] == [("vendor/x.py", "a" * 64)]


def test_parse_staged_raw_skips_gitlinks() -> None:
    """Revue (LOW) : un mode 160000 (sous-module) n'a aucun blob à scanner.

    Le SHA indexé désigne un commit, pas un blob : ignoré. En revanche, un
    passage gitlink → fichier (`T` vers 100644) porte un vrai blob et reste
    scanné.
    """
    brut = (
        b":000000 160000 " + b"0" * 40 + b" " + b"a" * 40 + b" A\x00sub\x00"
        b":160000 100644 " + b"c" * 40 + b" " + b"d" * 40 + b" T\x00converti.py\x00"
        b":000000 100644 0000000 " + b"b" * 40 + b" A\x00app.py\x00"
    )
    changements = parse_staged_raw(brut)
    assert [(c.path, c.blob) for c in changements] == [
        ("converti.py", "d" * 40),
        ("app.py", "b" * 40),
    ]


@pytest.mark.parametrize(
    "brut",
    [
        b"",  # sortie vide : aucun changement, pas une panne
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00",  # chemin manquant
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00x.py\x00:y.py\x00",  # impairs
        b":100644 100644 0000000 " + b"a" * 40 + b" U\x00conflit.py\x00",  # index non résolu
        b":100644 100644 0000000 " + b"a" * 40 + b" R100\x00a.py\x00b.py\x00",  # renommage
        b":100644 100644 0000000 pas-un-sha A\x00x.py\x00",  # SHA invalide
        b":100644 100644 0000000 " + b"a" * 43 + b" A\x00x.py\x00",  # ni 40 ni 64
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00../evasion.py\x00",  # traversée
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00d/" * 2100 + b"f.py\x00",  # > 4096
        b"pas-un-en-tete\x00x.py\x00",  # en-tête illisible
    ],
)
def test_parse_staged_raw_refuses_unreadable_output(brut: bytes) -> None:
    """Une sortie illisible est une panne : jamais une liste partielle."""
    if not brut:
        assert parse_staged_raw(brut) == []
        return
    with pytest.raises(ToolFailure):
        parse_staged_raw(brut)
