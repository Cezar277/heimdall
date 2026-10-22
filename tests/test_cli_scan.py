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

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

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
    _verify_root_unchanged,
)
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess, StagedChange, parse_staged_raw
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
        def __init__(self, root: Path, *, strict: bool) -> None:
            seen.append((Path(root), strict))

        def scan(self) -> list[object]:
            return []

    monkeypatch.setattr("heimdall.cli.scan.TreeScanner", ScannerEspion)
    racine = git_repo.root / ".." / git_repo.root.name
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_CLEAN
    assert seen == [(git_repo.root.resolve(), True)]


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


def test_scan_tree_keeps_technical_exclusions(tmp_path: Path) -> None:
    """Les exclusions **techniques** restent (binaire, répertoire généré)."""
    racine = _arbre(tmp_path, {"node_modules/pkg/evil.js": f'"{FAKE_AWS_KEY}"\n'})
    resultat = _run("scan", str(racine))
    assert resultat.exit_code == EXIT_CLEAN


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
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_ERROR


def test_scan_staged_skips_a_binary_blob(git_repo: GitRepo) -> None:
    """Un blob binaire n'a rien à analyser : il est ignoré, pas une erreur."""
    git_repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)
    git_repo.write("app.py", "x = 1\n")
    git_repo.stage("image.png", "app.py")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_CLEAN


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


def test_scan_staged_polyglot_binary_header_is_scanned(git_repo: GitRepo) -> None:
    """Revue #166 : en-tête binaire + texte clair (sans NUL) -> **scanné**.

    ``decode_text`` ne saute un blob que sur signature binaire **et**
    contenu majoritairement binaire : un faux PNG qui porte un secret en
    clair est analysé, pas ignoré en silence.
    """
    git_repo.write_bytes(
        "faux.png", b"\x89PNG\r\n\x1a\n" + f'AWS = "{FAKE_AWS_KEY}"\n'.encode()
    )
    git_repo.stage("faux.png")
    resultat = _run("scan", "--staged", str(git_repo.root))
    assert resultat.exit_code == EXIT_FINDINGS
    assert "faux.png:" in resultat.stdout
    assert FAKE_AWS_KEY not in resultat.output


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

    def snapshot_changeant(self: GitAccess) -> list[StagedChange]:
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

        def lit_puis_echange(self: GitAccess, blob: str) -> bytes:
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

    def lit_puis_remplace(self: GitAccess, blob: str) -> bytes:
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

    def scan_puis_echange(self: TreeScanner) -> list[object]:
        trouvailles = original_scan(self)
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

    def scan_puis_remplace(self: TreeScanner) -> list[object]:
        trouvailles = original_scan(self)
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

    def taille_mensongere(self: GitAccess, blob: str) -> int:
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

    def taille_negative(self: GitAccess, blob: str) -> int:
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

    def execute_negatif(self: GitAccess, arguments: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"-1\n")

    monkeypatch.setattr(GitAccess, "execute", execute_negatif)
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
    assert set(document) == {"schema", "scope", "count", "findings"}


def test_scan_schema_refuses_invalid_documents() -> None:
    """Le schéma fige le contrat : valeur, enum, fermeture et items Finding."""
    validator = _scan_validator()
    base = {"schema": "heimdall.scan.v1", "scope": "staged", "count": 0, "findings": []}
    assert validator.is_valid(base)
    for invalide in (
        dict(base, schema="heimdall.scan.v2"),
        dict(base, scope="historique"),
        dict(base, count="1"),
        dict(base, count=-1),
        dict(base, findings=[{"file": "x.py"}]),  # Finding incomplet
        dict(base, extra=True),  # contrat fermé
    ):
        assert not validator.is_valid(invalide), invalide
    # `count` cohérent avec `findings` : inexprimable en JSON Schema pur,
    # vérifié côté test (`test_scan_json_output_validates_against_the_schema`).
    assert base["count"] == len(base["findings"])


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
    assert "0 secret(s) détecté(s)" in resultat.stderr


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
    assert "1 secret(s) détecté(s)" in resultat.stderr
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
