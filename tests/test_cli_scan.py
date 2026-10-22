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
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.cli.scan import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, JSON_SCHEMA
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess, parse_staged_raw

#: Exemple de clé AWS (documentation AWS) : jamais une clé fonctionnelle.
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

#: Clé HMAC locale de test : empreinte déterministe, aucun fichier créé.
TEST_HMAC_KEY = "00" * 32


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


def _arbre(tmp_path: Path, contenu: dict[str, str]) -> Path:
    """Écrit un petit dépôt (hors dépôt Heimdall) et rend sa racine."""
    racine = tmp_path / "repo"
    racine.mkdir()
    for relatif, texte in contenu.items():
        chemin = racine / relatif
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text(texte, encoding="utf-8")
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
    assert "scan impossible" in resultat.stderr
    # L'entrée refusée n'est jamais reflétée (invariant 8).
    assert "absent-29" not in resultat.output


def test_scan_does_not_write_anything(tmp_path: Path) -> None:
    """Un scan n'écrit rien : ni dans le dépôt, ni à côté."""
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    avant = sorted(p.name for p in tmp_path.iterdir())
    assert _run("scan", str(racine)).exit_code == EXIT_CLEAN
    assert sorted(p.name for p in tmp_path.iterdir()) == avant


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
    racine = _arbre(tmp_path, {"app.py": "x = 1\n"})
    resultat = _run("scan", "--staged", str(racine))
    assert resultat.exit_code == EXIT_ERROR
    assert "scan impossible" in resultat.stderr


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


@pytest.mark.parametrize(
    "brut",
    [
        b"",  # sortie vide : aucun changement, pas une panne
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00",  # chemin manquant
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00x.py\x00:y.py\x00",  # impairs
        b":100644 100644 0000000 " + b"a" * 40 + b" U\x00conflit.py\x00",  # index non résolu
        b":100644 100644 0000000 " + b"a" * 40 + b" R100\x00a.py\x00b.py\x00",  # renommage
        b":100644 100644 0000000 pas-un-sha A\x00x.py\x00",  # SHA invalide
        b":100644 100644 0000000 " + b"a" * 40 + b" A\x00../evasion.py\x00",  # traversée
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
