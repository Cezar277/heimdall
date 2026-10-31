"""Exclusions Git **sûres** du scanner (#59).

Chaque catégorie demandée par le ticket est figée ici :

- ``.env`` ignoré, ``vendor/``, ``node_modules/``, lockfile, binaire et
  fichier surdimensionné : non lus **parce que** Git les déclare non suivis
  et ignorés ;
- fichier **suivi** qui matche un ``.gitignore`` (``git add -f``) ou fichier
  suivi dans un répertoire ignoré : toujours scanné ;
- fichier non suivi et non ignoré : scanné ;
- ``.gitignore`` lui-même : scanné ;
- ``.git/info/exclude`` et exclusions globales : **non** honorés (le verdict
  reste déterministe) ;
- panne de Git : parcours complet, jamais une exclusion silencieuse ;
- fichier unique explicite : toujours scanné ;
- compteur ``git_ignored`` : remis à zéro, jamais cumulé.

Toutes les valeurs sont synthétiques : ``AKIAIOSFODNN7EXAMPLE`` est la clé
d'exemple de la documentation AWS, jamais une clé fonctionnelle.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GitRepo

from heimdall.scanner import gitignore
from heimdall.scanner.detect import MAX_FILE_BYTES, Scanner
from heimdall.scanner.gitignore import (
    GitExclusions,
    _parse_tagged_nul_list,
    collect_git_exclusions,
)

#: Clé AWS d'exemple (documentation AWS) : jamais fonctionnelle.
AWS = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def repo() -> Iterator[GitRepo]:
    """Dépôt git jetable (jamais le dépôt Heimdall lui-même)."""
    depot = GitRepo("heimdall-t59-")
    try:
        yield depot
    finally:
        depot.close()


def _secret_file(repo: GitRepo, relative: str) -> None:
    repo.write(relative, f'AWS = "{AWS}"\n')


# --- catégories du ticket ---------------------------------------------------


def test_an_ignored_env_file_is_not_scanned(repo: GitRepo) -> None:
    """``.env`` non suivi et ignoré : aucune lecture, aucun Finding."""
    repo.write(".gitignore", ".env\n")
    repo.write("app.py", "x = 1\n")
    repo.stage(".gitignore", "app.py")
    repo.commit_all("base")
    _secret_file(repo, ".env")
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1
    assert scanner.files_scanned == 2


def test_an_ignored_vendor_directory_is_not_scanned(repo: GitRepo) -> None:
    """``vendor/`` ignoré est élagué : un répertoire compte pour une entrée."""
    repo.write(".gitignore", "vendor/\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "vendor/secret.py")
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_an_ignored_node_modules_directory_is_not_scanned(repo: GitRepo) -> None:
    """``node_modules/`` ignoré est élagué, sans lire ses paquets."""
    repo.write(".gitignore", "node_modules/\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "node_modules/pkg/index.js")
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_an_ignored_lockfile_is_not_scanned(repo: GitRepo) -> None:
    """Un lockfile ignoré n'est pas lu, sans règle nominale dans le code."""
    repo.write(".gitignore", "*.lock\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "package.lock")
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_an_ignored_binary_is_not_scanned(repo: GitRepo) -> None:
    """Un binaire ignoré est écarté avant décodage (aucun code 2)."""
    repo.write(".gitignore", "image.png\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_an_ignored_oversized_file_is_not_scanned(repo: GitRepo) -> None:
    """Un fichier ignoré au-delà de la borne de lecture n'est jamais ouvert."""
    repo.write(".gitignore", "huge.txt\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    repo.write("huge.txt", "A" * (MAX_FILE_BYTES + 1))
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_a_tracked_file_matching_gitignore_is_always_scanned(repo: GitRepo) -> None:
    """``git add -f`` rend le fichier suivi : le motif ne le cache jamais."""
    repo.write(".gitignore", "config.py\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "config.py")
    repo.git("add", "-f", "config.py")
    repo.commit_all("tracked")
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["config.py"]
    assert scanner.git_ignored == 0


def test_a_tracked_file_inside_an_ignored_directory_is_always_scanned(
    repo: GitRepo,
) -> None:
    """Un répertoire ignoré avec un fichier suivi n'est pas élagué.

    L'entrée non suivie voisine reste écartée : la décision porte fichier par
    fichier, jamais sur le nom du répertoire.
    """
    repo.write(".gitignore", "vendor/\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "vendor/keep.py")
    repo.git("add", "-f", "vendor/keep.py")
    repo.commit_all("tracked")
    _secret_file(repo, "vendor/secret.py")
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["vendor/keep.py"]
    assert scanner.git_ignored == 1


def test_an_untracked_non_ignored_secret_is_scanned(repo: GitRepo) -> None:
    """Un fichier non suivi mais **non ignoré** peut être commité : lu."""
    repo.write(".gitignore", "*.tmp\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "untracked.py")
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["untracked.py"]
    assert scanner.git_ignored == 0


def test_the_gitignore_file_itself_is_scanned(repo: GitRepo) -> None:
    """Le fichier de configuration des exclusions n'est pas une exclusion."""
    repo.write(".gitignore", f'# AWS = "{AWS}"\n')
    repo.write("app.py", "x = 1\n")
    repo.stage(".gitignore", "app.py")
    repo.commit_all("base")
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == [".gitignore"]


def test_git_info_exclude_is_not_honored(repo: GitRepo) -> None:
    """``.git/info/exclude`` varie par poste : il ne décide pas du périmètre.

    Le ``.gitignore`` versionné reste actif en parallèle, ce qui prouve que
    c'est bien la source d'exclusion qui est sélectionnée, pas Git en bloc.
    """
    repo.write(".gitignore", "ignored.env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "untracked.py")
    _secret_file(repo, "ignored.env")
    (repo.root / ".git" / "info" / "exclude").write_text(
        "untracked.py\n",
        encoding="utf-8",
    )
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["untracked.py"]
    assert scanner.git_ignored == 1


def test_global_git_excludes_are_not_honored(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Les exclusions globales du poste ne rendent pas le verdict variable.

    L'environnement Git du sous-processus est reconstruit : ``HOME`` et
    ``GIT_CONFIG_GLOBAL`` hérités ne sont jamais lus. Le fichier reste donc
    dans le périmètre, même si Git le verrait ignoré sur ce poste.
    """
    repo.write(".gitignore", "ignored.env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "untracked.py")
    _secret_file(repo, "ignored.env")
    global_ignore = repo.root.parent / "global-ignore"
    global_ignore.write_text("untracked.py\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_ignore))
    monkeypatch.setenv("HOME", str(repo.root.parent))
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["untracked.py"]
    assert scanner.git_ignored == 1


def test_git_unavailable_falls_back_to_a_full_scan(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sans Git, aucune exclusion n'est appliquée : le scanner lit plus."""
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, ".env")
    monkeypatch.setattr(gitignore, "_GIT", None)
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == [".env"]
    assert scanner.git_ignored == 0


def test_respect_gitignore_false_restores_the_full_scan(repo: GitRepo) -> None:
    """L'opt-out explicite lit le fichier ignoré et remet le compteur à zéro."""
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, ".env")
    scanner = Scanner(repo.root, respect_gitignore=False)
    assert [finding.file for finding in scanner.scan()] == [".env"]
    assert scanner.git_ignored == 0


@pytest.mark.parametrize("invalid", ["yes", "false", 1, 0, None, object()])
def test_an_invalid_respect_gitignore_policy_is_refused(
    tmp_path: Path, invalid: object
) -> None:
    """Une valeur non booléenne ne peut ni activer ni désactiver l'exclusion."""
    with pytest.raises(ValueError, match="politique d'exclusions Git invalide"):
        Scanner(tmp_path, respect_gitignore=invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "relative",
    (
        "vendor/evil.py",
        "node_modules/evil.js",
        "package-lock.json",
        "evil.png",
        "dist/evil.txt",
    ),
)
def test_a_technical_looking_name_is_scanned_when_not_ignored(
    repo: GitRepo, relative: str
) -> None:
    """Correctif #165 : aucun nom ne suffit à exclure un secret.

    Ces chemins sont précisément ceux qu'une liste nominale laisserait passer.
    Non suivis **et non ignorés**, ils peuvent partir dans un commit : ils
    doivent donc être lus, quel que soit leur nom.
    """
    repo.write(".gitignore", "*.tmp\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, relative)
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == [relative]
    assert scanner.git_ignored == 0


def test_single_file_mode_ignores_gitignore(repo: GitRepo) -> None:
    """Un fichier passé explicitement est toujours scanné, même ignoré."""
    repo.write(".gitignore", "config.py\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    path = repo.write("config.py", f'AWS = "{AWS}"\n')
    scanner = Scanner(path)
    assert [finding.file for finding in scanner.scan()] == ["config.py"]
    assert scanner.git_ignored == 0


def test_a_nested_gitignore_is_honored(repo: GitRepo) -> None:
    """Les motifs d'un ``.gitignore`` imbriqué sont appliqués par Git."""
    repo.write(".gitignore", "root.env\n")
    repo.write("sub/.gitignore", "local.env\n")
    repo.stage(".gitignore", "sub/.gitignore")
    repo.commit_all("base")
    _secret_file(repo, "root.env")
    _secret_file(repo, "sub/local.env")
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 2


def test_a_negated_pattern_reincludes_a_secret(repo: GitRepo) -> None:
    """Une négation ``!`` remet le fichier dans le périmètre : il est lu."""
    repo.write(".gitignore", "*.log\n!keep.log\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, "other.log")
    _secret_file(repo, "keep.log")
    scanner = Scanner(repo.root)
    assert [finding.file for finding in scanner.scan()] == ["keep.log"]
    assert scanner.git_ignored == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="liens symboliques indisponibles")
def test_an_ignored_symlink_is_not_followed(repo: GitRepo) -> None:
    """Un lien ignoré est écarté avant la garde ``symlink`` : pas de fuite."""
    outside = repo.root.parent / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(f'AWS = "{AWS}"\n', encoding="utf-8")
    repo.write(".gitignore", "link.py\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    try:
        (repo.root / "link.py").symlink_to(outside / "secret.txt")
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_git_ignored_is_reset_between_scans(repo: GitRepo) -> None:
    """Le compteur décrit **ce** scan, jamais l'accumulation des appels."""
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    ignored = repo.write(".env", f'AWS = "{AWS}"\n')
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1
    ignored.unlink()
    assert scanner.scan() == []
    assert scanner.git_ignored == 0


# --- unités de la couche Git ------------------------------------------------


def test_a_relative_root_disables_exclusions(tmp_path: Path) -> None:
    """Un chemin relatif n'est pas une base fiable pour Git : parcours complet."""
    assert collect_git_exclusions(Path("relative")) is None


def test_an_invalid_root_type_disables_exclusions() -> None:
    """Une entrée hors contrat rend ``None``, jamais une exception brute."""
    assert collect_git_exclusions(None) is None  # type: ignore[arg-type]


def test_a_broken_git_binary_falls_back_to_a_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un binaire Git absent à l'exécution n'invente aucune exclusion."""
    monkeypatch.setattr(gitignore, "_GIT", str(tmp_path / "missing-git"))
    assert collect_git_exclusions(tmp_path) is None


def test_a_non_repository_root_disables_exclusions(tmp_path: Path) -> None:
    """Hors dépôt, Git échoue : aucune exclusion n'est inventée."""
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / ".gitignore").write_text(".env\n", encoding="utf-8")
    (plain / ".env").write_text(f'AWS = "{AWS}"\n', encoding="utf-8")
    assert collect_git_exclusions(plain) is None


def test_the_parser_accepts_only_the_tagged_nul_format() -> None:
    """Le parseur refuse toute forme inattendue, jamais une approximation."""
    ignored, tracked = _parse_tagged_nul_list(b"? .env\x00? vendor/\x00H keep.py\x00")
    assert ignored == frozenset({".env", "vendor/"})
    assert tracked == frozenset({"keep.py"})
    assert _parse_tagged_nul_list(b"") == (frozenset(), frozenset())
    for invalid in (
        b"? .env",  # pas de NUL final
        b"?.env\x00",  # pas d'espace après l'étiquette
        b"X .env\x00",  # étiquette inconnue
        b"? ../evil\x00",  # traversée
        b"? /\x00",  # absolu
        b"H vendor/\x00",  # un fichier suivi n'est jamais un répertoire
        b"? bad-\xff\x00",  # non UTF-8
    ):
        assert _parse_tagged_nul_list(invalid) is None


def test_a_tracked_file_prevents_pruning_its_ignored_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Défense : ``H vendor/keep.py`` interdit d'élaguer ``vendor/``."""
    monkeypatch.setattr(
        gitignore,
        "_run_git",
        lambda *_args, **_kwargs: b"? vendor/\x00H vendor/keep.py\x00",
    )
    exclusions = collect_git_exclusions(tmp_path)
    assert exclusions == GitExclusions()


def test_an_ignored_file_that_is_also_tracked_is_never_excluded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Même une sortie incohérente ne peut pas exclure un fichier suivi."""
    monkeypatch.setattr(
        gitignore,
        "_run_git",
        lambda *_args, **_kwargs: b"? config.py\x00H config.py\x00",
    )
    exclusions = collect_git_exclusions(tmp_path)
    assert exclusions == GitExclusions()
