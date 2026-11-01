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

import io
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GitRepo

from heimdall.scanner import detect as detect_module
from heimdall.scanner import gitignore
from heimdall.scanner.detect import MAX_FILE_BYTES, Scanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.gitignore import (
    GitExclusions,
    _parse_tagged_nul_list,
    _read_bounded,
    _remaining,
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


class _FakeGitProcess:
    """Processus Git minimal pour éprouver les chemins de panne de ``_run_git``."""

    def __init__(self, stdout: bytes, *, wait_error: BaseException | None = None) -> None:
        self.stdout = io.BytesIO(stdout)
        self.returncode: int | None = 0
        self.killed = False
        self._wait_error = wait_error

    def wait(self, timeout: float | None = None) -> int | None:
        if self._wait_error is not None:
            error = self._wait_error
            self._wait_error = None
            raise error
        return self.returncode

    def kill(self) -> None:
        self.killed = True

    def poll(self) -> int | None:
        return self.returncode


def _run_fake_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeGitProcess,
    *,
    deadline: float | None = None,
) -> bytes | None:
    monkeypatch.setattr(gitignore, "_GIT", "git")
    monkeypatch.setattr(gitignore.subprocess, "Popen", lambda *_args, **_kwargs: process)
    return gitignore._run_git(tmp_path, ("ls-files",), deadline)


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


def test_an_index_change_during_the_scan_is_refused(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ``git add -f`` concurrent ne produit jamais un 0 silencieux.

    Le premier snapshot ignore ``.env`` ; il est promu suivi **après** ce
    snapshot, donc le parcours le saute encore. Le second snapshot, pris
    après le parcours, constate que l'exclusion n'est plus valide et refuse
    le scan (``ScanError``) au lieu de rendre un verdict périmé.
    """
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, ".env")

    original = detect_module.collect_git_exclusions
    calls = 0

    def changing(
        root: str | os.PathLike[str],
        *,
        deadline: float | None = None,
        root_fd: int | None = None,
        expected_root_id: tuple[int, int] | None = None,
    ) -> GitExclusions | None:
        nonlocal calls
        result = original(
            root,
            deadline=deadline,
            root_fd=root_fd,
            expected_root_id=expected_root_id,
        )
        if calls == 0:
            repo.git("add", "-f", ".env")
        calls += 1
        return result

    monkeypatch.setattr(detect_module, "collect_git_exclusions", changing)
    scanner = Scanner(repo.root)
    with pytest.raises(ScanError):
        scanner.scan()
    assert calls == 2


def test_a_root_swap_around_the_git_snapshot_reads_the_scanned_root(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un échange ``A → B → A`` autour de Git ne fait jamais lire ``B``.

    La racine est épinglée par descripteur : Git reçoit ``/proc/self/fd/N``
    (ou ``/dev/fd/N``), pas le chemin. Le remplaçant ``B`` n'est pas un dépôt :
    un appel par chemin échouerait, désactiverait les exclusions et ferait
    lire le secret de ``A``. Le test exige donc l'absence de Finding et
    ``git_ignored == 1``, jamais un verdict sur l'arbre substitué.
    """
    if not hasattr(os, "O_DIRECTORY") or not (
        os.path.isdir("/proc/self/fd") or os.path.isdir("/dev/fd")
    ):
        pytest.skip("descripteurs de répertoire indisponibles")
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, ".env")

    parent = repo.root.parent
    held = parent / "root-held"
    replacement = parent / "root-replacement"
    replacement.mkdir()
    original_popen = subprocess.Popen

    def swapping_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        os.rename(repo.root, held)
        os.rename(replacement, repo.root)
        try:
            process = original_popen(*args, **kwargs)  # type: ignore[arg-type]
        except BaseException:
            os.rename(repo.root, replacement)
            os.rename(held, repo.root)
            raise
        original_wait = process.wait
        restored = False

        def restoring_wait(timeout: float | None = None) -> int:
            nonlocal restored
            try:
                return original_wait(timeout=timeout)
            finally:
                if not restored:
                    os.rename(repo.root, replacement)
                    os.rename(held, repo.root)
                    restored = True

        process.wait = restoring_wait  # type: ignore[method-assign]
        return process

    monkeypatch.setattr(gitignore.subprocess, "Popen", swapping_popen)
    scanner = Scanner(repo.root)
    assert scanner.scan() == []
    assert scanner.git_ignored == 1


def test_a_second_snapshot_failure_is_fail_closed(
    repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Après un skip, un second snapshot impossible refuse le scan.

    Sans ce refus, le scanner ne pourrait pas prouver que l'entrée sautée
    est encore ignorée : mieux vaut un code 2 qu'un verdict potentiellement
    périmé.
    """
    repo.write(".gitignore", ".env\n")
    repo.stage(".gitignore")
    repo.commit_all("base")
    _secret_file(repo, ".env")

    original = detect_module.collect_git_exclusions
    calls = 0

    def changing(
        root: str | os.PathLike[str],
        *,
        deadline: float | None = None,
        root_fd: int | None = None,
        expected_root_id: tuple[int, int] | None = None,
    ) -> GitExclusions | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(
                root,
                deadline=deadline,
                root_fd=root_fd,
                expected_root_id=expected_root_id,
            )
        return None

    monkeypatch.setattr(detect_module, "collect_git_exclusions", changing)
    scanner = Scanner(repo.root)
    with pytest.raises(ScanError):
        scanner.scan()
    assert calls == 2


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


def test_git_resolution_ignores_relative_defpath_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un ``.`` de ``os.defpath`` ne doit jamais faire exécuter le dépôt.

    Windows met ``.`` en tête de ``os.defpath`` : un dépôt contenant un
    ``git`` exécutable serait lancé si le chemin relatif était accepté.
    """
    trusted = str(tmp_path / "bin")
    seen: list[str] = []

    def fake_which(_cmd: str, path: str | None = None) -> str | None:
        assert path is not None
        seen.append(path)
        return str(Path(path) / "git")

    monkeypatch.setattr(gitignore.os, "defpath", f".{os.pathsep}{trusted}")
    monkeypatch.setattr(gitignore.shutil, "which", fake_which)
    assert gitignore._resolve_git() == str(Path(trusted) / "git")
    assert "." not in seen


def test_git_resolution_requires_an_absolute_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Même un ``which`` qui rend ``git`` relatif est refusé (fail-closed)."""
    monkeypatch.setattr(gitignore.os, "defpath", "/usr/bin")
    monkeypatch.setattr(gitignore.shutil, "which", lambda *_args, **_kwargs: "git")
    assert gitignore._resolve_git() is None


def test_git_resolution_without_a_trusted_candidate_disables_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aucun répertoire absolu ou aucun Git : parcours complet, pas de skip."""
    monkeypatch.setattr(gitignore.os, "defpath", f".{os.pathsep}relative")
    monkeypatch.setattr(gitignore.shutil, "which", lambda *_args, **_kwargs: "git")
    assert gitignore._resolve_git() is None


def test_a_non_repository_root_disables_exclusions(tmp_path: Path) -> None:
    """Hors dépôt, Git échoue : aucune exclusion n'est inventée."""
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / ".gitignore").write_text(".env\n", encoding="utf-8")
    (plain / ".env").write_text(f'AWS = "{AWS}"\n', encoding="utf-8")
    assert collect_git_exclusions(plain) is None


def test_a_missing_or_non_directory_root_cannot_be_pinned(tmp_path: Path) -> None:
    """Un descripteur n'est rendu que pour un répertoire réellement ouvert."""
    assert gitignore._open_directory(tmp_path / "missing") is None
    plain = tmp_path / "file.txt"
    plain.write_text("x = 1\n", encoding="utf-8")
    assert gitignore._open_directory(plain) is None


def test_a_failed_pin_never_falls_back_to_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un lien racine refuse l'épinglage : Git n'est jamais relancé par chemin."""
    if not gitignore._ROOT_FD_SUPPORTED or not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("épinglage par descripteur indisponible")
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("liens symboliques indisponibles")
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        raise AssertionError("Git ne doit pas être relancé sur le chemin")

    monkeypatch.setattr(gitignore, "_run_git", forbidden)
    assert collect_git_exclusions(link) is None
    assert called is False


def test_a_descriptor_for_another_root_is_refused_before_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un descripteur qui ne porte pas l'identité attendue rend ``None``.

    Le contrôle est fait **avant** de lancer Git : aucune exclusion ne peut
    être calculée sur un inode substitué.
    """
    descriptor = gitignore._open_directory(tmp_path)
    if descriptor is None:
        pytest.skip("descripteurs de répertoire indisponibles")
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        raise AssertionError("Git ne doit pas être lancé sur un descripteur substitué")

    monkeypatch.setattr(gitignore, "_run_git", forbidden)
    try:
        assert (
            collect_git_exclusions(
                tmp_path,
                root_fd=descriptor,
                expected_root_id=(0, 0),
            )
            is None
        )
    finally:
        os.close(descriptor)
    assert called is False


def test_an_owned_descriptor_is_used_then_closed_after_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le descripteur ouvert par ``collect`` est transmis à Git puis fermé."""
    descriptor = gitignore._open_directory(tmp_path)
    if descriptor is None:
        pytest.skip("descripteurs de répertoire indisponibles")
    seen: list[object] = []

    def capture(root: object, *_args: object, **_kwargs: object) -> bytes:
        seen.append(root)
        return b""

    monkeypatch.setattr(gitignore, "_open_directory", lambda _path: descriptor)
    monkeypatch.setattr(gitignore, "_run_git", capture)
    assert collect_git_exclusions(tmp_path) == GitExclusions()
    assert len(seen) == 1
    assert isinstance(seen[0], gitignore._PinnedRoot)
    assert seen[0].descriptor == descriptor
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_a_descriptor_for_another_path_is_refused_without_expected_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sans identité attendue, le descripteur est confronté au chemin annoncé."""
    other = tmp_path / "other"
    other.mkdir()
    descriptor = gitignore._open_directory(other)
    if descriptor is None:
        pytest.skip("descripteurs de répertoire indisponibles")
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        raise AssertionError("Git ne doit pas être lancé sur un descripteur substitué")

    monkeypatch.setattr(gitignore, "_run_git", forbidden)
    try:
        assert collect_git_exclusions(tmp_path, root_fd=descriptor) is None
    finally:
        os.close(descriptor)
    assert called is False


def test_a_pinned_root_without_an_fd_path_never_falls_back_to_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un descripteur épinglé sans chemin de descripteur rend ``None``.

    Le repli par chemin serait exactement la course que l'épinglage ferme :
    mieux vaut un parcours complet qu'un Git relancé sur le chemin.
    """
    descriptor = gitignore._open_directory(tmp_path)
    if descriptor is None:
        pytest.skip("descripteurs de répertoire indisponibles")
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        raise AssertionError("aucun Git ne doit être lancé sans chemin de descripteur")

    monkeypatch.setattr(gitignore, "_directory_fd_path", lambda _fd: None)
    monkeypatch.setattr(gitignore, "_run_git_command", forbidden)
    pinned = gitignore._PinnedRoot(tmp_path, descriptor, (0, 0))
    try:
        assert gitignore._run_git(pinned, ("ls-files",), None) is None
    finally:
        os.close(descriptor)
    assert called is False


def test_fd_helpers_fall_back_without_a_descriptor_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sans ``/proc/self/fd`` ni ``/dev/fd``, le repli reste explicite."""
    monkeypatch.setattr(gitignore.os.path, "isdir", lambda _path: False)
    assert gitignore._directory_fd_path(3) is None

    monkeypatch.setattr(gitignore.os, "readlink", lambda _path: "relative")
    assert gitignore._fd_real_path("fd") is None

    deleted = f"{tmp_path}/root (deleted)"
    monkeypatch.setattr(gitignore.os, "readlink", lambda _path: deleted)
    assert gitignore._fd_real_path("fd") == f"{tmp_path}/root"

    def broken(_path: str) -> str:
        raise OSError

    monkeypatch.setattr(gitignore.os, "readlink", broken)
    assert gitignore._fd_real_path("fd") is None

    monkeypatch.setattr(gitignore, "_fd_real_path", lambda _path: None)
    assert gitignore._ceiling_for("fd", tmp_path) == str(tmp_path.parent)


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


def test_the_parser_treats_resolve_undo_entries_as_tracked() -> None:
    """``U`` (resolve-undo) est une entrée d'index : elle n'est jamais exclue.

    La table est épinglée sur ``git ls-files -t`` (Git 2.54) : ``U`` désigne
    un fichier suivi avec information de résolution, pas une entrée non
    suivie. Le traiter comme suivi évite un parcours complet inutile, sans
    ouvrir la porte à une exclusion.
    """
    ignored, tracked = _parse_tagged_nul_list(b"U resolve.py\x00")
    assert ignored == frozenset()
    assert tracked == frozenset({"resolve.py"})


def test_a_parse_failure_disables_exclusions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une sortie Git invalide rend le parcours complet, jamais une exclusion."""
    monkeypatch.setattr(gitignore, "_run_git", lambda *_args, **_kwargs: b"? .env")
    assert collect_git_exclusions(tmp_path) is None


def test_an_expired_deadline_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une deadline déjà franchie refuse la collecte, même sans lancer Git."""
    monkeypatch.setattr(gitignore, "_GIT", "git")
    with pytest.raises(ScanError):
        _remaining(time.monotonic() - 1.0)
    with pytest.raises(ScanError):
        collect_git_exclusions(tmp_path, deadline=time.monotonic() - 1.0)


def test_the_bounded_reader_refuses_an_oversized_output() -> None:
    """Le plafond est strict : un octet de trop rend ``None``, pas une liste."""
    assert _read_bounded(io.BytesIO(b"abcde"), 5) == b"abcde"
    assert _read_bounded(io.BytesIO(b"abcdef"), 5) is None


@pytest.mark.parametrize("error", [OSError, ValueError])
def test_the_bounded_reader_swallows_stream_errors(error: type[Exception]) -> None:
    """Une lecture de tube cassée n'expose jamais d'exception brute."""

    class Broken:
        def read(self, _size: int) -> bytes:
            raise error("tube cassé")

    assert _read_bounded(Broken(), 10) is None  # type: ignore[arg-type]


def test_a_git_timeout_falls_back_to_a_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un Git qui dépasse le timeout unitaire est tué, puis tout est parcouru."""
    process = _FakeGitProcess(
        b"", wait_error=subprocess.TimeoutExpired("git", 1.0)
    )
    assert _run_fake_git(tmp_path, monkeypatch, process) is None
    assert process.killed is True


def test_an_expired_scan_deadline_after_a_git_timeout_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La panne Git reste un repli, sauf si la deadline du scan est franchie."""
    monkeypatch.setattr(gitignore, "_remaining", lambda _deadline: 0.001)
    process = _FakeGitProcess(
        b"", wait_error=subprocess.TimeoutExpired("git", 0.001)
    )
    with pytest.raises(ScanError):
        _run_fake_git(tmp_path, monkeypatch, process, deadline=-1.0)


def test_a_git_wait_error_falls_back_to_a_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une panne d'attente ne rend jamais une liste partielle."""
    process = _FakeGitProcess(b"", wait_error=OSError("processus récolté"))
    assert _run_fake_git(tmp_path, monkeypatch, process) is None
    assert process.killed is True


def test_an_oversized_git_output_is_abandoned_and_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Au-delà du plafond, Git est tué et le parcours complet reprend."""
    monkeypatch.setattr(gitignore, "MAX_GIT_LIST_BYTES", 3)
    process = _FakeGitProcess(b"abcd")
    assert _run_fake_git(tmp_path, monkeypatch, process) is None
    assert process.killed is True


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
