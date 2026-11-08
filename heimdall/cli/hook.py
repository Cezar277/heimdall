"""Hook Git ``pre-commit`` et gestion de l'index (tickets #36, #103-#106).

Le hook installé est un script POSIX **généré**, sans interpolation de contenu
du dépôt : il exécute d'abord le hook précédent s'il existe, puis
``heimdall scan --staged .`` avec le script console absolu (ou, à défaut,
``python -I -m heimdall.cli.main``) qui a installé Heimdall. Le scan
``--staged`` lit uniquement les blobs de l'index : les modifications non
indexées ne sont jamais scannées (#104).

Invariants de sécurité :

- **aucun shell construit depuis une entrée** : les commandes git internes
  sont des argv figés, ``shell=True`` est proscrit, et les seules valeurs
  variables sont des chemins validés par la garde unique
  :func:`heimdall.mcp.paths.confine` (résolution réelle + confinement) ;
- **pas d'écrasement silencieux** : un hook existant est déplacé vers
  ``pre-commit.heimdall-legacy`` puis chaîné s'il est exécutable ; un second
  hook étranger alors qu'une sauvegarde existe déjà est refusé (fail-closed) ;
- **écriture atomique** : le hook est écrit dans un fichier temporaire du
  même répertoire, ``fsync`` puis ``os.replace``, permissions ``0700`` ;
- **anti-récursion** : le script pose ``HEIMDALL_IN_HOOK=1`` et sort
  immédiatement si la variable vaut déjà ``1`` ;
- **ré-indexation sûre** : :func:`apply_and_restage` vérifie **avant** la
  remédiation qu'aucun fichier cible n'a de modification non indexée, puis
  ré-indexe le contenu exact via ``git hash-object --no-filters`` et
  ``git update-index --cacheinfo``. Les filtres ``clean`` et les hooks Git du
  dépôt ne sont donc jamais exécutés par cette écriture.

Le hook local reste **contournable** (``git commit --no-verify``) : la CI
déterministe reste la barrière opposable (REQ-SEC-08).
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Callable, Iterable, Sequence
from enum import Enum
from pathlib import Path
from typing import Final

import typer

from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import (
    GIT_CONFIG_OVERRIDES,
    GIT_TIMEOUT_SECONDS,
    GitAccess,
    confined_environment,
)
from heimdall.mcp.paths import ConfinedPath, PathEscape, confine
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.errors import ScanError

#: Nom du hook géré.
HOOK_NAME: Final[str] = "pre-commit"
#: Marqueur d'identification du hook Heimdall (première ligne de commentaire).
HOOK_MARKER: Final[str] = "# heimdall-managed-hook: v1"
#: Suffixe du hook précédent conservé et chaîné.
LEGACY_SUFFIX: Final[str] = ".heimdall-legacy"
#: Variable d'environnement anti-récursion.
HEIMDALL_IN_HOOK_ENV: Final[str] = "HEIMDALL_IN_HOOK"
#: Taille maximale lue d'un hook existant (fichier local, non fiable).
MAX_HOOK_BYTES: Final[int] = 1_048_576
#: Nombre maximal de fichiers ré-indexés en une fois (borne argv et travail).
MAX_RESTAGE_PATHS: Final[int] = 32
#: Objet Git : SHA-1 (40) ou SHA-256 (64), minuscules.
_OBJECT_RE: Final[re.Pattern[str]] = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
#: Taille de lecture par bloc pour les fichiers locaux.
_READ_CHUNK: Final[int] = 65_536
#: Nombre de lignes du préambule du hook généré (shebang + marqueur).
_HOOK_PREFIX_LINES: Final[int] = 2
#: Champs de l'en-tête ``git ls-files -s`` : ``mode sha stage``.
_LS_FILES_FIELDS: Final[int] = 3


class HookError(Exception):
    """Erreur statique : aucun chemin, contenu ou secret n'est reflété."""

    def __init__(self, message: str = "gestion du hook impossible") -> None:
        super().__init__(message)


class UnstagedChangesError(HookError):
    """Un fichier cible a des modifications non indexées : refus fail-closed."""

    def __init__(self) -> None:
        super().__init__(
            "modifications non indexées : remédiation automatique refusée"
        )


class OutsideRepositoryError(HookError):
    """``core.hooksPath`` sort du dépôt et du répertoire Git commun."""

    def __init__(self) -> None:
        super().__init__("hooksPath hors du dépôt : utiliser --force")


class InstallOutcome(str, Enum):
    """Résultat d'une installation, pour un message CLI statique."""

    INSTALLED = "installed"
    UPDATED = "updated"
    CHAINED = "chained"
    BACKED_UP = "backed_up"


class UninstallOutcome(str, Enum):
    """Résultat d'une désinstallation, pour un message CLI statique."""

    REMOVED = "removed"
    RESTORED = "restored"
    NOT_INSTALLED = "not_installed"


def _git_binary(root: Path) -> str:
    """Résout git hors PATH hérité et refuse un binaire détourné par le dépôt.

    Même garde que :class:`heimdall.mcp.gitdiff.GitAccess` : un ``git``
    résolu sous la racine du dépôt (ou dans le répertoire courant, cas
    Windows) ne doit jamais être exécuté.
    """
    git = shutil.which("git", path=os.defpath)
    if git is None:
        raise HookError
    try:
        resolved = Path(git).resolve()
        repository_root = root.resolve()
        current = Path.cwd().resolve()
    except (OSError, RuntimeError):
        raise HookError from None
    if resolved.is_relative_to(repository_root) or resolved.parent == current:
        raise HookError
    return git


def _run_git(  # noqa: PLR0913 - options explicites
    root: Path,
    arguments: Sequence[str],
    *,
    stdin: bytes | None = None,
    timeout: float = GIT_TIMEOUT_SECONDS,
    extra_env: dict[str, str] | None = None,
    allowed_index_file: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Exécute une commande git figée, sans shell et sans hooks du dépôt.

    ``core.hooksPath`` est neutralisé vers ``os.devnull`` : les écritures
    internes (``update-index``) ne doivent jamais déclencher un
    ``post-index-change`` contrôlé par le dépôt. ``HEIMDALL_IN_HOOK=1`` est
    posé pour tout sous-processus, même si l'appelant direct ne l'a pas fait.
    """
    environment = confined_environment(str(root.parent))
    environment[HEIMDALL_IN_HOOK_ENV] = "1"
    if extra_env is not None:
        if set(extra_env) - {"GIT_INDEX_FILE"}:
            raise HookError
        index_file = extra_env.get("GIT_INDEX_FILE")
        if (
            index_file is None
            or allowed_index_file is None
            or not Path(index_file).is_absolute()
            or any(character in index_file for character in ("\x00", "\n", "\r"))
        ):
            raise HookError
        try:
            if Path(index_file).resolve() != allowed_index_file.resolve():
                raise HookError
        except (OSError, RuntimeError):
            raise HookError from None
        environment.update(extra_env)
    elif allowed_index_file is not None:
        raise HookError
    command = [
        _git_binary(root),
        *GIT_CONFIG_OVERRIDES,
        "-c",
        f"core.hooksPath={os.devnull}",
        "-C",
        str(root),
        *arguments,
    ]
    try:
        if stdin is not None:
            return subprocess.run(  # noqa: S603 # nosec B603
                command,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=timeout,
                check=False,
            )
        return subprocess.run(  # noqa: S603 # nosec B603
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HookError from None


def _git_path(access: GitAccess, name: str) -> Path:
    """Chemin réel d'un élément git (``hooks``), worktrees et hooksPath inclus.

    Un ``core.hooksPath`` **relatif** doit rester dans le dépôt : un dépôt
    piégé ne doit pas faire écrire ``pre-commit`` hors de sa racine via
    ``../`` ou un lien sortant. Un chemin **absolu** reste accepté : c'est
    la configuration explicite d'un dossier de hooks global.
    """
    try:
        completed = access.execute(("rev-parse", "--git-path", name))
    except ToolFailure:
        raise HookError from None
    if completed.returncode != 0:
        raise HookError
    raw = completed.stdout[:-1] if completed.stdout.endswith(b"\n") else completed.stdout
    if not raw or b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise HookError
    try:
        path = Path(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise HookError from None
    try:
        resolved = path.resolve() if path.is_absolute() else (access.root / path).resolve()
    except (OSError, RuntimeError):
        raise HookError from None
    if not path.is_absolute() and not resolved.is_relative_to(access.root):
        raise HookError
    return resolved


def _git_common_dir(access: GitAccess) -> Path:
    """Répertoire Git commun (``.git`` partagé par les worktrees liés)."""
    try:
        completed = access.execute(("rev-parse", "--git-common-dir"))
    except ToolFailure:
        raise HookError from None
    if completed.returncode != 0:
        raise HookError
    raw = completed.stdout[:-1] if completed.stdout.endswith(b"\n") else completed.stdout
    if not raw or b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise HookError
    try:
        path = Path(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise HookError from None
    if not path.is_absolute():
        path = access.root / path
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        raise HookError from None


def _inside_allowed_roots(access: GitAccess, path: Path) -> bool:
    """Vrai si ``path`` est dans le worktree ou dans le Git commun."""
    common = _git_common_dir(access)
    return path.is_relative_to(access.root) or path.is_relative_to(common)


def _validate_hooks_directory(access: GitAccess, path: Path) -> None:
    """Refuse un dossier de hooks confondu avec la racine ou le Git commun.

    Écrire ``pre-commit`` directement à la racine du dépôt (ou dans ``.git``)
    changerait l'identité du dossier racine et exposerait un fichier de hook
    au suivi Git. Le dossier doit être un sous-dossier dédié.
    """
    if path == access.root or path == _git_common_dir(access):
        raise HookError


def _interpreter() -> str:
    """Interpréteur absolu utilisé par le hook, sans dépendre du PATH."""
    python = os.path.abspath(sys.executable)
    if not python or any(character in python for character in ("\x00", "\n", "\r")):
        raise HookError
    return python


def _launcher(root: Path) -> str:
    """Commande absolue du hook, déjà quotée pour ``/bin/sh``.

    Le script console ``heimdall`` est préféré s'il est **hors du dépôt** :
    son ``sys.path[0]`` est le dossier ``bin`` de l'environnement, pas la
    racine du dépôt. Un console script sous la racine (venv dans le dépôt)
    est refusé et remplacé par ``python -I -m``, qui isole aussi
    l'interpréteur (pas de ``heimdall`` local importable, pas de
    ``PYTHONPATH``).
    """
    python = _interpreter()
    console = Path(python).with_name("heimdall")
    # Sous Windows, ``heimdall.exe`` est un lanceur natif, pas un script
    # Python : on garde le module isolé, qui fonctionne partout.
    if os.name != "nt" and console.is_file() and os.access(console, os.X_OK):
        try:
            repository_root = root.resolve()
            if console.is_relative_to(repository_root) or console.resolve().is_relative_to(
                repository_root
            ):
                return f"{shlex.quote(python)} -I -m heimdall.cli.main"
        except (OSError, RuntimeError):
            raise HookError from None
        return f"{shlex.quote(python)} -I {shlex.quote(str(console))}"
    return f"{shlex.quote(python)} -I -m heimdall.cli.main"


def interpreter_inside_repository(root: Path) -> bool:
    """True si l'interpréteur Python d'installation est sous la racine du dépôt.

    Un venv local est exécuté à chaque commit : le dépôt peut le modifier
    après l'installation. L'appelant affiche un avertissement ; la garantie
    forte exige un interpréteur hors du dépôt.
    """
    access = _open_repository(root)
    python = Path(_interpreter())
    try:
        repository_root = access.root
        return python.is_relative_to(repository_root) or python.resolve().is_relative_to(
            repository_root
        )
    except (OSError, RuntimeError):
        raise HookError from None


def _read_regular(path: Path, limit: int) -> bytes:
    """Lit un fichier régulier sans suivre un lien, avec borne stricte."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise HookError from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise HookError
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(_READ_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise HookError
        return data
    except OSError:
        raise HookError from None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _is_ours(path: Path) -> bool:
    """True si le fichier est exactement le hook Heimdall généré.

    Le marqueur doit être la deuxième ligne, juste après ``#!/bin/sh`` : un
    hook étranger qui contiendrait la chaîne en corps de fichier ne doit ni
    être écrasé à l'installation ni supprimé à la désinstallation.
    """
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        return False
    lines = _read_regular(path, MAX_HOOK_BYTES).splitlines()
    return (
        len(lines) >= _HOOK_PREFIX_LINES
        and lines[0] == b"#!/bin/sh"
        and lines[1] == HOOK_MARKER.encode()
    )


def _is_chainable(path: Path) -> bool:
    """True si le hook précédent est un fichier régulier exécutable."""
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and os.access(path, os.X_OK)


def _hook_script(launcher: str, legacy: Path | None) -> bytes:
    """Génère le script POSIX, avec quoting systématique des chemins.

    Le hook précédent est exécuté **avant** Heimdall : s'il modifie l'index,
    le scan juge l'état final qui sera réellement commité. L'inverse
    laisserait un hook hérité ajouter un secret après le verdict.
    """
    lines = [
        "#!/bin/sh",
        HOOK_MARKER,
        "# Généré par `heimdall hook install` : ne pas éditer à la main.",
        'if [ "${HEIMDALL_IN_HOOK:-}" = "1" ]; then',
        '    echo "heimdall: hook déjà en cours (HEIMDALL_IN_HOOK=1), scan ignoré" >&2',
        "    exit 0",
        "fi",
        "HEIMDALL_IN_HOOK=1",
        "export HEIMDALL_IN_HOOK",
    ]
    if legacy is not None:
        legacy_name = shlex.quote(legacy.name)
        lines.extend(
            [
                'hook_dir=$(dirname "$0")',
                f'legacy="$hook_dir"/{legacy_name}',
                'if [ -x "$legacy" ]; then',
                '    "$legacy" "$@"',
                "    status=$?",
                '    if [ "$status" -ne 0 ]; then',
                '        exit "$status"',
                "    fi",
                "fi",
            ]
        )
    lines.extend(
        [
            "unset PYTHONPATH PYTHONHOME",
            f'exec {launcher} scan --staged "$PWD"',
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _atomic_write(path: Path, content: bytes) -> None:
    """Écrit le hook atomiquement (temp + fsync + os.replace), mode 0700."""
    directory = path.parent
    descriptor = -1
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".heimdall-hook-", dir=directory)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o700)
        os.replace(temporary, path)
        temporary = None
        try:
            directory_descriptor = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
        except OSError:
            return
        try:
            os.fsync(directory_descriptor)
        finally:
            with contextlib.suppress(OSError):
                os.close(directory_descriptor)
    except OSError:
        raise HookError from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary)


def _ensure_hooks_directory(path: Path) -> None:
    """Crée le dossier de hooks si nécessaire, sans écraser un fichier.

    Un dossier accessible en écriture au groupe ou aux autres est refusé :
    un autre utilisateur pourrait y remplacer le hook, que Git exécuterait
    ensuite avec les droits du développeur. Un umask 0002 rend `.git/hooks`
    groupe-inscriptible : l'opérateur doit alors faire `chmod g-w`.
    """
    try:
        if path.exists() and not path.is_dir():
            raise HookError
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = os.stat(path)
    except OSError:
        raise HookError from None
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
        raise HookError


def _open_repository(root: Path) -> GitAccess:
    """Ouvre la racine comme dépôt Git, ou lève une erreur statique."""
    try:
        access = GitAccess(root)
        if not access.is_repository():
            raise HookError
    except (ScanError, ToolFailure):
        raise HookError from None
    return access


def _verify_root(access: GitAccess) -> None:
    """Vérifie que la racine n'a pas été remplacée depuis l'ouverture."""
    try:
        metadata = os.stat(access.root)
    except OSError:
        raise HookError from None
    if (metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns) != access.root_id:
        raise HookError


def _prepare_existing_hook(hook_path: Path, legacy_path: Path) -> tuple[bool, bool]:
    """Classe le hook existant et le sauvegarde si nécessaire.

    Rend ``(est_notre_hook, hook_deplace_vers_legacy)``. Un hook étranger
    n'est jamais écrasé : il est renommé, et un second hook étranger alors
    qu'une sauvegarde existe déjà est refusé.
    """
    if not os.path.lexists(hook_path):
        return False, False
    metadata = os.lstat(hook_path)
    if stat.S_ISDIR(metadata.st_mode):
        raise HookError
    if stat.S_ISLNK(metadata.st_mode):
        if os.path.lexists(legacy_path):
            raise HookError
        os.replace(hook_path, legacy_path)
        return False, True
    if not stat.S_ISREG(metadata.st_mode):
        raise HookError
    if _is_ours(hook_path):
        return True, False
    if os.path.lexists(legacy_path):
        raise HookError
    os.replace(hook_path, legacy_path)
    return False, True


def install_hook(root: Path, *, force: bool = False) -> InstallOutcome:
    """Installe (ou met à jour) le hook ``pre-commit`` du dépôt ``root``.

    Un hook existant est conservé : renommé en ``pre-commit.heimdall-legacy``
    puis chaîné s'il est exécutable. Si une sauvegarde existe déjà, un nouveau
    hook étranger est refusé au lieu d'être écrasé. Un ``hooksPath`` absolu
    hors du dépôt et du répertoire Git commun exige ``force=True``.
    """
    access = _open_repository(root)
    hooks_directory = _git_path(access, "hooks")
    _validate_hooks_directory(access, hooks_directory)
    if not force and not _inside_allowed_roots(access, hooks_directory):
        raise OutsideRepositoryError
    _verify_root(access)
    _ensure_hooks_directory(hooks_directory)
    # Le mkdir peut avoir changé le ctime de la racine : on rouvre pour
    # comparer la suite des écritures à l'identité courante, pas à l'ancienne.
    access = _open_repository(root)
    hooks_directory = _git_path(access, "hooks")
    _validate_hooks_directory(access, hooks_directory)
    if not force and not _inside_allowed_roots(access, hooks_directory):
        raise OutsideRepositoryError
    _verify_root(access)
    hook_path = hooks_directory / HOOK_NAME
    legacy_path = hooks_directory / (HOOK_NAME + LEGACY_SUFFIX)
    try:
        ours, moved_legacy = _prepare_existing_hook(hook_path, legacy_path)
        legacy_for_chain = legacy_path if _is_chainable(legacy_path) else None
        script = _hook_script(_launcher(access.root), legacy_for_chain)
        try:
            _atomic_write(hook_path, script)
            _verify_root(access)
        except BaseException:
            if moved_legacy:
                with contextlib.suppress(OSError):
                    os.replace(legacy_path, hook_path)
            raise
    except OSError:
        raise HookError from None

    if legacy_for_chain is not None:
        return InstallOutcome.CHAINED
    if moved_legacy:
        return InstallOutcome.BACKED_UP
    if ours:
        return InstallOutcome.UPDATED
    return InstallOutcome.INSTALLED


def _check_legacy_restorable(path: Path) -> None:
    """Refuse de restaurer autre chose qu'un fichier régulier ou un lien."""
    try:
        metadata = os.lstat(path)
    except OSError:
        raise HookError from None
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        raise HookError


def uninstall_hook(root: Path, *, force: bool = False) -> UninstallOutcome:
    """Retire le hook Heimdall et restaure le hook précédent s'il existe."""
    access = _open_repository(root)
    hooks_directory = _git_path(access, "hooks")
    _validate_hooks_directory(access, hooks_directory)
    if not force and not _inside_allowed_roots(access, hooks_directory):
        raise OutsideRepositoryError
    _verify_root(access)
    hook_path = hooks_directory / HOOK_NAME
    legacy_path = hooks_directory / (HOOK_NAME + LEGACY_SUFFIX)
    try:
        if os.path.lexists(hook_path):
            metadata = os.lstat(hook_path)
            if stat.S_ISDIR(metadata.st_mode):
                raise HookError
            if not stat.S_ISREG(metadata.st_mode) or not _is_ours(hook_path):
                outcome = UninstallOutcome.NOT_INSTALLED
            elif os.path.lexists(legacy_path):
                _check_legacy_restorable(legacy_path)
                os.replace(legacy_path, hook_path)
                outcome = UninstallOutcome.RESTORED
            else:
                os.unlink(hook_path)
                outcome = UninstallOutcome.REMOVED
        elif os.path.lexists(legacy_path):
            _check_legacy_restorable(legacy_path)
            os.replace(legacy_path, hook_path)
            outcome = UninstallOutcome.RESTORED
        else:
            outcome = UninstallOutcome.NOT_INSTALLED
    except OSError:
        raise HookError from None
    _verify_root(access)
    return outcome


def _confined_paths(root: Path, paths: Iterable[str]) -> list[ConfinedPath]:
    """Valide et confine une liste de chemins de remédiation (garde unique)."""
    raw_paths = list(paths)
    if any(not isinstance(path, str) for path in raw_paths):
        raise HookError
    unique = sorted(set(raw_paths))
    if not 1 <= len(unique) <= MAX_RESTAGE_PATHS:
        raise HookError
    confined: list[ConfinedPath] = []
    seen: set[str] = set()
    for raw_path in unique:
        try:
            item = confine(root, raw_path)
        except (PathEscape, OSError, RuntimeError, ValueError):
            raise HookError from None
        if item.relative in seen:
            continue
        seen.add(item.relative)
        if item.relative.startswith("-"):
            # Contrat explicite : un chemin ne doit jamais ressembler à une
            # option, même si l'arité de ``--cacheinfo`` le protège aujourd'hui.
            raise HookError
        raw_parts = item.relative.split("/")
        parts = [part.lower() for part in raw_parts]
        if ".git" in parts:
            raise HookError
        for index, part in enumerate(parts):
            if not part.startswith(".env"):
                continue
            # Seul le fichier exact ``.env.example`` (casse incluse) en dernier
            # composant est autorisé ; un répertoire ``.env.example/`` reste
            # refusé.
            if index == len(raw_parts) - 1 and raw_parts[index] == ".env.example":
                continue
            raise HookError
        confined.append(item)
    if not confined:
        raise HookError
    return confined


def _read_regular_bounded(path: Path) -> tuple[bytes, os.stat_result]:
    """Lit un fichier régulier borné, sans suivre un lien, avec ``fstat``.

    La taille et le mode sont lus sur le descripteur ouvert : une
    substitution entre la vérification et la lecture ne peut pas changer
    silencieusement le mode indexé ni faire lire au-delà de la borne.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise HookError from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
            raise HookError
        size = metadata.st_size
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = os.read(descriptor, min(_READ_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != size:
            raise HookError
        if os.read(descriptor, 1):
            raise HookError
        return data, metadata
    except OSError:
        raise HookError from None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _hash_blob(root: Path, data: bytes) -> str:
    """Écrit un blob brut (sans filtre) et rend son SHA validé."""
    completed = _run_git(
        root,
        ("hash-object", "-w", "--no-filters", "--stdin"),
        stdin=data,
    )
    if completed.returncode != 0:
        raise HookError
    try:
        digest = completed.stdout.strip().decode("ascii")
    except UnicodeDecodeError:
        raise HookError from None
    if _OBJECT_RE.fullmatch(digest) is None:
        raise HookError
    return digest


def assert_no_unstaged_changes(root: Path, paths: Iterable[str]) -> list[ConfinedPath]:
    """Refuse la remédiation si un fichier cible a des modifications non indexées.

    La vérification a lieu **avant** l'application du patch : après, les
    modifications apportées par la remédiation seraient indistinguables de
    celles du développeur, et un ``git add`` indexerait des lignes non
    choisies. Les chemins sont confinés par :func:`confine` (liens sortants
    et traversées refusés).
    """
    access = _open_repository(root)
    repository_root = access.root
    _verify_root(access)
    confined = _confined_paths(repository_root, paths)
    for item in confined:
        try:
            metadata = os.lstat(item.absolute)
        except FileNotFoundError:
            metadata = None
        except OSError:
            raise HookError from None
        if metadata is not None and not stat.S_ISREG(metadata.st_mode):
            raise HookError
        # Le diff est exécuté même si le fichier a disparu du dossier de
        # travail : une suppression suivie d'une recréation par la remédiation
        # doit aussi être refusée si elle n'était pas indexée.
        completed = _run_git(
            repository_root,
            (
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--no-textconv",
                "--",
                item.relative,
            ),
        )
        if completed.returncode == 1:
            raise UnstagedChangesError
        if completed.returncode != 0:
            raise HookError
    _verify_root(access)
    return confined


def _verify_index_entries(
    root: Path,
    entries: Sequence[tuple[str, str, str]],
    *,
    extra_env: dict[str, str],
    allowed_index_file: Path,
) -> None:
    """Vérifie que l'index temporaire contient exactement les entrées voulues."""
    arguments = ["ls-files", "-s", "-z", "--"]
    arguments.extend(relative for _, _, relative in entries)
    completed = _run_git(
        root,
        arguments,
        extra_env=extra_env,
        allowed_index_file=allowed_index_file,
    )
    if completed.returncode != 0:
        raise HookError
    actual: dict[str, tuple[str, str]] = {}
    for record in completed.stdout.split(b"\x00"):
        if not record:
            continue
        header, separator, path_bytes = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != _LS_FILES_FIELDS:
            raise HookError
        mode_bytes, digest_bytes, stage_bytes = fields
        if stage_bytes != b"0":
            raise HookError
        try:
            mode = mode_bytes.decode("ascii")
            digest = digest_bytes.decode("ascii")
            relative = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HookError from None
        actual[relative] = (mode, digest)
    expected = {relative: (mode, digest) for mode, digest, relative in entries}
    if actual != expected:
        raise HookError


def _create_locked_index_copy(index_path: Path, lock_path: Path) -> None:
    """Crée ``index.lock`` et y copie l'index via le descripteur verrouillé.

    Le chemin du verrou n'est jamais rouvert par nom après sa création : un
    remplacement par un lien symbolique entre ``O_EXCL`` et la copie ne peut
    donc pas faire tronquer la cible du lien.
    """
    try:
        descriptor = os.open(
            lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
        )
    except OSError:
        raise HookError from None
    source_descriptor = -1
    try:
        try:
            source_descriptor = os.open(
                index_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError:
            raise HookError from None
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise HookError
        with os.fdopen(source_descriptor, "rb", closefd=True) as source:
            source_descriptor = -1
            with os.fdopen(descriptor, "wb", closefd=True) as target:
                descriptor = -1
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
        os.chmod(lock_path, 0o600)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(lock_path)
        raise
    finally:
        if source_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(source_descriptor)
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _restage_paths(
    root: Path,
    paths: Iterable[str],
    *,
    expected: Sequence[ConfinedPath] | None = None,
) -> int:
    """Ré-indexe le contenu exact de fichiers remédiés, sans filtre ni hook.

    Fonction **interne** : l'appelant public est :func:`apply_and_restage`,
    qui vérifie d'abord l'absence de modifications non indexées. Le verrou
    Git ``index.lock`` est pris **avant** la copie, l'index est mis à jour
    dedans puis remplacé atomiquement : ni panne médiane ni ``git add``
    concurrent ne laisse l'index réel partiellement modifié.
    """
    access = _open_repository(root)
    repository_root = access.root
    _verify_root(access)
    confined = _confined_paths(repository_root, paths)
    if expected is not None:
        frozen = {item.relative: item.absolute for item in expected}
        for item in confined:
            if frozen.get(item.relative) != item.absolute:
                raise HookError
    entries: list[tuple[str, str, str]] = []
    for item in confined:
        data, metadata = _read_regular_bounded(item.absolute)
        digest = _hash_blob(repository_root, data)
        mode = "100755" if metadata.st_mode & 0o111 else "100644"
        entries.append((mode, digest, item.relative))
    try:
        index_path = access.index_path()
    except ToolFailure:
        raise HookError from None
    lock_path = index_path.with_name(index_path.name + ".lock")
    lock_created = False
    try:
        # Protocole Git natif : prendre ``index.lock`` AVANT de copier, pour
        # qu'un ``git add`` concurrent ne puisse pas se terminer puis être
        # écrasé silencieusement par notre ``os.replace``.
        _create_locked_index_copy(index_path, lock_path)
        lock_created = True
        extra_env = {"GIT_INDEX_FILE": str(lock_path)}
        arguments = ["update-index", "--add"]
        for mode, digest, relative in entries:
            arguments.extend(["--cacheinfo", mode, digest, relative])
        completed = _run_git(
            repository_root,
            arguments,
            extra_env=extra_env,
            allowed_index_file=lock_path,
        )
        if completed.returncode != 0:
            raise HookError
        _verify_index_entries(
            repository_root,
            entries,
            extra_env=extra_env,
            allowed_index_file=lock_path,
        )
        if not stat.S_ISREG(os.lstat(lock_path).st_mode):
            raise HookError
        os.replace(lock_path, index_path)
        lock_created = False
    except OSError:
        raise HookError from None
    finally:
        if lock_created:
            with contextlib.suppress(OSError):
                os.unlink(lock_path)
    _verify_root(access)
    return len(entries)


def apply_and_restage(
    root: Path,
    paths: Iterable[str],
    apply: Callable[[], None],
) -> int:
    """Applique une remédiation puis ré-indexe les seuls fichiers modifiés.

    L'ordre est contractuel : contrôle des modifications non indexées, puis
    ``apply()``, puis ré-indexation. ``HEIMDALL_IN_HOOK=1`` est posé pendant
    l'application et la ré-indexation pour qu'un hook imbriqué ne se relance
    pas. En cas d'échec de ``apply()``, l'index n'a pas été touché.
    """
    confined = assert_no_unstaged_changes(root, paths)
    previous = os.environ.get(HEIMDALL_IN_HOOK_ENV)
    os.environ[HEIMDALL_IN_HOOK_ENV] = "1"
    try:
        apply()
        return _restage_paths(
            root,
            [item.relative for item in confined],
            expected=confined,
        )
    finally:
        if previous is None:
            os.environ.pop(HEIMDALL_IN_HOOK_ENV, None)
        else:
            os.environ[HEIMDALL_IN_HOOK_ENV] = previous


_INSTALL_MESSAGES: Final[dict[InstallOutcome, str]] = {
    InstallOutcome.INSTALLED: "hook pre-commit installé",
    InstallOutcome.UPDATED: "hook pre-commit mis à jour",
    InstallOutcome.CHAINED: "hook pre-commit installé (hook existant chaîné)",
    InstallOutcome.BACKED_UP: "hook pre-commit installé (hook existant sauvegardé)",
}

_UNINSTALL_MESSAGES: Final[dict[UninstallOutcome, str]] = {
    UninstallOutcome.REMOVED: "hook pre-commit désinstallé",
    UninstallOutcome.RESTORED: "hook pre-commit désinstallé (hook précédent restauré)",
    UninstallOutcome.NOT_INSTALLED: "aucun hook Heimdall à désinstaller",
}

hook_app = typer.Typer(
    name="hook",
    help="Installe ou retire le hook Git pre-commit Heimdall.",
    no_args_is_help=True,
)


@hook_app.command("install")
def hook_install(
    path: str = typer.Argument(".", help="Racine du dépôt Git."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Autoriser un hooksPath absolu hors du dépôt et du Git commun.",
    ),
) -> None:
    """Installe le hook pre-commit dans le dépôt indiqué."""
    try:
        outcome = install_hook(Path(path), force=force)
        if interpreter_inside_repository(Path(path)):
            typer.echo(
                "hook pre-commit : avertissement : interpréteur Python dans le dépôt "
                "(garantie forte = interpréteur hors du dépôt)",
                err=True,
            )
    except OutsideRepositoryError:
        typer.echo("hook pre-commit : hooksPath hors du dépôt (utiliser --force)", err=True)
        raise typer.Exit(code=2) from None
    except HookError:
        typer.echo("hook pre-commit : installation impossible", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(_INSTALL_MESSAGES[outcome])
    raise typer.Exit(code=0)


@hook_app.command("uninstall")
def hook_uninstall(
    path: str = typer.Argument(".", help="Racine du dépôt Git."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Autoriser un hooksPath absolu hors du dépôt et du Git commun.",
    ),
) -> None:
    """Retire le hook pre-commit et restaure le hook précédent."""
    try:
        outcome = uninstall_hook(Path(path), force=force)
    except OutsideRepositoryError:
        typer.echo("hook pre-commit : hooksPath hors du dépôt (utiliser --force)", err=True)
        raise typer.Exit(code=2) from None
    except HookError:
        typer.echo("hook pre-commit : désinstallation impossible", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(_UNINSTALL_MESSAGES[outcome])
    raise typer.Exit(code=0)
