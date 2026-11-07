"""Exclusions Git **sûres** du scanner d'arbre (#59).

Une exclusion nominale est un contournement trivial : il suffit de nommer un
fichier ``evil.png``, ``package-lock.json`` ou de le placer dans ``vendor/``
pour qu'un secret ne soit plus signalé. Ce module n'exclut donc **jamais** un
fichier parce que son nom, son extension ou son répertoire « ressemble » à un
artefact. Il n'exclut que ce que Git lui-même déclare **non suivi et ignoré**
par un fichier ``.gitignore`` du dépôt :

- un fichier **suivi** est toujours scanné, même si un ``.gitignore`` le
  matche (``git add -f``) : c'est lui qui peut partir dans un commit ;
- un fichier non suivi et **non ignoré** est scanné : il peut être ajouté au
  prochain commit ;
- un fichier non suivi et **ignoré** ne peut pas partir dans un commit sans
  devenir suivi (``git add -f``), et il sera alors scanné. L'ignorer ne cache
  donc jamais un secret commité : c'est la seule exclusion automatique.

La liste est **configurable par le dépôt** : ce sont ses fichiers
``.gitignore`` (lus par Git, y compris les motifs imbriqués et les
négations). Les exclusions globales de la machine (``core.excludesFile``,
``.git/info/exclude``) ne sont **pas** lues : elles varient d'un poste à
l'autre et rendraient le verdict non déterministe. Pour les prendre en
compte, l'opérateur les recopie dans un ``.gitignore`` versionné.

Les appels Git sont confinés comme ceux du serveur MCP (#27) : binaire résolu
hors ``PATH`` hérité, argv figé, environnement reconstruit (aucun
``GIT_DIR``/``GIT_INDEX_FILE``/``GIT_WORK_TREE`` hérité), configuration
système/globale neutralisée, ``core.fsmonitor`` désactivé (il exécute une
commande du dépôt), stdin fermé, timeout et sortie bornés. Une panne de Git
n'exclut rien : le scanner retombe sur un parcours complet (il lit **plus**,
jamais moins), sauf dépassement de l'échéance qui est une erreur fail-closed.

La racine est **épinglée par descripteur** : Git reçoit ``-C /proc/self/fd/N``
(ou ``/dev/fd/N``) sur un descripteur ouvert ``O_DIRECTORY|O_NOFOLLOW`` et
vérifié par ``fstat``, jamais le chemin re-résolu. Un échange ``A → B → A`` du
chemin pendant l'appel ne peut donc pas faire lire les exclusions de ``B``.
Sur une plateforme sans descripteur de répertoire, le repli par chemin
conserve la double vérification ``lstat`` de l'appelant ; la précondition
« racine et index figés pendant le scan » y reste explicite (docs/scanner.md).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess  # nosec B404 - argv figé, aucun shell.
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import validate_relative_path


def _resolve_git() -> str | None:
    """Résout Git dans les répertoires **absolus** de ``os.defpath``.

    ``shutil.which(..., path=os.defpath)`` peut rendre un chemin relatif quand
    ``os.defpath`` contient ``.`` (cas de Windows : ``.;C:\\bin``) : exécuter
    un ``git`` fourni par le dépôt scanné serait une exécution de code
    arbitraire. Les entrées relatives sont donc ignorées, et le résultat doit
    lui-même être absolu. Aucun candidat sûr : ``None``, donc aucune exclusion
    Git et un parcours complet — jamais un skip silencieux.
    """
    for directory in os.defpath.split(os.pathsep):
        if not os.path.isabs(directory):
            continue
        candidate = shutil.which("git", path=directory)
        if candidate is not None and os.path.isabs(candidate):
            return candidate
    return None


#: Binaire Git résolu **hors** du ``PATH`` hérité : un ``PATH`` compromis ne
#: détourne pas l'exécutable. Absent du défaut système : aucune exclusion Git
#: n'est appliquée (parcours complet), jamais un skip silencieux.
_GIT: Final[str | None] = _resolve_git()

#: Timeout unitaire d'une commande Git (le scanner a sa propre deadline).
GIT_TIMEOUT_SECONDS: Final[float] = 30.0
#: Plafond de la sortie brute d'une énumération. Au-delà, le résultat est
#: abandonné : le scanner retombe sur un parcours complet, jamais sur une
#: liste tronquée qui exclurait à tort un fichier suivi.
MAX_GIT_LIST_BYTES: Final[int] = 16 * 1024 * 1024
#: Taille des blocs lus sur le tube du sous-processus.
_READ_CHUNK: Final[int] = 65_536

#: Message unique du contrat d'erreur du scanner (aucune entrée reflétée).
_ERROR: Final[str] = "scan impossible : entrée non analysable"

#: Options non négociables : neutralise la configuration locale qui exécute
#: une commande (``core.fsmonitor``) ou met en cache l'état des fichiers non
#: suivis (``core.untrackedCache``), et fige l'encodage des chemins. ``-z``
#: est ajouté par chaque commande : les noms ne sont jamais échappés.
_GIT_OPTIONS: Final[tuple[str, ...]] = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.quotepath=false",
)

#: La plateforme peut épingler une racine par descripteur de répertoire.
#: Ailleurs (Windows), le repli par chemin reste la seule option.
_ROOT_FD_SUPPORTED: Final[bool] = hasattr(os, "O_DIRECTORY")


@dataclass(frozen=True, slots=True)
class _PinnedRoot(os.PathLike[str]):
    """Racine épinglée : chemin transparent + descripteur déjà vérifié.

    Les appelants qui ne connaissent pas ce type continuent d'utiliser
    l'objet comme un chemin (``Path(root)``, ``str(root)``). Le descripteur
    n'est lu que par :func:`_run_git`, ce qui préserve la signature
    historique ``_run_git(root, arguments, deadline)`` et empêche un chemin
    re-résolu de se substituer à l'inode contrôlé.
    """

    path: Path
    descriptor: int
    root_id: tuple[int, int]

    def __fspath__(self) -> str:
        return os.fspath(self.path)

    def __str__(self) -> str:
        return str(self.path)


@dataclass(frozen=True, slots=True)
class GitExclusions:
    """Entrées non suivies qu'un ``.gitignore`` du dépôt déclare ignorées.

    Les répertoires sont stockés avec un ``/`` final (forme rendue par
    ``git ls-files --directory``). Un répertoire ignoré qui contient au moins
    un fichier suivi n'y figure pas : le parcours y entre et scanne tout son
    contenu (le scanner lit plus, jamais moins).
    """

    ignored_files: frozenset[str] = frozenset()
    ignored_dirs: frozenset[str] = frozenset()

    def skip_file(self, relative: str) -> bool:
        """Vrai si ``relative`` est un fichier non suivi et ignoré."""
        return relative in self.ignored_files

    def skip_dir(self, relative_dir: str) -> bool:
        """Vrai si ``relative_dir`` (avec ``/`` final) peut être élagué."""
        return relative_dir in self.ignored_dirs

    def is_still_excluded_by(self, current: GitExclusions) -> bool:
        """Vrai si **toutes** les exclusions initiales sont encore ignorées.

        Le scanner compare le snapshot pris avant le parcours à un second
        snapshot pris après : une entrée qui n'est plus ignorée (par exemple
        promue par ``git add -f`` pendant le scan) rend la comparaison fausse.
        Une entrée nouvellement ignorée ne change pas le verdict : elle n'a
        pas été sautée.
        """
        return (
            self.ignored_files <= current.ignored_files
            and self.ignored_dirs <= current.ignored_dirs
        )


def _open_directory(path: Path) -> int | None:
    """Ouvre un répertoire sans jamais suivre un lien, ou rend ``None``.

    ``O_DIRECTORY`` n'existe pas sur toutes les plateformes (Windows) : le
    repli par chemin reste alors utilisé par l'appelant. Un descripteur ouvert
    est vérifié par ``fstat`` pour refuser un non-répertoire.
    """
    if not _ROOT_FD_SUPPORTED:
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        return None
    return descriptor


def _directory_fd_path(descriptor: int) -> str | None:
    """Chemin magique qui désigne **ce descripteur**, jamais le chemin d'origine.

    Linux expose ``/proc/self/fd`` ; macOS/FreeBSD exposent ``/dev/fd``. Git
    reçoit ce chemin avec ``pass_fds`` : même si la racine est renommée ou
    remplacée entre l'ouverture et ``exec``, il ouvre l'inode déjà vérifié.
    Aucun de ces répertoires : ``None`` (l'appelant garde le repli par chemin).
    """
    for base in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(base):
            return f"{base}/{descriptor}"
    return None


def _fd_real_path(fd_path: str) -> str | None:
    """Chemin réel derrière un descripteur, ou ``None`` si non résolvable."""
    try:
        target = os.readlink(fd_path)
    except OSError:
        return None
    if target.endswith(" (deleted)"):
        target = target[: -len(" (deleted)")]
    return target if os.path.isabs(target) else None


def _ceiling_for(fd_path: str, root: Path) -> str:
    """Plafond de découverte Git, aligné sur la racine **réellement** ouverte.

    Sans déplacement, c'est le parent de la racine (comportement historique).
    Si la racine a été renommée, le parent réel du descripteur évite de
    laisser Git remonter au-delà de l'emplacement courant. En cas de
    résolution impossible, le parent d'origine reste le repli.
    """
    real = _fd_real_path(fd_path)
    if real is None:
        return str(root.parent)
    return str(Path(real).parent)


def _git_environment(root: Path, *, ceiling: str | None = None) -> dict[str, str]:
    """Environnement minimal : aucune redirection de dépôt héritée.

    ``GIT_CEILING_DIRECTORIES`` vaut le parent de la racine (ou le parent réel
    du descripteur épinglé) : Git ne découvre jamais un dépôt situé au-dessus
    du périmètre demandé (même garde que ``heimdall.mcp.gitdiff``). ``HOME``
    pointe sur ``os.devnull`` : aucune configuration personnelle n'influence le
    verdict.
    """
    return {
        "PATH": "",
        "HOME": os.devnull,
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_CEILING_DIRECTORIES": str(root.parent) if ceiling is None else ceiling,
    }


def _remaining(deadline: float | None) -> float:
    """Timeout du prochain appel Git, borné par la deadline du scan."""
    if deadline is None:
        return GIT_TIMEOUT_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ScanError(_ERROR)
    return min(remaining, GIT_TIMEOUT_SECONDS)


def _read_bounded(stream: IO[bytes], limit: int) -> bytes | None:
    """Lit un tube sans jamais dépasser ``limit`` octets.

    Retourne ``None`` dès que le plafond est franchi : le producteur est
    ensuite tué par l'appelant. Aucune exception de lecture ne remonte.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > limit:
                return None
            chunks.append(chunk)
    except (OSError, ValueError):
        return None


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Tue un processus Git et borne l'attente de sa disparition."""
    try:
        process.kill()
    except OSError:
        return
    try:
        process.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, OSError):
        # Processus non interruptible (D-state) ou déjà récolté : ne jamais
        # bloquer le scan.
        pass


def _run_git_command(  # noqa: PLR0911 - refus explicite à chaque panne, jamais un skip.
    command: list[str],
    *,
    environment: dict[str, str],
    pass_fds: tuple[int, ...],
    deadline: float | None,
) -> bytes | None:
    """Exécute un argv Git figé et rend sa sortie, ou ``None``.

    ``None`` couvre tous les cas où les exclusions ne sont **pas** connues
    avec certitude (git absent, dépôt invalide, sortie trop grande, lecture
    impossible, timeout unitaire) : l'appelant doit alors parcourir tout
    l'arbre. Seule une deadline de scan dépassée lève ``ScanError``
    (fail-closed).
    """
    timeout = _remaining(deadline)
    try:
        process = subprocess.Popen(  # noqa: S603 # nosec B603 - argv figé, aucun shell.
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except (OSError, ValueError):
        return None
    stdout = process.stdout
    if stdout is None:  # pragma: no cover - stdout=PIPE ne rend jamais None.
        _terminate(process)
        return None
    holder: list[bytes | None] = []

    def read_output() -> None:
        result = _read_bounded(stdout, MAX_GIT_LIST_BYTES)
        holder.append(result)
        if result is None:
            # Plafond franchi : tuer immédiatement plutôt que laisser Git
            # remplir un tube que plus personne ne lit (le ``wait`` rendrait
            # ensuite la main au timeout, 30 s inutiles).
            try:
                process.kill()
            except OSError:
                pass

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Un timeout unitaire est une panne de Git : le parcours complet est
        # plus sûr qu'une liste partielle. Seule l'échéance du scan déjà
        # franchie est une erreur fail-closed.
        timed_out = True
        _terminate(process)
    except (OSError, subprocess.SubprocessError):
        # Panne d'attente (processus déjà récolté, état invalide) : aucune
        # liste fiable, donc parcours complet. L'échéance reste fail-closed.
        _terminate(process)
        reader.join(timeout=1.0)
        if deadline is not None and time.monotonic() >= deadline:
            raise ScanError(_ERROR) from None
        return None
    reader.join(timeout=1.0)
    if timed_out:
        if deadline is not None and time.monotonic() >= deadline:
            raise ScanError(_ERROR) from None
        return None
    # Le tube est fermé à la sortie du processus ; le lecteur rend ensuite la
    # totalité des octets (ou ``None`` si le plafond a été franchi).
    if reader.is_alive() or not holder or holder[0] is None:
        if process.poll() is None:  # pragma: no cover - lecteur bloqué défensif.
            _terminate(process)
        return None
    if process.returncode != 0:
        return None
    return holder[0]


def _run_git(
    root: Path | _PinnedRoot,
    arguments: tuple[str, ...],
    deadline: float | None,
) -> bytes | None:
    """Exécute Git sur la racine, épinglée si ``root`` porte un descripteur.

    Avec un :class:`_PinnedRoot`, ``-C`` reçoit ``/proc/self/fd/N`` (ou
    ``/dev/fd/N``) et le descripteur est transmis par ``pass_fds`` : Git lit
    l'inode déjà vérifié, pas le chemin re-résolu. Sans descripteur —
    plateforme sans répertoire de descripteurs, ou appel unitaire historique
    — le chemin est utilisé et la double vérification ``lstat`` de l'appelant
    reste la garde. Un descripteur sans chemin de descripteur rend ``None``
    (parcours complet) : jamais un repli silencieux par chemin après
    épinglage.
    """
    if _GIT is None:
        return None
    descriptor = root.descriptor if isinstance(root, _PinnedRoot) else None
    path = Path(root)
    if descriptor is None:
        return _run_git_command(
            [_GIT, "-C", str(path), *_GIT_OPTIONS, *arguments],
            environment=_git_environment(path),
            pass_fds=(),
            deadline=deadline,
        )
    fd_path = _directory_fd_path(descriptor)
    if fd_path is None:
        return None
    return _run_git_command(
        [_GIT, "-C", fd_path, *_GIT_OPTIONS, *arguments],
        environment=_git_environment(path, ceiling=_ceiling_for(fd_path, path)),
        pass_fds=(descriptor,),
        deadline=deadline,
    )


#: Étiquettes rendues par ``git ls-files -t`` (Git 2.54, ``git help
#: ls-files``) : ``H`` suivi, ``S`` skip-worktree, ``M`` unmerged, ``R``
#: suppression non indexée, ``C`` modification non indexée, ``K`` conflit
#: fichier/répertoire (non suivi, mais jamais une exclusion), ``U``
#: resolve-undo. ``?`` est la seule étiquette d'une entrée non suivie. Les
#: minuscules n'apparaissent qu'avec ``-v``/``-f``, jamais avec l'argv figé
#: ci-dessus. Toute autre étiquette fait échouer le parsing (parcours complet).
_TRACKED_TAGS: Final[frozenset[bytes]] = frozenset({b"H", b"S", b"M", b"R", b"C", b"K", b"U"})
_IGNORED_TAG: Final[bytes] = b"?"


def _parse_tagged_nul_list(  # noqa: PLR0911 - refus explicite à chaque forme invalide.
    data: bytes,
) -> tuple[frozenset[str], frozenset[str]] | None:
    """Parse ``git ls-files -t -z`` en ``(ignorés, suivis)``.

    Chaque enregistrement est ``<étiquette><espace><chemin>``. Une étiquette
    ``?`` désigne une entrée non suivie et ignorée (fichier, ou répertoire
    avec un ``/`` final) ; les étiquettes de suivi désignent un fichier de
    l'index. La forme exacte de Git est conservée. Un octet non UTF-8, un
    chemin hors contrat, une étiquette inconnue ou une sortie non terminée
    par NUL rend ``None`` : le parcours complet est plus sûr qu'une exclusion
    approximative.
    """
    if not data:
        return frozenset(), frozenset()
    if not data.endswith(b"\x00"):
        return None
    ignored: set[str] = set()
    tracked: set[str] = set()
    for raw in data[:-1].split(b"\x00"):
        if raw[1:2] != b" ":
            return None
        tag = raw[:1]
        try:
            text = raw[2:].decode("utf-8")
        except UnicodeDecodeError:
            return None
        is_dir = text.endswith("/")
        candidate = text[:-1] if is_dir else text
        if not candidate:
            return None
        try:
            validate_relative_path(candidate)
        except ValueError:
            return None
        normalized = f"{candidate}/" if is_dir else candidate
        if tag == _IGNORED_TAG:
            ignored.add(normalized)
        elif tag in _TRACKED_TAGS:
            # Une entrée d'index est toujours un fichier (ou un gitlink),
            # jamais un répertoire : un suffixe ``/`` serait une sortie
            # inattendue, donc un refus.
            if is_dir:
                return None
            tracked.add(normalized)
        else:
            return None
    return frozenset(ignored), frozenset(tracked)


def _tracked_directories(tracked: frozenset[str]) -> frozenset[str]:
    """Préfixes de répertoires qui contiennent au moins un fichier suivi."""
    prefixes: set[str] = set()
    for path in tracked:
        parts = path.split("/")[:-1]
        current = ""
        for part in parts:
            current = f"{current}{part}/"
            prefixes.add(current)
    return frozenset(prefixes)


def collect_git_exclusions(  # noqa: PLR0911, PLR0912 - refus explicite à chaque panne.
    root: str | os.PathLike[str],
    *,
    deadline: float | None = None,
    root_fd: int | None = None,
    expected_root_id: tuple[int, int] | None = None,
) -> GitExclusions | None:
    """Collecte les entrées non suivies ignorées par les ``.gitignore``.

    ``None`` signifie « exclusions inconnues » : Git absent, racine relative
    ou hors dépôt, commande en échec ou sortie hors bornes. L'appelant doit
    alors scanner **tout** l'arbre. Un ``GitExclusions`` vide signifie
    « aucune entrée ignorée », pas « rien à scanner ».

    ``root_fd`` permet à l'appelant (le scanner) de fournir un descripteur
    déjà ouvert ``O_DIRECTORY|O_NOFOLLOW`` et vérifié : Git lit alors cet
    inode, jamais le chemin re-résolu. ``expected_root_id`` re-vérifie que ce
    descripteur désigne bien la racine figée ; une divergence rend ``None``
    (l'appelant décide fail-closed). Sans ``root_fd``, la fonction ouvre son
    propre descripteur ; le repli par chemin n'est utilisé que sur une
    plateforme qui n'expose pas de descripteur de répertoire (Windows). Si
    l'ouverture échoue alors que la plateforme sait épingler (lien, droits,
    course), la fonction rend ``None`` : jamais un Git relancé sur le chemin.

    Une **seule** commande Git rend à la fois les entrées ignorées (``?``)
    et les entrées suivies qui matchent un motif (``H``/``S``/…). Ce
    snapshot unique évite qu'un fichier ajouté à l'index entre deux appels
    ne soit à tort classé ignoré : le jeu des fichiers suivis est celui de
    la même lecture de l'index. Les fichiers suivis sont retirés des
    exclusions par défense en profondeur, et un répertoire ignoré qui
    contient un fichier suivi n'est jamais élagué.
    """
    pinned = root if isinstance(root, _PinnedRoot) else None
    try:
        path = Path(root)
    except (TypeError, ValueError, OSError):
        # Entrée hors contrat : aucune exclusion fiable, parcours complet.
        return None
    # Le scanner fournit déjà une racine absolue et résolue. Un appelant
    # public qui passerait un chemin relatif obtient le parcours complet :
    # ``GIT_CEILING_DIRECTORIES`` et la forme des chemins rendus par Git
    # dépendent du répertoire courant, donc aucune exclusion n'est fiable.
    if not path.is_absolute():
        return None
    descriptor = pinned.descriptor if pinned is not None else root_fd
    expected = pinned.root_id if pinned is not None else expected_root_id
    owned = False
    if descriptor is None:
        descriptor = _open_directory(path)
        if descriptor is None and _ROOT_FD_SUPPORTED:
            # L'épinglage est disponible mais a échoué : un repli par chemin
            # rouvrirait exactement la course que le descripteur ferme.
            return None
        owned = descriptor is not None
    try:
        if descriptor is not None:
            try:
                metadata = os.fstat(descriptor)
            except (OSError, TypeError, ValueError):
                return None
            identity = (metadata.st_dev, metadata.st_ino)
            if expected is None:
                # Descripteur fourni sans identité attendue : il doit désigner
                # le chemin annoncé, sinon Git lirait un autre arbre.
                try:
                    current = os.lstat(path)
                except OSError:
                    return None
                expected = (current.st_dev, current.st_ino)
            if identity != expected:
                return None
            if pinned is None:
                pinned = _PinnedRoot(path, descriptor, identity)
        raw = _run_git(
            pinned if pinned is not None else path,
            (
                "ls-files",
                "-t",
                "-z",
                "--cached",
                "--others",
                "--ignored",
                "--exclude-per-directory=.gitignore",
                "--directory",
            ),
            deadline,
        )
    finally:
        if owned and descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if raw is None:
        return None
    parsed = _parse_tagged_nul_list(raw)
    if parsed is None:
        return None
    ignored, tracked = parsed
    if not ignored:
        return GitExclusions()

    tracked_dirs = _tracked_directories(tracked)
    ignored_files: set[str] = set()
    ignored_dirs: set[str] = set()
    for entry in ignored:
        if entry.endswith("/"):
            # Un répertoire ignoré qui porte un fichier suivi n'est pas
            # élagué : on entre et on scanne tout (plus sûr que de deviner
            # quels enfants sont suivis).
            if entry not in tracked_dirs:
                ignored_dirs.add(entry)
        elif entry in tracked:
            # Défense en profondeur : une entrée suivie n'est jamais une
            # exclusion, même si une sortie Git inattendue la marquait ``?``.
            continue
        else:
            ignored_files.add(entry)
    return GitExclusions(frozenset(ignored_files), frozenset(ignored_dirs))


__all__ = [
    "GIT_TIMEOUT_SECONDS",
    "MAX_GIT_LIST_BYTES",
    "GitExclusions",
    "collect_git_exclusions",
]
