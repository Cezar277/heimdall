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
"""

from __future__ import annotations

import os
import shutil
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


def _git_environment(root: Path) -> dict[str, str]:
    """Environnement minimal : aucune redirection de dépôt héritée.

    ``GIT_CEILING_DIRECTORIES`` vaut le parent de la racine : Git ne
    découvre jamais un dépôt situé au-dessus du périmètre demandé (même
    garde que ``heimdall.mcp.gitdiff``). ``HOME`` pointe sur ``os.devnull`` :
    aucune configuration personnelle n'influence le verdict.
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
        "GIT_CEILING_DIRECTORIES": str(root.parent),
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


def _run_git(  # noqa: PLR0911 - refus explicite à chaque panne, jamais un skip.
    root: Path, arguments: tuple[str, ...], deadline: float | None
) -> bytes | None:
    """Exécute une commande Git figée et rend sa sortie, ou ``None``.

    ``None`` couvre tous les cas où les exclusions ne sont **pas** connues
    avec certitude (git absent, dépôt invalide, sortie trop grande, lecture
    impossible, timeout unitaire) : l'appelant doit alors parcourir tout
    l'arbre. Seule une deadline de scan dépassée lève ``ScanError``
    (fail-closed).
    """
    if _GIT is None:
        return None
    timeout = _remaining(deadline)
    try:
        process = subprocess.Popen(  # noqa: S603 # nosec B603 - argv figé, aucun shell.
            [_GIT, "-C", str(root), *_GIT_OPTIONS, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(root),
            close_fds=True,
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


#: Étiquettes rendues par ``git ls-files -t`` pour une entrée **suivie**
#: (index). ``?`` est la seule étiquette d'une entrée non suivie ; toute
#: autre étiquette inconnue fait échouer le parsing (parcours complet).
_TRACKED_TAGS: Final[frozenset[bytes]] = frozenset(
    {b"H", b"S", b"M", b"R", b"C", b"K"}
)
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


def collect_git_exclusions(
    root: str | os.PathLike[str], *, deadline: float | None = None
) -> GitExclusions | None:
    """Collecte les entrées non suivies ignorées par les ``.gitignore``.

    ``None`` signifie « exclusions inconnues » : Git absent, racine relative
    ou hors dépôt, commande en échec ou sortie hors bornes. L'appelant doit
    alors scanner **tout** l'arbre. Un ``GitExclusions`` vide signifie
    « aucune entrée ignorée », pas « rien à scanner ».

    Une **seule** commande Git rend à la fois les entrées ignorées (``?``)
    et les entrées suivies qui matchent un motif (``H``/``S``/…). Ce
    snapshot unique évite qu'un fichier ajouté à l'index entre deux appels
    ne soit à tort classé ignoré : le jeu des fichiers suivis est celui de
    la même lecture de l'index. Les fichiers suivis sont retirés des
    exclusions par défense en profondeur, et un répertoire ignoré qui
    contient un fichier suivi n'est jamais élagué.
    """
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
    raw = _run_git(
        path,
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
