"""Détection déterministe des candidats secrets (#22).

Le scanner parcourt un dépôt (ou un fichier explicite), applique les
signatures de ``signatures`` et les exclusions de ``exclusions``, puis produit
des Findings conformes au contrat #14. Aucun appel réseau, aucune dépendance
LLM ou crypto, aucune exécution du contenu analysé.

Invariants :

- un scan incomplet lève ``ScanError`` (fail-closed, jamais une liste
  partielle) ;
- un Finding ne contient jamais la valeur candidate, seulement son empreinte
  HMAC-SHA-256 et son entropie ;
- les chemins sont relatifs, en ``/``, sans ``..`` ni segment vide ;
- les liens symboliques ne sont jamais suivis, ni dans le périmètre, ni dans
  le chemin de la racine, et les fichiers restent confinés à la racine résolue ;
- les lectures sont bornées (1 Mio) et les regex sont linéaires et bornées ;
- la base VCS est écartée, et les seules autres entrées écartées sont les
  fichiers **non suivis** qu'un ``.gitignore`` du dépôt déclare ignorés :
  un fichier suivi reste toujours lu, même si un motif le matche.

L'interface est figée par #53 : ``Finding`` est l'unique classe canonique de
``heimdall.scanner.finding`` (réexportée ici pour compatibilité historique),
et la façade ``Scanner`` de ``heimdall.scanner.interface`` reste la surface
contractuelle. Ce module est la couche système de fichiers (#22 + #59) : il
marche sur le dépôt, applique les exclusions, lit de façon bornée puis
délègue la détection ligne à ligne au registre de signatures (#54).
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from functools import partial
from pathlib import Path
from typing import Final

from heimdall.scanner.allowlist import Allowlist, AllowlistTrace
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.entropy_detection import (
    DEFAULT_ENTROPY_CONFIG,
    EntropyConfig,
    check_multiline_overflow,
    find_line_matches,
)
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import (
    decode_text,
    est_base_vcs,
    est_chemin_hors_perimetre,
)
from heimdall.scanner.finding import (
    MAX_PATH_LENGTH,
    Finding,
    FindingSource,
    FindingStatus,
    validate_relative_path,
)
from heimdall.scanner.gitignore import GitExclusions, collect_git_exclusions
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import _open_flags, _resolve_root
from heimdall.scanner.signature_engine import MAX_FINDINGS
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches


def _raise_walk_error(_error: OSError) -> None:
    raise ScanError(_SCAN_ERROR)


def _not_link(p: Path) -> bool:
    try:
        return not p.is_symlink()
    except OSError:
        raise ScanError(_SCAN_ERROR) from None


def _directory_flags() -> int:
    """Drapeaux d'ouverture d'un répertoire, sans jamais suivre un lien."""
    return _open_flags() | getattr(os, "O_DIRECTORY", 0)


MAX_FILE_BYTES: Final[int] = 1_048_576
MULTILINE_WINDOW: Final[int] = 4096
#: Plafond du nombre de fichiers analysés en une passe (#29). Au-delà, le
#: scan est **refusé** (``ScanError``) : un dépôt adverse avec 100 000 petits
#: fichiers ne doit pas faire durer une CI sans rendre de verdict.
MAX_FILES: Final[int] = 50_000
#: Plafond du volume total lu en une passe, en octets (#29). Sans lui,
#: ``MAX_FILES`` fichiers de 1 Mio feraient 50 Gio de lecture.
MAX_TOTAL_BYTES: Final[int] = 256 * 1024 * 1024
# NOTE : `MAX_FINDINGS` est défini dans `signature_engine` (couche core) et
# réexporté ici (compatibilité : `detect.MAX_FINDINGS` reste patchable par
# les tests et documenté comme borne du mode arbre).
_READ_CHUNK: Final[int] = 65_536
_SCAN_ERROR: Final[str] = "scan impossible : entrée non analysable"
_BOUNDS_ERROR: Final[str] = "bornes de scan hors contrat"

#: Traversée ancrée sur un descripteur de répertoire (``openat``/``scandir``).
#: Disponible sur POSIX ; sur une plateforme qui ne l'expose pas, le scanner
#: retombe sur le parcours par chemin, avec les mêmes gardes par fichier
#: (``_recheck_root``, ``resolve`` + ``is_relative_to``, ``O_NOFOLLOW``).
_DIR_FD_SUPPORTED: Final[bool] = (
    os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and os.scandir in os.supports_fd
)

#: Un lecteur de fichier déjà confiné : le descripteur de répertoire parent
#: (mode ancré) ou le chemin re-vérifié (repli) est capturé à l'itération.
_FileReader = Callable[[], tuple[str | None, int]]


def _checked_bound(value: int | None, default: int) -> int:
    """Normalise une borne explicite sans permettre de la désactiver.

    ``None`` retombe sur ``default`` (la constante du module, patchable par
    les tests). Une valeur explicite doit être un entier strictement positif
    et **inférieur ou égal** au plafond par défaut : un entier géant
    (``10**12``) ne peut donc pas rouvrir un scan non borné. Refus loud
    (``ValueError``) plutôt que borne silencieusement ignorée.
    """
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= default:
        raise ValueError(_BOUNDS_ERROR)
    return value


__all__ = [
    "Finding",
    "FindingSource",
    "FindingStatus",
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_FINDINGS",
    "MAX_PATH_LENGTH",
    "MAX_TOTAL_BYTES",
    "MULTILINE_WINDOW",
    "ScanError",
    "find_candidates",
    "scan",
]


def _validate_relative_path(relative: str) -> str:
    """Valide via la **garde unique** du contrat Finding v1 (#14).

    Aucune grammaire locale : la seule différence avec
    :func:`heimdall.scanner.finding.validate_relative_path` est la
    traduction de ``ValueError`` en ``ScanError`` (fail-closed du scanner).
    Une divergence future entre les deux couches est ainsi impossible.
    """
    try:
        return validate_relative_path(relative)
    except ValueError:
        raise ScanError(_SCAN_ERROR) from None


def _decode_data(data: bytes) -> str:
    """Décode le contenu ; un binaire connu est refusé (fail-closed)."""
    text = decode_text(data)
    if text is None:
        raise ScanError(_SCAN_ERROR)
    return text


class Scanner:
    """Scanner déterministe d'une racine confinée (couche système #22/#59).

    ``root`` peut être un répertoire ou un fichier régulier explicite. La
    racine est résolue une fois, sans suivre de lien symbolique ; chaque
    fichier est ensuite vérifié à l'usage (identité de descripteur, chemin
    résolu sous la racine, refus des liens).

    Toute erreur de lecture interrompt le scan en ``ScanError`` (fail-closed) :
    aucun résultat partiel n'est jamais retourné.

    Seule la base VCS (``.git/``, ``.hg/``, ``.svn/``) est écartée par
    politique et sans ``ScanError`` ; :attr:`vcs_ignored` compte les bases
    ainsi élaguées lors du dernier scan. Un fichier régulier nommé ``.git``
    (gitlink de worktree ou de sous-module) n'est **pas** une base VCS : son
    contenu est lu comme tout autre fichier. Les entrées **non suivies** et
    ignorées par un ``.gitignore`` du dépôt sont également écartées
    (:attr:`git_ignored`), mais jamais un fichier suivi : voir
    ``respect_gitignore``.

    ``strict`` (mode strict, livré par #29 pour la CLI ``heimdall scan``)
    reste accepté pour compatibilité : seule la base VCS est écartée, quel que
    soit le mode.

    ``respect_gitignore`` (défaut ``True``) active les **exclusions Git sûres**
    de #59 : un fichier non suivi qu'un ``.gitignore`` du dépôt déclare
    ignoré n'est pas lu. Un fichier **suivi** reste toujours scanné, même si
    un ``.gitignore`` le matche (``git add -f``) : aucun nom ne peut donc
    cacher un secret qui peut partir dans un commit. Une panne de Git
    (binaire absent, dépôt invalide) désactive ces exclusions et parcourt tout
    l'arbre — le scanner lit plus, jamais moins.
    """

    __slots__ = (
        "_allowlist",
        "_hasher",
        "_entropy_config",
        "_files_scanned",
        "_git_exclusions",
        "_git_ignored",
        "_max_bytes",
        "_max_files",
        "_max_findings",
        "_max_file_bytes",
        "_skipped_files",
        "_root",
        "_root_id",
        "_single",
        "_strict",
        "_traces",
        "_vcs_ignored",
        "_respect_gitignore",
    )

    def __init__(  # noqa: PLR0913 - bornes nommées explicites, cf. MAX_*.
        self,
        root: str | os.PathLike[str],
        *,
        hasher: SnippetHasher | None = None,
        entropy_config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
        strict: bool = False,
        max_files: int | None = None,
        max_bytes: int | None = None,
        max_findings: int | None = None,
        allowlist: Allowlist | None = None,
        max_file_bytes: int | None = None,
        skipped_files: list[str] | None = None,
        respect_gitignore: bool = True,
    ) -> None:
        # Un booléen strict : une chaîne ou un entier ne doit jamais activer
        # ou désactiver les exclusions par accident.
        if not isinstance(respect_gitignore, bool):
            raise ValueError("politique d'exclusions Git invalide")
        # Les bornes sont validées avant tout accès disque : une surcharge
        # explicite ne peut ni annuler ni relever les plafonds par défaut.
        self._max_files = _checked_bound(max_files, MAX_FILES)
        self._max_bytes = _checked_bound(max_bytes, MAX_TOTAL_BYTES)
        self._max_findings = _checked_bound(max_findings, MAX_FINDINGS)
        self._max_file_bytes = _checked_bound(max_file_bytes, MAX_FILE_BYTES)
        self._skipped_files = skipped_files
        resolved = _resolve_root(root)
        try:
            resolved_stat = os.lstat(resolved)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        if stat.S_ISDIR(resolved_stat.st_mode):
            self._root = resolved
            self._single: Path | None = None
        elif stat.S_ISREG(resolved_stat.st_mode):
            self._root = resolved.parent
            self._single = resolved
        else:
            raise ScanError(_SCAN_ERROR)
        # Identité de la racine **effectivement parcourue** (le parent en mode
        # fichier unique), figée à la construction : `_recheck_root` refuse
        # qu'elle soit remplacée par un autre répertoire au même chemin.
        try:
            root_stat = os.lstat(self._root)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ScanError(_SCAN_ERROR)
        self._root_id = (root_stat.st_dev, root_stat.st_ino)
        self._hasher = SnippetHasher() if hasher is None else hasher
        if not isinstance(entropy_config, EntropyConfig):
            raise ValueError("configuration d'entropie invalide")
        self._entropy_config = entropy_config
        self._strict = strict
        self._respect_gitignore = respect_gitignore
        self._allowlist = allowlist if allowlist is not None else Allowlist.empty()
        self._traces: list[AllowlistTrace] = []
        self._git_exclusions: GitExclusions | None = None
        self._git_ignored = 0
        self._vcs_ignored = 0
        self._files_scanned = 0

    @property
    def traces(self) -> tuple[AllowlistTrace, ...]:
        """Traces déterministes des rejets par l'allowlist (#24)."""
        return tuple(self._traces)

    @property
    def vcs_ignored(self) -> int:
        """Nombre de bases VCS élaguées lors du dernier scan.

        La base VCS (``.git/``, ``.hg/``, ``.svn/``) n'est pas le contenu du
        dépôt : elle est écartée par politique, sans ``ScanError``. Ce
        compteur rend l'élagage **observable** : un ``[]`` ne signifie jamais
        « historique propre », seulement « rien trouvé dans le périmètre
        lu ». Pour couvrir le contenu qui va être commité, utiliser
        ``--staged`` (index git) ; l'historique déjà commité n'est jamais
        parcouru par l'arbre.
        """
        return self._vcs_ignored

    @property
    def files_scanned(self) -> int:
        """Nombre de fichiers effectivement lus lors du dernier scan.

        Un fichier n'est compté qu'après une lecture complète et vérifiée
        (identité, taille, ``mtime_ns``). Ce compteur décrit donc le
        **contenu réellement analysé**, hors base VCS élaguée. Il rend
        observable le cas d'un arbre réduit à sa base VCS (aucun fichier de
        contenu lu) sans transformer un dépôt vide en erreur : la politique
        d'élagage reste inchangée, et ``--staged`` couvre le contenu indexé.
        """
        return self._files_scanned

    @property
    def git_ignored(self) -> int:
        """Entrées non suivies ignorées par ``.gitignore`` lors du dernier scan.

        Chaque répertoire élagué compte pour **une** entrée (Git le rend
        comme une seule entrée ``--directory``), chaque fichier ignoré pour
        une. Un fichier **suivi** n'est jamais compté : il reste scanné.
        Ce compteur rend observable une exclusion qui, sans lui, produirait
        un ``[]`` indistinguable d'un arbre réellement propre. Il est remis
        à zéro à chaque scan et vaut toujours 0 avec
        ``respect_gitignore=False``.
        """
        return self._git_ignored

    def _snapshot_exclusions(self, deadline: float | None) -> GitExclusions | None:
        """Prend un snapshot Git en re-vérifiant l'identité de la racine.

        Git lit le dépôt par son chemin : un remplacement de la racine entre
        la re-vérification et cet appel pourrait faire calculer les
        exclusions sur un autre arbre. L'identité ``(st_dev, st_ino)`` est
        donc comparée **avant et après** la collecte ; toute divergence lève
        ``ScanError`` (aucun verdict sur un périmètre substitué).
        """
        try:
            before = os.lstat(self._root)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        exclusions = collect_git_exclusions(self._root, deadline=deadline)
        try:
            after = os.lstat(self._root)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        if (
            (before.st_dev, before.st_ino) != self._root_id
            or (after.st_dev, after.st_ino) != self._root_id
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ScanError(_SCAN_ERROR)
        return exclusions

    def _collect_exclusions(self, deadline: float | None) -> None:
        """Collecte les exclusions Git avant le parcours."""
        self._git_exclusions = None
        if not self._respect_gitignore or self._single is not None:
            return
        self._git_exclusions = self._snapshot_exclusions(deadline)

    def _verify_exclusions_unchanged(self, deadline: float | None) -> None:
        """Refuse un index qui a promu une entrée sautée pendant le parcours.

        Le snapshot initial fige la liste des entrées non suivies et ignorées,
        mais pas l'index lui-même : un ``git add -f`` concurrent peut rendre
        suivi un fichier déjà sauté, qui serait alors absent du rapport alors
        qu'il peut partir dans un commit (faux négatif). Un second snapshot,
        pris après le parcours, doit donc encore contenir **toutes** les
        exclusions initiales. Une divergence — ou un second snapshot
        impossible — lève ``ScanError`` : un verdict sur un état périmé ne
        vaut ni 0 ni 1. Le contrôle ne coûte rien lorsqu'aucune entrée n'a
        été sautée (rien n'a été caché).
        """
        exclusions = self._git_exclusions
        if self._git_ignored == 0 or exclusions is None:
            return
        current = self._snapshot_exclusions(deadline)
        if current is None or not exclusions.is_still_excluded_by(current):
            raise ScanError(_SCAN_ERROR)

    def _skip_git_excluded(self, relative: str, *, is_dir: bool) -> bool:
        """Vrai si l'entrée est une exclusion Git et doit être sautée.

        L'appelant a déjà classé l'entrée (``lstat``). Un fichier suivi
        n'est jamais dans les ensembles d'exclusions (Git le rend
        ``--cached``) ; la décision ne dépend donc jamais du nom.
        """
        exclusions = self._git_exclusions
        if exclusions is None:
            return False
        skipped = (
            exclusions.skip_dir(f"{relative}/") if is_dir else exclusions.skip_file(relative)
        )
        if skipped:
            self._git_ignored += 1
        return skipped

    def _recheck_root(self) -> None:
        """Re-vérifie la racine **et ses ancêtres** par ``lstat`` avant lecture.

        Entre ``__init__`` et le scan, la racine (ou son parent en mode
        fichier unique) peut avoir été remplacée par un lien symbolique. Un
        ancêtre remplacé par un lien détournerait aussi le chemin : chaque
        composant est donc contrôlé, pas seulement le dernier. L'identité
        ``(st_dev, st_ino)`` de la racine parcourue est en plus comparée à
        celle figée à la construction, pour refuser un répertoire substitué
        au même chemin même sans lien symbolique.
        """
        try:
            for candidate in (self._root, *self._root.parents):
                if stat.S_ISLNK(os.lstat(candidate).st_mode):
                    raise ScanError(_SCAN_ERROR)
            root_stat = os.lstat(self._root)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ScanError(_SCAN_ERROR)
        if (root_stat.st_dev, root_stat.st_ino) != self._root_id:
            raise ScanError(_SCAN_ERROR)

    def scan(self, *, deadline: float | None = None) -> list[Finding]:
        """Analyse tout le périmètre et retourne les Findings triés.

        Toute erreur de lecture interrompt le scan : aucun résultat partiel
        n'est retourné. Le nombre de fichiers (:data:`MAX_FILES`), le volume
        total lu (:data:`MAX_TOTAL_BYTES`) et le nombre de Findings
        (:data:`MAX_FINDINGS`) sont **bornés** : au-delà, le scan est refusé
        (``ScanError``) au lieu de durer indéfiniment ou de gonfler en
        mémoire sur un dépôt adverse (#29).

        ``deadline`` (optionnel) est une échéance ``time.monotonic()`` :
        dépassée, le scan est refusé (``ScanError``) avant de traiter le
        fichier suivant, et une dernière fois avant de rendre le résultat.
        La CLI ``heimdall scan`` l'utilise pour borner aussi le mode arbre.

        Le retour ne couvre **que** le périmètre lu : la base VCS est
        élaguée par politique (compteur :attr:`vcs_ignored`), les entrées non
        suivies ignorées par ``.gitignore`` sont écartées (compteur
        :attr:`git_ignored`) et l'historique n'est jamais parcouru. Un ``[]``
        ne prouve donc pas un historique propre ; ``--staged`` couvre le
        contenu indexé, pas l'historique. :attr:`files_scanned` indique
        combien de fichiers de contenu ont été réellement lus lors de cet
        appel.

        La racine est **ouverte** en ``O_NOFOLLOW|O_DIRECTORY`` puis
        parcourue par descripteurs (``openat``/``scandir``) : un remplacement
        de la racine ou d'un sous-répertoire entre la re-vérification et la
        lecture ne peut pas détourner le parcours vers un autre arbre. Sur
        une plateforme sans descripteurs de répertoire, le repli par chemin
        conserve les gardes par fichier (``resolve`` + ``is_relative_to`` +
        ``O_NOFOLLOW`` + identité ``dev/ino``).

        Si des entrées ``.gitignore`` ont été sautées, un second snapshot Git
        est pris **après** le parcours : une entrée devenue suivie entre
        l'instant initial et la fin du scan lève ``ScanError`` (verdict
        périmé refusé), au lieu de produire un faux négatif silencieux.
        """
        # Compteurs remis à zéro pour que `vcs_ignored`, `git_ignored` et
        # `files_scanned` décrivent **ce** scan, pas une accumulation d'appels
        # successifs sur la même instance — y compris si l'échéance refuse
        # avant lecture.
        self._vcs_ignored = 0
        self._git_ignored = 0
        self._git_exclusions = None
        self._files_scanned = 0
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        # La racine et ses ancêtres sont re-contrôlés avant toute ouverture :
        # un lien ou un répertoire substitué est refusé, même si la racine
        # est ensuite ouverte par son chemin.
        self._recheck_root()
        # Exclusions Git sûres (#59) : uniquement des entrées non suivies et
        # ignorées. Une panne de Git rend `None` et le parcours reste complet.
        self._collect_exclusions(deadline)
        findings: list[Finding]
        if _DIR_FD_SUPPORTED:
            root_descriptor = self._open_root_dir()
            try:
                entries: Iterable[tuple[str, _FileReader]]
                if self._single is not None:
                    relative = _validate_relative_path(self._single.name)
                    entries = (
                        (
                            relative,
                            partial(
                                self._read_text_at,
                                root_descriptor,
                                self._single.name,
                                relative,
                            ),
                        ),
                    )
                else:
                    entries = self._iter_files_at(root_descriptor, "")
                # Pas de `list()` sur le périmètre : un dépôt adverse avec un
                # très grand nombre de fichiers ne doit pas OOM le hook/CI.
                # Le tri final porte sur les findings, pas sur les chemins.
                findings = self._scan_entries(entries, deadline=deadline)
            finally:
                self._close_dir(root_descriptor)
        else:
            # Repli documenté pour les plateformes sans `openat`/`scandir(fd)` :
            # chaque lecture reste confinée et re-vérifiée par `_read_text`.
            path_entries: Iterable[tuple[str, _FileReader]]
            if self._single is not None:
                relative = _validate_relative_path(self._single.name)
                path_entries = ((relative, partial(self._read_text, self._single)),)
            else:
                path_entries = (
                    (relative, partial(self._read_text, path))
                    for path, relative in self._iter_files()
                )
            findings = self._scan_entries(path_entries, deadline=deadline)
        # Le snapshot initial ne figeait pas l'index : une entrée sautée peut
        # avoir été promue suivie pendant le parcours. Re-vérifier après coup
        # ferme cette course avant de rendre un verdict.
        self._verify_exclusions_unchanged(deadline)
        return findings

    def _scan_entries(
        self,
        entries: Iterable[tuple[str, _FileReader]],
        *,
        deadline: float | None,
    ) -> list[Finding]:
        """Lit et analyse des entrées ``(chemin relatif, lecteur confiné)``."""
        findings: list[Finding] = []
        count = 0
        total = 0
        try:
            for relative, reader in entries:
                if deadline is not None and time.monotonic() > deadline:
                    raise ScanError(_SCAN_ERROR)
                count += 1
                if count > self._max_files:
                    raise ScanError(_SCAN_ERROR)
                text, size = reader()
                if text is None:
                    continue
                total += size
                self._files_scanned += 1
                if total > self._max_bytes:
                    raise ScanError(_SCAN_ERROR)
                # Le plafond Findings est vérifié à deux granularités : par
                # candidat dans `_append` (un seul fichier dense ne fait jamais
                # gonfler la liste), et ici entre fichiers (l'accumulation sur
                # tout le périmètre reste bornée).
                findings.extend(self._scan_text(text, relative, deadline=deadline))
                if len(findings) > self._max_findings:
                    raise ScanError(_SCAN_ERROR)
        except RecursionError:
            # Parcours ancré récursif : un arbre d'une profondeur extrême ne
            # doit pas produire une exception brute (contrat ``ScanError``,
            # fail-closed, jamais un verdict propre).
            raise ScanError(_SCAN_ERROR) from None
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        findings.sort(
            key=lambda finding: (
                finding.file,
                finding.line,
                finding.type,
                finding.snippet_hash,
            )
        )
        return findings

    def _open_root_dir(self) -> int:
        """Ouvre la racine en ``O_NOFOLLOW|O_DIRECTORY`` et vérifie son identité.

        L'ouverture est ancrée sur un descripteur : même si un ancêtre ou la
        racine est renommé/substitué juste après, le parcours reste celui du
        répertoire effectivement ouvert. ``O_NOFOLLOW`` interdit de suivre un
        lien sur le dernier composant ; ``fstat`` refuse un non-répertoire ou
        une identité ``(st_dev, st_ino)`` différente de celle figée.
        """
        try:
            descriptor = os.open(self._root, _directory_flags())
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ScanError(_SCAN_ERROR)
            if (metadata.st_dev, metadata.st_ino) != self._root_id:
                raise ScanError(_SCAN_ERROR)
        except OSError:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise ScanError(_SCAN_ERROR) from None
        except ScanError:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        return descriptor

    @staticmethod
    def _close_dir(descriptor: int) -> None:
        """Ferme un descripteur de répertoire, en gardant le contrat d'erreur."""
        try:
            os.close(descriptor)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None

    @staticmethod
    def _list_names(dir_fd: int) -> list[str]:
        """Liste triée des noms d'un répertoire, sans suivre aucun lien."""
        try:
            with os.scandir(dir_fd) as iterator:
                return sorted(entry.name for entry in iterator)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None

    @staticmethod
    def _lstat_at(dir_fd: int, name: str) -> os.stat_result:
        """``lstat`` d'une entrée relative à un descripteur (jamais suivie)."""
        try:
            return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except (OSError, RuntimeError):
            # Une plateforme sans ``dir_fd`` lève une erreur d'exécution :
            # elle est convertie en ``ScanError`` (fail-closed, jamais propre).
            raise ScanError(_SCAN_ERROR) from None

    def _check_relative(self, relative: str) -> None:
        """Défense en profondeur du contrat de chemin (cf. ``_iter_files_at``)."""
        # Le chemin relatif doit rester représentable et ne jamais passer sous
        # une base VCS. Le parcours ancré ne peut pas produire un tel chemin ;
        # ce contrôle protège tout futur appelant et refuse un nom invalide.
        if est_chemin_hors_perimetre(relative):
            raise ScanError(_SCAN_ERROR)
        try:
            (self._root / relative).relative_to(self._root)
        except ValueError:
            raise ScanError(_SCAN_ERROR) from None
        if not _not_link(self._root / relative):
            raise ScanError(_SCAN_ERROR)

    def _iter_files_at(self, dir_fd: int, prefix: str) -> Iterator[tuple[str, _FileReader]]:
        """Parcourt un répertoire **par descripteur** (aucun chemin suivi).

        Chaque entrée est classée par ``lstat`` relatif au descripteur ; un
        sous-répertoire est ouvert en ``O_NOFOLLOW|O_DIRECTORY`` puis comparé
        à l'identité observée. Un remplacement par un lien, un autre
        répertoire ou un fichier est donc refusé avant lecture. La base VCS
        est élaguée (et comptée) ; les entrées non suivies ignorées par
        ``.gitignore`` sont aussi écartées (et comptées), mais jamais un
        fichier suivi ; tous les autres noms sont parcourus, quel que soit
        leur contenu.
        """
        directories: list[tuple[str, os.stat_result]] = []
        files: list[tuple[str, str]] = []
        for name in self._list_names(dir_fd):
            relative = f"{prefix}{name}"
            metadata = self._lstat_at(dir_fd, name)
            mode = metadata.st_mode
            # Exclusions Git (#59) : une entrée non suivie et ignorée n'est
            # jamais lue. Le prédicat porte sur l'état Git, jamais sur le nom.
            # Un lien ignoré est donc écarté sans être suivi ; un lien suivi ou
            # non ignoré reste refusé par la garde ci-dessous.
            if self._skip_git_excluded(relative, is_dir=stat.S_ISDIR(mode)):
                continue
            if stat.S_ISLNK(mode):
                # Un lien nommé comme une base VCS n'est jamais suivi : il est
                # élagué et compté comme la base elle-même. Tout autre lien est
                # refusé (fail-closed), jamais traversé.
                if est_base_vcs(name):
                    self._vcs_ignored += 1
                    continue
                raise ScanError(_SCAN_ERROR)
            if est_base_vcs(name) and stat.S_ISDIR(mode):
                self._vcs_ignored += 1
                continue
            self._check_relative(relative)
            if stat.S_ISDIR(mode):
                directories.append((name, metadata))
            else:
                files.append((name, relative))
        for name, relative in files:
            validated = _validate_relative_path(relative)
            yield validated, partial(self._read_text_at, dir_fd, name, relative)
        for name, expected in directories:
            try:
                sub_descriptor = os.open(name, _directory_flags(), dir_fd=dir_fd)
            except OSError:
                raise ScanError(_SCAN_ERROR) from None
            try:
                metadata = os.fstat(sub_descriptor)
                if not stat.S_ISDIR(metadata.st_mode) or (
                    metadata.st_dev,
                    metadata.st_ino,
                ) != (expected.st_dev, expected.st_ino):
                    raise ScanError(_SCAN_ERROR)
                yield from self._iter_files_at(sub_descriptor, f"{prefix}{name}/")
            finally:
                self._close_dir(sub_descriptor)

    def _iter_files(self) -> Iterator[tuple[Path, str]]:
        # Repli par chemin pour les plateformes sans descripteurs de
        # répertoire. Re-contrôle de la racine au moment du parcours : entre
        # la résolution de ``__init__`` et l'ouverture par ``os.walk``, la
        # racine pourrait être remplacée par un lien symbolique. ``os.walk``
        # suivrait alors la cible ; ``lstat`` refuse le lien (fail-closed).
        self._recheck_root()
        for current, directories, filenames in os.walk(
            self._root,
            topdown=True,
            onerror=_raise_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            kept: list[str] = []
            for name in sorted(directories):
                # Le nom ne décide jamais du contenu : un arbre de tiers
                # (vendor/, node_modules/, .venv/…) est parcouru, car un
                # secret y est un secret. Seule la base VCS est hors
                # périmètre par son nom ; une exclusion Git (#59) dépend de
                # l'état **suivi/ignoré**, jamais du nom seul.
                # Politique VCS assumée : la base VCS (.git/, .hg/, .svn/)
                # n'est pas le contenu du dépôt et son historique n'est jamais
                # scanné par l'arbre, par design (ce n'est pas un échec de
                # lecture : elle est élaguée sans ScanError).
                if est_base_vcs(name):
                    # L'élagage est une politique, pas un échec de lecture :
                    # il est compté pour que l'appelant distingue « aucune
                    # base VCS » de « base VCS non parcourue ». Aucun chemin
                    # ni contenu n'est exposé.
                    self._vcs_ignored += 1
                    continue
                try:
                    relative_dir = (current_path / name).relative_to(self._root).as_posix()
                except ValueError:
                    raise ScanError(_SCAN_ERROR) from None
                if self._skip_git_excluded(relative_dir, is_dir=True):
                    continue
                if not _not_link(current_path / name):
                    raise ScanError(_SCAN_ERROR)
                kept.append(name)
            directories[:] = kept
            for name in sorted(filenames):
                path = current_path / name
                try:
                    relative = path.relative_to(self._root).as_posix()
                except ValueError:
                    raise ScanError(_SCAN_ERROR) from None
                # Exclusions Git (#59) : uniquement des entrées non suivies
                # et ignorées, jamais un nom de fichier. La base VCS est un
                # **répertoire** déjà élaguée ci-dessus ; un fichier régulier
                # nommé `.git` (gitlink) n'est donc pas classé hors périmètre
                # et sera lu comme tout autre fichier.
                if self._skip_git_excluded(relative, is_dir=False):
                    continue
                # Un chemin qui mènerait encore dans une base VCS est refusé,
                # jamais sauté silencieusement. Défense en profondeur : ce
                # chemin est inatteignable via `os.walk` (le répertoire VCS
                # n'est jamais émis) ; la branche protège tout futur appelant
                # qui fournirait directement un chemin.
                if est_chemin_hors_perimetre(relative):
                    raise ScanError(_SCAN_ERROR)
                if not _not_link(path):
                    raise ScanError(_SCAN_ERROR)
                yield path, _validate_relative_path(relative)

    def _read_text(self, path: Path) -> tuple[str | None, int]:
        """Lit un fichier borné et rend ``(texte, taille)`` (repli par chemin).

        La taille lue est rendue pour que ``scan()`` borne le **volume total**
        analysé (#29), pas seulement chaque fichier. Un contenu non décodable
        lève ``ScanError`` : aucun fichier n'est ignoré silencieusement.
        """
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(self._root):
                raise ScanError(_SCAN_ERROR)
            before = os.stat(path, follow_symlinks=False)
        except (OSError, RuntimeError):
            raise ScanError(_SCAN_ERROR) from None
        if not stat.S_ISREG(before.st_mode):
            raise ScanError(_SCAN_ERROR)
        try:
            descriptor = os.open(path, _open_flags())
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        return self._read_descriptor(descriptor, before, path.relative_to(self._root).as_posix())

    def _read_text_at(self, dir_fd: int, name: str, relative: str) -> tuple[str | None, int]:
        """Lit un fichier **relatif au descripteur** du répertoire parent.

        ``openat`` + ``O_NOFOLLOW`` interdit de suivre un lien et fige le
        répertoire parent : le chemin affiché ne peut pas être redirigé vers
        un autre arbre entre l'énumération et l'ouverture. La résolution du
        chemin demandé reste contrôlée en défense en profondeur (fail-closed) ;
        elle ne décide jamais de la lecture, qui reste ancrée sur ``dir_fd``.
        """
        try:
            resolved = (self._root / relative).resolve(strict=True)
            if not resolved.is_relative_to(self._root):
                raise ScanError(_SCAN_ERROR)
            before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except (OSError, RuntimeError):
            raise ScanError(_SCAN_ERROR) from None
        if not stat.S_ISREG(before.st_mode):
            raise ScanError(_SCAN_ERROR)
        try:
            descriptor = os.open(name, _open_flags(), dir_fd=dir_fd)
        except (OSError, RuntimeError):
            raise ScanError(_SCAN_ERROR) from None
        return self._read_descriptor(descriptor, before, relative)

    def _read_descriptor(  # noqa: PLR0912 - descriptor identity and size checks
        self, descriptor: int, before: os.stat_result, relative: str
    ) -> tuple[str | None, int]:
        """Lit un descripteur déjà ouvert, vérifie son identité et le ferme.

        Avec un collecteur explicite, un fichier trop volumineux est signalé
        par son chemin relatif et ``(None, 0)``, sans lire son contenu. Les
        autres refus restent des ``ScanError``, y compris les binaires.
        """
        chunks: list[bytes] = []
        try:
            after = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode):
                raise ScanError(_SCAN_ERROR)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ScanError(_SCAN_ERROR)
            # Même inode ne suffit pas : une troncature (ou modification)
            # entre le ``stat`` et le ``fstat`` changerait le contenu lu sans
            # changer l'identité. Refus avant toute lecture partielle.
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise ScanError(_SCAN_ERROR)
            if after.st_size > self._max_file_bytes:
                if self._skipped_files is None:
                    raise ScanError(_SCAN_ERROR)
                self._skipped_files.append(relative)
                return None, 0
            remaining = self._max_file_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            final = os.fstat(descriptor)
            unchanged = (
                final.st_size == after.st_size
                and final.st_mtime_ns == after.st_mtime_ns
                and len(data) == after.st_size
            )
            if not unchanged or len(data) > self._max_file_bytes:
                raise ScanError(_SCAN_ERROR)
        except OSError:
            raise ScanError(_SCAN_ERROR) from None
        finally:
            # `os.close` peut lever `OSError` (EBADF/EINTR sur FS adverse) :
            # convertir pour garder le contrat unique `ScanError` (invariant 11).
            try:
                os.close(descriptor)
            except OSError:
                raise ScanError(_SCAN_ERROR) from None
        return _decode_data(data), len(data)

    def _scan_text(
        self,
        text: str,
        relative: str,
        *,
        deadline: float | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Déduplication sur l'empreinte HMAC, jamais sur la valeur brute : la
        # valeur candidate est hachée à la volée puis oubliée. Deux valeurs
        # distinctes du même type restent deux Findings (un secret ne doit
        # jamais en masquer un autre) ; seule une valeur strictement
        # identique, déjà émise sur la même ligne, est dédupliquée.
        seen: set[tuple[int, str, str]] = set()
        lines = text.splitlines()
        preceding: tuple[SignatureMatch, ...] = ()
        for index, line in enumerate(lines):
            # Contrôle périodique **intra-fichier** : un seul fichier de
            # 1 Mio dense (beaucoup de lignes ou de matches) ne doit pas
            # ignorer la deadline globale du mode arbre.
            if index % 256 == 0 and deadline is not None and time.monotonic() > deadline:
                raise ScanError(_SCAN_ERROR)
            line_number = index + 1
            for match in find_line_matches(
                line, self._entropy_config, preceding, deadline=deadline
            ):
                self._append(findings, seen, match, line_number, relative, deadline=deadline)
            following = self._joined_window(line, lines, index, deadline=deadline)
            if following is None:
                preceding = ()
                continue
            joined, limit = following
            # La fenêtre sert aussi à la déduplication de la ligne suivante.
            preceding = tuple(
                match for match in find_signature_matches(joined) if match.start < limit
            )
            for match in preceding:
                self._append(
                    findings,
                    seen,
                    match,
                    line_number,
                    relative,
                    deadline=deadline,
                )
        return findings

    def _joined_window(
        self, line: str, lines: list[str], index: int, *, deadline: float | None = None
    ) -> tuple[str, int] | None:
        """Jointure bornée de deux lignes, pour les secrets coupés par un ``\\n``.

        Au-delà de :data:`MULTILINE_WINDOW` octets, une affectation ou un
        jeton de longueur candidate refuse le scan au lieu d'être ignoré.
        """
        if index + 1 >= len(lines):
            return None
        following = lines[index + 1]
        # Fenêtre en octets UTF-8 (doc 4 Kio), pas en caractères : l'écart
        # doc/implantation sur UTF-8 multioctets serait une borne contournable.
        if len((line + following).encode("utf-8")) > MULTILINE_WINDOW:
            check_multiline_overflow(line, following, self._entropy_config, deadline=deadline)
            return None
        return line + following, len(line)

    def _append(  # noqa: PLR0913 - contexte de scan explicite (findings, seen…).
        self,
        findings: list[Finding],
        seen: set[tuple[int, str, str]],
        match: SignatureMatch,
        line_number: int,
        relative: str,
        *,
        deadline: float | None = None,
    ) -> None:
        # Une seule ligne peut porter des milliers de matches : le contrôle
        # par ligne ne suffit pas, on vérifie aussi périodiquement par
        # candidat (tous les 256) avant le hachage HMAC.
        if deadline is not None and len(findings) % 256 == 0 and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        snippet_hash = self._hasher.hash(match.value)
        key = (line_number, match.secret_type, snippet_hash)
        if key in seen:
            return
        seen.add(key)

        # Allowlist déterministe (#24) : écarte les cas évidents sans passer
        # par le LLM. Chaque rejet émet une trace traçable (règle, fichier, ligne).
        if not self._allowlist.is_empty():
            rule_name = self._allowlist.evaluate(
                value=match.value,
                file=relative,
                line=line_number,
                secret_type=match.secret_type,
            )
            if rule_name is not None:
                self._traces.append(AllowlistTrace(rule=rule_name, file=relative, line=line_number))
                return

        findings.append(
            Finding(
                file=relative,
                line=line_number,
                type=match.secret_type,
                entropy=round(shannon_entropy(match.value.encode("utf-8")), 4),
                snippet_hash=snippet_hash,
                source=match.source,
            )
        )
        if len(findings) > self._max_findings:
            # Compteur vérifié **par candidat**, pas par fichier : un seul
            # fichier dense (une ligne d'1 Mio bourrée de matches) ne fait
            # jamais gonfler la liste avant le refus (#29). Fail-fast : la
            # liste est abandonnée avec le scan, jamais triée ni rendue.
            raise ScanError(_SCAN_ERROR)


def scan(
    root: str | os.PathLike[str],
    *,
    hasher: SnippetHasher | None = None,
    strict: bool = False,
    entropy_config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    allowlist: Allowlist | None = None,
) -> list[Finding]:
    """Analyse ``root`` et retourne des objets :class:`Finding`.

    ``strict`` (mode strict de #29) reste accepté pour compatibilité : seule
    la base VCS est écartée, quel que soit le mode.
    """
    return Scanner(
        root, hasher=hasher, strict=strict, entropy_config=entropy_config, allowlist=allowlist
    ).scan()


def find_candidates(
    path: str,
    *,
    entropy_config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    allowlist: Allowlist | None = None,
) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (dépôt ou fichier).

    Retourne des dictionnaires conformes au contrat Finding v1 (#14). Lève
    ``ScanError`` dès qu'une partie du périmètre ne peut pas être analysée :
    un scan incomplet ne devient jamais une liste vide ou partielle.
    """
    return [
        finding.as_dict()
        for finding in scan(path, entropy_config=entropy_config, allowlist=allowlist)
    ]
