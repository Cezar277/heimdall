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
- seule la base VCS est écartée.

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
from collections.abc import Iterator
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

    Seule la base VCS (``.git/``, ``.hg/``, ``.svn/``) est écartée, par
    politique et sans ``ScanError`` ; :attr:`vcs_ignored` compte les bases
    ainsi élaguées lors du dernier scan. Un fichier régulier nommé ``.git``
    (gitlink de worktree ou de sous-module) n'est **pas** une base VCS : son
    contenu est lu comme tout autre fichier.

    ``strict`` (mode strict, livré par #29 pour la CLI ``heimdall scan``)
    reste accepté pour compatibilité : seule la base VCS est écartée, quel que
    soit le mode.
    """

    __slots__ = (
        "_allowlist",
        "_hasher",
        "_entropy_config",
        "_max_bytes",
        "_max_files",
        "_max_findings",
        "_root",
        "_root_id",
        "_single",
        "_strict",
        "_traces",
        "_vcs_ignored",
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
    ) -> None:
        # Les bornes sont validées avant tout accès disque : une surcharge
        # explicite ne peut ni annuler ni relever les plafonds par défaut.
        self._max_files = _checked_bound(max_files, MAX_FILES)
        self._max_bytes = _checked_bound(max_bytes, MAX_TOTAL_BYTES)
        self._max_findings = _checked_bound(max_findings, MAX_FINDINGS)
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
        self._allowlist = allowlist if allowlist is not None else Allowlist.empty()
        self._traces: list[AllowlistTrace] = []
        self._vcs_ignored = 0

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
        élaguée par politique (compteur :attr:`vcs_ignored`) et l'historique
        n'est jamais parcouru. Un ``[]`` ne prouve donc pas un historique
        propre ; ``--staged`` couvre le contenu indexé, pas l'historique.
        """
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        # Compteur remis à zéro pour que `vcs_ignored` décrive **ce** scan, pas
        # une accumulation d'appels successifs sur la même instance.
        self._vcs_ignored = 0
        if self._single is not None:
            # Le mode fichier unique ne passe pas par `_iter_files` : la
            # racine parente est re-vérifiée ici (aucun lien suivi).
            self._recheck_root()
        # Pas de `list()` sur le périmètre : un dépôt adverse avec un très
        # grand nombre de fichiers ne doit pas OOM le hook/CI. Le tri final
        # porte sur les findings, pas sur les chemins.
        files = (
            [(self._single, _validate_relative_path(self._single.name))]
            if self._single is not None
            else self._iter_files()
        )
        findings: list[Finding] = []
        count = 0
        total = 0
        for path, relative in files:
            if deadline is not None and time.monotonic() > deadline:
                raise ScanError(_SCAN_ERROR)
            count += 1
            if count > self._max_files:
                raise ScanError(_SCAN_ERROR)
            text, size = self._read_text(path)
            total += size
            if total > self._max_bytes:
                raise ScanError(_SCAN_ERROR)
            # Le plafond Findings est vérifié à deux granularités : par
            # candidat dans `_append` (un seul fichier dense ne fait jamais
            # gonfler la liste), et ici entre fichiers (l'accumulation sur
            # tout le périmètre reste bornée).
            findings.extend(self._scan_text(text, relative, deadline=deadline))
            if len(findings) > self._max_findings:
                raise ScanError(_SCAN_ERROR)
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

    def _iter_files(self) -> Iterator[tuple[Path, str]]:
        # Re-contrôle de la racine au moment du parcours : entre la résolution
        # de ``__init__`` et l'ouverture par ``os.walk``, la racine pourrait
        # être remplacée par un lien symbolique. ``os.walk`` suivrait alors la
        # cible ; ``lstat`` refuse le lien (fail-closed).
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
                # secret y est un secret. Seule la base VCS est hors périmètre.
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
                # Aucun fichier n'est exclu par son nom : le contenu décide.
                # La base VCS est un **répertoire** déjà élaguée ci-dessus ;
                # un fichier régulier nommé `.git` (gitlink) n'est donc pas
                # classé hors périmètre et sera lu comme tout autre fichier.
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

    def _read_text(self, path: Path) -> tuple[str, int]:  # noqa: PLR0912
        """Lit un fichier borné et rend ``(texte, taille)``.

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
        chunks: list[bytes] = []
        try:
            after = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode) or after.st_size > MAX_FILE_BYTES:
                raise ScanError(_SCAN_ERROR)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ScanError(_SCAN_ERROR)
            # Même inode ne suffit pas : une troncature (ou modification)
            # entre le ``stat`` et le ``fstat`` changerait le contenu lu sans
            # changer l'identité. Refus avant toute lecture partielle.
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise ScanError(_SCAN_ERROR)
            remaining = MAX_FILE_BYTES + 1
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
            if not unchanged or len(data) > MAX_FILE_BYTES:
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
                self._traces.append(
                    AllowlistTrace(rule=rule_name, file=relative, line=line_number)
                )
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
