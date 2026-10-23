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
- en mode strict (#29), seules les exclusions **techniques** de #59 restent :
  les répertoires et fichiers tiers textuels sont parcourus.

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

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import (
    decode_text,
    has_technical_suffix,
    is_excluded,
    is_excluded_directory,
    is_known_binary,
)
from heimdall.scanner.finding import (
    MAX_PATH_LENGTH,
    Finding,
    FindingSource,
    FindingStatus,
    validate_relative_path,
)
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signature_engine import MAX_FINDINGS
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

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


def _decode_data(data: bytes, *, allow_binary_suffix: bool) -> str | None:
    """Décode le contenu ; un suffixe binaire connu sert de repli.

    Le repli n'est armé qu'en mode strict pour un nom à suffixe technique,
    et seulement pour un binaire **connu** (magie connue + ratio binaire
    ≥ 0,5). Un binaire inconnu (NUL + texte) reste fail-closed comme en
    ``--staged`` : le suffixe ne masque jamais un doute. Un texte mal nommé
    est rendu et scanné ; sans repli, ``decode_text`` reste fail-closed.
    """
    try:
        return decode_text(data)
    except ScanError:
        if allow_binary_suffix and is_known_binary(data):
            return None
        raise


def _open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _raise_walk_error(_error: OSError) -> None:
    raise ScanError(_SCAN_ERROR)


def _resolve_root(root: str | os.PathLike[str]) -> Path:
    """Résout la racine sans jamais suivre un lien symbolique.

    La racine elle-même et chacun de ses ancêtres sont vérifiés par
    ``lstat`` : un lien symbolique dans le chemin de la racine est refusé
    (``ScanError``) au lieu d'être suivi en silence. La promesse « les liens
    symboliques ne sont jamais suivis » vaut donc aussi pour la racine et
    pour le fichier unique.
    """
    try:
        absolute = Path(os.path.abspath(Path(root).expanduser()))
        for candidate in (absolute, *absolute.parents):
            if candidate.is_symlink():
                raise ScanError(_SCAN_ERROR)
        resolved = absolute.resolve(strict=True)
        # Course symlink (check-then-resolve) : si un composant a été remplacé
        # entre le `lstat` et le `resolve`, le résolu diffère du demandé et la
        # racine serait détournée hors périmètre — refus au lieu de suivre.
        if resolved != absolute:
            raise ScanError(_SCAN_ERROR)
        return resolved
    except (OSError, RuntimeError):
        raise ScanError(_SCAN_ERROR) from None


class Scanner:
    """Scanner déterministe d'une racine confinée (couche système #22/#59).

    ``root`` peut être un répertoire ou un fichier régulier explicite. La
    racine est résolue une fois, sans suivre de lien symbolique ; chaque
    fichier est ensuite vérifié à l'usage (identité de descripteur, chemin
    résolu sous la racine, refus des liens).

    Toute erreur de lecture interrompt le scan en ``ScanError`` (fail-closed) :
    aucun résultat partiel n'est jamais retourné.

    ``strict=True`` (mode strict, livré par #29 pour la CLI ``heimdall
    scan``) ne conserve que les exclusions **techniques** de #59 : les
    répertoires et fichiers tiers **textuels** (``vendor/``,
    ``third_party/``, lockfiles, ``.gitignore``…) sont alors parcourus, parce
    qu'un secret y est un secret. Le comportement par défaut (``strict=False``)
    reste la politique #59 inchangée.
    """

    __slots__ = (
        "_hasher",
        "_max_bytes",
        "_max_files",
        "_max_findings",
        "_root",
        "_single",
        "_strict",
    )

    def __init__(  # noqa: PLR0913 - bornes nommées explicites, cf. MAX_*.
        self,
        root: str | os.PathLike[str],
        *,
        hasher: SnippetHasher | None = None,
        strict: bool = False,
        max_files: int | None = None,
        max_bytes: int | None = None,
        max_findings: int | None = None,
    ) -> None:
        # Les bornes sont validées avant tout accès disque : une surcharge
        # explicite ne peut ni annuler ni relever les plafonds par défaut.
        self._max_files = _checked_bound(max_files, MAX_FILES)
        self._max_bytes = _checked_bound(max_bytes, MAX_TOTAL_BYTES)
        self._max_findings = _checked_bound(max_findings, MAX_FINDINGS)
        resolved = _resolve_root(root)
        if resolved.is_dir():
            self._root = resolved
            self._single: Path | None = None
        elif resolved.is_file():
            self._root = resolved.parent
            self._single = resolved
        else:
            raise ScanError(_SCAN_ERROR)
        self._hasher = SnippetHasher() if hasher is None else hasher
        self._strict = strict

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
        """
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
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
            # En strict, un suffixe binaire n'exclut plus à lui seul : on lit
            # d'abord le contenu, et le suffixe ne sert de repli qu'en cas
            # d'échec de décodage (binaire réel). Un texte nommé `evil.png`
            # est donc scanné comme en `--staged`.
            text, size = self._read_text(
                path,
                allow_binary_suffix=self._strict and has_technical_suffix(relative),
            )
            total += size
            if total > self._max_bytes:
                raise ScanError(_SCAN_ERROR)
            if text is None:
                continue
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
        for current, directories, filenames in os.walk(
            self._root,
            topdown=True,
            onerror=_raise_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            directories[:] = sorted(
                name
                for name in directories
                if not is_excluded_directory(name, strict=self._strict)
                and not (current_path / name).is_symlink()
            )
            for name in sorted(filenames):
                path = current_path / name
                try:
                    relative = path.relative_to(self._root).as_posix()
                except ValueError:
                    raise ScanError(_SCAN_ERROR) from None
                if is_excluded(relative, strict=self._strict):
                    continue
                try:
                    if path.is_symlink():
                        continue
                except OSError:
                    raise ScanError(_SCAN_ERROR) from None
                yield path, _validate_relative_path(relative)

    def _read_text(
        self,
        path: Path,
        *,
        allow_binary_suffix: bool = False,
    ) -> tuple[str | None, int]:
        """Lit un fichier borné ; ``(None, taille)`` signifie binaire exclu.

        La taille lue est rendue pour que ``scan()`` borne le **volume total**
        analysé (#29), pas seulement chaque fichier.

        ``allow_binary_suffix`` n'est vrai qu'en mode strict pour un fichier
        dont le nom porte un suffixe binaire connu. Le contenu est alors
        prioritaire : un texte mal nommé est rendu et scanné ; seul un échec
        de décodage (binaire réel à signature inconnue) est converti en
        exclusion technique, au lieu de faire échouer tout le scan.
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
            os.close(descriptor)
        return (
            _decode_data(data, allow_binary_suffix=allow_binary_suffix),
            len(data),
        )

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
        for index, line in enumerate(lines):
            # Contrôle périodique **intra-fichier** : un seul fichier de
            # 1 Mio dense (beaucoup de lignes ou de matches) ne doit pas
            # ignorer la deadline globale du mode arbre.
            if index % 256 == 0 and deadline is not None and time.monotonic() > deadline:
                raise ScanError(_SCAN_ERROR)
            line_number = index + 1
            for match in find_signature_matches(line):
                self._append(
                    findings,
                    seen,
                    match,
                    line_number,
                    relative,
                    deadline=deadline,
                )
            following = self._joined_window(line, lines, index)
            if following is None:
                continue
            joined, limit = following
            for match in find_signature_matches(joined):
                # Seule une correspondance qui commence dans la ligne courante
                # est retenue : une valeur située après la jonction appartient
                # à la ligne suivante et y est déjà signalée.
                if match.start >= limit:
                    continue
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
        self, line: str, lines: list[str], index: int
    ) -> tuple[str, int] | None:
        """Jointure bornée de deux lignes, pour les secrets coupés par un ``\\n``.

        La fenêtre est limitée à :data:`MULTILINE_WINDOW` octets : au-delà, un
        secret coupé n'est pas recherché (limite documentée).
        """
        if index + 1 >= len(lines):
            return None
        following = lines[index + 1]
        # Fenêtre en octets UTF-8 (doc 4 Kio), pas en caractères : l'écart
        # doc/implantation sur UTF-8 multioctets serait une borne contournable.
        if len((line + following).encode("utf-8")) > MULTILINE_WINDOW:
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
        if (
            deadline is not None
            and len(findings) % 256 == 0
            and time.monotonic() > deadline
        ):
            raise ScanError(_SCAN_ERROR)
        snippet_hash = self._hasher.hash(match.value)
        key = (line_number, match.secret_type, snippet_hash)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                file=relative,
                line=line_number,
                type=match.secret_type,
                entropy=round(shannon_entropy(match.value.encode("utf-8")), 4),
                snippet_hash=snippet_hash,
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
) -> list[Finding]:
    """Analyse ``root`` et retourne des objets :class:`Finding`.

    ``strict=True`` (mode strict de #29) ne conserve que les exclusions
    techniques de #59 : ``vendor/``, lockfiles et fichiers de contrôle sont
    alors parcourus.
    """
    return Scanner(root, hasher=hasher, strict=strict).scan()


def find_candidates(path: str) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (dépôt ou fichier).

    Retourne des dictionnaires conformes au contrat Finding v1 (#14). Lève
    ``ScanError`` dès qu'une partie du périmètre ne peut pas être analysée :
    un scan incomplet ne devient jamais une liste vide ou partielle.
    """
    return [finding.as_dict() for finding in scan(path)]
