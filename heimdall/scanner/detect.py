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
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text, is_excluded, is_excluded_directory
from heimdall.scanner.finding import Finding, FindingSource, FindingStatus
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signature_engine import MAX_FINDINGS
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

MAX_FILE_BYTES: Final[int] = 1_048_576
MAX_PATH_LENGTH: Final[int] = 4096
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
_FIRST_CONTROL: Final[int] = 0x20
_DELETE: Final[int] = 0x7F
_UNICODE_LINE_SEPARATORS: Final[frozenset[int]] = frozenset({0x2028, 0x2029})
_SCAN_ERROR: Final[str] = "scan impossible : entrée non analysable"

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
    """Refuse un chemin qui violerait le contrat Finding v1."""
    if not relative or len(relative) > MAX_PATH_LENGTH or relative.endswith("/"):
        raise ScanError(_SCAN_ERROR)
    for character in relative:
        code = ord(character)
        if (
            character in "\\:"
            or code < _FIRST_CONTROL
            or code == _DELETE
            or code in _UNICODE_LINE_SEPARATORS
        ):
            raise ScanError(_SCAN_ERROR)
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ScanError(_SCAN_ERROR)
    return relative


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
        self._max_files = MAX_FILES if max_files is None else max_files
        self._max_bytes = MAX_TOTAL_BYTES if max_bytes is None else max_bytes
        self._max_findings = MAX_FINDINGS if max_findings is None else max_findings

    def scan(self) -> list[Finding]:
        """Analyse tout le périmètre et retourne les Findings triés.

        Toute erreur de lecture interrompt le scan : aucun résultat partiel
        n'est retourné. Le nombre de fichiers (:data:`MAX_FILES`), le volume
        total lu (:data:`MAX_TOTAL_BYTES`) et le nombre de Findings
        (:data:`MAX_FINDINGS`) sont **bornés** : au-delà, le scan est refusé
        (``ScanError``) au lieu de durer indéfiniment ou de gonfler en
        mémoire sur un dépôt adverse (#29).
        """
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
            count += 1
            if count > self._max_files:
                raise ScanError(_SCAN_ERROR)
            text, size = self._read_text(path)
            total += size
            if total > self._max_bytes:
                raise ScanError(_SCAN_ERROR)
            if text is None:
                continue
            # Le plafond Findings est vérifié à deux granularités : par
            # candidat dans `_append` (un seul fichier dense ne fait jamais
            # gonfler la liste), et ici entre fichiers (l'accumulation sur
            # tout le périmètre reste bornée).
            findings.extend(self._scan_text(text, relative))
            if len(findings) > self._max_findings:
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

    def _read_text(self, path: Path) -> tuple[str | None, int]:
        """Lit un fichier borné ; ``(None, taille)`` signifie binaire exclu.

        La taille lue est rendue pour que ``scan()`` borne le **volume total**
        analysé (#29), pas seulement chaque fichier.
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
        return decode_text(data), len(data)

    def _scan_text(self, text: str, relative: str) -> list[Finding]:
        findings: list[Finding] = []
        # Déduplication sur l'empreinte HMAC, jamais sur la valeur brute : la
        # valeur candidate est hachée à la volée puis oubliée. Deux valeurs
        # distinctes du même type restent deux Findings (un secret ne doit
        # jamais en masquer un autre) ; seule une valeur strictement
        # identique, déjà émise sur la même ligne, est dédupliquée.
        seen: set[tuple[int, str, str]] = set()
        lines = text.splitlines()
        for index, line in enumerate(lines):
            line_number = index + 1
            for match in find_signature_matches(line):
                self._append(findings, seen, match, line_number, relative)
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
                self._append(findings, seen, match, line_number, relative)
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

    def _append(
        self,
        findings: list[Finding],
        seen: set[tuple[int, str, str]],
        match: SignatureMatch,
        line_number: int,
        relative: str,
    ) -> None:
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
