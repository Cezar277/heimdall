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
- les liens symboliques ne sont jamais suivis et les fichiers restent confinés
  à la racine résolue ;
- les lectures sont bornées (1 Mio) et les regex sont linéaires et bornées.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import is_binary, is_excluded, is_excluded_directory
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signatures import find_signature_matches

FindingStatus = Literal["detecte", "confirme", "vaulte", "rote", "faux_positif"]
FindingSource = Literal["regex", "entropy", "llm"]

MAX_FILE_BYTES: Final[int] = 1_048_576
MAX_PATH_LENGTH: Final[int] = 4096
_READ_CHUNK: Final[int] = 65_536
_FIRST_CONTROL: Final[int] = 0x20
_DELETE: Final[int] = 0x7F
_UNICODE_LINE_SEPARATORS: Final[frozenset[int]] = frozenset({0x2028, 0x2029})
_SCAN_ERROR: Final[str] = "scan impossible : entrée non analysable"


@dataclass(frozen=True, slots=True)
class Finding:
    """Résultat sans valeur brute, conforme à ``schemas/finding.schema.json``."""

    file: str
    line: int
    type: str
    entropy: float
    snippet_hash: str
    status: FindingStatus = "detecte"
    source: FindingSource = "regex"

    def as_dict(self) -> dict[str, object]:
        """Représentation sérialisable, champs du contrat Finding v1."""
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "entropy": self.entropy,
            "snippet_hash": self.snippet_hash,
            "status": self.status,
            "source": self.source,
        }


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


class Scanner:
    """Scanner déterministe d'une racine confinée.

    ``root`` peut être un répertoire ou un fichier régulier explicite. La
    racine est résolue une fois ; chaque fichier est ensuite vérifié à l'usage
    (identité de descripteur, chemin résolu sous la racine, refus des liens).
    """

    __slots__ = ("_hasher", "_root", "_single")

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        hasher: SnippetHasher | None = None,
    ) -> None:
        try:
            resolved = Path(root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            raise ScanError(_SCAN_ERROR) from None
        if resolved.is_dir():
            self._root = resolved
            self._single: Path | None = None
        elif resolved.is_file():
            self._root = resolved.parent
            self._single = resolved
        else:
            raise ScanError(_SCAN_ERROR)
        self._hasher = SnippetHasher() if hasher is None else hasher

    def scan(self) -> list[Finding]:
        """Analyse tout le périmètre et retourne les Findings triés.

        Toute erreur de lecture interrompt le scan : aucun résultat partiel
        n'est retourné.
        """
        files = (
            [(self._single, _validate_relative_path(self._single.name))]
            if self._single is not None
            else list(self._iter_files())
        )
        findings: list[Finding] = []
        for path, relative in files:
            text = self._read_text(path)
            if text is None:
                continue
            findings.extend(self._scan_text(text, relative))
        findings.sort(key=lambda finding: (finding.file, finding.line, finding.type))
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
                if not is_excluded_directory(name) and not (current_path / name).is_symlink()
            )
            for name in sorted(filenames):
                path = current_path / name
                try:
                    relative = path.relative_to(self._root).as_posix()
                except ValueError:
                    raise ScanError(_SCAN_ERROR) from None
                if is_excluded(relative):
                    continue
                try:
                    if path.is_symlink():
                        continue
                except OSError:
                    raise ScanError(_SCAN_ERROR) from None
                yield path, _validate_relative_path(relative)

    def _read_text(self, path: Path) -> str | None:
        """Lit un fichier borné ; ``None`` signifie binaire exclu."""
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
        if is_binary(data):
            return None
        return data.decode("utf-8", errors="replace")

    def _scan_text(self, text: str, relative: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in find_signature_matches(line):
                key = (line_number, match.secret_type)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        file=relative,
                        line=line_number,
                        type=match.secret_type,
                        entropy=round(shannon_entropy(match.value.encode("utf-8")), 4),
                        snippet_hash=self._hasher.hash(match.value),
                    )
                )
        return findings


def scan(root: str | os.PathLike[str], *, hasher: SnippetHasher | None = None) -> list[Finding]:
    """Analyse ``root`` et retourne des objets :class:`Finding`."""
    return Scanner(root, hasher=hasher).scan()


def find_candidates(path: str) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (dépôt ou fichier).

    Retourne des dictionnaires conformes au contrat Finding v1 (#14). Lève
    ``ScanError`` dès qu'une partie du périmètre ne peut pas être analysée :
    un scan incomplet ne devient jamais une liste vide ou partielle.
    """
    return [finding.as_dict() for finding in scan(path)]
