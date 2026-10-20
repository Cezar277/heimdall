"""Sortie Finding v1 : le format commun au scanner, au MCP, à la CLI et au Vault.

Le schéma de référence est ``schemas/finding.schema.json`` (ticket #14,
contractualisé dans ``docs/contracts/finding.md`` et dans
``docs/adr/001-finding-et-etats.md``). Ce module en est le **gardien côté
code** : un ``Finding`` construit ici est conforme au schéma *par
construction*, et un objet non conforme ne peut pas exister.

Règle de secrecy (invariant 8 et piège du ticket #53) : **aucun champ ne
porte la valeur du secret**. ``snippet_hash`` est une empreinte
HMAC-SHA-256 (ADR-001) et ``entropy`` une métadonnée. Les messages d'erreur
sont statiques : la valeur rejetée n'est jamais reflétée, elle ne se retrouverait
pas dans un journal.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast, get_args

from heimdall.scanner.errors import InvalidFinding

FindingStatus = Literal["detecte", "confirme", "vaulte", "rote", "faux_positif"]
FindingSource = Literal["regex", "entropy", "llm"]

#: Les sept champs du contrat Finding v1, dans l'ordre du schéma (#14).
FINDING_FIELDS: Final[tuple[str, ...]] = (
    "file",
    "line",
    "type",
    "entropy",
    "snippet_hash",
    "status",
    "source",
)

#: Longueur maximale du chemin relatif au dépôt (contrat #14).
MAX_PATH_LENGTH: Final[int] = 4096
#: Longueur maximale de l'identifiant de catégorie (contrat #14).
MAX_TYPE_LENGTH: Final[int] = 64
#: Entropie maximale, en bits par octet (contrat #14).
MAX_ENTROPY: Final[float] = 8.0
#: Longueur de l'empreinte HMAC-SHA-256 en hexadécimal (contrat #14).
HASH_LENGTH: Final[int] = 64

#: États autorisés par la machine d'états du contrat #14.
FINDING_STATUSES: Final[frozenset[str]] = frozenset(get_args(FindingStatus))
#: Origines autorisées par le contrat #14 (un signal, jamais une autorité).
FINDING_SOURCES: Final[frozenset[str]] = frozenset(get_args(FindingSource))
#: Origines qu'un scanner déterministe peut produire (`llm` n'en est pas une).
SCANNER_SOURCES: Final[frozenset[str]] = frozenset({"regex", "entropy"})

_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]*")
_HASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]*")

#: Caractères interdits dans un chemin : antislash (séparateur Windows),
#: deux-points (lecteur de disque) et caractères de contrôle.
_FORBIDDEN_PATH_CHARACTERS: Final[frozenset[str]] = frozenset({":", "\\"})
_FIRST_CONTROL: Final[int] = 0x20
_DELETE: Final[int] = 0x7F
#: Séparateurs de ligne Unicode : exclus comme les contrôles par le schéma.
_UNICODE_LINE_SEPARATORS: Final[frozenset[int]] = frozenset({0x2028, 0x2029})


def validate_relative_path(value: object) -> str:
    """Renvoie le chemin s'il respecte la grammaire du contrat #14.

    Graphe lexical, identique à celui du schéma : chemin **relatif** au
    dépôt, séparateurs ``/``, segments non vides, aucun segment ``.`` ou
    ``..``, aucun caractère de contrôle, aucune fin de ligne Unicode. La
    résolution réelle (liens symboliques) reste du ressort du consommateur :
    ici, on refuse un chemin qu'on ne peut pas interpréter sans ambiguïté.

    Lève ``ValueError`` (message statique) si le chemin n'est pas conforme.
    """
    if not isinstance(value, str):
        raise ValueError("chemin non conforme au contrat Finding v1")
    if not 1 <= len(value) <= MAX_PATH_LENGTH:
        raise ValueError("chemin non conforme au contrat Finding v1")
    for character in value:
        code = ord(character)
        if (
            character in _FORBIDDEN_PATH_CHARACTERS
            or code < _FIRST_CONTROL
            or code == _DELETE
            or code in _UNICODE_LINE_SEPARATORS
        ):
            raise ValueError("chemin non conforme au contrat Finding v1")
    for segment in value.split("/"):
        # Segment vide : chemin absolu, double séparateur ou séparateur final.
        # Segment "." ou ".." : traversée hors du dépôt.
        if segment in ("", ".", ".."):
            raise ValueError("chemin non conforme au contrat Finding v1")
    return value


def _check_file(value: object) -> None:
    try:
        validate_relative_path(value)
    except ValueError:
        raise InvalidFinding("Finding non conforme au contrat v1 : champ file") from None


def _check_line(value: object) -> None:
    # `type(...) is not int` refuse aussi les booléens : `True` vaut 1 en
    # Python, alors que le schéma JSON distingue le booléen de l'entier.
    if type(value) is not int or value < 1:
        raise InvalidFinding("Finding non conforme au contrat v1 : champ line")


def _check_type(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > MAX_TYPE_LENGTH
        or _TYPE_PATTERN.fullmatch(value) is None
    ):
        raise InvalidFinding("Finding non conforme au contrat v1 : champ type")


def _check_entropy(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidFinding("Finding non conforme au contrat v1 : champ entropy")
    # NaN et infinis sont refusés : le schéma ne sait pas les exprimer, et
    # `json.dumps` en produirait un « NaN » que JSON interdit.
    if not math.isfinite(value) or not 0.0 <= value <= MAX_ENTROPY:
        raise InvalidFinding("Finding non conforme au contrat v1 : champ entropy")


def _check_hash(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != HASH_LENGTH
        or _HASH_PATTERN.fullmatch(value) is None
    ):
        raise InvalidFinding("Finding non conforme au contrat v1 : champ snippet_hash")


def _check_status(value: object) -> None:
    if value not in FINDING_STATUSES:
        raise InvalidFinding("Finding non conforme au contrat v1 : champ status")


def _check_source(value: object) -> None:
    if value not in FINDING_SOURCES:
        raise InvalidFinding("Finding non conforme au contrat v1 : champ source")


@dataclass(frozen=True, slots=True)
class Finding:
    """Un résultat de scan, sans valeur de secret (contrat Finding v1, #14).

    Les sept champs du schéma sont obligatoires. ``status`` vaut ``detecte``
    et ``source`` ``regex`` par défaut : un Finding est *créé* par le scanner
    déterministe, il n'est jamais créé dans un état ultérieur.
    """

    file: str
    line: int
    type: str
    entropy: float
    snippet_hash: str
    status: FindingStatus = "detecte"
    source: FindingSource = "regex"

    def __post_init__(self) -> None:
        """Refuse tout Finding qui ne serait pas conforme au schéma #14."""
        _check_file(self.file)
        _check_line(self.line)
        _check_type(self.type)
        _check_entropy(self.entropy)
        _check_hash(self.snippet_hash)
        _check_status(self.status)
        _check_source(self.source)

    def as_dict(self) -> dict[str, object]:
        """Représentation sérialisable : exactement les sept champs du contrat.

        Aucun champ supplémentaire, aucune valeur de secret : c'est cette
        forme que le MCP sérialise, que la CLI affiche et que le Vault
        relit.
        """
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "entropy": self.entropy,
            "snippet_hash": self.snippet_hash,
            "status": self.status,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Finding:
        """Relit un Finding sérialisé (Vault, cache, sortie d'un autre outil).

        Les propriétés inconnues sont refusées comme le fait le schéma
        (``additionalProperties: false``), et un champ manquant aussi : un
        Finding partiel n'est pas un Finding.
        """
        if not isinstance(data, Mapping):
            raise InvalidFinding("Finding non conforme au contrat v1 : objet attendu")
        if set(data) != set(FINDING_FIELDS):
            raise InvalidFinding("Finding non conforme au contrat v1 : champs inattendus")
        # Les `cast` sont validés juste après par `__post_init__` : aucune
        # valeur n'est utilisée avant d'être vérifiée.
        return cls(
            file=cast(str, data["file"]),
            line=cast(int, data["line"]),
            type=cast(str, data["type"]),
            entropy=cast(float, data["entropy"]),
            snippet_hash=cast(str, data["snippet_hash"]),
            status=cast(FindingStatus, data["status"]),
            source=cast(FindingSource, data["source"]),
        )
