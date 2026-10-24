"""Détection locale des valeurs hex/base64 sans signature connue (#23).

Les correspondances brutes restent internes au moteur ; aucun I/O ici.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

MIN_TOKEN_LENGTH = 16
MAX_TOKEN_LENGTH = 4096
CONTEXT_RADIUS = 5
PREFIX_WINDOW = 256

_TOKEN = re.compile(r"[A-Za-z0-9_+/-]+={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_PUBLIC_DIGEST = re.compile(
    r"(?i)\b(?:sha(?:1|224|256|384|512)?|md5|commit|integrity|checksum)"
    r"[\"']?\s*[:=]\s*[\"']?$"
)
_DATA_URI = re.compile(r"data:[^\s\"']{0,128};base64,$")
_AWS_ASSIGNMENT = re.compile(
    r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\"']?\]?\s*[:=]"
)


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    """Seuils en bits/caractère ASCII ; longueur minimale commune, ≥ 16."""

    hex_threshold: float = 3.0
    base64_threshold: float = 4.5
    min_length: int = 20

    def __post_init__(self) -> None:
        for value, maximum in ((self.hex_threshold, 4.0), (self.base64_threshold, 6.0)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 < value <= maximum
            ):
                raise ValueError("configuration d'entropie invalide")
        if (
            type(self.min_length) is not int
            or not MIN_TOKEN_LENGTH <= self.min_length <= MAX_TOKEN_LENGTH
        ):
            raise ValueError("configuration d'entropie invalide")


DEFAULT_ENTROPY_CONFIG = EntropyConfig()


def find_entropy_matches(
    line: str,
    config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    preceding_matches: tuple[SignatureMatch, ...] = (),
) -> Iterator[SignatureMatch]:
    """Valeurs maximales, jamais des fragments artificiels d'un long jeton.

    UUID et digests explicitement étiquetés ne sont pas des signaux d'entropie.
    Ce filtre ne s'applique jamais aux signatures déterministes.
    """
    signatures = find_signature_matches(line) + preceding_matches
    for token in _TOKEN.finditer(line):
        value = token.group()
        if len(value) < config.min_length or _UUID.fullmatch(value):
            continue
        # Pas de double signal pour une signature (JWT/PEM inclus).
        if any(value in match.value or match.value in value for match in signatures):
            continue
        prefix = line[max(0, token.start() - PREFIX_WINDOW) : token.start()]
        if _PUBLIC_DIGEST.search(prefix) or value.startswith("sha512-"):
            continue
        # Les data: URI ne sont pas des identifiants de connexion.
        if _DATA_URI.search(prefix):
            continue
        hexadecimal = _HEX.fullmatch(value) is not None
        if not hexadecimal:
            body = value.rstrip("=")
            if "=" in body or ("-" in body and "+" in body):
                continue
        threshold = config.hex_threshold if hexadecimal else config.base64_threshold
        if shannon_entropy(value.encode("ascii")) >= threshold:
            yield SignatureMatch(
                "high_entropy_hex" if hexadecimal else "high_entropy_base64",
                "entropy",
                value,
                token.start(),
            )


def check_multiline_overflow(line: str) -> None:
    """Refuse une affectation AWS non reconnue si la jointure est impossible."""
    assignments = tuple(_AWS_ASSIGNMENT.finditer(line))
    if not assignments:
        return
    recognized = {
        match.start
        for match in find_signature_matches(line)
        if match.signature == "aws_secret_access_key"
    }
    if any(assignment.start() not in recognized for assignment in assignments):
        raise ScanError("scan impossible : entrée non analysable")


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Contexte sensible dont le repr masque le contenu."""

    lines: tuple[tuple[int, str], ...] = field(repr=False)


def context_lines(target: object, line_number: int) -> ScanContext:
    """Cinq lignes avant/après, numéros réels, contenu sensible non journalisable.

    Surface explicite interne destinée au triage local, distincte de Finding v1.
    Le retour ne doit jamais être sérialisé dans un rapport ni un journal.
    Les trous d'un diff restent des trous : aucun contenu n'est inventé.
    """
    # Import différé pour éviter un cycle avec l'interface du moteur.
    from heimdall.scanner.interface import DiffTarget, FileTarget  # noqa: PLC0415

    if not isinstance(target, (FileTarget, DiffTarget)):
        raise ScanError("cible de contexte invalide")
    if type(line_number) is not int or line_number < 1:
        raise ScanError("ligne de contexte invalide")
    return ScanContext(
        tuple(
            (number, text)
            for number, text in target.lignes()
            if abs(number - line_number) <= CONTEXT_RADIUS
        )
    )
