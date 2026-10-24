"""Détection locale des valeurs hex/base64 sans exclusions de contenu (#23)."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

MIN_TOKEN_LENGTH = 16
MAX_TOKEN_LENGTH = 4096
_SCAN_ERROR = "scan impossible : entrée non analysable"

# Un caractère sentinelle au-delà du plafond : refus avant calcul d'entropie.
_TOKEN = re.compile(r"[A-Za-z0-9_+/-]{1,4097}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_HEX_FRAGMENT = re.compile(r"[0-9a-fA-F]{16,4096}")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


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


def _validate_input(line: str, config: EntropyConfig, deadline: float | None) -> None:
    if not isinstance(line, str) or not isinstance(config, EntropyConfig):
        raise ScanError(_SCAN_ERROR)
    if deadline is None:
        return
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise ScanError(_SCAN_ERROR)
    try:
        finite = math.isfinite(deadline)
    except OverflowError:
        raise ScanError(_SCAN_ERROR) from None
    if not finite:
        raise ScanError(_SCAN_ERROR)


def _tokens(line: str, deadline: float | None) -> Iterator[re.Match[str]]:
    for token in _TOKEN.finditer(line):
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        if token.end() - token.start() > MAX_TOKEN_LENGTH:
            raise ScanError(_SCAN_ERROR)
        yield token


def _hex_matches(
    token: re.Match[str],
    config: EntropyConfig,
    signatures: tuple[SignatureMatch, ...],
    deadline: float | None,
) -> Iterator[SignatureMatch]:
    """Cherche les suites hex maximales même dans un jeton d'alphabet mixte.

    Le jeton a déjà passé la borne 4096 ; les affixes non hexadécimaux ne
    doivent pas imposer le seuil base64 à une charge hexadécimale.
    """
    for fragment in _HEX_FRAGMENT.finditer(token.group()):
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        value = fragment.group()
        if len(value) < config.min_length or any(value in match.value for match in signatures):
            continue
        if shannon_entropy(value.encode("ascii")) >= config.hex_threshold:
            yield SignatureMatch(
                "high_entropy_hex",
                "entropy",
                value,
                token.start() + fragment.start(),
                source="entropy",
            )


def find_entropy_matches(
    line: str,
    config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    preceding_matches: tuple[SignatureMatch, ...] = (),
    *,
    deadline: float | None = None,
) -> Iterator[SignatureMatch]:
    """Candidats internes, sans filtre digest/UUID/data URI contrôlable.

    Un jeton > 4096 caractères refuse le scan ; aucun fragment n'est ignoré.
    Une signature reconnue conserve la priorité sur son signal entropie.
    """
    _validate_input(line, config, deadline)
    if not isinstance(preceding_matches, tuple) or any(
        not isinstance(match, SignatureMatch) for match in preceding_matches
    ):
        raise ScanError(_SCAN_ERROR)
    if deadline is not None and time.monotonic() > deadline:
        raise ScanError(_SCAN_ERROR)
    # Préflight avant les regex de signatures : même un jeton de 1 Mio
    # s'arrête à la première fenêtre bornée, avant hachage ou Shannon.
    for _token in _tokens(line, deadline):
        pass
    signatures = find_signature_matches(line) + preceding_matches
    for token in _tokens(line, deadline):
        value = token.group()
        if len(value) < config.min_length:
            continue
        found_hex = False
        for match in _hex_matches(token, config, signatures, deadline):
            found_hex = True
            yield match
        if found_hex:
            continue
        if any(value in match.value or match.value in value for match in signatures):
            continue
        hexadecimal = _HEX.fullmatch(value) is not None or _UUID.fullmatch(value) is not None
        threshold = config.hex_threshold if hexadecimal else config.base64_threshold
        if shannon_entropy(value.encode("ascii")) >= threshold:
            yield SignatureMatch(
                "high_entropy_hex" if hexadecimal else "high_entropy_base64",
                "entropy",
                value,
                token.start(),
                source="entropy",
            )


def check_multiline_overflow(
    line: str,
    following: str,
    config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    *,
    deadline: float | None = None,
) -> None:
    """Refus conservateur d'une jointure incomplète, tous fournisseurs.

    Un délimiteur d'affectation sur l'une des lignes suffit à refuser :
    distinguer une affectation complète nécessiterait un parseur de langage.
    Sans affectation, un jeton de longueur candidate refuse aussi : un secret
    fragmenté peut avoir moins d'entropie que sa valeur reconstruite.
    """
    _validate_input(line, config, deadline)
    _validate_input(following, config, deadline)
    if deadline is not None and time.monotonic() > deadline:
        raise ScanError(_SCAN_ERROR)
    if any(delimiter in text for text in (line, following) for delimiter in (":", "=")):
        raise ScanError(_SCAN_ERROR)
    for text in (line, following):
        for token in _tokens(text, deadline):
            if token.end() - token.start() >= config.min_length:
                raise ScanError(_SCAN_ERROR)
