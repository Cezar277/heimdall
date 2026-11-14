"""Détection locale des valeurs hex/base64 sans exclusions de contenu (#23)."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.limits import MAX_TOKEN_LENGTH
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

MIN_TOKEN_LENGTH = 16
SHORT_TOKEN_MIN = 20
SHORT_TOKEN_MAX = 22
_SCAN_ERROR = "scan impossible : entrée non analysable"

# Un caractère sentinelle au-delà du plafond : refus avant calcul d'entropie.
_TOKEN = re.compile(rf"[A-Za-z0-9_+/-]{{1,{MAX_TOKEN_LENGTH + 1}}}={{0,2}}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_HEX_FRAGMENT = re.compile(rf"[0-9a-fA-F]{{16,{MAX_TOKEN_LENGTH}}}")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    """Seuils en bits/caractère ASCII ; longueur minimale commune, ≥ 16."""

    hex_threshold: float = 3.0
    base64_threshold: float = 4.5
    min_length: int = 20
    short_token_adjustment: float = 0.65

    def __post_init__(self) -> None:
        adjustment = self.short_token_adjustment
        if (
            isinstance(adjustment, bool) or not isinstance(adjustment, (int, float))
            or not math.isfinite(adjustment) or not 0 <= adjustment <= 1
        ):
            raise ValueError("configuration d'entropie invalide")
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


def _prepare_line(
    line: str,
    config: EntropyConfig,
    preceding_matches: tuple[SignatureMatch, ...],
    deadline: float | None,
) -> tuple[list[re.Match[str]], tuple[SignatureMatch, ...]]:
    """Valide et borne les jetons avant un unique appel aux signatures."""
    _validate_input(line, config, deadline)
    if not isinstance(preceding_matches, tuple) or any(
        not isinstance(match, SignatureMatch) for match in preceding_matches
    ):
        raise ScanError(_SCAN_ERROR)
    if deadline is not None and time.monotonic() > deadline:
        raise ScanError(_SCAN_ERROR)
    # Un seul parcours lexical, avant les signatures/Shannon : refus immédiat
    # d'un jeton trop long, et conservation des seuls candidats assez longs.
    # Une ligne de micro-jetons n'accumule donc pas une liste de matches.
    tokens = [
        token
        for token in _tokens(line, deadline)
        if token.end() - token.start() >= config.min_length
    ]
    if not tokens:
        return tokens, ()
    return tokens, find_signature_matches(line)


def _entropy_matches(
    tokens: list[re.Match[str]],
    config: EntropyConfig,
    signatures: tuple[SignatureMatch, ...],
    deadline: float | None,
) -> Iterator[SignatureMatch]:
    for token in tokens:
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
        value = token.group()
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
        if (
            not hexadecimal and SHORT_TOKEN_MIN <= len(value) <= SHORT_TOKEN_MAX
            and any(char.islower() for char in value) and any(char.isupper() for char in value)
            and any(char.isdigit() for char in value)
        ):
            threshold = max(0.0, threshold - config.short_token_adjustment)
        if shannon_entropy(value.encode("ascii")) >= threshold:
            yield SignatureMatch(
                "high_entropy_hex" if hexadecimal else "high_entropy_base64",
                "entropy",
                value,
                token.start(),
                source="entropy",
            )


def find_entropy_matches(
    line: str,
    config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    preceding_matches: tuple[SignatureMatch, ...] = (),
    *,
    deadline: float | None = None,
) -> Iterator[SignatureMatch]:
    """Candidats entropie internes ; valeurs brutes à ne pas journaliser."""
    tokens, signatures = _prepare_line(line, config, preceding_matches, deadline)
    yield from _entropy_matches(tokens, config, signatures + preceding_matches, deadline)


def find_line_matches(
    line: str,
    config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
    preceding_matches: tuple[SignatureMatch, ...] = (),
    *,
    deadline: float | None = None,
) -> Iterator[SignatureMatch]:
    """Entropie puis signatures, calculées une seule fois pour cette ligne.

    Surface interne sensible : les moteurs hachent les valeurs immédiatement.
    Le préflight borné précède toujours les signatures, même sans candidat
    entropie ; la deadline est revérifiée après les signatures.
    """
    tokens, signatures = _prepare_line(line, config, preceding_matches, deadline)
    if not tokens:
        signatures = find_signature_matches(line)
        if deadline is not None and time.monotonic() > deadline:
            raise ScanError(_SCAN_ERROR)
    yield from _entropy_matches(tokens, config, signatures + preceding_matches, deadline)
    yield from signatures


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
