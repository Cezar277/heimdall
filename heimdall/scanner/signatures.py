"""Signatures de secrets (#54) : AWS, Stripe, Slack, GitHub, JWT et PEM.

Chaque motif est linéaire et borné : aucune quantification imbriquée, aucune
borne ouverte sur un contenu arbitraire. Les valeurs sont factices par
construction dans les tests ; un Finding ne conserve jamais la valeur, seule
son empreinte HMAC est produite (voir ``hashing``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern
from typing import Final


@dataclass(frozen=True, slots=True)
class Signature:
    """Une règle identifiable : nom stable, type Finding et motif compilé."""

    name: str
    secret_type: str
    pattern: Pattern[str]


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """Valeur candidate et règle qui l'a produite (usage interne seulement)."""

    secret_type: str
    signature: str
    value: str
    start: int = 0


def _signature(name: str, secret_type: str, pattern: str) -> Signature:
    return Signature(name=name, secret_type=secret_type, pattern=re.compile(pattern))


SIGNATURES: Final[tuple[Signature, ...]] = (
    _signature(
        "aws_access_key_id",
        "aws",
        r"(?P<value>\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b)",
    ),
    _signature(
        "aws_secret_access_key",
        "aws",
        r"(?i:aws_secret_access_key)\s*[:=]\s*[\"']?"
        r"(?P<value>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
    ),
    _signature(
        "stripe_secret_key",
        "stripe",
        r"(?P<value>\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247}\b)",
    ),
    _signature(
        "slack_token",
        "slack",
        r"(?P<value>\bxox[abprs]-[A-Za-z0-9-]{10,250}\b)",
    ),
    _signature(
        "slack_app_token",
        "slack",
        r"(?P<value>\b(?<!\.)(?:xapp|xwfp)-[A-Za-z0-9-]{10,250}\b)",
    ),
    _signature(
        "slack_rotating_token",
        "slack",
        r"(?P<value>\bxoxe\.[A-Za-z0-9-]{10,250}\b)",
    ),
    _signature(
        "github_classic_pat",
        "pat",
        r"(?P<value>\bgh[pousr]_[A-Za-z0-9]{36}\b)",
    ),
    _signature(
        "github_fine_grained_pat",
        "pat",
        r"(?P<value>\bgithub_pat_[A-Za-z0-9_]{22,255}\b)",
    ),
    _signature(
        "jwt",
        "jwt",
        r"(?P<value>\beyJ[A-Za-z0-9_-]{8,1024}\."
        r"[A-Za-z0-9_-]{8,65536}\.[A-Za-z0-9_-]{8,1024}\b)",
    ),
    _signature(
        "pem_private_key",
        "pem",
        r"(?P<value>-----BEGIN[A-Z0-9 ]{0,64}PRIVATE KEY(?: BLOCK)?-----)",
    ),
)


def find_signature_matches(line: str) -> tuple[SignatureMatch, ...]:
    """Signatures présentes dans une ligne, dédupliquées par (type, valeur)."""
    matches: list[SignatureMatch] = []
    seen: set[tuple[str, str]] = set()
    for signature in SIGNATURES:
        for match in signature.pattern.finditer(line):
            key = (signature.secret_type, match.group("value"))
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                SignatureMatch(
                    secret_type=signature.secret_type,
                    signature=signature.name,
                    value=match.group("value"),
                    start=match.start(),
                )
            )
    return tuple(matches)
