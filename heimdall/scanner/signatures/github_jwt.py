"""Famille GitHub PAT et JWT (#57).

Les jetons GitHub sont ancrés sur leurs préfixes publics (ghp_, gho_, ghu_,
ghs_, ghr_, github_pat_). Le JWT est reconnu à sa forme compacte en trois
segments base64url ; chaque segment est borné pour éviter toute regex
quadratique sur un contenu piégé.
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

_CLASSIC_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_FINE_GRAINED_PAT = "github_pat_" + "11ABCDEFG0123456789_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJoZWltZGFsbC1mYWN0aWNlIiwiZXhwIjowfQ."
    "ZmFrZS1zaWduYXR1cmUtaGVpbWRhbGw"
)

RULES: Final[tuple[Rule, ...]] = (
    make_rule(
        id="github_classic_pat",
        description="Jeton GitHub classique (ghp_, gho_, ghu_, ghs_ ou ghr_ + 36 caractères).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}"
            r"(?![A-Za-z0-9_]))"
        ),
        finding_type="pat",
        keywords=(),
        positive=f'GITHUB_TOKEN = "{_CLASSIC_PAT}"',
        negative='GITHUB_TOKEN = "ghp_short"',
    ),
    make_rule(
        id="github_fine_grained_pat",
        description="Jeton GitHub fine-grained (préfixe github_pat_ + 22 à 255 caractères).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}"
            r"(?![A-Za-z0-9_]))"
        ),
        finding_type="pat",
        keywords=(),
        positive=f'GITHUB_FINE_GRAINED = "{_FINE_GRAINED_PAT}"',
        negative='GITHUB_FINE_GRAINED = "github_pat_short"',
    ),
    make_rule(
        id="jwt",
        description="JWT compact : trois segments base64url, en-tête eyJ, charge bornée à 64 Kio.",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,1024}\."
            r"[A-Za-z0-9_-]{8,65536}\.[A-Za-z0-9_-]{8,1024}(?![A-Za-z0-9_-]))"
        ),
        finding_type="jwt",
        keywords=(),
        positive=f'JWT = "{_JWT}"',
        negative='JWT = "eyJhbGciOiJIUzI1NiJ9.e30"',
    ),
)
