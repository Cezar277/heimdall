"""Famille Stripe et Slack (#56).

Les préfixes sont ceux publiés par les fournisseurs. Les charges sont bornées
(16 à 247 caractères pour Stripe, 10 à 250 pour Slack) : une regex ne doit
jamais parcourir un contenu arbitraire sans limite supérieure.
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

_STRIPE_SECRET_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
_SLACK_BOT_TOKEN = "xoxb-" + "123456789012-123456789012-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
_SLACK_APP_TOKEN = "xapp-1-A0123456789-1234567890123-" + "a1b2c3d4e5f6" * 4
_SLACK_ROTATING_TOKEN = "xoxe.xapp-1-A0123456789-1234567890123-" + "a1b2c3d4e5f6"

RULES: Final[tuple[Rule, ...]] = (
    make_rule(
        id="stripe_secret_key",
        description="Clé secrète ou restreinte Stripe (sk/rk + live/test + charge).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_"
            r"[A-Za-z0-9]{16,247}(?![A-Za-z0-9_]))"
        ),
        finding_type="stripe",
        keywords=(),
        positive=f'STRIPE_SECRET_KEY = "{_STRIPE_SECRET_KEY}"',
        negative='STRIPE_SECRET_KEY = "sk_live_short"',
    ),
    make_rule(
        id="slack_token",
        description="Jeton Slack bot/utilisateur historique (xoxb-, xoxa-, xoxp-, xoxr-, xoxs-).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])xox[abprs]-[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_TOKEN = "{_SLACK_BOT_TOKEN}"',
        negative='SLACK_TOKEN = "xoxb-short"',
    ),
    make_rule(
        id="slack_app_token",
        description="Jeton app-level Slack (xapp-) ou workflow (xwfp-).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9.-])(?:xapp|xwfp)-[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_APP_TOKEN = "{_SLACK_APP_TOKEN}"',
        negative='SLACK_APP_TOKEN = "xapp-short"',
    ),
    make_rule(
        id="slack_rotating_token",
        description="Jeton app-level rotatif Slack (préfixe xoxe.).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9.-])xoxe\.[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_ROTATING_TOKEN = "{_SLACK_ROTATING_TOKEN}"',
        negative='SLACK_ROTATING_TOKEN = "xoxe.short"',
    ),
)
