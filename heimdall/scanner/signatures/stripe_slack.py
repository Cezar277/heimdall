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
        # `(?<!xoxe\.)` : un jeton rotatif `xoxe.xoxb-…` contient déjà un jeton
        # bot. Sans cette garde, la même clé serait signalée deux fois, sous
        # deux empreintes différentes — deux entrées Vault pour un seul secret
        # à révoquer. La garde est *précise* : elle ne vise que le préfixe
        # rotatif, pas tout point qui précéderait le jeton.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])(?<!xoxe\.)xox[abprs]-[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_TOKEN = "{_SLACK_BOT_TOKEN}"',
        negative='SLACK_TOKEN = "xoxb-short"',
    ),
    make_rule(
        id="slack_app_token",
        description=(
            "Jeton app-level Slack (xapp-) ou workflow (xwfp-). "
            "Un jeton déjà couvert par le préfixe rotatif `xoxe.` n'est pas "
            "signalé une seconde fois : c'est le même secret, pas deux."
        ),
        # `(?<!xoxe\.)` : le jeton rotatif `xoxe.xapp-…` contient un jeton
        # app-level. Sans cette garde, la même clé serait signalée deux fois,
        # sous deux empreintes différentes — deux entrées Vault pour un seul
        # secret à révoquer. La garde est *précise* : elle ne vise que le
        # préfixe rotatif, pas tout point qui précéderait le jeton.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])(?<!xoxe\.)(?:xapp|xwfp)-[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_APP_TOKEN = "{_SLACK_APP_TOKEN}"',
        negative=f'SLACK_APP_TOKEN = "{_SLACK_ROTATING_TOKEN}"',
    ),
    make_rule(
        id="slack_rotating_token",
        description="Jeton app-level rotatif Slack (préfixe xoxe.).",
        # Le lookbehind reste `(?<![A-Za-z0-9-])` : le point est un séparateur
        # légitime (`foo.xoxe.…`, un jeton collé à un préfixe de domaine ou
        # à une concaténation). Élargir la classe au point ferait perdre un
        # vrai secret après un `.` : c'est un faux négatif, pas un faux
        # positif — le motif reste ancré sur le préfixe publié `xoxe.`.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])xoxe\.[A-Za-z0-9-]{10,250}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_ROTATING_TOKEN = "{_SLACK_ROTATING_TOKEN}"',
        negative='SLACK_ROTATING_TOKEN = "xoxe.short"',
    ),
)
