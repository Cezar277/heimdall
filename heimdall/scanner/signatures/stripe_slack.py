"""Famille Stripe et Slack (#56).

Les préfixes sont ceux publiés par les fournisseurs. Les charges sont bornées
(16 à 247 caractères pour Stripe, 10 à 250 pour Slack) : une regex ne doit
jamais parcourir un contenu arbitraire sans limite supérieure.

La forme rotative ``xoxe.`` **porte** le jeton qu'elle enveloppe : sa
charge est donc bornée à 255 caractères (250 + les 5 caractères de
``xoxe.``). Ce couplage est délibéré : sans lui, un jeton detectable seul
pourrait devenir invisible une fois préfixé par ``xoxe.`` (le jeton interne
étant neutralisé alors que la forme rotative dépassait sa propre borne).
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
        # `(?<!(?<![A-Za-z0-9-])xoxe\.)` : un jeton rotatif `xoxe.xoxb-…`
        # contient déjà un jeton bot. Sans cette garde, la même clé serait
        # signalée deux fois, sous deux empreintes différentes — deux
        # entrées Vault pour un seul secret à révoquer. La garde est
        # *conditionnelle* : elle ne neutralise le jeton interne que si le
        # préfixe rotatif `xoxe.` est lui-même ancré (c'est-à-dire si la
        # règle `slack_rotating_token` le reconnaît). Un préfixe rotatif
        # bourré (`xxoxe.xoxb-…`) ne correspond plus à la règle rotative :
        # le jeton interne reste alors un vrai secret et doit être signalé.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])(?<!(?<![A-Za-z0-9-])xoxe\.)"
            r"xox[abprs]-[A-Za-z0-9-]{10,250}(?![A-Za-z0-9-]))"
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
        # Même garde conditionnelle que `slack_token` : le jeton interne
        # n'est neutralisé que si le préfixe rotatif est lui-même reconnu
        # par `slack_rotating_token`. Un bourrage du préfixe (`xxoxe.xapp-…`)
        # ne fait pas disparaître le secret.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])(?<!(?<![A-Za-z0-9-])xoxe\.)"
            r"(?:xapp|xwfp)-[A-Za-z0-9-]{10,250}(?![A-Za-z0-9-]))"
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
        #
        # La charge est bornée à 255 (et non 250) : la forme rotative porte
        # les 5 caractères de `xoxe.` en plus du jeton qu'elle enveloppe.
        # Un jeton detectable seul (charge ≤ 250) reste donc detectable une
        # fois préfixé — le préfixe ne peut pas faire disparaître le secret
        # en portant la charge au-delà de la borne de la forme rotative.
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])xoxe\.[A-Za-z0-9-]{10,255}"
            r"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_ROTATING_TOKEN = "{_SLACK_ROTATING_TOKEN}"',
        negative='SLACK_ROTATING_TOKEN = "xoxe.short"',
    ),
)
