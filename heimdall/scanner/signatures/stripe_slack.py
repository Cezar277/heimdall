"""Famille Stripe et Slack (#56).

Les préfixes sont ceux publiés par les fournisseurs. Les charges sont bornées
(16 à 247 caractères pour Stripe, 10 à 250 pour Slack) : une regex ne doit
jamais parcourir un contenu arbitraire sans limite supérieure.

**Couplage des bornes (invariant structurel).** La forme rotative ``xoxe.``
*porte* le jeton qu'elle enveloppe : sa charge doit donc couvrir le jeton
interne **en entier**, préfixe compris. Les deux bornes ne sont pas écrites
à la main l'une à côté de l'autre : elles sont **dérivées** des mêmes
constantes (``SLACK_PAYLOAD_MAX`` → borne du jeton interne →
``ROTATING_PAYLOAD_MAX``). Une borne qui évolue entraîne donc l'autre, et
l'invariant « la forme rotative couvre tout jeton detectable seul » ne peut
pas être rompu par une retouche locale. Il est de plus **vérifié au
chargement** du module (``_verifier_couplage``) : un registre incohérent
refuse d'être importé plutôt que de rendre un secret invisible.
"""

from __future__ import annotations

import re
from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

_STRIPE_SECRET_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
_SLACK_BOT_TOKEN = "xoxb-" + "123456789012-123456789012-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
_SLACK_APP_TOKEN = "xapp-1-A0123456789-1234567890123-" + "a1b2c3d4e5f6" * 4
_SLACK_ROTATING_TOKEN = "xoxe.xapp-1-A0123456789-1234567890123-" + "a1b2c3d4e5f6"

# --- Bornes Slack : une seule source de vérité ------------------------------

#: Charge minimale d'un jeton Slack, **après** son préfixe publié.
SLACK_PAYLOAD_MIN: Final[int] = 10
#: Charge maximale d'un jeton Slack, **après** son préfixe publié.
SLACK_PAYLOAD_MAX: Final[int] = 250
#: Longueur du plus long préfixe Slack publié : ``xoxb-``, ``xoxa-``, ``xoxp-``,
#: ``xoxr-``, ``xoxs-``, ``xapp-``, ``xwfp-`` (5 caractères).
SLACK_PREFIX_MAX: Final[int] = 5
#: Longueur **totale** d'un jeton Slack detectable seul (préfixe + charge).
SLACK_TOKEN_MIN: Final[int] = SLACK_PREFIX_MAX + SLACK_PAYLOAD_MIN
SLACK_TOKEN_MAX: Final[int] = SLACK_PREFIX_MAX + SLACK_PAYLOAD_MAX

#: Préfixe rotatif publié : ``xoxe.``.
_ROTATING_PREFIX: Final[str] = "xoxe."
#: Longueur du préfixe rotatif.
_ROTATING_PREFIX_LEN: Final[int] = len(_ROTATING_PREFIX)
#: Préfixe rotatif **échappé** pour la regex (le point est un littéral).
ROTATING_PREFIX_PATTERN: Final[str] = re.escape(_ROTATING_PREFIX)
#: Charge de la forme rotative : elle porte le jeton **entier** qu'elle
#: enveloppe (préfixe interne compris), donc sa borne est *dérivée* de celle du
#: jeton interne — jamais écrite en dur à côté.
ROTATING_PAYLOAD_MIN: Final[int] = SLACK_PAYLOAD_MIN
ROTATING_PAYLOAD_MAX: Final[int] = SLACK_TOKEN_MAX

#: Garde de neutralisation du jeton interne : le jeton `xoxb-…`/`xapp-…`/
#: `xwfp-…` contenu dans une forme rotative ancrée n'est **pas** signalé une
#: seconde fois (un secret, une empreinte, une entrée Vault). La garde est
#: un lookbehind *conditionnel à l'ancrage* du préfixe `xoxe.` :
#: `(?<!(?<![A-Za-z0-9-])xoxe\.)` — le préfixe n'est pris en compte que s'il
#: est lui-même ancré (précédé d'un caractère qui n'est ni lettre, ni chiffre,
#: ni tiret). Un préfixe **bourré** (`xxoxe.xapp-…`) n'est donc pas ancré :
#: le jeton interne reste alors un vrai secret et doit être signalé.
#:
#: Ce que la garde **ne** vérifie pas : la longueur de la charge. Elle
#: neutralise le jeton interne dès que `xoxe.` est ancré, sans regarder si la
#: forme rotative est elle-même reconnue. C'est sans effet tant que les
#: bornes sont couplées (invariant vérifié ci-dessus et figé par un test) :
#: tout jeton detectable seul est aussi detectable une fois préfixé, donc la
#: forme rotative le reconnaît. Une charge **hors** des bornes documentées
#: (au-delà de `SLACK_PAYLOAD_MAX`) n'est detectable ni seule ni préfixée :
#: c'est une limite écrite, pas un secret perdu en silence.
_GARDE_ROTATIVE: Final[str] = r"(?<!(?<![A-Za-z0-9-])xoxe\.)"


def _verifier_couplage() -> None:
    """Garde fail-closed : la forme rotative couvre le jeton interne.

    Si la forme rotative (`xoxe.`) ne pouvait pas porter un jeton que les
    règles « seul » reconnaissent, la garde qui neutralise le jeton interne
    le rendrait invisible **des deux** règles à la fois : un secret
    disparaîtrait du scan. L'invariant est donc vérifié au chargement du
    module — un registre incohérent refuse d'être importé (fail-closed).
    """
    if ROTATING_PAYLOAD_MIN > SLACK_TOKEN_MIN or ROTATING_PAYLOAD_MAX < SLACK_TOKEN_MAX:
        raise ValueError(
            "bornes Slack incohérentes : la forme rotative ne couvre pas le jeton interne"
        )


_verifier_couplage()

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
        # La garde neutralise le jeton interne d'une forme rotative : le même
        # secret ne doit pas être signalé deux fois (deux empreintes, donc
        # deux entrées Vault à révoquer pour un seul secret). Elle ne
        # neutralise que si le préfixe `xoxe.` est **ancré** : un préfixe
        # bourré (`xxoxe.xoxb-…`) ne correspond pas à la forme rotative, le
        # jeton interne reste alors un vrai secret et doit être signalé.
        # La neutralisation coïncide avec la reconnaissance de la forme
        # rotative **dans les bornes documentées** (invariant structurel
        # ci-dessus : `ROTATING_PAYLOAD_MAX` ≥ longueur totale d'un jeton
        # detectable seul) ; elle ne teste pas la longueur de la charge.
        regex=(
            rf"(?P<value>(?<![A-Za-z0-9-]){_GARDE_ROTATIVE}"
            rf"xox[abprs]-[A-Za-z0-9-]{{{SLACK_PAYLOAD_MIN},{SLACK_PAYLOAD_MAX}}}"
            rf"(?![A-Za-z0-9-]))"
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
        # Même garde conditionnelle que `slack_token` : le jeton interne n'est
        # neutralisé que si le préfixe rotatif est lui-même ancré. Un
        # bourrage du préfixe (`xxoxe.xapp-…`) ne fait pas disparaître le
        # secret. La neutralisation coïncide avec la reconnaissance de la
        # forme rotative dans les bornes documentées (voir l'invariant
        # structurel ci-dessus), sans tester la longueur de la charge.
        regex=(
            rf"(?P<value>(?<![A-Za-z0-9-]){_GARDE_ROTATIVE}"
            rf"(?:xapp|xwfp)-[A-Za-z0-9-]{{{SLACK_PAYLOAD_MIN},{SLACK_PAYLOAD_MAX}}}"
            rf"(?![A-Za-z0-9-]))"
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
        # La charge est bornée à `ROTATING_PAYLOAD_MAX` = longueur totale
        # d'un jeton detectable seul (préfixe interne compris) : la forme
        # rotative porte donc *toujours* les jetons que les règles « seul »
        # reconnaissent. Un jeton detectable seul (charge ≤
        # `SLACK_PAYLOAD_MAX`) reste donc detectable une fois préfixé — le
        # préfixe ne peut pas faire disparaître le secret en portant la
        # charge au-delà de la borne de la forme rotative.
        regex=(
            rf"(?P<value>(?<![A-Za-z0-9-]){ROTATING_PREFIX_PATTERN}"
            rf"[A-Za-z0-9-]{{{ROTATING_PAYLOAD_MIN},{ROTATING_PAYLOAD_MAX}}}"
            rf"(?![A-Za-z0-9-]))"
        ),
        finding_type="slack",
        keywords=(),
        positive=f'SLACK_ROTATING_TOKEN = "{_SLACK_ROTATING_TOKEN}"',
        negative='SLACK_ROTATING_TOKEN = "xoxe.short"',
    ),
)

__all__ = [
    "ROTATING_PAYLOAD_MAX",
    "ROTATING_PAYLOAD_MIN",
    "RULES",
    "SLACK_PAYLOAD_MAX",
    "SLACK_PAYLOAD_MIN",
    "SLACK_PREFIX_MAX",
    "SLACK_TOKEN_MAX",
    "SLACK_TOKEN_MIN",
]
