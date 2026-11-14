"""Préfixes supplémentaires déjà reconnus par le masquage MCP (#230)."""

import re
from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

# Charges manifestement factices, construites à l'exécution et jamais émises.
PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("gitlab", "glpat-"),
    ("google_api", "AIza"),
    ("google_oauth", "ya29."),
    ("npm", "npm_"),
    ("stripe_webhook", "whsec_"),
    ("digitalocean", "dop_v1_"),
    ("shopify", "shpat_"),
)


def _rule(name: str, prefix: str) -> Rule:
    minimum = 16 if prefix == "npm_" else 8
    return make_rule(
        id=f"service_{name}",
        description=(
            f"Jeton de service à préfixe {prefix}, charge bornée de {minimum} à 256 caractères."
        ),
        regex=(
            r"(?P<value>(?<![A-Za-z0-9_])"
            + re.escape(prefix)
            + r"[A-Za-z0-9_+/=-]{"
            + str(minimum)
            + r",256}(?![A-Za-z0-9_+/=-]))"
        ),
        finding_type="service_token",
        positive=prefix + "A" * 32,
        negative=prefix + "short",
    )


RULES: Final[tuple[Rule, ...]] = tuple(_rule(name, prefix) for name, prefix in PREFIXES)
