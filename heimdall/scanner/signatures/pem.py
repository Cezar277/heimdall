"""Famille des clés privées PEM (#58).

La détection porte sur l'en-tête ``-----BEGIN ... PRIVATE KEY-----`` : c'est
lui qui distingue une clé privée d'un certificat ou d'une clé publique. Le
corps n'est pas nécessaire au Finding (aucune valeur brute n'est conservée),
et le motif reste borné à 64 caractères de qualificatif.
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"

RULES: Final[tuple[Rule, ...]] = (
    make_rule(
        id="pem_private_key",
        description=("En-tête de clé privée PEM (RSA, EC, DSA, OpenSSH, chiffrée, PGP)."),
        regex=(
            r"(?P<value>(?<![A-Za-z0-9-])-----BEGIN[A-Z0-9 ]{0,64}"
            r"PRIVATE KEY(?: BLOCK)?-----(?![A-Za-z0-9-]))"
        ),
        finding_type="pem",
        keywords=(),
        positive=f'PRIVATE_KEY = "{_PRIVATE_KEY_HEADER}"',
        negative='CERTIFICATE = "-----BEGIN CERTIFICATE-----"',
    ),
)
