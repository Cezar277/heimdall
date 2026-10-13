"""Factices à forme réaliste pour les tests du serveur MCP (outil de test).

Règle du projet (CONTRIBUTING, DoD) : **jamais de vrai secret**, et même
les factices réalistes sont interdits dans un diff. Ces factices sont
faux **par construction** : charge dérivée en SHA-256 d'une graine
étiquetée `heimdall-factice-…`, jamais une clé émise ou fonctionnelle.
Un scanner de secrets qui les signale fait son travail ; un relecteur qui
les lit ici sait pourquoi ils sont sûrs.

Ce module est un outil de test : il n'est pas importé par le produit.
"""

import base64
import hashlib
from typing import Final


def fake_token(prefix: str, length: int = 40) -> str:
    """Factice `préfixe + charge`, jamais une clé fonctionnelle."""
    digest = hashlib.sha256(f"heimdall-factice-{prefix}".encode()).digest()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    stream = (digest * ((length // len(digest)) + 1))[:length]
    return prefix + "".join(alphabet[byte % len(alphabet)] for byte in stream)


def fake_pem_body(lines: int = 4, width: int = 64) -> str:
    """Corps de clé factice : base64 dense, structure DER invalide."""
    out: list[str] = []
    for index in range(lines):
        raw = hashlib.sha256(f"heimdall-fausse-cle-{index}".encode()).digest()
        out.append(base64.b64encode((raw * 4)[:48]).decode())
    return "\n".join(line[:width] for line in out)


# Jeton GitHub factice de 40 caractères au total (même gabarit que la forme
# réelle, contenu dérivé, aucune valeur). Les tests qui annoncent
# `<REDACTED:github:len=40>` l'utilisent.
FAKE_GITHUB_TOKEN: Final[str] = fake_token("ghp_", 36)
