"""Vault Heimdall — persistance chiffrée et client TLS.

Implémentation serveur : ticket #25 (contrat OpenAPI #15 : ``openapi.yaml``).

RÈGLE D'ARCHITECTURE (ticket #17, piège à éviter) : **toute** la crypto
(chiffrement au repos, dérivation Argon2, génération et hachage des clés API)
vit dans ``heimdall.vault.crypto``. Aucun autre module du dépôt ne doit
importer ``cryptography`` ou ``argon2`` — vérifié par
``tests/test_crypto_confinement.py``.
"""

from heimdall.vault.client import VaultClient

__all__ = ["VaultClient"]
