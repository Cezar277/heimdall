"""Crypto du Vault — SEUL module autorisé à importer ``cryptography``/``argon2``.

Ticket #25. Exigences du contrat (#15) à y implémenter :
- secrets chiffrés au repos (jamais en clair hors mémoire du destinataire autorisé) ;
- clés API jamais stockées en clair : haché de vérification salé par clé
  (ou HMAC avec pepper serveur distinct de la KEK), comparaison via
  ``hmac.compare_digest`` sur empreintes de longueur fixe, coût comparable
  entre cas existant/inexistant/révoqué (empreinte factice) ;
- clés générées à ≥ 256 bits via ``secrets.token_urlsafe(32)``, affichées une fois ;
- ``Cache-Control: no-store`` sur toute réponse portant métadonnées/valeur,
  aucun secret dans logs, erreurs ou buckets de rate-limit.

AUCUN autre module (scanner, MCP, CLI) ne doit importer ce module ni les
librairies crypto : la CLI ne manipule que des références (triplet
``project/env/name``), jamais de valeurs déchiffrées.
"""


def encrypt_at_rest(plaintext: bytes, key_id: str) -> bytes:
    """Chiffre ``plaintext`` pour stockage au repos (ticket #25)."""
    raise NotImplementedError("chiffrement non implémenté (voir #25)")


def decrypt_for_recipient(blob: bytes, key_id: str) -> bytes:
    """Déchiffre ``blob`` pour le destinataire autorisé (ticket #25)."""
    raise NotImplementedError("déchiffrement non implémenté (voir #25)")
