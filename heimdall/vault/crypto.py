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

GESTION DU PEPPER (ticket #64) : ``hash_api_key`` exige un pepper explicite,
jamais de valeur publique par défaut (pas de repli silencieux sur un secret
commité). La politique de résolution (obligatoire en production, aléatoire
éphémère sinon, avec avertissement) vit dans ``VaultSettings`` et est
documentée pour #25. ``generate_api_key`` produit les clés à ≥ 256 bits.

AUCUN autre module (scanner, MCP, CLI) ne doit importer ce module ni les
librairies crypto : la CLI ne manipule que des références (triplet
``project/env/name``), jamais de valeurs déchiffrées.
"""

import hashlib
import hmac
import secrets


def generate_api_key() -> str:
    """Génère une clé API aléatoire avec au moins 256 bits d'entropie (ticket #64).

    Conformité openapi.yaml:190-193 : ``secrets.token_urlsafe(32)``, jamais
    dérivée de données prédictibles (identifiant, horodatage, compteur).
    """
    return secrets.token_urlsafe(32)


def _normalize_pepper(pepper: str | bytes | None) -> bytes:
    """Normalise le pepper serveur en octets ; refuse absent ou vide (fail-closed)."""
    if pepper is None:
        raise ValueError(
            "Le pepper serveur est obligatoire : passer explicitement "
            "VaultSettings.api_key_pepper. Aucun pepper public par défaut n'est utilisé."
        )
    if isinstance(pepper, str):
        if not pepper or not pepper.strip():
            raise ValueError("Le pepper serveur ne peut pas être vide ou blanc.")
        return pepper.encode("utf-8")
    pepper_bytes = bytes(pepper)
    if not pepper_bytes:
        raise ValueError("Le pepper serveur ne peut pas être vide.")
    return pepper_bytes


def hash_api_key(key: str, pepper: str | bytes) -> str:
    """Hachage HMAC-SHA256 de vérification d'une clé API avec pepper serveur (ticket #64).

    Conformité openapi.yaml:197-200 :
    Le serveur DOIT stocker uniquement un haché salé de vérification de la clé
    (sel unique par clé, ou HMAC avec un pepper serveur distinct de la KEK de
    chiffrement), jamais sa valeur brute ; la fonction de hachage et la gestion
    du sel/pepper sont documentées pour #25.

    Le pepper est obligatoire et n'a aucune valeur par défaut : un appel sans
    pepper lève ``ValueError`` au lieu de produire une empreinte portable et
    corrélable entre déploiements.
    """
    pepper_bytes = _normalize_pepper(pepper)
    return hmac.new(pepper_bytes, key.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt_at_rest(plaintext: bytes, key_id: str) -> bytes:
    """Chiffre ``plaintext`` pour stockage au repos (ticket #25)."""
    raise NotImplementedError("chiffrement non implémenté (voir #25)")


def decrypt_for_recipient(blob: bytes, key_id: str) -> bytes:
    """Déchiffre ``blob`` pour le destinataire autorisé (ticket #25)."""
    raise NotImplementedError("déchiffrement non implémenté (voir #25)")
