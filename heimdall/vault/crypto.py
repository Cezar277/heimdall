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

import base64
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_SIZE_BYTES: int = 32  # AES-256 / KEK 256 bits
_NONCE_SIZE_BYTES: int = 12  # nonce AES-GCM 96 bits
_TAG_SIZE_BYTES: int = 16


class VaultCipherError(ValueError):
    """Erreur de chiffrement/déchiffrement sans détail sensible."""


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


def generate_encryption_key() -> str:
    """Génère une KEK 256 bits encodée base64 URL-safe."""
    return base64.urlsafe_b64encode(secrets.token_bytes(_KEY_SIZE_BYTES)).decode("ascii")


class VaultCipher:
    """Chiffrement authentifié AES-256-GCM des valeurs au repos (ticket #25/#26).

    - La KEK est fournie par l'exploitant (``HEIMDALL_VAULT_KEK``), jamais stockée
      dans la base SQLite : la compromission de la base seule ne révèle rien.
    - Chaque chiffrement utilise un nonce aléatoire de 96 bits.
    - L'AAD lie le ciphertext au triplet ``(project, env, name)`` : un blob déplacé
      vers une autre identité échoue à l'authentification.
    - Les erreurs de déchiffrement sont génériques (aucun oracle sur la cause).
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_SIZE_BYTES:
            raise ValueError(
                f"KEK invalide : {_KEY_SIZE_BYTES} octets exactement sont requis."
            )
        self._key = bytes(key)
        self._aead = AESGCM(self._key)

    def __repr__(self) -> str:
        return "VaultCipher(<REDACTED>)"

    @classmethod
    def generate(cls) -> "VaultCipher":
        """Génère une KEK éphémère (mémoire uniquement, hors production)."""
        return cls(secrets.token_bytes(_KEY_SIZE_BYTES))

    @classmethod
    def from_encoded_key(cls, encoded: str | bytes) -> "VaultCipher":
        """Décode une KEK base64 URL-safe (ou standard) de 32 octets."""
        if isinstance(encoded, str):
            if not encoded or encoded != encoded.strip():
                raise ValueError("KEK invalide : valeur vide ou entourée d'espaces.")
            try:
                raw = encoded.encode("ascii")
            except UnicodeEncodeError:
                raise ValueError("KEK invalide : encodage non ASCII.") from None
        elif isinstance(encoded, bytes):
            raw = bytes(encoded)
        else:
            raise ValueError("KEK invalide : chaîne base64 attendue.")
        try:
            # Accepte l'alphabet standard et URL-safe, avec ou sans padding,
            # mais valide strictement (pas de caractères ignorés).
            padding = b"=" * (-len(raw) % 4)
            key = base64.b64decode(raw + padding, altchars=b"-_", validate=True)
        except Exception:
            raise ValueError("KEK invalide : encodage base64 incorrect.") from None
        if len(key) != _KEY_SIZE_BYTES:
            raise ValueError(
                f"KEK invalide : {_KEY_SIZE_BYTES} octets décodés requis."
            )
        return cls(key)

    @staticmethod
    def aad(project: str, env: str, name: str) -> bytes:
        """Contexte authentifié liant un ciphertext à son triplet d'identité."""
        return f"{project}\x00{env}\x00{name}".encode()

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> str:
        """Chiffre et encode en base64 URL-safe (nonce || ciphertext || tag)."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("La valeur à chiffrer doit être de type bytes.")
        nonce = secrets.token_bytes(_NONCE_SIZE_BYTES)
        ciphertext = self._aead.encrypt(nonce, bytes(plaintext), aad)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str, *, aad: bytes = b"") -> bytes:
        """Déchiffre un jeton base64 URL-safe ; InvalidTag devient VaultCipherError."""
        if not isinstance(token, str) or not token:
            raise VaultCipherError("Donnée chiffrée invalide.")
        try:
            raw = base64.b64decode(
                token.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except Exception:
            raise VaultCipherError("Donnée chiffrée invalide.") from None
        if len(raw) < _NONCE_SIZE_BYTES + _TAG_SIZE_BYTES:
            raise VaultCipherError("Donnée chiffrée invalide.")
        nonce = raw[:_NONCE_SIZE_BYTES]
        ciphertext = raw[_NONCE_SIZE_BYTES:]
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise VaultCipherError("Authentification de la donnée chiffrée échouée.") from None

    def fingerprint(self, plaintext: bytes) -> str:
        """Empreinte HMAC-SHA256 non réversible de la valeur (intégrité/corrélation)."""
        return hmac.new(self._key, bytes(plaintext), hashlib.sha256).hexdigest()


def encrypt_at_rest(plaintext: bytes, key_id: str) -> bytes:
    """Chiffre ``plaintext`` pour stockage au repos (ticket #25).

    API historique réservée à la gestion de clés par identifiant (#25). La
    couche serveur utilise ``VaultCipher`` avec une KEK explicite.
    """
    raise NotImplementedError("chiffrement par key_id non implémenté (voir #25)")


def decrypt_for_recipient(blob: bytes, key_id: str) -> bytes:
    """Déchiffre ``blob`` pour le destinataire autorisé (ticket #25)."""
    raise NotImplementedError("déchiffrement par key_id non implémenté (voir #25)")
