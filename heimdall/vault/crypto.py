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

GESTION DU PEPPER (ticket #64) : ``hash_api_key`` exige un pepper explicite
d'au moins 32 octets (256 bits), jamais de valeur publique par défaut (pas de
repli silencieux sur un secret commité). La politique de résolution
(obligatoire en production, aléatoire éphémère sinon, avec avertissement) vit
dans ``VaultSettings`` et est documentée pour #25. ``generate_api_key`` produit
les clés à ≥ 256 bits ; les clés opérateur trop peu diverses sont refusées à
l'enregistrement par ``app.register_api_key``.

AUCUN autre module (scanner, MCP, CLI) ne doit importer ce module ni les
librairies crypto : la CLI ne manipule que des références (triplet
``project/env/name``), jamais de valeurs déchiffrées.

NONCE UNIQUE (ticket #67, sous-ticket de #66 « Module crypto isolé ») : le
chiffrement au repos est un AES-256-GCM dont le nonce de 96 bits est tiré de
``os.urandom`` **à chaque chiffrement**. Le blob stocké contient les trois
parties ensemble (``nonce || ciphertext || tag``) et l'AAD est l'identifiant du
secret : un blob copié sur un autre secret échoue à l'authentification. Deux
chiffrements du même texte donnent donc deux blobs différents — c'est la preuve
archivée dans ``tests/test_vault_crypto.py``.

CHIFFREMENT PAR ENVELOPPE (ticket #70, sous-ticket T26.3 de #26) : chaque secret
reçoit sa propre **DEK** aléatoire de 32 octets. La valeur est chiffrée avec
cette DEK, puis la DEK est chiffrée (« enveloppée ») avec la **KEK**. Les deux
blobs sont stockés dans la ligne du secret. La KEK ne chiffre donc que des
clés : si une DEK fuit, un seul secret est exposé. L'AAD de la valeur reste
l'identité ``(project, env, name)`` ; celui de l'enveloppe de DEK ajoute un
label de domaine dédié, pour qu'un blob de DEK ne puisse pas être rejoué comme
une valeur ni déplacé vers un autre secret.
"""

import base64
import hashlib
import hmac
import os
import secrets
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_SIZE_BYTES: int = 32  # AES-256 / KEK 256 bits
_NONCE_SIZE_BYTES: int = 12  # nonce AES-GCM 96 bits, unique par chiffrement (#67)
_TAG_SIZE_BYTES: int = 16  # étiquette d'authentification GCM, en fin de ciphertext
# Défense en profondeur : un pepper plus court que 256 bits réduit la
# résistance hors ligne si les empreintes stockées et le pepper fuient.
_MIN_PEPPER_BYTES: int = 32

# Une DEK fait 256 bits, comme la KEK : l'AES-256-GCM exige une clé de 32 octets.
_DEK_SIZE_BYTES: int = 32

# Label de domaine stable de l'enveloppe de DEK (ticket #70). L'AAD de la DEK
# n'est jamais celui de la valeur : un blob de DEK ne peut pas être rejoué comme
# un ciphertext de valeur, et inversement. Changer ce label rend les enveloppes
# existantes illisibles ; c'est un format de stockage, pas un secret.
_DEK_WRAP_AAD_PREFIX: bytes = b"heimdall-vault-dek-wrap-v1\x00"

# Label de domaine stable de la sous-clé d'empreinte (invariant 5 : la KEK de
# chiffrement n'est jamais réutilisée directement comme clé HMAC). Changer ce
# label rompt la vérification d'empreintes existantes ; c'est un dérivé
# auxiliaire, jamais une donnée de référence (rotation documentée sur la classe).
_FINGERPRINT_HKDF_INFO: bytes = b"heimdall-vault-fingerprint-v1"


class VaultCipherError(ValueError):
    """Erreur de chiffrement/déchiffrement sans détail sensible."""


class SecretEnvelope(NamedTuple):
    """Les deux blobs d'un secret chiffré par enveloppe (ticket #70).

    - ``encrypted_value`` : valeur chiffrée avec la DEK du secret ;
    - ``encrypted_dek`` : DEK chiffrée avec la KEK du serveur.

    Les deux champs sont des jetons base64 URL-safe autonomes
    (``nonce || ciphertext || tag``) et sont liés par AAD à l'identité du
    secret. Aucun des deux ne contient la valeur en clair.
    """

    encrypted_value: str
    encrypted_dek: str


def generate_dek() -> bytes:
    """Génère une DEK de 32 octets (256 bits) avec le CSPRNG du système.

    Chaque secret reçoit sa propre DEK (ticket #70). Elle n'est jamais dérivée
    de l'identifiant, d'un compteur ou de la KEK : deux secrets partagent donc
    des DEK indépendantes, et la fuite d'une DEK ne compromet qu'un secret.
    """
    return secrets.token_bytes(_DEK_SIZE_BYTES)


def generate_api_key() -> str:
    """Génère une clé API aléatoire avec au moins 256 bits d'entropie (ticket #64).

    Conformité openapi.yaml:190-193 : ``secrets.token_urlsafe(32)``, jamais
    dérivée de données prédictibles (identifiant, horodatage, compteur).
    """
    return secrets.token_urlsafe(32)


def generate_api_key_pepper() -> str:
    """Génère un pepper éphémère indépendant avec 256 bits d'entropie."""
    return secrets.token_urlsafe(_KEY_SIZE_BYTES)


def constant_time_equal(left: str | bytes, right: str | bytes) -> bool:
    """Compare deux empreintes ou deux secrets de même type en temps constant."""
    if isinstance(left, str) and isinstance(right, str):
        return hmac.compare_digest(left, right)
    if isinstance(left, bytes) and isinstance(right, bytes):
        return hmac.compare_digest(left, right)
    raise TypeError("La comparaison exige deux valeurs de même type.")


def kek_matches_pepper(kek: str, pepper: str) -> bool:
    """Détecte la réutilisation de clé, y compris sous des encodages différents."""
    pepper_bytes = pepper.encode("utf-8")
    encoded_match = constant_time_equal(kek.encode("utf-8"), pepper_bytes)
    decoded_match = constant_time_equal(decode_encoded_key(kek), pepper_bytes)
    return encoded_match or decoded_match


def _normalize_pepper(pepper: str | bytes | None) -> bytes:
    """Normalise le pepper serveur en octets ; refuse absent, vide ou trop court.

    Le seuil de 32 octets (256 bits) est une défense en profondeur : il aligne
    le pepper sur la KEK et évite qu'un secret d'un seul caractère réduise la
    résistance hors ligne des empreintes de clés API.
    """
    if pepper is None:
        raise ValueError(
            "Le pepper serveur est obligatoire : passer explicitement "
            "VaultSettings.api_key_pepper. Aucun pepper public par défaut n'est utilisé."
        )
    if isinstance(pepper, str):
        if not pepper or not pepper.strip():
            raise ValueError("Le pepper serveur ne peut pas être vide ou blanc.")
        try:
            pepper_bytes = pepper.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Le pepper serveur doit être encodable en UTF-8.") from None
    else:
        pepper_bytes = bytes(pepper)
        if not pepper_bytes or not pepper_bytes.strip():
            raise ValueError("Le pepper serveur ne peut pas être vide ou blanc.")
    if len(pepper_bytes) < _MIN_PEPPER_BYTES:
        raise ValueError(
            f"Le pepper serveur doit comporter au moins {_MIN_PEPPER_BYTES} octets "
            "(256 bits) pour une résistance hors ligne suffisante."
        )
    return pepper_bytes


def hash_api_key(key: str, pepper: str | bytes) -> str:
    """Hachage HMAC-SHA256 de vérification d'une clé API avec pepper serveur (ticket #64).

    Conformité openapi.yaml:197-200 :
    Le serveur DOIT stocker uniquement un haché salé de vérification de la clé
    (sel unique par clé, ou HMAC avec un pepper serveur distinct de la KEK de
    chiffrement), jamais sa valeur brute ; la fonction de hachage et la gestion
    du sel/pepper sont documentées pour #25.

    Le pepper est obligatoire, doit comporter au moins 32 octets et n'a aucune
    valeur par défaut : un appel sans pepper lève ``ValueError`` au lieu de
    produire une empreinte portable et corrélable entre déploiements. Une clé
    non encodable en UTF-8 (surrogate isolé) est refusée par une erreur
    générique, sans écho de la valeur reçue.
    """
    pepper_bytes = _normalize_pepper(pepper)
    if not isinstance(key, str):
        raise ValueError("Clé API invalide : chaîne attendue.")
    try:
        key_bytes = key.encode("utf-8")
    except UnicodeEncodeError:
        # Aucun écho de la valeur reçue : le message reste générique.
        raise ValueError("Clé API invalide : encodage UTF-8 impossible.") from None
    return hmac.new(pepper_bytes, key_bytes, hashlib.sha256).hexdigest()


def generate_encryption_key() -> str:
    """Génère une KEK 256 bits encodée base64 URL-safe."""
    return base64.urlsafe_b64encode(secrets.token_bytes(_KEY_SIZE_BYTES)).decode("ascii")


def decode_encoded_key(encoded: str | bytes) -> bytes:
    """Décode une KEK base64 URL-safe (ou standard) de 32 octets en octets bruts.

    Accepte l'alphabet standard et URL-safe, avec ou sans padding, mais valide
    strictement (pas de caractères ignorés). Exposé pour la vérification de
    séparation KEK/pepper (ticket #64) : comparer l'entropie décodée, pas
    seulement les chaînes encodées, sous peine de laisser passer la même clé
    sous deux représentations (invariant 5).
    """
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
        padding = b"=" * (-len(raw) % 4)
        key = base64.b64decode(raw + padding, altchars=b"-_", validate=True)
    except Exception:
        raise ValueError("KEK invalide : encodage base64 incorrect.") from None
    if len(key) != _KEY_SIZE_BYTES:
        raise ValueError(
            f"KEK invalide : {_KEY_SIZE_BYTES} octets décodés requis."
        )
    return key


def _new_nonce() -> bytes:
    """Tire un nonce AES-GCM de 96 bits dans l'aléatoire du système (ticket #67).

    ``os.urandom`` est le CSPRNG du noyau (getrandom(2)/urandom(2)) : il n'est
    ni prédictible ni dérivable d'une horloge ou d'un compteur. Un nonce
    réutilisé avec la même clé rendrait le mode GCM catastrophique (XOR des
    deux sorties, et forge de l'étiquette d'authentification) : le nonce est
    donc tiré **à chaque appel**, jamais mémorisé ni réutilisé.

    La taille de 12 octets (96 bits) est celle recommandée par NIST SP
    800-38D pour GCM : elle évite le calcul de GHASH sur un nonce non
    aligné. Probabilité de collision par paire : 2^-96 ; sur 2^32
    chiffrements, la probabilité d'au moins une collision reste de l'ordre de
    2^-33 (borne du birthday paradox).
    """
    return os.urandom(_NONCE_SIZE_BYTES)


def _decode_token(token: str) -> bytes:
    """Décode un jeton base64 URL-safe en ``nonce || ciphertext || tag``.

    Toute anomalie (type, chaîne vide, alphabet, longueur minimale) devient une
    ``VaultCipherError`` générique : aucun oracle n'est offert à l'appelant.
    """
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
    return raw


def _encrypt_token(aead: AESGCM, plaintext: bytes, aad: bytes) -> str:
    """Chiffre avec un AEAD déjà construit et encode ``nonce || ciphertext || tag``."""
    nonce = _new_nonce()
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def _decrypt_token(aead: AESGCM, token: str, aad: bytes) -> bytes:
    """Déchiffre un jeton et traduit ``InvalidTag`` en ``VaultCipherError`` générique."""
    raw = _decode_token(token)
    nonce = raw[:_NONCE_SIZE_BYTES]
    ciphertext = raw[_NONCE_SIZE_BYTES:]
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise VaultCipherError("Authentification de la donnée chiffrée échouée.") from None


class VaultCipher:
    """Chiffrement authentifié AES-256-GCM des valeurs au repos (ticket #25/#26/#67).

    - La KEK est fournie par l'exploitant (``HEIMDALL_VAULT_KEK``), jamais stockée
      dans la base SQLite : la compromission de la base seule ne révèle rien.
    - Chaque chiffrement tire un **nonce neuf de 96 bits** depuis l'aléatoire du
      système (``os.urandom``, ticket #67) : deux chiffremens du même texte
      donnent deux blobs différents, et un nonce n'est jamais réutilisé avec la
      même KEK (cela révélerait le clair par XOR des deux sorties).
    - Le blob stocké est ``nonce || ciphertext || tag`` (l'étiquette GCM de
      16 octets est déjà en fin de ciphertext), encodé en base64 URL-safe.
    - L'AAD lie le ciphertext au triplet ``(project, env, name)`` : un blob déplacé
      vers une autre identité échoue à l'authentification.
    - Les erreurs de déchiffrement sont génériques (aucun oracle sur la cause).
    - Le chiffrement par enveloppe (``encrypt_envelope``/``decrypt_envelope``,
      ticket #70) génère une DEK de 32 octets par secret : la valeur est
      chiffrée avec la DEK, puis la DEK est chiffrée avec la KEK. Un blob de
      DEK ne peut être rejoué comme une valeur (label de domaine distinct).
    - L'empreinte d'intégrité (``fingerprint``) utilise une sous-clé HKDF-SHA256
      dédiée et lie la valeur au triplet : la KEK n'est jamais réutilisée comme
      clé HMAC (invariant 5) et deux valeurs égales sous des triplets distincts
      ne sont pas corrélables par un lecteur de la seule base. L'empreinte est
      auxiliaire : une rotation de KEK la rend obsolète (recalcul après
      déchiffrement), jamais une perte de secret.
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_SIZE_BYTES:
            raise ValueError(
                f"KEK invalide : {_KEY_SIZE_BYTES} octets exactement sont requis."
            )
        self._key = bytes(key)
        self._aead = AESGCM(self._key)
        self._fingerprint_key = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_SIZE_BYTES,
            salt=None,
            info=_FINGERPRINT_HKDF_INFO,
        ).derive(self._key)

    def __repr__(self) -> str:
        return "VaultCipher(<REDACTED>)"

    @classmethod
    def generate(cls) -> "VaultCipher":
        """Génère une KEK éphémère (mémoire uniquement, hors production)."""
        return cls(secrets.token_bytes(_KEY_SIZE_BYTES))

    @classmethod
    def from_encoded_key(cls, encoded: str | bytes) -> "VaultCipher":
        """Décode une KEK base64 URL-safe (ou standard) de 32 octets."""
        return cls(decode_encoded_key(encoded))

    @staticmethod
    def aad(project: str, env: str, name: str) -> bytes:
        """Contexte authentifié liant un ciphertext à son triplet d'identité.

        L'identifiant du secret est le triplet ``(project, env, name)`` — l'AAD
        du ticket #67. Les trois champs sont séparés par un octet NUL, absent
        des identifiants validés : le triplet est donc non ambigu (deux
        triplets différents ne produisent jamais le même AAD).
        """
        return f"{project}\x00{env}\x00{name}".encode()

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> str:
        """Chiffre et encode en base64 URL-safe (nonce || ciphertext || tag).

        Le nonce est tiré **à chaque appel** par ``_new_nonce`` (96 bits,
        ``os.urandom``) : il n'est ni dérivé d'une horloge ni repris d'un
        compteur, donc jamais réutilisé avec la même clé. Le blob retourné
        contient les trois parties ensemble : ``nonce`` (12 octets) puis
        ``ciphertext`` (texte chiffré + étiquette GCM de 16 octets).
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("La valeur à chiffrer doit être de type bytes.")
        return _encrypt_token(self._aead, bytes(plaintext), aad)

    def decrypt(self, token: str, *, aad: bytes = b"") -> bytes:
        """Déchiffre un jeton base64 URL-safe ; InvalidTag devient VaultCipherError.

        Le jeton est relu comme ``nonce || ciphertext || tag`` : le nonce est
        repris tel quel, il n'est jamais régénéré. L'AAD doit être **exactement**
        celui du chiffrement, sinon l'authentification GCM échoue (blob copié sur
        un autre secret → ``VaultCipherError``).
        """
        return _decrypt_token(self._aead, token, aad)

    @staticmethod
    def encrypt_with_dek(
        plaintext: bytes,
        dek: bytes | bytearray,
        *,
        aad: bytes = b"",
    ) -> str:
        """Chiffre une valeur avec une DEK (AES-256-GCM, ticket #70).

        La DEK est une clé de 32 octets propre au secret ; l'AAD est l'identité
        du secret, comme pour le chiffrement direct historique. Le jeton retourné
        suit le même format ``nonce || ciphertext || tag`` que ``encrypt``.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("La valeur à chiffrer doit être de type bytes.")
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != _DEK_SIZE_BYTES:
            raise ValueError(
                f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis."
            )
        return _encrypt_token(AESGCM(bytes(dek)), bytes(plaintext), aad)

    @staticmethod
    def decrypt_with_dek(
        token: str,
        dek: bytes | bytearray,
        *,
        aad: bytes = b"",
    ) -> bytes:
        """Déchiffre une valeur avec sa DEK ; toute altération lève ``VaultCipherError``."""
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != _DEK_SIZE_BYTES:
            raise ValueError(
                f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis."
            )
        return _decrypt_token(AESGCM(bytes(dek)), token, aad)

    def wrap_dek(self, dek: bytes | bytearray, *, aad: bytes = b"") -> str:
        """Chiffre une DEK avec la KEK (ticket #70).

        L'AAD de l'enveloppe est préfixé par un label de domaine dédié, puis lié
        à l'identité du secret : une enveloppe de DEK ne peut être ni rejouée
        comme une valeur, ni déplacée vers un autre secret.
        """
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != _DEK_SIZE_BYTES:
            raise ValueError(
                f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis."
            )
        return self.encrypt(bytes(dek), aad=_DEK_WRAP_AAD_PREFIX + bytes(aad))

    def unwrap_dek(self, encrypted_dek: str, *, aad: bytes = b"") -> bytes:
        """Déchiffre une DEK enveloppée avec la KEK et vérifie sa taille."""
        dek = self.decrypt(encrypted_dek, aad=_DEK_WRAP_AAD_PREFIX + bytes(aad))
        if len(dek) != _DEK_SIZE_BYTES:
            raise VaultCipherError("DEK déchiffrée invalide.")
        return dek

    def encrypt_envelope(self, plaintext: bytes, *, aad: bytes = b"") -> SecretEnvelope:
        """Chiffre une valeur par enveloppe : DEK neuve, puis DEK chiffrée par la KEK.

        La DEK est tirée à chaque appel (``generate_dek``) : deux secrets — même
        avec la même valeur — ont des DEK indépendantes et des blobs distincts.
        Le buffer de DEK est effacé au mieux après usage (Python ne garantit pas
        l'absence de copies, mais aucune référence à la DEK n'est conservée).
        """
        dek = bytearray(generate_dek())
        try:
            encrypted_value = self.encrypt_with_dek(plaintext, dek, aad=aad)
            encrypted_dek = self.wrap_dek(dek, aad=aad)
        finally:
            dek[:] = b"\x00" * len(dek)
        return SecretEnvelope(
            encrypted_value=encrypted_value,
            encrypted_dek=encrypted_dek,
        )

    def decrypt_envelope(
        self,
        encrypted_value: str,
        encrypted_dek: str,
        *,
        aad: bytes = b"",
    ) -> bytes:
        """Déchiffre une valeur par enveloppe : DEK avec la KEK, puis valeur avec la DEK."""
        dek = bytearray(self.unwrap_dek(encrypted_dek, aad=aad))
        try:
            return self.decrypt_with_dek(encrypted_value, dek, aad=aad)
        finally:
            dek[:] = b"\x00" * len(dek)

    def fingerprint(self, plaintext: bytes, *, aad: bytes = b"") -> str:
        """Empreinte HMAC-SHA256 non réversible et liée au triplet d'identité.

        Utilise la sous-clé HKDF dédiée (jamais la KEK, invariant 5) et intègre
        l'AAD ``(project, env, name)`` au message : deux valeurs identiques
        stockées sous des triplets distincts produisent des empreintes
        distinctes, donc non corrélables depuis la seule base. Déterministe pour
        un même ``(KEK, aad, valeur)`` ; auxiliaire, recalculable après une
        rotation de KEK.
        """
        message = bytes(aad) + b"\x00" + bytes(plaintext)
        return hmac.new(self._fingerprint_key, message, hashlib.sha256).hexdigest()


def encrypt_at_rest(plaintext: bytes, key_id: str) -> bytes:
    """Chiffre ``plaintext`` pour stockage au repos (ticket #25).

    API historique réservée à la gestion de clés par identifiant (#25). La
    couche serveur utilise ``VaultCipher`` avec une KEK explicite.
    """
    raise NotImplementedError("chiffrement par key_id non implémenté (voir #25)")


def decrypt_for_recipient(blob: bytes, key_id: str) -> bytes:
    """Déchiffre ``blob`` pour le destinataire autorisé (ticket #25)."""
    raise NotImplementedError("déchiffrement par key_id non implémenté (voir #25)")
