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

DÉRIVATION DE LA KEK (ticket #262, sous-ticket de #26 « Clé maîtresse et
chiffrement par enveloppe ») : la KEK qui chiffre les secrets est dérivée de la
clé maîtresse du serveur avec **Argon2id** (``argon2.low_level.hash_secret_raw``,
``Type.ID``), sel public de 16 octets persisté à côté de la clé maîtresse.
Paramètres OWASP (64 Mio, 3 itérations, 4 lanes) : voir
``docs/adr/005-derivation-kek-argon2id.md``. La dérivation est volontairement
lente et n'a lieu **qu'une fois au démarrage** ; la KEK dérivée reste en mémoire
dans ``VaultCipher`` et n'est jamais écrite en base. Le mode historique
``HEIMDALL_VAULT_KEK`` (KEK 32 octets fournie directement) reste accepté pour ne
pas rendre illisibles les blobs existants ; les deux modes sont exclusifs.
"""

import base64
import collections
import hashlib
import hmac
import math
import os
import re
import secrets
import unicodedata
from collections.abc import Sequence
from typing import NamedTuple

import argon2.low_level
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
MAX_SERVER_HMAC_KEY_BYTES: int = 512  # Borne maximale pour la clé HMAC serveur (ticket #116)
_SHA256_HEX_LEN: int = 64  # Longueur en caractères hexadécimaux d'un SHA-256 (ticket #116)
_MIN_DISTINCT_SERVER_HMAC_KEY_BYTES: int = 24  # Diversité minimale durcie (>= 24 symboles)
_MIN_SERVER_HMAC_KEY_SHANNON_ENTROPY: float = 4.0  # Seuil d'entropie de Shannon durci (ticket #116)


def _shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon en bits par octet d'un bloc binaire."""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Garde anti-phrase humaine (revue #116) : une phrase naturelle de 32+ octets
# peut franchir les seuils de diversité (24 symboles) et d'entropie brute
# (Shannon >= 4.0) tout en ne portant que 60-80 bits effectifs (mots de
# dictionnaire), restant attaquable hors ligne avec un dump SQLite et le canari
# public. Cinq signatures sont refusées sur une clé de 32+ caractères
# normalisés :
#   1. minuscules ASCII + espaces >= 85 % (phrases basse-casse, avec ou sans
#      espaces, y compris les phrases à chiffres type "password123 ...") ;
#   2. majuscules ASCII >= 85 % (phrases capitales sans séparateur) ;
#   3. si la clé contient un blanc, caractères ASCII alphanumériques + blancs
#      >= 85 % (phrases capitales, à casse mixte ou à chiffres type
#      "password123 ..." séparées par des espaces, que la règle 1 ne
#      comptabilise pas) ;
#   4. lettres ASCII >= 85 % (phrases CamelCase sans séparateur type
#      "CorrectHorseBatteryStaple...", y compris avec suffixe chiffré, que les
#      règles 1 et 2 ne voient pas en raison du mélange majuscules/minuscules) ;
#   5. mots CamelCase répétés (>= 4 mots [A-Z][a-z]{2,}) représentant avec
#      chiffres associés >= 85 % de la clé (phrases CamelCase avec chiffres
#      intercalés sans espaces).
# Les règles 1 à 3 s'appliquent après une normalisation défensive qui remplace
# tout caractère non alphanumérique ASCII par un blanc (revue LOW #116 #226) :
# la liste fermée " -_.:,;!?/" n'étant pas exhaustive, une phrase de
# dictionnaire séparée par "#", "@", "&", ... ne doit pas échapper à la garde
# sous prétexte que son séparateur n'est pas listé. La règle 3 compte un mot
# dès que son squelette alphabétique porte >= 2 lettres (insensible à la casse
# et aux substitutions leet par chiffres), pour refuser aussi les phrases à
# casse mixte et à leetspeak type "C0rr3ct#H0rs3#...".
# generate_server_hmac_key() régénère en boucle jusqu'à conformité avec
# validate_server_hmac_key() : les clés produites par la voie officielle sont
# toujours garanties valides et portent 256 bits effectifs réels.
_HUMAN_PHRASE_MIN_CHARS: int = 32
_HUMAN_PHRASE_MAX_WORD_RATIO: float = 0.85
_CAMEL_WORDS_MIN_COUNT: int = 4
_CAMEL_WORDS_PATTERN: re.Pattern[str] = re.compile(r"[A-Z][a-z]{2,}")
_HUMAN_PHRASE_SEPARATORS: str = " -_.:,;!?/"
_NATURAL_WORD_MIN_LEN: int = 2
_ALTERNATING_CASE_MIN_RATIO: float = 0.75
_ALTERNATING_CASE_MIN_ALPHA_RATIO: float = 0.80


def _looks_like_human_phrase(key_bytes: bytes) -> bool:
    """Détecte une clé qui est en réalité une phrase naturelle (espaces, ponctuation, CamelCase).

    La détection ignore la casse par composition NFKD (accents retirés) et ne
    s'applique qu'aux clés textuelles d'au moins 32 caractères normalisés ;
    les octets binaires non UTF-8 sont réduits par ``errors="ignore"`` et
    restent du ressort des gardes de diversité et d'entropie.
    """
    normalized = unicodedata.normalize("NFKD", key_bytes.decode("utf-8", errors="ignore"))
    stripped = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    cleaned = "".join(" " if ch.isspace() else ch for ch in stripped)
    if len(cleaned) < _HUMAN_PHRASE_MIN_CHARS:
        return False
    # Normalisation défensive des séparateurs (revue LOW #116 #226) : la liste
    # _HUMAN_PHRASE_SEPARATORS est une liste fermée, contournable par tout
    # séparateur hors liste ("#", "@", "&", ...). Tout non-alphanumérique ASCII
    # est donc réduit à un blanc générique avant les règles de ratios.
    normalized_ascii = re.sub(r"[^A-Za-z0-9 ]+", " ", cleaned)
    total = len(normalized_ascii)
    lowercase_or_sep = sum(
        1
        for ch in normalized_ascii
        if ch.isascii() and (ch.islower() or ch == " ")
    )
    uppercase_or_sep = sum(
        1
        for ch in normalized_ascii
        if ch.isascii() and (ch.isupper() or ch == " ")
    )
    if (
        lowercase_or_sep / total >= _HUMAN_PHRASE_MAX_WORD_RATIO
        or uppercase_or_sep / total >= _HUMAN_PHRASE_MAX_WORD_RATIO
    ):
        return True
    if " " in normalized_ascii:
        word_chars = sum(
            1
            for ch in normalized_ascii
            if ch.isascii() and (ch.isalnum() or ch == " ")
        )
        words = [w for w in normalized_ascii.split(" ") if w]
        # Squelette alphabétique >= 2 lettres par mot : insensible à la casse et
        # aux substitutions leet par chiffres ("C0rr3ct" -> "Crrct"), pour ne pas
        # contourner la garde par un mélange majuscules/minuscules ou de chiffres.
        natural_words = [
            w
            for w in words
            if sum(1 for c in w if c.isascii() and c.isalpha()) >= _NATURAL_WORD_MIN_LEN
        ]
        if (
            len(natural_words) >= _CAMEL_WORDS_MIN_COUNT
            and word_chars / total >= _HUMAN_PHRASE_MAX_WORD_RATIO
        ):
            return True
    camel_words = _CAMEL_WORDS_PATTERN.findall(cleaned)
    camel_len = sum(len(w) for w in camel_words) + sum(
        1
        for ch in cleaned
        if ch.isascii() and (ch.isdigit() or ch in _HUMAN_PHRASE_SEPARATORS)
    )
    if (
        len(camel_words) >= _CAMEL_WORDS_MIN_COUNT
        and camel_len / total >= _HUMAN_PHRASE_MAX_WORD_RATIO
    ):
        return True
    letters = [ch for ch in cleaned if ch.isascii() and ch.isalpha()]
    if (
        len(letters) >= _HUMAN_PHRASE_MIN_CHARS
        and len(letters) / total >= _ALTERNATING_CASE_MIN_ALPHA_RATIO
    ):
        transitions = sum(
            1 for i in range(len(letters) - 1) if letters[i].islower() != letters[i + 1].islower()
        )
        if transitions / (len(letters) - 1) >= _ALTERNATING_CASE_MIN_RATIO:
            return True
    return False


# Une DEK fait 256 bits, comme la KEK : l'AES-256-GCM exige une clé de 32 octets.
_DEK_SIZE_BYTES: int = 32

# Label de domaine stable de l'enveloppe de DEK (ticket #70). L'AAD de la DEK
# n'est jamais celui de la valeur : un blob de DEK ne peut pas être rejoué comme
# un ciphertext de valeur, et inversement. Changer ce label rend les enveloppes
# existantes illisibles ; c'est un format de stockage, pas un secret.
_DEK_WRAP_AAD_PREFIX: bytes = b"heimdall-vault-dek-wrap-v1\x00"

# Paramètres Argon2id de dérivation de la KEK (ticket #262, ADR-005) :
# 64 Mio de mémoire, 3 itérations, 4 lanes. Ils dépassent les minimums OWASP
# (19 Mio / 2 / 1) tout en restant supportables au démarrage. Changer ces
# valeurs change la KEK produite pour un même couple (clé maîtresse, sel) :
# les traiter comme un format de stockage, jamais comme un réglage jetable.
ARGON2ID_TIME_COST: int = 3
ARGON2ID_MEMORY_COST_KIB: int = 64 * 1024  # 64 Mio
ARGON2ID_PARALLELISM: int = 4
ARGON2ID_HASH_LEN: int = _KEY_SIZE_BYTES  # 32 octets, clé AES-256
ARGON2ID_SALT_BYTES: int = 16  # 128 bits, sel public stocké à côté de la clé maîtresse
# Une clé maîtresse plus courte que 128 bits n'apporte pas la marge nécessaire
# face à une attaque hors ligne : refus fail-closed en amont d'Argon2id.
MIN_MASTER_KEY_BYTES: int = 16

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


def generate_server_hmac_key() -> str:
    """Génère une clé HMAC serveur aléatoire avec au moins 256 bits d'entropie (ticket #116).

    À utiliser comme clé HMAC serveur dédiée pour le calcul des empreintes de secrets,
    distincte de la KEK et de la clé maîtresse de chiffrement. Garantit que la clé
    produite satisfait immédiatement ``validate_server_hmac_key``.
    """
    while True:
        candidate = secrets.token_urlsafe(_KEY_SIZE_BYTES)
        try:
            validate_server_hmac_key(candidate)
            return candidate
        except ValueError:
            continue


def _to_raw_server_hmac_bytes(key: str | bytes | bytearray | None) -> bytes:
    if key is None:
        raise ValueError(
            "La clé HMAC serveur est obligatoire. Aucun repli silencieux sur un secret par défaut."
        )
    if isinstance(key, str):
        if not key or not key.strip():
            raise ValueError("La clé HMAC serveur ne peut pas être vide ou blanche.")
        try:
            return key.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("La clé HMAC serveur doit être encodable en UTF-8.") from None
    if isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
        if not key_bytes or not key_bytes.strip():
            raise ValueError("La clé HMAC serveur ne peut pas être vide ou blanche.")
        return key_bytes
    raise ValueError("Clé HMAC serveur invalide : chaîne ou octets attendus.")


def _validate_key_complexity(key_bytes: bytes) -> None:
    if len(key_bytes) < _MIN_PEPPER_BYTES:
        raise ValueError(
            f"La clé HMAC serveur doit comporter au moins {_MIN_PEPPER_BYTES} octets "
            "(256 bits) pour une résistance hors ligne suffisante."
        )
    if len(key_bytes) > MAX_SERVER_HMAC_KEY_BYTES:
        raise ValueError(
            f"La clé HMAC serveur ne doit pas dépasser {MAX_SERVER_HMAC_KEY_BYTES} octets "
            "(longueur excessive)."
        )
    if len(set(key_bytes)) < _MIN_DISTINCT_SERVER_HMAC_KEY_BYTES:
        raise ValueError(
            "La clé HMAC serveur est trop simple ou répétitive (diversité insuffisante : "
            f"au moins {_MIN_DISTINCT_SERVER_HMAC_KEY_BYTES} symboles distincts requis) : "
            "utiliser generate_server_hmac_key() comme seule voie supportée pour "
            "générer une clé aléatoire cryptographiquement sûre de 256 bits."
        )
    for period in range(1, len(key_bytes) // 2 + 1):
        if all(key_bytes[i] == key_bytes[i % period] for i in range(len(key_bytes))):
            raise ValueError(
                "La clé HMAC serveur ne peut pas être un motif périodique répétitif : "
                "utiliser generate_server_hmac_key() comme seule voie supportée pour "
                "générer une clé aléatoire cryptographiquement sûre de 256 bits."
            )
    if _shannon_entropy(key_bytes) < _MIN_SERVER_HMAC_KEY_SHANNON_ENTROPY:
        raise ValueError(
            "La clé HMAC serveur a une entropie insuffisante : "
            "utiliser generate_server_hmac_key() comme seule voie supportée pour "
            "générer une clé aléatoire cryptographiquement sûre de 256 bits."
        )
    if _looks_like_human_phrase(key_bytes):
        raise ValueError(
            "La clé HMAC serveur ressemble à une phrase naturelle et ne porte pas "
            "256 bits effectifs (mots de dictionnaire attaquables hors ligne) : "
            "utiliser generate_server_hmac_key() comme seule voie supportée pour "
            "générer une clé aléatoire cryptographiquement sûre de 256 bits."
        )


def validate_server_hmac_key(key: str | bytes | bytearray | None) -> bytes:
    """Valide et normalise la clé HMAC serveur en octets (ticket #116).

    Exige au moins 32 octets (256 bits), au plus 512 octets (borne maximale),
    au moins 24 symboles distincts, aucune période répétitive, une entropie
    de Shannon >= 4.0 bits/octet et aucun aspect de phrase naturelle (garde
    anti-phrase humaine). Ces contrôles neutralisent les attaques par
    dictionnaire et les ralentissements par clés géantes.

    Portée exacte de la garantie (revue LOW #116) : la neutralisation
    dictionnaire/arc-en-ciel avec 256 bits effectifs n'est **prouvée** que pour
    une clé produite par ``generate_server_hmac_key()`` (CSPRNG, base64url).
    Pour une clé fournie par l'opérateur, ces contrôles sont une défense en
    profondeur heuristique (échec fail-closed sur tout motif connu-faible) ;
    ils ne peuvent pas prouver l'entropie d'une clé arbitraire — c'est
    pourquoi les seuils ne sont pas relevés davantage (voir les constantes
    ``_HUMAN_PHRASE_*``) et pourquoi la voie supportée reste la génération.
    """
    key_bytes = _to_raw_server_hmac_bytes(key)
    _validate_key_complexity(key_bytes)
    return key_bytes


_normalize_server_hmac_key = validate_server_hmac_key


def _extract_key_variants(raw: str | bytes | bytearray) -> list[bytes]:
    """Extrait les représentations brutes, base64 décodées et hexadécimales d'une clé."""
    if not isinstance(raw, (str, bytes, bytearray)):
        raise TypeError("La clé doit être de type str, bytes ou bytearray.")
    variants: list[bytes] = []
    if isinstance(raw, str):
        try:
            raw_bytes: bytes | None = raw.encode("utf-8")
        except UnicodeEncodeError:
            raw_bytes = None
    else:
        raw_bytes = bytes(raw)

    if raw_bytes is not None:
        variants.append(raw_bytes)
        try:
            padding = b"=" * (-len(raw_bytes) % 4)
            variants.append(base64.b64decode(raw_bytes + padding, altchars=b"-_", validate=True))
        except ValueError:
            pass
        try:
            variants.append(bytes.fromhex(raw_bytes.decode("utf-8", errors="ignore")))
        except ValueError:
            pass
    return variants


def server_hmac_key_matches_master_key(
    master_or_kek: str | bytes | bytearray,
    server_hmac_key: str | bytes | bytearray,
) -> bool:
    """Détecte la réutilisation de la clé maîtresse ou KEK comme clé HMAC serveur (Invariant 5).

    Compare en temps constant la clé maîtresse ou la KEK (brute, normalisée, décodée)
    et la clé HMAC serveur pour s'assurer que les deux clés sont strictement distinctes.
    """
    if not isinstance(master_or_kek, (str, bytes, bytearray)):
        raise TypeError("La clé maîtresse ou KEK doit être de type str, bytes ou bytearray.")
    if not isinstance(server_hmac_key, (str, bytes, bytearray)):
        raise TypeError("La clé HMAC serveur doit être de type str, bytes ou bytearray.")
    # 1. Comparaison en temps constant de toutes les variantes (brute, base64, hex)
    # AVANT normalisation, afin de ne pas masquer une collision sur HMAC faible (revue LOW #116).
    master_variants = _extract_key_variants(master_or_kek)
    hmac_raw_variants = _extract_key_variants(server_hmac_key)
    for cand in master_variants:
        for var in hmac_raw_variants:
            if constant_time_equal(cand, var):
                return True

    # 2. Normalisation de la clé HMAC serveur et comparaisons complémentaires
    try:
        norm_hmac = _normalize_server_hmac_key(server_hmac_key)
    except ValueError:
        return False

    master_str = (
        master_or_kek
        if isinstance(master_or_kek, str)
        else bytes(master_or_kek).decode("utf-8", errors="ignore")
    )
    hmac_str = norm_hmac.decode("utf-8", errors="ignore")
    try:
        if kek_matches_pepper(master_str, hmac_str):
            return True
    except ValueError:
        pass

    hmac_variants = _extract_key_variants(norm_hmac)
    for cand in master_variants:
        for var in hmac_variants:
            if constant_time_equal(cand, var):
                return True

    return False


def canonicalize_secret_value(value: str | bytes | bytearray) -> bytes:
    """Canonicalise une valeur secrète en octets UTF-8 NFC (ticket #116).

    Les chaînes sont normalisées en NFC puis encodées en UTF-8. Les octets
    UTF-8 valides sont décodés, normalisés en NFC puis ré-encodés : un candidat
    ``bytes`` en forme décomposée (NFD) produit ainsi la même empreinte que sa
    forme ``str`` équivalente. Les octets non-UTF8 (données binaires brutes)
    sont conservés tels quels pour rester compatibles avec les secrets binaires.
    """
    if not isinstance(value, (str, bytes, bytearray)):
        raise TypeError("La valeur du secret doit être de type str ou bytes.")
    if isinstance(value, str):
        try:
            return unicodedata.normalize("NFC", value).encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("La valeur du secret doit être encodable en UTF-8.") from None
    raw = bytes(value)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    return unicodedata.normalize("NFC", text).encode("utf-8")


def compute_secret_hmac(
    server_key: str | bytes | bytearray,
    value: str | bytes | bytearray,
    *,
    aad: bytes | str | bytearray | None = None,
    forbidden_keys: (
        Sequence[str | bytes | bytearray]
        | set[str | bytes | bytearray]
        | str
        | bytes
        | bytearray
        | None
    ) = None,
) -> str:
    """Calcule l'empreinte HMAC-SHA256 non réversible d'un secret avec la clé serveur (ticket #116).

    Formule exacte : ``hmac.new(cle_serveur, valeur, sha256).hexdigest()``.

    Permet de déterminer si une valeur en production correspond à une valeur ayant
    fuité, sans jamais stocker ni renvoyer cette valeur au client.

    Avertissement de sécurité (Invariant 5 - Séparation des clés) :
    Cette fonction utilitaire pure ne peut PAS appliquer l'invariant 5 par défaut :
    elle n'a aucune connaissance de la KEK ou de la clé maîtresse de l'appelant.
    Ne JAMAIS passer directement la KEK ou la clé maîtresse en tant que ``server_key``.
    La seule voie supportée en production est ``VaultCipher.compute_secret_hmac``, qui
    injecte systématiquement sa KEK dans ``forbidden_keys`` et refuse fail-closed toute
    réutilisation d'entropie (``server_hmac_key_matches_master_key``). Un appelant qui
    utilise la fonction nue DOIT fournir lui-même ``forbidden_keys`` ; ce contrat de
    primitive bas niveau est verrouillé par test (décision d'architecture revue #116).

    Décision d'architecture (contrat de valeur vide) :
    Une valeur de secret vide lève ``ValueError`` (fail-closed), car aucun secret vide ne peut
    être créé ni indexé dans le Vault. À l'inverse, les prédicats de détection de fuite
    (``is_secret_value_matching``, ``find_secrets_matching_value``) retournent ``False`` ou ``[]``
    sur candidat vide, aucun secret en base ne pouvant correspondre.

    Paramètres :
    - ``server_key`` : Clé HMAC du serveur (au moins 32 octets / 256 bits), distincte
      de la clé maîtresse de chiffrement.
    - ``value`` : Valeur secrète (chaîne ou octets). Si chaîne, normalisée en Unicode NFC.
    - ``aad`` : Contexte d'authentification optionnel lié au triplet (project, env, name).
      Si fourni, préfixé avec un octet NUL pour lier l'empreinte au triplet spécifique.
    - ``forbidden_keys`` : Clé ou séquence de clés interdites (ex. KEK / master key). Si fourni,
      la fonction refuse fail-closed (``ValueError``) toute réutilisation d'entropie.
    """
    key_bytes = _normalize_server_hmac_key(server_key)
    if forbidden_keys is not None:
        if isinstance(forbidden_keys, (str, bytes, bytearray)):
            forbidden_seq: tuple[str | bytes | bytearray, ...] = (forbidden_keys,)
        elif isinstance(forbidden_keys, (list, tuple, set)):
            forbidden_seq = tuple(forbidden_keys)
        else:
            raise TypeError(
                "forbidden_keys doit être une clé (str, bytes, bytearray) "
                "ou une collection de clés."
            )
        for forbidden in forbidden_seq:
            if not isinstance(forbidden, (str, bytes, bytearray)):
                raise TypeError("Chaque clé interdite doit être de type str, bytes ou bytearray.")
            if server_hmac_key_matches_master_key(forbidden, key_bytes):
                raise ValueError(
                    "La clé HMAC serveur ne peut pas réutiliser l'entropie d'une clé interdite "
                    "(KEK ou clé maîtresse, Invariant 5)."
                )
    value_bytes = canonicalize_secret_value(value)
    if not value_bytes:
        raise ValueError("La valeur du secret ne peut pas être vide.")

    if aad is not None:
        aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else bytes(aad)
        if not aad_bytes:
            raise ValueError("Le contexte d'authentification lié (AAD) ne peut pas être vide.")
        message = aad_bytes + b"\x00" + value_bytes
    else:
        message = value_bytes

    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def verify_secret_hmac(
    server_key: str | bytes | bytearray,
    value: str | bytes | bytearray,
    expected_hmac: str,
    *,
    aad: bytes | str | bytearray | None = None,
    forbidden_keys: (
        Sequence[str | bytes | bytearray]
        | set[str | bytes | bytearray]
        | str
        | bytes
        | bytearray
        | None
    ) = None,
) -> bool:
    """Vérifie en temps constant si une valeur candidate correspond à l'empreinte HMAC.

    Ticket #116 : permet de vérifier si la valeur en production est encore celle qui a fuité,
    sans jamais déchiffrer ni exposer l'empreinte au client.

    Avertissement de sécurité (Invariant 5 - Séparation des clés) :
    Ne JAMAIS passer la KEK ou la clé maîtresse en tant que ``server_key``. Passer par
    ``VaultCipher.verify_secret_hmac`` ou renseigner ``forbidden_keys`` pour interdire
    fail-closed toute collision d'entropie avec la clé de chiffrement.

    Décision d'architecture (contrat de vérification booléenne et valeur vide) :
    - Si ``expected_hmac`` est malformée (longueur != 64, majuscules, non-hex), retourne ``False``.
    - Laisse propager ``ValueError`` et ``TypeError`` sur entrées invalides (clé faible,
      valeur vide ou AAD vide) pour le calcul cryptographique direct, parité avec
      ``compute_secret_hmac``.
      Pour la détection de fuite applicative, ``VaultCipher.is_secret_value_matching`` et les stores
      interceptent le candidat vide pour retourner directement ``False`` / ``[]`` (aucun secret ne
      pouvant correspondre).
    """
    if (
        not isinstance(expected_hmac, str)
        or len(expected_hmac) != _SHA256_HEX_LEN
        or not all(c in "0123456789abcdef" for c in expected_hmac)
    ):
        return False
    computed = compute_secret_hmac(server_key, value, aad=aad, forbidden_keys=forbidden_keys)
    return constant_time_equal(computed, expected_hmac)


def constant_time_equal(left: str | bytes, right: str | bytes) -> bool:
    """Compare deux empreintes ou deux secrets de même type en temps constant."""
    if isinstance(left, str) and isinstance(right, str):
        return hmac.compare_digest(left, right)
    if isinstance(left, bytes) and isinstance(right, bytes):
        return hmac.compare_digest(left, right)
    raise TypeError("La comparaison exige deux valeurs de même type.")


def kek_matches_pepper(kek: str, pepper: str) -> bool:
    """Détecte la réutilisation de clé, y compris sous des encodages différents.

    Quatre comparaisons en temps constant : chaîne KEK vs pepper, KEK décodée vs
    pepper brut, KEK décodée vs pepper **décodé base64**, puis KEK décodée vs
    pepper **décodé hexadécimal**. Elles couvrent un pepper encodé en base64
    standard (``+/``, padding) alors que la KEK est URL-safe (``-_``), et un
    pepper ``KEK.hex()`` : même entropie, donc invariant 5 violé même si les
    chaînes diffèrent (revues MEDIUM et LOW).
    """
    pepper_bytes = pepper.encode("utf-8")
    kek_bytes = decode_encoded_key(kek)
    encoded_match = constant_time_equal(kek.encode("utf-8"), pepper_bytes)
    decoded_match = constant_time_equal(kek_bytes, pepper_bytes)
    if encoded_match or decoded_match:
        return True
    try:
        pepper_key = decode_encoded_key(pepper)
    except ValueError:
        pepper_key = None
    if pepper_key is not None and constant_time_equal(kek_bytes, pepper_key):
        return True
    try:
        pepper_hex = bytes.fromhex(pepper)
    except ValueError:
        # Pepper arbitraire (ni base64 32 octets ni hexadécimal) : aucune
        # entropie de KEK.
        return False
    return constant_time_equal(kek_bytes, pepper_hex)


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


def generate_kek_salt() -> str:
    """Génère un sel public Argon2id de 16 octets encodé base64 URL-safe (ticket #262).

    Le sel n'est **pas** un secret : il doit être persisté à côté de la clé
    maîtresse et rester stable entre les démarrages. Seul, il ne permet pas de
    retrouver la KEK ; perdu ou modifié, il rend en revanche les secrets
    existants illisibles (la KEK dérivée change).
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(ARGON2ID_SALT_BYTES)).decode("ascii")


def decode_kek_salt(salt: str | bytes) -> bytes:
    """Décode et valide un sel Argon2id de 16 octets exactement (ticket #262).

    Une chaîne est interprétée comme du base64 URL-safe ou standard (avec ou
    sans padding, validation stricte). Des octets sont pris tels quels : les
    tests et les appels internes peuvent fournir le sel brut. Toute autre
    longueur est refusée : le sel est public, mais une erreur de configuration
    doit échouer franchement plutôt que dériver silencieusement une autre KEK.
    """
    if isinstance(salt, str):
        if not salt or salt != salt.strip():
            raise ValueError("Sel KEK invalide : valeur vide ou entourée d'espaces.")
        try:
            raw = salt.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("Sel KEK invalide : encodage non ASCII.") from None
        try:
            padding = b"=" * (-len(raw) % 4)
            decoded = base64.b64decode(raw + padding, altchars=b"-_", validate=True)
        except Exception:
            raise ValueError("Sel KEK invalide : encodage base64 incorrect.") from None
    elif isinstance(salt, (bytes, bytearray)):
        decoded = bytes(salt)
    else:
        raise ValueError("Sel KEK invalide : chaîne base64 ou octets attendus.")
    if len(decoded) != ARGON2ID_SALT_BYTES:
        raise ValueError(f"Sel KEK invalide : {ARGON2ID_SALT_BYTES} octets décodés requis.")
    return decoded


def _zeroize_buffer(buffer: bytearray) -> None:
    """Remet à zéro best-effort un tampon ``bytearray`` de dérivation (revue LOW).

    Seuls les ``bytearray`` passent par ici : un ``bytes`` est immuable en
    Python et le muter via ``ctypes`` serait un comportement indéfini sur un
    objet potentiellement partagé ou interné (corruption d'une autre référence,
    crash ou no-op selon la plateforme) — cette mutation n'est donc **jamais**
    faite. Ce nettoyage réduit la fenêtre d'exposition des copies que ce module
    crée lui-même ; il ne prétend ni effacer la clé maîtresse d'origine (``str``,
    ``os.environ``) ni les copies internes de ``argon2-cffi``.
    """
    buffer[:] = b"\x00" * len(buffer)


def _normalize_master_key(master_key: str | bytes) -> bytearray:
    """Normalise la clé maîtresse en octets effaçables, sans écho dans une erreur.

    Une chaîne est une phrase de passe UTF-8 **canonisée NFC** avant encodage ;
    des octets sont copiés tels quels (utile aux tests et aux appelants qui
    détiennent déjà une clé aléatoire). Le ``bytearray`` retourné appartient à
    l'appelant, qui doit l'effacer après usage (``_zeroize_buffer``). La longueur
    minimale de 128 bits est une défense en profondeur contre une phrase de passe
    triviale : Argon2id ralentit l'attaque hors ligne mais ne compense pas une
    clé maîtresse sans entropie.
    """
    if isinstance(master_key, str):
        if not master_key or not master_key.strip():
            raise ValueError("Clé maîtresse invalide : valeur vide ou blanche.")
        if master_key != master_key.strip():
            raise ValueError("Clé maîtresse invalide : espaces de début ou de fin interdits.")
        try:
            # Forme canonique NFC (ticket #262) : « é » précomposé et « e » +
            # accent combinant doivent dériver la même KEK (ADR-005).
            raw = bytearray(unicodedata.normalize("NFC", master_key).encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("Clé maîtresse invalide : encodage UTF-8 impossible.") from None
    elif isinstance(master_key, (bytes, bytearray)):
        # Copie systématique : effacer le buffer ne doit jamais corrompre
        # l'objet de l'appelant (bytes(bytearray) crée toujours un nouvel objet,
        # contrairement à bytes(bytes) qui peut renvoyer le même).
        raw = bytearray(master_key)
        if not raw.strip():
            raise ValueError("Clé maîtresse invalide : valeur vide ou blanche.")
        if raw != raw.strip():
            raise ValueError("Clé maîtresse invalide : espaces de début ou de fin interdits.")
    else:
        raise ValueError("Clé maîtresse invalide : chaîne ou octets attendus.")
    if len(raw) < MIN_MASTER_KEY_BYTES:
        raise ValueError(
            f"Clé maîtresse invalide : au moins {MIN_MASTER_KEY_BYTES} octets "
            "(128 bits) sont requis."
        )
    return raw


def derive_kek_from_master_key(master_key: str | bytes, salt: str | bytes) -> bytes:
    """Dérive la KEK 256 bits avec Argon2id (ticket #262, ADR-005).

    ``argon2.low_level.hash_secret_raw`` est utilisée en ``Type.ID`` (Argon2id),
    avec 64 Mio de mémoire, 3 itérations et 4 lanes. Ces paramètres sont figés
    dans le module (voir ``ARGON2ID_*``) et documentés dans l'ADR : ils font
    partie du format de la KEK, pas d'un réglage d'exécution.

    La fonction est déterministe pour un même couple (clé maîtresse, sel) —
    c'est le critère « Fait quand » du ticket — et volontairement lente. Elle
    DOIT être appelée une seule fois au démarrage, puis la KEK retournée est
    conservée en mémoire (``VaultCipher``), jamais recalculée par requête.

    Les octets normalisés sont effacés best-effort dans un ``finally``, y
    compris si la KDF échoue (revue LOW). La copie transmise à
    ``argon2-cffi`` doit être un ``bytes`` (API de la librairie) : elle est
    créée au dernier moment, pour la durée de l'appel seulement, et n'est pas
    mutée (voir ``_zeroize_buffer``).
    """
    secret = _normalize_master_key(master_key)
    try:
        salt_bytes = decode_kek_salt(salt)
        return argon2.low_level.hash_secret_raw(
            # Copie immuable transitoire exigée par `argon2-cffi` (ffi.new) :
            # le `bytearray` effaçable reste la seule forme durable du secret.
            secret=bytes(secret),
            salt=salt_bytes,
            time_cost=ARGON2ID_TIME_COST,
            memory_cost=ARGON2ID_MEMORY_COST_KIB,
            parallelism=ARGON2ID_PARALLELISM,
            hash_len=ARGON2ID_HASH_LEN,
            type=argon2.low_level.Type.ID,
        )
    finally:
        _zeroize_buffer(secret)


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
        raise ValueError(f"KEK invalide : {_KEY_SIZE_BYTES} octets décodés requis.")
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
    """Déchiffre un jeton et traduit toute erreur de primitive en erreur générique.

    ``AESGCM.decrypt`` lève aujourd'hui ``InvalidTag`` sur une altération, mais
    une future version de ``cryptography`` peut ajouter des ``ValueError`` de
    validation d'entrée. Les deux sont traduites en ``VaultCipherError`` pour
    qu'aucun appelant direct de ``VaultCipher`` ne reçoive un oracle brut.
    """
    raw = _decode_token(token)
    nonce = raw[:_NONCE_SIZE_BYTES]
    ciphertext = raw[_NONCE_SIZE_BYTES:]
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise VaultCipherError("Authentification de la donnée chiffrée échouée.") from None


class VaultCipher:
    """Chiffrement authentifié AES-256-GCM des valeurs au repos (ticket #25/#26/#67/#262).

    - La KEK est fournie par l'exploitant soit directement
      (``HEIMDALL_VAULT_KEK``, mode historique), soit dérivée au démarrage de la
      clé maîtresse avec Argon2id (``HEIMDALL_VAULT_MASTER_KEY`` +
      ``HEIMDALL_VAULT_KEK_SALT``, ticket #262). Elle n'est jamais stockée dans
      la base SQLite : la compromission de la base seule ne révèle rien.
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
      ne sont pas corrélables par un lecteur de la seule base. Empreinte
      **auxiliaire pré-rotation** (#71) : la rotation de KEK par enveloppe ne
      touche jamais aux valeurs, elle reste donc volontairement inchangée et
      **n'est jamais vérifiée en lecture** — elle ne doit pas servir de contrôle
      d'intégrité post-rotation (c'est le déchiffrement GCM, lui, qui détecte
      toute altération). Recalculer cette empreinte supposerait de déchiffrer la
      valeur, ce que la rotation interdit explicitement.
    """

    def __init__(
        self,
        key: bytes,
        *,
        server_hmac_key: bytes | str | None = None,
    ) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_SIZE_BYTES:
            raise ValueError(f"KEK invalide : {_KEY_SIZE_BYTES} octets exactement sont requis.")
        self._key = bytes(key)
        self._aead = AESGCM(self._key)
        if server_hmac_key is not None:
            if self.key_reuses_server_hmac_key(server_hmac_key):
                raise ValueError(
                    "La clé HMAC serveur doit être distincte de la KEK / clé maîtresse."
                )
            norm_hmac = _normalize_server_hmac_key(server_hmac_key)
            self._fingerprint_key = norm_hmac
            self._has_explicit_server_hmac_key = True
        else:
            self._fingerprint_key = HKDF(
                algorithm=hashes.SHA256(),
                length=_KEY_SIZE_BYTES,
                salt=None,
                info=_FINGERPRINT_HKDF_INFO,
            ).derive(self._key)
            self._has_explicit_server_hmac_key = False

    def __repr__(self) -> str:
        return "VaultCipher(<REDACTED>)"

    @property
    def has_explicit_server_hmac_key(self) -> bool:
        """Indique si la clé HMAC serveur est explicite (non dérivée de la KEK)."""
        return self._has_explicit_server_hmac_key

    def key_reuses_server_hmac_key(self, server_hmac_key: str | bytes) -> bool:
        """Détecte si la KEK de ce chiffreur réutilise l'entropie de la clé HMAC serveur.

        Vérifie la KEK brute et ses représentations encodées (invariant 5), sans
        jamais exposer ni la KEK ni la clé HMAC.
        """
        return server_hmac_key_matches_master_key(self._key, server_hmac_key)

    def server_hmac_key_canary(self) -> str:
        """Retourne une empreinte publique non réversible de la clé HMAC active.

        Dérivée par HMAC-SHA256 avec la clé d'empreinte active sur une constante
        de domaine dédiée, cette valeur publique permet aux stores de détecter
        tout changement de clé HMAC serveur (rotation non migrée ou ré-instanciation)
        et d'échouer fail-closed pour interdire tout faux négatif de compromission.
        Ce canari est cryptographiquement sûr pour toute clé de 256 bits issue
        de ``generate_server_hmac_key()`` (résistance absolue aux pré-images).
        """
        return hmac.new(
            self._fingerprint_key,
            b"heimdall-vault-server-hmac-canary-v1",
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def generate(cls, *, server_hmac_key: bytes | str | None = None) -> "VaultCipher":
        """Génère une KEK éphémère (mémoire uniquement, hors production)."""
        return cls(secrets.token_bytes(_KEY_SIZE_BYTES), server_hmac_key=server_hmac_key)

    @classmethod
    def from_encoded_key(
        cls,
        encoded: str | bytes,
        *,
        server_hmac_key: bytes | str | None = None,
    ) -> "VaultCipher":
        """Décode une KEK base64 URL-safe (ou standard) de 32 octets."""
        return cls(decode_encoded_key(encoded), server_hmac_key=server_hmac_key)

    @classmethod
    def from_master_key(
        cls,
        master_key: str | bytes,
        salt: str | bytes,
        *,
        server_hmac_key: bytes | str | None = None,
    ) -> "VaultCipher":
        """Dérive la KEK avec Argon2id puis construit le chiffreur (ticket #262).

        À appeler **une seule fois au démarrage** : la dérivation est coûteuse
        (64 Mio, 3 itérations) et la KEK obtenue reste en mémoire pour la durée
        de vie du processus.

        Invariant 5 (revue LOW #116) : la clé HMAC serveur doit être distincte
        de la clé maîtresse elle-même, pas seulement de la KEK dérivée — le
        contrôle interne de ``__init__`` ne compare que KEK dérivée vs HMAC,
        or la KEK dérivée diffère toujours de la clé maîtresse. Le contrôle
        master vs HMAC est donc fait ici, fail-closed avant toute dérivation.
        En production, la clé passe par ``VaultSettings``
        (``validate_server_hmac_key_distinct``) via
        ``_resolve_vault_cipher`` ; cet appel direct reste encadré pour l'usage
        librairie.
        """
        if server_hmac_key is not None and server_hmac_key_matches_master_key(
            master_key, server_hmac_key
        ):
            raise ValueError(
                "La clé HMAC serveur doit être distincte de la clé maîtresse : "
                "réutiliser l'entropie maîtresse pour l'empreinte annule la "
                "séparation des clés (invariant 5). Utiliser "
                "generate_server_hmac_key() comme seule voie supportée."
            )
        return cls(
            derive_kek_from_master_key(master_key, salt),
            server_hmac_key=server_hmac_key,
        )

    def key_reuses_pepper(self, pepper: str) -> bool:
        """Détecte si la KEK de ce chiffreur réutilise l'entropie du pepper.

        Compare la KEK brute, ses représentations base64 URL-safe et standard,
        l'encodage hexadécimal et la version décodée du pepper (invariant 5),
        sans jamais exposer ni la KEK ni ``pepper``. Sert au chemin
        ``secret_store`` explicite de ``create_app`` : c'est la clé
        **réellement portée par le chiffreur du store** qui est vérifiée, pas
        la dérivation que ``settings`` produirait — les deux peuvent diverger
        (revue LOW).
        """
        encoded = base64.urlsafe_b64encode(self._key).decode("ascii")
        return kek_matches_pepper(encoded, pepper) or constant_time_equal(
            self._key, pepper.encode("utf-8")
        )

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
            raise ValueError(f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis.")
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
            raise ValueError(f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis.")
        return _decrypt_token(AESGCM(bytes(dek)), token, aad)

    def wrap_dek(self, dek: bytes | bytearray, *, aad: bytes = b"") -> str:
        """Chiffre une DEK avec la KEK (ticket #70).

        L'AAD de l'enveloppe est préfixé par un label de domaine dédié, puis lié
        à l'identité du secret : une enveloppe de DEK ne peut être ni rejouée
        comme une valeur, ni déplacée vers un autre secret.
        """
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != _DEK_SIZE_BYTES:
            raise ValueError(f"DEK invalide : {_DEK_SIZE_BYTES} octets exactement sont requis.")
        return self.encrypt(bytes(dek), aad=_DEK_WRAP_AAD_PREFIX + bytes(aad))

    def unwrap_dek(self, encrypted_dek: str, *, aad: bytes = b"") -> bytes:
        """Déchiffre une DEK enveloppée avec la KEK et vérifie sa taille."""
        dek = self.decrypt(encrypted_dek, aad=_DEK_WRAP_AAD_PREFIX + bytes(aad))
        if len(dek) != _DEK_SIZE_BYTES:
            raise VaultCipherError("DEK déchiffrée invalide.")
        return dek

    def rewrap_dek(
        self,
        new_cipher: "VaultCipher",
        encrypted_dek: str,
        *,
        aad: bytes = b"",
    ) -> str:
        """Déchiffre une DEK avec cette KEK et la rechiffre avec ``new_cipher`` (#71).

        La DEK transitoire est conservée dans un ``bytearray`` effacé dès la fin
        de l'opération. L'effacement mémoire est best-effort (CPython ne garantit
        pas l'absence de copies d'objets bytes immuables transitoires créés lors
        du déchiffrement). L'AAD est préservé.
        """
        if not isinstance(new_cipher, VaultCipher):
            raise TypeError("new_cipher doit être une instance de VaultCipher.")
        dek = bytearray(self.unwrap_dek(encrypted_dek, aad=aad))
        try:
            return new_cipher.wrap_dek(dek, aad=aad)
        finally:
            dek[:] = b"\x00" * len(dek)

    def has_same_key_as(self, other: object) -> bool:
        """Indique si deux chiffreurs utilisent la même KEK sous-jacente."""
        if not isinstance(other, VaultCipher):
            return False
        return constant_time_equal(self._key, other._key)

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

        Utilise la clé d'empreinte active (sous-clé HKDF dérivée ou clé serveur
        explicite — jamais la KEK directe, invariant 5) et intègre l'AAD
        ``(project, env, name)`` au message : deux valeurs identiques stockées
        sous des triplets distincts produisent des empreintes distinctes, donc
        non corrélables depuis la seule base. Déterministe pour un même
        ``(clé d'empreinte, aad, valeur)``.

        La valeur est canonisée en NFC (``canonicalize_secret_value``, ticket
        #116) au même titre que ``compute_secret_hmac`` : un appelant librairie
        passant des octets en forme décomposée (NFD) obtient la même empreinte
        que sa forme NFC — aucun faux négatif silencieux de détection. Les
        octets non-UTF8 restent pris tels quels (secrets binaires).

        Note d'architecture (#71) : cette empreinte est un auxiliaire pré-rotation
        calculé lors de l'insertion initiale. Lors d'une rotation de KEK par
        enveloppe (#71), seules les DEK sont réenveloppées ; les valeurs ne sont
        jamais déchiffrées en mémoire, préservant le secret absolu des données.
        L'empreinte reste donc volontairement inchangée et ne doit pas servir de
        contrôle d'intégrité post-rotation.
        """
        message = bytes(aad) + b"\x00" + canonicalize_secret_value(plaintext)
        return hmac.new(self._fingerprint_key, message, hashlib.sha256).hexdigest()

    def compute_secret_hmac(
        self,
        value: str | bytes | bytearray,
        *,
        aad: bytes | str | bytearray | None = None,
    ) -> str:
        """Calcule l'empreinte HMAC-SHA256 avec la clé serveur dédiée (ticket #116).

        Formule : ``hmac.new(cle_serveur, valeur, sha256).hexdigest()``.
        Empreinte stable et non réversible, jamais renvoyée au client.
        Garantit la séparation des clés en interdisant la réutilisation de la KEK.
        """
        return compute_secret_hmac(
            self._fingerprint_key,
            value,
            aad=aad,
            forbidden_keys=(self._key,),
        )

    def verify_secret_hmac(
        self,
        value: str | bytes | bytearray,
        expected_hmac: str,
        *,
        aad: bytes | str | bytearray | None = None,
    ) -> bool:
        """Vérifie en temps constant si la valeur correspond à l'empreinte HMAC (ticket #116)."""
        return verify_secret_hmac(
            self._fingerprint_key,
            value,
            expected_hmac,
            aad=aad,
            forbidden_keys=(self._key,),
        )

    def is_secret_value_matching(
        self,
        value: str | bytes | bytearray,
        expected_fingerprint: str,
        *,
        aad: bytes | str | bytearray | None = None,
    ) -> bool:
        """Vérifie en temps constant si la valeur correspond à l'empreinte stockée.

        Exige une clé HMAC serveur explicite (non dérivée de la KEK) pour garantir
        que la détection reste valide et immunisée contre la rotation de KEK.
        Si un AAD est fourni, la vérification est liée à ce seul AAD (aucun repli
        vers une empreinte brute non liée).

        Décision d'architecture (contrat de vérification booléenne) : si
        ``expected_fingerprint`` est malformée (longueur != 64, majuscules,
        caractères non-hexadécimaux ou type non str), la méthode retourne ``False``.
        Une empreinte corrompue ne peut mathématiquement correspondre à aucun secret.
        Pour les stores de données, le repli déchiffrement transparent s'applique
        lors d'une altération en base afin d'interdire tout faux négatif (invariant 1).

        Avertissement de domaine (empreintes stockées vs brutes, revue LOW #116) :
        Sans ``aad``, la comparaison porte exclusivement sur l'empreinte HMAC brute non
        liée (``compute_secret_hmac(value)``). Les empreintes persistées en base étant
        systématiquement liées à l'identité du secret (``aad=VaultCipher.aad(...)``),
        passer une empreinte stockée sans fournir son ``aad`` retourne toujours ``False``
        (séparation cryptographique des domaines interdisant toute confusion de contexte).
        Pour vérifier une empreinte issue du stockage, fournir obligatoirement le paramètre
        ``aad``.
        """
        if not isinstance(value, (str, bytes, bytearray)):
            raise TypeError("La valeur candidate doit être de type str, bytes ou bytearray.")
        if not self._has_explicit_server_hmac_key:
            raise VaultCipherError(
                "La vérification d'empreinte exige une clé HMAC serveur explicite "
                "(HEIMDALL_VAULT_SERVER_HMAC_KEY distincte de la KEK). En mode dérivé de "
                "la KEK, la rotation de clé invalide les empreintes."
            )
        if not value:
            return False
        if (
            not isinstance(expected_fingerprint, str)
            or len(expected_fingerprint) != _SHA256_HEX_LEN
            or not all(c in "0123456789abcdef" for c in expected_fingerprint)
        ):
            return False
        if aad is not None:
            if not isinstance(aad, (str, bytes, bytearray)):
                raise TypeError("Le contexte AAD doit être de type str, bytes ou bytearray.")
            aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else bytes(aad)
            if not aad_bytes:
                raise ValueError("Le contexte d'authentification lié (AAD) ne peut pas être vide.")
            candidate_fp = self.fingerprint(canonicalize_secret_value(value), aad=aad_bytes)
            return constant_time_equal(candidate_fp, expected_fingerprint)
        direct_fp = self.compute_secret_hmac(value)
        return constant_time_equal(direct_fp, expected_fingerprint)


def encrypt_at_rest(plaintext: bytes, key_id: str) -> bytes:
    """Chiffre ``plaintext`` pour stockage au repos (ticket #25).

    API historique réservée à la gestion de clés par identifiant (#25). La
    couche serveur utilise ``VaultCipher`` avec une KEK explicite.
    """
    raise NotImplementedError("chiffrement par key_id non implémenté (voir #25)")


def decrypt_for_recipient(blob: bytes, key_id: str) -> bytes:
    """Déchiffre ``blob`` pour le destinataire autorisé (ticket #25)."""
    raise NotImplementedError("déchiffrement par key_id non implémenté (voir #25)")
