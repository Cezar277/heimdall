"""Preuves du ticket #68 — tests de falsification (AES-256-GCM).

Sous-ticket de #66 « Module crypto isolé » (grand ticket #26 « clé maîtresse et
chiffrement par enveloppe »). Le mode authentifié doit **refuser** toute donnée
modifiée au lieu de renvoyer une valeur fausse : ce fichier le prouve sur la
primitive ``VaultCipher`` de ``heimdall/vault/crypto.py``.

Checklist du ticket :

1. modifier un seul octet du blob → erreur (tout octet : nonce, ciphertext, tag) ;
2. mauvaise clé → erreur ;
3. mauvais AAD → erreur.

Chaque test vérifie qu'une exception ``VaultCipherError`` est levée, jamais
qu'une valeur fausse est renvoyée, et commence par un contrôle : le blob
intact, la bonne clé et le bon AAD le déchiffrent bien. Le blob est un
**vecteur figé**, généré une fois par ``VaultCipher.encrypt`` puis commité :
les tests sont donc strictement déterministes (aucun tirage aléatoire à
l'exécution) et restent valides quel que soit le mode de tirage du nonce.

Aucun code de production n'est modifié : la livraison est la suite de tests.
Faux secrets synthétiques uniquement, jamais de secret réel.
"""

import base64
import unittest

from heimdall.vault.crypto import VaultCipher, VaultCipherError

_KEY = b"K" * 32  # KEK synthétique de 32 octets (AES-256)
_OTHER_KEY = b"L" * 32
_PLAINTEXT = b"t68-synthetic-secret-value"
_AAD = VaultCipher.aad("demo", "dev", "API_TOKEN")
_OTHER_AAD = VaultCipher.aad("demo", "dev", "OTHER_TOKEN")
_NONCE_SIZE = 12  # 96 bits, en préfixe du blob
_TAG_SIZE = 16  # étiquette GCM de 16 octets, en suffixe du ciphertext

# Vecteur figé : blob réel ``nonce || ciphertext || tag`` généré une fois avec
# _KEY, _PLAINTEXT et _AAD. Le contrôle de chaque test vérifie qu'il se
# déchiffre avec la bonne clé et le bon AAD avant toute falsification ; il ne
# contient donc aucun secret réel (clair synthétique, KEK de test).
_FIXED_BLOB = "vPAtx_sMokuWIWcnzZ8uD6AvNKKFsOHm7ldBimoNnmjyCkQBXqds5PK9Q2moIrqdLqLE8huy"


def _decode_blob(blob: str) -> bytes:
    """Décode le blob base64 URL-safe en octets bruts."""
    return base64.urlsafe_b64decode(blob.encode("ascii"))


def _encode_blob(raw: bytes) -> str:
    """Ré-encode un blob brut en base64 URL-safe."""
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _flip_bit(raw: bytes, index: int) -> bytes:
    """Modifie un seul octet (XOR 0x01) à la position donnée."""
    tampered = bytearray(raw)
    tampered[index] ^= 0x01
    return bytes(tampered)


class BlobTamperingTests(unittest.TestCase):
    """Un seul octet modifié suffit : l'étiquette GCM ne correspond plus."""

    def test_one_modified_blob_byte_is_rejected(self) -> None:
        """Modifier n'importe quel octet du blob lève ``VaultCipherError``.

        Les 54 octets du vecteur sont couverts un par un : nonce (0-11),
        ciphertext (12-37) et étiquette (38-53). Le contrôle initial prouve
        que le blob non modifié se déchiffre : le refus vient de l'altération.
        """
        cipher = VaultCipher(_KEY)
        raw = _decode_blob(_FIXED_BLOB)
        self.assertEqual(cipher.decrypt(_FIXED_BLOB, aad=_AAD), _PLAINTEXT)
        self.assertEqual(len(raw), _NONCE_SIZE + len(_PLAINTEXT) + _TAG_SIZE)
        for index in range(len(raw)):
            with self.subTest(tampered_byte=index):
                tampered = _encode_blob(_flip_bit(raw, index))
                self.assertNotEqual(tampered, _FIXED_BLOB)
                with self.assertRaises(VaultCipherError):
                    cipher.decrypt(tampered, aad=_AAD)

    def test_decryption_with_wrong_key_is_rejected(self) -> None:
        """Une KEK différente (même taille) ne déchiffre jamais le blob."""
        right_cipher = VaultCipher(_KEY)
        wrong_cipher = VaultCipher(_OTHER_KEY)
        self.assertEqual(right_cipher.decrypt(_FIXED_BLOB, aad=_AAD), _PLAINTEXT)
        with self.assertRaises(VaultCipherError):
            wrong_cipher.decrypt(_FIXED_BLOB, aad=_AAD)

    def test_decryption_with_wrong_aad_is_rejected(self) -> None:
        """Un AAD différent (autre secret, ou absent) fait échouer GCM."""
        cipher = VaultCipher(_KEY)
        self.assertEqual(cipher.decrypt(_FIXED_BLOB, aad=_AAD), _PLAINTEXT)
        for wrong_aad in (_OTHER_AAD, b""):
            with self.subTest(aad=wrong_aad):
                with self.assertRaises(VaultCipherError):
                    cipher.decrypt(_FIXED_BLOB, aad=wrong_aad)

    def test_malformed_truncated_or_extended_blob_is_rejected(self) -> None:
        """Les gardes de format et de longueur restent fail-closed.

        Couvre les cas que la mutation à longueur constante ne voit pas :
        jeton vide, base64 invalide, blob tronqué sous le minimum
        ``nonce + tag``, dernier caractère base64 altéré, blob tronqué d'un
        caractère et blob étendu. Aucun ne doit renvoyer de valeur.
        """
        cipher = VaultCipher(_KEY)
        altered_last_char = _FIXED_BLOB[:-1] + ("A" if _FIXED_BLOB[-1] != "A" else "B")
        cases = {
            "empty": "",
            "invalid_base64": "!!!",
            "truncated_under_minimum": _FIXED_BLOB[:20],
            "altered_last_base64_char": altered_last_char,
            "truncated_last_char": _FIXED_BLOB[:-1],
            "extended": _FIXED_BLOB + "AAAA",
        }
        for name, token in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(VaultCipherError):
                    cipher.decrypt(token, aad=_AAD)
