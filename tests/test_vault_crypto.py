"""Preuves du ticket #67 — AES-256-GCM avec nonce unique.

Sous-ticket de #66 « Module crypto isolé » (grand ticket #26 « clé maîtresse et
chiffrement par enveloppe »). Le fichier ne teste que la primitive de
chiffrement au repos : ``heimdall/vault/crypto.py`` (``VaultCipher``), le seul
module autorisé à importer ``cryptography`` (invariant du ticket #17).

Ce que la suite prouve (checklist du ticket) :

1. le nonce est tiré de l'aléatoire du système (``os.urandom``) à **chaque**
   chiffrement, en 96 bits — pas de compteur, pas d'horloge ;
2. le blob stocké contient les trois parties ensemble :
   ``nonce || ciphertext || tag`` (étiquette GCM de 16 octets) ;
3. l'AAD est l'identifiant du secret : un blob copié sur un autre secret
   échoue au déchiffrement ;
4. **deux chiffrements du même texte donnent deux blobs différents** (critère
   « Fait quand » du ticket, preuve à archiver pour le rapport).

Périmètre strict : la falsification du ciphertext et de l'étiquette
(bit-flip, blob tronqué, forge de tag) est couverte par le sous-ticket
suivant #68 « Tests de falsification » ; ce fichier ne s'y substitue pas.

Faux secrets : valeurs synthétiques explicites, jamais de secret réel.
"""

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from heimdall.vault.crypto import VaultCipher, VaultCipherError
from heimdall.vault.database import db_session
from heimdall.vault.store import SqliteSecretStore

_KEY = b"K" * 32  # KEK synthétique de 32 octets (AES-256)
_PLAINTEXT = b"t67-synthetic-secret-value"
_NONCE_SIZE = 12  # 96 bits, taille recommandée par NIST SP 800-38D
_TAG_SIZE = 16  # étiquette d'authentification GCM
_AAD = VaultCipher.aad("demo", "dev", "API_TOKEN")


def _decode_blob(blob: str) -> bytes:
    """Décode le blob base64 URL-safe et rend ses octets bruts."""
    return base64.urlsafe_b64decode(blob.encode("ascii"))


class NonceGenerationTests(unittest.TestCase):
    """Le nonce est neuf, aléatoire et tiré de l'OS à chaque chiffrement."""

    def test_nonce_is_96_bits_drawn_from_os_urandom(self) -> None:
        """Le nonce vient bien d'``os.urandom(12)`` (preuve de source)."""
        cipher = VaultCipher(_KEY)
        fixed_nonce = bytes(range(_NONCE_SIZE))
        with patch.object(os, "urandom", return_value=fixed_nonce) as urandom:
            blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        urandom.assert_called_once_with(_NONCE_SIZE)
        # Les 12 premiers octets du blob sont exactement le nonce tiré.
        self.assertEqual(_decode_blob(blob)[:_NONCE_SIZE], fixed_nonce)
        self.assertEqual(cipher.decrypt(blob, aad=_AAD), _PLAINTEXT)

    def test_a_fresh_nonce_is_drawn_for_every_encryption(self) -> None:
        """Chaque appel à ``encrypt`` tire un nonce (jamais de nonce mémorisé)."""
        cipher = VaultCipher(_KEY)
        original_urandom = os.urandom
        with patch.object(os, "urandom", wraps=original_urandom) as urandom:
            for _ in range(64):
                cipher.encrypt(_PLAINTEXT, aad=_AAD)
        self.assertEqual(urandom.call_count, 64)

    def test_two_encryptions_of_the_same_text_give_two_different_blobs(self) -> None:
        """Critère « Fait quand » du ticket : deux sorties, jamais identiques.

        Deux chiffrements de la même valeur, avec la même clé et le même AAD,
        doivent produire deux blobs distincts — sinon le nonce est réutilisé
        (ou déterministe), ce qui casse le mode GCM.
        """
        cipher = VaultCipher(_KEY)
        first = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        second = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        self.assertNotEqual(first, second)
        self.assertNotEqual(
            _decode_blob(first)[:_NONCE_SIZE],
            _decode_blob(second)[:_NONCE_SIZE],
        )
        # Les deux blobs restent déchiffrables et donnent le même texte.
        self.assertEqual(cipher.decrypt(first, aad=_AAD), _PLAINTEXT)
        self.assertEqual(cipher.decrypt(second, aad=_AAD), _PLAINTEXT)

    def test_nonces_are_distinct_over_many_encryptions(self) -> None:
        """256 chiffrements successifs : 256 nonces distincts (aucun réutilisé)."""
        cipher = VaultCipher(_KEY)
        nonces = {
            _decode_blob(cipher.encrypt(_PLAINTEXT, aad=_AAD))[:_NONCE_SIZE] for _ in range(256)
        }
        self.assertEqual(len(nonces), 256)

    def test_nonce_does_not_depend_on_the_plaintext_or_the_key(self) -> None:
        """Le nonce n'est pas dérivé du texte clair ni de la clé.

        Deux textes différents et deux clés différentes donnent des nonces
        distincts : le nonce est tiré, pas calculé à partir de l'entrée. Les
        tirages sont figés (`os.urandom` patché) pour une preuve déterministe.
        """
        cipher = VaultCipher(_KEY)
        other_cipher = VaultCipher(b"L" * 32)
        nonce_a = bytes(range(1, 13))  # 12 octets distincts
        nonce_b = bytes(range(2, 14))
        nonce_c = bytes(range(3, 15))
        with patch.object(os, "urandom", side_effect=[nonce_a, nonce_b, nonce_c]):
            first = _decode_blob(cipher.encrypt(b"texte-a", aad=_AAD))[:_NONCE_SIZE]
            second = _decode_blob(cipher.encrypt(b"texte-b", aad=_AAD))[:_NONCE_SIZE]
            third = _decode_blob(other_cipher.encrypt(b"texte-a", aad=_AAD))[:_NONCE_SIZE]
        self.assertEqual(first, nonce_a)
        self.assertEqual(second, nonce_b)
        self.assertEqual(third, nonce_c)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)

    def test_nonce_is_not_derived_from_the_clock(self) -> None:
        """L'horloge gelée ne change rien : le nonce n'est pas temporel.

        Piège du ticket : un nonce dérivé de l'heure (ou un compteur) est
        prévisible et réutilisable. Horloge et temps monotones figés, les deux
        chiffrements restent différents.
        """
        cipher = VaultCipher(_KEY)
        with (
            patch("time.time", return_value=1_700_000_000.0),
            patch("time.monotonic", return_value=42.0),
            patch("time.time_ns", return_value=1_700_000_000_000_000_000),
        ):
            first = cipher.encrypt(_PLAINTEXT, aad=_AAD)
            second = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        self.assertNotEqual(first, second)


class BlobLayoutTests(unittest.TestCase):
    """Le blob stocké contient nonce + ciphertext + tag, et rien d'autre."""

    def test_blob_contains_nonce_ciphertext_and_tag(self) -> None:
        """Longueur exacte : 12 (nonce) + N (texte) + 16 (étiquette GCM)."""
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        raw = _decode_blob(blob)
        self.assertEqual(len(raw), _NONCE_SIZE + len(_PLAINTEXT) + _TAG_SIZE)
        # Le texte en clair n'est pas dans le blob.
        self.assertNotIn(_PLAINTEXT, raw)
        self.assertEqual(cipher.decrypt(blob, aad=_AAD), _PLAINTEXT)

    def test_empty_plaintext_still_carries_a_nonce_and_a_tag(self) -> None:
        """Même vide, le blob vaut nonce + étiquette (28 octets)."""
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(b"", aad=_AAD)
        self.assertEqual(len(_decode_blob(blob)), _NONCE_SIZE + _TAG_SIZE)
        self.assertEqual(cipher.decrypt(blob, aad=_AAD), b"")

    def test_decryption_reuses_the_stored_nonce(self) -> None:
        """Le déchiffrement relit le nonce du blob, il n'en regénère pas.

        Si ``decrypt`` tirait un nouveau nonce au lieu de relire celui stocké,
        le déchiffrement échouerait : le test le prouve en gelant
        ``os.urandom`` pendant l'opération.
        """
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        with patch.object(os, "urandom", return_value=b"\x00" * _NONCE_SIZE):
            self.assertEqual(cipher.decrypt(blob, aad=_AAD), _PLAINTEXT)


class AadBindingTests(unittest.TestCase):
    """L'AAD est l'identifiant du secret : un blob déplacé est refusé."""

    def test_blob_copied_to_another_secret_fails_to_decrypt(self) -> None:
        """Blob de SECRET_A déchiffré sous l'identité de SECRET_B → refus."""
        cipher = VaultCipher(_KEY)
        source_aad = VaultCipher.aad("demo", "dev", "SECRET_A")
        target_aad = VaultCipher.aad("demo", "dev", "SECRET_B")
        blob = cipher.encrypt(_PLAINTEXT, aad=source_aad)
        self.assertEqual(cipher.decrypt(blob, aad=source_aad), _PLAINTEXT)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt(blob, aad=target_aad)

    def test_blob_copied_to_another_project_or_env_fails_to_decrypt(self) -> None:
        """Le projet et l'environnement font partie de l'identité du secret."""
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(_PLAINTEXT, aad=VaultCipher.aad("demo", "dev", "API_TOKEN"))
        for other in (
            VaultCipher.aad("autre-projet", "dev", "API_TOKEN"),
            VaultCipher.aad("demo", "prod", "API_TOKEN"),
        ):
            with self.subTest(aad=other):
                with self.assertRaises(VaultCipherError):
                    cipher.decrypt(blob, aad=other)

    def test_decryption_without_aad_is_refused(self) -> None:
        """L'AAD n'est pas optionnel : sans lui, l'authentification échoue."""
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt(blob)

    def test_aad_separates_the_identity_fields(self) -> None:
        """Le triplet est encodé sans ambiguïté (séparateur NUL)."""
        self.assertEqual(VaultCipher.aad("demo", "dev", "API_TOKEN"), b"demo\x00dev\x00API_TOKEN")
        self.assertNotEqual(
            VaultCipher.aad("demo", "dev", "A"),
            VaultCipher.aad("demo", "dev", "B"),
        )

    def test_decryption_error_does_not_leak_the_plaintext(self) -> None:
        """L'erreur de déchiffrement reste générique (pas d'oracle)."""
        cipher = VaultCipher(_KEY)
        blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        with self.assertRaises(VaultCipherError) as ctx:
            cipher.decrypt(blob, aad=VaultCipher.aad("demo", "dev", "OTHER"))
        message = str(ctx.exception)
        self.assertNotIn(_PLAINTEXT.decode(), message)
        self.assertNotIn(_PLAINTEXT.hex(), message)


class StoredSecretBindingTests(unittest.IsolatedAsyncioTestCase):
    """Le blob stocké en base est lié à l'identité du secret qu'il protège."""

    async def test_stored_blob_is_bound_to_the_secret_identity(self) -> None:
        """Un blob lu en base ne se déchiffre que sous son propre triplet.

        Preuve au niveau du stockage : le blob de ``SECRET_ONE`` recopié sur
        ``SECRET_TWO`` échoue, et la valeur en clair n'apparaît pas dans le
        fichier SQLite.
        """
        cipher = VaultCipher(_KEY)
        with tempfile.TemporaryDirectory(prefix="heimdall-t67-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "SECRET_ONE", _PLAINTEXT.decode())
            await store.create("demo", "dev", "SECRET_TWO", _PLAINTEXT.decode())

            with db_session(db_path) as conn:
                rows = conn.execute(
                    "SELECT name, encrypted_value FROM secrets ORDER BY name"
                ).fetchall()
            blobs = {row["name"]: row["encrypted_value"] for row in rows}
            self.assertEqual(sorted(blobs), ["SECRET_ONE", "SECRET_TWO"])
            # Même valeur, deux secrets : deux blobs (nonce différent).
            self.assertNotEqual(blobs["SECRET_ONE"], blobs["SECRET_TWO"])

            # Chaque blob ne se déchiffre que sous l'identité de son secret.
            for name, blob in blobs.items():
                with self.subTest(name=name):
                    self.assertEqual(
                        cipher.decrypt(blob, aad=VaultCipher.aad("demo", "dev", name)),
                        _PLAINTEXT,
                    )
                    other = "SECRET_TWO" if name == "SECRET_ONE" else "SECRET_ONE"
                    with self.assertRaises(VaultCipherError):
                        cipher.decrypt(blob, aad=VaultCipher.aad("demo", "dev", other))

            # La valeur en clair n'est jamais écrite dans le fichier SQLite.
            self.assertNotIn(_PLAINTEXT.decode(), db_path.read_bytes().decode("latin-1"))


if __name__ == "__main__":
    unittest.main()
