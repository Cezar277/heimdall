"""Tests de l'empreinte HMAC avec clé serveur (ticket #116).

Sous-ticket du grand ticket #40 « États du secret dans le Vault ».
Exigences couvertes :
1. Calcul d'empreinte non réversible du secret : hmac.new(cle_serveur, valeur, sha256).hexdigest().
2. Clé HMAC du serveur distincte de la clé maîtresse de chiffrement et de la KEK (Invariant 5).
3. L'empreinte n'est JAMAIS renvoyée au client (audit des réponses API et des schémas).
4. Empreinte stable et déterministe, résistance aux attaques par dictionnaire / tables arc-en-ciel.
5. Détection de compromission en production sans jamais stocker ni exposer la valeur en clair.
6. Résistance à la rotation de KEK (fail-closed en mode dérivé, persistance en mode explicite).
7. Parité SQLite et mémoire pour les lignes héritées sans empreinte (repli déchiffrement).
8. Suppression de toute API d'extraction de la clé HMAC en clair sur VaultCipher.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import tempfile
import unicodedata
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, TestCase

from fastapi.testclient import TestClient
from pydantic import ValidationError

from heimdall.vault.app import (
    VaultSettings,
    create_app,
)
from heimdall.vault.auth import generate_project_api_key
from heimdall.vault.crypto import (
    _SHA256_HEX_LEN,
    VaultCipher,
    VaultCipherError,
    _normalize_server_hmac_key,
    compute_secret_hmac,
    generate_encryption_key,
    generate_server_hmac_key,
    server_hmac_key_matches_master_key,
    verify_secret_hmac,
)
from heimdall.vault.database import (
    create_secret,
    db_session,
    ensure_project,
    find_secrets_by_fingerprint,
    get_secret_metadata,
    init_db,
    update_secret,
)
from heimdall.vault.store import (
    InMemorySecretStore,
    SqliteSecretStore,
)

# Clés de test robustes et diversifiées (satisfaisant les contrôles d'entropie)
_VALID_SERVER_HMAC_KEY = "s3rv3r_hm4c_k3y_s3cur3_v4ult_t0k3n_256!"
_VALID_ALT_HMAC_KEY = "4lt3rn4t1v3_hm4c_s3rv3r_k3y_d1st1nct_t0k3n"
_VALID_KEK = generate_encryption_key()
_VALID_PEPPER = "p3pp3r_s3rv3r_s3cur3_t0k3n_256_b1ts_v4ult"
_VALID_MASTER_KEY = "m4st3r_p4ssphr4s3_s3cur3_v4ult_k3y_t0k3n"


class SecretHmacCryptoTests(TestCase):
    """Tests unitaires des primitives cryptographiques de l'empreinte HMAC de secret."""

    def test_compute_secret_hmac_exact_formula(self) -> None:
        """compute_secret_hmac applique hmac.new(cle_serveur, valeur, sha256).hexdigest()."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        expected = hmac.new(
            key.encode("utf-8"),
            valeur.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        computed = compute_secret_hmac(key, valeur)
        self.assertEqual(computed, expected)
        self.assertEqual(len(computed), _SHA256_HEX_LEN)
        self.assertTrue(all(c in "0123456789abcdef" for c in computed))

    def test_compute_secret_hmac_is_stable_and_deterministic(self) -> None:
        """L'empreinte est stable et déterministe pour un même couple (cle, valeur)."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "my-db-password-stable-test"

        first = compute_secret_hmac(key, valeur)
        second = compute_secret_hmac(key, valeur)
        self.assertEqual(first, second)

    def test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256(self) -> None:
        """L'empreinte est non réversible et déjoue les attaques par dictionnaire (piège évité)."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "password123"

        computed_hmac = compute_secret_hmac(key, valeur)
        plain_sha256 = hashlib.sha256(valeur.encode("utf-8")).hexdigest()

        # L'empreinte ne doit JAMAIS correspondre à un simple SHA-256
        self.assertNotEqual(computed_hmac, plain_sha256)

        # Effet avalanche : modifier un seul caractère change complètement l'empreinte
        valeur_altered = "password124"
        altered_hmac = compute_secret_hmac(key, valeur_altered)
        self.assertNotEqual(computed_hmac, altered_hmac)

    def test_compute_secret_hmac_supports_nfc_canonicalization(self) -> None:
        """Deux formes Unicode (NFC vs NFD) d'une même valeur produisent la même empreinte."""
        key = _VALID_SERVER_HMAC_KEY
        val_nfc = unicodedata.normalize("NFC", "secret_clé_prod")
        val_nfd = unicodedata.normalize("NFD", "secret_clé_prod")
        self.assertNotEqual(val_nfc.encode("utf-8"), val_nfd.encode("utf-8"))

        fp_nfc = compute_secret_hmac(key, val_nfc)
        fp_nfd = compute_secret_hmac(key, val_nfd)
        self.assertEqual(fp_nfc, fp_nfd)

    def test_compute_secret_hmac_with_and_without_aad(self) -> None:
        """Le contexte optionnel AAD lie l'empreinte au triplet d'identité."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "token-val-42"
        aad_prod = VaultCipher.aad("myproj", "prod", "API_KEY")
        aad_dev = VaultCipher.aad("myproj", "dev", "API_KEY")

        fp_raw = compute_secret_hmac(key, valeur)
        fp_prod = compute_secret_hmac(key, valeur, aad=aad_prod)
        fp_dev = compute_secret_hmac(key, valeur, aad=aad_dev)

        self.assertNotEqual(fp_raw, fp_prod)
        self.assertNotEqual(fp_raw, fp_dev)
        self.assertNotEqual(fp_prod, fp_dev)

    def test_compute_secret_hmac_rejects_empty_aad_explicitly(self) -> None:
        """compute_secret_hmac refuse un AAD vide explicite au lieu de basculer silencieusement."""
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", aad=b"")
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", aad="")

    def test_verify_and_matching_empty_aad_parity(self) -> None:
        """verify_secret_hmac et is_secret_value_matching refusent un AAD vide (False)."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        dummy_fp = "a" * 64

        self.assertFalse(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", dummy_fp, aad=b""))
        self.assertFalse(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", dummy_fp, aad=""))
        self.assertFalse(cipher.is_secret_value_matching("val", dummy_fp, aad=b""))
        self.assertFalse(cipher.is_secret_value_matching("val", dummy_fp, aad=""))

    def test_compute_secret_hmac_input_validation(self) -> None:
        """Refus fail-closed sur entrée vide, type invalide ou clé trop courte."""
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "")
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, b"")

        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, 12345)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            compute_secret_hmac(None, "valid_value")  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            compute_secret_hmac("", "valid_value")
        with self.assertRaises(ValueError):
            compute_secret_hmac("   ", "valid_value")

        with self.assertRaises(ValueError):
            compute_secret_hmac("short_key_16_bytes!", "valid_value")

    def test_normalize_server_hmac_key_rejects_trivial_or_repetitive_keys(self) -> None:
        """Refuse les clés de faible entropie (répétitives ou périodiques)."""
        # Caractère unique répété
        with self.assertRaises(ValueError) as ctx1:
            _normalize_server_hmac_key("S" * 32)
        self.assertIn("generate_server_hmac_key()", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            _normalize_server_hmac_key(b"\x00" * 32)
        self.assertIn("generate_server_hmac_key()", str(ctx2.exception))

        # Période triviale
        with self.assertRaises(ValueError) as ctx3:
            _normalize_server_hmac_key("1234" * 8)
        self.assertIn("generate_server_hmac_key()", str(ctx3.exception))

    def test_normalize_server_hmac_key_rejects_subtle_weak_patterns(self) -> None:
        """Refuse les clés subtilement faibles (période > 4, diversité < 16, entropie < 3.5)."""
        # Période 8 avec 8 symboles distincts ("ABCDEFGH" * 4 = 32 octets)
        with self.assertRaises(ValueError) as ctx1:
            _normalize_server_hmac_key("ABCDEFGH" * 4)
        self.assertIn("generate_server_hmac_key()", str(ctx1.exception))

        # Motif périodique de 10 caractères avec diversité insuffisante ("0123456789" * 3 + "01")
        with self.assertRaises(ValueError) as ctx2:
            _normalize_server_hmac_key("0123456789" * 3 + "01")
        self.assertIn("generate_server_hmac_key()", str(ctx2.exception))

        # Motif de période 16
        with self.assertRaises(ValueError) as ctx3:
            _normalize_server_hmac_key("abcdefghijklmnop" * 2)
        self.assertIn("generate_server_hmac_key()", str(ctx3.exception))

    def test_candidate_value_empty_parity_cipher(self) -> None:
        """Une valeur candidate vide retourne False en toute circonstance (avec ou sans AAD)."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        dummy_fp = "a" * 64
        aad = VaultCipher.aad("project", "prod", "TOKEN")

        self.assertFalse(cipher.is_secret_value_matching("", dummy_fp))
        self.assertFalse(cipher.is_secret_value_matching("", dummy_fp, aad=aad))
        self.assertFalse(cipher.is_secret_value_matching(b"", dummy_fp))
        self.assertFalse(cipher.is_secret_value_matching(b"", dummy_fp, aad=aad))

    def test_generate_server_hmac_key(self) -> None:
        """generate_server_hmac_key produit au moins 256 bits d'entropie aléatoire."""
        k1 = generate_server_hmac_key()
        k2 = generate_server_hmac_key()
        self.assertNotEqual(k1, k2)
        self.assertGreaterEqual(len(k1.encode("utf-8")), 32)
        # La clé générée doit être acceptée sans erreur par la normalisation
        norm = _normalize_server_hmac_key(k1)
        self.assertGreaterEqual(len(norm), 32)

    def test_verify_secret_hmac_constant_time(self) -> None:
        """verify_secret_hmac vérifie l'égalité en temps constant."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "valid-token-secret"
        expected = compute_secret_hmac(key, valeur)

        self.assertTrue(verify_secret_hmac(key, valeur, expected))
        self.assertFalse(verify_secret_hmac(key, "wrong-token", expected))
        self.assertFalse(verify_secret_hmac(_VALID_ALT_HMAC_KEY, valeur, expected))

        self.assertFalse(verify_secret_hmac(key, valeur, "invalid_len"))
        self.assertFalse(verify_secret_hmac(key, valeur, 12345))  # type: ignore[arg-type]
        self.assertFalse(verify_secret_hmac(key, "", expected))
        self.assertFalse(verify_secret_hmac("short", valeur, expected))
        self.assertFalse(verify_secret_hmac(key, 12345, expected))  # type: ignore[arg-type]

    def test_compute_secret_hmac_surrogate_unicode_error(self) -> None:
        """Une chaîne avec surrogate isolé non encodable lève ValueError générique."""
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "\ud800")
        with self.assertRaises(ValueError):
            compute_secret_hmac("\ud800" * 32, "valid_value")

    def test_vault_cipher_methods(self) -> None:
        """VaultCipher expose HMAC et vérification d'empreinte de secret."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        val = "test-secret-value-cipher"
        expected = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, val)

        self.assertEqual(cipher.compute_secret_hmac(val), expected)
        self.assertTrue(cipher.verify_secret_hmac(val, expected))
        self.assertFalse(cipher.verify_secret_hmac("wrong-val", expected))
        self.assertTrue(cipher.is_secret_value_matching(val, expected))

        # Avec AAD (str et bytes)
        aad = VaultCipher.aad("p", "prod", "SECRET")
        fp_aad = cipher.fingerprint(val.encode("utf-8"), aad=aad)
        self.assertTrue(cipher.is_secret_value_matching(val, fp_aad, aad=aad))
        self.assertTrue(cipher.is_secret_value_matching(val.encode("utf-8"), fp_aad, aad=aad))
        self.assertFalse(cipher.is_secret_value_matching("other", fp_aad, aad=aad))
        self.assertFalse(cipher.is_secret_value_matching(val, "invalid_len", aad=aad))

    def test_vault_cipher_factories_propagate_server_hmac_key_without_exposure(self) -> None:
        """Les factories propagent server_hmac_key sans exposer la propriété en clair."""
        c1 = VaultCipher.from_encoded_key(_VALID_KEK, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertTrue(c1.has_explicit_server_hmac_key)
        self.assertEqual(
            c1.compute_secret_hmac("probe"),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "probe"),
        )

        c2 = VaultCipher.from_master_key(
            _VALID_MASTER_KEY,
            "s" * 22,
            server_hmac_key=_VALID_SERVER_HMAC_KEY,
        )
        self.assertTrue(c2.has_explicit_server_hmac_key)
        self.assertEqual(
            c2.compute_secret_hmac("probe"),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "probe"),
        )

        c3 = VaultCipher.generate(server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertTrue(c3.has_explicit_server_hmac_key)
        self.assertEqual(
            c3.compute_secret_hmac("probe"),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "probe"),
        )

    def test_find_secrets_by_fingerprint_validates_format(self) -> None:
        """find_secrets_by_fingerprint refuse fail-closed tout format non-hex64."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                ensure_project(conn, "proj1")
                # Format non hexadécimal ou longueur incorrecte -> ValueError
                with self.assertRaises(ValueError):
                    find_secrets_by_fingerprint(conn, "proj1", "not_a_valid_hex_hash")
                with self.assertRaises(ValueError):
                    find_secrets_by_fingerprint(conn, "proj1", "f" * 63)
                with self.assertRaises(ValueError):
                    find_secrets_by_fingerprint(conn, "proj1", "G" * 64)


class KeySeparationTests(TestCase):
    """Vérification de l'Invariant 5 : séparation stricte KEK / clé maîtresse / clé HMAC serveur."""

    def test_server_hmac_key_matches_master_key_detects_collision(self) -> None:
        """server_hmac_key_matches_master_key détecte la réutilisation directe ou encodée."""
        master = _VALID_MASTER_KEY
        self.assertTrue(server_hmac_key_matches_master_key(master, master))
        self.assertFalse(server_hmac_key_matches_master_key(master, _VALID_SERVER_HMAC_KEY))

        kek_bytes = b"K" * 32
        self.assertTrue(server_hmac_key_matches_master_key(kek_bytes, kek_bytes))
        self.assertFalse(server_hmac_key_matches_master_key(kek_bytes, _VALID_SERVER_HMAC_KEY))

    def test_vault_cipher_key_reuses_server_hmac_key_method(self) -> None:
        """VaultCipher expose key_reuses_server_hmac_key pour encapsulation propre."""
        kek = b"K" * 32
        cipher = VaultCipher(kek, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertFalse(cipher.key_reuses_server_hmac_key(_VALID_SERVER_HMAC_KEY))
        self.assertTrue(cipher.key_reuses_server_hmac_key(kek))

    def test_vault_cipher_server_hmac_key_property_removed(self) -> None:
        """La propriété server_hmac_key a été supprimée pour interdire l'extraction de la clé."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertFalse(hasattr(cipher, "server_hmac_key"))
        self.assertTrue(cipher.has_explicit_server_hmac_key)

    def test_vault_cipher_rejects_server_hmac_key_equal_to_kek(self) -> None:
        """VaultCipher refuse à la construction une clé HMAC serveur identique à sa KEK."""
        kek = b"K" * 32
        with self.assertRaises(ValueError) as ctx:
            VaultCipher(kek, server_hmac_key=kek)
        self.assertIn("distincte", str(ctx.exception))

    def test_vault_cipher_default_fingerprint_key_is_distinct_from_kek(self) -> None:
        """Sans server_hmac_key explicite, la sous-clé HKDF dérivée est distincte de la KEK."""
        kek = b"K" * 32
        cipher = VaultCipher(kek)
        self.assertFalse(cipher.has_explicit_server_hmac_key)
        self.assertNotEqual(
            cipher.compute_secret_hmac("val"),
            hmac.new(kek, b"val", hashlib.sha256).hexdigest(),
        )

    def test_vault_settings_enforces_key_separation(self) -> None:
        """VaultSettings refuse server_hmac_key identique à master_key, KEK ou pepper."""
        # 1. Collision avec master_key
        with self.assertRaises(ValidationError):
            VaultSettings(
                master_key=_VALID_MASTER_KEY,
                kek_salt="s" * 22,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=_VALID_MASTER_KEY,
            )

        # 2. Collision avec KEK
        with self.assertRaises(ValidationError):
            VaultSettings(
                kek=_VALID_KEK,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=_VALID_KEK,
            )

        # 3. Collision avec pepper d'authentification
        with self.assertRaises(ValidationError):
            VaultSettings(
                kek=_VALID_KEK,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=_VALID_PEPPER,
            )

        # 4. Clés toutes distinctes -> accepté
        settings = VaultSettings(
            kek=_VALID_KEK,
            api_key_pepper=_VALID_PEPPER,
            server_hmac_key=_VALID_SERVER_HMAC_KEY,
        )
        self.assertEqual(settings.server_hmac_key, _VALID_SERVER_HMAC_KEY)

    def test_vault_settings_rejects_encoded_forms_of_keys(self) -> None:
        """VaultSettings refuse server_hmac_key égale à master_key ou KEK sous forme encodée."""
        # 1. master_key sous forme base64 comme server_hmac_key
        b64_master = base64.b64encode(_VALID_MASTER_KEY.encode("utf-8")).decode("ascii")
        with self.assertRaises(ValidationError):
            VaultSettings(
                master_key=_VALID_MASTER_KEY,
                kek_salt="s" * 22,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=b64_master,
            )

        # 2. KEK sous forme hexadécimale comme server_hmac_key
        hex_kek = _VALID_KEK.encode("utf-8").hex()
        with self.assertRaises(ValidationError):
            VaultSettings(
                kek=_VALID_KEK,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=hex_kek,
            )

        # 3. pepper sous forme base64 comme server_hmac_key
        b64_pepper = base64.b64encode(_VALID_PEPPER.encode("utf-8")).decode("ascii")
        with self.assertRaises(ValidationError):
            VaultSettings(
                kek=_VALID_KEK,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key=b64_pepper,
            )


class ProductionLeakDetectionTests(IsolatedAsyncioTestCase):
    """Vérification de détection : la valeur en prod est-elle celle qui a fuité ?"""

    async def test_sqlite_store_detects_leaked_production_value(self) -> None:
        """SqliteSecretStore permet de savoir si la valeur en prod a fuité sans déchiffrer."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store = SqliteSecretStore(db_path, cipher)

            leaked_value = "ghp_super_secret_leaked_token_123"
            await store.create("demo", "prod", "GH_TOKEN", leaked_value)

            # 1. La valeur testée est celle en production -> True
            is_matching = await store.is_secret_value_matching(
                "demo", "prod", "GH_TOKEN", leaked_value
            )
            self.assertTrue(is_matching)

            # 2. Une autre valeur n'est pas celle en production -> False
            self.assertFalse(
                await store.is_secret_value_matching("demo", "prod", "GH_TOKEN", "different_value")
            )

            # 3. Secret inexistant -> False
            self.assertFalse(
                await store.is_secret_value_matching("demo", "prod", "UNKNOWN", leaked_value)
            )

            # 4. Rotation du secret : la valeur en production change
            new_rotated_value = "ghp_new_safe_rotated_token_999"
            with db_session(db_path) as conn:
                aad = VaultCipher.aad("demo", "prod", "GH_TOKEN")
                env_val = cipher.encrypt_envelope(new_rotated_value.encode("utf-8"), aad=aad)
                new_fp = cipher.fingerprint(new_rotated_value.encode("utf-8"), aad=aad)
                update_secret(
                    conn,
                    "demo",
                    "prod",
                    "GH_TOKEN",
                    env_val.encrypted_value,
                    encrypted_dek=env_val.encrypted_dek,
                    fingerprint=new_fp,
                    status="rote",
                )

            # Maintenant, la valeur ayant fuité n'est PLUS celle en production !
            self.assertFalse(
                await store.is_secret_value_matching("demo", "prod", "GH_TOKEN", leaked_value)
            )
            self.assertTrue(
                await store.is_secret_value_matching("demo", "prod", "GH_TOKEN", new_rotated_value)
            )

    async def test_in_memory_store_detects_leaked_production_value(self) -> None:
        """InMemorySecretStore détecte également si la valeur en production a fuité."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        store = InMemorySecretStore(cipher=cipher)

        leaked_value = "slack_bot_token_xoxb_leaked"
        await store.create("demo", "prod", "SLACK_BOT_TOKEN", leaked_value)

        self.assertTrue(
            await store.is_secret_value_matching("demo", "prod", "SLACK_BOT_TOKEN", leaked_value)
        )
        self.assertFalse(
            await store.is_secret_value_matching("demo", "prod", "SLACK_BOT_TOKEN", "xoxb_other")
        )

    def test_cipher_is_secret_value_matching_rejects_raw_fp_when_aad_is_provided(self) -> None:
        """Non-régression double chemin : un AAD fourni n'accepte JAMAIS l'empreinte brute."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        val = "secret_cross_triplet_probe"
        raw_fp = cipher.compute_secret_hmac(val)
        aad = VaultCipher.aad("project", "env", "name")

        # Avec AAD, l'empreinte brute sans AAD doit être strictement refusée (False)
        self.assertFalse(cipher.is_secret_value_matching(val, raw_fp, aad=aad))

        # Et l'empreinte liée à l'AAD est bien acceptée
        bound_fp = cipher.fingerprint(val.encode("utf-8"), aad=aad)
        self.assertTrue(cipher.is_secret_value_matching(val, bound_fp, aad=aad))

    def test_cipher_is_secret_value_matching_in_derived_mode_raises_error(self) -> None:
        """is_secret_value_matching refuse fail-closed en mode dérivé de la KEK."""
        cipher_derived = VaultCipher(b"K" * 32)
        self.assertFalse(cipher_derived.has_explicit_server_hmac_key)
        with self.assertRaises(VaultCipherError) as ctx:
            cipher_derived.is_secret_value_matching("val", "0" * 64)
        self.assertIn("exige une clé HMAC serveur explicite", str(ctx.exception))

    async def test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed(self) -> None:
        """Après rotation KEK en mode dérivé, is_secret_value_matching échoue fail-closed."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(b"A" * 32)
            store = SqliteSecretStore(db_path, old_cipher)
            await store.create("demo", "prod", "TOKEN", "secret123")

            new_cipher = VaultCipher(b"B" * 32)
            await store.rotate_kek(new_cipher)

            # Échec fail-closed avec VaultCipherError (pas de faux négatif silencieux)
            with self.assertRaises(VaultCipherError):
                await store.is_secret_value_matching("demo", "prod", "TOKEN", "secret123")
            with self.assertRaises(VaultCipherError):
                await store.find_secrets_matching_value("demo", "secret123")

    async def test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true(self) -> None:
        """Après rotation KEK avec server_hmac_key explicite, la détection reste vraie."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(b"A" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store = SqliteSecretStore(db_path, old_cipher)
            await store.create("demo", "prod", "TOKEN", "secret123")

            # Rotation de la KEK avec le même server_hmac_key
            new_cipher = VaultCipher(b"B" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            await store.rotate_kek(new_cipher)

            # La vérification continue de fonctionner et retourne True
            self.assertTrue(
                await store.is_secret_value_matching("demo", "prod", "TOKEN", "secret123")
            )
            matches = await store.find_secrets_matching_value("demo", "secret123")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["name"], "TOKEN")

    async def test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory(self) -> None:
        """Secrets legacy sans fingerprint : parité SQLite et mémoire via repli déchiffrement."""
        # 1. En mémoire
        mem_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=mem_cipher)
        await mem_store.create("p", "prod", "LEGACY_MEM", "legacy_val")
        # Forcer la suppression de l'empreinte pour simuler un secret pré-#116
        mem_store._secrets[("p", "prod", "LEGACY_MEM")]["fingerprint"] = None

        self.assertTrue(
            await mem_store.is_secret_value_matching("p", "prod", "LEGACY_MEM", "legacy_val")
        )
        mem_matches = await mem_store.find_secrets_matching_value("p", "legacy_val")
        self.assertEqual(len(mem_matches), 1)

        # 2. En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            sql_store = SqliteSecretStore(db_path, sql_cipher)
            await sql_store.create("p", "prod", "LEGACY_SQL", "legacy_val")
            # Forcer l'empreinte à vide en base (comme dans les bases pré-#116)
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ? AND name = ?",
                    ("p", "LEGACY_SQL"),
                )

            # Parité stricte : SQLite détecte aussi le secret hérité via le repli déchiffrement
            self.assertTrue(
                await sql_store.is_secret_value_matching("p", "prod", "LEGACY_SQL", "legacy_val")
            )
            sql_matches = await sql_store.find_secrets_matching_value("p", "legacy_val")
            self.assertEqual(len(sql_matches), 1)
            self.assertEqual(sql_matches[0]["name"], "LEGACY_SQL")

    async def test_corrupted_fingerprint_in_database_handled_safely(self) -> None:
        """Une empreinte corrompue en base bascule sur le repli sans planter."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store = SqliteSecretStore(db_path, cipher)
            await store.create("p", "prod", "CORRUPT", "real_value")

            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET fingerprint = ? WHERE project_id = ? AND name = ?",
                    ("corrupted_non_hex_short_string", "p", "CORRUPT"),
                )

            self.assertTrue(
                await store.is_secret_value_matching("p", "prod", "CORRUPT", "real_value")
            )
            matches = await store.find_secrets_matching_value("p", "real_value")
            self.assertEqual(len(matches), 1)

    async def test_find_secrets_matching_value_returns_only_metadata(self) -> None:
        """find_secrets_matching_value ne retourne JAMAIS la valeur ni l'empreinte."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store = SqliteSecretStore(db_path, cipher)

            shared_leaked_value = "leaked_db_password_12345"
            await store.create("acme", "prod", "DB_PASS", shared_leaked_value)
            await store.create("acme", "staging", "DB_PASS", shared_leaked_value)
            await store.create("acme", "prod", "OTHER_PASS", "different_safe_pass")

            matches = await store.find_secrets_matching_value("acme", shared_leaked_value)
            self.assertEqual(len(matches), 2)
            names_and_envs = [(m["env"], m["name"]) for m in matches]
            self.assertIn(("prod", "DB_PASS"), names_and_envs)
            self.assertIn(("staging", "DB_PASS"), names_and_envs)

            for match in matches:
                self.assertNotIn("value", match)
                self.assertNotIn("fingerprint", match)
                self.assertNotIn("encrypted_value", match)
                self.assertNotIn("encrypted_dek", match)

            prod_matches = await store.find_secrets_matching_value(
                "acme", shared_leaked_value, env="prod"
            )
            self.assertEqual(len(prod_matches), 1)
            self.assertEqual(prod_matches[0]["name"], "DB_PASS")

    async def test_candidate_value_empty_parity_stores(self) -> None:
        """Une valeur candidate vide retourne False / [] sans déchiffrer ni planter."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)

        # 1. En mémoire
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("demo", "prod", "SEC1", "some_secret_value")
        self.assertFalse(await mem_store.is_secret_value_matching("demo", "prod", "SEC1", ""))
        self.assertEqual(await mem_store.find_secrets_matching_value("demo", ""), [])

        # 2. En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("demo", "prod", "SEC1", "some_secret_value")
            self.assertFalse(await sql_store.is_secret_value_matching("demo", "prod", "SEC1", ""))
            self.assertEqual(await sql_store.find_secrets_matching_value("demo", ""), [])

    async def test_explicit_server_hmac_key_change_fails_closed(self) -> None:
        """Changer la clé HMAC serveur invalide les empreintes et échoue fail-closed."""
        # 1. En SQLite : détection via canari persistant en base
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store1 = SqliteSecretStore(db_path, cipher1)
            await store1.create("demo", "prod", "API_KEY", "super_secret_value")

            # Réouverture du store avec une clé HMAC serveur différente
            cipher2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
            store2 = SqliteSecretStore(db_path, cipher2)

            with self.assertRaises(VaultCipherError) as ctx_sql_is:
                await store2.is_secret_value_matching(
                    "demo", "prod", "API_KEY", "super_secret_value"
                )
            self.assertIn("modifiée", str(ctx_sql_is.exception))

            with self.assertRaises(VaultCipherError) as ctx_sql_find:
                await store2.find_secrets_matching_value("demo", "super_secret_value")
            self.assertIn("modifiée", str(ctx_sql_find.exception))

        # 2. En mémoire : détection via canari du store
        mem_store = InMemorySecretStore(cipher=cipher1)
        await mem_store.create("demo", "prod", "API_KEY", "super_secret_value")
        # Simuler un changement de cipher sous-jacent
        mem_store._cipher = cipher2

        with self.assertRaises(VaultCipherError) as ctx_mem_is:
            await mem_store.is_secret_value_matching(
                "demo", "prod", "API_KEY", "super_secret_value"
            )
        self.assertIn("modifiée", str(ctx_mem_is.exception))

        with self.assertRaises(VaultCipherError) as ctx_mem_find:
            await mem_store.find_secrets_matching_value("demo", "super_secret_value")
        self.assertIn("modifiée", str(ctx_mem_find.exception))

    async def test_sqlite_create_with_changed_server_hmac_key_fails_closed(self) -> None:
        """SqliteSecretStore.create refuse fail-closed si la clé HMAC a changé."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store1 = SqliteSecretStore(db_path, cipher1)
            await store1.create("demo", "prod", "INITIAL", "initial_val")

            # 1. Tentative d'écriture sous une clé HMAC différente -> VaultCipherError
            cipher2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
            store2 = SqliteSecretStore(db_path, cipher2)
            with self.assertRaises(VaultCipherError) as ctx_create:
                await store2.create("demo", "prod", "NEW_SECRET", "new_val")
            self.assertIn("modifiée", str(ctx_create.exception))

            # 2. Le secret NEW_SECRET n'a PAS été créé en base
            with db_session(db_path) as conn:
                record = get_secret_metadata(conn, "demo", "prod", "NEW_SECRET")
                self.assertIsNone(record)

            # 3. Revenir à cipher1 : l'état reste cohérent et les lectures fonctionnent
            self.assertTrue(
                await store1.is_secret_value_matching("demo", "prod", "INITIAL", "initial_val")
            )

    async def test_in_memory_create_with_changed_server_hmac_key_fails_closed(self) -> None:
        """InMemorySecretStore.create refuse fail-closed si la clé HMAC a changé."""
        cipher1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=cipher1)
        await mem_store.create("demo", "prod", "INITIAL", "initial_val")

        cipher2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
        mem_store._cipher = cipher2
        with self.assertRaises(VaultCipherError):
            await mem_store.create("demo", "prod", "NEW_SECRET", "new_val")

    def test_database_find_secrets_by_fingerprint_uses_index(self) -> None:
        """find_secrets_by_fingerprint retourne les métadonnées sans déchiffrer."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                ensure_project(conn, "proj1")
                fp = "0123456789abcdef" * 4
                create_secret(
                    conn,
                    "proj1",
                    "prod",
                    "SEC_1",
                    "enc_blob_1",
                    fingerprint=fp,
                )
                create_secret(
                    conn,
                    "proj1",
                    "dev",
                    "SEC_2",
                    "enc_blob_2",
                    fingerprint=fp,
                )
                create_secret(
                    conn,
                    "proj1",
                    "prod",
                    "SEC_3",
                    "enc_blob_3",
                    fingerprint="f" * 64,
                )

                found = find_secrets_by_fingerprint(conn, "proj1", fp)
                self.assertEqual(len(found), 2)
                self.assertEqual([f["name"] for f in found], ["SEC_2", "SEC_1"])
                for item in found:
                    self.assertNotIn("encrypted_value", item)
                    self.assertNotIn("fingerprint", item)


class FingerprintNeverReturnedToClientTests(TestCase):
    """Vérification stricte de la checklist : l'empreinte n'est JAMAIS renvoyée au client."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-hmac-api-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        self.api_key = generate_project_api_key()
        self.settings = VaultSettings(
            kek=_VALID_KEK,
            api_key_pepper=_VALID_PEPPER,
            server_hmac_key=_VALID_SERVER_HMAC_KEY,
            storage_backend="sqlite",
            db_path=str(self.db_path),
            require_auth=True,
        )
        self.app = create_app(self.settings)
        self.client = TestClient(
            self.app,
            base_url="http://127.0.0.1:8443",
            client=("127.0.0.1", 50000),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_api_responses_never_expose_fingerprint(self) -> None:
        """Aucune réponse API (POST, GET, state, list) ne contient l'attribut 'fingerprint'."""
        self.app.state.register_api_key(self.api_key, "myproj")
        headers = {"X-Heimdall-API-Key": self.api_key}

        # 1. POST /api/v1/secrets
        post_resp = self.client.post(
            "/api/v1/secrets",
            json={
                "project": "myproj",
                "env": "prod",
                "name": "MY_SECRET",
                "value": "secret_plain_value_42",
            },
            headers=headers,
        )
        self.assertEqual(post_resp.status_code, 201)
        post_data = post_resp.json()
        self.assertNotIn("fingerprint", post_data)
        self.assertNotIn("value", post_data)
        self.assertEqual(set(post_data.keys()), {"project", "env", "name", "status"})

        # 2. GET /api/v1/secrets/{project}/{env}/{name}
        get_resp = self.client.get("/api/v1/secrets/myproj/prod/MY_SECRET", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertNotIn("fingerprint", get_data)
        self.assertEqual(get_data["value"], "secret_plain_value_42")
        self.assertEqual(set(get_data.keys()), {"project", "env", "name", "status", "value"})

        # 3. GET /api/v1/secrets/{project}/{env}/{name}/state
        state_resp = self.client.get("/api/v1/secrets/myproj/prod/MY_SECRET/state", headers=headers)
        self.assertEqual(state_resp.status_code, 200)
        state_data = state_resp.json()
        self.assertNotIn("fingerprint", state_data)
        self.assertNotIn("value", state_data)
        self.assertEqual(set(state_data.keys()), {"project", "env", "name", "status"})

        # 4. GET /api/v1/secrets
        list_resp = self.client.get("/api/v1/secrets?project=myproj", headers=headers)
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.json()
        self.assertEqual(len(list_data["items"]), 1)
        item = list_data["items"][0]
        self.assertNotIn("fingerprint", item)
        self.assertNotIn("value", item)
        self.assertEqual(set(item.keys()), {"project", "env", "name", "status"})

    def test_no_http_route_exposes_fingerprint_or_leak_detection(self) -> None:
        """Aucune route HTTP n'expose l'empreinte ou l'API de fuite (réservé à #117)."""
        for route in self.app.routes:
            path = getattr(route, "path", "")
            self.assertNotIn("fingerprint", path.lower())
            self.assertNotIn("matching", path.lower())
            self.assertNotIn("leak", path.lower())


class KeyLeakHuntTests(TestCase):
    """Vérification de l'absence de fuite de la clé HMAC serveur dans logs, exceptions et repr()."""

    def test_server_hmac_key_is_never_leaked_in_repr_or_serialization(self) -> None:
        """repr/model_dump/model_dump_json n'exposent jamais la clé HMAC serveur."""
        canary = "HMAC_CANARY_UNIQUE_SECRET_VAL_12345!"
        settings = VaultSettings(
            kek=_VALID_KEK,
            api_key_pepper=_VALID_PEPPER,
            server_hmac_key=canary,
        )

        rendered = "\n".join(
            (repr(settings), str(settings.model_dump()), settings.model_dump_json())
        )
        self.assertNotIn(canary, rendered)

        cipher = VaultCipher(b"K" * 32, server_hmac_key=canary)
        self.assertNotIn(canary, repr(cipher))
