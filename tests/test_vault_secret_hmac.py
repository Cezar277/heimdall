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
import importlib.util
import re
import secrets
import sqlite3
import sys
import tempfile
import unicodedata
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from heimdall.vault import app as vault_app
from heimdall.vault import crypto as vault_crypto
from heimdall.vault.app import (
    VaultSettings,
    create_app,
)
from heimdall.vault.auth import generate_project_api_key
from heimdall.vault.crypto import (
    _SHA256_HEX_LEN,
    MAX_SERVER_HMAC_KEY_BYTES,
    VaultCipher,
    VaultCipherError,
    _extract_key_variants,
    _normalize_server_hmac_key,
    canonicalize_secret_value,
    compute_secret_hmac,
    generate_server_hmac_key,
    server_hmac_key_matches_master_key,
    validate_server_hmac_key,
    verify_secret_hmac,
)
from heimdall.vault.database import (
    create_secret,
    db_session,
    ensure_project,
    find_secrets_by_fingerprint,
    get_secret_metadata,
    get_server_hmac_canary,
    init_db,
    set_server_hmac_canary,
    update_secret,
)
from heimdall.vault.store import (
    InMemorySecretStore,
    SqliteSecretStore,
)

# Clés de test robustes et diversifiées (satisfaisant les contrôles d'entropie)
_VALID_SERVER_HMAC_KEY = "k7_H9mP2xW4vL1zR8yB3qT6nF0sV5jC8dE4uA1gX7oZ"
_VALID_ALT_HMAC_KEY = "m3_Q8vK1zT6nF0sV5jC8dE4uA1gX7oZ2xW4vL9yB3rP"
_VALID_KEK = generate_server_hmac_key()  # base64url 256 bits valide (anti-flakiness)
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
        """verify_secret_hmac et is_secret_value_matching refusent un AAD vide (ValueError)."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        dummy_fp = "a" * 64

        with self.assertRaises(ValueError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", dummy_fp, aad=b"")
        with self.assertRaises(ValueError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", dummy_fp, aad="")
        with self.assertRaises(ValueError):
            cipher.is_secret_value_matching("val", dummy_fp, aad=b"")
        with self.assertRaises(ValueError):
            cipher.is_secret_value_matching("val", dummy_fp, aad="")

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

    def test_compute_and_verify_secret_hmac_supports_bytearray_types(self) -> None:
        """compute_secret_hmac et verify_secret_hmac acceptent bytearray pour clé, valeur et AAD."""
        key_str = _VALID_SERVER_HMAC_KEY
        key_ba = bytearray(key_str.encode("utf-8"))
        val_str = "secret_to_hash_bytearray"
        val_ba = bytearray(val_str.encode("utf-8"))
        aad_str = "aad_context_42"
        aad_ba = bytearray(aad_str.encode("utf-8"))

        # 1. Calcul avec bytearray identique au calcul avec str/bytes
        fp_str = compute_secret_hmac(key_str, val_str, aad=aad_str)
        fp_ba = compute_secret_hmac(key_ba, val_ba, aad=aad_ba)
        self.assertEqual(fp_ba, fp_str)

        # 2. verify_secret_hmac accepte également bytearray
        self.assertTrue(verify_secret_hmac(key_ba, val_ba, fp_str, aad=aad_ba))

        # 3. Rejet fail-closed sur type non supporté (int, etc.)
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, 12345)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            compute_secret_hmac(12345, val_str)  # type: ignore[arg-type]

    def test_compute_and_verify_secret_hmac_reject_non_str_bytes_bytearray_aad(self) -> None:
        """Refuse aad=int/memoryview (anti-bytes(int)) tout en acceptant str/bytes/bytearray."""
        fp_nul = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "secret_val", aad=b"\x00" * 3)
        fp_ctx = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "secret_val", aad="ctx")
        self.assertEqual(
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "secret_val", aad=bytearray(b"ctx")),
            fp_ctx,
        )
        self.assertTrue(
            verify_secret_hmac(
                _VALID_SERVER_HMAC_KEY, "secret_val", fp_ctx, aad=bytearray(b"ctx")
            )
        )

        # aad=3 ou memoryview ne doit jamais être converti en bytes(3) (b"\x00\x00\x00")
        for bad_aad in (3, 123, memoryview(b"ctx"), memoryview(b"\x00" * 3)):
            with self.subTest(bad_aad=bad_aad):
                with self.assertRaises(TypeError):
                    compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "secret_val", aad=bad_aad)  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    verify_secret_hmac(
                        _VALID_SERVER_HMAC_KEY,
                        "secret_val",
                        fp_nul,
                        aad=bad_aad,  # type: ignore[arg-type]
                    )

        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        for bad_aad in (123, memoryview(b"ctx")):
            with self.subTest(cipher_bad_aad=bad_aad):
                with self.assertRaises(TypeError):
                    cipher.compute_secret_hmac("secret_val", aad=bad_aad)  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    cipher.verify_secret_hmac("secret_val", fp_ctx, aad=bad_aad)  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    cipher.is_secret_value_matching(
                        "secret_val",
                        fp_ctx,
                        aad=bad_aad,  # type: ignore[arg-type]
                    )
                with self.assertRaises(TypeError):
                    cipher.fingerprint("secret_val", aad=bad_aad)  # type: ignore[arg-type]

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
        """Refuse les clés subtilement faibles (période, diversité < 24, entropie < 4.0)."""
        # Tests limites demandés par la revue :
        # 1. Période 8 avec 8 symboles distincts ("ABCDEFGH" * 4 = 32 octets)
        with self.assertRaises(ValueError) as ctx1:
            _normalize_server_hmac_key("ABCDEFGH" * 4)
        self.assertIn("generate_server_hmac_key()", str(ctx1.exception))

        # 2. Période 8 avec 8 chiffres distincts ("01234567" * 4 = 32 octets)
        with self.assertRaises(ValueError) as ctx2:
            _normalize_server_hmac_key("01234567" * 4)
        self.assertIn("generate_server_hmac_key()", str(ctx2.exception))

        # 3. Motif périodique de 10 caractères avec diversité insuffisante ("0123456789" * 3 + "01")
        with self.assertRaises(ValueError) as ctx3:
            _normalize_server_hmac_key("0123456789" * 3 + "01")
        self.assertIn("generate_server_hmac_key()", str(ctx3.exception))

        # 4. Motif de période 16 avec 16 symboles distincts ("abcdefghijklmnop" * 2 = 32 octets)
        with self.assertRaises(ValueError) as ctx4:
            _normalize_server_hmac_key("abcdefghijklmnop" * 2)
        self.assertIn("generate_server_hmac_key()", str(ctx4.exception))

        # 5. Motif hexadécimal de 16 symboles distincts ("0123456789abcdef" * 2 = 32 octets)
        with self.assertRaises(ValueError) as ctx5:
            _normalize_server_hmac_key("0123456789abcdef" * 2)
        self.assertIn("generate_server_hmac_key()", str(ctx5.exception))

        # 6. Non-périodique mais diversité < 24 ("0123456789abcdef0123456789abcdeg" = 17 symboles)
        with self.assertRaises(ValueError) as ctx6:
            _normalize_server_hmac_key("0123456789abcdef0123456789abcdeg")
        self.assertIn("generate_server_hmac_key()", str(ctx6.exception))

    def test_validate_server_hmac_key_rejects_hex_keys_by_construction(self) -> None:
        """Les clés hexadécimales (16 symboles max < 24) sont refusées explicitement."""
        for _ in range(8):
            hex_key = secrets.token_hex(32)
            with self.subTest(hex_key=hex_key):
                with self.assertRaises(ValueError) as ctx:
                    validate_server_hmac_key(hex_key)
                msg = str(ctx.exception)
                self.assertIn("hexadécimales", msg)
                self.assertIn("generate_server_hmac_key()", msg)

    def test_normalize_server_hmac_key_rejects_human_passphrase_phrases(self) -> None:
        """Refuse une phrase naturelle de 32+ octets malgré diversité et Shannon suffisants.

        Revue LOW #116 : la phrase ci-dessous franchit les anciens seuils (24
        symboles distincts, Shannon >= 4.0) tout en ne portant que ~60-80 bits
        effectifs (mots de dictionnaire) : attaquable hors ligne avec un dump
        SQLite et le canari public. Le garde anti-phrase la refuse fail-closed.
        """
        weak_phrases = [
            # 1. Phrase anglaise (xkcd) de 65 octets, 24 symboles distincts, Shannon ~4.12
            "Correct Horse Battery Staple is a famous xkcd passphrase example.",
            # 2. Phrase française avec accents (NFKD + espaces), 25 symboles, Shannon ~4.13
            (
                "Le canari public et le dump SQLite suffisent à attaquer cette "
                "phrase hors ligne, hélas."
            ),
            # 3. Phrase basse-casse sans ponctuation excédant 32 caractères normalisés
            "the quick brown fox jumps over the lazy dog and walks away quietly",
            # 4. Phrase en capitales avec espaces (revue MEDIUM #116)
            "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND WALKS AWAY QUIETLY",
            # 5. Phrase en capitales sans séparateur (règle majuscules)
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDWALKSAWAYQUIETLY",
            # 6. Phrase à casse mixte séparée par des espaces (règle 3)
            "This Is A Very Long Mixed Case Human Phrase Used As A Secret Key",
            # 7. Phrase à chiffres séparés par des espaces (chiffres comptés par la règle 3)
            "123 the quick brown fox jumps over 456 lazy dogs 789 and 0",
            # 8. Phrase CamelCase sans séparateur (revue LOW #116 : 45 chars, Shannon > 4.0)
            "CorrectHorseBatteryStapleExtraWordPlusMore123",
            # 9. Phrase CamelCase avec chiffres sans espaces (variante avec chiffres sans espaces)
            "CorrectHorse123Battery456Staple789Word000More111",
            # 10. Phrase CamelCase pure sans chiffres avec diversité de symboles suffisante
            "TheQuickBrownFoxJumpsOverTheLazyDogAndMore",
            # 11. Phrase avec ponctuation séparatrice (revue LOW #116 : 53 chars, Shannon ~4.15)
            "Correct-Horse-Battery-Staple-Extra-Word-Plus-More-12!",
            # 12. Phrase séparée par des points ou underscores
            "Correct.Horse.123.Battery.456.Staple.789.Word.More.Extra.Plus!",
            # 13. Phrase à casse alternée avec séparateurs (revue LOW #116 : 56 chars, Shannon ~4.7)
            "cOrReCt-hOrSe-BaTtErY-sTaPlE-eXtRa-WoRdS-1234-ABCD-xyzQ!",
            # 14. Variante à casse alternée sans séparateurs (revue LOW #116 : 59 chars)
            "cOrReCtHoRsEBaTtErYsTaPlEeXtRaWoRdS1234ABCDxyzQ!PlusMore456",
            # 15. Phrase avec tabulations et ponctuation (revue LOW #116 : >=32 chars)
            "correct\thorse\tbattery\tstaple\textra\twords\t1234-ABCD-xyzQ!0123456789",
            # 16. Phrase avec espace insécable (\u00a0) et ponctuation (revue LOW #116)
            "correct\u00a0horse\u00a0battery\u00a0staple\u00a0extra\u00a0words\u00a01234-ABCD-xyzQ!0123456789",
            # 17. Phrase basse-casse pure avec tabulations sans ponctuation (revue LOW #116)
            "correct\thorse\tbattery\tstaple\textra\twords\t1234567890abcdef",
            # 18. Phrase basse-casse pure avec espace insécable sans ponctuation (revue LOW #116)
            "correct\u00a0horse\u00a0battery\u00a0staple\u00a0extra\u00a0words\u00a01234567890abcdef",
        ]
        for phrase in weak_phrases:
            with self.subTest(phrase=phrase):
                with self.assertRaises(ValueError) as ctx:
                    validate_server_hmac_key(phrase)
                self.assertIn("phrase naturelle", str(ctx.exception))

        # Vérifier que validate_server_hmac_key lève également sur la phrase en capitales
        with self.assertRaises(ValueError) as ctx_v:
            validate_server_hmac_key(
                "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND WALKS AWAY QUIETLY"
            )
        self.assertIn("phrase naturelle", str(ctx_v.exception))

        # Aucun faux positif sur la voie supportée : clé de test et clés générées
        _normalize_server_hmac_key(_VALID_SERVER_HMAC_KEY)
        for _ in range(64):
            _normalize_server_hmac_key(generate_server_hmac_key())

    def test_normalize_server_hmac_key_rejects_unlisted_separators(self) -> None:
        """Refuse une phrase de dictionnaire séparée par des symboles hors liste.

        Revue LOW #226 : ``_HUMAN_PHRASE_SEPARATORS`` est une liste fermée
        (" -_.:,;!?/") ; une phrase à casse mixte et à leetspeak séparée par
        "#" ou "@" franchissait diversité (>= 24 symboles), Shannon (>= 4.0)
        et toutes les signatures de phrase naturelle (règles 1 à 5), donc
        ``validate_server_hmac_key`` l'acceptait malgré ~60-80 bits effectifs.
        La normalisation défensive (tout non-alphanumérique ASCII réduit à un
        blanc, squelette alphabérique >= 2 lettres par mot) rend la garde
        insensible au séparateur choisi et aux mutations leet.
        """
        weak_keys = [
            # 58 o, 26 symboles distincts, Shannon ~4.28, séparateur "#" (revue LOW #226)
            "C0rr3ct#H0rs3#B4tt3ry#St4pl3#3xtr4#W0rds#1234#ABCD#xyzQ!9z",
            # Variante "@" du même leetspeak à casse mixte (revue LOW #226)
            "C0rr3ct@H0rs3@B4tt3ry@St4pl3@3xtr4@W0rds@1234@ABCD@xyzQ!9z",
            # 60 o, 28 symboles distincts, Shannon ~4.34, séparateur "#" (revue LOW #226)
            "correct#horse#battery#staple#extra#words#1234#ABCD#xyzQ!9z##",
            # Variante "@" basse-casse (revue LOW #226)
            "correct@horse@battery@staple@extra@words@1234@ABCD@xyzQ!9z@@",
        ]
        for key in weak_keys:
            with self.subTest(key=key):
                # Précondition : ces clés franchissent diversité et Shannon, et ne
                # sont refusées que par la garde anti-phrase (d'où le message attendu).
                self.assertGreaterEqual(len(key.encode("utf-8")), 32)
                self.assertGreaterEqual(len(set(key)), 24)
                with self.assertRaises(ValueError) as ctx:
                    validate_server_hmac_key(key)
                self.assertIn("phrase naturelle", str(ctx.exception))
                # Non-périodique : le refus ne vient pas de la garde de périodicité.
                key_bytes = key.encode("utf-8")
                self.assertFalse(
                    any(
                        all(key_bytes[i] == key_bytes[i % period] for i in range(len(key_bytes)))
                        for period in range(1, len(key_bytes) // 2 + 1)
                    )
                )

        # Aucun faux positif sur la voie supportée après durcissement
        _normalize_server_hmac_key(_VALID_SERVER_HMAC_KEY)
        for _ in range(64):
            _normalize_server_hmac_key(generate_server_hmac_key())

    def test_validate_server_hmac_key_rejects_camel_and_alternating_unlisted_separators(
        self,
    ) -> None:
        """Alignement des règles CamelCase et casse alternée sur normalized_ascii.

        Vérifie que ``CorrectHorseBatteryStapleExtraWords1234#ABCD`` (sans
        espaces, séparateur ``#``) et la variante à casse alternée sans espaces
        sont rejetés sur le domaine normalisé ``normalized_ascii`` et que la
        constante fermée morte ``_HUMAN_PHRASE_SEPARATORS`` a été supprimée.
        """
        self.assertFalse(hasattr(vault_crypto, "_HUMAN_PHRASE_SEPARATORS"))
        for key in (
            "CorrectHorseBatteryStapleExtraWords1234#ABCD",
            "cOrReCtHoRsEBaTtErYsTaPlEeXtRaWoRdS#1234!A",
            "cOrReCtHoRsEBaTtErYsTaPlEeXtRa##1234!AxyZq98",
        ):
            with self.subTest(key=key):
                self.assertGreaterEqual(len(set(key)), 24)
                with self.assertRaises(ValueError) as ctx:
                    validate_server_hmac_key(key)
                self.assertIn("phrase naturelle", str(ctx.exception))

    def test_validate_server_hmac_key_rejects_non_ascii_human_phrases(self) -> None:
        """La garde anti-phrase couvre les alphabets non-ASCII (cyrillique, grec, ...)."""
        non_ascii_phrases = (
            "Секретная_фраза_на_русском_языке_1234567890_ключ",
            "СекретнаяФразаНаРусскомЯзыкеДляТеста1234567890!@",
            "ΜυστικήΦράσηΣταΕλληνικάΓιαΈλεγχο1234567890!@xyz",
            "секретная фраза на русском языке 1234567890 ключ!",
        )
        for phrase in non_ascii_phrases:
            with self.subTest(phrase=phrase):
                self.assertGreaterEqual(len(set(phrase.encode("utf-8"))), 24)
                with self.assertRaises(ValueError) as ctx:
                    validate_server_hmac_key(phrase)
                self.assertIn("phrase naturelle", str(ctx.exception))

    def test_cipher_fingerprint_canonicalizes_nfc_like_compute_secret_hmac(self) -> None:
        """VaultCipher.fingerprint canonise en NFC, parité avec compute_secret_hmac.

        Revue LOW #226 : ``fingerprint()`` nue calculait l'empreinte sur les
        octets bruts sans canonicalisation, alors que ``compute_secret_hmac``
        / ``is_secret_value_matching`` normalisent (NFD -> NFC). Un appelant
        librairie passant des octets NFD obtenait une empreinte différente de
        celle stockée -> faux négatif silencieux de détection (invariant 1).
        """
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        aad = VaultCipher.aad("project", "prod", "TOKEN")

        # "école" en NFC et en NFD : les octets NFD ("e" + accent combinant U+0301)
        # doivent produire la même empreinte que la forme NFC.
        value_nfc = unicodedata.normalize("NFC", "école secrète")
        value_nfd = unicodedata.normalize("NFD", value_nfc)
        self.assertNotEqual(value_nfc.encode("utf-8"), value_nfd.encode("utf-8"))

        fp_nfc = cipher.fingerprint(value_nfc.encode("utf-8"), aad=aad)
        fp_nfd = cipher.fingerprint(value_nfd.encode("utf-8"), aad=aad)
        self.assertEqual(fp_nfc, fp_nfd)

        # Parité contractuelle : fingerprint(canonicalize(v)) == compute_secret_hmac(v, aad=aad)
        v = "sécret~valeur"
        v_nfd = unicodedata.normalize("NFD", v).encode("utf-8")
        self.assertEqual(
            cipher.fingerprint(canonicalize_secret_value(v_nfd), aad=aad),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, v, aad=aad),
        )
        # Idempotence : l'octet déjà canonisé n'est pas altéré (stabilité des
        # empreintes persistées avant correctif).
        nfc_bytes = value_nfc.encode("utf-8")
        self.assertEqual(canonicalize_secret_value(nfc_bytes), nfc_bytes)
        # Les secrets binaires non-UTF8 restent pris tels quels.
        binary = bytes(range(0, 32))
        self.assertEqual(
            cipher.fingerprint(binary, aad=aad),
            hmac.new(
                _VALID_SERVER_HMAC_KEY.encode("utf-8"),
                bytes(aad) + b"\x00" + binary,
                hashlib.sha256,
            ).hexdigest(),
        )

    def test_cipher_fingerprint_accepts_str_bytes_bytearray_and_str_aad_parity(self) -> None:
        """Parité str | bytes | bytearray et domaines AAD sur VaultCipher.fingerprint()."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertEqual(cipher.fingerprint("str"), cipher.fingerprint(b"str"))
        self.assertEqual(cipher.fingerprint("str"), cipher.fingerprint(bytearray(b"str")))

        # Parité sans AAD (aad=None) : même domaine que compute_secret_hmac et matching
        fp_raw = cipher.fingerprint(b"val")
        self.assertEqual(fp_raw, cipher.compute_secret_hmac(b"val"))
        self.assertEqual(fp_raw, compute_secret_hmac(_VALID_SERVER_HMAC_KEY, b"val"))
        self.assertTrue(cipher.is_secret_value_matching(b"val", fp_raw))

        # Parité rejet AAD vide (b"" / "") : aucun 3e domaine silencieux
        with self.assertRaises(ValueError):
            cipher.fingerprint(b"val", aad=b"")
        with self.assertRaises(ValueError):
            cipher.fingerprint(b"val", aad="")
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, b"val", aad=b"")

        expected_ctx = cipher.compute_secret_hmac("caf\u00e9", aad="ctx")
        self.assertEqual(cipher.fingerprint("caf\u00e9", aad="ctx"), expected_ctx)
        self.assertEqual(cipher.fingerprint("cafe\u0301", aad="ctx"), expected_ctx)
        self.assertEqual(
            cipher.fingerprint(bytearray("cafe\u0301".encode("utf-8")), aad=bytearray(b"ctx")),
            expected_ctx,
        )
        self.assertEqual(
            cipher.fingerprint(b"caf\xc3\xa9", aad=b"ctx"),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "caf\u00e9", aad="ctx"),
        )

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

        # Les erreurs de préconditions sur les entrées lèvent ValueError/TypeError (fail-closed)
        with self.assertRaises(ValueError):
            verify_secret_hmac(key, "", expected)
        with self.assertRaises(ValueError):
            verify_secret_hmac(key, b"", expected)
        with self.assertRaises(ValueError):
            verify_secret_hmac("short", valeur, expected)
        with self.assertRaises(TypeError):
            verify_secret_hmac(key, 12345, expected)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            verify_secret_hmac(key, valeur, expected, aad="")
        with self.assertRaises(ValueError):
            verify_secret_hmac(key, valeur, expected, aad=b"")

    def test_verify_secret_hmac_and_cipher_matching_with_corrupted_fingerprint(self) -> None:
        """verify_secret_hmac et is_secret_value_matching renvoient False sur empreinte corrompue.

        Tranché (décision d'architecture) : longueur != 64, majuscules, non-hex ou types invalides
        retournent False sans exception (prédicat booléen pur).
        """
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        val = "test-secret-value-check"
        valid_fp = cipher.compute_secret_hmac(val)

        corrupted_cases = [
            "invalid_len",
            "a" * 63,
            "a" * 65,
            "",
            valid_fp.upper(),  # majuscules
            "g" * 64,  # non-hex minuscules
            "Z" * 64,  # non-hex majuscules
            "0123456789abcdef" * 3 + "xyz!",  # symboles hors hex
            12345,  # non-str int
            None,  # None
            b"0" * 64,  # bytes
        ]

        for bad_fp in corrupted_cases:
            with self.subTest(bad_fp=bad_fp):
                self.assertFalse(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, val, bad_fp))  # type: ignore[arg-type]
                self.assertFalse(cipher.verify_secret_hmac(val, bad_fp))  # type: ignore[arg-type]
                self.assertFalse(cipher.is_secret_value_matching(val, bad_fp))  # type: ignore[arg-type]
                aad = VaultCipher.aad("p", "prod", "S")
                self.assertFalse(cipher.is_secret_value_matching(val, bad_fp, aad=aad))  # type: ignore[arg-type]

    def test_compute_raises_while_predicates_return_false_contract_parity(self) -> None:
        """Verrouille la divergence documentée : compute lève, les prédicats retournent False.

        Revue LOW #116 — contrat verrouillé (décision d'architecture, docstrings
        ``compute_secret_hmac`` / ``verify_secret_hmac`` / ``is_secret_value_matching``) :
        - ``compute_secret_hmac`` lève ``ValueError``/``TypeError`` sur entrées invalides
          du calcul (clé courte/faible, valeur vide, AAD vide, type invalide) : fail-closed.
        - ``verify_secret_hmac`` et ``is_secret_value_matching`` retournent ``False`` sans
          exception sur une **empreinte attendue malformée** (format ``^[0-9a-f]{64}$`` non
          respecté) : une empreinte corrompue ne peut correspondre à aucun secret.
        - Mais ces prédicats **propagent** toujours les exceptions du calcul (valeur vide,
          AAD vide, clé faible) : ``False`` est réservé au format de l'empreinte attendue,
          jamais à une entrée du calcul — aucun faux négatif silencieux possible.
        Tout futur câblage de ces primitives doit respecter ce partage explicite.
        """
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        val = "contract-parity-value"
        good_fp = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, val)

        malformed_expected = [
            "a" * 63,  # longueur 63
            "a" * 65,  # longueur 65
            "",  # vide
            "G" * 64,  # majuscules
            "g" * 64,  # non-hex minuscules
            "0" * 32 + "xyz!",  # symboles hors hex
            12345,  # type non-str
            None,  # None
            b"0" * 64,  # bytes
        ]

        # 1. compute lève sur ses entrées invalides (fail-closed)
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "")
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, val, aad=b"")
        with self.assertRaises(ValueError):
            compute_secret_hmac("short_key_16_bytes!", val)
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, 12345)  # type: ignore[arg-type]

        # 2. Les prédicats retournent False (jamais d'exception) sur empreinte malformée
        for bad_fp in malformed_expected:
            with self.subTest(bad_fp=bad_fp):
                self.assertFalse(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, val, bad_fp))  # type: ignore[arg-type]
                self.assertFalse(cipher.verify_secret_hmac(val, bad_fp))  # type: ignore[arg-type]
                self.assertFalse(cipher.is_secret_value_matching(val, bad_fp))  # type: ignore[arg-type]

        # 3. Mais les prédicats PROPAGENT les exceptions du calcul (aucun faux négatif)
        with self.assertRaises(ValueError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "", good_fp)
        with self.assertRaises(ValueError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, val, good_fp, aad=b"")
        with self.assertRaises(ValueError):
            verify_secret_hmac("short_key_16_bytes!", val, good_fp)
        with self.assertRaises(TypeError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, 12345, good_fp)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            cipher.verify_secret_hmac("", good_fp)
        with self.assertRaises(ValueError):
            cipher.verify_secret_hmac(val, good_fp, aad=b"")
        with self.assertRaises(TypeError):
            cipher.is_secret_value_matching(12345, good_fp)  # type: ignore[arg-type]
        self.assertFalse(cipher.is_secret_value_matching("", good_fp))
        with self.assertRaises(ValueError):
            cipher.is_secret_value_matching(val, good_fp, aad=b"")

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

    def test_validate_server_hmac_key_rejects_overlong_keys(self) -> None:
        """Une clé HMAC dépassant 512 octets est refusée pour prévenir les abus CPU."""
        with self.assertRaises(ValueError) as ctx:
            validate_server_hmac_key("A" * 4096)
        self.assertIn("ne doit pas dépasser 512 octets", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_server_hmac_key(b"B" * (MAX_SERVER_HMAC_KEY_BYTES + 1))

        with self.assertRaises(ValidationError):
            VaultSettings(
                kek=_VALID_KEK,
                api_key_pepper=_VALID_PEPPER,
                server_hmac_key="A" * 4096,
            )

    def test_is_secret_value_matching_rejects_non_string_bytes_types(self) -> None:
        """is_secret_value_matching valide le type en tête et lève TypeError sur types invalides."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        valid_fp = "a" * 64

        # Sans AAD
        with self.assertRaises(TypeError):
            cipher.is_secret_value_matching(123, valid_fp)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            cipher.is_secret_value_matching(object(), valid_fp)  # type: ignore[arg-type]

        # Avec AAD
        with self.assertRaises(TypeError):
            cipher.is_secret_value_matching(123, valid_fp, aad=b"context")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            cipher.is_secret_value_matching("val", valid_fp, aad=123)  # type: ignore[arg-type]


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

        # Revue LOW #116 : HMAC faible égale à master détectée avant normalisation
        weak_master = b"W" * 32
        weak_b64 = base64.b64encode(weak_master).decode("ascii")  # "V1dX..." (répétitif -> faible)
        weak_hex = weak_master.hex()  # "5757..." (répétitif -> faible)
        self.assertTrue(server_hmac_key_matches_master_key(weak_master, weak_b64))
        self.assertTrue(server_hmac_key_matches_master_key(weak_master, weak_hex))
        self.assertTrue(server_hmac_key_matches_master_key(weak_b64, weak_master))
        # Clé HMAC faible distincte -> retourne False sans lever
        self.assertFalse(server_hmac_key_matches_master_key(weak_master, "short"))
        self.assertFalse(server_hmac_key_matches_master_key(weak_master, "A" * 32))

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

    def test_from_master_key_rejects_server_hmac_key_equal_to_master_key(self) -> None:
        """from_master_key refuse la clé HMAC réutilisant l'entropie maîtresse.

        Invariant 5, revue LOW #116 : ``from_master_key(master, salt,
        server_hmac_key=master)`` dérive KEK=Argon2id(master) ; le contrôle
        interne KEK vs HMAC passait (KEK != master) alors que l'empreinte
        réutilisait directement l'entropie maîtresse. La garde master vs HMAC
        est désormais faite dans ``from_master_key``, fail-closed avant toute
        dérivation.
        """
        salt = base64.urlsafe_b64encode(b"S" * 16).decode("ascii")
        with self.assertRaises(ValueError) as ctx:
            VaultCipher.from_master_key(_VALID_MASTER_KEY, salt, server_hmac_key=_VALID_MASTER_KEY)
        self.assertIn("distincte de la clé maîtresse", str(ctx.exception))

        # Variante encodée (base64 de la clé maîtresse) également refusée
        encoded_master = base64.urlsafe_b64encode(_VALID_MASTER_KEY.encode("utf-8")).decode("ascii")
        with self.assertRaises(ValueError):
            VaultCipher.from_master_key(_VALID_MASTER_KEY, salt, server_hmac_key=encoded_master)

        # Une clé HMAC distincte reste acceptée (pas de faux positif) : dérivation complète
        cipher = VaultCipher.from_master_key(
            _VALID_MASTER_KEY, salt, server_hmac_key=_VALID_SERVER_HMAC_KEY
        )
        self.assertTrue(cipher.has_explicit_server_hmac_key)

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

    def test_compute_and_verify_secret_hmac_reject_forbidden_keys(self) -> None:
        """compute_secret_hmac et verify_secret_hmac refusent toute réutilisation d'entropie."""
        kek = _VALID_KEK
        value = "secret_to_hash"

        # 1. compute_secret_hmac avec KEK directe dans forbidden_keys -> ValueError
        with self.assertRaises(ValueError) as ctx:
            compute_secret_hmac(kek, value, forbidden_keys=(kek,))
        self.assertIn("ne peut pas réutiliser l'entropie", str(ctx.exception))

        # 2. verify_secret_hmac avec KEK directe dans forbidden_keys -> ValueError
        dummy_fp = "a" * 64
        with self.assertRaises(ValueError) as ctx_v:
            verify_secret_hmac(kek, value, dummy_fp, forbidden_keys=(kek,))
        self.assertIn("ne peut pas réutiliser l'entropie", str(ctx_v.exception))

        # 3. Forme encodée de la clé interdite (hex) -> refusée également
        hex_kek = kek.encode("utf-8").hex()
        with self.assertRaises(ValueError):
            compute_secret_hmac(hex_kek, value, forbidden_keys=(kek,))

        # 4. Forme set et bytearray de forbidden_keys (revue LOW #116 : alignement contrat)
        with self.assertRaises(ValueError):
            compute_secret_hmac(kek, value, forbidden_keys={kek})
        ba_kek = bytearray(kek.encode("utf-8"))
        with self.assertRaises(ValueError):
            compute_secret_hmac(kek, value, forbidden_keys=ba_kek)
        with self.assertRaises(ValueError):
            compute_secret_hmac(kek, value, forbidden_keys=[ba_kek])
        with self.assertRaises(ValueError):
            verify_secret_hmac(kek, value, dummy_fp, forbidden_keys={kek})
        with self.assertRaises(ValueError):
            verify_secret_hmac(kek, value, dummy_fp, forbidden_keys=ba_kek)

        # 5. Clé distincte avec tuple, list, set et bytearray -> acceptée
        fp = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, value, forbidden_keys=(kek,))
        self.assertTrue(
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, value, fp, forbidden_keys=(kek,))
        )
        fp_set = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, value, forbidden_keys={kek})
        self.assertEqual(fp, fp_set)
        self.assertTrue(
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, value, fp, forbidden_keys={kek})
        )
        other_ba = bytearray(b"O" * 32)
        fp_ba = compute_secret_hmac(_VALID_SERVER_HMAC_KEY, value, forbidden_keys=other_ba)
        self.assertEqual(fp, fp_ba)
        self.assertTrue(
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, value, fp, forbidden_keys=[other_ba])
        )

    def test_compute_secret_hmac_naked_primitive_contract_is_documented(self) -> None:
        """Verrouille le contrat de la primitive nue (revue LOW #116 : interdiction documentée).

        Décision d'architecture (contrat d'interdiction documentée) :
        ``compute_secret_hmac`` est une primitive cryptographique pure (sans état)
        qui ne peut pas deviner l'entropie de la KEK de l'appelant. L'utilisation
        de la KEK comme clé serveur sans ``forbidden_keys`` est strictement interdite
        par contrat (docstring). La seule voie supportée en production est
        ``VaultCipher.compute_secret_hmac`` (qui injecte automatiquement sa KEK
        dans ``forbidden_keys``). Si la primitive nue est appelée directement,
        l'appelant DOIT fournir ``forbidden_keys`` pour que l'invariant 5 soit
        appliqué fail-closed.
        """
        value = "naked_primitive_value"
        kek = _VALID_KEK

        # 1. Contrat d'interdiction documentée : la fonction nue pure calcule l'HMAC
        #    mais la réutilisation de KEK est interdite par contrat/docstring...
        fp = compute_secret_hmac(kek, value)
        self.assertRegex(fp, r"^[0-9a-f]{64}$")

        # 2. ...et dès que l'appelant déclare l'entropie interdite, refus fail-closed immédiat.
        with self.assertRaises(ValueError):
            compute_secret_hmac(kek, value, forbidden_keys=kek)
        with self.assertRaises(ValueError):
            compute_secret_hmac(kek, value, forbidden_keys=[b"autre", kek])

        # 3. La seule voie de production supportée est VaultCipher, qui injecte
        #    systématiquement la KEK du chiffreur et prévient toute confusion d'entropie.
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertEqual(
            cipher.compute_secret_hmac(value),
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, value, forbidden_keys=(b"K" * 32,)),
        )

    def test_key_separation_type_safety_rejects_non_string_bytes_types(self) -> None:
        """server_hmac_key_matches_master_key et forbidden_keys lèvent TypeError sur int."""
        # int ne doit pas être converti via bytes(int) (prévention DoS mémoire et bypass)
        with self.assertRaises(TypeError):
            server_hmac_key_matches_master_key(12345, _VALID_SERVER_HMAC_KEY)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            server_hmac_key_matches_master_key(_VALID_KEK, 12345)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _extract_key_variants(12345)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _extract_key_variants(None)  # type: ignore[arg-type]

        # compute_secret_hmac et verify_secret_hmac avec forbidden_keys invalide
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", forbidden_keys=12345)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", forbidden_keys=[12345])  # type: ignore[list-item]
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", forbidden_keys={12345})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", "a" * 64, forbidden_keys=12345)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", "a" * 64, forbidden_keys=[12345])  # type: ignore[list-item]
        with self.assertRaises(TypeError):
            verify_secret_hmac(_VALID_SERVER_HMAC_KEY, "val", "a" * 64, forbidden_keys={12345})  # type: ignore[arg-type]

        # bytearray est accepté sans TypeError
        ba_kek = bytearray(_VALID_KEK.encode("utf-8"))
        self.assertTrue(server_hmac_key_matches_master_key(ba_kek, _VALID_KEK))
        self.assertEqual(len(_extract_key_variants(ba_kek)), len(_extract_key_variants(_VALID_KEK)))

    def test_resolve_vault_cipher_with_model_construct_rejects_master_hmac_collision(
        self,
    ) -> None:
        """_resolve_vault_cipher refuse master_key == server_hmac_key même via model_construct."""
        settings = VaultSettings.model_construct(
            master_key=_VALID_MASTER_KEY,
            kek_salt="s" * 22,
            api_key_pepper=_VALID_PEPPER,
            server_hmac_key=_VALID_MASTER_KEY,
        )
        with self.assertRaises(ValueError) as ctx:
            vault_app._resolve_vault_cipher(settings, "sqlite")
        self.assertIn("distinctes (invariant 5)", str(ctx.exception))

        # Forme encodée également refusée
        encoded_master = base64.b64encode(_VALID_MASTER_KEY.encode("utf-8")).decode("ascii")
        settings_enc = VaultSettings.model_construct(
            master_key=_VALID_MASTER_KEY,
            kek_salt="s" * 22,
            api_key_pepper=_VALID_PEPPER,
            server_hmac_key=encoded_master,
        )
        with self.assertRaises(ValueError) as ctx_enc:
            vault_app._resolve_vault_cipher(settings_enc, "sqlite")
        self.assertIn("distinctes (invariant 5)", str(ctx_enc.exception))

    def test_validate_explicit_secret_store_configuration_rejects_master_hmac_collision(
        self,
    ) -> None:
        """_validate_explicit_secret_store_configuration refuse master_key == server_hmac_key."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        store = InMemorySecretStore(cipher)
        settings = VaultSettings.model_construct(
            master_key=_VALID_MASTER_KEY,
            kek_salt="s" * 22,
            api_key_pepper=None,
            server_hmac_key=_VALID_MASTER_KEY,
        )
        with self.assertRaises(ValueError) as ctx:
            vault_app._validate_explicit_secret_store_configuration(settings, store)
        self.assertIn("distinctes (invariant 5)", str(ctx.exception))


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

    def test_cipher_is_secret_value_matching_without_aad_rejects_bound_fingerprint(
        self,
    ) -> None:
        """is_secret_value_matching sans aad ne matche pas une empreinte liée (revue LOW #116)."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        val = "secret_cross_triplet_probe"
        aad = VaultCipher.aad("project", "env", "name")
        bound_fp = cipher.fingerprint(val.encode("utf-8"), aad=aad)

        # Sans AAD, l'empreinte liée issue du stockage est strictement refusée (False)
        self.assertFalse(cipher.is_secret_value_matching(val, bound_fp))

        # Avec le bon AAD, la correspondance est validée
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

    async def test_nfc_parity_creation_and_verification_memory_and_sqlite(self) -> None:
        """Parité NFC création vs vérification (anti-faux négatif, Invariant 1).

        Scénario bot : secret créé en forme décomposée (NFD ex. 'cafe\\u0301'),
        recherche / vérification avec forme composée (NFC ex. 'caf\\u00e9'), et inversement.
        L'empreinte et le déchiffrement doivent tous deux répondre True en mémoire et SQLite.
        """
        nfd_cafe = "cafe\u0301"
        nfc_cafe = "caf\u00e9"
        nfd_resume = "re\u0301sume\u0301"
        nfc_resume = "résumé"

        # 1. InMemorySecretStore
        mem_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=mem_cipher)

        # Création en NFD -> vérification en NFC
        await mem_store.create("demo", "prod", "CAFE_NFD", nfd_cafe)
        await mem_store.create("demo", "prod", "RESUME_NFD", nfd_resume)

        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "CAFE_NFD", nfc_cafe)
        )
        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "RESUME_NFD", nfc_resume)
        )
        cafe_matches = await mem_store.find_secrets_matching_value("demo", nfc_cafe)
        self.assertEqual({m["name"] for m in cafe_matches}, {"CAFE_NFD"})

        # Création en NFC -> vérification en NFD
        await mem_store.create("demo", "prod", "CAFE_NFC", nfc_cafe)
        await mem_store.create("demo", "prod", "RESUME_NFC", nfc_resume)

        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "CAFE_NFC", nfd_cafe)
        )
        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "RESUME_NFC", nfd_resume)
        )
        # find_secrets_matching_value trouve les deux variantes canoniques
        all_cafe = await mem_store.find_secrets_matching_value("demo", nfd_cafe)
        self.assertEqual({m["name"] for m in all_cafe}, {"CAFE_NFD", "CAFE_NFC"})

        # 2. SqliteSecretStore
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            sql_store = SqliteSecretStore(db_path, sql_cipher)

            # Création en NFD -> vérification en NFC
            await sql_store.create("demo", "prod", "CAFE_NFD", nfd_cafe)
            await sql_store.create("demo", "prod", "RESUME_NFD", nfd_resume)

            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "CAFE_NFD", nfc_cafe)
            )
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "RESUME_NFD", nfc_resume)
            )
            matches_sql_nfc = await sql_store.find_secrets_matching_value("demo", nfc_cafe)
            self.assertEqual({m["name"] for m in matches_sql_nfc}, {"CAFE_NFD"})

            # Création en NFC -> vérification en NFD
            await sql_store.create("demo", "prod", "CAFE_NFC", nfc_cafe)
            await sql_store.create("demo", "prod", "RESUME_NFC", nfc_resume)

            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "CAFE_NFC", nfd_cafe)
            )
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "RESUME_NFC", nfd_resume)
            )
            matches_sql_nfd = await sql_store.find_secrets_matching_value("demo", nfd_cafe)
            self.assertEqual({m["name"] for m in matches_sql_nfd}, {"CAFE_NFD", "CAFE_NFC"})

    async def test_nfc_parity_bytes_candidates_memory_and_sqlite(self) -> None:
        """Parité str/bytes : un candidat bytes UTF-8 NFD égale la forme NFC stockée."""
        nfc_cafe = "caf\u00e9"
        nfd_bytes = "cafe\u0301".encode("utf-8")
        self.assertNotEqual(nfd_bytes, nfc_cafe.encode("utf-8"))

        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        aad = VaultCipher.aad("demo", "prod", "CAFE")

        # 1. Cipher : avec et sans AAD, le candidat bytes NFD correspond au HMAC calculé
        # depuis la forme str NFC.
        fp_with_aad = cipher.compute_secret_hmac(nfc_cafe, aad=aad)
        self.assertTrue(cipher.is_secret_value_matching(nfd_bytes, fp_with_aad, aad=aad))
        fp_without_aad = cipher.compute_secret_hmac(nfc_cafe)
        self.assertTrue(cipher.is_secret_value_matching(nfd_bytes, fp_without_aad))

        # 2. Mémoire : création NFC, vérification et recherche avec bytes NFD.
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("demo", "prod", "CAFE", nfc_cafe)
        self.assertTrue(await mem_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_bytes))
        mem_matches = await mem_store.find_secrets_matching_value("demo", nfd_bytes)
        self.assertEqual([m["name"] for m in mem_matches], ["CAFE"])

        # 3. SQLite : parité stricte.
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("demo", "prod", "CAFE", nfc_cafe)
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_bytes)
            )
            sql_matches = await sql_store.find_secrets_matching_value("demo", nfd_bytes)
            self.assertEqual([m["name"] for m in sql_matches], ["CAFE"])

        # 4. Parité sur les lignes héritées sans empreinte (repli déchiffrement transparent)
        mem_store._secrets[("demo", "prod", "CAFE")]["fingerprint"] = ""
        self.assertTrue(await mem_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_bytes))
        mem_legacy_matches = await mem_store.find_secrets_matching_value("demo", nfd_bytes)
        self.assertEqual([m["name"] for m in mem_legacy_matches], ["CAFE"])

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("demo", "prod", "CAFE", nfc_cafe)
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ? AND name = ?",
                    ("demo", "CAFE"),
                )
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_bytes)
            )
            sql_legacy_matches = await sql_store.find_secrets_matching_value("demo", nfd_bytes)
            self.assertEqual([m["name"] for m in sql_legacy_matches], ["CAFE"])

        # 5. Direct verify_secret_hmac API
        self.assertTrue(cipher.verify_secret_hmac(nfd_bytes, fp_with_aad, aad=aad))
        self.assertTrue(cipher.verify_secret_hmac(nfd_bytes, fp_without_aad))
        self.assertTrue(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, nfd_bytes, fp_without_aad))
        self.assertTrue(verify_secret_hmac(_VALID_SERVER_HMAC_KEY, nfd_bytes, fp_with_aad, aad=aad))

    async def test_stores_accept_bytearray_candidate_value_parity(self) -> None:
        """Parité str | bytes | bytearray sur is_secret_value_matching / find_secrets_matching."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        ascii_val = "v_secret_bytearray_prod_123"
        ascii_ba = bytearray(ascii_val.encode("utf-8"))
        wrong_ba = bytearray(b"other_secret_value")
        nfc_cafe = "caf\u00e9"
        nfd_ba = bytearray("cafe\u0301".encode("utf-8"))

        # 1. InMemorySecretStore
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("demo", "prod", "ASCII_KEY", ascii_val)
        await mem_store.create("demo", "prod", "CAFE", nfc_cafe)

        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", ascii_ba)
        )
        self.assertFalse(
            await mem_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", wrong_ba)
        )
        self.assertFalse(
            await mem_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", bytearray())
        )
        self.assertTrue(await mem_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_ba))
        self.assertEqual(
            [m["name"] for m in await mem_store.find_secrets_matching_value("demo", ascii_ba)],
            ["ASCII_KEY"],
        )
        self.assertEqual(
            [m["name"] for m in await mem_store.find_secrets_matching_value("demo", nfd_ba)],
            ["CAFE"],
        )
        self.assertEqual(await mem_store.find_secrets_matching_value("demo", bytearray()), [])

        # Repli déchiffrement ligne héritée (sans empreinte) en mémoire
        mem_store._secrets[("demo", "prod", "ASCII_KEY")]["fingerprint"] = ""
        self.assertTrue(
            await mem_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", ascii_ba)
        )
        self.assertEqual(
            [m["name"] for m in await mem_store.find_secrets_matching_value("demo", ascii_ba)],
            ["ASCII_KEY"],
        )

        # 2. SqliteSecretStore
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("demo", "prod", "ASCII_KEY", ascii_val)
            await sql_store.create("demo", "prod", "CAFE", nfc_cafe)

            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", ascii_ba)
            )
            self.assertFalse(
                await sql_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", wrong_ba)
            )
            self.assertFalse(
                await sql_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", bytearray())
            )
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "CAFE", nfd_ba)
            )
            self.assertEqual(
                [m["name"] for m in await sql_store.find_secrets_matching_value("demo", ascii_ba)],
                ["ASCII_KEY"],
            )
            self.assertEqual(
                [m["name"] for m in await sql_store.find_secrets_matching_value("demo", nfd_ba)],
                ["CAFE"],
            )
            self.assertEqual(await sql_store.find_secrets_matching_value("demo", bytearray()), [])

            # Repli déchiffrement ligne héritée SQLite
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ? AND name = ?",
                    ("demo", "ASCII_KEY"),
                )
            self.assertTrue(
                await sql_store.is_secret_value_matching("demo", "prod", "ASCII_KEY", ascii_ba)
            )
            self.assertEqual(
                [m["name"] for m in await sql_store.find_secrets_matching_value("demo", ascii_ba)],
                ["ASCII_KEY"],
            )

    async def test_corrupted_fingerprint_in_database_handled_safely(self) -> None:
        """Une empreinte corrompue bascule sur le repli déchiffrement sans faux négatif."""
        corrupted_fps = [
            "corrupted_non_hex_short_string",
            "A" * 64,  # majuscules
            "g" * 64,  # non-hex
            "0" * 63,  # longueur 63
            "0" * 65,  # longueur 65
        ]

        # 1. SqliteSecretStore
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            store = SqliteSecretStore(db_path, cipher)

            for i, bad_fp in enumerate(corrupted_fps):
                name = f"CORRUPT_SQL_{i}"
                await store.create("p", "prod", name, "real_value")
                with db_session(db_path) as conn:
                    conn.execute(
                        "UPDATE secrets SET fingerprint = ? WHERE project_id = ? AND name = ?",
                        (bad_fp, "p", name),
                    )

                # Avec la bonne valeur : repli déchiffrement répond True (anti-faux négatif)
                self.assertTrue(
                    await store.is_secret_value_matching("p", "prod", name, "real_value")
                )
                # Avec une mauvaise valeur : répond False
                self.assertFalse(
                    await store.is_secret_value_matching("p", "prod", name, "wrong_value")
                )

            matches = await store.find_secrets_matching_value("p", "real_value")
            self.assertEqual(len(matches), len(corrupted_fps))
            wrong_matches = await store.find_secrets_matching_value("p", "wrong_value")
            self.assertEqual(len(wrong_matches), 0)

        # 2. InMemorySecretStore (parité stricte)
        mem_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=mem_cipher)
        for i, bad_fp in enumerate(corrupted_fps):
            name = f"CORRUPT_MEM_{i}"
            await mem_store.create("p", "prod", name, "real_value")
            async with mem_store._lock:
                mem_store._secrets[("p", "prod", name)]["fingerprint"] = bad_fp

            self.assertTrue(
                await mem_store.is_secret_value_matching("p", "prod", name, "real_value")
            )
            self.assertFalse(
                await mem_store.is_secret_value_matching("p", "prod", name, "wrong_value")
            )

        mem_matches = await mem_store.find_secrets_matching_value("p", "real_value")
        self.assertEqual(len(mem_matches), len(corrupted_fps))
        mem_wrong = await mem_store.find_secrets_matching_value("p", "wrong_value")
        self.assertEqual(len(mem_wrong), 0)

    async def test_malformed_fingerprint_parity_cipher_returns_false_stores_fallback_decrypt(
        self,
    ) -> None:
        """Verrouille le contrat de parité cipher/stores sur empreinte malformée.

        Décision d'architecture (anti-faux négatif, Invariant 1) :
        - Sur l'API directe du cipher, une empreinte attendue malformée (longueur != 64,
          majuscules, non-hex) retourne False (prédicat booléen pur, aucune exception).
        - Sur les stores (mémoire et SQLite), une empreinte corrompue en base déclenche
          le repli transparent par déchiffrement en temps constant : si la valeur candidate
          correspond au secret réel, le store retourne True (invariant 1 : aucun faux négatif).
          Si la valeur candidate ne correspond pas, le store retourne False.
        """
        val = "super_secret_payload_value_123"
        bad_fingerprints = [
            "corrupted_non_hex_short_string",
            "A" * 64,  # majuscules
            "g" * 64,  # non-hex minuscules
            "0" * 63,  # longueur 63
            "0" * 65,  # longueur 65
            "!",  # symbole
        ]

        # 1. Vérification côté cipher direct
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        for bad_fp in bad_fingerprints:
            # Le cipher ne lève PAS mais retourne False (contrat de vérification booléenne)
            self.assertFalse(cipher.is_secret_value_matching(val, bad_fp))
            aad = VaultCipher.aad("p", "prod", "S")
            self.assertFalse(cipher.is_secret_value_matching(val, bad_fp, aad=aad))
            self.assertFalse(cipher.verify_secret_hmac(val, bad_fp))

        # 2. Vérification côté InMemorySecretStore (parité de repli déchiffrement)
        mem_store = InMemorySecretStore(cipher=cipher)
        for i, bad_fp in enumerate(bad_fingerprints):
            name = f"MEM_CORRUPT_{i}"
            await mem_store.create("p", "prod", name, val)
            async with mem_store._lock:
                mem_store._secrets[("p", "prod", name)]["fingerprint"] = bad_fp

            # Repli déchiffrement : True pour la bonne valeur, False pour une mauvaise
            self.assertTrue(await mem_store.is_secret_value_matching("p", "prod", name, val))
            self.assertFalse(
                await mem_store.is_secret_value_matching("p", "prod", name, "wrong_value")
            )

        # 3. Vérification côté SqliteSecretStore (parité de repli déchiffrement)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            for i, bad_fp in enumerate(bad_fingerprints):
                name = f"SQL_CORRUPT_{i}"
                await sql_store.create("p", "prod", name, val)
                with db_session(db_path) as conn:
                    conn.execute(
                        "UPDATE secrets SET fingerprint = ? WHERE project_id = ? AND name = ?",
                        (bad_fp, "p", name),
                    )

                # Repli déchiffrement : True pour la bonne valeur, False pour une mauvaise
                self.assertTrue(await sql_store.is_secret_value_matching("p", "prod", name, val))
                self.assertFalse(
                    await sql_store.is_secret_value_matching("p", "prod", name, "wrong_value")
                )

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

    async def test_stores_create_rejects_empty_secret_value_fail_closed(
        self,
    ) -> None:
        """Les stores mémoire et SQLite refusent fail-closed la création d'un secret vide."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)

        # 1. En mémoire
        mem_store = InMemorySecretStore(cipher=cipher)
        with self.assertRaises(ValueError) as ctx_mem:
            await mem_store.create("demo", "prod", "EMPTY_KEY", "")
        self.assertIn("vide", str(ctx_mem.exception).lower())

        # 2. En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            sql_store = SqliteSecretStore(db_path, cipher)
            with self.assertRaises(ValueError) as ctx_sql:
                await sql_store.create("demo", "prod", "EMPTY_KEY", "")
            self.assertIn("vide", str(ctx_sql.exception).lower())

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

    async def test_find_secrets_by_fingerprint_fails_closed_on_key_change_or_derived_mode(
        self,
    ) -> None:
        """find_secrets_by_fingerprint refuse fail-closed sans clé explicite ou après changement."""
        fp = "a" * 64

        # 1. Mode dérivé (sans clé HMAC serveur explicite)
        mem_derived = InMemorySecretStore(cipher=VaultCipher(b"K" * 32))
        with self.assertRaises(VaultCipherError):
            await mem_derived.find_secrets_by_fingerprint("demo", fp)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_derived = SqliteSecretStore(db_path, VaultCipher(b"K" * 32))
            with self.assertRaises(VaultCipherError):
                await sql_derived.find_secrets_by_fingerprint("demo", fp)

        # 2. Après changement de clé HMAC serveur
        # En mémoire
        c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=c1)
        await mem_store.create("demo", "prod", "S", "v")
        mem_store._cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
        with self.assertRaises(VaultCipherError):
            await mem_store.find_secrets_by_fingerprint("demo", fp)

        # En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store1 = SqliteSecretStore(db_path, c1)
            await sql_store1.create("demo", "prod", "S", "v")
            sql_store2 = SqliteSecretStore(
                db_path,
                VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY),
            )
            with self.assertRaises(VaultCipherError):
                await sql_store2.find_secrets_by_fingerprint("demo", fp)

    async def test_find_secrets_by_fingerprint_fails_closed_on_legacy_only_store(self) -> None:
        """Base 100 % héritée (fingerprint vide) : refus fail-closed, jamais [] silencieux."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        fingerprint = "a" * 64

        # 1. Mémoire : store vide -> [], puis store non vide sans canari ni empreinte -> refus.
        mem_store = InMemorySecretStore(cipher=cipher)
        self.assertEqual(await mem_store.find_secrets_by_fingerprint("demo", fingerprint), [])
        await mem_store.create("demo", "prod", "LEGACY_MEM", "legacy_val")
        mem_store._secrets[("demo", "prod", "LEGACY_MEM")]["fingerprint"] = ""
        mem_store._server_hmac_canary = None
        with self.assertRaises(VaultCipherError):
            await mem_store.find_secrets_by_fingerprint("demo", fingerprint)

        # 2. SQLite : base vide -> [], puis lignes héritées sans canari -> refus.
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            self.assertEqual(await sql_store.find_secrets_by_fingerprint("demo", fingerprint), [])
            await sql_store.create("demo", "prod", "LEGACY_SQL", "legacy_val")
            with db_session(db_path) as conn:
                conn.execute("DELETE FROM server_hmac_canary")
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ?",
                    ("demo",),
                )
            with self.assertRaises(VaultCipherError):
                await sql_store.find_secrets_by_fingerprint("demo", fingerprint)

    async def test_find_secrets_by_fingerprint_exception_precedence_parity_memory_and_sqlite(
        self,
    ) -> None:
        """Parité de précédence d'exception : format (ValueError) avant canari."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        malformed_cases = ["", "short", "a" * 63, "a" * 65, "G" * 64, 12345]  # type: ignore[list-item]

        # 1. Mémoire legacy-only (sans canari)
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("demo", "prod", "LEGACY_MEM", "legacy_val")
        mem_store._secrets[("demo", "prod", "LEGACY_MEM")]["fingerprint"] = ""
        mem_store._server_hmac_canary = None

        # 2. SQLite legacy-only (sans canari)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("demo", "prod", "LEGACY_SQL", "legacy_val")
            with db_session(db_path) as conn:
                conn.execute("DELETE FROM server_hmac_canary")
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ?",
                    ("demo",),
                )

            # Test de chaque cas malformé : TOUS lèvent ValueError (pas VaultCipherError)
            for bad_fp in malformed_cases:
                with self.subTest(bad_fp=bad_fp, store="memory"):
                    with self.assertRaises(ValueError):
                        await mem_store.find_secrets_by_fingerprint("demo", bad_fp)  # type: ignore[arg-type]
                with self.subTest(bad_fp=bad_fp, store="sqlite"):
                    with self.assertRaises(ValueError):
                        await sql_store.find_secrets_by_fingerprint("demo", bad_fp)  # type: ignore[arg-type]

            # Cas valide mais base legacy : les 2 lèvent VaultCipherError (pas ValueError)
            valid_fp = "a" * 64
            with self.assertRaises(VaultCipherError):
                await mem_store.find_secrets_by_fingerprint("demo", valid_fp)
            with self.assertRaises(VaultCipherError):
                await sql_store.find_secrets_by_fingerprint("demo", valid_fp)

    async def test_stores_reject_empty_identity_triplet(self) -> None:
        """Les stores refusent un triplet d'identité vide avec ValueError."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=cipher)
        with self.assertRaises(ValueError):
            await mem_store.is_secret_value_matching("", "prod", "NAME", "val")
        with self.assertRaises(ValueError):
            await mem_store.is_secret_value_matching("proj", "", "NAME", "val")
        with self.assertRaises(ValueError):
            await mem_store.is_secret_value_matching("proj", "prod", "", "val")

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            with self.assertRaises(ValueError):
                await sql_store.is_secret_value_matching("", "prod", "NAME", "val")
            with self.assertRaises(ValueError):
                await sql_store.is_secret_value_matching("proj", "", "NAME", "val")
            with self.assertRaises(ValueError):
                await sql_store.is_secret_value_matching("proj", "prod", "", "val")

    async def test_divergent_canary_during_creation_raises_vault_cipher_error_and_rolls_back(
        self,
    ) -> None:
        """En cas de désaccord de canari à l'écriture, lève VaultCipherError et rollback."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            c2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
            sql_store = SqliteSecretStore(db_path, c2)

            # Initialiser le canari avec c1
            init_db(db_path)
            with db_session(db_path) as conn:
                ensure_project(conn, "proj")
                set_server_hmac_canary(conn, c1.server_hmac_key_canary())

            # Tentative de création avec store sous c2 -> VaultCipherError
            with self.assertRaises(VaultCipherError):
                await sql_store.create("proj", "prod", "SECRET_KEY", "value123")

            # Vérifier qu'aucun secret n'a été inséré
            with db_session(db_path) as conn:
                self.assertIsNone(get_secret_metadata(conn, "proj", "prod", "SECRET_KEY"))

    async def test_sqlite_create_canary_race_does_not_mask_as_secret_duplicate(
        self,
    ) -> None:
        """Un conflit ou divergence sur le canari ne produit jamais d'erreur 409 doublon."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            c2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)

            # 1. Un canari identique déjà présent (course entre 2 requêtes concurrentes) :
            #    l'insertion est idempotente et la création réussit normalement.
            with db_session(db_path) as conn:
                ensure_project(conn, "proj")
                set_server_hmac_canary(conn, c1.server_hmac_key_canary())

            store_c1 = SqliteSecretStore(db_path, c1)
            created = await store_c1.create("proj", "prod", "SEC_1", "val1")
            self.assertEqual(created["status"], "vaulte")

            # 2. Un canari divergent présent lors de la création lève VaultCipherError,
            #    JAMAIS KeyError("Secret déjà existant") (qui serait mappé en HTTP 409).
            store_c2 = SqliteSecretStore(db_path, c2)
            with self.assertRaises(VaultCipherError) as ctx:
                await store_c2.create("proj", "prod", "SEC_2", "val2")
            self.assertIn("clé hmac serveur", str(ctx.exception).lower())

            # 3. Une collision IntegrityError sur le canari dans _create lève VaultCipherError,
            #    JAMAIS KeyError (prévention faux 409).
            with patch(
                "heimdall.vault.store.set_server_hmac_canary",
                side_effect=sqlite3.IntegrityError("canary lock"),
            ):
                with self.assertRaises(VaultCipherError) as ctx_race:
                    await store_c1.create("proj", "prod", "SEC_RACE", "val_race")
                self.assertIn("conflit d'écriture sur le canari", str(ctx_race.exception).lower())

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

    async def test_derived_to_explicit_mode_transition_fails_closed_without_migration(
        self,
    ) -> None:
        """Passage dérivé -> explicite sans migration : refuse fail-closed sans faux négatif."""
        # 1. En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            derived_cipher = VaultCipher(b"K" * 32, server_hmac_key=None)
            derived_store = SqliteSecretStore(db_path, derived_cipher)
            await derived_store.create("demo", "prod", "S1", "secret123")

            # Passage en mode clé explicite sans migration
            explicit_cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
            explicit_store = SqliteSecretStore(db_path, explicit_cipher)

            # Refus fail-closed de création sous nouvelle clé (anti-base hétérogène)
            with self.assertRaises(VaultCipherError):
                await explicit_store.create("demo", "prod", "S2", "val2")

            # Refus fail-closed de vérification sur l'ancien secret (anti-faux négatif)
            with self.assertRaises(VaultCipherError):
                await explicit_store.is_secret_value_matching("demo", "prod", "S1", "secret123")

            # Refus fail-closed de détection groupée
            with self.assertRaises(VaultCipherError):
                await explicit_store.find_secrets_matching_value("demo", "secret123")

            # Refus fail-closed de recherche par empreinte
            with self.assertRaises(VaultCipherError):
                await explicit_store.find_secrets_by_fingerprint("demo", "a" * 64)

        # 2. En mémoire
        mem_derived = VaultCipher(b"K" * 32, server_hmac_key=None)
        mem_store = InMemorySecretStore(cipher=mem_derived)
        await mem_store.create("demo", "prod", "S1", "secret123")

        mem_store._cipher = explicit_cipher
        with self.assertRaises(VaultCipherError):
            await mem_store.create("demo", "prod", "S2", "val2")
        with self.assertRaises(VaultCipherError):
            await mem_store.is_secret_value_matching("demo", "prod", "S1", "secret123")
        with self.assertRaises(VaultCipherError):
            await mem_store.find_secrets_matching_value("demo", "secret123")
        with self.assertRaises(VaultCipherError):
            await mem_store.find_secrets_by_fingerprint("demo", "a" * 64)

    async def test_clear_resets_canary_and_allows_recreation_under_new_explicit_key(
        self,
    ) -> None:
        """clear() réinitialise le canari et permet la recréation sous clé explicite."""
        c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        c2 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)

        # 1. En mémoire
        mem_store = InMemorySecretStore(cipher=c1)
        await mem_store.create("p", "prod", "S1", "val1")
        self.assertIsNotNone(mem_store._server_hmac_canary)

        await mem_store.clear()
        self.assertIsNone(mem_store._server_hmac_canary)

        mem_store._cipher = c2
        await mem_store.create("p", "prod", "S2", "val2")
        self.assertTrue(await mem_store.is_secret_value_matching("p", "prod", "S2", "val2"))

        # 2. En SQLite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, c1)
            await sql_store.create("p", "prod", "S1", "val1")

            await sql_store.clear()
            with db_session(db_path) as conn:
                self.assertIsNone(get_server_hmac_canary(conn))

            sql_store_2 = SqliteSecretStore(db_path, c2)
            await sql_store_2.create("p", "prod", "S2", "val2")
            self.assertTrue(await sql_store_2.is_secret_value_matching("p", "prod", "S2", "val2"))

    async def test_get_server_hmac_canary_read_only_without_table_returns_none_without_ddl(
        self,
    ) -> None:
        """get_server_hmac_canary en mode=ro sans table canari rend None sans DDL."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "legacy_ro.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                conn.execute("DROP TABLE server_hmac_canary;")

            # Connexion SQLite strictement read-only : tout CREATE TABLE lèverait OperationalError
            ro_conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                self.assertIsNone(get_server_hmac_canary(ro_conn))
                # La table reste absente (aucun DDL tenté)
                row = ro_conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='server_hmac_canary';"
                ).fetchone()
                self.assertIsNone(row)
            finally:
                ro_conn.close()

    def test_get_server_hmac_canary_uses_sqlite_master_catalog_not_error_text(self) -> None:
        """Sonde sqlite_master avant SELECT canary : indépendant du libellé OperationalError."""

        class _CursorStub:
            def __init__(self, row: tuple[object, ...] | None) -> None:
                self._row = row

            def fetchone(self) -> tuple[object, ...] | None:
                return self._row

        class _MissingTableConn:
            def execute(self, sql: str) -> _CursorStub:
                if "sqlite_master" in sql:
                    return _CursorStub(None)
                raise sqlite3.OperationalError("localized missing table message")

        class _LockedTableConn:
            def execute(self, sql: str) -> _CursorStub:
                if "sqlite_master" in sql:
                    return _CursorStub((1,))
                raise sqlite3.OperationalError("database is locked")

        # Table absente : retourne None via sqlite_master sans exécuter SELECT canary
        self.assertIsNone(get_server_hmac_canary(_MissingTableConn()))  # type: ignore[arg-type]
        # Table présente mais erreur opérationnelle réelle : propagation fail-closed
        with self.assertRaises(sqlite3.OperationalError):
            get_server_hmac_canary(_LockedTableConn())  # type: ignore[arg-type]

    async def test_stores_reject_invalid_candidate_value_types(self) -> None:
        """Les stores rejettent avec TypeError tout type invalide de candidate_value."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("p", "prod", "S", "v")

        with self.assertRaises(TypeError):
            await mem_store.is_secret_value_matching("p", "prod", "S", 123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            await mem_store.find_secrets_matching_value("p", 123)  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("p", "prod", "S", "v")

            with self.assertRaises(TypeError):
                await sql_store.is_secret_value_matching("p", "prod", "S", 123)  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                await sql_store.find_secrets_matching_value("p", 123)  # type: ignore[arg-type]

    async def test_raw_non_utf8_bytes_leak_detection_parity(self) -> None:
        """Les octets bruts non-UTF8 (ex. b'\\xff\\xfe') sont traités sans UnicodeDecodeError."""
        cipher = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        non_utf8 = b"\xff\xfe\x00\x01\x80"

        # 1. VaultCipher direct
        fp_non_utf8 = cipher.compute_secret_hmac(non_utf8, aad=b"myproj:prod:BLOB_KEY")
        self.assertTrue(
            cipher.is_secret_value_matching(
                non_utf8,
                fp_non_utf8,
                aad=b"myproj:prod:BLOB_KEY",
            )
        )
        self.assertFalse(
            cipher.is_secret_value_matching(
                b"\xaa\xbb\xcc",
                fp_non_utf8,
                aad=b"myproj:prod:BLOB_KEY",
            )
        )

        # 2. InMemorySecretStore (avec secret UTF-8 normal)
        mem_store = InMemorySecretStore(cipher=cipher)
        await mem_store.create("myproj", "prod", "STR_KEY", "ascii_value_123")
        self.assertFalse(
            await mem_store.is_secret_value_matching("myproj", "prod", "STR_KEY", non_utf8)
        )
        self.assertEqual(
            await mem_store.find_secrets_matching_value("myproj", non_utf8),
            [],
        )

        # 3. SqliteSecretStore (avec secret UTF-8 normal)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("myproj", "prod", "STR_KEY", "ascii_value_123")

            self.assertFalse(
                await sql_store.is_secret_value_matching("myproj", "prod", "STR_KEY", non_utf8)
            )
            self.assertEqual(
                await sql_store.find_secrets_matching_value("myproj", non_utf8),
                [],
            )

        # 4. Repli legacy sans empreinte (fingerprint=None) : parité mémoire et SQLite
        # sans conversion decode("utf-8") risquant UnicodeDecodeError
        await mem_store.create("myproj", "prod", "LEGACY", "ascii_value_123")
        mem_store._secrets[("myproj", "prod", "LEGACY")]["fingerprint"] = None
        self.assertFalse(
            await mem_store.is_secret_value_matching("myproj", "prod", "LEGACY", non_utf8)
        )
        self.assertEqual(
            await mem_store.find_secrets_matching_value("myproj", non_utf8),
            [],
        )

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, cipher)
            await sql_store.create("myproj", "prod", "LEGACY", "ascii_value_123")
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET fingerprint = '' WHERE project_id = ? AND name = ?",
                    ("myproj", "LEGACY"),
                )
            self.assertFalse(
                await sql_store.is_secret_value_matching("myproj", "prod", "LEGACY", non_utf8)
            )
            self.assertEqual(
                await sql_store.find_secrets_matching_value("myproj", non_utf8),
                [],
            )

    async def test_rotate_kek_with_divergent_hmac_key_fails_closed_immediately(self) -> None:
        """rotate_kek refuse fail-closed immédiatement si la clé HMAC change (store non-vide)."""
        c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        c_alt = VaultCipher(b"N" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
        c_derived = VaultCipher(b"D" * 32, server_hmac_key=None)

        # 1. InMemorySecretStore non-vide sous clé explicite
        mem_store = InMemorySecretStore(cipher=c1)
        await mem_store.create("proj", "prod", "K1", "v1")

        with self.assertRaises(VaultCipherError) as ctx_mem_alt:
            await mem_store.rotate_kek(c_alt)
        self.assertIn("diffère", str(ctx_mem_alt.exception))

        with self.assertRaises(VaultCipherError) as ctx_mem_der:
            await mem_store.rotate_kek(c_derived)
        self.assertIn("dérivé", str(ctx_mem_der.exception))

        # Store intact après les échecs
        self.assertIs(mem_store._cipher, c1)
        self.assertTrue(await mem_store.is_secret_value_matching("proj", "prod", "K1", "v1"))

        # 2. InMemorySecretStore vide : rotate_kek réussit sans effet
        empty_mem_store = InMemorySecretStore(cipher=c1)
        self.assertEqual(await empty_mem_store.rotate_kek(c_alt), 0)

        # 3. InMemorySecretStore créé en mode dérivé puis rotation vers explicite
        mem_derived = InMemorySecretStore(cipher=c_derived)
        await mem_derived.create("proj", "prod", "KD", "vd")
        with self.assertRaises(VaultCipherError) as ctx_mem_der_exp:
            await mem_derived.rotate_kek(c1)
        self.assertIn("explicite", str(ctx_mem_der_exp.exception))

        # 4. SqliteSecretStore non-vide sous clé explicite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, c1)
            await sql_store.create("proj", "prod", "K1", "v1")

            with self.assertRaises(VaultCipherError) as ctx_sql_alt:
                await sql_store.rotate_kek(c_alt)
            self.assertIn("diffère", str(ctx_sql_alt.exception))

            with self.assertRaises(VaultCipherError) as ctx_sql_der:
                await sql_store.rotate_kek(c_derived)
            self.assertIn("dérivé", str(ctx_sql_der.exception))

            # Store intact
            self.assertIs(sql_store._cipher, c1)
            self.assertTrue(await sql_store.is_secret_value_matching("proj", "prod", "K1", "v1"))

        # 5. SqliteSecretStore vide : rotate_kek réussit sans effet
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, c1)
            self.assertEqual(await sql_store.rotate_kek(c_alt), 0)

        # 6. SqliteSecretStore en mode dérivé puis rotation vers explicite
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store_der = SqliteSecretStore(db_path, c_derived)
            await sql_store_der.create("proj", "prod", "KD", "vd")
            with self.assertRaises(VaultCipherError) as ctx_sql_der_exp:
                await sql_store_der.rotate_kek(c1)
            self.assertIn("explicite", str(ctx_sql_der_exp.exception))

    async def test_rotate_kek_on_store_emptied_by_delete_still_checks_canary(self) -> None:
        """rotate_kek sur store vidé par delete() (canari persistant) échoue immédiatement.

        Revue LOW #116 : contrairement à ``clear()``, ``delete()`` du dernier
        secret conserve le canari : la rotation divergente doit lever
        sur-le-champ (fail-closed immédiat), et non différer l'échec au
        prochain ``create``.
        """
        c1 = VaultCipher(b"K" * 32, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        c_alt = VaultCipher(b"N" * 32, server_hmac_key=_VALID_ALT_HMAC_KEY)
        c_derived = VaultCipher(b"D" * 32, server_hmac_key=None)

        # 1. InMemorySecretStore vidé par delete() : canari conservé en mémoire
        mem_store = InMemorySecretStore(cipher=c1)
        await mem_store.create("proj", "prod", "K1", "v1")
        self.assertTrue(await mem_store.delete("proj", "prod", "K1"))
        self.assertEqual(mem_store._secrets, {})
        self.assertIsNotNone(mem_store._server_hmac_canary)

        with self.assertRaises(VaultCipherError) as ctx_mem_alt:
            await mem_store.rotate_kek(c_alt)
        self.assertIn("diffère", str(ctx_mem_alt.exception))

        with self.assertRaises(VaultCipherError) as ctx_mem_der:
            await mem_store.rotate_kek(c_derived)
        self.assertIn("dérivé", str(ctx_mem_der.exception))

        # Store intact : cipher non swappé malgré le store vide
        self.assertIs(mem_store._cipher, c1)

        # 2. SqliteSecretStore vidé par delete() : canari persisté en base
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            sql_store = SqliteSecretStore(db_path, c1)
            await sql_store.create("proj", "prod", "K1", "v1")
            self.assertTrue(await sql_store.delete("proj", "prod", "K1"))

            with db_session(db_path) as conn:
                self.assertIsNotNone(get_server_hmac_canary(conn))

            with self.assertRaises(VaultCipherError) as ctx_sql_alt:
                await sql_store.rotate_kek(c_alt)
            self.assertIn("diffère", str(ctx_sql_alt.exception))

            with self.assertRaises(VaultCipherError) as ctx_sql_der:
                await sql_store.rotate_kek(c_derived)
            self.assertIn("dérivé", str(ctx_sql_der.exception))

            # Store intact : cipher non swappé malgré la base vide
            self.assertIs(sql_store._cipher, c1)


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
        canary = generate_server_hmac_key()
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

    def test_app_does_not_contain_dead_server_hmac_min_constant(self) -> None:
        """La constante morte _MIN_SERVER_HMAC_KEY_BYTES est bien supprimée d'app.py."""
        self.assertFalse(hasattr(vault_app, "_MIN_SERVER_HMAC_KEY_BYTES"))


class SammProofLineIntegrityTests(TestCase):
    """Vérification mécanique de l'intégrité des preuves et permaliens SAMM (#116)."""

    def test_t116_samm_sheet_permalinks_and_line_references_valid(self) -> None:
        """Chaque permalien de docs/t116-samm.md pointe vers une tranche de code existante."""
        repo_root = Path(__file__).resolve().parents[1]
        samm_path = repo_root / "docs" / "t116-samm.md"
        self.assertTrue(samm_path.exists(), "La fiche docs/t116-samm.md est introuvable.")
        content = samm_path.read_text(encoding="utf-8")

        pattern = re.compile(
            r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
            r"/blob/(?P<sha>[0-9a-f]{40})/(?P<path>[^#\s\)]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?"
        )
        matches = list(pattern.finditer(content))
        self.assertGreaterEqual(
            len(matches), 20, "La fiche SAMM doit contenir au moins 20 permaliens."
        )

        for m in matches:
            owner, repo, _sha, rel_path = (
                m.group("owner"),
                m.group("repo"),
                m.group("sha"),
                m.group("path"),
            )
            start = int(m.group("start"))
            end = int(m.group("end") or start)

            self.assertEqual(
                (owner, repo), ("Cezar277", "heimdall"), f"Dépôt invalide: {owner}/{repo}"
            )
            target_file = repo_root / rel_path
            self.assertTrue(target_file.exists(), f"Fichier cité inexistant : {rel_path}")

            file_lines = target_file.read_text(encoding="utf-8").splitlines()
            total_lines = len(file_lines)
            self.assertGreaterEqual(start, 1, f"Ligne de début < 1 pour {rel_path}")
            self.assertLessEqual(
                end, total_lines, f"Ligne de fin {end} > {total_lines} pour {rel_path}"
            )
            self.assertLessEqual(
                start, end, f"Ligne de début > fin ({start} > {end}) pour {rel_path}"
            )

        # Contrôle de présence des symboles clés dans les tranches citées
        checks = [
            ("heimdall/vault/crypto.py", "def compute_secret_hmac"),
            ("heimdall/vault/crypto.py", "def verify_secret_hmac"),
            ("heimdall/vault/crypto.py", "def canonicalize_secret_value"),
            ("heimdall/vault/crypto.py", "def validate_server_hmac_key"),
            ("heimdall/vault/crypto.py", "def server_hmac_key_canary"),
            ("heimdall/vault/store.py", "def _check_creation_canary"),
            ("heimdall/vault/store.py", "def _check_rotate_hmac_continuity"),
            ("heimdall/vault/store.py", "async def find_secrets_by_fingerprint"),
            ("heimdall/vault/database.py", "def _check_rotate_kek_hmac_continuity"),
            ("heimdall/vault/database.py", "def find_secrets_by_fingerprint"),
        ]
        for path_sub, symbol in checks:
            found = False
            for m in matches:
                if m.group("path") == path_sub:
                    start = int(m.group("start"))
                    end = int(m.group("end") or start)
                    slice_text = "\n".join(
                        (repo_root / path_sub)
                        .read_text(encoding="utf-8")
                        .splitlines()[start - 1 : end]
                    )
                    if symbol in slice_text:
                        found = True
                        break
            self.assertTrue(
                found, f"Symbole '{symbol}' non trouvé dans les tranches citées de {path_sub}"
            )

        # Contrôle par le script officiel de vérification des permaliens SAMM
        repin_script = repo_root / "scripts" / "repin_samm.py"
        self.assertTrue(repin_script.exists())
        spec = importlib.util.spec_from_file_location("repin_samm", repin_script)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        repin_module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = repin_module
        spec.loader.exec_module(repin_module)
        check_func = getattr(repin_module, "main", None)
        assert callable(check_func)
        self.assertEqual(
            check_func(["--check", "--fiche", str(samm_path)]),
            0,
            "scripts/repin_samm.py --check a échoué sur docs/t116-samm.md",
        )
