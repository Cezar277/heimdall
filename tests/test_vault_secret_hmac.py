"""Tests de l'empreinte HMAC avec clé serveur (ticket #116).

Sous-ticket du grand ticket #40 « États du secret dans le Vault ».
Exigences couvertes :
1. Calcul d'empreinte non réversible du secret : hmac.new(cle_serveur, valeur, sha256).hexdigest().
2. Clé HMAC du serveur distincte de la clé maîtresse de chiffrement et de la KEK (Invariant 5).
3. L'empreinte n'est JAMAIS renvoyée au client (audit des réponses API et des schémas).
4. Empreinte stable et déterministe, résistance aux attaques par dictionnaire / tables arc-en-ciel.
5. Détection de compromission en production sans jamais stocker ni exposer la valeur en clair.
"""

from __future__ import annotations

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
    init_db,
    update_secret,
)
from heimdall.vault.store import (
    InMemorySecretStore,
    SqliteSecretStore,
)

_VALID_SERVER_HMAC_KEY = "S" * 32
_VALID_ALT_HMAC_KEY = "T" * 32
_VALID_KEK = generate_encryption_key()
_VALID_PEPPER = "P" * 32
_VALID_MASTER_KEY = "M" * 32


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
        """L'empreinte est non réversible et déjoue les attaques par dictionnaire (piège évité).

        Un simple SHA-256 sans clé permettrait à un attaquant volant la base de tester
        des valeurs connues via des tables arc-en-ciel. La clé HMAC serveur secrète
        empêche ce calcul hors-ligne.
        """
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
        # « secret_clé » avec é précomposé (NFC) vs e + accent combinant (NFD)
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

    def test_compute_secret_hmac_input_validation(self) -> None:
        """Refus fail-closed sur entrée vide, type invalide ou clé trop courte."""
        # Valeur vide
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, "")
        with self.assertRaises(ValueError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, b"")

        # Type de valeur invalide
        with self.assertRaises(TypeError):
            compute_secret_hmac(_VALID_SERVER_HMAC_KEY, 12345)  # type: ignore[arg-type]

        # Clé serveur absente / None
        with self.assertRaises(ValueError):
            compute_secret_hmac(None, "valid_value")  # type: ignore[arg-type]

        # Clé serveur vide ou blanche
        with self.assertRaises(ValueError):
            compute_secret_hmac("", "valid_value")
        with self.assertRaises(ValueError):
            compute_secret_hmac("   ", "valid_value")

        # Clé serveur trop courte (< 32 octets)
        with self.assertRaises(ValueError):
            compute_secret_hmac("short_key_16_bytes!", "valid_value")

    def test_generate_server_hmac_key(self) -> None:
        """generate_server_hmac_key produit au moins 256 bits d'entropie aléatoire."""
        k1 = generate_server_hmac_key()
        k2 = generate_server_hmac_key()
        self.assertNotEqual(k1, k2)
        self.assertGreaterEqual(len(k1.encode("utf-8")), 32)

    def test_verify_secret_hmac_constant_time(self) -> None:
        """verify_secret_hmac vérifie l'égalité en temps constant."""
        key = _VALID_SERVER_HMAC_KEY
        valeur = "valid-token-secret"
        expected = compute_secret_hmac(key, valeur)

        # Cas nominal : correspondance
        self.assertTrue(verify_secret_hmac(key, valeur, expected))

        # Non-correspondance de la valeur
        self.assertFalse(verify_secret_hmac(key, "wrong-token", expected))

        # Non-correspondance de la clé
        self.assertFalse(verify_secret_hmac(_VALID_ALT_HMAC_KEY, valeur, expected))

        # Format attendu invalide
        self.assertFalse(verify_secret_hmac(key, valeur, "invalid_len"))
        self.assertFalse(verify_secret_hmac(key, valeur, 12345))  # type: ignore[arg-type]
        # Exceptions internes lors du calcul -> False
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

    def test_vault_cipher_factories_propagate_server_hmac_key(self) -> None:
        """from_encoded_key, from_master_key et generate propagent server_hmac_key."""
        c1 = VaultCipher.from_encoded_key(_VALID_KEK, server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertEqual(c1.server_hmac_key, _VALID_SERVER_HMAC_KEY.encode("utf-8"))

        c2 = VaultCipher.from_master_key(
            _VALID_MASTER_KEY,
            "s" * 22,
            server_hmac_key=_VALID_SERVER_HMAC_KEY,
        )
        self.assertEqual(c2.server_hmac_key, _VALID_SERVER_HMAC_KEY.encode("utf-8"))

        c3 = VaultCipher.generate(server_hmac_key=_VALID_SERVER_HMAC_KEY)
        self.assertEqual(c3.server_hmac_key, _VALID_SERVER_HMAC_KEY.encode("utf-8"))


class KeySeparationTests(TestCase):
    """Vérification de l'Invariant 5 : séparation stricte KEK / clé maîtresse / clé HMAC serveur."""

    def test_server_hmac_key_matches_master_key_detects_collision(self) -> None:
        """server_hmac_key_matches_master_key détecte la réutilisation directe ou encodée."""
        master = "M" * 32
        self.assertTrue(server_hmac_key_matches_master_key(master, master))
        self.assertFalse(server_hmac_key_matches_master_key(master, _VALID_SERVER_HMAC_KEY))

        # Détection de collision KEK brute vs HMAC
        kek_bytes = b"K" * 32
        self.assertTrue(server_hmac_key_matches_master_key(kek_bytes, kek_bytes))
        self.assertFalse(server_hmac_key_matches_master_key(kek_bytes, _VALID_SERVER_HMAC_KEY))

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
        self.assertNotEqual(cipher.server_hmac_key, kek)
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
            # La nouvelle valeur est bien celle courante
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

            # Recherche globale par valeur ayant fuité dans le projet
            matches = await store.find_secrets_matching_value("acme", shared_leaked_value)
            self.assertEqual(len(matches), 2)
            names_and_envs = [(m["env"], m["name"]) for m in matches]
            self.assertIn(("prod", "DB_PASS"), names_and_envs)
            self.assertIn(("staging", "DB_PASS"), names_and_envs)

            # Vérification stricte : ni valeur ni empreinte dans les métadonnées retournées
            for match in matches:
                self.assertNotIn("value", match)
                self.assertNotIn("fingerprint", match)
                self.assertNotIn("encrypted_value", match)
                self.assertNotIn("encrypted_dek", match)

            # Recherche ciblée sur prod uniquement
            prod_matches = await store.find_secrets_matching_value(
                "acme", shared_leaked_value, env="prod"
            )
            self.assertEqual(len(prod_matches), 1)
            self.assertEqual(prod_matches[0]["name"], "DB_PASS")

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
        # On utilise le store initialisé avec client de boucle locale
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

        # 1. POST /api/v1/secrets (Création de secret)
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

        # 2. GET /api/v1/secrets/{project}/{env}/{name} (Lecture)
        get_resp = self.client.get("/api/v1/secrets/myproj/prod/MY_SECRET", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertNotIn("fingerprint", get_data)
        self.assertEqual(get_data["value"], "secret_plain_value_42")
        self.assertEqual(set(get_data.keys()), {"project", "env", "name", "status", "value"})

        # 3. GET /api/v1/secrets/{project}/{env}/{name}/state (État sans la valeur)
        state_resp = self.client.get("/api/v1/secrets/myproj/prod/MY_SECRET/state", headers=headers)
        self.assertEqual(state_resp.status_code, 200)
        state_data = state_resp.json()
        self.assertNotIn("fingerprint", state_data)
        self.assertNotIn("value", state_data)
        self.assertEqual(set(state_data.keys()), {"project", "env", "name", "status"})

        # 4. GET /api/v1/secrets (Liste paginée)
        list_resp = self.client.get("/api/v1/secrets?project=myproj", headers=headers)
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.json()
        self.assertEqual(len(list_data["items"]), 1)
        item = list_data["items"][0]
        self.assertNotIn("fingerprint", item)
        self.assertNotIn("value", item)
        self.assertEqual(set(item.keys()), {"project", "env", "name", "status"})


class KeyLeakHuntTests(TestCase):
    """Vérification de l'absence de fuite de la clé HMAC serveur dans logs, exceptions et repr()."""

    def test_server_hmac_key_is_never_leaked_in_repr_or_serialization(self) -> None:
        """repr/model_dump/model_dump_json n'exposent jamais la clé HMAC serveur."""
        canary = "HMAC_CANARY_UNIQUE_SECRET_VAL_12345"
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
