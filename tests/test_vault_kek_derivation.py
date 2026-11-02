"""Preuves du ticket #262 — KEK dérivée avec Argon2id.

Sous-ticket de #26 « Clé maîtresse et chiffrement par enveloppe ». Ce fichier
prouve la brique livrée dans ``heimdall/vault/crypto.py`` et son branchement au
démarrage dans ``heimdall/vault/app.py`` :

1. la KEK 256 bits est dérivée de la clé maîtresse avec
   ``argon2.low_level.hash_secret_raw`` en ``Type.ID`` (Argon2id) ;
2. les paramètres sont au moins les minimums OWASP (19 Mio / 2 / 1) et sont
   exactement ceux documentés dans l'ADR-005 (64 Mio / 3 / 4) ;
3. **même clé maîtresse + même sel ⇒ même KEK** (critère « Fait quand ») ;
4. un sel différent ou une clé maîtresse différente produit une KEK différente ;
5. la dérivation a lieu **une seule fois au démarrage**, pas à chaque requête,
   et la KEK reste en mémoire (elle n'est jamais écrite dans SQLite) ;
6. le mode historique ``HEIMDALL_VAULT_KEK`` reste accepté sans régression, et
   les deux modes sont fail-closed lorsqu'ils sont mélangés.

Faux secrets uniquement : clé maîtresse, sel et valeurs explicitement
synthétiques. Aucun secret réel n'est présent dans ce fichier.
"""

import base64
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

import argon2.low_level
from fastapi.testclient import TestClient
from pydantic import ValidationError

from heimdall.vault.app import (
    VaultSettings,
    _resolve_vault_cipher,
    create_app,
)
from heimdall.vault.crypto import (
    ARGON2ID_HASH_LEN,
    ARGON2ID_MEMORY_COST_KIB,
    ARGON2ID_PARALLELISM,
    ARGON2ID_SALT_BYTES,
    ARGON2ID_TIME_COST,
    MIN_MASTER_KEY_BYTES,
    VaultCipher,
    _zeroize_buffer,
    decode_encoded_key,
    decode_kek_salt,
    derive_kek_from_master_key,
    generate_encryption_key,
    generate_kek_salt,
    kek_matches_pepper,
)
from heimdall.vault.store import InMemorySecretStore

# Matériaux synthétiques, jamais des secrets de déploiement.
_MASTER_KEY = "correct horse battery staple heimdall"  # phrase de passe factice, > 16 octets
_OTHER_MASTER_KEY = "another synthetic master passphrase for tests"
_PEPPER = "synthetic_pepper_" + "P" * 32
_SALT_A = base64.urlsafe_b64encode(b"A" * ARGON2ID_SALT_BYTES).decode("ascii")
_SALT_B = base64.urlsafe_b64encode(b"B" * ARGON2ID_SALT_BYTES).decode("ascii")
_PLAINTEXT = b"t262-synthetic-secret-value"
_AAD = VaultCipher.aad("demo", "dev", "API_TOKEN")


class Argon2idDerivationTests(unittest.TestCase):
    """La primitive de dérivation : Argon2id, déterministe, paramètres OWASP."""

    def test_same_master_key_and_same_salt_derive_the_same_kek(self) -> None:
        """Critère « Fait quand » : même clé maîtresse + même sel ⇒ même KEK."""
        first = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        second = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        self.assertEqual(first, second)
        self.assertEqual(len(first), ARGON2ID_HASH_LEN)
        self.assertEqual(len(first), 32)
        # La KEK n'est ni la clé maîtresse ni le sel (aucune copie directe).
        self.assertNotEqual(first, _MASTER_KEY.encode("utf-8"))
        self.assertNotEqual(first, decode_kek_salt(_SALT_A))

    def test_two_cipher_instances_derived_from_the_same_pair_interoperate(self) -> None:
        """Deux démarrages avec le même couple produisent la même KEK effective."""
        first_cipher = VaultCipher.from_master_key(_MASTER_KEY, _SALT_A)
        second_cipher = VaultCipher.from_master_key(_MASTER_KEY, _SALT_A)
        blob = first_cipher.encrypt(_PLAINTEXT, aad=_AAD)
        self.assertEqual(second_cipher.decrypt(blob, aad=_AAD), _PLAINTEXT)
        self.assertEqual(
            first_cipher.fingerprint(_PLAINTEXT, aad=_AAD),
            second_cipher.fingerprint(_PLAINTEXT, aad=_AAD),
        )

    def test_different_salt_derives_a_different_kek(self) -> None:
        """Le sel sépare les dérivations : un autre sel change la KEK."""
        first = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        second = derive_kek_from_master_key(_MASTER_KEY, _SALT_B)
        self.assertNotEqual(first, second)

    def test_different_master_key_derives_a_different_kek(self) -> None:
        """Une autre clé maîtresse change la KEK (pas de collision triviale)."""
        first = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        second = derive_kek_from_master_key(_OTHER_MASTER_KEY, _SALT_A)
        self.assertNotEqual(first, second)

    def test_argon2id_parameters_are_owasp_or_better_and_actually_used(self) -> None:
        """Argon2id + 64 Mio / 3 / 4, au-delà des minimums OWASP (19 Mio / 2 / 1).

        Le test observe les arguments réellement passés à
        ``argon2.low_level.hash_secret_raw`` : le type est bien ``Type.ID`` et
        les paramètres sont ceux de l'ADR, pas des valeurs par défaut.
        """
        self.assertEqual(ARGON2ID_TIME_COST, 3)
        self.assertEqual(ARGON2ID_MEMORY_COST_KIB, 64 * 1024)
        self.assertEqual(ARGON2ID_PARALLELISM, 4)
        self.assertGreaterEqual(ARGON2ID_TIME_COST, 2)
        self.assertGreaterEqual(ARGON2ID_MEMORY_COST_KIB, 19 * 1024)
        self.assertGreaterEqual(ARGON2ID_PARALLELISM, 1)
        with patch(
            "heimdall.vault.crypto.argon2.low_level.hash_secret_raw",
            wraps=argon2.low_level.hash_secret_raw,
        ) as raw:
            derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        raw.assert_called_once()
        kwargs = raw.call_args.kwargs
        self.assertIs(kwargs["type"], argon2.low_level.Type.ID)
        self.assertEqual(kwargs["time_cost"], ARGON2ID_TIME_COST)
        self.assertEqual(kwargs["memory_cost"], ARGON2ID_MEMORY_COST_KIB)
        self.assertEqual(kwargs["parallelism"], ARGON2ID_PARALLELISM)
        self.assertEqual(kwargs["hash_len"], ARGON2ID_HASH_LEN)

    def test_salt_is_generated_from_secrets_and_is_public(self) -> None:
        """Le sel est public, tiré au hasard et encodé sur exactement 16 octets."""
        with patch(
            "heimdall.vault.crypto.secrets.token_bytes", return_value=b"S" * ARGON2ID_SALT_BYTES
        ) as token_bytes:
            salt = generate_kek_salt()
        token_bytes.assert_called_once_with(ARGON2ID_SALT_BYTES)
        self.assertEqual(decode_kek_salt(salt), b"S" * ARGON2ID_SALT_BYTES)

    def test_generated_salts_are_distinct(self) -> None:
        """Deux sels générés ne se répètent pas (64 tirages distincts)."""
        salts = {generate_kek_salt() for _ in range(64)}
        self.assertEqual(len(salts), 64)

    def test_invalid_salt_is_rejected(self) -> None:
        """Sel vide, mal encodé, de mauvaise longueur ou non ASCII ⇒ ValueError."""
        invalid_salts: list[str | bytes] = [
            "",
            "   ",
            "not-base64!",
            base64.urlsafe_b64encode(b"short").decode("ascii"),
            base64.urlsafe_b64encode(b"S" * (ARGON2ID_SALT_BYTES + 1)).decode("ascii"),
            b"",
            b"short",
            b"S" * (ARGON2ID_SALT_BYTES + 1),
            "sel-accentue-\u00e9",
        ]
        for invalid_salt in invalid_salts:
            with self.subTest(salt=invalid_salt):
                with self.assertRaises(ValueError):
                    decode_kek_salt(invalid_salt)
        with self.assertRaises(ValueError):
            decode_kek_salt(None)  # type: ignore[arg-type]

    def test_invalid_master_key_is_rejected(self) -> None:
        """Clé maîtresse vide, blanche, trop courte ou non UTF-8 ⇒ ValueError."""
        invalid_master_keys: list[str | bytes] = [
            "",
            "   ",
            "short",
            b"",
            b"short",
            " leading-space",
            "trailing-space ",
            "\ud800",  # surrogate isolé : encodage UTF-8 impossible
        ]
        for invalid_master_key in invalid_master_keys:
            with self.subTest(master_key=invalid_master_key):
                with self.assertRaises(ValueError):
                    derive_kek_from_master_key(invalid_master_key, _SALT_A)
        with self.assertRaises(ValueError):
            derive_kek_from_master_key(None, _SALT_A)  # type: ignore[arg-type]

    def test_minimum_master_key_length_is_128_bits(self) -> None:
        """La borne est inclusive : 16 octets passent, 15 sont refusés."""
        self.assertEqual(MIN_MASTER_KEY_BYTES, 16)
        accepted = derive_kek_from_master_key("A" * MIN_MASTER_KEY_BYTES, _SALT_A)
        self.assertEqual(len(accepted), 32)
        with self.assertRaises(ValueError):
            derive_kek_from_master_key("A" * (MIN_MASTER_KEY_BYTES - 1), _SALT_A)


class VaultSettingsMasterKeyTests(unittest.TestCase):
    """La configuration : paire obligatoire, exclusivité, fail-closed."""

    def test_settings_accept_a_master_key_and_salt_pair(self) -> None:
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        self.assertEqual(settings.master_key, _MASTER_KEY)
        self.assertEqual(settings.kek_salt, _SALT_A)
        self.assertIsNone(settings.kek)

    def test_settings_require_master_key_and_salt_together(self) -> None:
        """Une moitié de paire est refusée : le sel ne doit jamais être implicite."""
        for kwargs in (
            {"master_key": _MASTER_KEY},
            {"kek_salt": _SALT_A},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(api_key_pepper=_PEPPER, **kwargs)
                self.assertIn("ensemble", str(ctx.exception))

    def test_settings_reject_legacy_kek_and_master_key_together(self) -> None:
        """Deux sources de KEK concurrentes sont refusées (choix explicite)."""
        with self.assertRaises(ValidationError) as ctx:
            VaultSettings(
                kek=generate_encryption_key(),
                master_key=_MASTER_KEY,
                kek_salt=_SALT_A,
                api_key_pepper=_PEPPER,
            )
        self.assertIn("mutuellement exclusifs", str(ctx.exception))

    def test_settings_validate_master_key_length_and_whitespace(self) -> None:
        for invalid_master_key in ("", "   ", "short", " leading", "trailing ", "\ud800"):
            with self.subTest(master_key=invalid_master_key):
                with self.assertRaises(ValidationError):
                    VaultSettings(
                        master_key=invalid_master_key,
                        kek_salt=_SALT_A,
                        api_key_pepper=_PEPPER,
                    )

    def test_validation_errors_do_not_echo_secrets(self) -> None:
        """Aucun ValidationError de configuration ne doit refléter un secret."""
        cases = (
            (
                "master_key",
                {"master_key": "t262-short", "kek_salt": _SALT_A, "api_key_pepper": _PEPPER},
                "t262-short",
            ),
            (
                "kek",
                {"kek": "t262-invalid-kek", "api_key_pepper": _PEPPER},
                "t262-invalid-kek",
            ),
            (
                "api_key_pepper",
                {"api_key_pepper": "t262-short-pepper"},
                "t262-short-pepper",
            ),
        )
        for field_name, kwargs, candidate in cases:
            with self.subTest(field=field_name):
                with self.assertRaises(ValidationError) as ctx:
                    VaultSettings(**kwargs)
                rendered = str(ctx.exception)
                self.assertEqual(ctx.exception.errors()[0]["loc"], (field_name,))
                self.assertNotIn(candidate, rendered)
                self.assertNotIn("input_value", rendered)

    def test_settings_validate_salt(self) -> None:
        invalid_short_salt = base64.urlsafe_b64encode(b"S" * 15).decode("ascii")
        for invalid_salt in ("", "   ", "not-base64!", invalid_short_salt):
            with self.subTest(salt=invalid_salt):
                with self.assertRaises(ValidationError):
                    VaultSettings(
                        master_key=_MASTER_KEY,
                        kek_salt=invalid_salt,
                        api_key_pepper=_PEPPER,
                    )

    def test_master_key_mode_produces_a_stable_cipher(self) -> None:
        """``_resolve_vault_cipher`` dérive une KEK stable pour un même couple."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        first = _resolve_vault_cipher(settings, "sqlite")
        second = _resolve_vault_cipher(settings, "sqlite")
        self.assertEqual(
            first.fingerprint(_PLAINTEXT, aad=_AAD),
            second.fingerprint(_PLAINTEXT, aad=_AAD),
        )

    def test_derived_kek_equal_to_pepper_is_rejected(self) -> None:
        """Invariant 5 : la KEK dérivée ne peut pas être le pepper d'authentification."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        with patch(
            "heimdall.vault.app.derive_kek_from_master_key",
            return_value=_PEPPER.encode("utf-8"),
        ):
            with self.assertRaises(ValueError) as ctx:
                _resolve_vault_cipher(settings, "memory")
        self.assertIn("distincts", str(ctx.exception))

    def test_derived_kek_equal_to_pepper_in_base64_is_rejected(self) -> None:
        """Le pepper ne peut pas réutiliser la KEK dérivée sous son encodage base64."""
        derived_kek = b"K" * 32
        pepper = base64.urlsafe_b64encode(derived_kek).decode("ascii")
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=pepper,
        )
        with patch(
            "heimdall.vault.app.derive_kek_from_master_key",
            return_value=derived_kek,
        ):
            with self.assertRaises(ValueError) as ctx:
                _resolve_vault_cipher(settings, "memory")
        self.assertIn("distincts", str(ctx.exception))

    def test_derived_kek_equal_to_standard_base64_pepper_is_rejected(self) -> None:
        """Même entropie sous l'alphabet base64 standard : refusée (revue MEDIUM)."""
        derived_kek = b"\xff" * 32
        pepper = base64.b64encode(derived_kek).decode("ascii")
        self.assertIn("/", pepper)  # alphabet standard, absent de l'URL-safe
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=pepper,
        )
        with patch(
            "heimdall.vault.app.derive_kek_from_master_key",
            return_value=derived_kek,
        ):
            with self.assertRaises(ValueError) as ctx:
                _resolve_vault_cipher(settings, "memory")
        self.assertIn("distincts", str(ctx.exception))

    def test_settings_reject_master_key_equal_to_pepper(self) -> None:
        """La validation refuse maître == pepper avant tout store injecté."""
        shared_secret = "shared_master_key_and_pepper_" + "Q" * 8
        with self.assertRaises(ValidationError) as ctx:
            VaultSettings(
                master_key=shared_secret,
                kek_salt=_SALT_A,
                api_key_pepper=shared_secret,
            )
        self.assertIn("distincts", str(ctx.exception))

    def test_resolver_rejects_master_key_equal_to_pepper_before_kdf(self) -> None:
        """Défense en profondeur : collision refusée avant la KDF, même après bypass."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        settings.master_key = _PEPPER  # mutation volontaire, hors validation
        with patch("heimdall.vault.app.derive_kek_from_master_key") as derive:
            with self.assertRaises(ValueError) as ctx:
                _resolve_vault_cipher(settings, "memory")
        derive.assert_not_called()
        self.assertIn("distincts", str(ctx.exception))

    def test_missing_salt_after_validation_is_rejected(self) -> None:
        """Garde de défense en profondeur : pas de dérivation sans sel stable."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        settings.kek_salt = None  # contourne volontairement la validation pydantic
        with self.assertRaises(ValueError) as ctx:
            _resolve_vault_cipher(settings, "memory")
        self.assertIn("HEIMDALL_VAULT_KEK_SALT", str(ctx.exception))

    def test_legacy_kek_mode_still_works(self) -> None:
        """Aucune régression : la KEK historique directe reste acceptée."""
        settings = VaultSettings(
            kek=generate_encryption_key(),
            api_key_pepper=_PEPPER,
        )
        cipher = _resolve_vault_cipher(settings, "sqlite")
        blob = cipher.encrypt(_PLAINTEXT, aad=_AAD)
        self.assertEqual(cipher.decrypt(blob, aad=_AAD), _PLAINTEXT)

    def test_sqlite_backend_still_requires_a_key_material(self) -> None:
        """Le backend SQLite refuse toujours l'absence de KEK (fail-closed)."""
        settings = VaultSettings(
            storage_backend="sqlite",
            api_key_pepper=_PEPPER,
        )
        with self.assertRaises(ValueError) as ctx:
            _resolve_vault_cipher(settings, "sqlite")
        self.assertIn("HEIMDALL_VAULT_KEK", str(ctx.exception))
        self.assertIn("HEIMDALL_VAULT_MASTER_KEY", str(ctx.exception))


class StartupDerivationTests(unittest.TestCase):
    """Le branchement démarrage : une dérivation, puis la KEK reste en mémoire."""

    def test_derivation_happens_once_at_startup_not_per_request(self) -> None:
        """``create_app`` dérive une fois ; une requête HTTP ne redérive pas."""
        with patch(
            "heimdall.vault.app.derive_kek_from_master_key",
            wraps=derive_kek_from_master_key,
        ) as derive:
            settings = VaultSettings(
                master_key=_MASTER_KEY,
                kek_salt=_SALT_A,
                api_key_pepper=_PEPPER,
            )
            app = create_app(settings)
            self.assertEqual(derive.call_count, 1)
            with TestClient(app, client=("127.0.0.1", 54321)) as client:
                response = client.get("/api/v1/health")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(derive.call_count, 1)

    def test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt(self) -> None:
        """Même clé maîtresse + même sel ⇒ un redémarrage relit le secret chiffré."""
        with tempfile.TemporaryDirectory() as tmp:
            settings = VaultSettings(
                storage_backend="sqlite",
                db_path=str(Path(tmp) / "vault.db"),
                require_auth=False,
                master_key=_MASTER_KEY,
                kek_salt=_SALT_A,
                api_key_pepper=_PEPPER,
            )
            payload = {
                "project": "demo",
                "env": "dev",
                "name": "API_TOKEN",
                "value": "t262-synthetic-secret-value",
            }

            # Premier « processus » : crée le secret avec la KEK dérivée.
            first_app = create_app(settings)
            with TestClient(first_app, client=("127.0.0.1", 54321)) as client:
                created = client.post("/api/v1/secrets", json=payload)
                self.assertEqual(created.status_code, 201)
                self.assertNotIn("value", created.json())

            # La KEK dérivée reste en mémoire : elle n'apparaît jamais dans SQLite.
            derived_kek = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
            db_bytes = Path(settings.db_path).read_bytes()
            self.assertNotIn(derived_kek, db_bytes)
            self.assertNotIn(derived_kek.hex().encode("ascii"), db_bytes)

            # Deuxième « processus » : même couple ⇒ même KEK ⇒ lecture OK.
            second_app = create_app(settings)
            with TestClient(second_app, client=("127.0.0.1", 54321)) as client:
                read = client.get("/api/v1/secrets/demo/dev/API_TOKEN")
                self.assertEqual(read.status_code, 200)
                self.assertEqual(read.json()["value"], payload["value"])

    def test_restart_with_a_different_salt_cannot_read_the_secret(self) -> None:
        """Un sel différent ⇒ KEK différente ⇒ le ciphertext n'est plus lisible."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "vault.db")
            base = {
                "storage_backend": "sqlite",
                "db_path": db_path,
                "require_auth": False,
                "master_key": _MASTER_KEY,
                "api_key_pepper": _PEPPER,
            }
            payload = {
                "project": "demo",
                "env": "dev",
                "name": "API_TOKEN",
                "value": "t262-synthetic-secret-value",
            }
            first_app = create_app(VaultSettings(kek_salt=_SALT_A, **base))
            with TestClient(first_app, client=("127.0.0.1", 54321)) as client:
                self.assertEqual(client.post("/api/v1/secrets", json=payload).status_code, 201)

            wrong_app = create_app(VaultSettings(kek_salt=_SALT_B, **base))
            with TestClient(
                wrong_app,
                client=("127.0.0.1", 54321),
                raise_server_exceptions=False,
            ) as client:
                read = client.get("/api/v1/secrets/demo/dev/API_TOKEN")
                self.assertEqual(read.status_code, 500)
                self.assertEqual(
                    read.json(),
                    {"code": "internal_error", "message": "Erreur interne"},
                )
                self.assertNotIn(payload["value"], read.text)


class T262ReviewHygieneTests(unittest.TestCase):
    """Verrous d'hygiène demandés par la revue (LOW, non bloquants)."""

    def test_bytes_master_key_with_surrounding_whitespace_is_rejected(self) -> None:
        """Le chemin ``bytes`` applique la même règle d'espaces que ``str``."""
        padded = b"  correct horse battery staple  "
        with self.assertRaises(ValueError) as ctx:
            derive_kek_from_master_key(padded, _SALT_A)
        self.assertIn("espaces", str(ctx.exception))

    def test_settings_repr_hides_master_key_salt_and_pepper(self) -> None:
        """``repr(VaultSettings)`` ne divulgue ni clé, ni sel, ni pepper."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        rendered = repr(settings)
        for secret in (_MASTER_KEY, _SALT_A, _PEPPER):
            self.assertNotIn(secret, rendered)
        kek = generate_encryption_key()
        legacy = VaultSettings(kek=kek, api_key_pepper=_PEPPER)
        self.assertNotIn(kek, repr(legacy))

    def test_kek_matches_pepper_detects_standard_base64_alphabet(self) -> None:
        """Un pepper en base64 standard révèle la même entropie que la KEK.

        Revue MEDIUM : ``b64standard`` (``+/``) et ``b64url`` (``-_``) encodent
        la même KEK ; la comparaison doit décoder le pepper, pas seulement la KEK.
        """
        raw = b"\xff" * 32
        urlsafe_kek = base64.urlsafe_b64encode(raw).decode("ascii")
        standard_pepper = base64.b64encode(raw).decode("ascii")
        self.assertIn("/", standard_pepper)
        self.assertNotEqual(urlsafe_kek, standard_pepper)
        self.assertEqual(
            decode_encoded_key(standard_pepper), decode_encoded_key(urlsafe_kek)
        )
        self.assertTrue(kek_matches_pepper(urlsafe_kek, standard_pepper))
        unrelated = base64.b64encode(b"Z" * 32).decode("ascii")
        self.assertFalse(kek_matches_pepper(urlsafe_kek, unrelated))


class T262UnicodeAndFailClosedTests(unittest.TestCase):
    """Normalisation Unicode de la clé maîtresse et échec KDF fail-closed (revue LOW)."""

    def test_nfc_and_nfd_master_keys_derive_the_same_kek(self) -> None:
        """Deux formes canoniquement équivalentes dérivent la même KEK."""
        phrase = "café résumé hérisson naïf éclair"  # ≥ 16 octets une fois NFC
        nfc = unicodedata.normalize("NFC", phrase)
        nfd = unicodedata.normalize("NFD", phrase)
        # Garde : les deux formes ont des octets réellement différents, sinon
        # le test n'éprouverait rien (sous-test d'hypothèse).
        self.assertNotEqual(nfc.encode("utf-8"), nfd.encode("utf-8"))
        first = derive_kek_from_master_key(nfc, _SALT_A)
        second = derive_kek_from_master_key(nfd, _SALT_A)
        self.assertEqual(first, second)

    def test_settings_master_key_is_stored_nfc_canonical(self) -> None:
        """`VaultSettings` canonise la clé maîtresse NFC dès la validation."""
        nfd = unicodedata.normalize("NFD", _MASTER_KEY)
        settings = VaultSettings(master_key=nfd, kek_salt=_SALT_A, api_key_pepper=_PEPPER)
        self.assertEqual(settings.master_key, unicodedata.normalize("NFC", _MASTER_KEY))

    def test_kdf_failure_is_fail_closed_at_startup(self) -> None:
        """Une panne de la KDF lève au démarrage : jamais de repli silencieux.

        Ni KEK éphémère (backend mémoire), ni bascule vers le mode historique :
        l'exception traverse ``create_app`` et le serveur ne démarre pas.
        """
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        with patch(
            "heimdall.vault.crypto.argon2.low_level.hash_secret_raw",
            side_effect=MemoryError("KDF indisponible (test)"),
        ):
            with self.assertRaises(MemoryError) as ctx:
                create_app(settings)
        self.assertIn("KDF", str(ctx.exception))


class ExplicitSecretStoreInvariantTests(unittest.TestCase):
    """Invariant 5 sur le chemin ``create_app(secret_store=...)`` (revue LOW)."""

    def test_explicit_store_rejects_cipher_key_equal_to_pepper(self) -> None:
        """Le chiffreur du store réutilisant l'entropie du pepper est refusé.

        Revue LOW : le contrôle porte sur la KEK **réellement portée** par le
        store explicite (pas sur la dérivation des settings, qui peut diverger).
        """
        kek = generate_encryption_key()
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=kek,
        )
        store = InMemorySecretStore(cipher=VaultCipher.from_encoded_key(kek))
        with self.assertRaises(ValueError) as ctx:
            create_app(settings, secret_store=store)
        self.assertIn("distincts", str(ctx.exception))

    def test_explicit_store_rejects_standard_base64_pepper(self) -> None:
        """La variante base64 standard est refusée aussi sur le store explicite.

        Revue MEDIUM : le pepper ``b64standard`` (``+/``) révèle la même
        entropie que la KEK ``b64url`` (``-_``) du chiffreur.
        """
        raw = b"\xff" * 32
        pepper = base64.b64encode(raw).decode("ascii")
        self.assertIn("/", pepper)
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=pepper,
        )
        store = InMemorySecretStore(
            cipher=VaultCipher.from_encoded_key(
                base64.urlsafe_b64encode(raw).decode("ascii")
            )
        )
        with self.assertRaises(ValueError) as ctx:
            create_app(settings, secret_store=store)
        self.assertIn("distincts", str(ctx.exception))

    def test_explicit_store_without_cipher_fails_closed(self) -> None:
        """Un store sans chiffreur lève un ``ValueError`` générique, pas un traceback.

        Revue LOW : l'accès à ``_cipher`` passe par ``getattr`` pour rester
        fail-closed même avec un mock ou un futur store sans attribut.
        """
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        with self.assertRaises(ValueError) as ctx:
            create_app(settings, secret_store=object())  # type: ignore[arg-type]
        self.assertIn("Store explicite invalide", str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, AttributeError)

    def test_explicit_store_still_starts_with_distinct_kek(self) -> None:
        """Pas de faux positif : un chiffreur distinct du pepper démarre normalement."""
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        test_app = create_app(settings, secret_store=InMemorySecretStore())
        self.assertIsNotNone(test_app.state.secret_store)

    def test_explicit_store_path_performs_no_kdf(self) -> None:
        """Le contrôle du store explicite ne dérive rien : aucune KDF inutile.

        Revue LOW : la vérification porte sur la KEK réelle du chiffreur, donc
        aucune dérivation Argon2id n'est lancée sur ce chemin (contrairement à
        l'ancienne version qui dérivait les settings).
        """
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        with patch(
            "heimdall.vault.app.derive_kek_from_master_key",
            side_effect=AssertionError("aucune dérivation attendue sur ce chemin"),
        ):
            test_app = create_app(settings, secret_store=InMemorySecretStore())
        self.assertIsNotNone(test_app.state.secret_store)


class SecretBufferZeroizationTests(unittest.TestCase):
    """Effacement best-effort du buffer de dérivation (revue LOW #262)."""

    def test_derivation_zeroizes_normalized_buffer_after_success(self) -> None:
        """Le `bytearray` normalisé est effacé après une KDF réussie."""
        secret = bytearray(_MASTER_KEY.encode("utf-8"))
        with (
            patch(
                "heimdall.vault.crypto._normalize_master_key",
                return_value=secret,
            ),
            patch(
                "heimdall.vault.crypto.argon2.low_level.hash_secret_raw",
                return_value=b"K" * 32,
            ) as mocked_kdf,
        ):
            derived = derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        self.assertEqual(derived, b"K" * 32)
        # Seul le `bytearray` que nous possédons est effacé ; la copie
        # immuable transmise à Argon2 est créée au dernier moment et n'est
        # jamais mutée (voir `test_zeroize_buffer_never_touches_immutable_bytes`).
        self.assertEqual(bytes(secret), b"\x00" * len(secret))
        self.assertEqual(
            mocked_kdf.call_args.kwargs["secret"], _MASTER_KEY.encode("utf-8")
        )

    def test_derivation_zeroizes_buffer_on_kdf_failure(self) -> None:
        """Le buffer est aussi effacé quand la KDF échoue (fail-closed)."""
        secret = bytearray(_MASTER_KEY.encode("utf-8"))
        with (
            patch(
                "heimdall.vault.crypto._normalize_master_key",
                return_value=secret,
            ),
            patch(
                "heimdall.vault.crypto.argon2.low_level.hash_secret_raw",
                side_effect=RuntimeError("KDF indisponible"),
            ),
        ):
            with self.assertRaises(RuntimeError):
                derive_kek_from_master_key(_MASTER_KEY, _SALT_A)
        self.assertEqual(bytes(secret), b"\x00" * len(secret))

    def test_zeroize_buffer_clears_bytearray(self) -> None:
        """`_zeroize_buffer` remet bien à zéro un tampon effaçable."""
        buffer = bytearray(b"cle-derivee" * 4)
        _zeroize_buffer(buffer)
        self.assertEqual(bytes(buffer), b"\x00" * len(buffer))

    def test_zeroize_buffer_never_touches_immutable_bytes(self) -> None:
        """`_zeroize_buffer` refuse les `bytes` : aucun objet immuable altéré.

        Revue LOW : muter un `bytes` via `ctypes` serait indéfini sur un objet
        partagé/interné ; la fonction n'accepte donc que des `bytearray` et
        laisse les `bytes` intacts (y compris un objet de contenu égal).
        """
        first = b"meme-entropie" * 8
        second = b"meme-entropie" * 8  # contenu égal, objet distinct
        with self.assertRaises(TypeError):
            _zeroize_buffer(first)  # type: ignore[arg-type]
        self.assertEqual(first, second)
        self.assertEqual(second, b"meme-entropie" * 8)


class SettingsSerializationHygieneTests(unittest.TestCase):
    """Sérialisation des settings sans secret (revue LOW, mitigation structurelle)."""

    def test_model_dump_never_contains_master_key_kek_or_pepper(self) -> None:
        """`model_dump`/`model_dump_json` excluent clé maîtresse, KEK et pepper.

        Revue LOW : la mitigation « ne jamais sérialiser `app.state.settings` »
        est désormais structurelle (`Field(exclude=True)`) — même un appelant qui
        sérialiserait les settings n'en obtiendrait aucun secret. Le sel public
        est également exclu par défense en profondeur.
        """
        with_master = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        legacy_kek = generate_encryption_key()
        with_kek = VaultSettings(kek=legacy_kek, api_key_pepper=_PEPPER)
        for settings in (with_master, with_kek):
            dumped = settings.model_dump()
            serialized = settings.model_dump_json()
            self.assertNotIn("master_key", dumped)
            self.assertNotIn("kek", dumped)
            self.assertNotIn("kek_salt", dumped)
            self.assertNotIn("api_key_pepper", dumped)
            for secret in (_MASTER_KEY, _SALT_A, legacy_kek, _PEPPER):
                self.assertNotIn(secret, dumped.values())
                self.assertNotIn(secret, serialized)

    def test_app_state_settings_never_serializes_secrets(self) -> None:
        """`app.state.settings` (`app.py:1601–1603`) ne peut exposer aucun secret.

        Revue LOW : l'interdiction de sérialiser ``app.state.settings`` est
        vérifiée de bout en bout sur l'objet réellement porté par l'application,
        et pas seulement sur une instance ``VaultSettings`` isolée.
        """
        settings = VaultSettings(
            master_key=_MASTER_KEY,
            kek_salt=_SALT_A,
            api_key_pepper=_PEPPER,
        )
        app = create_app(settings)
        state_settings = app.state.settings
        self.assertIs(state_settings, settings)
        dumped = state_settings.model_dump()
        serialized = state_settings.model_dump_json()
        rendered = repr(state_settings)
        self.assertNotIn("master_key", dumped)
        self.assertNotIn("kek", dumped)
        self.assertNotIn("kek_salt", dumped)
        self.assertNotIn("api_key_pepper", dumped)
        for secret in (_MASTER_KEY, _SALT_A, _PEPPER):
            self.assertNotIn(secret, dumped.values())
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
