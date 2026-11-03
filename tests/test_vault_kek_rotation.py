"""Tests de rotation transactionnelle de la KEK (ticket #71).

Grand ticket #26 « Clé maîtresse et chiffrement par enveloppe ».
Sous-ticket T264 : Rotation de la KEK sans rechiffrer les valeurs.
"""

from __future__ import annotations

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from heimdall.cli.main import app as cli_app
from heimdall.vault.crypto import (
    VaultCipher,
    VaultCipherError,
    generate_dek,
    generate_kek_salt,
)
from heimdall.vault.database import (
    _SCHEMA_MIGRATION_HINT,
    create_project,
    create_secret,
    db_session,
    get_secret,
    get_secret_metadata,
    init_db,
    reenvelope_secret,
    rotate_secrets_kek,
)
from heimdall.vault.store import InMemorySecretStore, SecretStoreError, SqliteSecretStore

_OLD_KEK_BYTES = b"O" * 32
_NEW_KEK_BYTES = b"N" * 32
_OLD_KEK_B64 = base64.urlsafe_b64encode(_OLD_KEK_BYTES).decode("ascii")
_NEW_KEK_B64 = base64.urlsafe_b64encode(_NEW_KEK_BYTES).decode("ascii")


class VaultCipherRewrapTests(unittest.TestCase):
    """Tests unitaires du réenveloppement de DEK au niveau crypto."""

    def setUp(self) -> None:
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        self.new_cipher = VaultCipher(_NEW_KEK_BYTES)
        self.aad = VaultCipher.aad("my-project", "prod", "DATABASE_URL")

    def test_rewrap_dek_unwraps_with_old_and_wraps_with_new(self) -> None:
        """La DEK réenveloppée est lisible par la nouvelle KEK et illisible par l'ancienne."""
        raw_dek = generate_dek()
        wrapped_old = self.old_cipher.wrap_dek(raw_dek, aad=self.aad)

        wrapped_new = self.old_cipher.rewrap_dek(self.new_cipher, wrapped_old, aad=self.aad)

        # La nouvelle DEK réenveloppée se déchiffre avec la nouvelle KEK et restitue la même DEK
        unwrapped_new = self.new_cipher.unwrap_dek(wrapped_new, aad=self.aad)
        self.assertEqual(unwrapped_new, raw_dek)

        # L'ancienne KEK ne peut plus déchiffrer la nouvelle enveloppe
        with self.assertRaises(VaultCipherError):
            self.old_cipher.unwrap_dek(wrapped_new, aad=self.aad)

    def test_rewrap_dek_with_wrong_old_key_fails(self) -> None:
        """Tenter de réenvelopper avec un mauvais chiffreur initial échoue."""
        raw_dek = generate_dek()
        other_cipher = VaultCipher(b"Z" * 32)
        wrapped = other_cipher.wrap_dek(raw_dek, aad=self.aad)

        with self.assertRaises(VaultCipherError):
            self.old_cipher.rewrap_dek(self.new_cipher, wrapped, aad=self.aad)

    def test_rewrap_dek_with_wrong_aad_fails(self) -> None:
        """Tenter de réenvelopper sous un autre AAD échoue fail-closed."""
        raw_dek = generate_dek()
        wrapped = self.old_cipher.wrap_dek(raw_dek, aad=self.aad)
        wrong_aad = VaultCipher.aad("other-project", "prod", "DATABASE_URL")

        with self.assertRaises(VaultCipherError):
            self.old_cipher.rewrap_dek(self.new_cipher, wrapped, aad=wrong_aad)

    def test_rewrap_dek_rejects_non_cipher_instance(self) -> None:
        """new_cipher doit être une instance de VaultCipher."""
        raw_dek = generate_dek()
        wrapped = self.old_cipher.wrap_dek(raw_dek, aad=self.aad)
        with self.assertRaises(TypeError):
            self.old_cipher.rewrap_dek("not-a-cipher", wrapped, aad=self.aad)  # type: ignore[arg-type]

    def test_has_same_key_as_detects_identical_keys(self) -> None:
        """Détecte correctement deux chiffreurs portant la même KEK."""
        cipher1 = VaultCipher(_OLD_KEK_BYTES)
        cipher2 = VaultCipher(_OLD_KEK_BYTES)
        cipher3 = VaultCipher(_NEW_KEK_BYTES)

        self.assertTrue(cipher1.has_same_key_as(cipher2))
        self.assertFalse(cipher1.has_same_key_as(cipher3))
        self.assertFalse(cipher1.has_same_key_as("not-a-cipher"))


class DatabaseRotationTests(unittest.TestCase):
    """Tests de rotation transactionnelle en base de données SQLite."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-test-rot-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        init_db(self.db_path)
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        self.new_cipher = VaultCipher(_NEW_KEK_BYTES)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rotation_rewraps_only_deks_without_touching_values(self) -> None:
        """Fait quand : Rotation sans rechiffrer les valeurs chiffrées."""
        store_old = SqliteSecretStore(self.db_path, self.old_cipher)
        store_old._create("proj", "dev", "API_KEY", "super_secret_value_123")
        store_old._create("proj", "dev", "DB_PASS", "another_database_secret_456")

        # Capture des blobs bruts avant rotation
        with db_session(self.db_path) as conn:
            secret1_before = get_secret(conn, "proj", "dev", "API_KEY")
            secret2_before = get_secret(conn, "proj", "dev", "DB_PASS")
            assert secret1_before is not None
            assert secret2_before is not None
            val1_before = secret1_before["encrypted_value"]
            dek1_before = secret1_before["encrypted_dek"]
            val2_before = secret2_before["encrypted_value"]
            dek2_before = secret2_before["encrypted_dek"]
            self.assertEqual(secret1_before["kek_version"], 1)
            self.assertEqual(secret2_before["kek_version"], 1)

        # Exécution de la rotation
        with db_session(self.db_path) as conn:
            count = rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
            self.assertEqual(count, 2)

        # Vérification post-rotation
        with db_session(self.db_path) as conn:
            secret1_after = get_secret(conn, "proj", "dev", "API_KEY")
            secret2_after = get_secret(conn, "proj", "dev", "DB_PASS")
            assert secret1_after is not None
            assert secret2_after is not None

            # Les valeurs chiffrées sont STRICTEMENT identiques
            self.assertEqual(secret1_after["encrypted_value"], val1_before)
            self.assertEqual(secret2_after["encrypted_value"], val2_before)

            # Les DEK chiffrées ont changé
            self.assertNotEqual(secret1_after["encrypted_dek"], dek1_before)
            self.assertNotEqual(secret2_after["encrypted_dek"], dek2_before)

            # La version de KEK a été incrémentée à 2
            self.assertEqual(secret1_after["kek_version"], 2)
            self.assertEqual(secret2_after["kek_version"], 2)

        # Relecture par le store avec la nouvelle clé : valeur en clair inchangée
        store_new = SqliteSecretStore(self.db_path, self.new_cipher)
        rec1 = store_new._get("proj", "dev", "API_KEY")
        rec2 = store_new._get("proj", "dev", "DB_PASS")
        assert rec1 is not None and rec2 is not None
        self.assertEqual(rec1["value"], "super_secret_value_123")
        self.assertEqual(rec2["value"], "another_database_secret_456")

        # Tentative de lecture avec l'ancienne clé échoue
        with self.assertRaises(SecretStoreError):
            store_old._get("proj", "dev", "API_KEY")

    def test_rotation_atomicity_rolls_back_on_error(self) -> None:
        """Une rotation interrompue à moitié doit effectuer un rollback complet."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "SECRET_OK_1", "value1")
        store._create("proj", "dev", "SECRET_CORRUPT", "value2")
        store._create("proj", "dev", "SECRET_OK_2", "value3")

        # Corrompre délibérément l'enveloppe de DEK du deuxième secret
        with db_session(self.db_path) as conn:
            conn.execute(
                "UPDATE secrets SET encrypted_dek = 'corrupted_token' WHERE name = 'SECRET_CORRUPT'"
            )

        # Capturer l'état avant
        with db_session(self.db_path) as conn:
            sec1_before = get_secret(conn, "proj", "dev", "SECRET_OK_1")
            sec3_before = get_secret(conn, "proj", "dev", "SECRET_OK_2")
            assert sec1_before is not None and sec3_before is not None
            dek1_before = sec1_before["encrypted_dek"]
            dek3_before = sec3_before["encrypted_dek"]

        # Lancer la rotation : doit échouer lors du déchiffrement du secret corrompu
        with db_session(self.db_path) as conn:
            with self.assertRaises(VaultCipherError):
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)

        # Vérifier que le rollback a restauré TOUS les secrets intacts (y compris SECRET_OK_1)
        with db_session(self.db_path) as conn:
            sec1_after = get_secret(conn, "proj", "dev", "SECRET_OK_1")
            sec3_after = get_secret(conn, "proj", "dev", "SECRET_OK_2")
            assert sec1_after is not None and sec3_after is not None
            self.assertEqual(sec1_after["encrypted_dek"], dek1_before)
            self.assertEqual(sec1_after["kek_version"], 1)
            self.assertEqual(sec3_after["encrypted_dek"], dek3_before)
            self.assertEqual(sec3_after["kek_version"], 1)

    def test_rotation_rejects_identical_ciphers(self) -> None:
        """Refuse la rotation si l'ancienne et la nouvelle KEK sont identiques."""
        same_cipher = VaultCipher(_OLD_KEK_BYTES)
        with db_session(self.db_path) as conn:
            with self.assertRaises(ValueError):
                rotate_secrets_kek(conn, self.old_cipher, same_cipher)

    def test_rotation_with_explicit_target_version(self) -> None:
        """Permet de spécifier une version cible explicite."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "TOKEN", "val")

        with db_session(self.db_path) as conn:
            rotate_secrets_kek(conn, self.old_cipher, self.new_cipher, target_kek_version=42)
            meta = get_secret_metadata(conn, "proj", "dev", "TOKEN")
            assert meta is not None
            self.assertEqual(meta["kek_version"], 42)

    def test_rotation_fails_closed_on_legacy_unwrapped_secret(self) -> None:
        """Un secret hérité sans enveloppe de DEK bloque la rotation."""
        with db_session(self.db_path) as conn:
            create_project(conn, "proj")
            # Insertion directe d'une ligne héritée sans DEK
            create_secret(
                conn,
                "proj",
                "dev",
                "LEGACY",
                encrypted_value="legacy_direct_value",
                encrypted_dek=None,
            )

        with db_session(self.db_path) as conn:
            with self.assertRaises(VaultCipherError):
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)

    def test_reenvelope_secret_direct(self) -> None:
        """reenvelope_secret met à jour l'enveloppe et la version sans toucher à la valeur."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "SECRET_SINGLE", "single_value")

        with db_session(self.db_path) as conn:
            sec_before = get_secret(conn, "proj", "dev", "SECRET_SINGLE")
            assert sec_before is not None
            val_before = sec_before["encrypted_value"]

            # Réenveloppement unitaire
            aad = VaultCipher.aad("proj", "dev", "SECRET_SINGLE")
            new_dek = self.old_cipher.rewrap_dek(
                self.new_cipher, sec_before["encrypted_dek"], aad=aad
            )
            success = reenvelope_secret(
                conn, "proj", "dev", "SECRET_SINGLE", new_dek, kek_version=3
            )
            self.assertTrue(success)

            sec_after = get_secret(conn, "proj", "dev", "SECRET_SINGLE")
            assert sec_after is not None
            self.assertEqual(sec_after["encrypted_value"], val_before)
            self.assertEqual(sec_after["encrypted_dek"], new_dek)
            self.assertEqual(sec_after["kek_version"], 3)


class StoreRotationMethodTests(unittest.IsolatedAsyncioTestCase):
    """Tests des méthodes rotate_kek() sur SqliteSecretStore et InMemorySecretStore."""

    async def test_sqlite_store_rotate_kek(self) -> None:
        """SqliteSecretStore.rotate_kek pivote la KEK et met à jour self._cipher."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-rot-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("demo", "dev", "KEY1", "secret1")
            await store.create("demo", "dev", "KEY2", "secret2")

            # Rotation
            count = await store.rotate_kek(new_cipher)
            self.assertEqual(count, 2)

            # Lecture immédiate avec le store
            r1 = await store.get("demo", "dev", "KEY1")
            r2 = await store.get("demo", "dev", "KEY2")
            assert r1 is not None and r2 is not None
            self.assertEqual(r1["value"], "secret1")
            self.assertEqual(r2["value"], "secret2")

    async def test_in_memory_store_rotate_kek(self) -> None:
        """InMemorySecretStore.rotate_kek pivote la KEK en mémoire de façon atomique."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)

        await store.create("demo", "dev", "KEY1", "val1")
        await store.create("demo", "dev", "KEY2", "val2")

        count = await store.rotate_kek(new_cipher)
        self.assertEqual(count, 2)

        r1 = await store.get("demo", "dev", "KEY1")
        assert r1 is not None
        self.assertEqual(r1["value"], "val1")


class SchemaMigrationTests(unittest.TestCase):
    """Vérifie la migration additive du schéma existant vers kek_version."""

    def test_schema_migration_adds_kek_version_without_data_loss(self) -> None:
        """Une base sans colonne kek_version reçoit la colonne avec DEFAULT 1."""
        with tempfile.TemporaryDirectory(prefix="heimdall-t264-") as tmp:
            db_path = Path(tmp) / "legacy.db"
            conn = sqlite3.connect(str(db_path))
            conn.execute("CREATE TABLE projects (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);")
            conn.execute(
                "CREATE TABLE secrets ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, "
                "env TEXT NOT NULL, name TEXT NOT NULL, encrypted_value TEXT NOT NULL, "
                "encrypted_dek TEXT, status TEXT NOT NULL DEFAULT 'vaulte', "
                "fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
                "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE, "
                "CONSTRAINT uq_secrets_project_env_name UNIQUE (project_id, env, name), "
                "CONSTRAINT chk_secrets_status CHECK (status IN ('vaulte', 'rote')));"
            )
            conn.execute(
                "CREATE TABLE api_keys ("
                "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, key_hash TEXT NOT NULL, "
                "created_at TEXT NOT NULL, revoked_at TEXT, "
                "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE);"
            )
            conn.execute(
                "INSERT INTO projects (id, created_at) VALUES ('legacy_proj', '2026-01-01');"
            )
            conn.execute(
                "INSERT INTO secrets (project_id, env, name, encrypted_value, encrypted_dek, "
                "status, fingerprint, created_at, updated_at) "
                "VALUES ('legacy_proj', 'dev', 'SECRET', 'enc_val', 'enc_dek', 'vaulte', "
                "'fp', '2026', '2026');"
            )
            conn.commit()
            conn.close()

            # get_secret avant init_db doit lever RuntimeError
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            with self.assertRaises(RuntimeError) as ctx:
                get_secret(conn, "legacy_proj", "dev", "SECRET")
            self.assertEqual(str(ctx.exception), _SCHEMA_MIGRATION_HINT)
            conn.close()

            # init_db applique la migration additive
            init_db(db_path)

            # Lecture post-migration : kek_version vaut 1 par défaut
            with db_session(db_path) as conn_post:
                row = get_secret(conn_post, "legacy_proj", "dev", "SECRET")
                assert row is not None
                self.assertEqual(row["kek_version"], 1)
                self.assertEqual(row["encrypted_value"], "enc_val")


class RawSqliteNoPlaintextTests(unittest.TestCase):
    """Preuve de sécurité : aucune valeur en clair et aucune DEK dans SQLite après rotation."""

    def test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek_after_rotation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-raw-rot-") as tmp:
            db_path = Path(tmp) / "vault.db"
            canary_secret = "CANARY_PLAIN_SECRET_TO_NOT_LEAK_IN_SQLITE_99"  # noqa: S105
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)

            store = SqliteSecretStore(db_path, old_cipher)
            store._create("proj", "dev", "CANARY_NAME", canary_secret)

            # Rotation
            with db_session(db_path) as conn:
                rotate_secrets_kek(conn, old_cipher, new_cipher)

            # Lecture binaire brute du fichier
            raw_bytes = db_path.read_bytes()

            # Ni le secret en clair, ni les KEK, ni du texte sensible
            self.assertNotIn(canary_secret.encode("utf-8"), raw_bytes)
            self.assertNotIn(_OLD_KEK_BYTES, raw_bytes)
            self.assertNotIn(_NEW_KEK_BYTES, raw_bytes)


class VaultRotateCliTests(unittest.TestCase):
    """Tests de la commande CLI `heimdall vault rotate-kek`."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-cli-rot-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        self.runner = CliRunner()
        init_db(self.db_path)
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("demo", "dev", "API_KEY", "super_secret_value")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_cli_rotate_nominal_options(self) -> None:
        """Rotation nominale via options CLI directes."""
        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                _OLD_KEK_B64,
                "--new-kek",
                _NEW_KEK_B64,
            ],
        )
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Rotation de la KEK réussie : 1 secret(s) réenveloppé(s)", res.output)

        # Vérifier que le secret se lit avec la nouvelle KEK
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store_new = SqliteSecretStore(self.db_path, new_cipher)
        rec = store_new._get("demo", "dev", "API_KEY")
        assert rec is not None
        self.assertEqual(rec["value"], "super_secret_value")

    def test_cli_rotate_via_env_vars(self) -> None:
        """Rotation via variables d'environnement."""
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Rotation de la KEK réussie", res.output)

    def test_cli_rotate_with_argon2id_derivation(self) -> None:
        """Rotation avec dérivation de KEK via clé maîtresse Argon2id."""
        old_salt = generate_kek_salt()
        new_salt = generate_kek_salt()
        old_cipher = VaultCipher.from_master_key("old_master_passphrase_32_chars_ok!", old_salt)
        new_cipher = VaultCipher.from_master_key("new_master_passphrase_32_chars_ok!", new_salt)

        db_path = Path(self.tmp.name) / "vault_argon2.db"
        init_db(db_path)
        store = SqliteSecretStore(db_path, old_cipher)
        store._create("demo", "prod", "TOKEN", "val_argon2")

        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(db_path),
                "--old-master-key",
                "old_master_passphrase_32_chars_ok!",
                "--old-salt",
                old_salt,
                "--new-master-key",
                "new_master_passphrase_32_chars_ok!",
                "--new-salt",
                new_salt,
            ],
        )
        self.assertEqual(res.exit_code, 0)

        # Lecture post-rotation avec la nouvelle KEK dérivée
        store_new = SqliteSecretStore(db_path, new_cipher)
        rec = store_new._get("demo", "prod", "TOKEN")
        assert rec is not None
        self.assertEqual(rec["value"], "val_argon2")

    def test_cli_rotate_rejects_identical_keys(self) -> None:
        """Code 2 si l'ancienne et la nouvelle KEK sont identiques."""
        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                _OLD_KEK_B64,
                "--new-kek",
                _OLD_KEK_B64,
            ],
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : L'ancienne et la nouvelle KEK doivent être distinctes", res.output)

    def test_cli_rotate_rejects_missing_keys(self) -> None:
        """Code 2 si aucune clé n'est fournie."""
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env={"HEIMDALL_VAULT_OLD_KEK": "", "HEIMDALL_VAULT_KEK": ""},
        )
        self.assertEqual(res.exit_code, 2)

    def test_cli_rotate_rejects_invalid_base64(self) -> None:
        """Code 2 si l'encodage base64 est invalide."""
        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                "not-valid-base64!!!",
                "--new-kek",
                _NEW_KEK_B64,
            ],
        )
        self.assertEqual(res.exit_code, 2)

    def test_cli_rotate_wrong_old_key_exits_one(self) -> None:
        """Code 1 si l'ancienne KEK fournie ne parvient pas à déchiffrer les DEK."""
        wrong_old_kek = base64.urlsafe_b64encode(b"W" * 32).decode("ascii")
        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                wrong_old_kek,
                "--new-kek",
                _NEW_KEK_B64,
            ],
        )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("échec du déchiffrement avec l'ancienne KEK", res.output)

    def test_cli_aliases_work(self) -> None:
        """Les alias `rotate` et `kek-rotate` exécutent la même commande."""
        # Premier alias : rotation de OLD vers NEW
        res1 = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                _OLD_KEK_B64,
                "--new-kek",
                _NEW_KEK_B64,
            ],
        )
        self.assertEqual(res1.exit_code, 0)
        self.assertIn("Rotation de la KEK réussie", res1.output)

        # Deuxième alias : rotation subséquente de NEW vers une troisième KEK
        third_kek_b64 = base64.urlsafe_b64encode(b"3" * 32).decode("ascii")
        res2 = self.runner.invoke(
            cli_app,
            [
                "vault",
                "kek-rotate",
                "--db-path",
                str(self.db_path),
                "--old-kek",
                _NEW_KEK_B64,
                "--new-kek",
                third_kek_b64,
            ],
        )
        self.assertEqual(res2.exit_code, 0)
        self.assertIn("Rotation de la KEK réussie", res2.output)
