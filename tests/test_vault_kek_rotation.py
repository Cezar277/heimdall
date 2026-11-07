"""Tests de rotation transactionnelle de la KEK (ticket #71).

Grand ticket #26 « Clé maîtresse et chiffrement par enveloppe ».
Sous-ticket T264 : Rotation de la KEK sans rechiffrer les valeurs.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path
from typing import Any

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
    MAX_KEK_VERSION,
    KekConcurrencyError,
    KekVersionError,
    create_project,
    create_secret,
    db_session,
    ensure_project,
    get_secret,
    get_secret_metadata,
    init_db,
    reenvelope_secret,
    rotate_secrets_kek,
    update_secret,
    validate_kek_version,
)
from heimdall.vault.store import (
    InMemorySecretStore,
    SecretStoreError,
    SqliteSecretStore,
    _read_max_kek_version,
)

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
            count, new_ver = rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
            self.assertEqual(count, 2)
            self.assertEqual(new_ver, 2)

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

    def test_rotation_rejects_target_version_downgrade(self) -> None:
        """Refuse un numéro de version cible <= à la version actuelle (anti-downgrade)."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "TOKEN", "val")

        with db_session(self.db_path) as conn:
            # kek_version actuelle est 1 -> target=1 refusé
            with self.assertRaises(ValueError) as ctx1:
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher, target_kek_version=1)
            self.assertIn("doit être strictement supérieur", str(ctx1.exception))

            # target=0 refusé
            with self.assertRaises(ValueError):
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher, target_kek_version=0)

    def test_rotation_with_explicit_valid_target_version(self) -> None:
        """Permet de spécifier une version cible strictement supérieure."""
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

    def test_rotation_on_empty_db_returns_zero(self) -> None:
        """La rotation sur une base sans aucun secret renvoie 0."""
        with db_session(self.db_path) as conn:
            count, new_ver = rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
            self.assertEqual(count, 0)
            self.assertEqual(new_ver, 1)

    def test_rotation_on_empty_db_with_target_version_returns_one_and_writes_nothing(self) -> None:
        """rotate_secrets_kek sur base vide avec target_kek_version=42 → (0, 1) (#71 LOW 2)."""
        with db_session(self.db_path) as conn:
            count, new_ver = rotate_secrets_kek(
                conn, self.old_cipher, self.new_cipher, target_kek_version=42
            )
            self.assertEqual(count, 0)
            self.assertEqual(new_ver, 1)

            # Vérifier que rien n'est écrit dans la table secrets
            total = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
            self.assertEqual(total, 0)

    def test_rotation_refuses_auto_increment_beyond_sqlite_integer_max(self) -> None:
        """Auto-incrément borné : rotate avec MAX(kek_version)=2**63-1 → ValueError (#71 LOW 1)."""
        with db_session(self.db_path) as conn:
            ensure_project(conn, "proj")
            aad = VaultCipher.aad("proj", "dev", "AT_MAX")
            envelope = self.old_cipher.encrypt_envelope(b"val_at_max", aad=aad)
            create_secret(
                conn,
                "proj",
                "dev",
                "AT_MAX",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=MAX_KEK_VERSION,
            )

        with self.assertRaises(ValueError) as ctx:
            with db_session(self.db_path) as conn:
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
        self.assertIn("9223372036854775807", str(ctx.exception))
        # Aucun reflet de l'auto-incrément débordant (invariant 8).
        self.assertNotIn("9223372036854775808", str(ctx.exception))

        # Rien persisté : la version reste un INTEGER à sa valeur d'origine.
        with db_session(self.db_path) as conn:
            rec = get_secret(conn, "proj", "dev", "AT_MAX")
            assert rec is not None
            self.assertEqual(rec["kek_version"], MAX_KEK_VERSION)
            self.assertIsInstance(rec["kek_version"], int)

    def test_rotate_secrets_kek_update_is_version_guarded_no_downgrade(self) -> None:
        """L'UPDATE de rotation est conditionné : aucun écrasement v3 -> v2 (#71 §3).

        `BEGIN IMMEDIATE` sérialise les rotations inter-processus ; la clause
        `WHERE kek_version < ?` prouve en plus que la ligne relue n'est jamais
        rétrogradée si elle a bougé depuis la lecture.
        """
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "GUARDED", "valeur_initiale")

        with db_session(self.db_path) as conn:

            class _InterceptingConn:
                def __init__(self, target: sqlite3.Connection) -> None:
                    self._target = target

                def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
                    if "UPDATE secrets SET" in sql:
                        # Bump « concurrent » intercalé : la ligne est portée à 3
                        # juste avant l'écriture de la rotation (qui vise la 2).
                        self._target.execute(
                            "UPDATE secrets SET kek_version = 3 "
                            "WHERE project_id = 'proj' AND env = 'dev' AND name = 'GUARDED'"
                        )
                    return self._target.execute(sql, parameters)

                def __enter__(self) -> _InterceptingConn:
                    return self

                def __exit__(self, *args: object) -> object:
                    return False

                def __getattr__(self, name: str) -> object:
                    return getattr(self._target, name)

            proxy_conn: Any = _InterceptingConn(conn)
            with self.assertRaises(KekConcurrencyError) as ctx:
                rotate_secrets_kek(proxy_conn, self.old_cipher, self.new_cipher)
            self.assertEqual(str(ctx.exception), "Concurrence détectée sur kek_version.")
            # Invariant 8 : aucun identifiant dans le message.
            self.assertNotIn("GUARDED", str(ctx.exception))

            # Aucun écrasement : ni rétrogradation vers 2, ni réenveloppement.
            sec = get_secret(conn, "proj", "dev", "GUARDED")
            assert sec is not None
            self.assertEqual(sec["kek_version"], 1)
            self.assertNotEqual(sec["kek_version"], 2)

    def test_concurrent_double_rotation_serializes_without_downgrade(self) -> None:
        """Deux rotations concurrentes : sérialisées, version uniforme, pas de mélange (#71 §3)."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "CONC_1", "valeur_1")
        store._create("proj", "dev", "CONC_2", "valeur_2")
        third_cipher = VaultCipher(b"T" * 32)

        barrier = threading.Barrier(2, timeout=10)
        results: dict[str, Any] = {}

        def rotate(name: str, old: VaultCipher, new: VaultCipher) -> None:
            try:
                with db_session(self.db_path) as conn:
                    barrier.wait()
                    results[name] = rotate_secrets_kek(conn, old, new)
            except (sqlite3.OperationalError, VaultCipherError) as exc:
                # Verrou occupé (échec fail-closed) ou DEK déjà réenveloppées par
                # l'autre rotation : la tentative est annulée, jamais partiellement
                # appliquée.
                results[name] = type(exc).__name__

        t1 = threading.Thread(target=rotate, args=("a", self.old_cipher, self.new_cipher))
        t2 = threading.Thread(target=rotate, args=("b", self.old_cipher, self.new_cipher))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        # Une seule rotation s'applique (l'autre échoue fail-closed), version 2.
        applied = [v for v in results.values() if isinstance(v, tuple)]
        self.assertEqual(len(applied), 1)
        self.assertEqual(applied[0], (2, 2))
        with db_session(self.db_path) as conn:
            versions = [
                row[0]
                for row in conn.execute("SELECT DISTINCT kek_version FROM secrets ORDER BY 1")
            ]
        self.assertEqual(versions, [2], "aucune ligne mélangée ni rétrogradée")

        # Rotation suivante sérialisée : passage strictement monotone à 3.
        with db_session(self.db_path) as conn:
            count, new_v = rotate_secrets_kek(conn, self.new_cipher, third_cipher)
        self.assertEqual((count, new_v), (2, 3))
        with db_session(self.db_path) as conn:
            versions = [
                row[0]
                for row in conn.execute("SELECT DISTINCT kek_version FROM secrets ORDER BY 1")
            ]
        self.assertEqual(versions, [3])

    def test_create_secret_validates_kek_version(self) -> None:
        """create_secret refuse les versions de KEK < 1 ou de type invalide."""
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_val")
            for invalid_v in (0, -1, -5, True, False, "1"):
                with self.assertRaises(ValueError):
                    create_secret(
                        conn,
                        "proj_val",
                        "dev",
                        f"K_{invalid_v}",
                        "val",
                        kek_version=invalid_v,  # type: ignore[arg-type]
                    )

    def test_update_and_reenvelope_validate_kek_version(self) -> None:
        """update_secret et reenvelope_secret refusent kek_version < 1."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "SEC_UPD", "val")

        with db_session(self.db_path) as conn:
            with self.assertRaises(ValueError):
                update_secret(conn, "proj", "dev", "SEC_UPD", "new_val", kek_version=0)
            with self.assertRaises(ValueError):
                reenvelope_secret(conn, "proj", "dev", "SEC_UPD", "new_dek", kek_version=0)

    def test_reenvelope_secret_direct(self) -> None:
        """reenvelope_secret met à jour l'enveloppe et la version sans toucher à la valeur."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "SECRET_SINGLE", "single_value")

        with db_session(self.db_path) as conn:
            sec_before = get_secret(conn, "proj", "dev", "SECRET_SINGLE")
            assert sec_before is not None
            val_before = sec_before["encrypted_value"]

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

    def test_rotation_under_lock_contention_fails_closed(self) -> None:
        """En cas de contention sur BEGIN IMMEDIATE, la rotation échoue proprement sans fuite."""
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "CONCURRENT_SEC", "val")

        # Ouvrir la connexion pour la rotation et réduire le busy_timeout
        with db_session(self.db_path) as conn_rotating:
            conn_rotating.execute("PRAGMA busy_timeout = 10")

            # Ouvrir une seconde connexion qui prend un verrou exclusif
            conn_locking = sqlite3.connect(str(self.db_path), timeout=0.01)
            conn_locking.execute("BEGIN EXCLUSIVE")
            try:
                with self.assertRaises(sqlite3.OperationalError) as ctx:
                    rotate_secrets_kek(conn_rotating, self.old_cipher, self.new_cipher)
                err_msg = str(ctx.exception)
                self.assertNotIn("kek", err_msg.lower())
                self.assertNotIn("dek", err_msg.lower())
                self.assertNotIn(_OLD_KEK_BYTES.hex(), err_msg)
                self.assertNotIn(_NEW_KEK_BYTES.hex(), err_msg)
            finally:
                conn_locking.rollback()
                conn_locking.close()

        # Vérifier que le secret est resté intact
        with db_session(self.db_path) as conn_check:
            sec = get_secret(conn_check, "proj", "dev", "CONCURRENT_SEC")
            assert sec is not None
            self.assertEqual(sec["kek_version"], 1)


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

    async def test_sqlite_store_rotate_kek_persists_returned_new_version_without_drift(
        self,
    ) -> None:
        """`_rotate_kek` aligne `store.kek_version` sur la `new_version` retournée.

        Verrouille la revue LOW : la version mémorisée par le store doit être
        exactement celle persistée par `rotate_secrets_kek` (aucun SELECT
        supplémentaire, aucune dérive future entre la mémoire du worker et la base).
        """
        with tempfile.TemporaryDirectory(prefix="heimdall-store-rot-sync-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("demo", "dev", "KEY1", "secret1")
            await store.create("demo", "dev", "KEY2", "secret2")

            count = await store.rotate_kek(new_cipher, target_kek_version=7)
            self.assertEqual(count, 2)
            # store.kek_version == new_version retournée par rotate_secrets_kek.
            self.assertEqual(store.kek_version, 7)
            # ... et identique à la version persistée en base (pas de dérive).
            with db_session(db_path) as conn:
                row = conn.execute("SELECT MAX(kek_version) FROM secrets").fetchone()
            self.assertEqual(row is not None and row[0], store.kek_version)

            # Le secret créé ensuite hérite de cette même version (pas de dérive future).
            await store.create("demo", "dev", "KEY3", "secret3")
            with db_session(db_path) as conn:
                sec = get_secret(conn, "demo", "dev", "KEY3")
            assert sec is not None
            self.assertEqual(sec["kek_version"], store.kek_version)

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

    async def test_in_memory_store_rotate_kek_rejects_downgrade_and_invalid_version(self) -> None:
        """InMemorySecretStore.rotate_kek refuse le downgrade et les versions invalides."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)

        await store.create("demo", "dev", "KEY1", "val1")

        with self.assertRaises(ValueError):
            await store.rotate_kek(new_cipher, target_kek_version=0)

        with self.assertRaises(ValueError) as ctx:
            await store.rotate_kek(new_cipher, target_kek_version=1)
        self.assertIn("doit être strictement supérieur", str(ctx.exception))

    async def test_sqlite_store_create_after_rotate_has_target_kek_version(self) -> None:
        """Un secret créé après rotation SQLite hérite de la nouvelle kek_version."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-postrot-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("proj", "dev", "PRE_ROT", "val_pre")
            with db_session(db_path) as conn:
                sec_pre = get_secret(conn, "proj", "dev", "PRE_ROT")
                assert sec_pre is not None
                self.assertEqual(sec_pre["kek_version"], 1)

            # Rotation vers version 42
            count = await store.rotate_kek(new_cipher, target_kek_version=42)
            self.assertEqual(count, 1)
            self.assertEqual(store.kek_version, 42)

            # Création post-rotation
            await store.create("proj", "dev", "POST_ROT", "val_post")

            with db_session(db_path) as conn:
                sec_post = get_secret(conn, "proj", "dev", "POST_ROT")
                assert sec_post is not None
                self.assertEqual(sec_post["kek_version"], 42)

            # Les deux secrets se lisent avec le store mis à jour
            r_pre = await store.get("proj", "dev", "PRE_ROT")
            r_post = await store.get("proj", "dev", "POST_ROT")
            assert r_pre is not None and r_post is not None
            self.assertEqual(r_pre["value"], "val_pre")
            self.assertEqual(r_post["value"], "val_post")

    async def test_in_memory_store_create_after_rotate_has_target_kek_version(self) -> None:
        """Un secret créé après rotation mémoire hérite de la nouvelle kek_version."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)

        await store.create("proj", "dev", "PRE_ROT", "val_pre")
        self.assertEqual(store._secrets[("proj", "dev", "PRE_ROT")]["kek_version"], 1)

        count = await store.rotate_kek(new_cipher, target_kek_version=15)
        self.assertEqual(count, 1)
        self.assertEqual(store.kek_version, 15)

        await store.create("proj", "dev", "POST_ROT", "val_post")
        self.assertEqual(store._secrets[("proj", "dev", "POST_ROT")]["kek_version"], 15)

        r_pre = await store.get("proj", "dev", "PRE_ROT")
        r_post = await store.get("proj", "dev", "POST_ROT")
        assert r_pre is not None and r_post is not None
        self.assertEqual(r_pre["value"], "val_pre")
        self.assertEqual(r_post["value"], "val_post")

    async def test_sqlite_store_rotate_empty_does_not_swap_cipher(self) -> None:
        """La rotation sur un SqliteSecretStore vide retourne 0 sans modifier son cipher."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-empty-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            count = await store.rotate_kek(new_cipher)
            self.assertEqual(count, 0)
            self.assertTrue(store._cipher.has_same_key_as(old_cipher))
            self.assertEqual(store.kek_version, 1)

            # Un secret créé après cette tentative vide reste chiffrable sous l'ancienne clé
            await store.create("proj", "dev", "POST_EMPTY", "val")
            r = await store.get("proj", "dev", "POST_EMPTY")
            assert r is not None
            self.assertEqual(r["value"], "val")

    async def test_in_memory_store_rotate_empty_does_not_swap_cipher(self) -> None:
        """La rotation sur un InMemorySecretStore vide retourne 0 sans modifier son cipher."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)

        count = await store.rotate_kek(new_cipher)
        self.assertEqual(count, 0)
        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store.kek_version, 1)

    async def test_in_memory_rotate_kek_corrupted_version_raises_generic_error(self) -> None:
        """InMemorySecretStore.rotate_kek : erreur générique sans reflet si version corrompue."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        corrupt_val = "<corrupt-kek-version-in-mem>"
        store._secrets[("demo", "dev", "KEY1")]["kek_version"] = corrupt_val
        with self.assertRaises(KekVersionError) as ctx:
            await store.rotate_kek(new_cipher)
        err_msg = str(ctx.exception)
        self.assertNotIn(corrupt_val, err_msg)
        self.assertEqual(str(ctx.exception), "Version de KEK illisible.")

    async def test_in_memory_rotate_kek_rejects_oversized_version_without_reflection(self) -> None:
        """Version mémoire > INTEGER 64 bits refusée sans reflet (#71 LOW 2)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        store._secrets[("demo", "dev", "KEY1")]["kek_version"] = 2**100
        with self.assertRaises(KekVersionError) as ctx:
            await store.rotate_kek(new_cipher)
        err_msg = str(ctx.exception)
        self.assertEqual(err_msg, "Version de KEK illisible.")
        # Aucun reflet de la valeur débordante (invariant 8).
        self.assertNotIn("1267650600228229401496703205376", err_msg)
        self.assertNotIn("1e+30", err_msg)
        # Échec fail-closed : ni swap de clé, ni réenveloppement.
        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store._secrets[("demo", "dev", "KEY1")]["kek_version"], 2**100)

    async def test_in_memory_rotate_kek_restores_cipher_and_version_on_interrupt(self) -> None:
        """Interruption entre les deux affectations de sortie : couple restauré (#71 LOW)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)

        class _InterruptingVersionStore(InMemorySecretStore):
            @property
            def _kek_version(self) -> int:
                value: int = self.__dict__["_kek_version"]
                return value

            @_kek_version.setter
            def _kek_version(self, value: int) -> None:
                if getattr(self, "_interrupt_version_set", False):
                    raise KeyboardInterrupt("interruption simulée entre les affectations")
                self.__dict__["_kek_version"] = value

        store = _InterruptingVersionStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        store._interrupt_version_set = True  # type: ignore[attr-defined]
        try:
            with self.assertRaises(KeyboardInterrupt):
                await store.rotate_kek(new_cipher)
        finally:
            store._interrupt_version_set = False  # type: ignore[attr-defined]

        # Couple restauré : ni cipher neuf avec d'anciennes DEK, ni version haussée.
        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store.kek_version, 1)
        # Le store reste lisible avec l'ancienne KEK (pas d'indisponibilité).
        rec = await store.get("demo", "dev", "KEY1")
        assert rec is not None
        self.assertEqual(rec["value"], "val1")

    async def test_sqlite_store_rotate_kek_restores_cipher_and_version_on_interrupt(
        self,
    ) -> None:
        """SqliteSecretStore restaure le couple (cipher, version) si le swap est interrompu."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-interrupt-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)

            class _InterruptingVersionStore(SqliteSecretStore):
                @property
                def _kek_version(self) -> int:
                    value: int = self.__dict__["_kek_version"]
                    return value

                @_kek_version.setter
                def _kek_version(self, value: int) -> None:
                    if getattr(self, "_interrupt_version_set", False):
                        raise KeyboardInterrupt("interruption simulée entre les affectations")
                    self.__dict__["_kek_version"] = value

            store = _InterruptingVersionStore(db_path, old_cipher)
            await store.create("demo", "dev", "KEY1", "val1")
            store._interrupt_version_set = True  # type: ignore[attr-defined]
            try:
                with self.assertRaises(KeyboardInterrupt):
                    await store.rotate_kek(new_cipher)
            finally:
                store._interrupt_version_set = False  # type: ignore[attr-defined]

            # Couple restauré : pas de cipher neuf étiqueté avec l'ancienne version.
            self.assertTrue(store._cipher.has_same_key_as(old_cipher))
            self.assertEqual(store.kek_version, 1)
            with db_session(db_path) as conn:
                sec = get_secret(conn, "demo", "dev", "KEY1")
                assert sec is not None
                self.assertEqual(sec["kek_version"], 2)

            # Le store ne peut plus lire (DEK en base sous la nouvelle KEK) et
            # refuse de créer un secret sous l'ancienne KEK (fail-closed).
            with self.assertRaises(SecretStoreError):
                await store.get("demo", "dev", "KEY1")
            with self.assertRaises(RuntimeError):
                await store.create("demo", "dev", "POST_INTERRUPT", "val")

    async def test_in_memory_rotate_kek_atomicity_on_keyboard_interrupt(self) -> None:
        """InMemorySecretStore.rotate_kek restaure l'état sur KeyboardInterrupt (#71 LOW 3)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        await store.create("demo", "dev", "KEY2", "val2")

        initial_secrets = {k: dict(v) for k, v in store._secrets.items()}
        call_count = 0
        orig_rewrap = old_cipher.rewrap_dek

        def mock_rewrap(*args: Any, **kwargs: Any) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise KeyboardInterrupt
            return orig_rewrap(*args, **kwargs)

        with unittest.mock.patch.object(old_cipher, "rewrap_dek", side_effect=mock_rewrap):
            with self.assertRaises(KeyboardInterrupt):
                await store.rotate_kek(new_cipher)

        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store.kek_version, 1)
        self.assertEqual(store._secrets, initial_secrets)

    async def test_in_memory_rotate_kek_atomicity_on_cancelled_error(self) -> None:
        """InMemorySecretStore.rotate_kek restaure l'état sur CancelledError (#71 LOW 3)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        await store.create("demo", "dev", "KEY2", "val2")

        initial_secrets = {k: dict(v) for k, v in store._secrets.items()}
        call_count = 0
        orig_rewrap = old_cipher.rewrap_dek

        def mock_rewrap(*args: Any, **kwargs: Any) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise asyncio.CancelledError
            return orig_rewrap(*args, **kwargs)

        with unittest.mock.patch.object(old_cipher, "rewrap_dek", side_effect=mock_rewrap):
            with self.assertRaises(asyncio.CancelledError):
                await store.rotate_kek(new_cipher)

        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store.kek_version, 1)
        self.assertEqual(store._secrets, initial_secrets)

    async def test_in_memory_rotate_kek_task_cancellation_restores_state(self) -> None:
        """Annulation d'une tâche asyncio pendant rotate_kek restaure l'état (#71 LOW 3)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        await store.create("demo", "dev", "KEY2", "val2")

        initial_secrets = {k: dict(v) for k, v in store._secrets.items()}

        def mock_rewrap_cancel(*args: Any, **kwargs: Any) -> str:
            raise asyncio.CancelledError

        with unittest.mock.patch.object(old_cipher, "rewrap_dek", side_effect=mock_rewrap_cancel):
            with self.assertRaises(asyncio.CancelledError):
                await store.rotate_kek(new_cipher)

        self.assertTrue(store._cipher.has_same_key_as(old_cipher))
        self.assertEqual(store.kek_version, 1)
        self.assertEqual(store._secrets, initial_secrets)

    async def test_in_memory_rotate_kek_backup_resists_inplace_mutation_on_error(self) -> None:
        """InMemorySecretStore: deepcopy protège contre les mutations in-place (#71 LOW 4)."""
        old_cipher = VaultCipher(_OLD_KEK_BYTES)
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = InMemorySecretStore(cipher=old_cipher)
        await store.create("demo", "dev", "KEY1", "val1")
        await store.create("demo", "dev", "KEY2", "val2")

        initial_secrets = copy.deepcopy(store._secrets)
        call_count = 0
        orig_rewrap = old_cipher.rewrap_dek

        def mock_rewrap_with_inplace_tamper(*args: Any, **kwargs: Any) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # Simuler une mutation in-place accidentelle dans un record du store
                store._secrets[("demo", "dev", "KEY1")]["encrypted_dek"] = "MUTATED_IN_PLACE"
                raise RuntimeError("Simulation d'erreur pendant rotation")
            return orig_rewrap(*args, **kwargs)

        with unittest.mock.patch.object(
            old_cipher, "rewrap_dek", side_effect=mock_rewrap_with_inplace_tamper
        ):
            with self.assertRaises(RuntimeError):
                await store.rotate_kek(new_cipher)

        self.assertEqual(store._secrets, initial_secrets)
        self.assertNotEqual(
            store._secrets[("demo", "dev", "KEY1")]["encrypted_dek"],
            "MUTATED_IN_PLACE",
        )

    async def test_sqlite_store_create_rejects_stale_cipher_after_external_rotation(
        self,
    ) -> None:
        """SqliteSecretStore.create lève RuntimeError si rotation externe (#71 MEDIUM)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-stale-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("proj", "dev", "KEY1", "val1")

            # Rotation externe effectuée directement en base
            with db_session(db_path) as conn:
                rotate_secrets_kek(conn, old_cipher, new_cipher)

            # store utilise encore old_cipher (self._kek_version == 1, alors que DB max == 2)
            with self.assertRaises(RuntimeError) as ctx:
                await store.create("proj", "dev", "KEY2", "val2")

            err_msg = str(ctx.exception)
            self.assertIn("rotation de KEK externe", err_msg)
            self.assertIn("Redémarrage du worker requis", err_msg)

            # Vérifier que KEY2 n'a pas été inséré avec l'ancien cipher
            with db_session(db_path) as conn:
                self.assertIsNone(get_secret(conn, "proj", "dev", "KEY2"))

            # Un store fraîchement initialisé avec new_cipher prend le relais
            store_restarted = SqliteSecretStore(db_path, new_cipher)
            self.assertEqual(store_restarted.kek_version, 2)
            await store_restarted.create("proj", "dev", "KEY2", "val2")
            r1 = await store_restarted.get("proj", "dev", "KEY1")
            r2 = await store_restarted.get("proj", "dev", "KEY2")
            assert r1 is not None and r2 is not None
            self.assertEqual(r1["value"], "val1")
            self.assertEqual(r2["value"], "val2")

    async def test_sqlite_store_reinit_after_simulated_crash_reloads_version(self) -> None:
        """SqliteSecretStore rechargé après crash relit MAX(kek_version) en DB (#71 LOW 3)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-crash-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("proj", "dev", "KEY1", "val1")

            # Rotation atomique en DB vers version 5
            with db_session(db_path) as conn:
                count, new_v = rotate_secrets_kek(
                    conn, old_cipher, new_cipher, target_kek_version=5
                )
                self.assertEqual(count, 1)
                self.assertEqual(new_v, 5)

            # Simulation d'un arrêt de processus / crash : nouveau store instancié
            store_after_crash = SqliteSecretStore(db_path, new_cipher)
            self.assertEqual(store_after_crash.kek_version, 5)

            # Nouveau secret étiqueté version 5
            await store_after_crash.create("proj", "dev", "KEY2", "val2")
            with db_session(db_path) as conn:
                sec2 = get_secret(conn, "proj", "dev", "KEY2")
                assert sec2 is not None
                self.assertEqual(sec2["kek_version"], 5)

    async def test_sqlite_store_read_after_crash_window_fails_closed_with_stale_cipher(
        self,
    ) -> None:
        """Commit DB fait, swap mémoire jamais fait : lecture fail-closed (#71 §3)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-crash-read-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)

            await store.create("proj", "dev", "KEY1", "val1")

            # Fenêtre de crash : la rotation est COMMITée en base alors que ce
            # store n'a jamais rechargé ni son cipher ni sa version en mémoire.
            with db_session(db_path) as conn:
                count, new_v = rotate_secrets_kek(conn, old_cipher, new_cipher)
                self.assertEqual((count, new_v), (1, 2))

            # État mémoire inchangé (jamais de swap) : version toujours 1.
            self.assertEqual(store.kek_version, 1)

            # Relecture avec l'ancien cipher : échec fail-closed, sans reflet.
            with self.assertRaises(SecretStoreError) as ctx:
                await store.get("proj", "dev", "KEY1")
            err_msg = str(ctx.exception)
            self.assertIn("illisible", err_msg)
            self.assertNotIn("val1", err_msg)

            # Écriture également refusée : pas de secret sous-étiqueté en v1.
            with self.assertRaises(RuntimeError) as ctx_create:
                await store.create("proj", "dev", "KEY2", "val2")
            self.assertIn("rotation de KEK externe", str(ctx_create.exception))

            # Le store redémarré avec la nouvelle KEK prend le relais.
            restarted = SqliteSecretStore(db_path, new_cipher)
            self.assertEqual(restarted.kek_version, 2)
            rec = await restarted.get("proj", "dev", "KEY1")
            assert rec is not None
            self.assertEqual(rec["value"], "val1")


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

    def test_cli_help_does_not_accept_secret_options_on_argv(self) -> None:
        """Preuve invariant 9 : aucune option --old-kek ni --new-kek n'existe en argument."""
        res = self.runner.invoke(cli_app, ["vault", "rotate-kek", "--help"])
        self.assertEqual(res.exit_code, 0)
        output_lower = res.output.lower()
        self.assertNotIn("--old-kek", output_lower)
        self.assertNotIn("--new-kek", output_lower)
        self.assertNotIn("--old-master-key", output_lower)
        self.assertNotIn("--new-master-key", output_lower)
        self.assertIn("règles de sécurité (invariant 9)", output_lower)

    def test_cli_rotate_nominal_via_env_vars(self) -> None:
        """Rotation nominale via variables d'environnement."""
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
        self.assertIn("Rotation de la KEK réussie : 1 secret(s) réenveloppé(s)", res.output)

        # Vérifier que le secret se lit avec la nouvelle KEK
        new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store_new = SqliteSecretStore(self.db_path, new_cipher)
        rec = store_new._get("demo", "dev", "API_KEY")
        assert rec is not None
        self.assertEqual(rec["value"], "super_secret_value")

    def test_cli_rotate_with_argon2id_derivation_env_vars(self) -> None:
        """Rotation via Argon2id avec clés et sels passés par l'environnement."""
        old_salt = generate_kek_salt()
        new_salt = generate_kek_salt()
        old_cipher = VaultCipher.from_master_key("old_master_passphrase_32_chars_ok!", old_salt)
        new_cipher = VaultCipher.from_master_key("new_master_passphrase_32_chars_ok!", new_salt)

        db_path = Path(self.tmp.name) / "vault_argon2.db"
        init_db(db_path)
        store = SqliteSecretStore(db_path, old_cipher)
        store._create("demo", "prod", "TOKEN", "val_argon2")

        env = {
            "HEIMDALL_VAULT_OLD_MASTER_KEY": "old_master_passphrase_32_chars_ok!",
            "HEIMDALL_VAULT_OLD_KEK_SALT": old_salt,
            "HEIMDALL_VAULT_NEW_MASTER_KEY": "new_master_passphrase_32_chars_ok!",
            "HEIMDALL_VAULT_NEW_KEK_SALT": new_salt,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 0)

        # Lecture post-rotation avec la nouvelle KEK dérivée
        store_new = SqliteSecretStore(db_path, new_cipher)
        rec = store_new._get("demo", "prod", "TOKEN")
        assert rec is not None
        self.assertEqual(rec["value"], "val_argon2")

    def test_cli_rotate_rejects_identical_keys(self) -> None:
        """Code 2 si l'ancienne et la nouvelle KEK sont identiques."""
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _OLD_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : L'ancienne et la nouvelle KEK doivent être distinctes", res.output)

    def test_cli_rotate_rejects_missing_keys_without_echoing(self) -> None:
        """Code 2 si aucune clé n'est fournie dans l'environnement."""
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env={"HEIMDALL_VAULT_OLD_KEK": "", "HEIMDALL_VAULT_KEK": ""},
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : l'ancienne KEK manquante", res.output)

    def test_cli_rotate_rejects_nonexistent_or_empty_database(self) -> None:
        """Code 2 si la base de données est inexistante ou vide sans la créer implicitement."""
        fake_db = Path(self.tmp.name) / "does_not_exist.db"
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(fake_db)],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : la base de données Vault est introuvable ou vide", res.output)
        self.assertFalse(fake_db.exists(), "La commande ne doit pas créer une fausse base vide")

    def test_cli_rotate_rejects_symlink_db_path_without_following(self) -> None:
        """Un --db-path symlink est refusé sans être suivi (fail-closed, invariant 8).

        La cible est une vraie base Vault : si le pré-contrôle suivait le lien,
        la rotation réussirait (exit 0). On vérifie donc qu'aucun secret n'a été
        lu/réenveloppé et que ni le lien ni sa cible ne sont modifiés.
        """
        target_db = Path(self.tmp.name) / "symlink_target.db"
        init_db(target_db)
        target_store = SqliteSecretStore(target_db, self.old_cipher)
        target_store._create("demo", "dev", "TARGET_SECRET", "target_value")

        link = Path(self.tmp.name) / "vault_link.db"
        link.symlink_to(target_db)

        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(link)],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : la base de données Vault est introuvable ou vide", res.output)
        self.assertNotIn(str(target_db), res.output)
        self.assertTrue(link.is_symlink(), "Le lien symbolique ne doit pas être remplacé")
        with db_session(target_db) as conn:
            sec = get_secret(conn, "demo", "dev", "TARGET_SECRET")
            assert sec is not None
            self.assertEqual(sec["kek_version"], 1)

    def test_cli_rotate_on_database_with_zero_secrets_exits_one(self) -> None:
        """Code 1 si la base existe mais ne contient aucun secret (fail-closed)."""
        empty_db = Path(self.tmp.name) / "empty_vault.db"
        init_db(empty_db)
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(empty_db)],
            env=env,
        )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("Erreur : aucun secret trouvé dans la base", res.output)

    def test_cli_rotate_rejects_target_version_downgrade(self) -> None:
        """Code 2 si --target-version tente un downgrade."""
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path), "--target-version", "1"],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Erreur : Le numéro de version cible (1) doit être", res.output)

    def test_cli_rotate_rejects_target_version_above_sqlite_integer_range(self) -> None:
        """Code 2 si --target-version dépasse INTEGER 64 bits signé (LOW revue).

        Sans borne haute, SQLite stockerait un REAL/TEXT hors contrat dans
        `kek_version` (audit faussé, lectures incohérentes).
        """
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            [
                "vault",
                "rotate-kek",
                "--db-path",
                str(self.db_path),
                "--target-version",
                "99999999999999999999",
            ],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("valeur <= 9223372036854775807 requise", res.output)
        self.assertNotIn("99999999999999999999", res.output)
        # Aucune écriture : la version persistée reste inchangée.
        with db_session(self.db_path) as conn:
            sec = get_secret(conn, "demo", "dev", "API_KEY")
            assert sec is not None
            self.assertEqual(sec["kek_version"], 1)
            self.assertIsInstance(sec["kek_version"], int)

    def test_cli_rotate_rejects_auto_increment_overflow_at_max(self) -> None:
        """Code 2 si l'auto-incrément atteint l'INTEGER 64 bits (LOW revue)."""
        with sqlite3.connect(str(self.db_path)) as conn_raw:
            conn_raw.execute(
                "UPDATE secrets SET kek_version = ? WHERE name = 'API_KEY'",
                (MAX_KEK_VERSION,),
            )
            conn_raw.commit()

        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("9223372036854775807", res.output)
        self.assertNotIn("9223372036854775808", res.output)
        # Aucune écriture : la version persistée reste en INTEGER à MAX.
        with db_session(self.db_path) as conn:
            sec = get_secret(conn, "demo", "dev", "API_KEY")
            assert sec is not None
            self.assertEqual(sec["kek_version"], MAX_KEK_VERSION)
            self.assertIsInstance(sec["kek_version"], int)

    def test_cli_rotate_wrong_old_key_exits_one(self) -> None:
        """Code 1 si l'ancienne KEK fournie ne parvient pas à déchiffrer les DEK."""
        wrong_old_kek = base64.urlsafe_b64encode(b"W" * 32).decode("ascii")
        env = {
            "HEIMDALL_VAULT_OLD_KEK": wrong_old_kek,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("échec du déchiffrement avec l'ancienne KEK", res.output)

    def test_cli_alias_kek_rotate_works_and_rotate_removed(self) -> None:
        """L'alias `kek-rotate` fonctionne et l'alias trop générique `rotate` est supprimé."""
        # L'alias générique 'rotate' n'existe plus pour éviter toute ambiguïté (LOW 3)
        res_generic = self.runner.invoke(
            cli_app,
            ["vault", "rotate", "--db-path", str(self.db_path)],
        )
        self.assertNotEqual(res_generic.exit_code, 0)

        # L'alias spécifique 'kek-rotate' fonctionne nominalement
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "kek-rotate", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Rotation de la KEK réussie", res.output)

    def test_cli_rotate_empty_old_kek_env_var_fails_closed_without_fallback(self) -> None:
        """CLI avec HEIMDALL_VAULT_OLD_KEK='' sort en code 2 sans utiliser le fallback."""
        env = {
            "HEIMDALL_VAULT_OLD_KEK": "",
            "HEIMDALL_VAULT_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("ne peut pas être vide", res.output)

    def test_cli_rotate_corrupted_kek_version_exits_one(self) -> None:
        """Code 1 (opérationnel) et message générique si kek_version corrompue (#71 LOW 2)."""
        corrupted_val = 1.5
        with sqlite3.connect(str(self.db_path)) as conn_raw:
            conn_raw.execute(
                "UPDATE secrets SET kek_version = ? WHERE name = 'API_KEY'",
                (corrupted_val,),
            )
            conn_raw.commit()

        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        res = self.runner.invoke(
            cli_app,
            ["vault", "rotate-kek", "--db-path", str(self.db_path)],
            env=env,
        )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("Erreur : base de données corrompue ou invalide", res.output)
        self.assertNotIn(str(corrupted_val), res.output)
        self.assertNotIn("1.5", res.output)

    def test_cli_rotate_concurrency_error_exits_one_without_reflection(self) -> None:
        """KekConcurrencyError est classée exit 1 par type, sans matching de libellé."""
        env = {
            "HEIMDALL_VAULT_OLD_KEK": _OLD_KEK_B64,
            "HEIMDALL_VAULT_NEW_KEK": _NEW_KEK_B64,
        }
        with unittest.mock.patch(
            "heimdall.cli.vault_keys.rotate_secrets_kek",
            side_effect=KekConcurrencyError("Concurrence détectée sur kek_version."),
        ):
            res = self.runner.invoke(
                cli_app,
                ["vault", "rotate-kek", "--db-path", str(self.db_path)],
                env=env,
            )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("Erreur : base de données corrompue ou invalide", res.output)
        self.assertNotIn("Concurrence", res.output)

    def test_cli_rotate_two_concurrent_processes_one_fails_closed(self) -> None:
        """Deux CLI rotate-kek simultanées : une réussit, l'autre échoue exit 1."""
        env = os.environ.copy()
        env["HEIMDALL_VAULT_OLD_KEK"] = _OLD_KEK_B64
        env["HEIMDALL_VAULT_NEW_KEK"] = _NEW_KEK_B64
        command = [
            sys.executable,
            "-c",
            "from heimdall.cli.main import main; main()",
            "vault",
            "rotate-kek",
            "--db-path",
            str(self.db_path),
        ]
        processes = [
            subprocess.Popen(  # noqa: S603 — commande statique, env de test contrôlé
                command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        results: list[tuple[int, str, str]] = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=60)
            results.append((process.returncode, stdout, stderr))

        self.assertEqual(sorted(code for code, _, _ in results), [0, 1])
        loser_output = "".join(
            stdout + stderr for code, stdout, stderr in results if code != 0
        )
        self.assertNotIn(_OLD_KEK_B64, loser_output)
        self.assertNotIn(_NEW_KEK_B64, loser_output)
        self.assertNotIn("super_secret_value", loser_output)

        with db_session(self.db_path) as conn:
            secret = get_secret(conn, "demo", "dev", "API_KEY")
            assert secret is not None
            self.assertEqual(secret["kek_version"], 2)

        rotated = SqliteSecretStore(self.db_path, VaultCipher(_NEW_KEK_BYTES))._get(
            "demo", "dev", "API_KEY"
        )
        assert rotated is not None
        self.assertEqual(rotated["value"], "super_secret_value")
        with self.assertRaises(SecretStoreError):
            SqliteSecretStore(self.db_path, self.old_cipher)._get(
                "demo", "dev", "API_KEY"
            )


class ValidateKekVersionHelperTests(unittest.TestCase):
    """Tests unitaires de validate_kek_version."""

    def test_validate_kek_version_nominal(self) -> None:
        self.assertEqual(validate_kek_version(1), 1)
        self.assertEqual(validate_kek_version(42), 42)

    def test_validate_kek_version_rejects_invalid_types_and_values(self) -> None:
        for val in (0, -1, -99, True, False, "1", 1.5, None):
            with self.assertRaises(ValueError):
                validate_kek_version(val)

    def test_validate_kek_version_bounds_sqlite_signed_integer(self) -> None:
        """Borne haute = INTEGER signé 64 bits de SQLite (LOW revue)."""
        self.assertEqual(validate_kek_version(MAX_KEK_VERSION), MAX_KEK_VERSION)
        for val in (MAX_KEK_VERSION + 1, 2**63, 99999999999999999999):
            with self.assertRaises(ValueError) as ctx:
                validate_kek_version(val)
            # Aucun reflet de la valeur refusée (invariant 8).
            self.assertNotIn(str(val), str(ctx.exception))
            self.assertIn("valeur <= 9223372036854775807 requise", str(ctx.exception))


class ReenvelopeSecretMonotonicityTests(unittest.TestCase):
    """Tests de la garde de monotonie de reenvelope_secret (#71 LOW 1)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-reenv-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        init_db(self.db_path)
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        self.new_cipher = VaultCipher(_NEW_KEK_BYTES)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_reenvelope_downgrade_refused(self) -> None:
        """reenvelope_secret refuse de descendre la kek_version (audit-faussable)."""
        with db_session(self.db_path) as conn:
            aad = VaultCipher.aad("proj", "dev", "KEY")
            envelope = self.old_cipher.encrypt_envelope(b"secret", aad=aad)
            # Créer le projet et le secret à kek_version=3
            ensure_project(conn, "proj")
            create_secret(
                conn,
                "proj",
                "dev",
                "KEY",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=3,
            )
            # Réenvelopper pour kek_version 5 (OK — montée)
            new_dek = self.old_cipher.rewrap_dek(self.new_cipher, envelope.encrypted_dek, aad=aad)
            reenvelope_secret(conn, "proj", "dev", "KEY", new_dek, kek_version=5)

            sec = get_secret(conn, "proj", "dev", "KEY")
            assert sec is not None
            self.assertEqual(sec["kek_version"], 5)

            # Downgrade 5 → 3 : doit être refusé
            with self.assertRaises(ValueError) as ctx:
                reenvelope_secret(conn, "proj", "dev", "KEY", new_dek, kek_version=3)
            self.assertIn("supérieure", str(ctx.exception))

    def test_reenvelope_same_version_refused(self) -> None:
        """reenvelope_secret refuse une version égale à la version courante."""
        with db_session(self.db_path) as conn:
            aad = VaultCipher.aad("proj", "dev", "KEY2")
            envelope = self.old_cipher.encrypt_envelope(b"val", aad=aad)
            ensure_project(conn, "proj")
            create_secret(
                conn,
                "proj",
                "dev",
                "KEY2",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=2,
            )
            with self.assertRaises(ValueError):
                reenvelope_secret(
                    conn, "proj", "dev", "KEY2", envelope.encrypted_dek, kek_version=2
                )

    def test_update_secret_downgrade_refused(self) -> None:
        """update_secret refuse de descendre la kek_version (audit faussable)."""
        with db_session(self.db_path) as conn:
            aad = VaultCipher.aad("proj", "dev", "KEY_UPD")
            envelope = self.old_cipher.encrypt_envelope(b"secret", aad=aad)
            ensure_project(conn, "proj")
            create_secret(
                conn,
                "proj",
                "dev",
                "KEY_UPD",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=5,
            )
            # Downgrade 5 -> 1 refusé
            with self.assertRaises(ValueError) as ctx:
                update_secret(
                    conn,
                    "proj",
                    "dev",
                    "KEY_UPD",
                    "new_val",
                    kek_version=1,
                )
            self.assertIn("inférieure", str(ctx.exception))

    def test_reenvelope_nonexistent_row_still_validates_kek_version(self) -> None:
        """reenvelope_secret sur une ligne inexistante retourne False sans erreur si version OK."""
        with db_session(self.db_path) as conn:
            # Pas de ligne : rowcount == 0, retourne False — pas d'exception
            result = reenvelope_secret(conn, "proj", "dev", "MISSING", "enc_dek", kek_version=1)
            self.assertFalse(result)

    def test_reenvelope_secret_intercalated_concurrent_update_refuses_downgrade(self) -> None:
        """reenvelope_secret intercalé (version passée de 1 à 3) refuse le downgrade 3->2."""
        with db_session(self.db_path) as conn:
            aad = VaultCipher.aad("proj", "dev", "INTERCAL")
            envelope = self.old_cipher.encrypt_envelope(b"val", aad=aad)
            ensure_project(conn, "proj")
            create_secret(
                conn,
                "proj",
                "dev",
                "INTERCAL",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=1,
            )
            new_dek = self.old_cipher.rewrap_dek(self.new_cipher, envelope.encrypted_dek, aad=aad)

            class _InterceptingConn:
                def __init__(self, target: sqlite3.Connection) -> None:
                    self._target = target

                def execute(
                    self, sql: str, parameters: Any = ()
                ) -> sqlite3.Cursor:
                    # Simuler un bump concurrent à 3 intercalé juste avant l'UPDATE atomique
                    if "UPDATE secrets SET encrypted_dek" in sql:
                        self._target.execute(
                            "UPDATE secrets SET kek_version = 3 "
                            "WHERE project_id = 'proj' AND env = 'dev' AND name = 'INTERCAL'"
                        )
                    return self._target.execute(sql, parameters)

                def __enter__(self) -> _InterceptingConn:
                    return self

                def __exit__(self, *args: object) -> object:
                    return False

                def __getattr__(self, name: str) -> object:
                    return getattr(self._target, name)

            proxy_conn: Any = _InterceptingConn(conn)
            with self.assertRaises(KekConcurrencyError) as ctx:
                reenvelope_secret(proxy_conn, "proj", "dev", "INTERCAL", new_dek, kek_version=2)
            self.assertEqual(str(ctx.exception), "Concurrence détectée sur kek_version.")
            # Invariant 8 : aucun identifiant ni version dans l'exception (#71 LOW 3)
            self.assertNotIn("proj", str(ctx.exception))
            self.assertNotIn("dev", str(ctx.exception))
            self.assertNotIn("INTERCAL", str(ctx.exception))

            sec = get_secret(conn, "proj", "dev", "INTERCAL")
            assert sec is not None
            # Le bump simulé partage le savepoint du helper : l'échec annule
            # aussi cette écriture (un vrai concurrent utiliserait une autre
            # connexion et ne serait pas concerné par ce rollback local).
            self.assertEqual(sec["kek_version"], 1)

    def test_update_secret_intercalated_concurrent_update_refuses_downgrade(self) -> None:
        """update_secret(..., kek_version=2) après montée 1->3 refuse l'écriture (#71 LOW 1)."""
        with db_session(self.db_path) as conn:
            aad = VaultCipher.aad("proj", "dev", "INTERCAL_UPD")
            envelope = self.old_cipher.encrypt_envelope(b"val_init", aad=aad)
            ensure_project(conn, "proj")
            create_secret(
                conn,
                "proj",
                "dev",
                "INTERCAL_UPD",
                envelope.encrypted_value,
                encrypted_dek=envelope.encrypted_dek,
                kek_version=1,
            )

            class _InterceptingConn:
                def __init__(self, target: sqlite3.Connection) -> None:
                    self._target = target

                def execute(
                    self, sql: str, parameters: Any = ()
                ) -> sqlite3.Cursor:
                    # Simuler un bump concurrent à 3 intercalé juste avant l'UPDATE atomique
                    if "UPDATE secrets SET" in sql:
                        self._target.execute(
                            "UPDATE secrets SET kek_version = 3 "
                            "WHERE project_id = 'proj' AND env = 'dev' AND name = 'INTERCAL_UPD'"
                        )
                    return self._target.execute(sql, parameters)

                def __enter__(self) -> _InterceptingConn:
                    return self

                def __exit__(self, *args: object) -> object:
                    return False

                def __getattr__(self, name: str) -> object:
                    return getattr(self._target, name)

            proxy_conn: Any = _InterceptingConn(conn)
            # update_secret avec kek_version=2 lève KekConcurrencyError et ne retourne pas False
            with self.assertRaises(KekConcurrencyError) as ctx:
                update_secret(
                    proxy_conn,
                    "proj",
                    "dev",
                    "INTERCAL_UPD",
                    "new_encrypted_val",
                    kek_version=2,
                )
            self.assertEqual(str(ctx.exception), "Concurrence détectée sur kek_version.")
            # Invariant 8 : aucun identifiant ni version dans l'exception (#71 LOW 3)
            self.assertNotIn("proj", str(ctx.exception))
            self.assertNotIn("dev", str(ctx.exception))
            self.assertNotIn("INTERCAL_UPD", str(ctx.exception))

            sec = get_secret(conn, "proj", "dev", "INTERCAL_UPD")
            assert sec is not None
            # Le bump simulé partage le savepoint du helper et est annulé avec
            # son échec : aucune écriture partielle ne subsiste.
            self.assertEqual(sec["kek_version"], 1)
            self.assertEqual(sec["encrypted_value"], envelope.encrypted_value)

    def test_update_secret_missing_row_with_kek_version_returns_false(self) -> None:
        """update_secret sur ligne absente avec kek_version retourne False (#71 LOW 1)."""
        with db_session(self.db_path) as conn:
            res = update_secret(
                conn,
                "proj",
                "dev",
                "DOES_NOT_EXIST",
                "enc_val",
                kek_version=2,
            )
            self.assertFalse(res)


class RotateSecretsKekCorruptedVersionTests(unittest.TestCase):
    """Tests de non-réflexion de contenu corrompu en base (#71 LOW 2 — invariant 8)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-corrupt-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        init_db(self.db_path)
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        self.new_cipher = VaultCipher(_NEW_KEK_BYTES)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _insert_secret_with_corrupt_kek_version(self, corrupt_value: str) -> None:
        """Insère une ligne avec une kek_version TEXT injectée directement en SQL."""
        # Insertion directe contournant validate_kek_version pour simuler une corruption.
        with sqlite3.connect(str(self.db_path)) as conn_raw:
            conn_raw.row_factory = sqlite3.Row
            conn_raw.execute("PRAGMA foreign_keys = ON")
            conn_raw.execute("INSERT OR IGNORE INTO projects (id, created_at) VALUES ('p','2026')")
            # Désactiver le CHECK SQLite le temps de l'insertion frauduleuse (ne fonctionne que
            # si le PRAGMA ignore_check_constraints est disponible, sinon ignorer silencieusement).
            try:
                conn_raw.execute("PRAGMA ignore_check_constraints = ON")
            except sqlite3.Error:
                pass
            aad = VaultCipher.aad("p", "dev", "BAD")
            envelope = self.old_cipher.encrypt_envelope(b"val", aad=aad)
            try:
                conn_raw.execute(
                    "INSERT INTO secrets "
                    "(project_id, env, name, encrypted_value, encrypted_dek, "
                    "kek_version, status, fingerprint, created_at, updated_at) "
                    "VALUES (?, 'dev', 'BAD', ?, ?, ?, 'vaulte', 'fp', '2026', '2026')",
                    ("p", envelope.encrypted_value, envelope.encrypted_dek, corrupt_value),
                )
                conn_raw.commit()
                return  # Insertion réussie (SQLite sans contrainte CHECK appliquée)
            except sqlite3.IntegrityError:
                pass  # CHECK actif : on ne peut pas insérer la valeur corrompue, test ignoré

    def test_corrupted_text_kek_version_raises_generic_error(self) -> None:
        """rotate_secrets_kek lève ValueError générique sans réfléter la valeur TEXT corrompue."""
        self._insert_secret_with_corrupt_kek_version("<script>alert(1)</script>")
        try:
            with db_session(self.db_path) as conn:
                secret = get_secret(conn, "p", "dev", "BAD")
        except Exception:
            self.skipTest(
                "Insertion de la valeur corrompue refusée par SQLite — test inapplicable."
            )
            return
        if secret is None or secret.get("kek_version") is None:
            self.skipTest(
                "Insertion de la valeur corrompue refusée par SQLite — test inapplicable."
            )
            return

        with db_session(self.db_path) as conn:
            with self.assertRaises(KekVersionError) as ctx:
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
        err_msg = str(ctx.exception)
        self.assertNotIn("<script>", err_msg)
        self.assertIn("illisible", err_msg)

    def test_reenvelope_secret_corrupted_version_raises_generic_error(self) -> None:
        """reenvelope_secret sur ligne avec kek_version corrompue lève ValueError générique."""
        self._insert_secret_with_corrupt_kek_version("<script>alert('reenvelope')</script>")
        try:
            with db_session(self.db_path) as conn:
                secret = get_secret(conn, "p", "dev", "BAD")
        except Exception:
            self.skipTest(
                "Insertion de la valeur corrompue refusée par SQLite — test inapplicable."
            )
            return
        if secret is None or secret.get("kek_version") is None:
            self.skipTest(
                "Insertion de la valeur corrompue refusée par SQLite — test inapplicable."
            )
            return

        with db_session(self.db_path) as conn:
            with self.assertRaises(KekVersionError) as ctx:
                reenvelope_secret(conn, "p", "dev", "BAD", "new_dek", kek_version=2)
        err_msg = str(ctx.exception)
        self.assertNotIn("<script>", err_msg)
        self.assertEqual(str(ctx.exception), "Version de KEK illisible en base.")

    def test_corrupted_real_kek_version_raises_generic_error(self) -> None:
        """rotate_secrets_kek lève ValueError sur kek_version REAL (1.5) sans reflet (#71 LOW 2)."""
        with sqlite3.connect(str(self.db_path)) as conn_raw:
            conn_raw.execute("INSERT OR IGNORE INTO projects (id, created_at) VALUES ('p', '2026')")
            aad = VaultCipher.aad("p", "dev", "BAD_REAL")
            envelope = self.old_cipher.encrypt_envelope(b"val", aad=aad)
            conn_raw.execute(
                "INSERT INTO secrets "
                "(project_id, env, name, encrypted_value, encrypted_dek, "
                "kek_version, status, fingerprint, created_at, updated_at) "
                "VALUES ('p', 'dev', 'BAD_REAL', ?, ?, 1.5, 'vaulte', 'fp', '2026', '2026')",
                (envelope.encrypted_value, envelope.encrypted_dek),
            )
            conn_raw.commit()

        with db_session(self.db_path) as conn:
            with self.assertRaises(KekVersionError) as ctx:
                rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
            self.assertEqual(str(ctx.exception), "Version de KEK illisible en base.")
            self.assertNotIn("1.5", str(ctx.exception))

            with self.assertRaises(KekVersionError) as ctx_up:
                update_secret(conn, "p", "dev", "BAD_REAL", "new_val", kek_version=2)
            self.assertEqual(str(ctx_up.exception), "Version de KEK illisible en base.")
            self.assertNotIn("1.5", str(ctx_up.exception))

            with self.assertRaises(KekVersionError) as ctx_re:
                reenvelope_secret(conn, "p", "dev", "BAD_REAL", "new_dek", kek_version=2)
            self.assertEqual(str(ctx_re.exception), "Version de KEK illisible en base.")
            self.assertNotIn("1.5", str(ctx_re.exception))


class SqliteStoreDetectKekVersionTests(unittest.TestCase):
    """Tests du comportement fail-closed de _detect_current_kek_version (#71 LOW 3)."""

    def test_detect_kek_version_on_accessible_db(self) -> None:
        """_detect_current_kek_version retourne MAX(kek_version) sur base accessible."""
        with tempfile.TemporaryDirectory(prefix="heimdall-detect-") as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(_OLD_KEK_BYTES)
            store = SqliteSecretStore(db_path, cipher)
            # Base vide : version initiale = 1
            self.assertEqual(store.kek_version, 1)

    def test_detect_kek_version_on_nonexistent_path_raises(self) -> None:
        """SqliteSecretStore: _detect_current_kek_version fail-closed sur base illisible."""
        # init_db est appelé dans __init__ ; on construit le store normalement puis
        # on pointe _db_path vers un chemin inexistant pour tester la propagation d'erreur.
        with tempfile.TemporaryDirectory(prefix="heimdall-detect2-") as tmp:
            db_path = Path(tmp) / "vault.db"
            cipher = VaultCipher(_OLD_KEK_BYTES)
            store = SqliteSecretStore(db_path, cipher)
            self.assertEqual(store.kek_version, 1)

            # Simuler une erreur SQLite lors de _detect_current_kek_version
            # en appelant la méthode avec un chemin invalide après construction.
            store._db_path = Path(tmp) / "nonexistent_subdir" / "vault.db"
            with self.assertRaises(RuntimeError) as ctx:
                store._detect_current_kek_version()
            self.assertIn("fail-closed", str(ctx.exception).lower())

    def test_detect_kek_version_reflects_rotated_version(self) -> None:
        """Un SqliteSecretStore rechargé après rotation détecte correctement MAX(kek_version)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-detect3-") as tmp:
            db_path = Path(tmp) / "vault.db"
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)

            store = SqliteSecretStore(db_path, old_cipher)
            store._create("proj", "dev", "K1", "val1")
            # Rotation vers version 7
            with db_session(db_path) as conn:
                rotate_secrets_kek(conn, old_cipher, new_cipher, target_kek_version=7)

            # Recréer le store à partir de la même base
            store2 = SqliteSecretStore(db_path, new_cipher)
            self.assertEqual(store2.kek_version, 7)

    def test_detect_kek_version_corrupted_text_raises_runtime_error_no_reflection(self) -> None:
        """SqliteSecretStore: _detect_current_kek_version fail-closed sans reflet sur TEXT."""
        with tempfile.TemporaryDirectory(prefix="heimdall-detect-corrupt-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            corrupt_val = "<injected-corrupted-version>"
            with sqlite3.connect(str(db_path)) as conn_raw:
                conn_raw.execute(
                    "INSERT OR IGNORE INTO projects (id, created_at) VALUES ('p','2026')"
                )
                conn_raw.execute(
                    "INSERT INTO secrets "
                    "(project_id, env, name, encrypted_value, encrypted_dek, "
                    "kek_version, status, fingerprint, created_at, updated_at) "
                    "VALUES ('p', 'dev', 'CORRUPT', 'enc_val', 'enc_dek', ?, 'vaulte', 'fp', "
                    "'2026', '2026')",
                    (corrupt_val,),
                )
                conn_raw.commit()

            cipher = VaultCipher(_OLD_KEK_BYTES)
            with self.assertRaises(RuntimeError) as ctx:
                SqliteSecretStore(db_path, cipher)
            err_msg = str(ctx.exception)
            self.assertNotIn(corrupt_val, err_msg)
            self.assertIn("Impossible de lire la version KEK courante", err_msg)

    def test_detect_kek_version_corrupted_real_raises_runtime_error_no_reflection(self) -> None:
        """SqliteSecretStore: _detect_current_kek_version fail-closed sur REAL (1.5) (#71 LOW 2)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-detect-real-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with sqlite3.connect(str(db_path)) as conn_raw:
                conn_raw.execute(
                    "INSERT OR IGNORE INTO projects (id, created_at) VALUES ('p', '2026')"
                )
                conn_raw.execute(
                    "INSERT INTO secrets "
                    "(project_id, env, name, encrypted_value, encrypted_dek, "
                    "kek_version, status, fingerprint, created_at, updated_at) "
                    "VALUES ('p', 'dev', 'REAL_VER', 'enc_val', 'enc_dek', 1.5, 'vaulte', 'fp', "
                    "'2026', '2026')"
                )
                conn_raw.commit()

            cipher = VaultCipher(_OLD_KEK_BYTES)
            with self.assertRaises(RuntimeError) as ctx:
                SqliteSecretStore(db_path, cipher)
            err_msg = str(ctx.exception)
            self.assertNotIn("1.5", err_msg)
            self.assertIn("Impossible de lire la version KEK courante", err_msg)

    def test_detect_kek_version_oversized_real_raises_generic_error_no_reflection(self) -> None:
        """_read_max_kek_version refuse un MAX hors INTEGER 64 bits (REAL) sans reflet (#71 LOW 2).

        SQLite ne peut stocker une valeur > 2**63-1 que sous forme de REAL :
        le garde-fou `> MAX_KEK_VERSION` ferme la porte en profondeur.
        """
        oversized = float(2**100)
        with tempfile.TemporaryDirectory(prefix="heimdall-detect-oversized-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with sqlite3.connect(str(db_path)) as conn_raw:
                conn_raw.execute(
                    "INSERT OR IGNORE INTO projects (id, created_at) VALUES ('p', '2026')"
                )
                conn_raw.execute(
                    "INSERT INTO secrets "
                    "(project_id, env, name, encrypted_value, encrypted_dek, "
                    "kek_version, status, fingerprint, created_at, updated_at) "
                    "VALUES ('p', 'dev', 'OVERSIZE', 'enc_val', 'enc_dek', ?, 'vaulte', 'fp', "
                    "'2026', '2026')",
                    (oversized,),
                )
                conn_raw.commit()

            cipher = VaultCipher(_OLD_KEK_BYTES)
            with self.assertRaises(RuntimeError) as ctx:
                SqliteSecretStore(db_path, cipher)
            err_msg = str(ctx.exception)
            self.assertIn("Impossible de lire la version KEK courante", err_msg)
            # Aucun reflet de la valeur débordante (invariant 8).
            self.assertNotIn("1.2676506002282294e+30", err_msg)
            self.assertNotIn("1e+30", err_msg)

        # Garde explicite `> MAX_KEK_VERSION` : un entier hors bornes (cas
        # mémoire / mock, impossible à obtenir via SQLite) est aussi refusé.
        class _OversizedConn:
            def execute(self, _sql: str) -> Any:
                return self

            def fetchone(self) -> Any:
                return (2**100,)

        with self.assertRaises(RuntimeError) as ctx_direct:
            _read_max_kek_version(_OversizedConn())  # type: ignore[arg-type]
        direct_msg = str(ctx_direct.exception)
        self.assertIn("Impossible de lire la version KEK courante", direct_msg)
        self.assertNotIn("1267650600228229401496703205376", direct_msg)

    def test_sqlite_store_rotate_kek_nominal_uses_returned_new_version_without_second_select(
        self,
    ) -> None:
        """SqliteSecretStore._rotate_kek nominal utilise new_version sans 2e SELECT."""
        with tempfile.TemporaryDirectory(prefix="heimdall-store-rot-no-select-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            old_cipher = VaultCipher(_OLD_KEK_BYTES)
            new_cipher = VaultCipher(_NEW_KEK_BYTES)
            store = SqliteSecretStore(db_path, old_cipher)
            store._create("p", "dev", "K1", "val1")

            mock_conn = unittest.mock.MagicMock()
            with unittest.mock.patch("heimdall.vault.store.db_session") as mock_db_session:
                mock_db_session.return_value.__enter__.return_value = mock_conn
                with unittest.mock.patch(
                    "heimdall.vault.store.rotate_secrets_kek",
                    return_value=(1, 42),
                ):
                    count = store._rotate_kek(new_cipher)

            self.assertEqual(count, 1)
            # Vérifier que store.kek_version vaut exactement la new_version retournée
            self.assertEqual(store.kek_version, 42)
            # Vérifier que _cipher a pivoté
            self.assertTrue(store._cipher.has_same_key_as(new_cipher))
            # Vérifier qu'AUCUNE 2e requête SELECT n'a été exécutée
            mock_conn.execute.assert_not_called()


class NestedTransactionIsolationTests(unittest.TestCase):
    """LOW revue : aucun helper d'écriture ne commite la transaction de l'appelant."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="heimdall-nested-tx-")
        self.db_path = Path(self.tmp.name) / "vault.db"
        init_db(self.db_path)
        self.old_cipher = VaultCipher(_OLD_KEK_BYTES)
        self.new_cipher = VaultCipher(_NEW_KEK_BYTES)
        store = SqliteSecretStore(self.db_path, self.old_cipher)
        store._create("proj", "dev", "API_KEY", "valeur_initiale")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _snapshot(self) -> dict[str, Any]:
        with db_session(self.db_path) as conn:
            record = get_secret(conn, "proj", "dev", "API_KEY")
        assert record is not None
        return record

    def _run_then_fail(self, write: Any) -> None:
        """Écriture antérieure + helper + échec dans la même session SQLite."""
        with self.assertRaises(RuntimeError):
            with db_session(self.db_path) as conn:
                # Écriture antérieure : la transaction de l'appelant est ouverte.
                ensure_project(conn, "caller_tx_marker")
                write(conn)
                raise RuntimeError("échec ultérieur simulé")

    def _assert_fully_rolled_back(self, before: dict[str, Any]) -> None:
        after = self._snapshot()
        self.assertEqual(after["encrypted_value"], before["encrypted_value"])
        self.assertEqual(after["encrypted_dek"], before["encrypted_dek"])
        self.assertEqual(after["fingerprint"], before["fingerprint"])
        self.assertEqual(after["kek_version"], before["kek_version"])
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM projects WHERE id = 'caller_tx_marker'"
            ).fetchone()
        assert row is not None
        self.assertEqual(row[0], 0, "L'écriture antérieure de l'appelant doit être annulée")

    def test_update_secret_does_not_commit_caller_transaction(self) -> None:
        before = self._snapshot()
        self._run_then_fail(
            lambda conn: update_secret(
                conn,
                "proj",
                "dev",
                "API_KEY",
                "valeur_rechiffree",
                encrypted_dek="enveloppe_v2",
                kek_version=2,
                fingerprint="empreinte_v2",
            )
        )
        self._assert_fully_rolled_back(before)

    def test_reenvelope_secret_does_not_commit_caller_transaction(self) -> None:
        before = self._snapshot()
        self._run_then_fail(
            lambda conn: reenvelope_secret(conn, "proj", "dev", "API_KEY", "enveloppe_v2", 2)
        )
        self._assert_fully_rolled_back(before)

    def test_rotate_secrets_kek_does_not_commit_caller_transaction(self) -> None:
        before = self._snapshot()
        self._run_then_fail(
            lambda conn: rotate_secrets_kek(conn, self.old_cipher, self.new_cipher)
        )
        self._assert_fully_rolled_back(before)

    def test_two_helpers_chained_in_same_session_roll_back_together(self) -> None:
        """Deux helpers chaînés : aucun commit partiel si le second échoue (LOW revue)."""
        before = self._snapshot()
        with self.assertRaises(RuntimeError):
            with db_session(self.db_path) as conn:
                # Premier helper : ne doit pas commiter avant la fin de la session.
                update_secret(
                    conn,
                    "proj",
                    "dev",
                    "API_KEY",
                    "valeur_v2",
                    encrypted_dek="enveloppe_v2",
                    kek_version=2,
                    fingerprint="empreinte_v2",
                )
                # Second helper, puis échec : les deux écritures doivent être annulées.
                reenvelope_secret(conn, "proj", "dev", "API_KEY", "enveloppe_v3", 3)
                raise RuntimeError("échec après deux helpers")
        self._assert_fully_rolled_back(before)

    def test_concurrent_sessions_do_not_cross_commit(self) -> None:
        """Deux sessions concurrentes : portées transactionnelles indépendantes (#71 LOW 3).

        Le marquage de session porte sur l'objet connexion (attribut
        `_heimdall_session`), pas sur un registre global d'`id()` : aucune
        classification croisée possible entre deux sessions de threads.
        """
        paths: list[Path] = []
        for idx in (1, 2):
            path = Path(self.tmp.name) / f"concurrent_{idx}.db"
            init_db(path)
            SqliteSecretStore(path, self.old_cipher)._create(
                "proj", "dev", f"K{idx}", f"valeur_{idx}"
            )
            paths.append(path)

        barrier = threading.Barrier(2, timeout=10)
        outcomes: dict[str, str] = {}

        def failing() -> None:
            try:
                with db_session(paths[0]) as conn:
                    barrier.wait()
                    update_secret(
                        conn,
                        "proj",
                        "dev",
                        "K1",
                        "valeur_modifiee",
                        encrypted_dek="enveloppe_v2",
                        kek_version=2,
                        fingerprint="empreinte_v2",
                    )
                    raise RuntimeError("échec simulé")
            except RuntimeError:
                outcomes["failing"] = "rolled_back"
            else:  # pragma: no cover - garde
                outcomes["failing"] = "committed"

        def succeeding() -> None:
            with db_session(paths[1]) as conn:
                barrier.wait()
                update_secret(
                    conn,
                    "proj",
                    "dev",
                    "K2",
                    "valeur_modifiee",
                    encrypted_dek="enveloppe_v2",
                    kek_version=2,
                    fingerprint="empreinte_v2",
                )
            outcomes["succeeding"] = "committed"

        t1 = threading.Thread(target=failing)
        t2 = threading.Thread(target=succeeding)
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
        self.assertEqual(
            outcomes, {"failing": "rolled_back", "succeeding": "committed"}
        )

        # Aucun commit croisé : chaque base ne reflète que sa propre session.
        with db_session(paths[0]) as conn:
            rec1 = get_secret(conn, "proj", "dev", "K1")
        with db_session(paths[1]) as conn:
            rec2 = get_secret(conn, "proj", "dev", "K2")
        assert rec1 is not None and rec2 is not None
        self.assertEqual(rec1["kek_version"], 1)
        self.assertEqual(rec2["kek_version"], 2)
