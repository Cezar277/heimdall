"""Preuves du ticket #70 — DEK par secret et stockage chiffré par enveloppe.

Sous-ticket de #26 « clé maîtresse et chiffrement par enveloppe ». Chaque
secret reçoit une DEK aléatoire de 32 octets ; la valeur est chiffrée avec la
DEK, puis la DEK est chiffrée avec la KEK. Les deux blobs sont stockés dans la
même ligne SQLite (``encrypted_value`` et ``encrypted_dek``).

Ce que cette suite prouve (checklist du ticket) :

1. une DEK de 32 octets est générée par secret, indépendante des autres ;
2. la valeur se déchiffre avec la DEK, et la DEK se déchiffre avec la KEK ;
3. les deux blobs sont persistés dans la ligne du secret ;
4. **aucune valeur en clair** n'apparaît dans le fichier SQLite brut, et la
   DEK elle-même n'y apparaît pas en clair (elle est enveloppée) ;
5. un blob de valeur ou de DEK déplacé vers un autre secret échoue (AAD) ;
6. les lignes héritées (#25/#62, sans ``encrypted_dek``) restent lisibles ;
7. le réenveloppement via ``update_secret`` reste lisible et une chaîne vide
   ne peut pas effacer une enveloppe existante ;
8. le défaut de ``create_secret`` est ``NULL`` (jamais ``""``) et les
   métadonnées/listes n'exposent ni valeur ni enveloppe ;
9. le swap valeur ↔ enveloppe est refusé et un ``ValueError`` du chemin
   enveloppe devient une ``SecretStoreError`` générique ;
10. une base pré-#70 non migrée guide vers ``init_db`` au lieu de laisser
    remonter un ``OperationalError`` SQL brut ;
11. la course ``PRAGMA`` → ``ALTER`` entre deux ``init_db`` est absorbée ;
12. la KEK elle-même n'apparaît pas dans le fichier SQLite brut.

Faux secrets : valeurs synthétiques explicites, jamais de secret réel.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from heimdall.vault.crypto import (
    SecretEnvelope,
    VaultCipher,
    VaultCipherError,
    generate_dek,
)
from heimdall.vault.database import (
    SCHEMA_SQL,
    _ensure_secret_envelope_column,
    create_project,
    create_secret,
    db_session,
    get_secret,
    get_secret_metadata,
    init_db,
    list_secrets,
    update_secret,
)
from heimdall.vault.store import (
    InMemorySecretStore,
    SecretStoreError,
    SqliteSecretStore,
)

_KEK = b"K" * 32  # KEK synthétique de 32 octets (AES-256)
_PLAINTEXT = "t263-synthetic-secret-value"


def _aad(project: str = "demo", env: str = "dev", name: str = "API_TOKEN") -> bytes:
    return VaultCipher.aad(project, env, name)


class DekGenerationTests(unittest.TestCase):
    """Une DEK aléatoire de 256 bits, indépendante pour chaque secret."""

    def test_generate_dek_returns_32_random_bytes(self) -> None:
        """Chaque appel rend 32 octets, et 64 tirages sont tous distincts."""
        deks = [generate_dek() for _ in range(64)]
        self.assertTrue(all(len(dek) == 32 for dek in deks))
        self.assertEqual(len(set(deks)), 64)

    def test_envelope_wraps_value_with_dek_and_dek_with_kek(self) -> None:
        """La valeur se déchiffre avec la DEK, la DEK avec la KEK — pas l'inverse."""
        cipher = VaultCipher(_KEK)
        aad = _aad()
        envelope = cipher.encrypt_envelope(_PLAINTEXT.encode("utf-8"), aad=aad)

        self.assertIsInstance(envelope, SecretEnvelope)
        dek = cipher.unwrap_dek(envelope.encrypted_dek, aad=aad)
        self.assertEqual(len(dek), 32)
        self.assertEqual(
            cipher.decrypt_with_dek(envelope.encrypted_value, dek, aad=aad),
            _PLAINTEXT.encode("utf-8"),
        )

        # La KEK seule ne déchiffre ni la valeur ni l'enveloppe de DEK : le
        # domaine de l'enveloppe est distinct de celui de la valeur.
        with self.assertRaises(VaultCipherError):
            cipher.decrypt(envelope.encrypted_value, aad=aad)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt(envelope.encrypted_dek, aad=aad)

        # Une autre DEK ne déchiffre pas la valeur.
        with self.assertRaises(VaultCipherError):
            cipher.decrypt_with_dek(envelope.encrypted_value, b"L" * 32, aad=aad)

    def test_wrapped_dek_and_value_are_bound_to_the_secret_identity(self) -> None:
        """Un blob de valeur ou de DEK déplacé vers un autre secret est refusé."""
        cipher = VaultCipher(_KEK)
        aad_one = _aad(name="SECRET_ONE")
        aad_two = _aad(name="SECRET_TWO")
        envelope_one = cipher.encrypt_envelope(b"value-one", aad=aad_one)
        envelope_two = cipher.encrypt_envelope(b"value-two", aad=aad_two)

        with self.assertRaises(VaultCipherError):
            cipher.unwrap_dek(envelope_one.encrypted_dek, aad=aad_two)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt_envelope(
                envelope_one.encrypted_value,
                envelope_one.encrypted_dek,
                aad=aad_two,
            )

        dek_two = cipher.unwrap_dek(envelope_two.encrypted_dek, aad=aad_two)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt_with_dek(envelope_one.encrypted_value, dek_two, aad=aad_one)


class SqliteEnvelopeStorageTests(unittest.IsolatedAsyncioTestCase):
    """Persistance des deux blobs et absence de clair dans le fichier SQLite."""

    async def test_two_secrets_same_value_have_distinct_deks_and_blobs(self) -> None:
        """Même valeur, deux secrets : deux DEK et deux blobs distincts."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "SECRET_ONE", _PLAINTEXT)
            await store.create("demo", "dev", "SECRET_TWO", _PLAINTEXT)

            with db_session(db_path) as conn:
                rows = conn.execute(
                    "SELECT name, encrypted_value, encrypted_dek FROM secrets ORDER BY name"
                ).fetchall()

            self.assertEqual(len(rows), 2)
            deks: dict[str, bytes] = {}
            for row in rows:
                self.assertTrue(row["encrypted_dek"])
                self.assertNotIn(_PLAINTEXT, row["encrypted_value"])
                self.assertNotIn(_PLAINTEXT, row["encrypted_dek"])
                deks[row["name"]] = cipher.unwrap_dek(
                    row["encrypted_dek"],
                    aad=_aad(name=row["name"]),
                )
            self.assertNotEqual(deks["SECRET_ONE"], deks["SECRET_TWO"])
            self.assertNotEqual(rows[0]["encrypted_value"], rows[1]["encrypted_value"])
            self.assertNotEqual(rows[0]["encrypted_dek"], rows[1]["encrypted_dek"])

    async def test_sqlite_store_roundtrip_after_reopen(self) -> None:
        """Les deux blobs suffisent à relire le secret après redémarrage."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            await SqliteSecretStore(db_path, cipher).create(
                "demo", "dev", "API_TOKEN", _PLAINTEXT
            )
            reopened = SqliteSecretStore(db_path, cipher)
            record = await reopened.get("demo", "dev", "API_TOKEN")
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record["value"], _PLAINTEXT)

    async def test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek(self) -> None:
        """Critère « Fait quand » : ni valeur ni DEK en clair dans le fichier brut."""
        cipher = VaultCipher(_KEK)
        canaries = [
            "T263_CANARY_ALPHA_91b7",
            "T263_CANARY_BETA_4d2e",
            "T263_CANARY_GAMMA_c8f1",
        ]
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            for index, canary in enumerate(canaries):
                await store.create("demo", "dev", f"CANARY_{index}", canary)

            raw = db_path.read_bytes()
            self.assertNotIn(_KEK, raw)
            for canary in canaries:
                self.assertNotIn(canary.encode("utf-8"), raw)

            with db_session(db_path) as conn:
                rows = conn.execute(
                    "SELECT name, encrypted_value, encrypted_dek FROM secrets ORDER BY name"
                ).fetchall()
            self.assertEqual(len(rows), len(canaries))
            for row in rows:
                for column in ("encrypted_value", "encrypted_dek"):
                    self.assertNotIn(canaries[0], row[column])
                    self.assertNotIn(canaries[1], row[column])
                    self.assertNotIn(canaries[2], row[column])
                dek = cipher.unwrap_dek(row["encrypted_dek"], aad=_aad(name=row["name"]))
                self.assertNotIn(dek, raw)

    async def test_in_memory_store_uses_the_same_envelope(self) -> None:
        """Le backend mémoire chiffre aussi avec une DEK par secret."""
        cipher = VaultCipher(_KEK)
        store = InMemorySecretStore(cipher=cipher)
        await store.create("demo", "dev", "API_TOKEN", _PLAINTEXT)
        internal = next(iter(store._secrets.values()))

        self.assertTrue(internal["encrypted_dek"])
        self.assertNotIn(_PLAINTEXT, json.dumps(internal))
        dek = cipher.unwrap_dek(internal["encrypted_dek"], aad=_aad())
        self.assertEqual(
            cipher.decrypt_with_dek(internal["encrypted_value"], dek, aad=_aad()),
            _PLAINTEXT.encode("utf-8"),
        )

    async def test_legacy_row_without_dek_is_still_readable(self) -> None:
        """Une ligne #25/#62 (KEK directe, sans encrypted_dek) reste lisible."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            aad = _aad(name="LEGACY_TOKEN")
            legacy_blob = cipher.encrypt(_PLAINTEXT.encode("utf-8"), aad=aad)
            with db_session(db_path) as conn:
                create_project(conn, "demo")
                create_secret(
                    conn,
                    "demo",
                    "dev",
                    "LEGACY_TOKEN",
                    legacy_blob,
                    fingerprint="legacy-fingerprint",
                )

            store = SqliteSecretStore(db_path, cipher)
            record = await store.get("demo", "dev", "LEGACY_TOKEN")
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record["value"], _PLAINTEXT)


class SchemaMigrationTests(unittest.TestCase):
    """La colonne d'enveloppe est ajoutée aux bases existantes, sans perte."""

    def test_init_db_adds_encrypted_dek_to_legacy_schema(self) -> None:
        """Une base créée avant #70 reçoit la colonne nullable à l'init."""
        legacy_schema = SCHEMA_SQL.replace("    encrypted_dek TEXT,\n", "")
        self.assertNotIn("encrypted_dek", legacy_schema)

        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            conn = sqlite3.connect(str(db_path))
            try:
                conn.executescript(legacy_schema)
            finally:
                conn.close()

            init_db(db_path)
            with db_session(db_path) as conn:
                columns = {
                    str(row[1])
                    for row in conn.execute("PRAGMA table_info(secrets);").fetchall()
                }
            self.assertIn("encrypted_dek", columns)

    def test_ensure_secret_envelope_column_tolerates_concurrent_alter(self) -> None:
        """La course PRAGMA→ALTER entre deux init_db est absorbée sans erreur."""
        legacy_schema = SCHEMA_SQL.replace("    encrypted_dek TEXT,\n", "")
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            conn = sqlite3.connect(str(db_path))
            other = sqlite3.connect(str(db_path))
            try:
                conn.executescript(legacy_schema)

                class _RacingConnection:
                    """Connexion qui simule un autre worker gagnant l'ALTER."""

                    def __init__(
                        self,
                        real: sqlite3.Connection,
                        concurrent: sqlite3.Connection,
                    ) -> None:
                        self._real = real
                        self._concurrent = concurrent

                    def execute(
                        self,
                        sql: str,
                        parameters: tuple[object, ...] = (),
                    ) -> sqlite3.Cursor:
                        if sql.startswith("ALTER TABLE secrets ADD COLUMN encrypted_dek"):
                            self._concurrent.execute(sql)
                            self._concurrent.commit()
                        return self._real.execute(sql, parameters)

                _ensure_secret_envelope_column(
                    _RacingConnection(conn, other)  # type: ignore[arg-type]
                )
                columns = {
                    str(row[1])
                    for row in conn.execute("PRAGMA table_info(secrets);").fetchall()
                }
                self.assertIn("encrypted_dek", columns)
            finally:
                conn.close()
                other.close()


class EnvelopeDatabaseContractTests(unittest.TestCase):
    """Contrat DB : NULL legacy, métadonnées sans blobs, swap de blobs refusé."""

    def test_create_secret_defaults_to_null_envelope(self) -> None:
        """Le défaut est NULL, jamais une chaîne vide (une seule représentation)."""
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                create_project(conn, "demo")
                created = create_secret(
                    conn,
                    "demo",
                    "dev",
                    "LEGACY_TOKEN",
                    "legacy-blob",
                )
                self.assertIsNone(created["encrypted_dek"])
                row = conn.execute(
                    "SELECT encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "LEGACY_TOKEN"),
                ).fetchone()
                self.assertIsNone(row["encrypted_dek"])

                # Une chaîne vide explicite est normalisée en NULL, pas stockée.
                create_secret(
                    conn,
                    "demo",
                    "dev",
                    "EMPTY_TOKEN",
                    "legacy-blob",
                    encrypted_dek="",
                )
                row = conn.execute(
                    "SELECT encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "EMPTY_TOKEN"),
                ).fetchone()
                self.assertIsNone(row["encrypted_dek"])

    def test_metadata_and_list_do_not_expose_envelope(self) -> None:
        """Les métadonnées et listes ne divulguent ni valeur ni enveloppe de DEK."""
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            with db_session(db_path) as conn:
                create_project(conn, "demo")
                create_secret(
                    conn,
                    "demo",
                    "dev",
                    "API_TOKEN",
                    "encrypted-value",
                    encrypted_dek="wrapped-dek",
                )
                meta = get_secret_metadata(conn, "demo", "dev", "API_TOKEN")
                self.assertIsNotNone(meta)
                assert meta is not None
                self.assertNotIn("encrypted_value", meta)
                self.assertNotIn("encrypted_dek", meta)

                listed = list_secrets(conn, "demo", env="dev")
                self.assertEqual(len(listed), 1)
                self.assertNotIn("encrypted_value", listed[0])
                self.assertNotIn("encrypted_dek", listed[0])

    def test_get_secret_on_unmigrated_schema_raises_actionable_error(self) -> None:
        """Une base pré-#70 non migrée guide vers init_db, sans SQL brut."""
        legacy_schema = SCHEMA_SQL.replace("    encrypted_dek TEXT,\n", "")
        self.assertNotIn("encrypted_dek", legacy_schema)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            conn = sqlite3.connect(str(db_path))
            try:
                conn.executescript(legacy_schema)
                conn.execute(
                    "INSERT INTO projects (id, created_at) VALUES (?, ?)",
                    ("demo", "2026-01-01T00:00:00Z"),
                )
                conn.execute(
                    "INSERT INTO secrets (project_id, env, name, encrypted_value, "
                    "status, fingerprint, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "demo",
                        "dev",
                        "LEGACY_TOKEN",
                        "legacy-blob",
                        "vaulte",
                        "legacy-fingerprint",
                        "2026-01-01T00:00:00Z",
                        "2026-01-01T00:00:00Z",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            with db_session(db_path) as conn:
                with self.assertRaises(RuntimeError) as ctx:
                    get_secret(conn, "demo", "dev", "LEGACY_TOKEN")
            message = str(ctx.exception)
            self.assertIn("init_db", message)
            self.assertIn("SqliteSecretStore", message)
            self.assertNotIn("no such column", message)

    def test_swapping_value_and_wrapped_dek_fails_authentication(self) -> None:
        """Un swap valeur ↔ enveloppe de DEK échoue à l'authentification GCM."""
        cipher = VaultCipher(_KEK)
        aad = _aad()
        envelope = cipher.encrypt_envelope(_PLAINTEXT.encode("utf-8"), aad=aad)
        with self.assertRaises(VaultCipherError):
            cipher.decrypt_envelope(
                envelope.encrypted_dek,
                envelope.encrypted_value,
                aad=aad,
            )


class EnvelopeUpdateTests(unittest.IsolatedAsyncioTestCase):
    """Réenveloppement, garde anti-effacement et mapping d'erreur du store."""

    async def test_update_secret_rewraps_dek_and_remains_readable(self) -> None:
        """La branche non-NULL de COALESCE réenveloppe la DEK et reste lisible."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "API_TOKEN", _PLAINTEXT)
            aad = _aad()
            replacement = cipher.encrypt_envelope(_PLAINTEXT.encode("utf-8"), aad=aad)
            with db_session(db_path) as conn:
                self.assertTrue(
                    update_secret(
                        conn,
                        "demo",
                        "dev",
                        "API_TOKEN",
                        replacement.encrypted_value,
                        encrypted_dek=replacement.encrypted_dek,
                    )
                )
                row = conn.execute(
                    "SELECT encrypted_value, encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "API_TOKEN"),
                ).fetchone()
            self.assertEqual(row["encrypted_value"], replacement.encrypted_value)
            self.assertEqual(row["encrypted_dek"], replacement.encrypted_dek)
            record = await store.get("demo", "dev", "API_TOKEN")
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record["value"], _PLAINTEXT)

    async def test_update_secret_rejects_empty_dek_without_wiping_envelope(self) -> None:
        """Une chaîne vide est refusée et ne détruit pas l'enveloppe existante."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "API_TOKEN", _PLAINTEXT)
            with db_session(db_path) as conn:
                before = conn.execute(
                    "SELECT encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "API_TOKEN"),
                ).fetchone()
                with self.assertRaises(ValueError):
                    update_secret(
                        conn,
                        "demo",
                        "dev",
                        "API_TOKEN",
                        "replacement-value",
                        encrypted_dek="",
                    )
                after = conn.execute(
                    "SELECT encrypted_value, encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "API_TOKEN"),
                ).fetchone()
            self.assertEqual(after["encrypted_dek"], before["encrypted_dek"])
            self.assertNotEqual(after["encrypted_value"], "replacement-value")
            record = await store.get("demo", "dev", "API_TOKEN")
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record["value"], _PLAINTEXT)

    async def test_value_error_from_envelope_is_mapped_to_store_error(self) -> None:
        """Un ValueError du chemin enveloppe devient une SecretStoreError générique."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "API_TOKEN", _PLAINTEXT)
            with patch.object(
                cipher,
                "decrypt_envelope",
                side_effect=ValueError("synthetic"),
            ):
                with self.assertRaises(SecretStoreError):
                    await store.get("demo", "dev", "API_TOKEN")

    async def test_swapped_blobs_in_sqlite_are_rejected(self) -> None:
        """Un swap valeur ↔ enveloppe directement en base est refusé au déchiffrement."""
        cipher = VaultCipher(_KEK)
        with tempfile.TemporaryDirectory(prefix="heimdall-t263-") as tmp:
            db_path = Path(tmp) / "vault.db"
            store = SqliteSecretStore(db_path, cipher)
            await store.create("demo", "dev", "API_TOKEN", _PLAINTEXT)
            with db_session(db_path) as conn:
                conn.execute(
                    "UPDATE secrets SET encrypted_value = encrypted_dek, "
                    "encrypted_dek = encrypted_value "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "API_TOKEN"),
                )
                row = conn.execute(
                    "SELECT encrypted_value, encrypted_dek FROM secrets "
                    "WHERE project_id = ? AND env = ? AND name = ?",
                    ("demo", "dev", "API_TOKEN"),
                ).fetchone()
            with self.assertRaises(VaultCipherError):
                cipher.decrypt_envelope(
                    row["encrypted_value"],
                    row["encrypted_dek"],
                    aad=_aad(),
                )
            with self.assertRaises(SecretStoreError):
                await store.get("demo", "dev", "API_TOKEN")


if __name__ == "__main__":
    unittest.main()
