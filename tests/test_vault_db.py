"""Tests unitaires et de sécurité pour la base de données SQLite du Vault (#62).

Vérifie :
1. L'initialisation à froid de la base (script `init_db` et module `database`).
2. L'activation stricte et systématique de `PRAGMA foreign_keys = ON;`.
3. Le rejet immédiat de clés étrangères invalides (intégrité référentielle).
4. La suppression en cascade (suppression d'un projet supprime ses clés et secrets).
5. La contrainte d'unicité `UNIQUE(project_id, env, name)` sur les secrets.
6. La contrainte d'intégrité `CHECK(status IN ('vaulte', 'rote'))`.
7. L'immunité absolue aux injections SQL (CWE-89) via requêtes paramétrées.
8. Les opérations CRUD complètes sur les projets, clés API et secrets.
9. La gestion transactionnelle `db_session` (commit automatique et rollback sur exception).
10. Les permissions sécurisées du fichier SQLite (`0o600` sous POSIX, fail-closed).
11. Le refus des chemins symboliques (protection TOCTOU).
12. Le comportement fail-closed si `chmod` échoue (mock OSError).
13. L'absence de fichiers sidecar SQLite (`-wal`, `-shm`, `-journal`) après écriture.
14. Le rejet applicatif du statut invalide sur `update_secret`.
15. La couverture du `.gitignore` sur `vault.db` (non-régression commit accidentel).
16. La validation de `VaultSettings.db_path` (vide, caractères de contrôle).
"""

import fnmatch
import io
import os
import shutil
import sqlite3
import stat as stat_module
import subprocess
import tempfile
import typing
import unittest
import warnings
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from heimdall.vault.app import VaultSettings
from heimdall.vault.database import (
    DEFAULT_DB_PATH,
    SecretStatus,
    _apply_secure_permissions,
    create_api_key,
    create_project,
    create_secret,
    db_session,
    delete_api_key,
    delete_project,
    delete_secret,
    get_api_key,
    get_api_key_by_hash,
    get_connection,
    get_project,
    get_secret,
    get_secret_metadata,
    init_db,
    list_api_keys_for_project,
    list_projects,
    list_secrets,
    resolve_db_path,
    revoke_api_key,
    update_secret,
    validate_db_path,
)
from heimdall.vault.init_db import main as init_db_main


class VaultDatabaseTests(unittest.TestCase):
    """Suite de tests du modèle SQLite du Vault Heimdall."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vault.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -----------------------------------------------------------------------
    # 1. Initialisation à froid
    # -----------------------------------------------------------------------

    def test_cold_init_creates_schema_and_indexes(self) -> None:
        """Critère d'acceptation #62 : la base est créée à froid depuis zéro."""
        self.assertFalse(self.db_path.exists())
        init_db(self.db_path)
        self.assertTrue(self.db_path.exists())

        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = {row["name"] for row in cursor.fetchall()}
            self.assertIn("projects", tables)
            self.assertIn("api_keys", tables)
            self.assertIn("secrets", tables)

            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")
            indexes = {row["name"] for row in cursor.fetchall()}
            self.assertIn("idx_api_keys_project_id", indexes)
            self.assertIn("idx_api_keys_key_hash", indexes)
            self.assertIn("idx_secrets_project_env_name", indexes)
        finally:
            conn.close()

    def test_init_db_cli_script(self) -> None:
        """Le script CLI `python -m heimdall.vault.init_db` s'exécute avec succès."""
        target_path = Path(self.temp_dir.name) / "cli_vault.db"
        ret = init_db_main(["--db-path", str(target_path)])
        self.assertEqual(ret, 0)
        self.assertTrue(target_path.exists())

    # -----------------------------------------------------------------------
    # 2 & 10. Permissions fichier (M2 corrigé : fail-closed)
    # -----------------------------------------------------------------------

    def test_secure_file_permissions(self) -> None:
        """Vérifie que les permissions du fichier créé sont restreintes à 0o600 sous POSIX."""
        init_db(self.db_path)
        if os.name != "nt":
            mode = self.db_path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_chmod_failure_raises_permission_error(self) -> None:
        """M2 — Si chmod échoue, _apply_secure_permissions lève PermissionError (fail-closed)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        self.db_path.touch()
        with patch.object(Path, "chmod", side_effect=OSError("FS readonly")):
            with self.assertRaises(PermissionError):
                _apply_secure_permissions(self.db_path)

    def test_chmod_wrong_mode_raises_permission_error(self) -> None:
        """M2 — Si le mode effectif après chmod n'est pas 0o600, PermissionError (fail-closed)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        self.db_path.touch()
        # chmod réussit mais stat() retourne un mode incorrect
        with patch.object(Path, "chmod"):
            fake_stat = type(
                "FakeStat", (), {"st_mode": stat_module.S_IFREG | 0o644, "st_size": 0}
            )()
            with patch.object(Path, "stat", return_value=fake_stat):
                with self.assertRaises(PermissionError):
                    _apply_secure_permissions(self.db_path)

    # -----------------------------------------------------------------------
    # 11. Refus des chemins symboliques (M1 corrigé)
    # -----------------------------------------------------------------------

    def test_symlink_on_db_path_is_refused(self) -> None:
        """M1 — Un lien symbolique sur le chemin de la base est refusé (TOCTOU)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        real_file = Path(self.temp_dir.name) / "real_vault.db"
        real_file.touch()
        symlink_path = Path(self.temp_dir.name) / "symlink_vault.db"
        symlink_path.symlink_to(real_file)

        with self.assertRaises(PermissionError):
            get_connection(symlink_path)

    def test_symlink_on_parent_dir_is_refused(self) -> None:
        """M1 — Un lien symbolique sur le répertoire parent est refusé."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        real_dir = Path(self.temp_dir.name) / "real_dir"
        real_dir.mkdir()
        symlink_dir = Path(self.temp_dir.name) / "symlink_dir"
        symlink_dir.symlink_to(real_dir)
        db_via_symlink = symlink_dir / "vault.db"

        with self.assertRaises(PermissionError):
            get_connection(db_via_symlink)

    def test_symlink_on_grandparent_dir_is_refused(self) -> None:
        """M1 — Un lien symbolique sur un répertoire ancêtre (grand-parent) est refusé."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        real_root = Path(self.temp_dir.name) / "real_root"
        real_root.mkdir()
        symlink_root = Path(self.temp_dir.name) / "symlink_root"
        symlink_root.symlink_to(real_root)
        deep_db_path = symlink_root / "sub1" / "sub2" / "vault.db"

        with self.assertRaises(PermissionError):
            get_connection(deep_db_path)

    def test_db_path_pointing_to_existing_directory_is_refused(self) -> None:
        """Un db_path pointant vers un répertoire existant lève IsADirectoryError."""
        existing_dir = Path(self.temp_dir.name) / "some_dir"
        existing_dir.mkdir()
        with self.assertRaises(IsADirectoryError):
            get_connection(existing_dir)

    def test_preexisting_parent_dir_is_never_modified(self) -> None:
        """Remarque 1 (MEDIUM) — Un répertoire parent pré-existant (0755, CWD, /tmp)
        n'est jamais chmod par init_db / _open_db_file."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        # 1. Parent pré-existant en 0755
        parent_dir = Path(self.temp_dir.name) / "preexisting_parent"
        parent_dir.mkdir(mode=0o755)
        parent_dir.chmod(0o755)
        initial_mode = parent_dir.stat().st_mode & 0o777

        db_path = parent_dir / "vault.db"
        init_db(db_path)
        after_mode = parent_dir.stat().st_mode & 0o777
        self.assertEqual(
            after_mode,
            initial_mode,
            "Le parent pré-existant ne doit jamais voir ses permissions altérées par init_db",
        )

        # 2. Cas du CWD (parent == Path("."))
        current_cwd = Path.cwd()
        cwd_dir = Path(self.temp_dir.name) / "test_cwd"
        cwd_dir.mkdir(mode=0o755)
        cwd_dir.chmod(0o755)
        initial_cwd_mode = cwd_dir.stat().st_mode & 0o777
        try:
            os.chdir(cwd_dir)
            init_db(Path("vault.db"))
            after_cwd_mode = cwd_dir.stat().st_mode & 0o777
            self.assertEqual(
                after_cwd_mode,
                initial_cwd_mode,
                "Le CWD (Path('.')) ne doit jamais être altéré",
            )
        finally:
            os.chdir(current_cwd)

        # 3. Répertoire ancêtre effectivement créé par _open_db_file
        nested_dir = Path(self.temp_dir.name) / "created_parent"
        nested_db = nested_dir / "vault.db"
        self.assertFalse(nested_dir.exists())
        init_db(nested_db)
        self.assertTrue(nested_dir.exists())
        created_mode = nested_dir.stat().st_mode & 0o777
        self.assertEqual(
            created_mode,
            0o700,
            (
                "Les répertoires créés par l'application doivent être 0o700, "
                f"obtenu {oct(created_mode)}"
            ),
        )

    def test_umask_restored_after_exception_in_open_db_file(self) -> None:
        """Remarque 3 — L'umask est restauré même si _open_db_file lève une exception."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        initial_umask = os.umask(0o022)
        os.umask(initial_umask)  # restaure immédiatement
        symlink_target = Path(self.temp_dir.name) / "target.db"
        symlink_target.touch()
        symlink_path = Path(self.temp_dir.name) / "link.db"
        symlink_path.symlink_to(symlink_target)
        with self.assertRaises(PermissionError):
            get_connection(symlink_path)
        restored_umask = os.umask(0o022)
        os.umask(restored_umask)
        self.assertEqual(
            restored_umask,
            initial_umask,
            f"umask non restauré : attendu {oct(initial_umask)}, obtenu {oct(restored_umask)}",
        )

        # Vérifie également la restauration lorsque l'exception survient dans le bloc try
        target_path = Path(self.temp_dir.name) / "fail_in_try.db"
        with patch(
            "heimdall.vault.database._apply_secure_permissions",
            side_effect=PermissionError("Simulated failure"),
        ):
            with self.assertRaises(PermissionError):
                get_connection(target_path)
        restored_umask_try = os.umask(0o022)
        os.umask(restored_umask_try)
        self.assertEqual(
            restored_umask_try,
            initial_umask,
            (
                "umask non restauré après exception interne : "
                f"attendu {oct(initial_umask)}, obtenu {oct(restored_umask_try)}"
            ),
        )

    # -----------------------------------------------------------------------
    # 13. Absence de fichiers sidecar SQLite & permissions journal (M3 corrigé)
    # -----------------------------------------------------------------------

    def test_no_sidecar_files_after_write(self) -> None:
        """M3 — Pas de sidecar SQLite (-wal/-shm/-journal) après écriture (journal_mode=DELETE)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_sidecar")

        db_dir = self.db_path.parent
        sidecar_extensions = ("-wal", "-shm", "-journal")
        for ext in sidecar_extensions:
            sidecar = db_dir / (self.db_path.name + ext)
            self.assertFalse(
                sidecar.exists(),
                f"Fichier sidecar inattendu après écriture : {sidecar.name}",
            )

    def test_transient_journal_permissions_during_transaction(self) -> None:
        """M3 — Le fichier -journal transitoire pendant une transaction possède les droits 0o600."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        init_db(self.db_path)
        conn = get_connection(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE;")
            create_project(conn, "proj_tx_journal")
            journal_path = self.db_path.parent / (self.db_path.name + "-journal")
            self.assertTrue(
                journal_path.exists(),
                "Le fichier -journal doit exister pendant une transaction active non commitée",
            )
            mode = journal_path.stat().st_mode & 0o777
            self.assertEqual(
                mode,
                0o600,
                f"Permissions du fichier -journal permissives : {oct(mode)}, attendu 0o600",
            )
            conn.commit()
            self.assertFalse(
                journal_path.exists(),
                "Le fichier -journal doit être supprimé après commit (journal_mode=DELETE)",
            )
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # 2. Foreign keys
    # -----------------------------------------------------------------------

    def test_foreign_keys_strictly_enforced_by_default(self) -> None:
        """PRAGMA foreign_keys = ON est systématiquement actif sur toute connexion."""
        init_db(self.db_path)
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("PRAGMA foreign_keys;")
            fk_status = cursor.fetchone()[0]
            self.assertEqual(fk_status, 1)

            with self.assertRaises(sqlite3.IntegrityError):
                create_api_key(conn, "key_orphan", "non_existent_project", "hash123")

            with self.assertRaises(sqlite3.IntegrityError):
                create_secret(
                    conn,
                    project_id="non_existent_project",
                    env="dev",
                    name="API_KEY",
                    encrypted_value="enc_blob",
                )
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # 4. Cascade delete
    # -----------------------------------------------------------------------

    def test_cascade_delete_removes_keys_and_secrets(self) -> None:
        """La suppression d'un projet supprime en cascade ses clés API et ses secrets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_cascade")
            create_api_key(conn, "key_casc", "proj_cascade", "hash_casc")
            create_secret(
                conn,
                project_id="proj_cascade",
                env="dev",
                name="PASSWD",
                encrypted_value="enc_pwd",
                fingerprint="fp1",
            )

            self.assertIsNotNone(get_api_key(conn, "key_casc"))
            self.assertIsNotNone(get_secret(conn, "proj_cascade", "dev", "PASSWD"))

            deleted = delete_project(conn, "proj_cascade")
            self.assertTrue(deleted)

            self.assertIsNone(get_api_key(conn, "key_casc"))
            self.assertIsNone(get_secret(conn, "proj_cascade", "dev", "PASSWD"))

    # -----------------------------------------------------------------------
    # 5. Contrainte d'unicité
    # -----------------------------------------------------------------------

    def test_unique_constraint_on_secrets(self) -> None:
        """La contrainte UNIQUE(project_id, env, name) interdit les doublons de secrets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj1")
            create_project(conn, "proj2")

            create_secret(conn, "proj1", "dev", "DB_PASS", "blob_v1", fingerprint="fp1")

            with self.assertRaises(sqlite3.IntegrityError):
                create_secret(conn, "proj1", "dev", "DB_PASS", "blob_v2", fingerprint="fp2")

            sec_prod = create_secret(conn, "proj1", "prod", "DB_PASS", "blob_prod")
            self.assertEqual(sec_prod["env"], "prod")

            sec_other = create_secret(conn, "proj1", "dev", "OTHER_PASS", "blob_other")
            self.assertEqual(sec_other["name"], "OTHER_PASS")

            sec_proj2 = create_secret(conn, "proj2", "dev", "DB_PASS", "blob_p2")
            self.assertEqual(sec_proj2["project_id"], "proj2")

    # -----------------------------------------------------------------------
    # 6 & 14. Validation du statut (CHECK SQL + Literal applicatif)
    # -----------------------------------------------------------------------

    def test_status_check_constraint_on_create(self) -> None:
        """Seuls les statuts contractuels 'vaulte' et 'rote' sont acceptés à la création."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_stat")
            create_secret(conn, "proj_stat", "dev", "SEC_V", "b", status="vaulte")
            create_secret(conn, "proj_stat", "dev", "SEC_R", "b", status="rote")

            # Validation applicative runtime en tête de fonction : lève ValueError
            with self.assertRaises(ValueError):
                create_secret(conn, "proj_stat", "dev", "SEC_BAD", "b", status="invalid_status")  # type: ignore[arg-type]

    def test_status_check_constraint_on_update(self) -> None:
        """14 — update_secret avec un statut invalide lève ValueError applicativement."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_upd")
            create_secret(conn, "proj_upd", "dev", "MY_KEY", "enc_v1")

            with self.assertRaises(ValueError):
                update_secret(
                    conn,
                    project_id="proj_upd",
                    env="dev",
                    name="MY_KEY",
                    encrypted_value="enc_v2",
                    status="invalid_status",  # type: ignore[arg-type]
                )

    def test_status_raw_sql_check_constraint(self) -> None:
        """Le CHECK SQLite DDL rejette les statuts invalides en cas d'insertion SQL directe."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_raw")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO secrets (project_id, env, name, encrypted_value, status, "
                    "fingerprint, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "proj_raw",
                        "dev",
                        "RAW_SEC",
                        "enc",
                        "invalid_status",
                        "fp",
                        "2026-01-01",
                        "2026-01-01",
                    ),
                )

    def test_status_value_error_does_not_reflect_input(self) -> None:
        """Remarque 1 — Le message ValueError ne répercute pas le statut fourni par l'appelant."""
        init_db(self.db_path)
        injection_payload = "x\n[INJECTION]"
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_reflect")
            # create_secret
            with self.assertRaises(ValueError) as ctx_create:
                create_secret(
                    conn,
                    "proj_reflect",
                    "dev",
                    "SEC_LOG_INJ",
                    "enc",
                    status=injection_payload,  # type: ignore[arg-type]
                )
            self.assertNotIn(injection_payload, str(ctx_create.exception))
            self.assertNotIn("\\n", str(ctx_create.exception))

            create_secret(conn, "proj_reflect", "dev", "SEC_OK", "enc")
            # update_secret
            with self.assertRaises(ValueError) as ctx_update:
                update_secret(
                    conn,
                    project_id="proj_reflect",
                    env="dev",
                    name="SEC_OK",
                    encrypted_value="enc_v2",
                    status=injection_payload,  # type: ignore[arg-type]
                )
            self.assertNotIn(injection_payload, str(ctx_update.exception))

    # -----------------------------------------------------------------------
    # 7. SQL Injection (CWE-89)
    # -----------------------------------------------------------------------

    def test_sql_injection_defense_in_depth(self) -> None:
        """Mitigation CWE-89 : requêtes paramétrées insensibles aux injections SQL."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            sql_injections = [
                "proj'; DROP TABLE projects; --",
                "demo' OR '1'='1",
                "admin'--",
                "' UNION SELECT 1, 'evil' --",
                "\x00' OR 1=1 --",
            ]

            for payload in sql_injections:
                with self.subTest(payload=payload):
                    create_project(conn, payload)
                    retrieved = get_project(conn, payload)
                    self.assertIsNotNone(retrieved)
                    assert retrieved is not None
                    self.assertEqual(retrieved["id"], payload)

                    cursor = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'"
                    )
                    self.assertIsNotNone(cursor.fetchone())

                    create_api_key(conn, f"k_{payload}", payload, f"hash_{payload}")
                    key_row = get_api_key_by_hash(conn, f"hash_{payload}")
                    self.assertIsNotNone(key_row)
                    assert key_row is not None
                    self.assertEqual(key_row["id"], f"k_{payload}")

                    create_secret(
                        conn,
                        project_id=payload,
                        env=f"env_{payload}",
                        name="VAR_INJECT",
                        encrypted_value="ciphertext_payload",
                        fingerprint=f"fp_{payload}",
                    )
                    secret = get_secret(conn, payload, f"env_{payload}", "VAR_INJECT")
                    self.assertIsNotNone(secret)
                    assert secret is not None
                    self.assertEqual(secret["encrypted_value"], "ciphertext_payload")

    # -----------------------------------------------------------------------
    # 8. CRUD complet
    # -----------------------------------------------------------------------

    def test_crud_projects(self) -> None:
        """Cycle de vie complet des projets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            self.assertEqual(list_projects(conn), [])

            p1 = create_project(conn, "project-alpha")
            self.assertEqual(p1["id"], "project-alpha")
            self.assertIn("T", p1["created_at"])

            p2 = create_project(conn, "project-beta")
            self.assertEqual(p2["id"], "project-beta")
            self.assertEqual(len(list_projects(conn)), 2)

            fetched = get_project(conn, "project-alpha")
            self.assertIsNotNone(fetched)
            assert fetched is not None
            self.assertEqual(fetched["id"], "project-alpha")

            self.assertIsNone(get_project(conn, "unknown-project"))

            self.assertTrue(delete_project(conn, "project-alpha"))
            self.assertFalse(delete_project(conn, "project-alpha"))
            self.assertIsNone(get_project(conn, "project-alpha"))
            self.assertEqual(len(list_projects(conn)), 1)

    def test_crud_api_keys(self) -> None:
        """Cycle de vie complet des clés API."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_keys")

            k1 = create_api_key(conn, "key_001", "proj_keys", "hash_sha256_001")
            self.assertEqual(k1["id"], "key_001")
            self.assertIsNone(k1["revoked_at"])

            by_id = get_api_key(conn, "key_001")
            self.assertIsNotNone(by_id)
            assert by_id is not None
            self.assertEqual(by_id["key_hash"], "hash_sha256_001")

            by_hash = get_api_key_by_hash(conn, "hash_sha256_001")
            self.assertIsNotNone(by_hash)
            assert by_hash is not None
            self.assertEqual(by_hash["id"], "key_001")

            keys = list_api_keys_for_project(conn, "proj_keys")
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0]["id"], "key_001")

            revoked = revoke_api_key(conn, "key_001")
            self.assertTrue(revoked)
            self.assertFalse(revoke_api_key(conn, "key_001"))

            updated_key = get_api_key(conn, "key_001")
            self.assertIsNotNone(updated_key)
            assert updated_key is not None
            self.assertIsNotNone(updated_key["revoked_at"])

            self.assertTrue(delete_api_key(conn, "key_001"))
            self.assertIsNone(get_api_key(conn, "key_001"))

    def test_crud_secrets(self) -> None:
        """Cycle de vie complet des secrets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_secrets")

            s = create_secret(
                conn,
                project_id="proj_secrets",
                env="dev",
                name="APP_SECRET",
                encrypted_value="cipher_12345",
                fingerprint="hmac_fp",
            )
            self.assertEqual(s["status"], "vaulte")

            full = get_secret(conn, "proj_secrets", "dev", "APP_SECRET")
            self.assertIsNotNone(full)
            assert full is not None
            self.assertEqual(full["encrypted_value"], "cipher_12345")
            self.assertEqual(full["fingerprint"], "hmac_fp")

            meta = get_secret_metadata(conn, "proj_secrets", "dev", "APP_SECRET")
            self.assertIsNotNone(meta)
            assert meta is not None
            self.assertEqual(meta["name"], "APP_SECRET")
            self.assertEqual(meta["status"], "vaulte")
            self.assertNotIn("encrypted_value", meta)

            updated = update_secret(
                conn,
                project_id="proj_secrets",
                env="dev",
                name="APP_SECRET",
                encrypted_value="new_cipher",
                fingerprint="new_fp",
                status="rote",
            )
            self.assertTrue(updated)

            after_update = get_secret(conn, "proj_secrets", "dev", "APP_SECRET")
            self.assertIsNotNone(after_update)
            assert after_update is not None
            self.assertEqual(after_update["encrypted_value"], "new_cipher")
            self.assertEqual(after_update["status"], "rote")

            secrets_dev = list_secrets(conn, "proj_secrets", env="dev")
            self.assertEqual(len(secrets_dev), 1)
            secrets_prod = list_secrets(conn, "proj_secrets", env="prod")
            self.assertEqual(len(secrets_prod), 0)

            self.assertTrue(delete_secret(conn, "proj_secrets", "dev", "APP_SECRET"))
            self.assertIsNone(get_secret(conn, "proj_secrets", "dev", "APP_SECRET"))

    # -----------------------------------------------------------------------
    # 9. Gestion transactionnelle
    # -----------------------------------------------------------------------

    def test_transaction_rollback_on_error(self) -> None:
        """Le gestionnaire db_session effectue un rollback propre en cas d'erreur."""
        init_db(self.db_path)

        with self.assertRaises(RuntimeError):
            with db_session(self.db_path) as conn:
                create_project(conn, "proj_rollback")
                raise RuntimeError("Panne inattendue durant la transaction")

        with db_session(self.db_path) as conn:
            self.assertIsNone(get_project(conn, "proj_rollback"))

    # -----------------------------------------------------------------------
    # 15. .gitignore couvre vault.db et tous ses sidecars (-wal, -shm, etc.)
    # -----------------------------------------------------------------------

    def test_gitignore_covers_vault_db(self) -> None:
        """15 — Le .gitignore exclut vault.db, *.db et les sidecars (-wal/-shm/-journal)."""
        root = Path(__file__).resolve().parents[1]
        gitignore_path = root / ".gitignore"
        self.assertTrue(gitignore_path.exists(), ".gitignore doit exister à la racine du dépôt")
        patterns = [
            line.strip()
            for line in gitignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        # Assertions statiques des motifs obligatoires
        required_patterns = ("vault.db*", "*.db", "*.db-wal", "*.db-shm", "*.db-journal")
        for req in required_patterns:
            self.assertIn(
                req,
                patterns,
                f"Motif obligatoire manquant dans .gitignore : {req}",
            )

        # Test de filtrage fnmatch indépendant de git
        sidecar_files = (
            "vault.db",
            "vault.db-journal",
            "vault.db-wal",
            "vault.db-shm",
            "other.db",
        )
        for filename in sidecar_files:
            matched = any(fnmatch.fnmatch(filename, pat) for pat in patterns)
            self.assertTrue(
                matched,
                f"{filename!r} n'est pas couvert par les motifs du .gitignore (test fnmatch)",
            )

        # Vérification optionnelle avec git check-ignore si git est installé
        git_bin = shutil.which("git")
        if git_bin is not None:
            for filename in sidecar_files:
                result = subprocess.run(  # noqa: S603
                    [git_bin, "check-ignore", "-q", filename],
                    cwd=root,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"{filename!r} n'est pas couvert par .gitignore (git check-ignore)",
                )

    # -----------------------------------------------------------------------
    # 16. Validation VaultSettings.db_path (L4)
    # -----------------------------------------------------------------------

    def test_vault_settings_db_path_rejects_empty(self) -> None:
        """L4 — VaultSettings refuse un db_path vide ou blanc."""
        with self.assertRaises(ValidationError):
            VaultSettings(db_path="")
        with self.assertRaises(ValidationError):
            VaultSettings(db_path="   ")

    def test_vault_settings_db_path_rejects_control_chars(self) -> None:
        """L4 — VaultSettings refuse un db_path contenant des caractères de contrôle."""
        with self.assertRaises(ValidationError):
            VaultSettings(db_path="vault\x00.db")
        with self.assertRaises(ValidationError):
            VaultSettings(db_path="vault\x1f.db")
        with self.assertRaises(ValidationError):
            VaultSettings(db_path="vault\t.db")

    def test_vault_settings_db_path_rejects_directory(self) -> None:
        """VaultSettings refuse un db_path pointant vers un répertoire existant."""
        with self.assertRaises(ValidationError):
            VaultSettings(db_path=self.temp_dir.name)

    def test_vault_settings_db_path_accepts_valid_path(self) -> None:
        """L4 — VaultSettings accepte un chemin valide et normalise les espaces."""
        valid_path = str(Path(self.temp_dir.name) / "valid_vault.db")
        s = VaultSettings(db_path=f"  {valid_path}  ")
        self.assertEqual(s.db_path, valid_path)

    # -----------------------------------------------------------------------
    # resolve_db_path & validate_db_path
    # -----------------------------------------------------------------------

    def test_validate_db_path_direct(self) -> None:
        """validate_db_path valide les entrées valides et refuse les entrées invalides."""
        self.assertEqual(validate_db_path(":memory:"), ":memory:")
        self.assertEqual(validate_db_path("  :memory:  "), ":memory:")
        self.assertEqual(validate_db_path("path/to/vault.db"), "path/to/vault.db")
        with self.assertRaises(ValueError):
            validate_db_path("")
        with self.assertRaises(ValueError):
            validate_db_path("   ")
        with self.assertRaises(ValueError):
            validate_db_path("vault\x00.db")
        with self.assertRaises(ValueError):
            validate_db_path("vault\n.db")
        with self.assertRaises(ValueError):
            validate_db_path("vault\t.db")
        with self.assertRaises(IsADirectoryError):
            validate_db_path(self.temp_dir.name)

    def test_resolve_db_path_rejects_empty_and_whitespace(self) -> None:
        """resolve_db_path avec chaîne vide ou blanche lève ValueError."""
        with self.assertRaises(ValueError):
            resolve_db_path("")
        with self.assertRaises(ValueError):
            resolve_db_path("   ")

    def test_resolve_db_path_rejects_control_characters(self) -> None:
        """resolve_db_path refuse les caractères de contrôle dans le chemin."""
        with self.assertRaises(ValueError):
            resolve_db_path("vault\x00.db")
        with self.assertRaises(ValueError):
            resolve_db_path("vault\n.db")
        with self.assertRaises(ValueError):
            resolve_db_path("vault\x1f.db")
        with self.assertRaises(ValueError):
            resolve_db_path("vault\t.db")

    def test_resolve_db_path_environment_variable(self) -> None:
        """resolve_db_path prend en compte HEIMDALL_VAULT_DB_PATH."""
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path(), Path("/custom/path/vault.db"))

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ":memory:"}):
            self.assertEqual(resolve_db_path(), ":memory:")

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "  :memory:  "}):
            self.assertEqual(resolve_db_path(), ":memory:")

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path("/override/path.db"), Path("/override/path.db"))

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_db_path(), DEFAULT_DB_PATH)

    def test_resolve_db_path_env_rejects_empty_and_control_chars(self) -> None:
        """resolve_db_path valide la variable HEIMDALL_VAULT_DB_PATH (vide, espaces, ctrl)."""
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ""}):
            with self.assertRaises(ValueError):
                resolve_db_path()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "   "}):
            with self.assertRaises(ValueError):
                resolve_db_path()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "vault\n.db"}):
            with self.assertRaises(ValueError):
                resolve_db_path()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "vault\x1f.db"}):
            with self.assertRaises(ValueError):
                resolve_db_path()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "vault\t.db"}):
            with self.assertRaises(ValueError):
                resolve_db_path()
        with patch.object(os.environ, "get", return_value="vault\x00.db"):
            with self.assertRaises(ValueError):
                resolve_db_path()

    def test_relative_db_path_resolved_against_cwd(self) -> None:
        """Pinnage CWD (remarque 1) : un chemin relatif résolu dépend du CWD courant."""
        cwd1 = Path(self.temp_dir.name) / "cwd1"
        cwd2 = Path(self.temp_dir.name) / "cwd2"
        cwd1.mkdir()
        cwd2.mkdir()
        rel_path = "relative_vault.db"
        resolved = resolve_db_path(rel_path)
        self.assertIsInstance(resolved, Path)
        assert isinstance(resolved, Path)
        self.assertFalse(resolved.is_absolute())
        # La résolution absolue dans deux CWD distincts donne deux chemins différents
        abs_cwd1 = (cwd1 / resolved).resolve()
        abs_cwd2 = (cwd2 / resolved).resolve()
        self.assertNotEqual(abs_cwd1, abs_cwd2)
        self.assertEqual(abs_cwd1.name, abs_cwd2.name)

        # Vérification opérationnelle : initialisation relative dans deux CWD distincts
        current_cwd = Path.cwd()
        try:
            os.chdir(cwd1)
            init_db(rel_path)
            self.assertTrue((cwd1 / rel_path).exists())
            self.assertFalse((cwd2 / rel_path).exists())

            os.chdir(cwd2)
            init_db(rel_path)
            self.assertTrue((cwd2 / rel_path).exists())
        finally:
            os.chdir(current_cwd)

    def test_windows_warning_on_apply_secure_permissions(self) -> None:
        """_apply_secure_permissions émet un RuntimeWarning sous Windows (remarque 4)."""
        with patch("os.name", "nt"):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                _apply_secure_permissions(self.db_path)
                self.assertEqual(len(recorded), 1)
                self.assertTrue(issubclass(recorded[0].category, RuntimeWarning))
                self.assertIn("POSIX", str(recorded[0].message))

    def test_exception_messages_do_not_leak_absolute_path(self) -> None:
        """Sanitization : les exceptions ne contiennent aucun chemin FS absolu (remarque 2)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        real_file = Path(self.temp_dir.name) / "real.db"
        real_file.touch()
        symlink = Path(self.temp_dir.name) / "sym.db"
        symlink.symlink_to(real_file)

        # 1. Symlink
        with self.assertRaises(PermissionError) as ctx_sym:
            get_connection(symlink)
        self.assertNotIn(str(symlink), str(ctx_sym.exception))
        self.assertNotIn(str(real_file), str(ctx_sym.exception))

        # 2. Répertoire existant
        existing_dir = Path(self.temp_dir.name) / "dir_test"
        existing_dir.mkdir()
        with self.assertRaises(IsADirectoryError) as ctx_dir:
            get_connection(existing_dir)
        self.assertNotIn(str(existing_dir), str(ctx_dir.exception))

        # 3. Chmod failure
        with patch.object(Path, "chmod", side_effect=OSError("Read-only")):
            with self.assertRaises(PermissionError) as ctx_chmod:
                _apply_secure_permissions(real_file)
            self.assertNotIn(str(real_file), str(ctx_chmod.exception))

        # 4. Mode mismatch
        fake_stat = type("FakeStat", (), {"st_mode": stat_module.S_IFREG | 0o644, "st_size": 0})()
        with patch.object(Path, "chmod"):
            with patch.object(Path, "stat", return_value=fake_stat):
                with self.assertRaises(PermissionError) as ctx_mode:
                    _apply_secure_permissions(real_file)
                self.assertNotIn(str(real_file), str(ctx_mode.exception))

    def test_resolve_db_path_memory_as_path_object(self) -> None:
        """resolve_db_path avec Path(':memory:') retourne la chaîne ':memory:'."""
        self.assertEqual(resolve_db_path(Path(":memory:")), ":memory:")

    # -----------------------------------------------------------------------
    # CLI init_db (--verbose vs sans verbose)
    # -----------------------------------------------------------------------

    def test_init_db_cli_error_output_sanitized_unless_verbose(self) -> None:
        """Le script CLI init_db n'affiche pas le chemin d'erreur par défaut, sauf avec -v."""
        # On cible un symlink interdit pour déclencher une erreur
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        real_f = Path(self.temp_dir.name) / "cli_real.db"
        real_f.touch()
        sym_f = Path(self.temp_dir.name) / "cli_sym.db"
        sym_f.symlink_to(real_f)

        # Sans -v : message générique uniquement
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = init_db_main(["--db-path", str(sym_f)])
        self.assertEqual(code, 1)
        output = stderr_buf.getvalue()
        self.assertIn("Erreur : échec de l'initialisation", output)
        self.assertNotIn("Détail :", output)
        self.assertNotIn(str(sym_f), output)

        # Avec -v : détail technique présent
        stderr_buf_v = io.StringIO()
        with redirect_stderr(stderr_buf_v):
            code_v = init_db_main(["--db-path", str(sym_f), "-v"])
        self.assertEqual(code_v, 1)
        output_v = stderr_buf_v.getvalue()
        self.assertIn("Erreur : échec de l'initialisation", output_v)
        self.assertIn("Détail :", output_v)

    # -----------------------------------------------------------------------
    # SecretStatus type alias
    # -----------------------------------------------------------------------

    def test_secret_status_literal_type_is_exported(self) -> None:
        """SecretStatus est exporté et correspond à Literal['vaulte', 'rote']."""
        self.assertIs(SecretStatus, SecretStatus)
        # Vérification que les valeurs attendues sont dans le __args__ du Literal
        args = typing.get_args(SecretStatus)
        self.assertIn("vaulte", args)
        self.assertIn("rote", args)


if __name__ == "__main__":
    unittest.main()
