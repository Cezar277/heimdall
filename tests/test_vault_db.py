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
11. Le refus des chemins symboliques (protection TOCTOU) et la fermeture de la
    fenêtre d'ouverture : descripteur épinglé `/dev/fd` sous Linux, repli POSIX.
12. Le comportement fail-closed si `chmod`/`fchmod` échoue (mock OSError).
13. L'absence de fichiers sidecar SQLite (`-wal`, `-shm`, `-journal`) après écriture.
14. Le rejet applicatif du statut invalide sur `update_secret`.
15. La couverture du `.gitignore` sur `vault.db` (non-régression commit accidentel).
16. La validation de `VaultSettings.db_path` (vide, caractères de contrôle).
17. Le défaut hors dépôt (`$XDG_DATA_HOME` ou `~/.local/share/heimdall/vault.db`),
    assaini (contrôles/`..`/relatif refusés → repli) et validé.
18. Le refus fail-closed de ':memory:' via l'environnement (argument explicite seul),
    épinglé de bout en bout (sous-processus CLI, `create_app`).
19. Le durcissement des répertoires créés par descripteur épinglé
    (`O_NOFOLLOW|O_DIRECTORY` + `fchmod`/`fstat`, course `mkdir` → `chmod` fermée).
20. Le refus du chemin relatif à la CLI (argument et environnement, exit 2).
21. Le refus central du chemin relatif à l'ouverture (`_open_db_file`), quel que
    soit l'appelant direct (revue v6) ; `XDG_DATA_HOME=/` replié (jamais de base
    sous la racine) ; bornes de longueur : responsabilité de la couche API (#63+).
22. L'assainissement `--verbose` des chemins absolus cités avec espaces (basename
    conservé, aucun répertoire parent en sortie — revue v6), y compris le casseur
    quote + espace (revue v7 : déjà assaini via le choix de guillemet de CPython).
23. Le repli XDG pour la racine sous toutes ses formes (`/`, `//`, `///`, `/.`,
    `/./` — revue v7 : `pathlib`/`normpath` préservent `//`).
"""

import errno
import fnmatch
import io
import os
import shutil
import socket
import sqlite3
import stat as stat_module
import subprocess
import sys
import tempfile
import typing
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

import heimdall.vault.database as vault_database
from heimdall.vault.app import VaultSettings
from heimdall.vault.database import (
    DEFAULT_DB_PATH,
    SCHEMA_SQL,
    SecretStatus,
    _apply_secure_permissions,
    _harden_created_parents,
    _stat_no_follow,
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
    list_secret_page,
    list_secrets,
    resolve_db_path,
    revoke_api_key,
    update_secret,
    validate_db_path,
)
from heimdall.vault.init_db import (
    _ABSOLUTE_PATH_TOKEN_RE,
    _QUOTED_ABSOLUTE_PATH_RE,
    _sanitize_error_message,
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
            self.assertIn("uq_api_keys_key_hash", indexes)
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

        # 2. Cas du CWD (parent == Path(".")) : chemin absolu pointant dans le CWD —
        # le répertoire courant lui-même ne doit jamais être altéré.
        current_cwd = Path.cwd()
        cwd_dir = Path(self.temp_dir.name) / "test_cwd"
        cwd_dir.mkdir(mode=0o755)
        cwd_dir.chmod(0o755)
        initial_cwd_mode = cwd_dir.stat().st_mode & 0o777
        try:
            os.chdir(cwd_dir)
            init_db(cwd_dir / "vault.db")
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
            "heimdall.vault.database._verify_opened_connection",
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
                create_secret(
                    conn,
                    "proj_stat",
                    "dev",
                    "SEC_BAD",
                    "b",
                    status="invalid_status",  # type: ignore[arg-type]
                )

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
            with self.assertLogs("heimdall.vault.database", level="DEBUG") as log_ctx:
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
            self.assertFalse(any(injection_payload in msg for msg in log_ctx.output))

            create_secret(conn, "proj_reflect", "dev", "SEC_OK", "enc")
            # update_secret
            with self.assertLogs("heimdall.vault.database", level="DEBUG") as log_ctx_up:
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
            self.assertFalse(any(injection_payload in msg for msg in log_ctx_up.output))

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

    def test_list_secret_page_rejects_out_of_bounds_pagination(self) -> None:
        """Défense en profondeur : la couche SQL refuse LIMIT/OFFSET hors bornes."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_page")
            for limit, offset in ((0, 0), (-1, 0), (102, 0), (1, -1), (1, 1_000_001)):
                with self.subTest(limit=limit, offset=offset):
                    with self.assertRaisesRegex(ValueError, "pagination hors bornes"):
                        list_secret_page(conn, "proj_page", limit, offset)
            self.assertEqual(list_secret_page(conn, "proj_page", 101, 0), [])
            self.assertEqual(list_secret_page(conn, "proj_page", 1, 1_000_000), [])

    def test_oversized_identifiers_pin_absence_of_db_level_length_validation(self) -> None:
        """Comportement pinné : la couche DB ne valide pas la longueur (ressort de l'API future).

        Des identifiants de plusieurs Mo sont stockés et relus sans troncature.
        Le bornage/longueur relèvera des routes API (#63+) et non du modèle #62.
        """
        init_db(self.db_path)
        big_project = "p" * (2 * 1024 * 1024)
        big_env = "e" * (1024 * 1024)
        big_name = "n" * (1024 * 1024)
        with db_session(self.db_path) as conn:
            create_project(conn, big_project)
            create_secret(
                conn,
                project_id=big_project,
                env=big_env,
                name=big_name,
                encrypted_value="cipher_12345",
                fingerprint="fp",
            )
        with db_session(self.db_path) as conn:
            secret = get_secret(conn, big_project, big_env, big_name)
            self.assertIsNotNone(secret)
            assert secret is not None
            self.assertEqual(secret["name"], big_name)
            self.assertEqual(secret["env"], big_env)
            self.assertEqual(secret["encrypted_value"], "cipher_12345")

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

        # Vérification reproductible via git check-ignore dans un dépôt temporaire
        # (aucune dépendance au dépôt réel ni à la config git globale de la machine).
        git_bin = shutil.which("git")
        if git_bin is None:
            self.skipTest(
                "git introuvable : vérification check-ignore non exécutée "
                "(l'assertion fnmatch ci-dessus reste bloquante)"
            )
        git_repo = Path(self.temp_dir.name) / "gitignore_repo"
        git_repo.mkdir()
        (git_repo / ".gitignore").write_text(
            gitignore_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        subprocess.run(  # noqa: S603
            [git_bin, "-c", "init.defaultBranch=main", "init", "--quiet", str(git_repo)],
            capture_output=True,
            check=True,
        )
        for filename in sidecar_files:
            result = subprocess.run(  # noqa: S603
                [
                    git_bin,
                    "-c",
                    "core.excludesFile=/dev/null",
                    "check-ignore",
                    "--quiet",
                    filename,
                ],
                cwd=git_repo,
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
        """resolve_db_path prend en compte HEIMDALL_VAULT_DB_PATH (hors ':memory:')."""
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path(), Path("/custom/path/vault.db"))

        # ':memory:' via l'environnement : refus fail-closed (remarque 2 de la revue v4)
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ":memory:"}):
            with self.assertRaises(ValueError):
                resolve_db_path()

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "  :memory:  "}):
            with self.assertRaises(ValueError):
                resolve_db_path()

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path("/override/path.db"), Path("/override/path.db"))

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_db_path(), DEFAULT_DB_PATH)

    def test_env_memory_mode_refused_fail_closed(self) -> None:
        """Remarque 2 (v4) — ':memory:' refusé via env, autorisé en argument explicite.

        Une base éphémère silencieuse diffère les échecs (`no such table`) et perd
        toute écriture : fail-closed hors argument explicite (tests unitaires).
        """
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ":memory:"}):
            with self.assertRaises(ValueError) as ctx:
                get_connection()
        self.assertIn(":memory:", str(ctx.exception))
        self.assertIn("argument explicite", str(ctx.exception))
        # L'argument explicite reste le canal de test supporté
        conn = get_connection(":memory:")
        try:
            cursor = conn.execute("SELECT 1;")
            self.assertEqual(cursor.fetchone()[0], 1)
        finally:
            conn.close()

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

    def test_default_db_path_is_absolute_and_outside_repo(self) -> None:
        """Remarque 3 (LOW) — le défaut est absolu et hors dépôt (plus de CWD-relatif).

        Deux répertoires de travail convergent désormais vers la même base
        (~/.local/share/heimdall/vault.db ou XDG_DATA_HOME), plus de cloisonnement
        silencieux.
        """
        default = vault_database.default_db_path()
        self.assertTrue(default.is_absolute(), f"défaut non absolu : {default}")
        self.assertEqual(default.name, "vault.db")
        self.assertEqual(default.parent.name, "heimdall")
        self.assertEqual(DEFAULT_DB_PATH, default)
        repo_root = Path(__file__).resolve().parent.parent
        self.assertFalse(
            default.is_relative_to(repo_root),
            f"le défaut ne doit pas être dans le dépôt : {default}",
        )

    def test_default_db_path_respects_xdg_data_home(self) -> None:
        """XDG — absolu respecté ; `..`, relatif, contrôles et vide ignorés (confinement)."""
        tmp_root = Path(tempfile.gettempdir())
        with patch.dict(os.environ, {"XDG_DATA_HOME": "/custom/xdg-data"}):
            self.assertEqual(
                vault_database.default_db_path(),
                Path("/custom/xdg-data/heimdall/vault.db"),
            )
        expected_home_default = Path.home() / ".local" / "share" / "heimdall" / "vault.db"
        # `..` → repli complet : le défaut reste confiné sous la base annoncée et
        # n'écrit jamais hors du XDG_DATA_HOME déclaré (`/tmp/a/../../etc`, remarque 1 v5)
        for traversal in (f"{tmp_root}/dir/../xdg-data", f"{tmp_root}/a/../../etc"):
            with patch.dict(os.environ, {"XDG_DATA_HOME": traversal}):
                self.assertEqual(
                    vault_database.default_db_path(),
                    expected_home_default,
                    f"XDG_DATA_HOME={traversal!r} avec '..' doit être refusé (confinement)",
                )
        # Relatif, racine sous toutes ses formes, blanc, vide ET caractères de
        # contrôle → repli ~/.local/share (invariant 8 : pas d'injection de ligne
        # de log par basename — remarque 1 v4 ; `//`/`///`/`/.` refusés comme `/`
        # car `pathlib`/`normpath` préservent `//` — revue v7)
        bad_newline = f"{tmp_root}/bad\nname"
        bad_control = f"{tmp_root}/bad\x1fname"
        ignored_values = (
            "relative/xdg",
            "/",
            "///",
            "//",
            "/.",
            "/./",
            "//.",  # parts == ('//',) : fermé par `_is_filesystem_root`
            "/..",  # parts == ('/', '..') : fermé par le garde `..`, pas la racine
            "//..",  # parts == ('//', '..') : fermé par le garde `..`, pas la racine
            "   ",
            "",
            bad_newline,
            bad_control,
        )
        for ignored in ignored_values:
            with patch.dict(os.environ, {"XDG_DATA_HOME": ignored}):
                self.assertEqual(
                    vault_database.default_db_path(),
                    expected_home_default,
                    f"XDG_DATA_HOME={ignored!r} doit être ignoré (non absolu, vide ou contrôle)",
                )

    def test_relative_db_path_refused_at_open_central(self) -> None:
        """Remarque 1 (LOW, revue v6) — refus central du relatif dans `_open_db_file`.

        `resolve_db_path()` reste neutre (renvoie le relatif tel quel), mais
        `get_connection()` / `init_db()` / `db_session()` refusent tout fichier
        relatif quel que soit l'appelant : le CWD ne décide plus jamais quelle
        base est ouverte (plus de cloisonnement silencieux entre processus).
        """
        rel_path = "relative_vault.db"
        resolved = resolve_db_path(rel_path)
        self.assertIsInstance(resolved, Path)
        assert isinstance(resolved, Path)
        self.assertFalse(resolved.is_absolute())

        for opener in (get_connection, init_db):
            with self.subTest(opener=opener.__name__):
                with self.assertRaises(ValueError) as ctx:
                    opener(rel_path)
                self.assertIn("absolu", str(ctx.exception))
                self.assertNotIn(rel_path, str(ctx.exception))
        with self.assertRaises(ValueError):
            with db_session(rel_path):
                pass
        self.assertFalse(Path(rel_path).exists())

    def test_windows_fail_closed_on_apply_secure_permissions(self) -> None:
        """Windows (nt) — les helpers de permissions lèvent RuntimeError fail-closed."""
        with patch("os.name", "nt"):
            with self.assertRaises(RuntimeError) as ctx:
                _apply_secure_permissions(self.db_path)
            self.assertIn("POSIX requis", str(ctx.exception))

        # Vérifie que _harden_created_parents refuse également les répertoires sous Windows
        with patch("os.name", "nt"):
            with self.assertRaises(RuntimeError) as ctx_parents:
                _harden_created_parents([self.db_path.parent])
            self.assertIn("POSIX requis", str(ctx_parents.exception))

    def test_windows_get_connection_fails_closed_with_runtime_error(self) -> None:
        """Windows (nt) — get_connection refuse fail-closed, sans poursuite.

        Patcher `os.name` globalement casserait pathlib (dispatch dynamique
        `WindowsPath`) : on substitue l'objet `os` vu par la seule couche
        `database`, qui délègue tout le reste au `os` réel.
        """
        real_os = vault_database.os

        class NtOsProxy:
            name = "nt"
            path = real_os.path

            def __getattr__(self, item: str) -> typing.Any:
                return getattr(real_os, item)

        with patch.object(vault_database, "os", NtOsProxy()):
            with self.assertRaises(RuntimeError) as ctx:
                get_connection(self.db_path)
        self.assertIn("POSIX requis", str(ctx.exception))

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

    def test_stat_no_follow_failure_raises_generic_permission_error(self) -> None:
        """Anti-fuite — un stat refusé lève PermissionError générique sans chemin FS."""
        secret_path = Path(self.temp_dir.name) / "inaccessible" / "vault.db"
        with patch.object(os, "stat", side_effect=OSError("boom " + str(secret_path))):
            with self.assertRaises(PermissionError) as ctx:
                _stat_no_follow(secret_path)
        self.assertEqual(
            str(ctx.exception),
            "Chemin de base de données refusé : accès impossible",
        )
        self.assertNotIn(str(secret_path), str(ctx.exception))

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

        # Avec -v : détail technique présent mais assaini sans chemin absolu
        stderr_buf_v = io.StringIO()
        with redirect_stderr(stderr_buf_v):
            code_v = init_db_main(["--db-path", str(sym_f), "-v"])
        self.assertEqual(code_v, 1)
        output_v = stderr_buf_v.getvalue()
        self.assertIn("Erreur : échec de l'initialisation", output_v)
        self.assertIn("Détail [PermissionError] :", output_v)
        self.assertNotIn(str(sym_f), output_v)

        # Avec HEIMDALL_VAULT_DB_PATH et -v : détail présent mais sans chemin absolu
        stderr_buf_env = io.StringIO()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": str(sym_f)}):
            with redirect_stderr(stderr_buf_env):
                code_env = init_db_main(["-v"])
        self.assertEqual(code_env, 1)
        output_env = stderr_buf_env.getvalue()
        self.assertIn("Erreur : échec de l'initialisation", output_env)
        self.assertIn("Détail [PermissionError] :", output_env)
        self.assertNotIn(str(sym_f), output_env)

    def test_init_db_cli_verbose_sanitizes_default_db_path(self) -> None:
        """Remarque 1 (LOW) — `-v` avec le défaut `vault.db` n'expose aucun chemin absolu.

        Couvre le trou de la remarque : `msg.replace()` ne couvrait que l'argument
        et la variable d'environnement, pas le chemin par défaut résolu (CWD).
        """
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        default_path = DEFAULT_DB_PATH
        error = sqlite3.OperationalError(f"unable to open database file: {default_path} (code 14)")
        with patch.dict(os.environ, {}, clear=True):
            with patch("heimdall.vault.init_db.init_db", side_effect=error):
                stderr_buf = io.StringIO()
                with redirect_stderr(stderr_buf):
                    code = init_db_main(["-v"])
        self.assertEqual(code, 1)
        output = stderr_buf.getvalue()
        self.assertIn("Erreur : échec de l'initialisation", output)
        self.assertIn("Détail [OperationalError] :", output)
        self.assertNotIn(str(default_path), output)
        self.assertNotIn(str(default_path.parent), output)
        # Le basename reste visible pour le diagnostic opérateur
        self.assertIn("vault.db", output)

    def test_sanitize_error_message_scrubs_paths(self) -> None:
        """Assainissement verbose : basenames seuls, chemins à espaces et multilignes gérés."""
        # 1. Chemin candidat avec espaces remplacé intégralement (pas de résidu)
        candidate = "/srv/data/my vault dir/vault.db"
        exc = sqlite3.OperationalError(f"unable to open database file: {candidate}")
        self.assertEqual(
            _sanitize_error_message(exc, [candidate]),
            "unable to open database file: vault.db",
        )

        # 2. Chemin absolu non déclaré en candidat : réduit au basename par la regex
        exc_unknown = OSError("write failed at /var/lib/other/file.db (disk full)")
        self.assertEqual(
            _sanitize_error_message(exc_unknown, [None, "", Path("vault.db")]),
            "write failed at file.db (disk full)",
        )

        # 3. Quoted path + multi-lignes : première ligne seule, guillemets préservés
        exc_multi = PermissionError("refusé '/a/b/c.db'\nseconde ligne /x/y/z.db")
        self.assertEqual(_sanitize_error_message(exc_multi, []), "refusé 'c.db'")

        # 4. Message vide : chaîne vide, jamais None
        self.assertEqual(_sanitize_error_message(Exception(), []), "")

    def test_init_db_cli_rejects_memory_mode(self) -> None:
        """CLI — init_db refuse le mode ':memory:' et retourne un code de sortie non nul (2)."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = init_db_main(["--db-path", ":memory:"])
        self.assertEqual(code, 2)
        self.assertIn("Erreur : le mode ':memory:' est réservé aux tests", stderr_buf.getvalue())

        stderr_buf_env = io.StringIO()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ":memory:"}):
            with redirect_stderr(stderr_buf_env):
                code_env = init_db_main([])
        self.assertEqual(code_env, 2)
        self.assertIn(
            "Erreur : le mode ':memory:' est réservé aux tests",
            stderr_buf_env.getvalue(),
        )

    def test_init_db_cli_refuses_relative_path_exit_2(self) -> None:
        """Revue v5 (double source) — CLI : chemin relatif refusé (exit 2), rien créé.

        Argument `--db-path` ET variable d'environnement : un chemin relatif dépend du
        répertoire courant et ferait diverger la CLI du serveur sans erreur.
        """
        target = "relative_cli_refused.db"
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = init_db_main(["--db-path", target])
        self.assertEqual(code, 2)
        self.assertIn("chemin absolu requis", stderr_buf.getvalue())
        self.assertNotIn(target, stderr_buf.getvalue())
        self.assertFalse(Path(target).exists())

        stderr_env = io.StringIO()
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": target}):
            with redirect_stderr(stderr_env):
                code_env = init_db_main([])
        self.assertEqual(code_env, 2)
        self.assertIn("chemin absolu requis", stderr_env.getvalue())
        self.assertFalse(Path(target).exists())

    def test_is_filesystem_root_total_on_empty_and_dot(self) -> None:
        """Remarque 2 (v8) — `_is_filesystem_root` totale : jamais « racine » sans composant.

        `Path("").parts == ()` et `Path(".").parts == ()` : `all()` y serait
        vacuement vrai. Le `bool(parts)` rend la classification exacte, sûre en
        réutilisation future sans garde d'appel (l'appelant actuel court-circuite
        déjà, sens fail-closed).
        """
        self.assertFalse(vault_database._is_filesystem_root(""))
        self.assertFalse(vault_database._is_filesystem_root("."))
        for root in ("/", "//", "///", "/.", "/./", "//."):
            with self.subTest(root=root):
                self.assertTrue(vault_database._is_filesystem_root(root))
        tmp_root = Path(tempfile.gettempdir())
        for real in (str(tmp_root), str(tmp_root / "x"), "relative", "relative/x"):
            with self.subTest(real=real):
                self.assertFalse(vault_database._is_filesystem_root(real))

    def test_sanitize_quoted_absolute_path_with_spaces(self) -> None:
        """Remarque 3 (v6) — unitaire : absolu cité avec espaces réduit à son basename.

        Format standard des `OSError` (`[Errno 13] ...: '/tmp/my dir/vault.db'`) :
        la regex token s'arrête à l'espace, la passe des chemins cités traite le
        contenu entier. Basename conservé (politique basename, invariant 8), aucun
        répertoire parent en sortie.
        """
        spaced_target = f"{tempfile.gettempdir()}/my dir/vault.db"
        exc = OSError(13, "Permission denied", spaced_target)
        detail = _sanitize_error_message(exc, [])
        self.assertNotIn(str(Path(spaced_target).parent), detail)
        self.assertNotIn(tempfile.gettempdir(), detail)
        self.assertIn("'vault.db'", detail)

    def test_sanitize_crusher_quote_and_space_in_filename(self) -> None:
        """À vérifier (revue v7, non bloquant) — casseur : quote + espace dans le nom.

        `/tmp/a'b dir/vault.db` est légal POSIX. CPython cite le nom avec l'autre
        type de guillemet (`"..."` si `'` dedans et inversement), donc une passe
        citée suffit et aucun fragment absolu ne subsiste : ni chemin complet, ni
        résidu regex, basename présent. Classes niées uniquement : pas de ReDoS
        (invariant 14).
        """
        crushers = (
            f"{tempfile.gettempdir()}/a'b dir/vault.db",
            f'{tempfile.gettempdir()}/a"b dir/vault.db',
        )
        for crusher in crushers:
            with self.subTest(crusher=crusher):
                exc = OSError(13, "Permission denied", crusher)
                detail = _sanitize_error_message(exc, [])
                self.assertNotIn(crusher, detail)
                self.assertNotIn(tempfile.gettempdir(), detail)
                self.assertIsNone(_QUOTED_ABSOLUTE_PATH_RE.search(detail))
                self.assertIsNone(_ABSOLUTE_PATH_TOKEN_RE.search(detail))
                self.assertIn("vault.db", detail)

    def test_init_db_verbose_with_spaces_hides_absolute_path(self) -> None:
        """Remarque 3 (v6/v8) — bout en bout : `-v` avec un chemin à espaces en échec.

        L'échec `EACCES` est injecté par mock de `Path.mkdir` (revue v8) : un
        répertoire en `0o555` réel ne provoque rien sous root (conteneur CI
        pentest — `mkdir` y réussit), ce qui rendait le test inopérant et créait
        la base au lieu de tester le sanitizer. Le message `OSError` porte le
        parent avec espaces (non couvert par les candidats connus, qui portent
        le chemin complet avec `vault.db`). Le détail ne doit contenir aucun
        chemin absolu — ni token nu, ni contenu cité — et aucun secret ; le
        basename reste visible pour garder un message utile.
        """
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        base = Path(self.temp_dir.name)
        spaced_parent = base / "ro base" / "my dir"
        target = spaced_parent / "vault.db"
        mkdir_error = OSError(errno.EACCES, "Permission denied", str(spaced_parent))
        stderr_buf = io.StringIO()
        with patch.object(Path, "mkdir", side_effect=mkdir_error):
            with redirect_stderr(stderr_buf):
                code = init_db_main(["--db-path", str(target), "-v"])
        self.assertEqual(code, 1)
        detail = stderr_buf.getvalue()
        self.assertNotIn(str(target), detail)
        self.assertNotIn(str(spaced_parent), detail)
        self.assertNotIn(str(base), detail)
        self.assertIsNone(_QUOTED_ABSOLUTE_PATH_RE.search(detail))
        self.assertIsNone(_ABSOLUTE_PATH_TOKEN_RE.search(detail))
        self.assertIn("my dir", detail)

    def test_symlink_defense_with_dotdot_normalization(self) -> None:
        """TOCTOU — Normalisation lexicale et rejet de symlink sur chemin avec '..'."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        base = Path(self.temp_dir.name)
        real_dir = base / "real_dir"
        real_dir.mkdir()
        symlink_dir = base / "sym_dir"
        symlink_dir.symlink_to(real_dir)

        # 1. Chemin contenant '..' traversant un lien symbolique
        traversed_symlink = symlink_dir / ".." / "real_dir" / "vault.db"
        with self.assertRaises(PermissionError):
            get_connection(traversed_symlink)

        # 2. Chemin contenant '..' valide sans aucun lien symbolique
        valid_dotdot = real_dir / ".." / "real_dir" / "valid_vault.db"
        conn = get_connection(valid_dotdot)
        try:
            cursor = conn.execute("SELECT 1;")
            self.assertEqual(cursor.fetchone()[0], 1)
        finally:
            conn.close()

    def test_dotdot_traversing_symlink_ancestor_is_refused(self) -> None:
        """Tests manquants revue — `sub/../cible` où `sub` est un symlink : refus fail-closed.

        La normalisation lexicale seule (`sub/..` → parent) ne suffit pas : c'est la
        vérification `lstat` de tous les ancêtres bruts (dont `sub`, lié) qui refuse,
        sans jamais créer de fichier ni modifier un répertoire.
        """
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        base = Path(self.temp_dir.name)
        real_dir = base / "real_sub"
        real_dir.mkdir()
        link_dir = base / "sub"
        link_dir.symlink_to(real_dir)

        combined = link_dir / ".." / "cible_vault.db"
        with self.assertRaises(PermissionError) as ctx:
            get_connection(combined)
        self.assertIn("lien symbolique interdit", str(ctx.exception).lower())
        self.assertNotIn(str(combined), str(ctx.exception))
        self.assertFalse((base / "cible_vault.db").exists())
        self.assertFalse((real_dir / "cible_vault.db").exists())

    def test_dangling_symlink_refused_without_exists_follow(self) -> None:
        """Remarque 2 (LOW) — un symlink pendant est refusé : plus de `path.exists()` suivi."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        dangling = Path(self.temp_dir.name) / "dangling.db"
        dangling.symlink_to(Path(self.temp_dir.name) / "absent.db")
        with self.assertRaises(PermissionError) as ctx:
            get_connection(dangling)
        self.assertIn("lien symbolique interdit", str(ctx.exception).lower())
        # `_check_regular_file` seul (lstat) ne traite jamais un symlink pendant comme absent
        with self.assertRaises(PermissionError) as ctx_regular:
            vault_database._check_regular_file(dangling)
        self.assertIn("fichier non régulier interdit", str(ctx_regular.exception).lower())

    def test_non_regular_file_rejected_without_blocking(self) -> None:
        """Remarque 1 (LOW) — get_connection refuse FIFO, socket et device POSIX sans bloquer."""
        if os.name == "nt":
            self.skipTest("Test POSIX avec support FIFO/socket/device requis")

        # 1. FIFO (named pipe)
        if hasattr(os, "mkfifo"):
            fifo_path = Path(self.temp_dir.name) / "test_fifo.db"
            os.mkfifo(fifo_path)
            with self.assertRaises(PermissionError) as ctx_fifo:
                get_connection(fifo_path)
            self.assertIn("fichier non régulier", str(ctx_fifo.exception).lower())
            self.assertNotIn(str(fifo_path), str(ctx_fifo.exception))

        # 2. Socket de domaine Unix (AF_UNIX)
        if hasattr(socket, "AF_UNIX"):
            sock_path = Path(self.temp_dir.name) / "test_sock.db"
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(sock_path))
                with self.assertRaises(PermissionError) as ctx_sock:
                    get_connection(sock_path)
                self.assertIn("fichier non régulier", str(ctx_sock.exception).lower())
                self.assertNotIn(str(sock_path), str(ctx_sock.exception))
            finally:
                sock.close()

        # 3. Device POSIX (character device, ex: /dev/null ou /dev/zero)
        for dev in ("/dev/null", "/dev/zero"):
            dev_path = Path(dev)
            if dev_path.exists():
                with self.assertRaises(PermissionError) as ctx_dev:
                    get_connection(dev_path)
                self.assertIn("fichier non régulier", str(ctx_dev.exception).lower())
                self.assertNotIn(str(dev_path), str(ctx_dev.exception))

    def test_hardlink_preplanted_rejected(self) -> None:
        """Remarque 4 — get_connection refuse un hardlink (st_nlink != 1) sans altérer la cible."""
        if os.name == "nt" or not hasattr(os, "link"):
            self.skipTest("Test POSIX avec support hardlink requis")
        victim_file = Path(self.temp_dir.name) / "victim.txt"
        victim_file.write_text("victim secret content", encoding="utf-8")
        hardlink_db = Path(self.temp_dir.name) / "hardlink.db"
        os.link(victim_file, hardlink_db)

        with self.assertRaises(PermissionError) as ctx:
            get_connection(hardlink_db)
        self.assertIn("lien physique interdit", str(ctx.exception).lower())
        self.assertNotIn(str(hardlink_db), str(ctx.exception))
        self.assertEqual(victim_file.read_text(encoding="utf-8"), "victim secret content")

    def test_toctou_symlink_swapped_during_connect_is_refused(self) -> None:
        """TOCTOU — Symlink substitué pendant sqlite3.connect() : connexion fermée (fail-closed)."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        victim = Path(self.temp_dir.name) / "victim.db"
        victim_conn = sqlite3.connect(str(victim))
        victim_conn.execute("CREATE TABLE t (x INTEGER);")
        victim_conn.commit()
        victim_conn.close()
        target = Path(self.temp_dir.name) / "swapped_symlink.db"
        real_connect = sqlite3.connect
        opened: list[sqlite3.Connection] = []

        def swapping_connect(*args: typing.Any, **kwargs: typing.Any) -> sqlite3.Connection:
            # Substitution dans la fenêtre non atomique précédant l'ouverture réelle.
            target.unlink(missing_ok=True)
            target.symlink_to(victim)
            conn = real_connect(*args, **kwargs)
            opened.append(conn)
            return conn

        with patch("heimdall.vault.database.sqlite3.connect", side_effect=swapping_connect):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(target)

        self.assertIn("lien symbolique interdit", str(ctx.exception).lower())
        self.assertNotIn(str(target), str(ctx.exception))
        self.assertNotIn(str(victim), str(ctx.exception))
        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1;")

    def test_toctou_regular_file_swapped_during_connect_is_refused(self) -> None:
        """TOCTOU — Fichier régulier substitué (nouvel inode) pendant connect() : refus."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        target = Path(self.temp_dir.name) / "swapped_regular.db"
        replacement = Path(self.temp_dir.name) / "replacement.db"
        replacement.touch()
        real_connect = sqlite3.connect
        opened: list[sqlite3.Connection] = []

        def swapping_connect(*args: typing.Any, **kwargs: typing.Any) -> sqlite3.Connection:
            # Remplacement par un autre fichier régulier : symlink et type passent,
            # seule la comparaison (st_dev, st_ino) détecte la substitution.
            os.replace(replacement, target)
            conn = real_connect(*args, **kwargs)
            opened.append(conn)
            return conn

        with patch("heimdall.vault.database.sqlite3.connect", side_effect=swapping_connect):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(target)

        self.assertIn("substitution détectée", str(ctx.exception).lower())
        self.assertNotIn(str(target), str(ctx.exception))
        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1;")

    def test_linux_pinned_fd_connect_uses_dev_fd(self) -> None:
        """Remarque 1 (LOW) — Linux : SQLite ouvre /dev/fd/N (inode épinglé), pas le chemin."""
        if not vault_database._FD_DB_CONNECT_SUPPORTED:
            self.skipTest("Repli POSIX actif (pas de /dev/fd fiable)")
        captured: list[str] = []
        real_connect = sqlite3.connect

        def capturing_connect(
            database: str, *args: typing.Any, **kwargs: typing.Any
        ) -> sqlite3.Connection:
            captured.append(database)
            return real_connect(database, *args, **kwargs)

        with patch("heimdall.vault.database.sqlite3.connect", side_effect=capturing_connect):
            conn = get_connection(self.db_path)
        self.assertEqual(len(captured), 1)
        self.assertTrue(
            captured[0].startswith("/dev/fd/"),
            f"connect() doit ouvrir le descripteur épinglé, obtenu {captured[0]}",
        )
        conn.close()

        # La base reste pleinement utilisable (journal adjacent au chemin réel, pas /dev/fd)
        init_db(self.db_path)
        with db_session(self.db_path) as session:
            create_project(session, "proj_pinned")
            self.assertIsNotNone(get_project(session, "proj_pinned"))
        self.assertEqual(self.db_path.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.db_path.parent / f"{self.db_path.name}-journal").exists())

    def test_posix_fallback_path_open_without_dev_fd(self) -> None:
        """Remarque 1 (LOW) — repli POSIX sans /dev/fd : ouverture par chemin + identité."""
        fallback_path = Path(self.temp_dir.name) / "fallback_vault.db"
        with patch.object(vault_database, "_FD_DB_CONNECT_SUPPORTED", False):
            init_db(fallback_path)
            with db_session(fallback_path) as conn:
                create_project(conn, "proj_fallback")
                self.assertIsNotNone(get_project(conn, "proj_fallback"))
            # Réouverture d'un fichier existant (branche « déjà présent » du repli)
            with db_session(fallback_path) as conn_existing:
                self.assertIsNotNone(get_project(conn_existing, "proj_fallback"))
        self.assertEqual(fallback_path.stat().st_mode & 0o777, 0o600)

    def test_pinned_fd_open_errors_map_to_generic_refusals(self) -> None:
        """Défense en profondeur — ELOOP (course symlink) et OSError divers → refus génériques."""
        if not vault_database._FD_DB_CONNECT_SUPPORTED:
            self.skipTest("Repli POSIX actif (pas de /dev/fd fiable)")
        # 1. Symlink présent au moment exact de os.open(O_NOFOLLOW) → ELOOP → refus symlink
        real_target = Path(self.temp_dir.name) / "race_real.db"
        real_target.touch()
        race_symlink = Path(self.temp_dir.name) / "race_symlink.db"
        race_symlink.symlink_to(real_target)
        with self.assertRaises(PermissionError) as ctx_loop:
            vault_database._connect_pinned_fd(race_symlink)
        self.assertIn("lien symbolique interdit", str(ctx_loop.exception).lower())
        # 2. Toute autre OSError → message générique sans chemin
        with patch.object(vault_database.os, "open", side_effect=OSError(errno.EACCES, "denied")):
            with self.assertRaises(PermissionError) as ctx_os:
                vault_database._connect_pinned_fd(real_target)
        self.assertIn("accès impossible", str(ctx_os.exception).lower())
        self.assertNotIn(str(real_target), str(ctx_os.exception))

    def test_check_regular_file_stat_failure_is_generic_refusal(self) -> None:
        """Anti-fuite — un lstat refusé dans _check_regular_file lève PermissionError générique."""
        secret_path = Path(self.temp_dir.name) / "stat_fail" / "vault.db"
        with patch.object(os, "stat", side_effect=OSError("boom " + str(secret_path))):
            with self.assertRaises(PermissionError) as ctx:
                vault_database._check_regular_file(secret_path)
        self.assertEqual(
            str(ctx.exception),
            "Chemin de base de données refusé : accès impossible",
        )
        self.assertNotIn(str(secret_path), str(ctx.exception))

    def test_pinned_fd_guards_fifo_and_hardlink(self) -> None:
        """Défense en profondeur — les gardes fd (non régulier, nlink > 1) refusent sur l'inode."""
        if not vault_database._FD_DB_CONNECT_SUPPORTED:
            self.skipTest("Repli POSIX actif (pas de /dev/fd fiable)")
        # 1. FIFO : os.open(O_RDWR|O_NONBLOCK) réussit sans bloquer, le fstat fd refuse
        if hasattr(os, "mkfifo"):
            fifo_path = Path(self.temp_dir.name) / "fd_fifo.db"
            os.mkfifo(fifo_path)
            with self.assertRaises(PermissionError) as ctx_fifo:
                vault_database._connect_pinned_fd(fifo_path)
            self.assertIn("fichier non régulier interdit", str(ctx_fifo.exception).lower())
        # 2. Hardlink : nlink > 1 refusé via le descripteur épinglé
        hardlink_target = Path(self.temp_dir.name) / "fd_hardlink.db"
        hardlink_target.touch()
        os.link(hardlink_target, Path(self.temp_dir.name) / "fd_hardlink_2.db")
        with self.assertRaises(PermissionError) as ctx_link:
            vault_database._connect_pinned_fd(hardlink_target)
        self.assertIn("lien physique interdit", str(ctx_link.exception).lower())

    def test_pinned_fd_permission_mismatch_fails_closed(self) -> None:
        """Fail-closed — mode effectif != 0o600 constaté sur le fd après fchmod → refus."""
        if not vault_database._FD_DB_CONNECT_SUPPORTED:
            self.skipTest("Repli POSIX actif (pas de /dev/fd fiable)")
        target = Path(self.temp_dir.name) / "fd_mode_mismatch.db"
        real_fstat = os.fstat
        call_count = {"n": 0}

        def fake_fstat(fd: int) -> os.stat_result:
            call_count["n"] += 1
            st = real_fstat(fd)
            if call_count["n"] >= 2:
                fake_mode = (st.st_mode & ~0o777) | 0o644
                return os.stat_result(
                    (
                        fake_mode,
                        st.st_ino,
                        st.st_dev,
                        st.st_nlink,
                        st.st_uid,
                        st.st_gid,
                        st.st_size,
                        st.st_atime,
                        st.st_mtime,
                        st.st_ctime,
                    )
                )
            return st

        with patch.object(vault_database.os, "fstat", side_effect=fake_fstat):
            with self.assertRaises(PermissionError) as ctx:
                vault_database._connect_pinned_fd(target)
        self.assertIn("insuffisantes", str(ctx.exception).lower())
        self.assertNotIn(str(target), str(ctx.exception))

    def test_init_db_rejects_degraded_schema(self) -> None:
        """Remarque 2 (LOW) — init_db lève RuntimeError sur une base au schéma dégradé."""
        degraded_db = Path(self.temp_dir.name) / "degraded.db"

        # Base pré-existante avec table secrets sans contrainte CHECK ni UNIQUE
        conn = sqlite3.connect(str(degraded_db))
        conn.execute("CREATE TABLE projects (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);")
        conn.execute(
            "CREATE TABLE api_keys ("
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, key_hash TEXT NOT NULL, "
            "created_at TEXT NOT NULL, revoked_at TEXT, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE);"
        )
        # Table secrets dégradée (sans UNIQUE, sans CHECK, sans CASCADE)
        conn.execute(
            "CREATE TABLE secrets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, env TEXT NOT NULL, "
            "name TEXT NOT NULL, encrypted_value TEXT NOT NULL, status TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);"
        )
        conn.commit()
        conn.close()

        # init_db sur cette base doit détecter le schéma non conforme et lever RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            init_db(degraded_db)
        self.assertIn("Schéma de base de données non conforme", str(ctx.exception))

    def test_verify_schema_rejects_missing_cascade_under_optimized_python(self) -> None:
        """Remarque 3 — _verify_schema refuse une base sans CASCADE même avec python -O."""
        degraded_db = Path(self.temp_dir.name) / "no_cascade_opt.db"
        conn = sqlite3.connect(str(degraded_db))
        conn.execute("CREATE TABLE projects (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);")
        # api_keys sans ON DELETE CASCADE
        conn.execute(
            "CREATE TABLE api_keys ("
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, key_hash TEXT NOT NULL, "
            "created_at TEXT NOT NULL, revoked_at TEXT, "
            "FOREIGN KEY (project_id) REFERENCES projects(id));"
        )
        conn.execute(
            "CREATE TABLE secrets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, env TEXT NOT NULL, "
            "name TEXT NOT NULL, encrypted_value TEXT NOT NULL, status TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE, "
            "CHECK (status IN ('vaulte', 'rote')));"
        )
        conn.execute("CREATE UNIQUE INDEX idx_secrets_u ON secrets(project_id, env, name);")
        conn.commit()
        conn.close()

        code = f"from heimdall.vault.database import init_db; init_db({str(degraded_db)!r})"
        res = subprocess.run(  # noqa: S603
            [sys.executable, "-O", "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RuntimeError", res.stderr)
        self.assertIn("ON DELETE CASCADE manquant", res.stderr)

    def test_init_db_rejects_malicious_index_name(self) -> None:
        """init_db lève RuntimeError si le nom d'un index contient des caractères invalides."""
        malicious_db = Path(self.temp_dir.name) / "malicious_idx.db"
        conn = sqlite3.connect(str(malicious_db))
        conn.execute("CREATE TABLE projects (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);")
        conn.execute(
            "CREATE TABLE api_keys ("
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, key_hash TEXT NOT NULL, "
            "created_at TEXT NOT NULL, revoked_at TEXT, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE);"
        )
        conn.execute(
            "CREATE TABLE secrets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, env TEXT NOT NULL, "
            "name TEXT NOT NULL, encrypted_value TEXT NOT NULL, status TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE, "
            "CHECK (status IN ('vaulte', 'rote')));"
        )
        # Nom d'index malveillant contenant des guillemets simples/espaces
        conn.execute('CREATE UNIQUE INDEX "idx\'injection" ON secrets(project_id, env, name);')
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            init_db(malicious_db)
        self.assertIn("nom d'index invalide", str(ctx.exception))

    def test_init_db_behavioral_check_rejects_comment_bypass(self) -> None:
        """init_db vérifie le comportement du CHECK et refuse le contournement par commentaire."""
        bypass_db = Path(self.temp_dir.name) / "bypass_comment.db"
        conn = sqlite3.connect(str(bypass_db))
        conn.execute("CREATE TABLE projects (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);")
        conn.execute(
            "CREATE TABLE api_keys ("
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, key_hash TEXT NOT NULL, "
            "created_at TEXT NOT NULL, revoked_at TEXT, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE);"
        )
        # Table secrets sans vraie contrainte CHECK, mais avec le motif textuel en commentaire
        conn.execute(
            "CREATE TABLE secrets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, env TEXT NOT NULL, "
            "name TEXT NOT NULL, encrypted_value TEXT NOT NULL, "
            "status TEXT DEFAULT 'status in (''vaulte'', ''rote'')', "
            "fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE, "
            "UNIQUE (project_id, env, name)); -- status in ('vaulte', 'rote')"
        )
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            init_db(bypass_db)
        self.assertIn("contrainte CHECK de statut inopérante", str(ctx.exception))

    def test_parent_dir_chmod_failure_raises_fail_closed(self) -> None:
        """L'échec de sécurisation d'un répertoire créé lève PermissionError (fail-closed)."""
        if os.name == "nt":
            self.skipTest("chmod 0o700 testé sous POSIX uniquement")
        target_db = Path(self.temp_dir.name) / "new_parent_fail" / "vault.db"

        with patch.object(
            vault_database.os, "fchmod", side_effect=OSError("Simulated fchmod failure")
        ):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(target_db)
            self.assertIn("sécuriser les permissions du répertoire parent", str(ctx.exception))

    def test_parent_dir_insufficient_permissions_raises_fail_closed(self) -> None:
        """Un répertoire créé dont le mode effectif != 0o700 lève PermissionError."""
        if os.name == "nt":
            self.skipTest("chmod 0o700 testé sous POSIX uniquement")
        target_db = Path(self.temp_dir.name) / "new_parent_mode" / "vault.db"
        orig_fstat = os.fstat

        def fake_fstat(fd: int) -> os.stat_result:
            st = orig_fstat(fd)
            if stat_module.S_ISDIR(st.st_mode):
                fake_mode = (st.st_mode & ~0o777) | 0o755
                return os.stat_result(
                    (
                        fake_mode,
                        st.st_ino,
                        st.st_dev,
                        st.st_nlink,
                        st.st_uid,
                        st.st_gid,
                        st.st_size,
                        st.st_atime,
                        st.st_mtime,
                        st.st_ctime,
                    )
                )
            return st

        with patch.object(vault_database.os, "fstat", side_effect=fake_fstat):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(target_db)
            self.assertIn(
                "Permissions du répertoire parent insuffisantes",
                str(ctx.exception),
            )

    def test_parent_dir_swapped_to_symlink_refused_before_chmod(self) -> None:
        """Remarque 2 (v5) — dir créé échangé contre un symlink : refus avant tout chmod.

        Simule la course `mkdir` → `_harden_created_parents` : un attaquant local avec
        écriture sur le parent remplace le répertoire tout juste créé par un lien vers
        une cible hors contrôle. L'ouverture épinglée `O_NOFOLLOW|O_DIRECTORY` échoue
        (ELOOP) et la cible ne reçoit jamais le fchmod 0o700.
        """
        if os.name == "nt":
            self.skipTest("symlinks POSIX uniquement")
        base = Path(self.temp_dir.name)
        race_parent = base / "race_parent"
        real_target = base / "race_target"
        real_target.mkdir(mode=0o755)
        real_target.chmod(0o755)
        initial_mode = real_target.stat().st_mode & 0o777
        real_mkdir = Path.mkdir

        def racing_mkdir(path_obj: Path, *args: typing.Any, **kwargs: typing.Any) -> None:
            real_mkdir(path_obj, *args, **kwargs)
            if path_obj == race_parent:
                path_obj.rmdir()
                path_obj.symlink_to(real_target)

        with patch.object(Path, "mkdir", autospec=True, side_effect=racing_mkdir):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(race_parent / "vault.db")
        self.assertIn("répertoire parent", str(ctx.exception))
        # La cible du lien n'a jamais été chmodée (refus fail-closed avant fchmod)
        self.assertEqual(real_target.stat().st_mode & 0o777, initial_mode)

    def test_probe_collision_raises_normalized_runtime_error(self) -> None:
        """Remarque 4 — Sonde en collision lève RuntimeError normalisée sans toucher aux données."""
        collision_db = Path(self.temp_dir.name) / "collision.db"
        conn = sqlite3.connect(str(collision_db))
        conn.executescript(SCHEMA_SQL)

        fake_uuid = type("FakeUUID", (), {"hex": "fixed_collision_hex"})()
        target_proj = "__schema_probe_fixed_collision_hex__"
        target_uq = "PROBE_UQ_fixed_collision_hex"

        # Pré-plante la ligne en collision avec la sonde
        conn.execute(
            "INSERT INTO projects (id, created_at) VALUES (?, ?);",
            (target_proj, "2026-01-01"),
        )
        conn.execute(
            "INSERT INTO secrets ("
            "project_id, env, name, encrypted_value, status, fingerprint, "
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target_proj,
                "dev",
                target_uq,
                "real_user_val",
                "vaulte",
                "fp_user",
                "2026-01-01",
                "2026-01-01",
            ),
        )
        conn.commit()
        conn.close()

        # init_db sur cette base doit lever RuntimeError (et JAMAIS sqlite3.IntegrityError)
        with patch("heimdall.vault.database.uuid4", return_value=fake_uuid):
            with self.assertRaises(RuntimeError) as ctx:
                init_db(collision_db)
        self.assertIn("collision", str(ctx.exception).lower())

        # Vérifie que la donnée utilisateur pré-existante n'a pas été altérée ni supprimée
        verify_conn = sqlite3.connect(str(collision_db))
        try:
            proj_row = verify_conn.execute(
                "SELECT id FROM projects WHERE id=?;",
                (target_proj,),
            ).fetchone()
            self.assertIsNotNone(proj_row)
            assert proj_row is not None
            self.assertEqual(proj_row[0], target_proj)

            row = verify_conn.execute(
                "SELECT encrypted_value FROM secrets WHERE project_id=? AND env='dev' AND name=?;",
                (target_proj, target_uq),
            ).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row[0], "real_user_val")
        finally:
            verify_conn.close()

    def test_memory_db_behavior_pinned(self) -> None:
        """Remarque 5 — Pinnage du comportement de :memory: (isolée, schéma perdu si init_db)."""
        # 1. get_connection(':memory:') rend une base isolée vierge
        conn1 = get_connection(":memory:")
        try:
            tables1 = conn1.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
            self.assertEqual(tables1, [])

            # 2. init_db(':memory:') crée le schéma sur une connexion éphémère aussitôt fermée
            init_db(":memory:")

            # 3. Une nouvelle connexion :memory: reste vierge (isolation par connexion)
            conn2 = get_connection(":memory:")
            try:
                tables2 = conn2.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
                self.assertEqual(tables2, [])
            finally:
                conn2.close()

            # 4. Le schéma en mémoire s'instancie directement via executescript(SCHEMA_SQL)
            conn1.executescript(SCHEMA_SQL)
            create_project(conn1, "proj_mem")
            proj = get_project(conn1, "proj_mem")
            self.assertIsNotNone(proj)
            assert proj is not None
            self.assertEqual(proj["id"], "proj_mem")
        finally:
            conn1.close()

    def test_umask_restored_on_chmod_failure(self) -> None:
        """Section 3 — L'umask est restauré après _open_db_file même sur chmod mocké en OSError."""
        if os.name == "nt":
            self.skipTest("Test POSIX uniquement")
        initial_umask = os.umask(0o022)
        os.umask(initial_umask)

        fail_path = Path(self.temp_dir.name) / "umask_chmod_fail" / "vault.db"
        if vault_database._FD_DB_CONNECT_SUPPORTED:
            # Linux : le chemin épinglé sécurise via os.fchmod sur le descripteur
            fail_patcher = patch.object(
                vault_database.os, "fchmod", side_effect=OSError("chmod error")
            )
        else:
            fail_patcher = patch.object(Path, "chmod", side_effect=OSError("chmod error"))
        with fail_patcher:
            with self.assertRaises(PermissionError):
                get_connection(fail_path)

        restored_umask = os.umask(0o022)
        os.umask(restored_umask)
        self.assertEqual(
            restored_umask,
            initial_umask,
            f"umask non restauré après échec chmod : attendu {oct(initial_umask)}, "
            f"obtenu {oct(restored_umask)}",
        )

    def test_linux_fchmod_failure_fails_closed(self) -> None:
        """Remarque 1 (LOW) — Linux : échec de fchmod → PermissionError générique, sans chemin."""
        if not vault_database._FD_DB_CONNECT_SUPPORTED:
            self.skipTest("Repli POSIX actif (pas de /dev/fd fiable)")
        target = Path(self.temp_dir.name) / "fchmod_fail.db"
        with patch.object(vault_database.os, "fchmod", side_effect=OSError("read-only fs")):
            with self.assertRaises(PermissionError) as ctx:
                get_connection(target)
        self.assertIn("permissions", str(ctx.exception).lower())
        self.assertNotIn(str(target), str(ctx.exception))

    def test_get_connection_rejects_existing_directory_and_path_memory(self) -> None:
        """Section 3 — get_connection refuse un répertoire existant et gère Path(':memory:')."""
        existing_dir = Path(self.temp_dir.name) / "some_dir"
        existing_dir.mkdir(exist_ok=True)
        with self.assertRaises(IsADirectoryError):
            get_connection(existing_dir)

        # Path(':memory:') littéral est normalisé en mode en mémoire ':memory:'
        conn_mem = get_connection(Path(":memory:"))
        try:
            cur = conn_mem.execute("SELECT 1;")
            self.assertEqual(cur.fetchone()[0], 1)
        finally:
            conn_mem.close()

    def test_init_db_cli_help_documents_exit_codes(self) -> None:
        """Pinnage des codes de sortie 0, 1 et 2 dans l'aide de la CLI init_db."""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "heimdall.vault.init_db", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Codes de retour", result.stdout)
        self.assertIn("0", result.stdout)
        self.assertIn("1", result.stdout)
        self.assertIn("2", result.stdout)

    def test_init_db_cli_subprocess_env_memory_exit_2(self) -> None:
        """Remarque 2 (v4/v5) — bout en bout : env ':memory:' → exit 2, message dédié.

        Exécution dans un vrai sous-processus (pas seulement `main()` en mémoire) :
        `HEIMDALL_VAULT_DB_PATH=:memory:` ne doit jamais produire une base éphémère
        silencieuse en CLI.
        """
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "heimdall.vault.init_db"],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "HEIMDALL_VAULT_DB_PATH": ":memory:"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("':memory:'", result.stderr)
        self.assertIn("interdit en CLI", result.stderr)

    def test_oversized_inputs_behavior_pinned(self) -> None:
        """Pinnage du comportement face à des entrées surdimensionnées (bloat DoS)."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            huge_id = "proj_" + "a" * (2 * 1024 * 1024)
            huge_name = "VAR_" + "b" * (2 * 1024 * 1024)
            create_project(conn, huge_id)
            p = get_project(conn, huge_id)
            self.assertIsNotNone(p)
            assert p is not None
            self.assertEqual(p["id"], huge_id)

            create_secret(
                conn,
                project_id=huge_id,
                env="dev",
                name=huge_name,
                encrypted_value="ciphertext",
                fingerprint="fp_huge",
            )
            s = get_secret(conn, huge_id, "dev", huge_name)
            self.assertIsNotNone(s)
            assert s is not None
            self.assertEqual(s["name"], huge_name)

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
