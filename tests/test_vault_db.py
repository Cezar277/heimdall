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
10. Les permissions sécurisées du fichier SQLite (`0o600` sous POSIX).
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from heimdall.vault.database import (
    DEFAULT_DB_PATH,
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
)
from heimdall.vault.init_db import main as init_db_main


class VaultDatabaseTests(unittest.TestCase):
    """Suite de tests du modèle SQLite du Vault Heimdall."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vault.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_cold_init_creates_schema_and_indexes(self) -> None:
        """Critère d'acceptation #62 : la base est créée à froid depuis zéro."""
        self.assertFalse(self.db_path.exists())
        init_db(self.db_path)
        self.assertTrue(self.db_path.exists())

        conn = get_connection(self.db_path)
        try:
            # Vérification des tables
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = {row["name"] for row in cursor.fetchall()}
            self.assertIn("projects", tables)
            self.assertIn("api_keys", tables)
            self.assertIn("secrets", tables)

            # Vérification des index
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")
            indexes = {row["name"] for row in cursor.fetchall()}
            self.assertIn("idx_api_keys_project_id", indexes)
            self.assertIn("idx_api_keys_key_hash", indexes)
            self.assertIn("idx_secrets_project_env_name", indexes)
        finally:
            conn.close()

    def test_secure_file_permissions(self) -> None:
        """Vérifie que les permissions du fichier créé sont restreintes à 0o600 sous POSIX."""
        init_db(self.db_path)
        if os.name != "nt":
            mode = self.db_path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_init_db_cli_script(self) -> None:
        """Le script CLI `python -m heimdall.vault.init_db` s'exécute avec succès."""
        target_path = Path(self.temp_dir.name) / "cli_vault.db"
        ret = init_db_main(["--db-path", str(target_path)])
        self.assertEqual(ret, 0)
        self.assertTrue(target_path.exists())

    def test_foreign_keys_strictly_enforced_by_default(self) -> None:
        """PRAGMA foreign_keys = ON est systématiquement actif sur toute connexion."""
        init_db(self.db_path)
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("PRAGMA foreign_keys;")
            fk_status = cursor.fetchone()[0]
            self.assertEqual(fk_status, 1)

            # Tentative d'insertion d'une clé API sans projet existant -> refus immédiat
            with self.assertRaises(sqlite3.IntegrityError):
                create_api_key(conn, "key_orphan", "non_existent_project", "hash123")

            # Tentative d'insertion d'un secret sans projet existant -> refus immédiat
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

            # Vérification de présence initiale
            self.assertIsNotNone(get_api_key(conn, "key_casc"))
            self.assertIsNotNone(get_secret(conn, "proj_cascade", "dev", "PASSWD"))

            # Suppression du projet
            deleted = delete_project(conn, "proj_cascade")
            self.assertTrue(deleted)

            # Clés et secrets associés doivent avoir été purgés en cascade
            self.assertIsNone(get_api_key(conn, "key_casc"))
            self.assertIsNone(get_secret(conn, "proj_cascade", "dev", "PASSWD"))

    def test_unique_constraint_on_secrets(self) -> None:
        """La contrainte UNIQUE(project_id, env, name) interdit les doublons de secrets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj1")
            create_project(conn, "proj2")

            # Premier secret : OK
            create_secret(conn, "proj1", "dev", "DB_PASS", "blob_v1", fingerprint="fp1")

            # Même project, même env, même name -> IntegrityError (conflit)
            with self.assertRaises(sqlite3.IntegrityError):
                create_secret(conn, "proj1", "dev", "DB_PASS", "blob_v2", fingerprint="fp2")

            # Même project, environnement différent (prod) -> autorisé
            sec_prod = create_secret(conn, "proj1", "prod", "DB_PASS", "blob_prod")
            self.assertEqual(sec_prod["env"], "prod")

            # Même project, même env, nom différent -> autorisé
            sec_other = create_secret(conn, "proj1", "dev", "OTHER_PASS", "blob_other")
            self.assertEqual(sec_other["name"], "OTHER_PASS")

            # Projet différent, même env et nom -> autorisé (cloisonnement)
            sec_proj2 = create_secret(conn, "proj2", "dev", "DB_PASS", "blob_p2")
            self.assertEqual(sec_proj2["project_id"], "proj2")

    def test_status_check_constraint(self) -> None:
        """Seuls les statuts contractuels 'vaulte' et 'rote' sont acceptés."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_stat")
            create_secret(conn, "proj_stat", "dev", "SEC_V", "b", status="vaulte")
            create_secret(conn, "proj_stat", "dev", "SEC_R", "b", status="rote")

            # Statut invalide -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                create_secret(conn, "proj_stat", "dev", "SEC_BAD", "b", status="invalid_status")

    def test_sql_injection_defense_in_depth(self) -> None:
        """Mitigation CWE-89 : requêtes paramétrées insensibles aux injections SQL."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            # Payloads d'injection malveillants typiques de pentest
            sql_injections = [
                "proj'; DROP TABLE projects; --",
                "demo' OR '1'='1",
                "admin'--",
                "' UNION SELECT 1, 'evil' --",
                "\x00' OR 1=1 --",
            ]

            for payload in sql_injections:
                with self.subTest(payload=payload):
                    # Création avec project_id injecté
                    create_project(conn, payload)
                    retrieved = get_project(conn, payload)
                    self.assertIsNotNone(retrieved)
                    assert retrieved is not None
                    self.assertEqual(retrieved["id"], payload)

                    # Les tables doivent toujours exister intactes
                    cursor = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'"
                    )
                    self.assertIsNotNone(cursor.fetchone())

                    # Clé API avec identifiant ou hash injecté
                    create_api_key(conn, f"k_{payload}", payload, f"hash_{payload}")
                    key_row = get_api_key_by_hash(conn, f"hash_{payload}")
                    self.assertIsNotNone(key_row)
                    assert key_row is not None
                    self.assertEqual(key_row["id"], f"k_{payload}")

                    # Secret avec champs injectés
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

            # Non trouvé
            self.assertIsNone(get_project(conn, "unknown-project"))

            # Suppression
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

            # Révocation
            revoked = revoke_api_key(conn, "key_001")
            self.assertTrue(revoked)
            # Seconde révocation doit retourner False (déjà révoquée)
            self.assertFalse(revoke_api_key(conn, "key_001"))

            updated_key = get_api_key(conn, "key_001")
            self.assertIsNotNone(updated_key)
            assert updated_key is not None
            self.assertIsNotNone(updated_key["revoked_at"])

            # Suppression
            self.assertTrue(delete_api_key(conn, "key_001"))
            self.assertIsNone(get_api_key(conn, "key_001"))

    def test_crud_secrets(self) -> None:
        """Cycle de vie complet des secrets."""
        init_db(self.db_path)
        with db_session(self.db_path) as conn:
            create_project(conn, "proj_secrets")

            # Création
            s = create_secret(
                conn,
                project_id="proj_secrets",
                env="dev",
                name="APP_SECRET",
                encrypted_value="cipher_12345",
                fingerprint="hmac_fp",
            )
            self.assertEqual(s["status"], "vaulte")

            # Lecture complète (avec valeur)
            full = get_secret(conn, "proj_secrets", "dev", "APP_SECRET")
            self.assertIsNotNone(full)
            assert full is not None
            self.assertEqual(full["encrypted_value"], "cipher_12345")
            self.assertEqual(full["fingerprint"], "hmac_fp")

            # Lecture métadonnées uniquement (sans exposer la valeur)
            meta = get_secret_metadata(conn, "proj_secrets", "dev", "APP_SECRET")
            self.assertIsNotNone(meta)
            assert meta is not None
            self.assertEqual(meta["name"], "APP_SECRET")
            self.assertEqual(meta["status"], "vaulte")
            self.assertNotIn("encrypted_value", meta)

            # Mise à jour
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

            # Liste par environnement
            secrets_dev = list_secrets(conn, "proj_secrets", env="dev")
            self.assertEqual(len(secrets_dev), 1)
            secrets_prod = list_secrets(conn, "proj_secrets", env="prod")
            self.assertEqual(len(secrets_prod), 0)

            # Suppression
            self.assertTrue(delete_secret(conn, "proj_secrets", "dev", "APP_SECRET"))
            self.assertIsNone(get_secret(conn, "proj_secrets", "dev", "APP_SECRET"))

    def test_transaction_rollback_on_error(self) -> None:
        """Le gestionnaire db_session effectue un rollback propre en cas d'erreur."""
        init_db(self.db_path)

        with self.assertRaises(RuntimeError):
            with db_session(self.db_path) as conn:
                create_project(conn, "proj_rollback")
                raise RuntimeError("Panne inattendue durant la transaction")

        with db_session(self.db_path) as conn:
            # Le projet n'a pas été persisté grâce au rollback
            self.assertIsNone(get_project(conn, "proj_rollback"))

    def test_resolve_db_path_environment_variable(self) -> None:
        """resolve_db_path prend en compte HEIMDALL_VAULT_DB_PATH."""
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path(), Path("/custom/path/vault.db"))

        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": ":memory:"}):
            self.assertEqual(resolve_db_path(), ":memory:")

        # Argument explicite prioritaire sur l'environnement
        with patch.dict(os.environ, {"HEIMDALL_VAULT_DB_PATH": "/custom/path/vault.db"}):
            self.assertEqual(resolve_db_path("/override/path.db"), Path("/override/path.db"))

        # Valeur par défaut quand aucune variable d'environnement n'est définie
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_db_path(), DEFAULT_DB_PATH)


if __name__ == "__main__":
    unittest.main()
