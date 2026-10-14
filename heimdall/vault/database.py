"""Modèle de données et persistance SQLite du Vault Heimdall (ticket #25 / #62).

Ce module implémente la couche d'accès à la base de données SQLite du Vault
stockant les projets, les clés API de projet et les secrets chiffrés.

RÈGLES DE SÉCURITÉ ET CONFORMITÉ (DoD, STRIDE, pentest) :
- Accès exclusif par requêtes SQL paramétrées (`?`) : AUCUNE f-string, AUCUNE
  concaténation de chaînes dans les requêtes SQL (mitigation stricte CWE-89 / SQL Injection).
- Clés étrangères strictement activées : `PRAGMA foreign_keys = ON;` exécuté sur
  CHAQUE nouvelle connexion SQLite (par défaut inactif dans SQLite).
- Confinement crypto (ticket #17) : ce module n'importe JAMAIS `cryptography`
  ni `argon2`. Il manipule uniquement des blobs chiffrés (ciphertext) et des
  hachés de vérification de clés API fournis par les couches appelantes.
- Contraintes d'intégrité :
  - `projects`: `id` unique (PK).
  - `api_keys`: clé étrangère sur `projects(id)` avec `ON DELETE CASCADE`.
  - `secrets`: clé étrangère sur `projects(id)` avec `ON DELETE CASCADE`,
    contrainte d'unicité `UNIQUE(project_id, env, name)`.
  - `status`: contrainte `CHECK(status IN ('vaulte', 'rote'))`.
- Permissions fichier au repos : création de fichier avec permissions restreintes
  (mode 0o600, lecture/écriture propriétaire uniquement sur systèmes POSIX).
"""

import os
import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH: Path = Path("vault.db")

SCHEMA_SQL: str = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_project_id ON api_keys(project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    env TEXT NOT NULL,
    name TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'vaulte',
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT uq_secrets_project_env_name UNIQUE (project_id, env, name),
    CONSTRAINT chk_secrets_status CHECK (status IN ('vaulte', 'rote'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_project_env_name ON secrets(project_id, env, name);
"""


def get_iso_timestamp() -> str:
    """Retourne l'horodatage UTC courant au format ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def resolve_db_path(db_path: Path | str | None = None) -> Path | str:
    """Résout le chemin de la base de données (argument, variable d'environnement ou défaut)."""
    if db_path is not None:
        if str(db_path) == ":memory:":
            return ":memory:"
        return Path(db_path)
    env_path = os.environ.get("HEIMDALL_VAULT_DB_PATH")
    if env_path:
        if env_path == ":memory:":
            return ":memory:"
        return Path(env_path)
    return DEFAULT_DB_PATH


def _apply_secure_permissions(path: Path) -> None:
    """Applique les permissions 0o600 (lecture/écriture propriétaire) sur fichier POSIX."""
    try:
        if path.exists() and os.name != "nt":
            path.chmod(0o600)
    except OSError:
        pass


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Ouvre une connexion SQLite sécurisée avec foreign keys activées et row_factory.

    Active systématiquement `PRAGMA foreign_keys = ON;` (invariant de sécurité).
    """
    resolved = resolve_db_path(db_path)
    if isinstance(resolved, Path):
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if not resolved.exists():
            resolved.touch(mode=0o600, exist_ok=True)
        _apply_secure_permissions(resolved)
        conn = sqlite3.connect(str(resolved))
    else:
        conn = sqlite3.connect(resolved)

    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session(db_path: Path | str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Gestionnaire de contexte pour transaction SQLite sûre (commit/rollback et fermeture)."""
    conn = get_connection(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str | None = None) -> None:
    """Initialise à froid la base de données SQLite en créant le schéma complet.

    Exécute le script DDL créant `projects`, `api_keys`, `secrets` et leurs index.
    """
    resolved = resolve_db_path(db_path)
    if isinstance(resolved, Path):
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if not resolved.exists():
            resolved.touch(mode=0o600, exist_ok=True)
        _apply_secure_permissions(resolved)
        conn = sqlite3.connect(str(resolved))
    else:
        conn = sqlite3.connect(resolved)

    try:
        with conn:
            conn.executescript(SCHEMA_SQL)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Opérations CRUD — Projets
# ---------------------------------------------------------------------------


def create_project(
    conn: sqlite3.Connection,
    project_id: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Crée un projet dans la base de données."""
    ts = created_at or get_iso_timestamp()
    query = "INSERT INTO projects (id, created_at) VALUES (?, ?)"
    conn.execute(query, (project_id, ts))
    return {"id": project_id, "created_at": ts}


def get_project(conn: sqlite3.Connection, project_id: str) -> dict[str, Any] | None:
    """Récupère un projet par son identifiant."""
    query = "SELECT id, created_at FROM projects WHERE id = ?"
    cursor = conn.execute(query, (project_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def list_projects(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Liste tous les projets enregistrés."""
    query = "SELECT id, created_at FROM projects ORDER BY created_at ASC"
    cursor = conn.execute(query)
    return [dict(row) for row in cursor.fetchall()]


def delete_project(conn: sqlite3.Connection, project_id: str) -> bool:
    """Supprime un projet et ses entités associées en cascade."""
    query = "DELETE FROM projects WHERE id = ?"
    cursor = conn.execute(query, (project_id,))
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Opérations CRUD — Clés API
# ---------------------------------------------------------------------------


def create_api_key(
    conn: sqlite3.Connection,
    key_id: str,
    project_id: str,
    key_hash: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Enregistre une nouvelle clé API (haché de vérification uniquement)."""
    ts = created_at or get_iso_timestamp()
    query = (
        "INSERT INTO api_keys (id, project_id, key_hash, created_at, revoked_at) "
        "VALUES (?, ?, ?, ?, NULL)"
    )
    conn.execute(query, (key_id, project_id, key_hash, ts))
    return {
        "id": key_id,
        "project_id": project_id,
        "key_hash": key_hash,
        "created_at": ts,
        "revoked_at": None,
    }


def get_api_key(conn: sqlite3.Connection, key_id: str) -> dict[str, Any] | None:
    """Récupère une clé API par son identifiant."""
    query = "SELECT id, project_id, key_hash, created_at, revoked_at FROM api_keys WHERE id = ?"
    cursor = conn.execute(query, (key_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def get_api_key_by_hash(conn: sqlite3.Connection, key_hash: str) -> dict[str, Any] | None:
    """Récupère une clé API par son haché de vérification."""
    query = (
        "SELECT id, project_id, key_hash, created_at, revoked_at FROM api_keys WHERE key_hash = ?"
    )
    cursor = conn.execute(query, (key_hash,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def list_api_keys_for_project(conn: sqlite3.Connection, project_id: str) -> list[dict[str, Any]]:
    """Liste les clés API d'un projet."""
    query = (
        "SELECT id, project_id, key_hash, created_at, revoked_at "
        "FROM api_keys WHERE project_id = ? ORDER BY created_at ASC"
    )
    cursor = conn.execute(query, (project_id,))
    return [dict(row) for row in cursor.fetchall()]


def revoke_api_key(
    conn: sqlite3.Connection,
    key_id: str,
    revoked_at: str | None = None,
) -> bool:
    """Marque une clé API comme révoquée avec horodatage."""
    ts = revoked_at or get_iso_timestamp()
    query = "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
    cursor = conn.execute(query, (ts, key_id))
    return cursor.rowcount > 0


def delete_api_key(conn: sqlite3.Connection, key_id: str) -> bool:
    """Supprime définitivement une clé API."""
    query = "DELETE FROM api_keys WHERE id = ?"
    cursor = conn.execute(query, (key_id,))
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Opérations CRUD — Secrets
# ---------------------------------------------------------------------------


def create_secret(  # noqa: PLR0913
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
    encrypted_value: str,
    *,
    status: str = "vaulte",
    fingerprint: str = "",
    created_at: str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Crée un secret chiffré dans la base de données.

    Lève sqlite3.IntegrityError si la contrainte d'unicité (project_id, env, name)
    ou la clé étrangère est enfreinte.
    """
    ts = created_at or get_iso_timestamp()
    up_ts = updated_at or ts
    query = (
        "INSERT INTO secrets ("
        "project_id, env, name, encrypted_value, status, fingerprint, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    conn.execute(
        query,
        (project_id, env, name, encrypted_value, status, fingerprint, ts, up_ts),
    )
    return {
        "project_id": project_id,
        "env": env,
        "name": name,
        "encrypted_value": encrypted_value,
        "status": status,
        "fingerprint": fingerprint,
        "created_at": ts,
        "updated_at": up_ts,
    }


def get_secret(
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
) -> dict[str, Any] | None:
    """Récupère un secret complet (y compris valeur chiffrée) par son triplet."""
    query = (
        "SELECT id, project_id, env, name, encrypted_value, status, fingerprint, "
        "created_at, updated_at "
        "FROM secrets WHERE project_id = ? AND env = ? AND name = ?"
    )
    cursor = conn.execute(query, (project_id, env, name))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def get_secret_metadata(
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
) -> dict[str, Any] | None:
    """Récupère les métadonnées d'un secret sans exposer la valeur chiffrée."""
    query = (
        "SELECT id, project_id, env, name, status, fingerprint, created_at, updated_at "
        "FROM secrets WHERE project_id = ? AND env = ? AND name = ?"
    )
    cursor = conn.execute(query, (project_id, env, name))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def list_secrets(
    conn: sqlite3.Connection,
    project_id: str,
    env: str | None = None,
) -> list[dict[str, Any]]:
    """Liste les métadonnées des secrets d'un projet, filtrés optionnellement par environnement."""
    if env is not None:
        query = (
            "SELECT id, project_id, env, name, status, fingerprint, created_at, updated_at "
            "FROM secrets WHERE project_id = ? AND env = ? ORDER BY name ASC"
        )
        cursor = conn.execute(query, (project_id, env))
    else:
        query = (
            "SELECT id, project_id, env, name, status, fingerprint, created_at, updated_at "
            "FROM secrets WHERE project_id = ? ORDER BY env ASC, name ASC"
        )
        cursor = conn.execute(query, (project_id,))
    return [dict(row) for row in cursor.fetchall()]


def update_secret(  # noqa: PLR0913
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
    encrypted_value: str,
    *,
    fingerprint: str = "",
    status: str = "vaulte",
    updated_at: str | None = None,
) -> bool:
    """Met à jour la valeur chiffrée, l'empreinte et le statut d'un secret existant."""
    up_ts = updated_at or get_iso_timestamp()
    query = (
        "UPDATE secrets SET "
        "encrypted_value = ?, fingerprint = ?, status = ?, updated_at = ? "
        "WHERE project_id = ? AND env = ? AND name = ?"
    )
    cursor = conn.execute(
        query,
        (encrypted_value, fingerprint, status, up_ts, project_id, env, name),
    )
    return cursor.rowcount > 0


def delete_secret(
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
) -> bool:
    """Supprime un secret identifié par son triplet (project_id, env, name)."""
    query = "DELETE FROM secrets WHERE project_id = ? AND env = ? AND name = ?"
    cursor = conn.execute(query, (project_id, env, name))
    return cursor.rowcount > 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Initialisation à froid de la base de données SQLite du Vault Heimdall."
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help=f"Chemin du fichier SQLite (défaut : {DEFAULT_DB_PATH} ou $HEIMDALL_VAULT_DB_PATH)",
    )
    cli_args = parser.parse_args()
    try:
        init_db(cli_args.db_path)
        print("Base de données SQLite initialisée avec succès.")
        sys.exit(0)
    except Exception as exc:
        print(f"Erreur lors de l'initialisation de la base : {exc}", file=sys.stderr)
        sys.exit(1)
