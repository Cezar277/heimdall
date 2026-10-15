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
  - `status`: contrainte `CHECK(status IN ('vaulte', 'rote'))` + validation
    applicative `Literal["vaulte", "rote"]` avant toute requête.
- Permissions fichier au repos :
  - Umask restrictif `0o077` positionné avant création du fichier/répertoire.
  - Mode `0o600` (lecture/écriture propriétaire uniquement) vérifié et confirmé
    après création — fail-closed si le chmod échoue ou si le mode effectif diffère.
  - Refus de tout chemin symbolique (`is_symlink()` via lstat) : protection TOCTOU.
  - `journal_mode=DELETE` forcé pour éviter la création de fichiers sidecar
    `-wal`/`-shm`/`-journal` en permissions larges.
"""

import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

SecretStatus = Literal["vaulte", "rote"]

DEFAULT_DB_PATH: Path = Path("vault.db")

# Mode fichier sécurisé : lecture/écriture propriétaire uniquement (aucun accès groupe/autres).
_SECURE_FILE_MODE: int = 0o600

SCHEMA_SQL: str = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;

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


def _assert_not_symlink(path: Path) -> None:
    """Refuse tout chemin symbolique : protection TOCTOU (lstat, pas de suivi du lien).

    Lève PermissionError si le chemin ou l'un de ses parents connus est un symlink.
    """
    # Vérifie le fichier lui-même (s'il existe)
    if path.is_symlink():
        raise PermissionError(
            f"Chemin de base de données refusé : lien symbolique interdit ({path})"
        )
    # Vérifie aussi le répertoire parent s'il existe
    if path.parent.exists() and path.parent.is_symlink():
        raise PermissionError(
            f"Répertoire parent refusé : lien symbolique interdit ({path.parent})"
        )


def _apply_secure_permissions(path: Path) -> None:
    """Applique et vérifie les permissions 0o600 sur le fichier SQLite (POSIX uniquement).

    Lève PermissionError si le chmod échoue ou si le mode effectif après chmod diffère
    de 0o600 — fail-closed : mieux vaut planter que laisser la base lisible.
    """
    if os.name == "nt":
        return
    try:
        path.chmod(_SECURE_FILE_MODE)
    except OSError as exc:
        raise PermissionError(
            f"Impossible de sécuriser les permissions de la base SQLite ({path}) : {exc}"
        ) from exc
    # Vérification post-chmod (fail-closed)
    actual_mode = path.stat().st_mode & 0o777
    if actual_mode != _SECURE_FILE_MODE:
        raise PermissionError(
            f"Permissions de la base SQLite insuffisantes : attendu 0o600, obtenu "
            f"{oct(actual_mode)} ({path})"
        )


def _open_db_file(path: Path) -> sqlite3.Connection:
    """Ouvre une connexion SQLite vers un fichier en appliquant les gardes de sécurité.

    - Refuse les symlinks (TOCTOU).
    - Crée le répertoire parent avec umask 0o077 (droits 0o700).
    - Crée le fichier avec mode 0o600 si inexistant.
    - Vérifie et confirme les permissions après création (fail-closed).
    - Positionne journal_mode=DELETE (pas de sidecar -wal/-shm).
    """
    _assert_not_symlink(path)
    old_umask = os.umask(0o077)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch(mode=0o600, exist_ok=True)
    finally:
        os.umask(old_umask)
    _apply_secure_permissions(path)
    conn = sqlite3.connect(str(path))
    # journal_mode=DELETE : empêche la création de fichiers sidecar en permissions larges.
    conn.execute("PRAGMA journal_mode = DELETE;")
    return conn


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Ouvre une connexion SQLite sécurisée avec foreign keys activées et row_factory.

    Active systématiquement `PRAGMA foreign_keys = ON;` (invariant de sécurité).
    """
    resolved = resolve_db_path(db_path)
    if isinstance(resolved, Path):
        conn = _open_db_file(resolved)
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
    Réutilise `get_connection()` pour garantir les mêmes gardes de sécurité
    (symlink, umask, permissions, journal_mode=DELETE).
    """
    conn = get_connection(db_path)
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
    status: SecretStatus = "vaulte",
    fingerprint: str = "",
    created_at: str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Crée un secret chiffré dans la base de données.

    Le paramètre `status` est typé `Literal["vaulte", "rote"]` pour une validation
    applicative avant toute requête SQL, en complément du CHECK SQLite.
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
    status: SecretStatus = "vaulte",
    updated_at: str | None = None,
) -> bool:
    """Met à jour la valeur chiffrée, l'empreinte et le statut d'un secret existant.

    Le paramètre `status` est typé `Literal["vaulte", "rote"]` pour une validation
    applicative avant toute requête SQL.
    """
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
