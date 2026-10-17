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
- Confinement d'environnement : POSIX uniquement (Linux, macOS, BSD). Sous Windows (nt),
  les permissions 0o600 ne sont pas applicables nativement via os.chmod
  (avertissement RuntimeWarning émis).
"""

import logging
import os
import sqlite3
import stat as stat_module
import warnings
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

SecretStatus = Literal["vaulte", "rote"]
_ALLOWED_STATUSES: frozenset[str] = frozenset({"vaulte", "rote"})

DEFAULT_DB_PATH: Path = Path("vault.db")

# Mode fichier sécurisé : lecture/écriture propriétaire uniquement (aucun accès groupe/autres).
_SECURE_FILE_MODE: int = 0o600
_SECURE_DIR_MODE: int = 0o700
_DIR_PERM_MASK: int = 0o777
_CONTROL_CHAR_THRESHOLD: int = 0x20

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


def validate_db_path(db_path: Path | str) -> str:
    """Valide et normalise une chaîne ou un objet Path représentant un chemin SQLite.

    Règles de validation :
    - Refuse les chemins vides ou composés uniquement d'espaces.
    - Refuse tout caractère de contrôle ASCII (< 0x20, tabulation incluse).
    - Refuse les chemins pointant vers un répertoire existant.
    - Autorise le mode spécial SQLite ':memory:'.

    Lève ValueError si vide ou avec caractères de contrôle.
    Lève IsADirectoryError si le chemin pointe vers un répertoire existant.
    """
    stripped = str(db_path).strip()
    if not stripped:
        raise ValueError("Le chemin de la base de données SQLite ne peut pas être vide.")
    if any(ord(c) < _CONTROL_CHAR_THRESHOLD for c in stripped):
        raise ValueError(
            "Le chemin de la base de données SQLite contient des caractères de contrôle."
        )
    if stripped != ":memory:" and Path(stripped).is_dir():
        logger.debug(
            "Chemin de base de données pointe vers un répertoire existant : %s",
            Path(stripped).name,
        )
        raise IsADirectoryError(
            "Chemin de base de données invalide : pointe vers un répertoire existant"
        )
    return stripped


def resolve_db_path(db_path: Path | str | None = None) -> Path | str:
    """Résout et valide le chemin SQLite (argument, variable d'environnement ou défaut).

    Ordre de priorité :
    1. Argument explicite `db_path`
    2. Variable d'environnement `HEIMDALL_VAULT_DB_PATH`
    3. `DEFAULT_DB_PATH`

    Comportement CWD (remarque 1 de revue) :
    Les chemins relatifs passés en argument ou via variable d'environnement sont
    interprétés relativement au répertoire de travail courant (CWD / `Path.cwd()`).
    Pour éviter tout cloisonnement silencieux entre deux processus ayant des CWD
    distincts, privilégier des chemins absolus (ou ':memory:' en test).

    Mode en mémoire ':memory:' :
    Le mode ':memory:' est réservé aux tests unitaires. Chaque appel à
    get_connection(':memory:') ouvre une base de données en mémoire vierge et isolée.
    Initialiser le schéma via init_db(':memory:') sur la connexion avant toute requête.
    """
    if db_path is not None:
        validated = validate_db_path(db_path)
        if validated == ":memory:":
            return ":memory:"
        return Path(validated)
    env_path = os.environ.get("HEIMDALL_VAULT_DB_PATH")
    if env_path is not None:
        validated = validate_db_path(env_path)
        if validated == ":memory:":
            return ":memory:"
        return Path(validated)
    return DEFAULT_DB_PATH


def _assert_not_symlink(path: Path) -> None:
    """Refuse tout chemin dont le fichier ou l'un des ancêtres est un lien symbolique.

    Protection TOCTOU stricte via lstat (pas de déréférencement).
    Vérifie le chemin relatif/absolu, ses ancêtres, ainsi que leurs formes normalisées
    lexicalement (os.path.normpath sans suivi de symlink pour neutraliser les '..').
    """
    candidates: list[Path] = [path, *path.parents]
    # Vérifie également sous forme absolue pour couvrir les symlinks ancêtres non relatifs
    abs_path = path.absolute()
    candidates.extend([abs_path, *abs_path.parents])

    # Normalisation lexicale pour couvrir les chemins contenant des '..'
    norm_path = Path(os.path.normpath(str(path)))
    candidates.extend([norm_path, *norm_path.parents])
    norm_abs = Path(os.path.normpath(str(abs_path)))
    candidates.extend([norm_abs, *norm_abs.parents])

    seen: set[Path] = set()
    for p in candidates:
        if p not in seen:
            seen.add(p)
            if os.path.islink(p):
                logger.debug("Chemin de base de données refusé (symlink détecté) : %s", p.name)
                raise PermissionError("Chemin de base de données refusé : lien symbolique interdit")


def _apply_secure_permissions(path: Path) -> None:
    """Applique et vérifie les permissions 0o600 sur le fichier SQLite (POSIX uniquement).

    Lève PermissionError si le chmod échoue ou si le mode effectif après chmod diffère
    de 0o600 — fail-closed : mieux vaut planter que laisser la base lisible.

    Plateformes non-POSIX (Windows / nt) :
    Le Vault Heimdall requiert un environnement POSIX pour garantir le confinement
    des permissions fichier (0o600). Windows est strictement hors cible de déploiement
    en production. Sous Windows, les ACL ne sont pas restreintes nativement via os.chmod ;
    cette fonction émet un RuntimeWarning explicite.
    """
    if os.name == "nt":
        warnings.warn(
            "Le Vault Heimdall requiert un environnement POSIX pour garantir le confinement "
            "des permissions fichier (0o600). Sous Windows, les ACL ne sont pas restreintes.",
            RuntimeWarning,
            stacklevel=2,
        )
        return
    try:
        path.chmod(_SECURE_FILE_MODE)
    except OSError as exc:
        logger.debug("Échec du chmod 0o600 sur %s : %s", path.name, exc.__class__.__name__)
        raise PermissionError("Impossible de sécuriser les permissions de la base SQLite") from exc
    # Vérification post-chmod (fail-closed)
    actual_mode = path.stat().st_mode & 0o777
    if actual_mode != _SECURE_FILE_MODE:
        logger.debug(
            "Permissions insuffisantes sur %s : attendu 0o600, obtenu %s",
            path.name,
            oct(actual_mode),
        )
        raise PermissionError(
            "Permissions de la base SQLite insuffisantes : attendu 0o600, "
            f"obtenu {oct(actual_mode)}"
        )


def _check_regular_file(path: Path) -> None:
    """Vérifie que le chemin correspond à un fichier régulier (refus FIFO/socket/device)."""
    if not path.exists():
        return
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode
    except OSError as exc:
        logger.debug("Impossible de stat le chemin %s : %s", path.name, exc.__class__.__name__)
        raise PermissionError("Chemin de base de données refusé : accès impossible") from exc
    if not stat_module.S_ISREG(mode):
        logger.debug("Chemin de base de données non régulier : %s", path.name)
        raise PermissionError("Chemin de base de données refusé : fichier non régulier interdit")


def _harden_created_parents(missing_parents: list[Path]) -> None:
    """Durcit uniquement les répertoires effectivement créés par mkdir (POSIX).

    Les répertoires pré-existants (ex: CWD '.', /tmp) relèvent de la confiance
    opérateur et ne sont jamais modifiés pour éviter tout effet de bord destructeur.
    """
    if os.name == "nt":
        return
    for new_dir in missing_parents:
        if not new_dir.exists():
            continue
        try:
            new_dir.chmod(_SECURE_DIR_MODE)
        except OSError as exc:
            logger.debug(
                "Échec du chmod 0o700 sur %s : %s",
                new_dir.name,
                exc.__class__.__name__,
            )
            raise PermissionError(
                "Impossible de sécuriser les permissions du répertoire parent"
            ) from exc
        mode = new_dir.stat().st_mode & _DIR_PERM_MASK
        if mode != _SECURE_DIR_MODE:
            logger.debug(
                "Permissions du répertoire parent insuffisantes sur %s",
                new_dir.name,
            )
            raise PermissionError("Permissions du répertoire parent insuffisantes")


def _open_db_file(path: Path) -> sqlite3.Connection:
    """Ouvre une connexion SQLite vers un fichier en appliquant les gardes de sécurité.

    - Refuse les symlinks (TOCTOU) sur le fichier et tous ses répertoires ancêtres.
    - Refuse les chemins pointant vers des répertoires existants.
    - Crée les répertoires ancêtres manquants avec umask 0o077 (droits 0o700).
    - Préserve intacts les répertoires pré-existants (ex: CWD '.', /tmp) sans les modifier
      (confiance opérateur, évite tout effet de bord destructeur ou DoS).
    - Re-vérifie les symlinks après mkdir (fermeture de la fenêtre TOCTOU).
    - Crée le fichier avec mode 0o600 si inexistant.
    - Vérifie et confirme les permissions après création (fail-closed).
    - Positionne journal_mode=DELETE (pas de sidecar -wal/-shm).
    - Maintient umask 0o077 autour de sqlite3.connect() pour réduire la fenêtre
      TOCTOU résiduelle (le dernier _assert_not_symlink() et connect() ne sont
      pas atomiques sans O_NOFOLLOW, acceptable en config opérateur).
    """
    _assert_not_symlink(path)
    if path.is_dir():
        logger.debug("Chemin de base de données pointe vers un répertoire : %s", path.name)
        raise IsADirectoryError(
            "Chemin de base de données invalide : pointe vers un répertoire existant"
        )
    _check_regular_file(path)

    # Identifier les répertoires ancêtres inexistants avant mkdir
    missing_parents = [parent for parent in path.parents if not parent.exists()]

    old_umask = os.umask(0o077)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _harden_created_parents(missing_parents)
        _assert_not_symlink(path)
        if not path.exists():
            path.touch(mode=_SECURE_FILE_MODE, exist_ok=True)
        else:
            _check_regular_file(path)

        _assert_not_symlink(path)
        _apply_secure_permissions(path)
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = DELETE;")
        return conn
    finally:
        os.umask(old_umask)


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Ouvre une connexion SQLite sécurisée avec foreign keys activées et row_factory.

    Active systématiquement `PRAGMA foreign_keys = ON;` (invariant de sécurité).

    Mode en mémoire ':memory:' :
    Réservé exclusivement aux tests unitaires en mémoire. Chaque appel à
    get_connection(':memory:') produit une base isolée éphémère sans schéma.
    Pour y déployer le schéma, exécuter conn.executescript(SCHEMA_SQL) sur la même
    connexion. Ne pas utiliser init_db(':memory:') car la connexion serait aussitôt
    fermée et le schéma perdu. Pour les tests d'intégration, privilégier une base
    sur fichier temporaire.
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


def _verify_schema(conn: sqlite3.Connection) -> None:
    """Vérifie l'intégrité et la conformité du schéma de la base SQLite.

    Valide structurellement et comportementalement la présence des tables obligatoires,
    des contraintes ON DELETE CASCADE, de la contrainte UNIQUE(project_id, env, name)
    et de la contrainte CHECK(status IN ('vaulte', 'rote')).
    Lève RuntimeError si le schéma est manquant ou dégradé (fail-closed).
    """
    cursor = conn.cursor()
    # 1. Tables obligatoires
    tables = {
        row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    }
    required_tables = {"projects", "api_keys", "secrets"}
    if not required_tables.issubset(tables):
        raise RuntimeError("Schéma de base de données non conforme : tables manquantes.")

    # 2. Clés étrangères ON DELETE CASCADE (requêtes statiques sans f-string SQL)
    for pragma_sql, tbl in (
        ("PRAGMA foreign_key_list(api_keys);", "api_keys"),
        ("PRAGMA foreign_key_list(secrets);", "secrets"),
    ):
        assert tbl in ("api_keys", "secrets")
        fk_rows = cursor.execute(pragma_sql).fetchall()
        has_cascade = any(row[2] == "projects" and row[6].upper() == "CASCADE" for row in fk_rows)
        if not has_cascade:
            raise RuntimeError(
                f"Schéma de base de données non conforme : ON DELETE CASCADE manquant sur {tbl}."
            )

    # 3. Contrainte UNIQUE(project_id, env, name) sur secrets (zéro f-string SQL)
    secrets_indexes = cursor.execute("PRAGMA index_list(secrets);").fetchall()
    for idx in secrets_indexes:
        idx_name = idx[1]
        if not isinstance(idx_name, str) or not idx_name.isidentifier():
            raise RuntimeError("Schéma de base de données non conforme : nom d'index invalide.")

    secrets_table_row = cursor.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?;",
        ("secrets",),
    ).fetchone()
    table_sql = (secrets_table_row[0] or "").lower() if secrets_table_row else ""
    has_table_unique = "unique" in table_sql and "project_id" in table_sql

    unique_indexes = cursor.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name=?;",
        ("secrets",),
    ).fetchall()
    has_explicit_unique_idx = any(
        row[1] and "unique" in row[1].lower() and "project_id" in row[1].lower()
        for row in unique_indexes
    )
    has_pragma_unique = any(idx[2] == 1 for idx in secrets_indexes)

    if not (has_pragma_unique and (has_table_unique or has_explicit_unique_idx)):
        raise RuntimeError(
            "Schéma de base de données non conforme : UNIQUE(project_id, env, name) manquant."
        )

    # 4. Vérification comportementale des contraintes (CHECK, UNIQUE, CASCADE)
    _verify_schema_behavior(conn)


def _verify_schema_behavior(conn: sqlite3.Connection) -> None:
    """Vérifie comportementalement les contraintes d'intégrité (CHECK, UNIQUE, CASCADE).

    Exécutée au sein d'un SAVEPOINT systématiquement annulé (non destructeur).
    """
    conn.execute("SAVEPOINT schema_behavioral_verify_sp;")
    try:
        conn.execute(
            "INSERT OR IGNORE INTO projects (id, created_at) "
            "VALUES ('__schema_probe_proj__', '2026-01-01');"
        )

        # Test comportemental du CHECK sur status
        chk_enforced = False
        try:
            conn.execute(
                "INSERT INTO secrets ("
                "project_id, env, name, encrypted_value, status, fingerprint, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "__schema_probe_proj__",
                    "dev",
                    "PROBE_CHK",
                    "val",
                    "invalid_probe_status",
                    "fp",
                    "2026-01-01",
                    "2026-01-01",
                ),
            )
        except sqlite3.IntegrityError:
            chk_enforced = True
        if not chk_enforced:
            raise RuntimeError(
                "Schéma de base de données non conforme : contrainte CHECK de statut inopérante."
            )

        # Test comportemental de la contrainte UNIQUE(project_id, env, name)
        try:
            conn.execute(
                "INSERT INTO secrets ("
                "project_id, env, name, encrypted_value, status, fingerprint, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "__schema_probe_proj__",
                    "dev",
                    "PROBE_UQ",
                    "val1",
                    "vaulte",
                    "fp1",
                    "2026-01-01",
                    "2026-01-01",
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise RuntimeError(
                "Schéma de base de données non conforme : collision ou intégrité non respectée."
            ) from exc
        uq_enforced = False
        try:
            conn.execute(
                "INSERT INTO secrets ("
                "project_id, env, name, encrypted_value, status, fingerprint, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "__schema_probe_proj__",
                    "dev",
                    "PROBE_UQ",
                    "val2",
                    "vaulte",
                    "fp2",
                    "2026-01-01",
                    "2026-01-01",
                ),
            )
        except sqlite3.IntegrityError:
            uq_enforced = True
        if not uq_enforced:
            raise RuntimeError(
                "Schéma de base de données non conforme : contrainte UNIQUE inopérante."
            )

        # Test comportemental de ON DELETE CASCADE
        conn.execute("DELETE FROM projects WHERE id='__schema_probe_proj__';")
        cur = conn.execute("SELECT COUNT(*) FROM secrets WHERE project_id='__schema_probe_proj__';")
        if cur.fetchone()[0] != 0:
            raise RuntimeError(
                "Schéma de base de données non conforme : ON DELETE CASCADE inopérant."
            )
    finally:
        conn.execute("ROLLBACK TO schema_behavioral_verify_sp;")
        conn.execute("RELEASE schema_behavioral_verify_sp;")


def init_db(db_path: Path | str | None = None) -> None:
    """Initialise à froid la base de données SQLite en créant le schéma complet.

    Exécute le script DDL créant `projects`, `api_keys`, `secrets` et leurs index,
    puis vérifie la conformité et l'intégrité du schéma via `_verify_schema()`.
    Réutilise `get_connection()` pour garantir les mêmes gardes de sécurité
    (symlink, umask, permissions, journal_mode=DELETE).
    Lève RuntimeError si le schéma résultant est incomplet ou dégradé.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.executescript(SCHEMA_SQL)
            _verify_schema(conn)
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
    if status not in _ALLOWED_STATUSES:
        logger.debug("Statut de secret invalide reçu : %r", status)
        raise ValueError("Statut de secret invalide.")
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
    if status not in _ALLOWED_STATUSES:
        logger.debug("Statut de secret invalide reçu : %r", status)
        raise ValueError("Statut de secret invalide.")
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
