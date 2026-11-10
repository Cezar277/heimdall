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
- Chiffrement par enveloppe (ticket #70) : `secrets.encrypted_value` contient
  la valeur chiffrée par une DEK propre au secret et `secrets.encrypted_dek`
  contient cette DEK chiffrée par la KEK. Les deux colonnes ne reçoivent que
  des jetons base64 (jamais de clair). `encrypted_dek` est nullable pour les
  lignes héritées de #25/#62, chiffrées directement par la KEK ; les nouvelles
  lignes via `SqliteSecretStore` renseignent toujours les deux blobs.
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
  - Linux : ouverture par descripteur épinglé `O_NOFOLLOW|O_CREAT` et connexion
    SQLite via `/dev/fd/N` — SQLite ouvre l'inode exact déjà validé (fstat/fchmod),
    la fenêtre TOCTOU de `sqlite3.connect()` est fermée. POSIX sans `/dev/fd`
    fiable : repli par chemin + re-vérification post-ouverture.
  - Re-vérification APRÈS l'ouverture SQLite (symlink, fichier régulier, identité
    `st_dev`/`st_ino`) : toute substitution persistante du chemin ferme la
    connexion (fail-closed).
  - `journal_mode=DELETE` forcé pour éviter la création de fichiers sidecar
    `-wal`/`-shm`/`-journal` en permissions larges.
- Confinement d'environnement : POSIX uniquement (Linux, macOS, BSD). Sous Windows (nt),
  les permissions 0o600 ne sont pas applicables nativement via os.chmod
  (refus fail-closed via RuntimeError, invariants 1/10).
"""

import errno
import hmac
import logging
import os
import re
import sqlite3
import stat as stat_module
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

if TYPE_CHECKING:
    from heimdall.vault.crypto import VaultCipher

logger = logging.getLogger(__name__)


class _SessionConnection(sqlite3.Connection):
    """Connexion SQLite portant l'indicateur de session `db_session`.

    `sqlite3.Connection` n'est ni extensible ni faiblement référençable : le
    `factory` de `connect()` permet de porter l'attribut `_heimdall_session`
    directement sur l'objet, sans registre global d'`id()` (impossible de
    reclasser une connexion périmée après un recyclage d'`id` après GC).
    """

    _heimdall_session: bool = False


SecretStatus = Literal["vaulte", "rote"]
_ALLOWED_STATUSES: frozenset[str] = frozenset({"vaulte", "rote"})
_SCHEMA_MIGRATION_HINT: str = (
    "Schéma Vault antérieur au ticket #70 : exécuter "
    "`python -m heimdall.vault.init_db` (ou ouvrir la base via "
    "`SqliteSecretStore`) avant de lire un secret."
)


# SQLite stocke les INTEGER sur 64 bits signés : au-delà, le moteur bascule en
# REAL et `kek_version` sortirait du contrat (audit faussé, lectures incohérentes).
MAX_KEK_VERSION: int = 2**63 - 1


def validate_kek_version(version: Any, *, label: str = "Numéro de version de KEK") -> int:
    """Valide qu'un numéro de version de KEK est un entier dans [1, 2**63-1]."""
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"{label} invalide : entier attendu.")
    if version < 1:
        raise ValueError(f"{label} invalide : valeur >= 1 requise.")
    if version > MAX_KEK_VERSION:
        raise ValueError(f"{label} invalide : valeur <= {MAX_KEK_VERSION} requise.")
    return version


class KekVersionError(RuntimeError):
    """Version de KEK illisible ou hors contrat dans la base (intégrité)."""


class KekConcurrencyError(RuntimeError):
    """Écriture conditionnelle sur ``kek_version`` perdante (concurrence)."""


# Mode fichier sécurisé : lecture/écriture propriétaire uniquement (aucun accès groupe/autres).
_SECURE_FILE_MODE: int = 0o600
_SECURE_DIR_MODE: int = 0o700
_DIR_PERM_MASK: int = 0o777
_CONTROL_CHAR_THRESHOLD: int = 0x20
SQLITE_TIMEOUT_SECONDS: float = 0.25

# `/dev/fd/N` (procfs Linux) permet à SQLite d'ouvrir l'inode EXACT déjà validé
# par un descripteur épinglé `O_NOFOLLOW`, fermant la fenêtre TOCTOU de
# `sqlite3.connect()`. Sur les autres POSIX (macOS/BSD), la sémantique de
# `/dev/fd` n'est pas garantie pour une base SQLite (journal adjacent) : repli
# par chemin + re-vérification d'identité.
_FD_DB_CONNECT_SUPPORTED: bool = sys.platform.startswith("linux") and os.path.isdir("/dev/fd")

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
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_key_hash ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    env TEXT NOT NULL,
    name TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    -- DEK chiffrée par la KEK (ticket #70) ; NULL = ligne héritée (#25/#62)
    -- chiffrée directement par la KEK. Les nouvelles lignes renseignent les deux.
    encrypted_dek TEXT,
    -- Version de la KEK ayant enveloppé la DEK (ticket #71).
    kek_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'vaulte',
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT uq_secrets_project_env_name UNIQUE (project_id, env, name),
    CONSTRAINT chk_secrets_status CHECK (status IN ('vaulte', 'rote')),
    CONSTRAINT chk_secrets_kek_version CHECK (kek_version >= 1)
);

CREATE INDEX IF NOT EXISTS idx_secrets_project_env_name ON secrets(project_id, env, name);
CREATE INDEX IF NOT EXISTS idx_secrets_project_fingerprint ON secrets(project_id, fingerprint);

-- Admissions de rate-limiting en fenêtre glissante (tickets #63/#111).
-- Les noms de budgets par clé sont des empreintes HMAC, jamais les clés brutes.
CREATE TABLE IF NOT EXISTS rate_limit_hits (
    name TEXT NOT NULL,
    hit_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_name_at
    ON rate_limit_hits(name, hit_at);
CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_at
    ON rate_limit_hits(hit_at);

-- Ancienne table de fenêtres fixes (lot #63), conservée pour compatibilité
-- des bases existantes : plus aucun code ne la lit ni ne l'écrit.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    name TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at REAL NOT NULL
);

-- Enregistrement du canari de clé HMAC serveur (ticket #116).
-- Détecte tout changement de HEIMDALL_VAULT_SERVER_HMAC_KEY et échoue fail-closed
-- pour empêcher un faux négatif silencieux sur les empreintes existantes.
CREATE TABLE IF NOT EXISTS server_hmac_canary (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    canary TEXT NOT NULL
);

-- Journal d'audit chaîné (ticket #113). Aucune valeur de secret, aucune clé
-- complète : uniquement des métadonnées publiques et une empreinte tronquée.
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    key_id TEXT,
    key_fingerprint TEXT,
    project TEXT,
    peer TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    status_code INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at
    ON audit_events(occurred_at);

-- Point de contrôle de chaîne après purge de rétention (ticket #113).
-- Le premier événement retenu pointe sur `checkpoint_hash` ; la vérification
-- reprend donc à ce point sans charger tout l'historique.
CREATE TABLE IF NOT EXISTS audit_chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    checkpoint_hash TEXT NOT NULL,
    pruned_events INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


def get_iso_timestamp() -> str:
    """Retourne l'horodatage UTC courant au format ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _has_control_characters(value: str) -> bool:
    """Détecte tout caractère de contrôle ASCII (< 0x20) dans une chaîne."""
    return any(ord(c) < _CONTROL_CHAR_THRESHOLD for c in value)


def _is_filesystem_root(value: str) -> bool:
    """Détecte la racine sous toutes ses formes (`/`, `//`, `///`, `/.`, `//.`).

    Ni `Path(v) == Path("/")` ni `os.path.normpath` ne suffisent : `pathlib`
    préserve `//` (POSIX : deux slashes initiaux au sens potentiellement défini
    par l'implémentation, `parts == ('//',)`) et `normpath("//")` renvoie
    `"//"`. Seule l'absence de tout composant réel est fiable (revue v7).

    Le `bool(parts)` écarte `""` et `"."` (`parts == ()`, où `all()` serait
    vacuement vrai) : fonction totale, sûre en réutilisation future sans garde
    d'appel (revue v8).
    """
    parts = Path(value).parts
    return bool(parts) and all(part in ("/", "//") for part in parts)


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
    if _has_control_characters(stripped):
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


def default_db_path() -> Path:
    """Retourne le chemin de base par défaut, hors dépôt et assaini (remarques 1 v4/v5).

    - `$XDG_DATA_HOME` est utilisé s'il est défini, absolu, distinct de la
      racine sous toutes ses formes (`/`, `//`, `///`, `/.` — `pathlib` et
      `normpath` préservent `//`, seule l'absence de composant réel est fiable,
      revue v7), sans segment `..` et sans caractère de contrôle (spec XDG Base
      Directory : un chemin relatif est invalide). Toute valeur vide, blanche,
      relative, racine, porteuse de caractères de contrôle ou de `..` est
      ignorée au profit de `~/.local/share` :
      - contrôles → pas d'injection de ligne de log par basename (invariant 8) ;
      - `..` → le défaut reste confiné sous le répertoire annoncé, jamais
        `/tmp/a/../../etc/heimdall/vault.db` (remarque 1 de la revue v5) ;
      - `/`, `//`, `///`, `/.` → jamais de base écrite directement sous la
        racine (revues v6/v7) ;
      - relatif → pas de dépendance au CWD.
    - Le chemin final est normalisé lexicalement (canonicalisation sans suivi de
      symlink), sans jamais sortir de la base retenue.

    Le défaut n'est plus CWD-relatif : deux répertoires de travail convergent
    vers la même base, plus de cloisonnement silencieux entre processus.
    """
    xdg_data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    if (
        xdg_data_home
        and Path(xdg_data_home).is_absolute()
        and not _is_filesystem_root(xdg_data_home)
        and ".." not in Path(xdg_data_home).parts
        and not _has_control_characters(xdg_data_home)
    ):
        base_dir = Path(xdg_data_home)
    else:
        base_dir = Path.home() / ".local" / "share"
    return Path(os.path.normpath(str(base_dir / "heimdall" / "vault.db")))


# Résolu une fois à l'import (changer XDG_DATA_HOME requiert un redémarrage du processus).
DEFAULT_DB_PATH: Path = default_db_path()


def resolve_db_path(db_path: Path | str | None = None) -> Path | str:
    """Résout et valide le chemin SQLite (argument, variable d'environnement ou défaut).

    Ordre de priorité :
    1. Argument explicite `db_path` (les tests peuvent demander ':memory:')
    2. Variable d'environnement `HEIMDALL_VAULT_DB_PATH`
    3. `DEFAULT_DB_PATH` (hors dépôt : `$XDG_DATA_HOME/heimdall/vault.db`,
       sinon `~/.local/share/heimdall/vault.db`), validé comme tout autre chemin
       (vide/contrôles/répertoire refusés — remarque 1 de la revue v4).

    Comportement CWD (remarque 1 de revue, garde centrale revue v6) :
    Cette fonction reste neutre : un chemin relatif est renvoyé tel quel (testé
    comme tel). L'ouverture refuse ensuite tout relatif de façon centrale dans
    `_open_db_file()` (fail-closed) : `get_connection()`, `db_session()` et
    `init_db()` n'ouvrent donc jamais un fichier sur un chemin relatif, quel que
    soit l'appelant. Les POINTS D'ENTRÉE — CLI `init_db` et serveur `create_app`
    — exigent en plus un chemin ABSOLU en amont pour des messages et codes
    dédiés (exit 2 / ValueError) : un chemin relatif dépend du répertoire
    courant, donc la CLI lancée depuis un autre répertoire aurait créé une base
    différente de celle du serveur, sans aucune erreur. Le défaut
    (XDG / `~/.local/share`) est toujours absolu.

    Mode en mémoire ':memory:' :
    Réservé aux tests unitaires, via l'ARGUMENT EXPLICITE uniquement. Chaque appel à
    get_connection(':memory:') ouvre une base en mémoire vierge et isolée ; initialiser
    le schéma sur la connexion avant toute requête. La variable
    `HEIMDALL_VAULT_DB_PATH=:memory:` est REFUSÉE (ValueError, fail-closed — remarque 2
    de la revue v4) : une base éphémère silencieuse viole l'esprit de l'invariant 11
    et diffère les échecs en `no such table`. La CLI init_db refuse ':memory:' (code 2).
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
            raise ValueError(
                "Le mode ':memory:' est interdit via HEIMDALL_VAULT_DB_PATH : "
                "base éphémère silencieuse, réservé aux tests via argument explicite."
            )
        return Path(validated)
    return Path(validate_db_path(str(DEFAULT_DB_PATH)))


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
    en production : refus fail-closed immédiat (invariants 1/10).
    """
    if os.name == "nt":
        raise RuntimeError(
            "Environnement non supporté : système POSIX requis pour sécuriser les permissions."
        )
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


def _stat_no_follow(path: Path) -> os.stat_result:
    """`stat` sans suivi de lien symbolique, erreur générique sans chemin (anti-fuite)."""
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError as exc:
        logger.debug("Impossible de stat le chemin %s : %s", path.name, exc.__class__.__name__)
        raise PermissionError("Chemin de base de données refusé : accès impossible") from exc


def _check_regular_file(path: Path) -> None:
    """Vérifie que le chemin est un fichier régulier non lié (refus FIFO/socket/device/hardlink).

    Absence tolérée (création à suivre). S'appuie exclusivement sur `lstat`
    (`follow_symlinks=False`) : plus de `path.exists()` préalable qui suivrait un
    symlink avant la vérification (remarque 2 de revue) — un lien symbolique
    pendant n'est donc plus considéré comme un fichier absent.
    """
    try:
        stat_res = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.debug("Impossible de stat le chemin %s : %s", path.name, exc.__class__.__name__)
        raise PermissionError("Chemin de base de données refusé : accès impossible") from exc
    if not stat_module.S_ISREG(stat_res.st_mode):
        logger.debug("Chemin de base de données non régulier : %s", path.name)
        raise PermissionError("Chemin de base de données refusé : fichier non régulier interdit")
    if stat_res.st_nlink != 1:
        logger.debug("Chemin de base de données avec liens physiques multiples : %s", path.name)
        raise PermissionError("Chemin de base de données refusé : lien physique interdit")


def _harden_created_parents(missing_parents: list[Path]) -> None:
    """Durcit uniquement les répertoires effectivement créés par mkdir (POSIX).

    Les répertoires pré-existants (ex: CWD '.', /tmp) relèvent de la confiance
    opérateur et ne sont jamais modifiés pour éviter tout effet de bord destructeur.

    Chaque répertoire est ouvert par descripteur épinglé
    (`O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, jamais de suivi de lien) : si le chemin a
    été échangé contre un symlink entre `mkdir` et le durcissement, l'ouverture
    échoue (ELOOP) — refus fail-closed AVANT tout changement de permission
    (remarque 2 de la revue v5, course `mkdir` → `chmod`). Le `fchmod 0o700` et
    la vérification du mode s'appliquent au descripteur (`fchmod`/`fstat`),
    jamais au chemin : aucun chmod ne peut atteindre une cible substituée.
    """
    if os.name == "nt":
        if missing_parents:
            raise RuntimeError(
                "Environnement non supporté : système POSIX requis pour sécuriser les répertoires."
            )
        return
    dir_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    for new_dir in missing_parents:
        try:
            dir_fd = os.open(new_dir, dir_flags)
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.debug(
                "Répertoire parent non sûr (lien ou accès refusé) %s : %s",
                new_dir.name,
                exc.__class__.__name__,
            )
            raise PermissionError(
                "Impossible de sécuriser les permissions du répertoire parent"
            ) from exc
        try:
            if not stat_module.S_ISDIR(os.fstat(dir_fd).st_mode):
                logger.debug("Répertoire parent non régulier : %s", new_dir.name)
                raise PermissionError(
                    "Impossible de sécuriser les permissions du répertoire parent"
                )
            try:
                os.fchmod(dir_fd, _SECURE_DIR_MODE)
            except OSError as exc:
                logger.debug(
                    "Échec du fchmod 0o700 sur %s : %s",
                    new_dir.name,
                    exc.__class__.__name__,
                )
                raise PermissionError(
                    "Impossible de sécuriser les permissions du répertoire parent"
                ) from exc
            mode = os.fstat(dir_fd).st_mode & _DIR_PERM_MASK
            if mode != _SECURE_DIR_MODE:
                logger.debug(
                    "Permissions du répertoire parent insuffisantes sur %s",
                    new_dir.name,
                )
                raise PermissionError("Permissions du répertoire parent insuffisantes")
        finally:
            os.close(dir_fd)


def _open_db_file(path: Path) -> sqlite3.Connection:
    """Ouvre une connexion SQLite vers un fichier en appliquant les gardes de sécurité.

    - Refuse les chemins relatifs (garde centrale, revue v6) : un chemin relatif
      dépend du répertoire courant du processus, donc un appel direct tel que
      `get_connection("relative.db")` créerait deux bases silencieuses selon le
      CWD (perte/cloisonnement). Seul un chemin absolu est accepté ici (le mode
      `:memory:`, réservé aux tests, est court-circuité en amont dans
      `get_connection` et n'atteint jamais cette fonction) ; les points
      d'entrée CLI/serveur conservent leurs propres refus explicites
      (exit 2 / ValueError) pour des messages dédiés.
    - Refuse les symlinks (TOCTOU) sur le fichier et tous ses répertoires ancêtres.
    - Refuse les chemins pointant vers des répertoires existants.
    - Crée les répertoires ancêtres manquants avec umask 0o077 (droits 0o700).
    - Préserve intacts les répertoires pré-existants (ex: CWD '.', /tmp) sans les modifier
      (confiance opérateur, évite tout effet de bord destructeur ou DoS).
    - Durcit les répertoires créés via descripteur épinglé (`O_NOFOLLOW|O_DIRECTORY`
      + `fchmod`/`fstat`) et jamais via le chemin : la course `mkdir` → `chmod` est
      fermée (refus ELOOP avant tout changement de permission, remarque 2 v5).
    - Re-vérifie les symlinks après mkdir (fermeture de la fenêtre TOCTOU).
    - Crée le fichier avec mode 0o600 si inexistant.
    - Vérifie et confirme les permissions après création (fail-closed).
    - Positionne journal_mode=DELETE (pas de sidecar -wal/-shm).
    - Maintient umask 0o077 autour de l'ouverture : couvre les répertoires
      intermédiaires créés par mkdir(parents=True) et les sidecars SQLite écrits
      pendant l'initialisation. Umask global au processus (course possible avec
      des threads, uniquement dans le sens restrictif → fail-safe), restaurée
      en `finally`.
    - Linux : ouverture par descripteur épinglé (`_connect_pinned_fd`) — le
      chemin est ouvert en `O_NOFOLLOW|O_CREAT` puis SQLite ouvre ce même
      descripteur via `/dev/fd/N`, donc l'inode EXACT déjà validé. La fenêtre
      TOCTOU de `sqlite3.connect()` (qui n'expose ni O_NOFOLLOW ni le fd) est
      fermée. POSIX sans `/dev/fd` fiable : repli `_connect_by_path`.
    - Re-vérification APRÈS l'ouverture SQLite (défense en profondeur TOCTOU) :
      symlink, fichier régulier puis identité (st_dev, st_ino) avec l'inode
      réellement ouvert. Une substitution persistante du chemin dans la fenêtre
      d'ouverture est détectée, la connexion est fermée puis l'erreur remontée
      (fail-closed).
    """
    if os.name == "nt":
        # Windows strictement hors cible de déploiement en production (invariants 1/10) :
        # refus fail-closed immédiat, avant toute création de fichier ou de répertoire.
        raise RuntimeError(
            "Environnement non supporté : système POSIX requis pour sécuriser les permissions."
        )
    if not path.is_absolute():
        # Garde centrale (revue v6) : `resolve_db_path()` reste neutre et renvoie
        # un relatif tel quel, mais aucun fichier n'est jamais ouvert sur un
        # chemin relatif — le CWD ne doit pas décider quelle base est utilisée.
        # Message générique sans reflet du chemin (invariant anti-fuite).
        logger.debug("Chemin de base de données relatif refusé : %s", path.name)
        raise ValueError(
            "Chemin de base de données relatif interdit : fournir un chemin absolu "
            "(un chemin relatif dépend du répertoire courant)."
        )
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
        if _FD_DB_CONNECT_SUPPORTED:
            conn, opened_identity = _connect_pinned_fd(path)
        else:
            conn, opened_identity = _connect_by_path(path)

        try:
            _verify_opened_connection(path, conn, opened_identity)
        except BaseException:
            conn.close()
            raise
        return conn
    finally:
        os.umask(old_umask)


def _connect_pinned_fd(path: Path) -> tuple[sqlite3.Connection, tuple[int, int]]:
    """Ouvre la base par descripteur épinglé puis `sqlite3.connect("/dev/fd/N")` (Linux).

    `os.open(O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK)` est atomique vis-à-vis des
    symlinks et ne bloque pas sur un FIFO. Toutes les gardes (fichier régulier,
    `st_nlink == 1`, fchmod 0o600 vérifié) s'appliquent via `fstat`/`fchmod` au
    descripteur, et SQLite ouvre ce MÊME inode : validation et usage portent sur
    le même objet noyau, sans fenêtre TOCTOU.

    Retourne la connexion et l'identité (st_dev, st_ino) du descripteur épinglé
    pour la re-vérification post-ouverture du chemin.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, _SECURE_FILE_MODE)
    except OSError as exc:
        logger.debug(
            "Ouverture sécurisée impossible pour %s : %s", path.name, exc.__class__.__name__
        )
        if exc.errno == errno.ELOOP:
            raise PermissionError(
                "Chemin de base de données refusé : lien symbolique interdit"
            ) from exc
        raise PermissionError("Chemin de base de données refusé : accès impossible") from exc
    try:
        fd_stat = os.fstat(fd)
        if not stat_module.S_ISREG(fd_stat.st_mode):
            logger.debug("Chemin de base de données non régulier : %s", path.name)
            raise PermissionError(
                "Chemin de base de données refusé : fichier non régulier interdit"
            )
        if fd_stat.st_nlink != 1:
            logger.debug("Chemin de base de données avec liens physiques multiples : %s", path.name)
            raise PermissionError("Chemin de base de données refusé : lien physique interdit")
        try:
            os.fchmod(fd, _SECURE_FILE_MODE)
        except OSError as exc:
            logger.debug("Échec du fchmod 0o600 sur %s : %s", path.name, exc.__class__.__name__)
            raise PermissionError(
                "Impossible de sécuriser les permissions de la base SQLite"
            ) from exc
        applied_mode = os.fstat(fd).st_mode & _DIR_PERM_MASK
        if applied_mode != _SECURE_FILE_MODE:
            logger.debug(
                "Permissions insuffisantes sur %s : attendu 0o600, obtenu %s",
                path.name,
                oct(applied_mode),
            )
            raise PermissionError(
                "Permissions de la base SQLite insuffisantes : attendu 0o600, "
                f"obtenu {oct(applied_mode)}"
            )
        conn = sqlite3.connect(
            f"/dev/fd/{fd}", timeout=SQLITE_TIMEOUT_SECONDS, factory=_SessionConnection
        )
        opened_identity = (fd_stat.st_dev, fd_stat.st_ino)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    return conn, opened_identity


def _connect_by_path(path: Path) -> tuple[sqlite3.Connection, tuple[int, int]]:
    """Repli POSIX (sans `/dev/fd` fiable) : gardes chemin, chmod, `connect()`, identité.

    `sqlite3` n'expose ni O_NOFOLLOW ni le descripteur sous-jacent : la fenêtre
    entre la dernière vérification et `connect()` n'est pas atomique. L'empreinte
    (st_dev, st_ino) relevée juste avant l'ouverture est comparée après
    (`_verify_opened_connection`) pour détecter une substitution persistante.

    RÉSIDUEL ACCEPTÉ (revue v5, option « accepter comme résiduel documenté ») :
    une substitution transitoire, restaurée avant la re-vérification, n'est pas
    détectable sans ouverture par descripteur. Ce repli ne sert qu'aux POSIX sans
    `/dev/fd` fiable (macOS/BSD) ; le chemin d'entrée est opérateur (CLI/env), non
    contrôlé par une entrée LLM. Linux utilise `_connect_pinned_fd`, sans fenêtre.
    """
    _assert_not_symlink(path)
    if not path.exists():
        path.touch(mode=_SECURE_FILE_MODE, exist_ok=True)
    else:
        _check_regular_file(path)

    _assert_not_symlink(path)
    _apply_secure_permissions(path)
    pre_open_stat = _stat_no_follow(path)
    conn = sqlite3.connect(str(path), timeout=SQLITE_TIMEOUT_SECONDS, factory=_SessionConnection)
    return conn, (pre_open_stat.st_dev, pre_open_stat.st_ino)


def _verify_opened_connection(
    path: Path,
    conn: sqlite3.Connection,
    opened_identity: tuple[int, int],
) -> None:
    """Vérifie après ouverture que le chemin est sain et pointe l'inode attendu (TOCTOU).

    - `journal_mode=DELETE` positionné (pas de sidecar -wal/-shm).
    - Symlink et type de fichier re-vérifiés via lstat (aucun suivi de lien).
    - Identité (st_dev, st_ino) du chemin comparée à l'inode réellement ouvert.

    Lève PermissionError générique (sans chemin) ; la connexion est fermée par l'appelant.
    """
    conn.execute("PRAGMA journal_mode = DELETE;")
    _assert_not_symlink(path)
    _check_regular_file(path)
    post_open_stat = _stat_no_follow(path)
    if (post_open_stat.st_dev, post_open_stat.st_ino) != opened_identity:
        raise PermissionError(
            "Chemin de base de données refusé : substitution détectée pendant l'ouverture"
        )


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
        conn = sqlite3.connect(resolved, timeout=SQLITE_TIMEOUT_SECONDS, factory=_SessionConnection)

    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session(db_path: Path | str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Gestionnaire de contexte pour transaction SQLite sûre (commit/rollback et fermeture)."""
    conn = get_connection(db_path)
    # Marque la connexion : sa transaction appartient à l'appelant (LOW revue).
    if isinstance(conn, _SessionConnection):
        conn._heimdall_session = True
    try:
        with conn:
            yield conn
    finally:
        conn.close()


@contextmanager
def _write_transaction(conn: sqlite3.Connection) -> Generator[None, None, None]:
    """Exécute un bloc d'écriture sans briser l'atomicité de l'appelant (#71 LOW).

    Les helpers ``update_secret``, ``reenvelope_secret`` et
    ``rotate_secrets_kek`` sont appelés depuis un ``with db_session(...)`` déjà
    transactionnel. Un ``with conn:`` imbriqué commiterait prématurément la
    transaction de l'appelant : on utilise donc un ``SAVEPOINT`` lorsque la
    connexion appartient à une session ``db_session`` (ou qu'une transaction
    est déjà ouverte). Le savepoint permet d'annuler uniquement les écritures
    du helper en cas d'erreur, sans commiter le reste : ``db_session`` garde
    l'exclusivité du commit/rollback, y compris pour plusieurs helpers chaînés
    dans la même session. Hors session (appel direct), le helper possède la
    transaction et la valide ou l'annule à sa sortie.
    """
    in_session = getattr(conn, "_heimdall_session", False)
    if not in_session and not conn.in_transaction:
        # Appel direct : le helper possède une transaction exclusive complète.
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        return

    if in_session and not conn.in_transaction:
        # Ouvre la transaction de session (verrou d'écriture) avant le savepoint.
        conn.execute("BEGIN IMMEDIATE")
    conn.execute("SAVEPOINT heimdall_write")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK TO SAVEPOINT heimdall_write")
        conn.execute("RELEASE SAVEPOINT heimdall_write")
        raise
    else:
        conn.execute("RELEASE SAVEPOINT heimdall_write")


class DatabaseUnavailableError(Exception):
    """Stockage indisponible (contention ou panne), sans détail sensible."""


@contextmanager
def runtime_db_session(db_path: Path | str) -> Generator[sqlite3.Connection, None, None]:
    """Traduit les pannes DB du serveur ; préserve les erreurs de programmation/intégrité.

    La session de bas niveau reste disponible pour les outils d'administration.
    Ouverture, transaction, commit et fermeture sont tous couverts ici.
    """
    try:
        with db_session(db_path) as conn:
            yield conn
    except (sqlite3.IntegrityError, sqlite3.ProgrammingError):
        raise
    except (sqlite3.DatabaseError, OSError):
        raise DatabaseUnavailableError("Stockage temporairement indisponible.") from None


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
    required_tables = {
        "projects",
        "api_keys",
        "secrets",
        "rate_limit_hits",
        "audit_events",
        "audit_chain_state",
    }
    if not required_tables.issubset(tables):
        raise RuntimeError("Schéma de base de données non conforme : tables manquantes.")

    # 1bis. Colonne d'enveloppe de DEK (ticket #70) : les bases existantes sont
    # migrées par `_ensure_secret_envelope_column` avant cette vérification.
    secret_columns = {
        str(row[1]) for row in cursor.execute("PRAGMA table_info(secrets);").fetchall()
    }
    required_secret_columns = {
        "project_id",
        "env",
        "name",
        "encrypted_value",
        "encrypted_dek",
        "kek_version",
        "status",
        "fingerprint",
        "created_at",
        "updated_at",
    }
    missing_columns = sorted(required_secret_columns - secret_columns)
    if missing_columns:
        raise RuntimeError(
            "Schéma de base de données non conforme : colonne(s) manquante(s) "
            f"dans secrets ({', '.join(missing_columns)})."
        )

    # 2. Clés étrangères ON DELETE CASCADE (requêtes statiques sans f-string SQL)
    for pragma_sql, tbl in (
        ("PRAGMA foreign_key_list(api_keys);", "api_keys"),
        ("PRAGMA foreign_key_list(secrets);", "secrets"),
    ):
        if tbl not in ("api_keys", "secrets"):
            raise RuntimeError("Schéma de base de données non conforme : nom de table invalide.")
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
    probe_proj = f"__schema_probe_{uuid4().hex}__"
    probe_chk = f"PROBE_CHK_{uuid4().hex}"
    probe_uq = f"PROBE_UQ_{uuid4().hex}"

    conn.execute("SAVEPOINT schema_behavioral_verify_sp;")
    try:
        conn.execute(
            "INSERT OR IGNORE INTO projects (id, created_at) VALUES (?, ?);",
            (probe_proj, "2026-01-01"),
        )

        # Une empreinte ne peut jamais désigner deux clés/projets.
        probe_hash = f"schema_probe_hash_{uuid4().hex}"
        create_api_key(conn, f"probe_key_{uuid4().hex}", probe_proj, probe_hash)
        try:
            create_api_key(conn, f"probe_key_{uuid4().hex}", probe_proj, probe_hash)
        except sqlite3.IntegrityError:
            pass
        else:
            raise RuntimeError(
                "Schéma de base de données non conforme : UNIQUE(key_hash) manquant."
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
                    probe_proj,
                    "dev",
                    probe_chk,
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

        # Test comportemental du CHECK sur kek_version (ticket #71)
        chk_kek_enforced = False
        try:
            conn.execute(
                "INSERT INTO secrets ("
                "project_id, env, name, encrypted_value, kek_version, status, fingerprint, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    probe_proj,
                    "dev",
                    f"PROBE_KEK_V_{uuid4().hex}",
                    "val",
                    0,
                    "vaulte",
                    "fp",
                    "2026-01-01",
                    "2026-01-01",
                ),
            )
        except sqlite3.IntegrityError:
            chk_kek_enforced = True
        if not chk_kek_enforced:
            raise RuntimeError(
                "Schéma de base de données non conforme : "
                "contrainte CHECK de kek_version inopérante."
            )

        # Test comportemental de la contrainte UNIQUE(project_id, env, name)
        try:
            conn.execute(
                "INSERT INTO secrets ("
                "project_id, env, name, encrypted_value, status, fingerprint, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    probe_proj,
                    "dev",
                    probe_uq,
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
                    probe_proj,
                    "dev",
                    probe_uq,
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

        # Test comportemental de ON DELETE CASCADE (paramétré en '?')
        conn.execute("DELETE FROM projects WHERE id=?;", (probe_proj,))
        cur = conn.execute(
            "SELECT COUNT(*) FROM secrets WHERE project_id=?;",
            (probe_proj,),
        )
        if cur.fetchone()[0] != 0:
            raise RuntimeError(
                "Schéma de base de données non conforme : ON DELETE CASCADE inopérant."
            )
    finally:
        conn.execute("ROLLBACK TO schema_behavioral_verify_sp;")
        conn.execute("RELEASE schema_behavioral_verify_sp;")


def _ensure_secret_envelope_column(conn: sqlite3.Connection) -> None:
    """Ajoute `secrets.encrypted_dek` aux bases créées avant le ticket #70.

    `CREATE TABLE IF NOT EXISTS` ne modifie pas une table existante : une base
    issue de #25/#62 n'aurait pas la colonne d'enveloppe. La migration est
    idempotente et purement additive (colonne nullable) : les lignes héritées
    restent lisibles via le repli KEK direct de `SqliteSecretStore`, et aucune
    donnée existante n'est réécrite ni supprimée.
    """
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(secrets);").fetchall()}
    if "encrypted_dek" in columns:
        return
    try:
        conn.execute("ALTER TABLE secrets ADD COLUMN encrypted_dek TEXT")
    except sqlite3.OperationalError:
        # Course entre deux workers au démarrage : un autre processus a pu
        # ajouter la colonne entre le PRAGMA et l'ALTER. On ne masque l'erreur
        # que si la colonne est réellement présente ; sinon elle est remontée.
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(secrets);").fetchall()}
        if "encrypted_dek" not in columns:
            raise


def _ensure_secret_kek_version_column(conn: sqlite3.Connection) -> None:
    """Ajoute `secrets.kek_version` aux bases créées avant le ticket #71.

    La migration est idempotente et purement additive : la valeur par défaut
    est 1 pour toutes les lignes existantes.
    """
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(secrets);").fetchall()}
    if "kek_version" in columns:
        return
    try:
        conn.execute(
            "ALTER TABLE secrets ADD COLUMN kek_version INTEGER NOT NULL DEFAULT 1 "
            "CHECK (kek_version >= 1)"
        )
    except sqlite3.OperationalError:
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(secrets);").fetchall()}
        if "kek_version" not in columns:
            raise


def _ensure_server_hmac_canary_table(conn: sqlite3.Connection) -> None:
    """Crée la table server_hmac_canary si elle n'existe pas (idempotent, ticket #116)."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS server_hmac_canary (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            canary TEXT NOT NULL
        );
        """
    )


def get_server_hmac_canary(conn: sqlite3.Connection) -> str | None:
    """Lit le canari de clé HMAC serveur persisté en base (ticket #116)."""
    _ensure_server_hmac_canary_table(conn)
    cursor = conn.execute("SELECT canary FROM server_hmac_canary WHERE id = 1;")
    row = cursor.fetchone()
    return str(row[0]) if row else None


def set_server_hmac_canary(conn: sqlite3.Connection, canary: str) -> None:
    """Enregistre le canari de clé HMAC serveur si absent (ticket #116).

    Vérifie la cohérence si un canari existe déjà pour interdire toute cohabitation silencieuse.
    """
    _ensure_server_hmac_canary_table(conn)
    cursor = conn.execute("SELECT canary FROM server_hmac_canary WHERE id = 1;")
    row = cursor.fetchone()
    if row is not None:
        if not hmac.compare_digest(str(row[0]), canary):
            raise ValueError(
                "La clé HMAC serveur a changé par rapport au canari persistant en base."
            )
        return
    conn.execute(
        "INSERT INTO server_hmac_canary (id, canary) VALUES (1, ?);",
        (canary,),
    )


def init_db(db_path: Path | str | None = None) -> None:
    """Initialise à froid la base de données SQLite en créant le schéma complet.

    Exécute le script DDL créant `projects`, `api_keys`, `secrets` et leurs index,
    applique les migrations additives des colonnes d'enveloppe `encrypted_dek` (#70)
    et de version `kek_version` (#71), puis vérifie la conformité et l'intégrité
    du schéma via `_verify_schema()`. Réutilise `get_connection()` pour garantir
    les mêmes gardes de sécurité (symlink, umask, permissions, journal_mode=DELETE).
    Lève RuntimeError si le schéma résultant est incomplet ou dégradé.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.executescript(SCHEMA_SQL)
            _ensure_secret_envelope_column(conn)
            _ensure_secret_kek_version_column(conn)
            _verify_schema(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Opérations CRUD — Projets
# ---------------------------------------------------------------------------
# Note (revue v6, hors périmètre #62) : aucune borne de longueur n'est imposée
# ici — le stockage de valeurs volumineuses est pinné et assumé (voir
# `test_oversized_inputs_behavior_pinned`). La protection contre le bloat
# disque/DoS relève de la couche API (`max_length` pydantic / `CHECK` à
# l'exposition des routes, tickets #63+) : la couche DB reste neutre et
# réutilisable par les tests.


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


def ensure_project(
    conn: sqlite3.Connection,
    project_id: str,
    created_at: str | None = None,
) -> None:
    """Crée le projet s'il n'existe pas (idempotent, requête paramétrée)."""
    ts = created_at or get_iso_timestamp()
    conn.execute(
        "INSERT OR IGNORE INTO projects (id, created_at) VALUES (?, ?)",
        (project_id, ts),
    )


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
    """Récupère une clé API par son haché de vérification.

    DÉPRÉCIÉ POUR L'AUTHENTIFICATION : l'égalité est évaluée par SQLite, donc
    PAS en temps constant (oracle temporel sur l'existence d'une empreinte).
    Le chemin d'authentification du serveur DOIT utiliser le full-scan à coût
    comparable (`auth.find_api_key_project` + `constant_time_equal`, sans
    `break`) ; cette fonction reste réservée aux accès admin/outils hors
    requête (tests unitaires de la couche DB). Ne jamais l'appeler depuis
    `heimdall/vault/app.py` (garde : test grep dédié).
    """
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
    encrypted_dek: str | None = None,
    kek_version: int = 1,
    status: SecretStatus = "vaulte",
    fingerprint: str = "",
    created_at: str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Crée un secret chiffré dans la base de données.

    `encrypted_dek` est la DEK du secret chiffrée par la KEK (ticket #70).
    `kek_version` est la version de la KEK ayant enveloppé la DEK (ticket #71).
    `None` (défaut) correspond à une ligne héritée (#25/#62) chiffrée
    directement par la KEK : la colonne SQLite vaut alors NULL, jamais la
    chaîne vide. Les nouvelles lignes du store la renseignent toujours. Le
    paramètre `status` est typé `Literal["vaulte", "rote"]` pour une validation
    applicative avant toute requête SQL, en complément du CHECK SQLite. Lève
    sqlite3.IntegrityError si la contrainte d'unicité (project_id, env, name)
    ou la clé étrangère est enfreinte.
    """
    validate_kek_version(kek_version)
    if encrypted_dek == "":
        # Une seule représentation du « sans enveloppe » : NULL. Une chaîne
        # vide explicite est tolérée pour les appelants historiques, mais elle
        # ne doit jamais être persistée telle quelle.
        encrypted_dek = None
    if status not in _ALLOWED_STATUSES:
        logger.debug("Statut de secret invalide rejeté applicativement.")
        raise ValueError("Statut de secret invalide.")
    ts = created_at or get_iso_timestamp()
    up_ts = updated_at or ts
    query = (
        "INSERT INTO secrets ("
        "project_id, env, name, encrypted_value, encrypted_dek, kek_version, status, fingerprint, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    conn.execute(
        query,
        (
            project_id,
            env,
            name,
            encrypted_value,
            encrypted_dek,
            kek_version,
            status,
            fingerprint,
            ts,
            up_ts,
        ),
    )
    return {
        "project_id": project_id,
        "env": env,
        "name": name,
        "encrypted_value": encrypted_value,
        "encrypted_dek": encrypted_dek,
        "kek_version": kek_version,
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
    """Récupère un secret complet (y compris valeur chiffrée) par son triplet.

    Tout accès direct à un fichier existant doit avoir exécuté ``init_db`` (ou
    ouvrir la base via ``SqliteSecretStore``) pour appliquer la migration
    additive de #70/#71. Sur une base antérieure non migrée, la colonne
    ``encrypted_dek`` ou ``kek_version`` manque : une ``RuntimeError`` actionnable
    est levée au lieu de laisser remonter un ``OperationalError`` SQL brut.
    """
    query = (
        "SELECT id, project_id, env, name, encrypted_value, encrypted_dek, kek_version, status, "
        "fingerprint, created_at, updated_at "
        "FROM secrets WHERE project_id = ? AND env = ? AND name = ?"
    )
    try:
        cursor = conn.execute(query, (project_id, env, name))
    except sqlite3.OperationalError as exc:
        if "encrypted_dek" not in str(exc) and "kek_version" not in str(exc):
            raise
        raise RuntimeError(_SCHEMA_MIGRATION_HINT) from None
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
        "SELECT id, project_id, env, name, kek_version, status, fingerprint, "
        "created_at, updated_at "
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
            "SELECT id, project_id, env, name, kek_version, status, fingerprint, "
            "created_at, updated_at "
            "FROM secrets WHERE project_id = ? AND env = ? ORDER BY name ASC"
        )
        cursor = conn.execute(query, (project_id, env))
    else:
        query = (
            "SELECT id, project_id, env, name, kek_version, status, fingerprint, "
            "created_at, updated_at "
            "FROM secrets WHERE project_id = ? ORDER BY env ASC, name ASC"
        )
        cursor = conn.execute(query, (project_id,))
    return [dict(row) for row in cursor.fetchall()]


_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def find_secrets_by_fingerprint(
    conn: sqlite3.Connection,
    project_id: str,
    fingerprint: str,
    env: str | None = None,
) -> list[dict[str, str]]:
    """Trouve les métadonnées des secrets d'un projet correspondant à une empreinte HMAC.

    Permet de vérifier si une valeur ayant fuité est encore présente en production
    sans jamais déchiffrer les valeurs ni exposer l'empreinte au client (ticket #116).
    Retourne uniquement les métadonnées publiques (project, env, name, status).
    """
    if not isinstance(fingerprint, str) or not _HEX_64_PATTERN.match(fingerprint):
        raise ValueError(
            "L'empreinte HMAC doit être une chaîne hexadécimale de 64 caractères minuscules."
        )
    if env is not None:
        query = (
            "SELECT project_id AS project, env, name, status "
            "FROM secrets WHERE project_id = ? AND env = ? AND fingerprint = ? "
            "ORDER BY name ASC"
        )
        cursor = conn.execute(query, (project_id, env, fingerprint))
    else:
        query = (
            "SELECT project_id AS project, env, name, status "
            "FROM secrets WHERE project_id = ? AND fingerprint = ? "
            "ORDER BY env ASC, name ASC"
        )
        cursor = conn.execute(query, (project_id, fingerprint))
    return [dict(row) for row in cursor.fetchall()]


_MAX_SECRET_PAGE_LIMIT = 101
_MAX_SECRET_PAGE_OFFSET = 1_000_000


def validate_secret_page_bounds(limit: int, offset: int) -> None:
    """Refuse fail-closed une pagination hors bornes (défense en profondeur).

    La couche HTTP valide déjà ``limit`` (1..100) et ``offset``
    (0..1 000 000). Ce garde couvre les appelants directs du store et de la
    couche SQLite : la route demande ``limit + 1`` au store pour détecter la
    page suivante, donc la borne interne est 101. En SQLite, ``LIMIT -1``
    signifie « illimité » et un ``OFFSET`` négatif a une sémantique
    surprenante.
    """
    if (
        limit < 1
        or limit > _MAX_SECRET_PAGE_LIMIT
        or offset < 0
        or offset > _MAX_SECRET_PAGE_OFFSET
    ):
        raise ValueError("pagination hors bornes")


def list_secret_page(
    conn: sqlite3.Connection, project_id: str, limit: int, offset: int
) -> list[dict[str, str]]:
    """Lit une page de métadonnées publiques, sans charger les blobs chiffrés."""
    validate_secret_page_bounds(limit, offset)
    rows = conn.execute(
        "SELECT project_id AS project, env, name, status FROM secrets "
        "WHERE project_id = ? ORDER BY env ASC, name ASC LIMIT ? OFFSET ?",
        (project_id, limit, offset),
    ).fetchall()
    return [dict(row) for row in rows]


def count_secrets(conn: sqlite3.Connection, project_id: str | None = None) -> int:
    """Compte les secrets (globalement ou pour un projet), sans exposer de valeur."""
    if project_id is None:
        row = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM secrets WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    return int(row[0]) if row is not None else 0


def delete_all_secrets(conn: sqlite3.Connection) -> int:
    """Supprime tous les secrets (isolation des tests, jamais exposé par l'API)."""
    cursor = conn.execute("DELETE FROM secrets")
    return cursor.rowcount


def update_secret(  # noqa: PLR0913
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
    encrypted_value: str,
    *,
    encrypted_dek: str | None = None,
    kek_version: int | None = None,
    fingerprint: str = "",
    status: SecretStatus = "vaulte",
    updated_at: str | None = None,
) -> bool:
    """Met à jour la valeur chiffrée, l'enveloppe de DEK, la version KEK, l'empreinte et le statut.

    `encrypted_dek=None` conserve l'enveloppe existante pour une mise à jour
    partielle qui ne remplace pas la valeur chiffrée. Si `encrypted_value` est
    chiffrée avec une DEK neuve, les deux blobs doivent provenir du même
    `VaultCipher.encrypt_envelope` et être fournis ensemble ; sinon la ligne
    deviendrait illisible (fail-closed). Une chaîne vide est refusée car elle
    effacerait l'enveloppe. Pour une rotation de KEK sans toucher à la valeur,
    utiliser `reenvelope_secret()` ou `rotate_secrets_kek()` (ticket #71). Le
    paramètre `status` est typé `Literal["vaulte", "rote"]` pour une validation
    applicative avant toute requête SQL.

    Garantie de monotonie : si ``kek_version`` est fournie, elle ne peut pas être
    inférieure à la version actuellement stockée pour la ligne ciblée (anti-downgrade).
    """
    if encrypted_dek == "":
        raise ValueError("Enveloppe de DEK invalide.")
    if status not in _ALLOWED_STATUSES:
        logger.debug("Statut de secret invalide rejeté applicativement.")
        raise ValueError("Statut de secret invalide.")

    with _write_transaction(conn):
        if kek_version is not None:
            validate_kek_version(kek_version)
        row = conn.execute(
            "SELECT kek_version FROM secrets WHERE project_id = ? AND env = ? AND name = ?",
            (project_id, env, name),
        ).fetchone()
        if row is None:
            return False
        raw_v = row["kek_version"]
        if raw_v is not None and (
            not isinstance(raw_v, int)
            or isinstance(raw_v, bool)
            or raw_v < 1
            or raw_v > MAX_KEK_VERSION
        ):
            raise KekVersionError("Version de KEK illisible en base.")
        current_v = raw_v if raw_v is not None else 1
        if kek_version is not None and kek_version < current_v:
            raise ValueError(
                "La nouvelle kek_version ne peut pas être inférieure à la version courante."
            )

        up_ts = updated_at or get_iso_timestamp()
        query = (
            "UPDATE secrets SET "
            "encrypted_value = ?, encrypted_dek = COALESCE(NULLIF(?, ''), encrypted_dek), "
            "kek_version = COALESCE(?, kek_version), "
            "fingerprint = ?, status = ?, updated_at = ? "
            "WHERE project_id = ? AND env = ? AND name = ? AND "
            "COALESCE(kek_version, 1) = ? AND "
            "(? IS NULL OR kek_version IS NULL OR kek_version <= ?)"
        )
        cursor = conn.execute(
            query,
            (
                encrypted_value,
                encrypted_dek,
                kek_version,
                fingerprint,
                status,
                up_ts,
                project_id,
                env,
                name,
                current_v,
                kek_version,
                kek_version,
            ),
        )
        if cursor.rowcount == 0:
            raise KekConcurrencyError("Concurrence détectée sur kek_version.")
        return True


def reenvelope_secret(  # noqa: PLR0913, PLR0917
    conn: sqlite3.Connection,
    project_id: str,
    env: str,
    name: str,
    encrypted_dek: str,
    kek_version: int,
    updated_at: str | None = None,
) -> bool:
    """Met à jour l'enveloppe de DEK et la version de KEK sans toucher à la valeur chiffrée (#71).

    L'ancienne valeur chiffrée (``encrypted_value``) et son empreinte restent
    strictement inchangées en base.

    Garantie de monotonie : ``kek_version`` doit être strictement supérieure
    à la version actuellement stockée pour la ligne ciblée.  Cela empêche
    toute régression d'audit d'un appelant externe (la rotation interne
    ``rotate_secrets_kek`` n'utilise pas cette fonction).
    """
    if not encrypted_dek:
        raise ValueError("Enveloppe de DEK invalide.")
    validate_kek_version(kek_version)

    with _write_transaction(conn):
        # Lire la version courante et imposer la monotonie.
        row = conn.execute(
            "SELECT kek_version FROM secrets WHERE project_id = ? AND env = ? AND name = ?",
            (project_id, env, name),
        ).fetchone()
        if row is None:
            return False

        raw_v = row["kek_version"]
        if raw_v is not None and (
            not isinstance(raw_v, int)
            or isinstance(raw_v, bool)
            or raw_v < 1
            or raw_v > MAX_KEK_VERSION
        ):
            raise KekVersionError("Version de KEK illisible en base.")
        current_v = raw_v if raw_v is not None else 1
        if kek_version <= current_v:
            raise ValueError(
                "La nouvelle kek_version doit être strictement supérieure à la version courante."
            )

        up_ts = updated_at or get_iso_timestamp()
        query = (
            "UPDATE secrets SET "
            "encrypted_dek = ?, kek_version = ?, updated_at = ? "
            "WHERE project_id = ? AND env = ? AND name = ? AND "
            "(kek_version IS NULL OR kek_version < ?)"
        )
        cursor = conn.execute(
            query,
            (encrypted_dek, kek_version, up_ts, project_id, env, name, kek_version),
        )
        if cursor.rowcount == 0:
            raise KekConcurrencyError("Concurrence détectée sur kek_version.")
        return True


def rotate_secrets_kek(
    conn: sqlite3.Connection,
    old_cipher: "VaultCipher",
    new_cipher: "VaultCipher",
    *,
    target_kek_version: int | None = None,
) -> tuple[int, int]:
    """Effectue la rotation transactionnelle de la KEK sur l'ensemble des secrets (#71).

    Règles de sécurité :
    - Exécution strictement transactionnelle : tout réussit ou tout est annulé
      (rollback automatique en cas d'erreur).
    - Seules les DEK sont rechiffrées : les valeurs chiffrées (``encrypted_value``)
      ne sont JAMAIS rechiffrées ni modifiées.
    - La colonne ``kek_version`` est strictement monotone (target_kek_version > max courant).
    - Les DEK déchiffrées en mémoire sont effacées (zeroization) dès leur réenveloppement.
    - L'empreinte auxiliaire (fingerprint) reste strictement inchangée car les
      valeurs ne sont jamais déchiffrées en mémoire lors de la rotation.
    - Échoue fail-closed si un secret hérité (#25/#62) sans enveloppe de DEK est rencontré.
    - Si la base est vide (aucun secret), retourne (0, 1) sans modifier la base,
      target_kek_version étant ignorée car aucune version n'est persistée (#71 LOW 2).

    Returns:
        tuple[int, int]: Un tuple (nombre_de_secrets_reenveloppes, nouvelle_version_kek).
    """
    from heimdall.vault.crypto import VaultCipher, VaultCipherError  # noqa: PLC0415

    if old_cipher.has_same_key_as(new_cipher):
        raise ValueError("L'ancienne et la nouvelle KEK doivent être distinctes.")
    if target_kek_version is not None:
        validate_kek_version(target_kek_version, label="Numéro de version cible")

    with _write_transaction(conn):
        cursor = conn.execute(
            "SELECT id, project_id, env, name, encrypted_dek, kek_version "
            "FROM secrets ORDER BY id ASC"
        )
        secrets_to_rotate = cursor.fetchall()
        if not secrets_to_rotate:
            # Base vide : aucun secret réenveloppé, aucune version n'est persistée.
            # target_kek_version est ignorée pour ne pas faire croire à l'appelant
            # qu'une version non persistée est active (#71 LOW 2).
            return 0, 1

        for r in secrets_to_rotate:
            v = r["kek_version"]
            if v is not None and (
                not isinstance(v, int) or isinstance(v, bool) or v < 1 or v > MAX_KEK_VERSION
            ):
                raise KekVersionError("Version de KEK illisible en base.")

        current_max = max(
            (r["kek_version"] if r["kek_version"] is not None else 1 for r in secrets_to_rotate),
            default=1,
        )
        if target_kek_version is not None:
            if target_kek_version <= current_max:
                raise ValueError(
                    "Le numéro de version cible doit être strictement supérieur "
                    "à la version actuelle."
                )
            new_version = target_kek_version
        else:
            # Fail-closed : l'auto-incrément ne doit jamais dépasser l'INTEGER
            # signé 64 bits de SQLite (sinon bascule en REAL, audit faussé).
            # Limite système, pas une erreur d'usage : KekVersionError => exit 1.
            try:
                new_version = validate_kek_version(current_max + 1)
            except ValueError:
                raise KekVersionError("Version de KEK maximale atteinte en base.") from None

        rotated_count = 0
        now_ts = get_iso_timestamp()

        for row in secrets_to_rotate:
            sec_id = row["id"]
            project_id = str(row["project_id"])
            env = str(row["env"])
            name = str(row["name"])
            enc_dek = row["encrypted_dek"]

            if not enc_dek:
                raise VaultCipherError(
                    "Rotation impossible : un secret hérité sans enveloppe de DEK est présent."
                )

            aad = VaultCipher.aad(project_id, env, name)
            new_wrapped_dek = old_cipher.rewrap_dek(new_cipher, str(enc_dek), aad=aad)

            # Garde anti-downgrade : la ligne doit encore être à une version
            # strictement inférieure à la cible. BEGIN IMMEDIATE sérialise les
            # rotations inter-processus, mais l'écriture conditionnelle prouve
            # l'absence d'écrasement (v3 -> v2) même si la ligne a bougé depuis
            # la lecture — même contrat que update_secret/reenvelope_secret.
            cursor = conn.execute(
                "UPDATE secrets SET encrypted_dek = ?, kek_version = ?, updated_at = ? "
                "WHERE id = ? AND kek_version < ?",
                (new_wrapped_dek, new_version, now_ts, sec_id, new_version),
            )
            if cursor.rowcount != 1:
                raise KekConcurrencyError("Concurrence détectée sur kek_version.")
            rotated_count += 1

        logger.info(
            "Rotation de KEK réussie : %d secret(s) réenveloppé(s) (version %d -> %d).",
            rotated_count,
            current_max,
            new_version,
        )

    return rotated_count, new_version


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
