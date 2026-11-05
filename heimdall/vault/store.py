"""Stockage des secrets du Vault — mémoire chiffrée ou SQLite chiffré (tickets #25/#26/#62).

Deux implémentations interchangeables exposent la même interface asynchrone
``get`` / ``create`` / ``clear`` :

- ``InMemorySecretStore`` : squelette de développement/test. Les valeurs sont
  chiffrées en mémoire (AES-256-GCM) avec une KEK éphémère, jamais conservées
  en clair dans le dictionnaire interne. Ce mode reste mono-processus : chaque
  worker possède son propre état et la garantie 409 n'est pas inter-processus.
  Il ne doit jamais être utilisé pour un déploiement réel.
- ``SqliteSecretStore`` : persistance partagée SQLite avec la contrainte
  ``UNIQUE(project_id, env, name)``, ``PRAGMA foreign_keys=ON`` et des valeurs
  chiffrées AES-256-GCM. La KEK est fournie par l'exploitant et reste hors base ;
  plusieurs workers partagent donc le même état, la même garantie 409 et un
  quota vérifié atomiquement sous ``BEGIN IMMEDIATE``.

Aucun module ne stocke de valeur brute en base, dans les logs ou dans un dict
interne : les valeurs ne sont déchiffrées qu'au moment de la réponse autorisée.
``create`` ne retourne que les métadonnées (jamais le plaintext) ; seule la
lecture autorisée ``get`` déchiffre la valeur. Les valeurs stockées sont
canonicalisées en Unicode NFC (décision #62) : deux écritures visuellement
identiques d'un même secret ne peuvent pas diverger en base.

Chiffrement par enveloppe (ticket #70) : chaque nouveau secret reçoit une DEK
aléatoire de 32 octets. La valeur est chiffrée avec la DEK, puis la DEK est
chiffrée avec la KEK ; les deux blobs sont stockés dans la même ligne
(``encrypted_value`` et ``encrypted_dek``). La lecture déchiffre d'abord la DEK
avec la KEK, puis la valeur avec la DEK. Les lignes héritées de #25/#62, sans
``encrypted_dek``, restent lisibles via le repli KEK direct : aucune migration
destructive n'est nécessaire.
"""

import asyncio
import copy
import logging
import sqlite3
import unicodedata
from pathlib import Path
from typing import Any

from heimdall.vault.crypto import VaultCipher, VaultCipherError
from heimdall.vault.database import (
    MAX_KEK_VERSION,
    DatabaseUnavailableError,
    count_secrets,
    create_secret,
    delete_all_secrets,
    ensure_project,
    get_secret,
    init_db,
    rotate_secrets_kek,
    validate_kek_version,
)
from heimdall.vault.database import runtime_db_session as db_session

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SECRETS: int = 10_000
_DEFAULT_MAX_SECRETS_PER_PROJECT: int = 1_000


class QuotaExceededError(Exception):
    """Exception levée en cas de dépassement de quota (global ou par projet)."""


class SecretStoreError(Exception):
    """Erreur interne de stockage/déchiffrement sans détail sensible."""


def _decrypt_record(
    record: dict[str, Any],
    cipher: VaultCipher,
    project: str,
    env: str,
    name: str,
) -> dict[str, str]:
    """Déchiffre un enregistrement (enveloppe #70 ou ligne héritée) en clair."""
    aad = VaultCipher.aad(project, env, name)
    try:
        encrypted_dek = str(record.get("encrypted_dek") or "")
        if encrypted_dek:
            plaintext = cipher.decrypt_envelope(
                str(record["encrypted_value"]),
                encrypted_dek,
                aad=aad,
            )
        else:
            # Compatibilité #25/#62 : les lignes antérieures au ticket #70
            # étaient chiffrées directement par la KEK, sans colonne de DEK.
            plaintext = cipher.decrypt(str(record["encrypted_value"]), aad=aad)
        value = plaintext.decode("utf-8")
    except (VaultCipherError, ValueError, UnicodeDecodeError, KeyError):
        # ``VaultCipherError`` est un ``ValueError`` ; les deux sont listés
        # explicitement pour que le contrat reste lisible si la hiérarchie
        # évolue. Aucun message d'erreur ne contient de secret.
        raise SecretStoreError("Donnée chiffrée illisible.") from None
    return {
        "project": str(record.get("project", record.get("project_id", project))),
        "env": str(record["env"]),
        "name": str(record["name"]),
        "status": str(record["status"]),
        "value": value,
    }


class InMemorySecretStore:
    """Stockage mémoire chiffré des secrets pour le squelette fonctionnel (#63).

    NOTE DE SÉCURITÉ :
    Les valeurs sont chiffrées en mémoire (AES-256-GCM) mais ce mode reste un
    squelette de développement/test : une KEK éphémère est générée par instance
    et un dump mémoire du processus contient à la fois ciphertexts et clé. Il ne
    doit jamais être déployé en production.
    RÉSOLU (#26, #62, mergé PR #139) : la persistance SQLite chiffrée
    (``SqliteSecretStore``) existe avec contrainte d'unicité
    UNIQUE(project_id, env, name) et PRAGMA foreign_keys=ON ; c'est le backend
    prod par défaut, et le quota par projet y est vérifié atomiquement.
    RESTE (suivi post-#63, hors contrat v1) : pagination (pas de route de
    listage) et route DELETE (libération de capacité) — sans elles, le 429 de
    capacité reste permanent (retry inutile), voir TODO(#156).
    Ce quota n'est PAS le rate-limiting : il ne borne pas le débit des requêtes.
    Le débit est borné séparément par le middleware `ratelimit.py` (buckets par
    clé validée, pair réseau et global, 400/401 inclus, lot #63), conformément
    à openapi.yaml:289-294. Ce stockage en mémoire est strictement mono-processus
    (workers=1). Avec plusieurs
    workers (workers > 1), chaque worker détiendrait une instance mémoire indépendante
    et divergente sans garantie d'unicité inter-processus ; utiliser
    ``SqliteSecretStore`` pour un déploiement multi-worker.
    """

    def __init__(
        self,
        max_secrets: int = _DEFAULT_MAX_SECRETS,
        max_secrets_per_project: int = _DEFAULT_MAX_SECRETS_PER_PROJECT,
        *,
        cipher: VaultCipher | None = None,
    ) -> None:
        self._secrets: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._project_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._max_secrets = max_secrets
        self._max_secrets_per_project = max_secrets_per_project
        self._cipher = cipher if cipher is not None else VaultCipher.generate()
        self._kek_version: int = 1

    @property
    def kek_version(self) -> int:
        """Numéro de version courant de la KEK gérée par ce store."""
        return self._kek_version

    async def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        async with self._lock:
            record = self._secrets.get((project, env, name))
            if record is None:
                return None
            return _decrypt_record(record, self._cipher, project, env, name)

    async def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        key = (project, env, name)
        aad = VaultCipher.aad(project, env, name)
        # Défense en profondeur : la valeur stockée est canonique (NFC) et sans
        # NUL, même si l'appelant contourne la validation HTTP (décision #62).
        # La normalisation est idempotente, donc sans effet pour l'API.
        value = unicodedata.normalize("NFC", value)
        if "\x00" in value:
            raise ValueError("Le caractère NUL est interdit dans la valeur du secret.")
        async with self._lock:
            if key in self._secrets:
                raise KeyError("Secret déjà existant")
            if len(self._secrets) >= self._max_secrets:
                raise QuotaExceededError("Capacité maximale globale du store atteinte")
            project_count = self._project_counts.get(project, 0)
            if project_count >= self._max_secrets_per_project:
                raise QuotaExceededError(
                    f"Quota maximal de secrets atteint pour le projet '{project}'"
                )
            envelope = self._cipher.encrypt_envelope(value.encode("utf-8"), aad=aad)
            record = {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "encrypted_value": envelope.encrypted_value,
                "encrypted_dek": envelope.encrypted_dek,
                "kek_version": self._kek_version,
            }
            self._secrets[key] = record
            self._project_counts[project] = project_count + 1
            # Métadonnées seules : la route POST n'a pas besoin de la valeur et
            # le plaintext ne doit pas prolonger sa durée de vie en mémoire.
            return {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
            }

    async def clear(self) -> None:
        async with self._lock:
            self._secrets.clear()
            self._project_counts.clear()

    async def rotate_kek(
        self,
        new_cipher: VaultCipher,
        *,
        old_cipher: VaultCipher | None = None,
        target_kek_version: int | None = None,
    ) -> int:
        """Effectue la rotation atomique de la KEK en mémoire (ticket #71)."""
        active_old = old_cipher or self._cipher
        if active_old.has_same_key_as(new_cipher):
            raise ValueError("L'ancienne et la nouvelle KEK doivent être distinctes.")
        if target_kek_version is not None:
            validate_kek_version(target_kek_version, label="Numéro de version cible")

        async with self._lock:
            if not self._secrets:
                return 0
            for r in self._secrets.values():
                v = r.get("kek_version")
                if v is not None and (
                    not isinstance(v, int) or isinstance(v, bool) or v < 1 or v > MAX_KEK_VERSION
                ):
                    raise ValueError("Version de KEK illisible.")

            current_max = max(
                (
                    r["kek_version"]
                    if r.get("kek_version") is not None
                    else 1
                    for r in self._secrets.values()
                ),
                default=1,
            )
            if target_kek_version is not None:
                if target_kek_version <= current_max:
                    raise ValueError(
                        f"Le numéro de version cible ({target_kek_version}) doit être "
                        f"strictement supérieur à la version actuelle ({current_max})."
                    )
                new_version = target_kek_version
            else:
                # Fail-closed : l'auto-incrément reste borné à l'INTEGER 64 bits.
                new_version = validate_kek_version(current_max + 1)

            # Invariant d'atomicité : backup profond pour garantir que self._secrets
            # est restauré intact même en cas de mutation in-place (#71 LOW 4).
            backup = copy.deepcopy(self._secrets)
            try:
                count = 0
                for key, record in list(self._secrets.items()):
                    enc_dek = record.get("encrypted_dek")
                    if not enc_dek:
                        raise VaultCipherError(
                            "Rotation impossible : un secret sans enveloppe de DEK est présent."
                        )
                    aad = VaultCipher.aad(record["project"], record["env"], record["name"])
                    new_dek = active_old.rewrap_dek(new_cipher, enc_dek, aad=aad)
                    updated_record = dict(record)
                    updated_record["encrypted_dek"] = new_dek
                    updated_record["kek_version"] = new_version
                    self._secrets[key] = updated_record
                    count += 1
                self._cipher = new_cipher
                self._kek_version = new_version
                return count
            except BaseException:
                self._secrets = backup
                raise


def _read_max_kek_version(conn: sqlite3.Connection) -> int | None:
    """Lit la version KEK maximale dans la base avec validation stricte du type."""
    row = conn.execute("SELECT MAX(kek_version) FROM secrets").fetchone()
    if row and row[0] is not None:
        raw_val = row[0]
        if (
            not isinstance(raw_val, int)
            or isinstance(raw_val, bool)
            or raw_val < 1
            or raw_val > MAX_KEK_VERSION
        ):
            raise RuntimeError(
                "Impossible de lire la version KEK courante dans la base "
                "(version corrompue ou invalide)."
            )
        return raw_val
    return None


class SqliteSecretStore:
    """Stockage SQLite chiffré, partagé entre workers (tickets #26/#62).

    La base est initialisée et vérifiée par ``init_db`` (schéma, UNIQUE,
    ``foreign_keys=ON``). Les accès SQLite sont déportés dans des threads ; les écritures sont
    sérialisées par les transactions et la contrainte UNIQUE SQLite ; un second
    worker obtient donc un 409 sur un doublon, même après redémarrage.

    Le quota (``max_secrets``, ``max_secrets_per_project``) est vérifié dans la
    même transaction que l'insertion, sous ``BEGIN IMMEDIATE`` : le verrou
    d'écriture SQLite est acquis avant ``count_secrets()``, ce qui sérialise le
    comptage et la création entre processus et empêche tout dépassement
    inter-workers.

    Le 429 de capacité (``QuotaExceededError``) n'est PAS transitoire : le
    contrat impose l'en-tête ``Retry-After`` sur tout 429, mais un retry avec
    ce délai restera refusé tant que la capacité est pleine — le contrat #63
    n'expose aucune route DELETE, donc aucun emplacement ne peut être libéré.
    Le retry est donc INUTILE tant que la capacité est pleine ; la libération
    (route DELETE, quotas par projet) est suivie dans TODO(#156). Ce 429 de
    capacité est distinct du 429 de débit (rate-limit, lot #63), lui transitoire.

    L'empreinte d'intégrité persistée utilise la sous-clé HKDF dédiée et le
    triplet ``(project, env, name)`` fournis par ``VaultCipher`` : jamais la KEK
    directement (invariant 5) et non corrélable entre triplets. Le mode
    ``:memory:`` est refusé fail-closed (base éphémère par connexion).
    """

    def __init__(
        self,
        db_path: Path | str,
        cipher: VaultCipher,
        max_secrets: int = _DEFAULT_MAX_SECRETS,
        max_secrets_per_project: int = _DEFAULT_MAX_SECRETS_PER_PROJECT,
    ) -> None:
        if str(db_path).strip() == ":memory:":
            # Fail-closed : chaque connexion ouvrirait une base éphémère isolée
            # et sans schéma (`no such table` différé, écritures perdues).
            raise ValueError(
                "Le mode ':memory:' est interdit pour SqliteSecretStore : base "
                "éphémère isolée par connexion (fail-closed). Fournir un fichier "
                "SQLite persistant."
            )
        self._db_path: Path | str = Path(db_path) if isinstance(db_path, str) else db_path
        self._cipher = cipher
        self._max_secrets = max_secrets
        self._max_secrets_per_project = max_secrets_per_project
        init_db(db_path)
        self._kek_version: int = self._detect_current_kek_version()

    @property
    def kek_version(self) -> int:
        """Numéro de version courant de la KEK gérée par ce store."""
        return self._kek_version

    def _detect_current_kek_version(self) -> int:
        """Détecte la version KEK maximale persistée dans la base.

        Lève ``RuntimeError`` fail-closed si la base est illisible : mieux
        vaut refuser de démarrer que de créer des secrets sous-étiquetés en
        kek_version=1 alors que la version réelle est supérieure.
        """
        try:
            with db_session(self._db_path) as conn:
                max_v = _read_max_kek_version(conn)
                return max_v if max_v is not None else 1
        except (sqlite3.Error, OSError, DatabaseUnavailableError) as exc:
            raise RuntimeError(
                "Impossible de lire la version KEK courante dans la base "
                "(fail-closed pour éviter une sous-étiquetage silencieux)."
            ) from exc

    @property
    def db_path(self) -> Path | str:
        """Chemin effectif de la base, utilisé pour partager l'auth entre workers."""
        return self._db_path

    async def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        return await asyncio.to_thread(self._get, project, env, name)

    def _get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        with db_session(self._db_path) as conn:
            record = get_secret(conn, project, env, name)
        if record is None:
            return None
        return _decrypt_record(record, self._cipher, project, env, name)

    async def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        return await asyncio.to_thread(self._create, project, env, name, value)

    def _create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        aad = VaultCipher.aad(project, env, name)
        # Défense en profondeur : valeur canonique (NFC) et sans NUL même hors
        # du chemin HTTP, pour que l'empreinte d'intégrité soit toujours
        # calculée sur la forme stockée (décision #62). Le NUL tronque les
        # valeurs dans les outils texte : refusé comme au contrat API.
        value = unicodedata.normalize("NFC", value)
        if "\x00" in value:
            raise ValueError("Le caractère NUL est interdit dans la valeur du secret.")
        with db_session(self._db_path) as conn:
            # Verrou d'écriture inter-processus AVANT le comptage : le
            # quota et l'insertion forment une seule transaction atomique,
            # même entre workers partageant le fichier SQLite.
            conn.execute("BEGIN IMMEDIATE")
            # Vérification de non-obsolescence de la KEK (ticket #71 MEDIUM) :
            # si une rotation externe (ex. via CLI) a incrémenté la version en base
            # au-delà de celle chargée en mémoire par ce worker, refuser fail-closed
            # pour ne pas chiffrer un nouveau secret avec une ancienne KEK compromise.
            db_max = _read_max_kek_version(conn)
            if db_max is not None and db_max > self._kek_version:
                raise RuntimeError(
                    "La base de données a subi une rotation de KEK externe. "
                    "Redémarrage du worker requis."
                )
            # Un doublon reste un 409 même si la capacité est saturée.
            if get_secret(conn, project, env, name) is not None:
                raise KeyError("Secret déjà existant")
            if count_secrets(conn) >= self._max_secrets:
                raise QuotaExceededError("Capacité maximale globale du store atteinte")
            if count_secrets(conn, project) >= self._max_secrets_per_project:
                raise QuotaExceededError(
                    f"Quota maximal de secrets atteint pour le projet '{project}'"
                )
            ensure_project(conn, project)
            envelope = self._cipher.encrypt_envelope(value.encode("utf-8"), aad=aad)
            fingerprint = self._cipher.fingerprint(value.encode("utf-8"), aad=aad)
            try:
                create_secret(
                    conn,
                    project,
                    env,
                    name,
                    envelope.encrypted_value,
                    encrypted_dek=envelope.encrypted_dek,
                    kek_version=self._kek_version,
                    fingerprint=fingerprint,
                )
            except sqlite3.IntegrityError:
                raise KeyError("Secret déjà existant") from None
        return {
            "project": project,
            "env": env,
            "name": name,
            "status": "vaulte",
        }

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear)

    def _clear(self) -> None:
        with db_session(self._db_path) as conn:
            delete_all_secrets(conn)

    async def rotate_kek(
        self,
        new_cipher: VaultCipher,
        *,
        old_cipher: VaultCipher | None = None,
        target_kek_version: int | None = None,
    ) -> int:
        """Effectue la rotation transactionnelle de la KEK dans SQLite (ticket #71)."""
        return await asyncio.to_thread(
            self._rotate_kek,
            new_cipher,
            old_cipher=old_cipher,
            target_kek_version=target_kek_version,
        )

    def _rotate_kek(
        self,
        new_cipher: VaultCipher,
        *,
        old_cipher: VaultCipher | None = None,
        target_kek_version: int | None = None,
    ) -> int:
        """Exécute la rotation transactionnelle de la KEK dans SQLite (ticket #71).

        La transaction SQLite garantit l'atomicité sur disque. Les attributs en
        mémoire (self._cipher, self._kek_version) sont mis à jour immédiatement après
        le commit réussi. En cas de crash ou redémarrage du processus entre le
        commit DB et l'affectation en mémoire, l'initialisation du nouveau store
        relit automatiquement la version KEK maximale via _detect_current_kek_version.
        """
        active_old = old_cipher or self._cipher
        with db_session(self._db_path) as conn:
            count, new_version = rotate_secrets_kek(
                conn,
                active_old,
                new_cipher,
                target_kek_version=target_kek_version,
            )
            if count == 0:
                # Store vide : aucun secret réenveloppé, self._cipher et self._kek_version
                # restent inchangés (aligné sur InMemorySecretStore).
                return 0
        self._cipher = new_cipher
        self._kek_version = new_version
        return count
