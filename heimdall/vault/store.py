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
  plusieurs workers partagent donc le même état et la même garantie 409.

Aucun module ne stocke de valeur brute en base, dans les logs ou dans un dict
interne : les valeurs ne sont déchiffrées qu'au moment de la réponse autorisée.
"""

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

from heimdall.vault.crypto import VaultCipher, VaultCipherError
from heimdall.vault.database import (
    count_secrets,
    create_secret,
    db_session,
    delete_all_secrets,
    ensure_project,
    get_secret,
    init_db,
)

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
    """Déchiffre un enregistrement et retourne une copie défensive en clair."""
    try:
        plaintext = cipher.decrypt(
            str(record["encrypted_value"]),
            aad=VaultCipher.aad(project, env, name),
        )
        value = plaintext.decode("utf-8")
    except (VaultCipherError, UnicodeDecodeError, KeyError):
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
    TODO(#26, #62) : Remplacer ce mode par la persistance SQLite chiffrée
    (``SqliteSecretStore``) avec contrainte d'unicité UNIQUE(project_id, env, name)
    et PRAGMA foreign_keys=ON.
    TODO(#62) : Poursuivre le quota par projet et la pagination lors du branchement
    SQLite pour borner la croissance disque et mémoire (capacité de stockage), en
    distinguant quota de stockage et débit (retry inutile tant que la capacité est pleine).
    Ce quota n'est PAS le rate-limiting : il ne borne pas le débit des requêtes.
    Le débit est borné séparément par le middleware `ratelimit.py` (buckets par
    clé validée, pair réseau et global, 400/401 inclus, ticket #65), conformément
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
        self._secrets: dict[tuple[str, str, str], dict[str, str]] = {}
        self._project_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._max_secrets = max_secrets
        self._max_secrets_per_project = max_secrets_per_project
        self._cipher = cipher if cipher is not None else VaultCipher.generate()

    async def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        async with self._lock:
            record = self._secrets.get((project, env, name))
            if record is None:
                return None
            return _decrypt_record(record, self._cipher, project, env, name)

    async def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        key = (project, env, name)
        aad = VaultCipher.aad(project, env, name)
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
            record = {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "encrypted_value": self._cipher.encrypt(value.encode("utf-8"), aad=aad),
            }
            self._secrets[key] = record
            self._project_counts[project] = project_count + 1
            return {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "value": value,
            }

    async def clear(self) -> None:
        async with self._lock:
            self._secrets.clear()
            self._project_counts.clear()


class SqliteSecretStore:
    """Stockage SQLite chiffré, partagé entre workers (tickets #26/#62).

    La base est initialisée et vérifiée par ``init_db`` (schéma, UNIQUE,
    ``foreign_keys=ON``). Les écritures sont sérialisées par un verrou asyncio
    local et par la contrainte UNIQUE SQLite ; un second worker obtient donc un
    409 sur un doublon, même après redémarrage.

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
        self._lock = asyncio.Lock()
        init_db(db_path)

    @property
    def db_path(self) -> Path | str:
        """Chemin effectif de la base, utilisé pour partager l'auth entre workers."""
        return self._db_path

    async def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        async with self._lock:
            with db_session(self._db_path) as conn:
                record = get_secret(conn, project, env, name)
            if record is None:
                return None
            return _decrypt_record(record, self._cipher, project, env, name)

    async def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        aad = VaultCipher.aad(project, env, name)
        async with self._lock:
            with db_session(self._db_path) as conn:
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
                encrypted_value = self._cipher.encrypt(value.encode("utf-8"), aad=aad)
                fingerprint = self._cipher.fingerprint(value.encode("utf-8"), aad=aad)
                try:
                    create_secret(
                        conn,
                        project,
                        env,
                        name,
                        encrypted_value,
                        fingerprint=fingerprint,
                    )
                except sqlite3.IntegrityError:
                    raise KeyError("Secret déjà existant") from None
            return {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "value": value,
            }

    async def clear(self) -> None:
        async with self._lock:
            with db_session(self._db_path) as conn:
                delete_all_secrets(conn)
