## Ticket lié

Closes #71

> **Numérotation** : Sous-ticket **T264** (issue GitHub **#71**) du grand ticket `#26 « Clé
> maîtresse et chiffrement par enveloppe »`, branche `71-t264-rotation-de-la-kek`.

## Ce qui a changé

**1. Colonne `kek_version` et persistance SQLite (`heimdall/vault/database.py`)** — ajout de la
colonne `kek_version INTEGER NOT NULL DEFAULT 1 CHECK (kek_version >= 1)` sur la table `secrets`.
Migration idempotente et purement additive `_ensure_secret_kek_version_column` pour les bases pré-#71
sans perte de données. Helper applicatif strict `validate_kek_version(version >= 1)` interdisant les types
invalides (bool, str, float/REAL, entiers < 1).

**2. Réenveloppement exclusif des DEK (`heimdall/vault/crypto.py`, `heimdall/vault/database.py`)** —
méthode `VaultCipher.rewrap_dek(new_cipher, encrypted_dek, aad)` déchiffrant la DEK avec l'ancienne KEK
et la rechiffrant avec la nouvelle. Zeroization en mémoire via tampon `bytearray` remis à zéro dans un
bloc `finally`. Les valeurs chiffrées (`encrypted_value`) et leurs empreintes (`fingerprint`) ne sont
**jamais lues ni rechiffrées** lors de la rotation.

**3. Rotation transactionnelle atomique (`rotate_secrets_kek`)** — rotation globale sous verrou
`BEGIN IMMEDIATE` : rollback intégral si une DEK échoue (ou secret hérité sans DEK). Détection de version
fail-closed sur non-entiers (REAL `1.5`, TEXT) levant une exception générique sans reflet. Retourne `(0, 1)`
sans écriture ni persistance si la base est vide, ignorant toute `target_kek_version` non persistée.

**4. Monotonie et intégrité (`reenvelope_secret`, `update_secret`)** — mise à jour atomique conditionnelle
(`UPDATE ... WHERE kek_version < ?` ou `<= ?`). Si une course concurrente est détectée, levée d'une
exception générique fail-closed `ValueError("Concurrence détectée sur kek_version.")` sans reflet
d'identifiants (`project`, `env`, `name`) dans le message d'erreur (invariant 8).

**5. Stores `SqliteSecretStore` et `InMemorySecretStore` (`heimdall/vault/store.py`)** — suivi de
`kek_version` post-rotation : les secrets créés après rotation héritent de la nouvelle version.
Atomicité préservée en mémoire sur `BaseException` (`KeyboardInterrupt`, `asyncio.CancelledError`, `SystemExit`)
avec snapshot profond `copy.deepcopy(self._secrets)`. Détection fail-closed de la version courante
`_detect_current_kek_version` refusant strictement tout type non-entier (REAL `1.5`, TEXT, bool).
Vérification fail-closed de non-obsolescence sous `BEGIN IMMEDIATE` dans `SqliteSecretStore.create` si une
rotation externe (ex. CLI) a incrémenté `kek_version` en base au-delà de la version en mémoire du store :
levée de `RuntimeError` générique et refus de chiffrer avec l'ancienne KEK compromise. La rotation hors-ligne
exige le redémarrage de tous les processus Vault pour charger le nouveau chiffreur. Fenêtre crash entre le
commit DB et le swap mémoire : documentée et sans fuite — la réinitialisation du store relit la version
courante via `_detect_current_kek_version` (test épinglé
`test_sqlite_store_reinit_after_simulated_crash_reloads_version`).

**6. Commande CLI durcie (`heimdall vault rotate-kek`, `heimdall/cli/vault_keys.py`)** — variables
d'environnement uniquement (`HEIMDALL_VAULT_OLD_KEK`, `HEIMDALL_VAULT_NEW_KEK`, ou dérivation Argon2id via
`HEIMDALL_VAULT_*_MASTER_KEY` / `*_SALT`), aucune option secrète en `argv` (invariant 9). Refus fail-closed
si base absente/vide (code 2), si variable vide (code 2), ou si les deux clés sont identiques (code 2).
Distinction stricte des codes d'erreur : exit 1 pour erreur opérationnelle ou anomalie d'intégrité DB
(`illisible`/`Concurrence`, message générique sans reflet), exit 2 pour erreur d'usage / arguments.
Alias spécifique `kek-rotate` supporté, alias trop générique `rotate` supprimé.

**7. Suite de tests et documentation** — 64 tests automatisés dans `tests/test_vault_kek_rotation.py`,
fiche de preuves SAMM complète `docs/t264-samm.md` et mise à jour de `docs/contracts/vault-traceability.md`.

## Comment tester

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -v
# 64 passed
```

Vérification que les valeurs chiffrées ne changent pas et qu'aucun clair n'est présent dans SQLite :

```sh
.venv/bin/python -m pytest \
  tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values \
  tests/test_vault_kek_rotation.py::RawSqliteNoPlaintextTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek_after_rotation -q
# 2 passed
```

Démonstration CLI (rotation avec variables d'environnement) :

```sh
.venv/bin/python - <<'PY'
import base64
from heimdall.vault.crypto import VaultCipher
from heimdall.vault.store import SqliteSecretStore

old_kek = b"O" * 32
new_kek = b"N" * 32
old_b64 = base64.urlsafe_b64encode(old_kek).decode()
new_b64 = base64.urlsafe_b64encode(new_kek).decode()
print("Variables configurées pour rotation : HEIMDALL_VAULT_OLD_KEK et HEIMDALL_VAULT_NEW_KEK")
PY
```

## Tests

- [x] Tests unitaires et d'intégration ajoutés (64 tests)
- [x] Tests verts en local (`pytest tests/test_vault_kek_rotation.py`)
- [x] Suite complète Vault et confinement crypto verte
- [x] Linter ruff conforme (`ruff check heimdall tests/test_vault_kek_rotation.py`)
- [x] Typage mypy strict conforme (`mypy heimdall tests/test_vault_kek_rotation.py`)
