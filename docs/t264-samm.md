# T264 — preuves pour la ligne SAMM (Rotation de la KEK)

Sous-ticket **T264** (ticket GitHub **#71**) du grand ticket `#26 « Clé
maîtresse et chiffrement par enveloppe »`, branche
`71-t264-rotation-de-la-kek`. Cette fiche fournit les couples module + ligne et
les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Colonne `kek_version`** sur les secrets / DEK | [heimdall/vault/database.py:125-135](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L125-L135) (`SCHEMA_SQL`), [heimdall/vault/database.py:959-980](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L959-L980) (`_ensure_secret_kek_version_column`), [heimdall/vault/database.py:1157-1226](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1157-L1226) (`create_secret`), [heimdall/vault/database.py:1229-1265](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1229-L1265) (`get_secret`) | `tests/test_vault_kek_rotation.py::SchemaMigrationTests::test_schema_migration_adds_kek_version_without_data_loss` | Réussi |
| **Commande de rotation** transactionnelle | [heimdall/cli/vault_keys.py:267-331](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/cli/vault_keys.py#L267-L331) (`rotate_kek_command`), [heimdall/vault/database.py:1441-1533](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1441-L1533) (`rotate_secrets_kek`) | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_nominal_options` | Réussi |
| **Rechiffrer uniquement les DEK** (valeurs chiffrées inchangées) | [heimdall/vault/database.py:1441-1533](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1441-L1533) (`rotate_secrets_kek`), [heimdall/vault/crypto.py:649-669](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/crypto.py#L649-L669) (`VaultCipher.rewrap_dek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` | Réussi |
| **Lecture OK avant et après rotation** | [heimdall/vault/store.py:201-263](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/store.py#L201-L263) (`InMemorySecretStore.rotate_kek`), [heimdall/vault/store.py:415-465](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/store.py#L415-L465) (`SqliteSecretStore.rotate_kek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values`, `::StoreRotationMethodTests::test_sqlite_store_rotate_kek` | Réussi |
| **Atomicité (tout ou rien)** : rollback intégral si une DEK échoue | [heimdall/vault/database.py:1441-1533](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1441-L1533) (`rotate_secrets_kek` sous transaction exclusive SQLite) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_atomicity_rolls_back_on_error` | Réussi |
| **Fait quand** : rotation sans rechiffrer les valeurs | [heimdall/vault/database.py:1441-1533](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/heimdall/vault/database.py#L1441-L1533) (`rotate_secrets_kek`), [tests/test_vault_kek_rotation.py:105-162](https://github.com/Cezar277/heimdall/blob/eb1a3cd695b6ffb53ff10b243fbd3baa32a19291/tests/test_vault_kek_rotation.py#L105-L162) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` (comparaison exacte de `encrypted_value` avant/après) | Réussi |
| **Sécurité SQLite au repos** : aucun secret ni DEK en clair | Fichier binaire brut `vault.db` inspecté post-rotation | `tests/test_vault_kek_rotation.py::RawSqliteNoPlaintextTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek_after_rotation` | Réussi |
| **Confinement crypto (#17)** | Aucun import de `cryptography` ni `argon2` hors de `crypto.py` | `tests/test_crypto_confinement.py` | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Rechiffrer uniquement les DEK | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |
| Commande de rotation | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_nominal_options` |
| Test : lecture OK avant et après rotation | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |
| **Fait quand** : rotation sans rechiffrer les valeurs | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |

## 3. Preuve à garder pour le rapport

Exécution de la suite complète du sous-ticket #71 :

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -v
# 51 passed in 1.9s
```

Vérification que les valeurs chiffrées ne changent pas et que le fichier SQLite brut ne contient aucun clair :

```sh
.venv/bin/python -m pytest \
  tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values \
  tests/test_vault_kek_rotation.py::RawSqliteNoPlaintextTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek_after_rotation -q
# 2 passed
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Information disclosure** — KEK compromise | La rotation de la KEK réenveloppe toutes les DEK sans toucher aux valeurs chiffrées ; l'ancienne KEK ne peut plus déchiffrer aucune DEK. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |
| **Tampering** — rotation interrompue / corruption | Transaction SQLite exclusive (`BEGIN IMMEDIATE`) : toute erreur (décodage, clé invalide) entraîne un rollback immédiat, laissant la base dans son état cohérent initial. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_atomicity_rolls_back_on_error` |
| **Information disclosure** — rémanence mémoire de la DEK | La DEK déchiffrée en mémoire lors du réenveloppement est stockée dans un `bytearray` remis à zéro (`b"\x00" * 32`) dans un bloc `finally` (meilleur effort compte tenu des copies immuables CPython). | `heimdall/vault/crypto.py` (`rewrap_dek`), `tests/test_vault_kek_rotation.py` |
| **Denial of Service** — migration dégradée | `_ensure_secret_kek_version_column` est idempotente, concurrente et additive ; les bases pré-#71 conservent leurs données avec `kek_version=1`. | `tests/test_vault_kek_rotation.py::SchemaMigrationTests::test_schema_migration_adds_kek_version_without_data_loss` |
| **Invariant 5** — KEK distinctes | La commande CLI et la méthode de base refusent la rotation si l'ancienne et la nouvelle KEK sont identiques. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rejects_identical_ciphers`, `::VaultRotateCliTests::test_cli_rotate_rejects_identical_keys` |
| **Invariant 8** — Pas de reflet de secret dans les erreurs | Messages génériques sur échec opérationnel (code 1) ou d'usage (code 2), aucune clé affichée dans stderr ni dans les exceptions de contention ; protection contre le reflet de `kek_version` corrompue dans SQLite, InMemory et reenvelope. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_wrong_old_key_exits_one`, `::DatabaseRotationTests::test_rotation_under_lock_contention_fails_closed`, `::RotateSecretsKekCorruptedVersionTests`, `::SqliteStoreDetectKekVersionTests`, `::StoreRotationMethodTests` |
| **Invariant 9** — Pas de clé secrète dans argv | Options CLI supprimées (`--old-kek`, `--new-kek`, etc.) ; injection des KEK/passphrases uniquement via variables d'environnement (`HEIMDALL_VAULT_*`), interdisant l'exfiltration via `ps aux` ou `/proc` ; fail-closed si variable vide sans repli silencieux. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_no_key_options_in_help_or_argv`, `::VaultRotateCliTests::test_cli_rotate_empty_old_kek_env_var_fails_closed_without_fallback` |
| **Intégrité & Monotonie** — Anti-downgrade `kek_version` | Validation systématique (`validate_kek_version >= 1`) et refus strict d'une version cible inférieure ou égale à la version courante (`target_kek_version <= max(current)`) dans `rotate_secrets_kek` et `reenvelope_secret` (clause conditionnelle atomique et verrouillage `BEGIN IMMEDIATE`). | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rejects_downgrade_or_same_version`, `::KekVersionValidationTests`, `::ReenvelopeSecretMonotonicityTests` |
| **Traçabilité post-rotation** — Nouveaux secrets | Suivi de la version courante (`_kek_version`) dans `SqliteSecretStore` et `InMemorySecretStore` : les secrets créés après rotation héritent de la nouvelle version KEK. | `tests/test_vault_kek_rotation.py::StoreRotationMethodTests::test_sqlite_store_create_after_rotate_has_target_kek_version`, `::test_in_memory_store_create_after_rotate_has_target_kek_version` |
| **Fail-closed opérationnel** — Base inexistante ou vide | La commande CLI refuse de créer silencieusement une base vide (code 2 si fichier absent/vide, code 1 si 0 secret) ; les stores retournent 0 sans changer de KEK si 0 secret ; détection de version fail-closed. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_missing_or_empty_database_fails_closed`, `::StoreRotationMethodTests::test_sqlite_store_rotate_empty_does_not_swap_cipher`, `::SqliteStoreDetectKekVersionTests` |
| **Intégrité zéro-déchiffrement** — HMAC auxiliaire | L'empreinte HMAC auxiliaire n'est pas modifiée lors de la rotation pour préserver l'absence totale de déchiffrement des valeurs (DoD #71). | `heimdall/vault/crypto.py` (`fingerprint`), `heimdall/vault/database.py` (`rotate_secrets_kek`) |
| **Confinement crypto (#17)** | Aucun import `cryptography`/`argon2` hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -q
# 50 passed
.venv/bin/ruff check heimdall tests
# All checks passed!
.venv/bin/mypy heimdall tests/test_vault_kek_rotation.py
# Success: no issues found
```
