# T264 — preuves pour la ligne SAMM (Rotation de la KEK)

Sous-ticket **T264** (ticket GitHub **#71**) du grand ticket `#26 « Clé
maîtresse et chiffrement par enveloppe »`, branche
`71-t264-rotation-de-la-kek`. Cette fiche fournit les couples module + ligne et
les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Colonne `kek_version`** sur les secrets / DEK | [heimdall/vault/database.py:112-114](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L112-L114) (`SCHEMA_SQL`), [heimdall/vault/database.py:922-942](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L922-L942) (`_ensure_secret_kek_version_column`), [heimdall/vault/database.py:1117-1175](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1117-L1175) (`create_secret`), [heimdall/vault/database.py:1188-1217](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1188-L1217) (`get_secret`) | `tests/test_vault_kek_rotation.py::SchemaMigrationTests::test_schema_migration_adds_kek_version_without_data_loss` | Réussi |
| **Commande de rotation** transactionnelle | [heimdall/cli/vault_keys.py:234-315](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/cli/vault_keys.py#L234-L315) (`rotate_kek_command`, `_resolve_cli_cipher`), [heimdall/vault/database.py:1373-1430](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1373-L1430) (`rotate_secrets_kek`) | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_nominal_options` | Réussi |
| **Rechiffrer uniquement les DEK** (valeurs chiffrées inchangées) | [heimdall/vault/database.py:1373-1430](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1373-L1430) (`rotate_secrets_kek`), [heimdall/vault/crypto.py:649-665](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/crypto.py#L649-L665) (`VaultCipher.rewrap_dek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` | Réussi |
| **Lecture OK avant et après rotation** | [heimdall/vault/store.py:345-376](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/store.py#L345-L376) (`SqliteSecretStore.rotate_kek`, `InMemorySecretStore.rotate_kek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values`, `::StoreRotationMethodTests::test_sqlite_store_rotate_kek` | Réussi |
| **Atomicité (tout ou rien)** : rollback intégral si une DEK échoue | [heimdall/vault/database.py:1373-1430](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1373-L1430) (`rotate_secrets_kek` sous transaction exclusive SQLite) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_atomicity_rolls_back_on_error` | Réussi |
| **Fait quand** : rotation sans rechiffrer les valeurs | [heimdall/vault/database.py:1373-1430](https://github.com/Cezar277/heimdall/blob/c401f3f/heimdall/vault/database.py#L1373-L1430) (`rotate_secrets_kek`), [tests/test_vault_kek_rotation.py:100-155](https://github.com/Cezar277/heimdall/blob/c401f3f/tests/test_vault_kek_rotation.py#L100-L155) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` (comparaison exacte de `encrypted_value` avant/après) | Réussi |
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
# 33 passed in 1.1s
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
| **Invariant 8** — Pas de reflet de secret dans les erreurs | Messages génériques sur échec opérationnel (code 1) ou d'usage (code 2), aucune clé affichée dans stderr. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_wrong_old_key_exits_one` |
| **Invariant 9** — Pas de clé secrète dans argv | Options CLI supprimées (`--old-kek`, `--new-kek`, etc.) ; injection des KEK/passphrases uniquement via variables d'environnement (`HEIMDALL_VAULT_*`), interdisant l'exfiltration via `ps aux` ou `/proc`. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_no_key_options_in_help_or_argv` |
| **Intégrité & Monotonie** — Anti-downgrade `kek_version` | Validation systématique (`validate_kek_version >= 1`) et refus strict d'une version cible inférieure ou égale à la version courante (`target_kek_version <= max(current)`). | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rejects_downgrade_or_same_version`, `::KekVersionValidationTests` |
| **Fail-closed opérationnel** — Base inexistante ou vide | La commande CLI refuse de créer silencieusement une base vide (code 2 si fichier absent/vide, code 1 si 0 secret). | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_missing_or_empty_database_fails_closed`, `test_cli_rotate_zero_secrets_exits_one` |
| **Confinement crypto (#17)** | Aucun import `cryptography`/`argon2` hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -q
# 33 passed
.venv/bin/ruff check heimdall tests
# All checks passed!
.venv/bin/mypy heimdall tests/test_vault_kek_rotation.py
# Success: no issues found
```
