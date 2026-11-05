# T264 — preuves pour la ligne SAMM (Rotation de la KEK)

Sous-ticket **T264** (ticket GitHub **#71**) du grand ticket `#26 « Clé
maîtresse et chiffrement par enveloppe »`, branche
`71-t264-rotation-de-la-kek`. Cette fiche fournit les couples module + ligne et
les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens du tableau ci-dessous sont épinglés au commit
> [`fb45ba9`](https://github.com/Cezar277/heimdall/commit/fb45ba943ce9d80ea07749c688079973b17c90de),
> qui contient l'intégralité du code et des tests de #71 ; le commit suivant (celui-ci)
> ne modifie que la présente fiche, les plages citées sont donc identiques au `HEAD` de
> la branche et vérifiables ligne à ligne. Au moment de la fusion, re-épingler le tableau
> vers le SHA de merge (procédure déjà suivie pour `docs/t262-samm.md`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Colonne `kek_version`** sur les secrets / DEK | [heimdall/vault/database.py:125-135](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L125-L135) (`SCHEMA_SQL`), [heimdall/vault/database.py:959-980](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L959-L980) (`_ensure_secret_kek_version_column`), [heimdall/vault/database.py:1157-1226](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1157-L1226) (`create_secret`), [heimdall/vault/database.py:1229-1257](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1229-L1257) (`get_secret`) | `tests/test_vault_kek_rotation.py::SchemaMigrationTests::test_schema_migration_adds_kek_version_without_data_loss` | Réussi |
| **Commande de rotation** transactionnelle | [heimdall/cli/vault_keys.py:267-335](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/cli/vault_keys.py#L267-L335) (`rotate_kek_command`), [heimdall/vault/database.py:1471-1573](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1471-L1573) (`rotate_secrets_kek`) | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_nominal_via_env_vars` | Réussi |
| **Rechiffrer uniquement les DEK** (valeurs chiffrées inchangées) | [heimdall/vault/database.py:1471-1573](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1471-L1573) (`rotate_secrets_kek`), [heimdall/vault/crypto.py:649-669](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/crypto.py#L649-L669) (`VaultCipher.rewrap_dek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` | Réussi |
| **Lecture OK avant et après rotation** | [heimdall/vault/store.py:202-268](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/store.py#L202-L268) (`InMemorySecretStore.rotate_kek`), [heimdall/vault/store.py:442-486](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/store.py#L442-L486) (`SqliteSecretStore.rotate_kek`) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values`, `::StoreRotationMethodTests::test_sqlite_store_rotate_kek` | Réussi |
| **Atomicité (tout ou rien)** : rollback intégral si une DEK échoue | [heimdall/vault/database.py:1471-1573](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1471-L1573) (`rotate_secrets_kek` sous transaction exclusive SQLite) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_atomicity_rolls_back_on_error` | Réussi |
| **Fait quand** : rotation sans rechiffrer les valeurs | [heimdall/vault/database.py:1471-1573](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/heimdall/vault/database.py#L1471-L1573) (`rotate_secrets_kek`), [tests/test_vault_kek_rotation.py](https://github.com/Cezar277/heimdall/blob/fb45ba943ce9d80ea07749c688079973b17c90de/tests/test_vault_kek_rotation.py) | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` (comparaison exacte de `encrypted_value` avant/après) | Réussi |
| **Sécurité SQLite au repos** : aucun secret ni DEK en clair | Fichier binaire brut `vault.db` inspecté post-rotation | `tests/test_vault_kek_rotation.py::RawSqliteNoPlaintextTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek_after_rotation` | Réussi |
| **Confinement crypto (#17)** | Aucun import de `cryptography` ni `argon2` hors de `crypto.py` | `tests/test_crypto_confinement.py` | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Rechiffrer uniquement les DEK | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |
| Commande de rotation | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_nominal_via_env_vars` |
| Test : lecture OK avant et après rotation | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |
| **Fait quand** : rotation sans rechiffrer les valeurs | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values` |

## 3. Preuve à garder pour le rapport

Exécution de la suite complète du sous-ticket #71 :

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -v
# 64 passed
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
| **Information disclosure** — KEK compromise & workers en mémoire | La rotation de la KEK réenveloppe toutes les DEK sans toucher aux valeurs chiffrées ; l'ancienne KEK ne peut plus déchiffrer aucune DEK. Les stores en mémoire détectent toute rotation externe sous `BEGIN IMMEDIATE` (`SqliteSecretStore.create` refuse fail-closed avec `RuntimeError` si la base a une version supérieure) évitant de créer de nouveaux secrets avec une KEK compromise. La rotation hors-ligne exige le redémarrage des workers. En cas de crash entre commit et swap mémoire, le redémarrage recharge automatiquement la version via `_detect_current_kek_version`. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rewraps_only_deks_without_touching_values`, `::StoreRotationMethodTests::test_sqlite_store_create_rejects_stale_cipher_after_external_rotation`, `::StoreRotationMethodTests::test_sqlite_store_reinit_after_simulated_crash_reloads_version` |
| **Tampering** — rotation interrompue / corruption | Transaction SQLite exclusive (`BEGIN IMMEDIATE`) : toute erreur (décodage, clé invalide) entraîne un rollback immédiat, laissant la base dans son état cohérent initial. En mémoire, `InMemorySecretStore.rotate_kek` restaure `_secrets` sur `BaseException` (`KeyboardInterrupt`, `asyncio.CancelledError`). | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_atomicity_rolls_back_on_error`, `::StoreRotationMethodTests::test_in_memory_rotate_kek_atomicity_on_base_exception` |
| **Information disclosure** — rémanence mémoire de la DEK | La DEK déchiffrée en mémoire lors du réenveloppement est stockée dans un `bytearray` remis à zéro (`b"\x00" * 32`) dans un bloc `finally` (meilleur effort compte tenu des copies immuables CPython). | `heimdall/vault/crypto.py` (`rewrap_dek`), `tests/test_vault_kek_rotation.py` |
| **Denial of Service** — migration dégradée | `_ensure_secret_kek_version_column` est idempotente, concurrente et additive ; les bases pré-#71 conservent leurs données avec `kek_version=1`. | `tests/test_vault_kek_rotation.py::SchemaMigrationTests::test_schema_migration_adds_kek_version_without_data_loss` |
| **Invariant 5** — KEK distinctes | La commande CLI et la méthode de base refusent la rotation si l'ancienne et la nouvelle KEK sont identiques. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rejects_identical_ciphers`, `::VaultRotateCliTests::test_cli_rotate_rejects_identical_keys` |
| **Invariant 8** — Pas de reflet de secret dans les erreurs | Messages génériques sur échec opérationnel (code 1) ou d'usage (code 2), aucune clé affichée dans stderr ni dans les exceptions de contention ; protection contre le reflet de `kek_version` corrompue dans SQLite, InMemory et reenvelope ; distinction stricte exit 1 (opérationnel / intégrité DB) vs exit 2 (usage / downgrade) en CLI sans reflet. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_wrong_old_key_exits_one`, `::VaultRotateCliTests::test_cli_rotate_corrupted_kek_version_exits_one`, `::DatabaseRotationTests::test_rotation_under_lock_contention_fails_closed`, `::RotateSecretsKekCorruptedVersionTests`, `::SqliteStoreDetectKekVersionTests`, `::StoreRotationMethodTests` |
| **Invariant 9** — Pas de clé secrète dans argv | Options CLI supprimées (`--old-kek`, `--new-kek`, etc.) ; injection des KEK/passphrases uniquement via variables d'environnement (`HEIMDALL_VAULT_*`), interdisant l'exfiltration via `ps aux` ou `/proc` ; fail-closed si variable vide sans repli silencieux. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_no_key_options_in_help_or_argv`, `::VaultRotateCliTests::test_cli_rotate_empty_old_kek_env_var_fails_closed_without_fallback` |
| **Intégrité & Monotonie** — Anti-downgrade `kek_version` | Validation systématique (`validate_kek_version >= 1`) et refus strict d'une version cible inférieure ou égale à la version courante (`target_kek_version <= max(current)`) dans `rotate_secrets_kek` et `reenvelope_secret` (clause conditionnelle atomique et verrouillage `BEGIN IMMEDIATE`) ; refus explicite (`ValueError`) d'un downgrade concurrent sur `update_secret`. | `tests/test_vault_kek_rotation.py::DatabaseRotationTests::test_rotation_rejects_downgrade_or_same_version`, `::KekVersionValidationTests`, `::ReenvelopeSecretMonotonicityTests` |
| **Traçabilité post-rotation** — Nouveaux secrets | Suivi de la version courante (`_kek_version`) dans `SqliteSecretStore` et `InMemorySecretStore` : les secrets créés après rotation héritent de la nouvelle version KEK, alignée sur la `new_version` retournée par `rotate_secrets_kek` sans SELECT supplémentaire ni dérive future. | `tests/test_vault_kek_rotation.py::StoreRotationMethodTests::test_sqlite_store_create_after_rotate_has_target_kek_version`, `::test_in_memory_store_create_after_rotate_has_target_kek_version`, `::test_sqlite_store_rotate_kek_persists_returned_new_version_without_drift` |
| **Fail-closed opérationnel** — Base inexistante ou vide | La commande CLI refuse de créer silencieusement une base vide (code 2 si fichier absent/vide, code 1 si 0 secret) ; les stores retournent 0 sans changer de KEK si 0 secret ; `rotate_secrets_kek` retourne `(0, 1)` sur base vide sans altérer la base même avec `--target-version` (LOW 2) ; détection de version fail-closed. | `tests/test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_missing_or_empty_database_fails_closed`, `::StoreRotationMethodTests::test_sqlite_store_rotate_empty_does_not_swap_cipher`, `::SqliteStoreDetectKekVersionTests`, `::DatabaseRotationTests::test_rotation_on_empty_db_with_target_version_returns_one_and_writes_nothing` |
| **Intégrité zéro-déchiffrement** — HMAC auxiliaire | L'empreinte HMAC auxiliaire n'est pas modifiée lors de la rotation pour préserver l'absence totale de déchiffrement des valeurs (DoD #71). | `heimdall/vault/crypto.py` (`fingerprint`), `heimdall/vault/database.py` (`rotate_secrets_kek`) |
| **Confinement crypto (#17)** | Aucun import `cryptography`/`argon2` hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest tests/test_vault_kek_rotation.py -q
# 64 passed
.venv/bin/ruff check heimdall tests
# All checks passed!
.venv/bin/mypy heimdall tests/test_vault_kek_rotation.py
# Success: no issues found
```
