# T116 — preuves pour la ligne SAMM (Empreinte HMAC avec clé serveur)

Sous-ticket **T402** (ticket GitHub **#116**) du grand ticket `#40 « États du secret dans le Vault »`,
branche `116-t402-empreinte-hmac-avec-clé-serveur`. Cette fiche fournit les couples
**module + ligne** et les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`e118a69`](https://github.com/Cezar277/heimdall/commit/e118a69e3452d191291096ba9228b61a33ba899f),
> qui intègre le calcul HMAC, la séparation des clés, l'isolation fail-closed post-rotation,
> la parité de repli déchiffrement pour lignes héritées, la suppression de l'extraction de clé
> et l'indexation SQLite. Cette fiche est le commit de documentation associé.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **HMAC-SHA256 avec clé du serveur** : calcul de l'empreinte non réversible selon la formule `hmac.new(cle_serveur, valeur, sha256).hexdigest()` | [crypto.py:255-297](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L255-L297) (`compute_secret_hmac`), [crypto.py:299-318](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L299-L318) (`verify_secret_hmac`), [crypto.py:914-946](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L914-L946) (`VaultCipher.compute_secret_hmac`, `VaultCipher.verify_secret_hmac`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_exact_formula`, `::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time` | Réussi (32 tests passés) |
| **Clé HMAC serveur distincte de la KEK / clé maîtresse** (Invariant 5) | [crypto.py:203-253](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L203-L253) (`server_hmac_key_matches_master_key`), [crypto.py:721-728](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L721-L728) (`VaultCipher.key_reuses_server_hmac_key`), [app.py:943-964](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/app.py#L943-L964) (`validate_server_hmac_key_distinct`), [app.py:374-382](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/app.py#L374-L382) (`_validate_explicit_secret_store_configuration`) | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision`, `::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method`, `::KeySeparationTests::test_vault_settings_enforces_key_separation` | Réussi |
| **Suppression de toute API d'extraction de clé en clair** | [crypto.py:716-719](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L716-L719) (seul le booléen `has_explicit_server_hmac_key` est exposé, aucune propriété `server_hmac_key`) | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed`, `::SecretHmacCryptoTests::test_vault_cipher_factories_propagate_server_hmac_key_without_exposure` | Réussi |
| **Empreinte jamais renvoyée au client** : absente des schémas de réponse HTTP, métadonnées publiques seules | [app.py:116-139](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/app.py#L116-L139) (`SecretMetadata`, `SecretRead` `extra="forbid"`), [store.py:203-210](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L203-L210) (`InMemorySecretStore.create`), [store.py:606-611](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L606-L611) (`SqliteSecretStore.create`), [store.py:660-721](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L660-L721) (`find_secrets_matching_value`) | `tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint`, `::FingerprintNeverReturnedToClientTests::test_no_http_route_exposes_fingerprint_or_leak_detection` | Réussi |
| **Empreinte stable, non réversible et garde anti-clés faibles** : impossible de retrouver le clair sans la clé, normalisation NFC, rejet fail-closed des motifs triviaux | [crypto.py:159-200](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L159-L200) (`_normalize_server_hmac_key`), [crypto.py:275-296](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L275-L296) (`compute_secret_hmac`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256`, `::SecretHmacCryptoTests::test_compute_secret_hmac_supports_nfc_canonicalization`, `::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_trivial_or_repetitive_keys` | Réussi |
| **Vérification zéro-déchiffrement de fuite en production** : détection immédiate de correspondance sans déchiffrer le blob SQLite au repos | [store.py:245-281](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L245-L281) (`InMemorySecretStore.is_secret_value_matching`), [store.py:613-658](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L613-L658) (`SqliteSecretStore.is_secret_value_matching`), [database.py:168](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/database.py#L168) (`idx_secrets_project_fingerprint`), [database.py:1375-1412](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/database.py#L1375-L1412) (`find_secrets_by_fingerprint`) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value`, `::ProductionLeakDetectionTests::test_find_secrets_matching_value_returns_only_metadata` | Réussi |
| **Isolation post-rotation fail-closed et persistance en mode explicite** : en mode dérivé, refus fail-closed (`VaultCipherError`) ; en mode explicite, validité conservée | [crypto.py:948-983](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L948-L983) (`VaultCipher.is_secret_value_matching`), [store.py:245-281](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L245-L281), [store.py:613-658](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L613-L658) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed`, `::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true` | Réussi |
| **Parité des lignes héritées sans empreinte (#25/#62)** : repli transparent par déchiffrement en mémoire et en SQLite (aucun faux négatif silencieux) | [store.py:276-277](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L276-L277), [store.py:313-314](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L313-L314), [store.py:650-652](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L650-L652), [store.py:698-703](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/store.py#L698-L703) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory`, `::ProductionLeakDetectionTests::test_corrupted_fingerprint_in_database_handled_safely` | Réussi |
| **Non-régression double chemin AAD** : un AAD fourni n'accepte jamais une empreinte brute non liée au triplet | [crypto.py:970-983](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py#L970-L983) (`VaultCipher.is_secret_value_matching`) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_rejects_raw_fp_when_aad_is_provided` | Réussi |
| **Validation de format sur requêtes d'empreinte** : `^[0-9a-f]{64}$` requis sur `find_secrets_by_fingerprint` | [database.py:1372-1390](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/database.py#L1372-L1390) (`_HEX_64_PATTERN`, `find_secrets_by_fingerprint`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_find_secrets_by_fingerprint_validates_format` | Réussi |
| **Protection anti-fuite dans logs et sérialisation** : `server_hmac_key` masquée dans `repr()`, `model_dump()` et logs | [app.py:640-650](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/app.py#L640-L650) (`repr=False, exclude=True`) | `tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization`, `tests/test_vault_key_leak_hunt.py` | Réussi |
| **Confinement crypto (#17)** : aucun import de `cryptography` ou `argon2` hors de `crypto.py` | [crypto.py](https://github.com/Cezar277/heimdall/blob/e118a69e3452d191291096ba9228b61a33ba899f/heimdall/vault/crypto.py) | `tests/test_crypto_confinement.py` | Réussi |

## 2. Checklist du ticket

- [x] **HMAC-SHA256 avec clé du serveur** : calculé par `hmac.new(cle_serveur, message, hashlib.sha256).hexdigest()`.
- [x] **Clé HMAC serveur distincte de la clé de chiffrement (Invariant 5)** : contrôle au démarrage et à l'instanciation de `VaultCipher` via la méthode publique `key_reuses_server_hmac_key`.
- [x] **Suppression de l'API d'extraction de clé** : la propriété `VaultCipher.server_hmac_key` est supprimée ; seul le booléen `has_explicit_server_hmac_key` est accessible.
- [x] **Empreinte jamais renvoyée au client** : les schémas `SecretMetadata` et `SecretRead` excluent strictement `fingerprint` (`extra="forbid"`), aucune route HTTP ne l'expose.
- [x] **Empreinte stable, non réversible et garde anti-clés faibles** : garantie par HMAC-SHA256, clé 256 bits, contrôle de diversité minimale et normalisation NFC.
- [x] **Isolation post-rotation** : en mode dérivé, toute tentative de vérification de fuite post-rotation échoue fail-closed (`VaultCipherError`), interdisant les faux négatifs.
- [x] **Parité SQLite / mémoire pour les lignes héritées** : détection garantie des secrets créés avant le ticket #116 via repli transparent par déchiffrement.
- [x] **Chemin unique pour AAD** : aucun repli vers une empreinte brute non liée lorsque l'AAD est fourni.

## 3. Preuve à garder pour le rapport

Exécution de la suite complète du sous-ticket #116 (32 tests unitaires et d'intégration) :

```sh
poetry run pytest tests/test_vault_secret_hmac.py -v
```

Extrait du journal de test :

```text
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.2.0, pluggy-1.6.0
rootdir: /home/epita/Documents/S7/heimdall
configfile: pyproject.toml
plugins: cov-7.1.0, platformdirs-4.12.4, anyio-4.15.1
collected 32 items

tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_exact_formula PASSED [  3%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_stable_and_deterministic PASSED [  6%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256 PASSED [  9%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_supports_nfc_canonicalization PASSED [ 12%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_with_and_without_aad PASSED [ 15%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_input_validation PASSED [ 18%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_trivial_or_repetitive_keys PASSED [ 21%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_generate_server_hmac_key PASSED [ 25%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time PASSED [ 28%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_surrogate_unicode_error PASSED [ 31%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_vault_cipher_methods PASSED [ 34%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_vault_cipher_factories_propagate_server_hmac_key_without_exposure PASSED [ 37%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_find_secrets_by_fingerprint_validates_format PASSED [ 40%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision PASSED [ 43%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method PASSED [ 46%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed PASSED [ 50%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_rejects_server_hmac_key_equal_to_kek PASSED [ 53%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_default_fingerprint_key_is_distinct_from_kek PASSED [ 56%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_settings_enforces_key_separation PASSED [ 59%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value PASSED [ 62%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_in_memory_store_detects_leaked_production_value PASSED [ 65%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_rejects_raw_fp_when_aad_is_provided PASSED [ 68%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_in_derived_mode_raises_error PASSED [ 71%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed PASSED [ 75%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true PASSED [ 78%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory PASSED [ 81%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_corrupted_fingerprint_in_database_handled_safely PASSED [ 84%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_find_secrets_matching_value_returns_only_metadata PASSED [ 87%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_database_find_secrets_by_fingerprint_uses_index PASSED [ 90%]
tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint PASSED [ 93%]
tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_no_http_route_exposes_fingerprint_or_leak_detection PASSED [ 96%]
tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization PASSED [100%]

============================== 32 passed in 0.97s ==============================
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Information Disclosure** — Fuite de la base de données (`vault.db`) | L'empreinte stockée dans la colonne `fingerprint` est calculée par HMAC-SHA256 avec une clé serveur de 256 bits non stockée dans la base SQLite. Contrairement à un simple SHA-256 sans clé, un attaquant disposant d'un dump de la base ne peut pas précalculer de tables arc-en-ciel ni tester des dictionnaires de mots de passe pour retrouver les valeurs originales. | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256` |
| **Information Disclosure** — Extraction de la clé depuis l'objet cipher | La propriété `server_hmac_key` a été supprimée de `VaultCipher`. Aucun code client, composant de débogage ou appel de journalisation ne peut extraire la clé HMAC en clair depuis le chiffreur. | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed` |
| **Information Disclosure** — Fuite vers le client de l'API HTTP | Les modèles FastAPI / Pydantic (`SecretMetadata`, `SecretRead`) n'incluent pas le champ `fingerprint`. Toute tentative d'adjonction est rejetée (`extra="forbid"`). Les fonctions de recherche (`find_secrets_by_fingerprint`, `find_secrets_matching_value`) ne retournent que le quadruplet `(project, env, name, status)`. | `tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint` |
| **Information Disclosure** — Fuite par les journaux et le débogage | `server_hmac_key` dans `VaultSettings` est configurée avec `repr=False` et `exclude=True`. Elle n'apparaît jamais dans `str()`, `repr()`, `model_dump()`, ni `model_dump_json()`. | `tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization`, `tests/test_vault_key_leak_hunt.py` |
| **Invariant 1 & 5** — Invalidation post-rotation en mode dérivé (anti-fail-open) | Sans clé explicite (`server_hmac_key=None`), l'empreinte dérive de la KEK. Comme la rotation de KEK ne modifie pas les empreintes au repos (afin de préserver le non-déchiffrement des valeurs), toute vérification future recalcule une empreinte avec la nouvelle KEK qui ne correspondrait plus. Pour empêcher tout faux négatif de fuite (fail-open), les méthodes de détection de fuite (`is_secret_value_matching`, `find_secrets_matching_value`) échouent fail-closed avec `VaultCipherError` en mode dérivé. En mode clé explicite, la détection reste pérenne et valide post-rotation. | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed`, `::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true` |
| **Invariant 5** — Séparation des clés cryptographiques | La clé HMAC serveur est strictement distincte de la KEK de chiffrement, de la clé maîtresse et du pepper d'authentification API. Les comparateurs en temps constant `server_hmac_key_matches_master_key` et `key_reuses_server_hmac_key` ainsi que les validateurs Pydantic rejettent au démarrage toute tentative de réutilisation d'entropie (fail-closed). | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision`, `::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method` |
| **Tampering & Timing attacks** — Comparaison en temps constant | Les vérifications d'empreinte (`verify_secret_hmac`, `is_secret_value_matching`, `constant_time_equal`) utilisent `hmac.compare_digest` pour interdire toute attaque par canal auxiliaire temporel. | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time` |
| **Zero-Decryption Leak Detection (avec repli documenté)** | Pour savoir si un secret en production est celui qui a fuité dans Git, `is_secret_value_matching` et `find_secrets_matching_value` comparent l'empreinte de la valeur suspectée avec celle indexée en base, sans jamais déchiffrer le blob de données au repos. Pour les lignes héritées des tickets antérieurs (#25/#62) ne comportant pas d'empreinte, un repli transparent par déchiffrement est opéré avec stricte parité SQLite / mémoire pour éviter tout faux négatif. | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value`, `::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory` |
| **Confinement crypto (#17)** | Aucun import `cryptography` ou `argon2` n'est autorisé hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv Poetry local.

```sh
poetry run pytest tests/test_vault_secret_hmac.py -v
# 32 passed in 0.97s

poetry run pytest tests/test_vault_*.py tests/test_crypto_confinement.py -q
# 100% passed

poetry run ruff check heimdall tests
# All checks passed!

poetry run mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found in 51 source files

poetry run python docs/security/check_model.py
# OK: 48 STRIDE scenarios, valid scores, 10 linked risks/requirements, local links
```
