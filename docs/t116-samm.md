# T116 — preuves pour la ligne SAMM (Empreinte HMAC avec clé serveur)

Sous-ticket **T402** (ticket GitHub **#116**) du grand ticket `#40 « États du secret dans le Vault »`,
branche `116-t402-empreinte-hmac-avec-clé-serveur`. Cette fiche fournit les couples
**module + ligne** et les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`f294fcd`](https://github.com/Cezar277/heimdall/commit/f294fcd753b9847f5a071f493d92c5e6171c7693),
> qui implémente le calcul HMAC, la séparation des clés, l'indexation SQLite et la vérification
> zéro-déchiffrement. Cette fiche est le commit de documentation associé.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **HMAC-SHA256 avec clé du serveur** : calcul de l'empreinte non réversible selon la formule `hmac.new(cle_serveur, valeur, sha256).hexdigest()` | [heimdall/vault/crypto.py:228-270](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L228-L270) (`compute_secret_hmac`), [heimdall/vault/crypto.py:272-291](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L272-L291) (`verify_secret_hmac`), [heimdall/vault/crypto.py:900-935](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L900-L935) (`VaultCipher.compute_secret_hmac`, `VaultCipher.verify_secret_hmac`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_compute_secret_hmac_exact_formula_and_determinism`, `::test_verify_secret_hmac_constant_time` | Réussi (21 tests passés) |
| **Clé HMAC serveur distincte de la KEK / clé maîtresse** (Invariant 5) | [heimdall/vault/crypto.py:189-226](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L189-L226) (`server_hmac_key_matches_master_key`), [heimdall/vault/app.py:954-975](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/app.py#L954-L975) (`validate_server_hmac_key_distinct`), [heimdall/vault/app.py:375-385](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/app.py#L375-L385) (`_validate_explicit_secret_store_configuration`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_server_hmac_key_must_be_distinct_from_master_key_and_kek`, `::test_settings_reject_server_hmac_key_equal_to_master_key_or_pepper` | Réussi |
| **Empreinte jamais renvoyée au client** : absente des schémas de réponse HTTP, métadonnées publiques seules | [heimdall/vault/app.py:117-140](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/app.py#L117-L140) (`SecretMetadata`, `SecretRead` `extra="forbid"`), [heimdall/vault/store.py:203-210](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/store.py#L203-L210) (`InMemorySecretStore.create`), [heimdall/vault/store.py:573-578](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/store.py#L573-L578) (`SqliteSecretStore.create`), [heimdall/vault/store.py:623-667](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/store.py#L623-L667) (`find_secrets_matching_value`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_api_responses_never_expose_fingerprint` | Réussi |
| **Empreinte stable et non réversible** : impossible de retrouver le clair sans la clé, résistance dictionnaire / tables arc-en-ciel, normalisation NFC | [heimdall/vault/crypto.py:158-186](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L158-L186) (`_normalize_server_hmac_key`), [heimdall/vault/crypto.py:248-269](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py#L248-L269) (`compute_secret_hmac`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_non_reversibility_and_key_dependency`, `::test_nfc_normalization_produces_identical_hmac` | Réussi |
| **Vérification zéro-déchiffrement de fuite en production** : détection immédiate de correspondance sans déchiffrer le blob SQLite au repos | [heimdall/vault/store.py:245-269](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/store.py#L245-L269) (`InMemorySecretStore.is_secret_value_matching`), [heimdall/vault/store.py:580-622](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/store.py#L580-L622) (`SqliteSecretStore.is_secret_value_matching`), [heimdall/vault/database.py:167](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/database.py#L167) (`idx_secrets_project_fingerprint`), [heimdall/vault/database.py:1371-1398](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/database.py#L1371-L1398) (`find_secrets_by_fingerprint`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_detect_leaked_secret_in_production_without_decryption`, `::test_find_secrets_matching_value_returns_only_matching_metadata` | Réussi |
| **Protection anti-fuite dans logs et sérialisation** : `server_hmac_key` masquée dans `repr()`, `model_dump()` et logs | [heimdall/vault/app.py:641-651](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/app.py#L641-L651) (`repr=False, exclude=True`) | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_server_hmac_key_redacted_in_settings_repr_and_export`, `tests/test_vault_key_leak_hunt.py` | Réussi |
| **Confinement crypto (#17)** : aucun import de `cryptography` ou `argon2` hors de `crypto.py` | [heimdall/vault/crypto.py](https://github.com/Cezar277/heimdall/blob/f294fcd753b9847f5a071f493d92c5e6171c7693/heimdall/vault/crypto.py) | `tests/test_crypto_confinement.py` | Réussi |

## 2. Checklist du ticket

- [x] **HMAC-SHA256 avec clé du serveur** : implémenté via `hmac.new(cle_serveur, message, hashlib.sha256).hexdigest()`.
- [x] **Clé HMAC serveur distincte de la clé de chiffrement** : validé statiquement et dynamiquement (Invariant 5) ; en l'absence de clé explicite, une sous-clé HKDF dédiée est dérivée.
- [x] **Empreinte jamais renvoyée au client** : les modèles `SecretMetadata` et `SecretRead` excluent strictement `fingerprint` (`extra="forbid"`), les requêtes API ne la divulguent jamais.
- [x] **Empreinte stable, non réversible** : garantie par HMAC-SHA256 avec clé 256 bits et normalisation NFC.
- [x] **Pièges évités** : pas de SHA-256 sans clé (vulnérable aux attaques pré-calculées par tables arc-en-ciel).

## 3. Preuve à garder pour le rapport

Exécution de la suite dédiée à l'empreinte HMAC (#116) :

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
collected 21 items

tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_compute_secret_hmac_exact_formula_and_determinism PASSED [  4%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_compute_secret_hmac_rejects_empty_or_invalid_inputs PASSED [  9%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_non_reversibility_and_key_dependency PASSED [ 14%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_nfc_normalization_produces_identical_hmac PASSED [ 19%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_aad_binding_changes_hmac PASSED [ 23%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_verify_secret_hmac_constant_time PASSED [ 28%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_generate_server_hmac_key_entropy PASSED [ 33%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_normalize_server_hmac_key_length_and_whitespace PASSED [ 38%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_server_hmac_key_must_be_distinct_from_master_key_and_kek PASSED [ 42%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_vault_cipher_uses_explicit_or_derived_server_hmac_key PASSED [ 47%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_vault_cipher_from_master_key_and_encoded_key_forward_server_hmac_key PASSED [ 52%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_detect_leaked_secret_in_production_without_decryption PASSED [ 57%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_find_secrets_matching_value_returns_only_matching_metadata PASSED [ 61%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_find_secrets_by_fingerprint_in_database PASSED [ 66%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_store_creation_stores_hmac_fingerprint PASSED [ 71%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_settings_server_hmac_key_validation PASSED [ 76%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_settings_reject_server_hmac_key_equal_to_master_key_or_pepper PASSED [ 80%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_settings_server_hmac_key_redacted_in_repr_and_dump PASSED [ 85%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_api_responses_never_expose_fingerprint PASSED [ 90%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_api_secret_store_initialization_with_server_hmac_key PASSED [ 95%]
tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_server_hmac_key_redacted_in_settings_repr_and_export PASSED [100%]

============================== 21 passed in 0.96s ==============================
```

Exécution de l'intégralité des suites Vault et de confinement crypto :

```sh
poetry run pytest tests/test_vault_*.py tests/test_crypto_confinement.py -q
# 100% passed
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Information Disclosure** — Fuite de la base de données (`vault.db`) | L'empreinte stockée dans la colonne `fingerprint` est calculée par HMAC-SHA256 avec une clé serveur de 256 bits non stockée dans la base SQLite. Contrairement à un simple SHA-256 sans clé, un attaquant disposant d'un dump de la base ne peut pas précalculer de tables arc-en-ciel ni tester des dictionnaires de mots de passe pour retrouver les valeurs originales. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_non_reversibility_and_key_dependency` |
| **Information Disclosure** — Fuite vers le client de l'API HTTP | Les modèles FastAPI / Pydantic (`SecretMetadata`, `SecretRead`) n'incluent pas le champ `fingerprint`. Toute tentative d'adjonction est rejetée (`extra="forbid"`). Les fonctions de recherche (`find_secrets_by_fingerprint`, `find_secrets_matching_value`) ne retournent que le quadruplet `(project, env, name, status)`. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_api_responses_never_expose_fingerprint` |
| **Information Disclosure** — Fuite par les journaux et le débogage | `server_hmac_key` dans `VaultSettings` est configurée avec `repr=False` et `exclude=True`. Elle n'apparaît jamais dans `str()`, `repr()`, `model_dump()`, ni `model_dump_json()`. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_settings_server_hmac_key_redacted_in_repr_and_dump`, `tests/test_vault_key_leak_hunt.py` |
| **Invariant 5** — Séparation des clés cryptographiques | La clé HMAC serveur est strictement distincte de la KEK de chiffrement, de la clé maîtresse et du pepper d'authentification API. Les comparateurs en temps constant `server_hmac_key_matches_master_key` et les validateurs Pydantic rejettent au démarrage toute tentative de réutilisation d'entropie (fail-closed). En l'absence de clé HMAC explicite, `VaultCipher` dérive une sous-clé HKDF dédiée distincte avec l'info `heimdall-vault-fingerprint-v1`. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_server_hmac_key_must_be_distinct_from_master_key_and_kek`, `::test_settings_reject_server_hmac_key_equal_to_master_key_or_pepper` |
| **Tampering & Timing attacks** — Comparaison en temps constant | Les vérifications d'empreinte (`verify_secret_hmac`, `is_secret_value_matching`, `constant_time_equal`) utilisent `hmac.compare_digest` pour interdire toute attaque par canal auxiliaire temporel. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_verify_secret_hmac_constant_time` |
| **Zero-Decryption Leak Detection** | Pour savoir si un secret en production est celui qui a fuité dans Git, `is_secret_value_matching` et `find_secrets_matching_value` comparent l'empreinte de la valeur suspectée avec celle indexée en base, sans jamais déchiffrer le blob de données au repos. L'opération est rapide et n'expose pas la DEK en mémoire. | `tests/test_vault_secret_hmac.py::VaultSecretHmacTests::test_detect_leaked_secret_in_production_without_decryption` |
| **Confinement crypto (#17)** | Aucun import `cryptography` ou `argon2` n'est autorisé hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv Poetry local.

```sh
poetry run pytest tests/test_vault_secret_hmac.py -v
# 21 passed in 0.96s

poetry run ruff check heimdall tests
# All checks passed!

poetry run mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found in 51 source files

poetry run python docs/security/check_model.py
# OK: 48 STRIDE scenarios, valid scores, 10 linked risks/requirements, local links
```
