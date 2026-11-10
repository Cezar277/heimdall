# T116 — preuves pour la ligne SAMM (Empreinte HMAC avec clé serveur)

Sous-ticket **T402** (ticket GitHub **#116**) du grand ticket `#40 « États du secret dans le Vault »`,
branche `116-t402-empreinte-hmac-avec-clé-serveur`. Cette fiche fournit les couples
**module + ligne** et les tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`2657e6d`](https://github.com/Cezar277/heimdall/commit/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7),
> qui intègre le calcul HMAC, la séparation des clés, l'isolation fail-closed post-rotation,
> le canari d'invalidation de clé HMAC serveur, le contrôle d'entropie de Shannon, la parité de valeur vide,
> la parité de repli déchiffrement pour lignes héritées, la suppression de l'extraction de clé
> et l'indexation SQLite. Cette fiche est le commit de documentation associé.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **HMAC-SHA256 avec clé du serveur** : calcul de l'empreinte non réversible selon la formule `hmac.new(cle_serveur, valeur, sha256).hexdigest()` | [crypto.py:274-316](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L274-L316) (`compute_secret_hmac`), [crypto.py:318-337](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L318-L337) (`verify_secret_hmac`), [crypto.py:967-987](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L967-L987) (`VaultCipher.compute_secret_hmac`, `VaultCipher.verify_secret_hmac`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_exact_formula`, `::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time` | Réussi (36 tests passés) |
| **Clé HMAC serveur distincte de la KEK / clé maîtresse** (Invariant 5) | [crypto.py:222-272](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L222-L272) (`server_hmac_key_matches_master_key`), [crypto.py:734-741](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L734-L741) (`VaultCipher.key_reuses_server_hmac_key`), [app.py:943-964](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/app.py#L943-L964) (`validate_server_hmac_key_distinct`), [app.py:374-382](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/app.py#L374-L382) (`_validate_explicit_secret_store_configuration`) | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision`, `::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method`, `::KeySeparationTests::test_vault_settings_enforces_key_separation` | Réussi |
| **Suppression de toute API d'extraction de clé en clair** | [crypto.py:729-732](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L729-L732) (seul le booléen `has_explicit_server_hmac_key` est exposé, aucune propriété `server_hmac_key`) | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed`, `::SecretHmacCryptoTests::test_vault_cipher_factories_propagate_server_hmac_key_without_exposure` | Réussi |
| **Empreinte jamais renvoyée au client** : absente des schémas de réponse HTTP, métadonnées publiques seules | [app.py:116-139](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/app.py#L116-L139) (`SecretMetadata`, `SecretRead` `extra="forbid"`), [store.py:203-214](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L203-L214) (`InMemorySecretStore.create`), [store.py:627-640](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L627-L640) (`SqliteSecretStore.create`), [store.py:719-780](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L719-L780) (`find_secrets_matching_value`) | `tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint`, `::FingerprintNeverReturnedToClientTests::test_no_http_route_exposes_fingerprint_or_leak_detection` | Réussi |
| **Empreinte stable, non réversible et garde anti-clés faibles durcie** : au moins 32 octets, au moins 16 symboles distincts, rejet périodes répétitives $1 \dots \lfloor \text{len}/2 \rfloor$, entropie Shannon $\ge 3.5$, normalisation NFC, `generate_server_hmac_key()` seule voie supportée | [crypto.py:77-86](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L77-L86) (`_shannon_entropy`), [crypto.py:171-220](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L171-L220) (`_normalize_server_hmac_key`), [crypto.py:274-316](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L274-L316) (`compute_secret_hmac`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256`, `::SecretHmacCryptoTests::test_compute_secret_hmac_supports_nfc_canonicalization`, `::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_trivial_or_repetitive_keys`, `::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_subtle_weak_patterns` | Réussi |
| **Vérification zéro-déchiffrement de fuite en production** : détection immédiate de correspondance sans déchiffrer le blob SQLite au repos | [store.py:258-299](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L258-L299) (`InMemorySecretStore.is_secret_value_matching`), [store.py:656-715](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L656-L715) (`SqliteSecretStore.is_secret_value_matching`), [database.py:168](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/database.py#L168) (`idx_secrets_project_fingerprint`), [database.py:1412-1449](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/database.py#L1412-L1449) (`find_secrets_by_fingerprint`) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value`, `::ProductionLeakDetectionTests::test_find_secrets_matching_value_returns_only_metadata` | Réussi |
| **Canari cryptographique de clé HMAC serveur (anti-faux négatif fail-closed)** : persistance d'un canari non réversible en table `server_hmac_canary` et détection de désaccord de clé | [crypto.py:743-753](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L743-L753) (`VaultCipher.server_hmac_key_canary`), [database.py:1073-1088](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/database.py#L1073-L1088) (`get_server_hmac_canary`, `set_server_hmac_canary`), [store.py:276-285,322-331,684-699,748-761](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L276-L285) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_explicit_server_hmac_key_change_fails_closed` | Réussi |
| **Parité de traitement de la valeur candidate vide** : retour immédiat `False` ou `[]` sans déchiffrement ni exception avec et sans AAD | [crypto.py:996-997](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L996-L997) (`VaultCipher.is_secret_value_matching`), [store.py:260-261,305-306,658-659,718-719](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L260-L261) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_candidate_value_empty_parity_cipher`, `::ProductionLeakDetectionTests::test_candidate_value_empty_parity_stores` | Réussi |
| **Isolation post-rotation fail-closed et persistance en mode explicite** : en mode dérivé, refus fail-closed (`VaultCipherError`) ; en mode explicite, validité conservée | [crypto.py:989-1025](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L989-L1025) (`VaultCipher.is_secret_value_matching`), [store.py:258-299](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L258-L299), [store.py:656-715](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L656-L715) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed`, `::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true` | Réussi |
| **Parité des lignes héritées sans empreinte (#25/#62)** : repli transparent par déchiffrement en mémoire et en SQLite (aucun faux négatif silencieux) | [store.py:293-294](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L293-L294), [store.py:349-350](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L349-L350), [store.py:707-709](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L707-L709), [store.py:768-773](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/store.py#L768-L773) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory`, `::ProductionLeakDetectionTests::test_corrupted_fingerprint_in_database_handled_safely` | Réussi |
| **Non-régression double chemin AAD** : un AAD fourni n'accepte jamais une empreinte brute non liée au triplet | [crypto.py:1012-1025](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py#L1012-L1025) (`VaultCipher.is_secret_value_matching`) | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_rejects_raw_fp_when_aad_is_provided` | Réussi |
| **Validation de format sur requêtes d'empreinte** : `^[0-9a-f]{64}$` requis sur `find_secrets_by_fingerprint` | [database.py:1409-1427](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/database.py#L1409-L1427) (`_HEX_64_PATTERN`, `find_secrets_by_fingerprint`) | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_find_secrets_by_fingerprint_validates_format` | Réussi |
| **Protection anti-fuite dans logs et sérialisation** : `server_hmac_key` masquée dans `repr()`, `model_dump()` et logs | [app.py:640-650](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/app.py#L640-L650) (`repr=False, exclude=True`) | `tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization`, `tests/test_vault_key_leak_hunt.py` | Réussi |
| **Confinement crypto (#17)** : aucun import de `cryptography` ou `argon2` hors de `crypto.py` | [crypto.py](https://github.com/Cezar277/heimdall/blob/2657e6d8ec05ff6731f2eadf23bd0b5fdf5d31e7/heimdall/vault/crypto.py) | `tests/test_crypto_confinement.py` | Réussi |

## 2. Checklist du ticket

- [x] **HMAC-SHA256 avec clé du serveur** : calculé par `hmac.new(cle_serveur, message, hashlib.sha256).hexdigest()`.
- [x] **Clé HMAC serveur distincte de la clé de chiffrement (Invariant 5)** : contrôle au démarrage et à l'instanciation de `VaultCipher` via la méthode publique `key_reuses_server_hmac_key`.
- [x] **Suppression de l'API d'extraction de clé** : la propriété `VaultCipher.server_hmac_key` est supprimée ; seul le booléen `has_explicit_server_hmac_key` est accessible.
- [x] **Canari persistant de clé HMAC serveur** : table SQLite `server_hmac_canary` (`id=1`) et état mémoire détectant tout changement non synchronisé de la clé d'empreinte, avec refus fail-closed immédiat (`VaultCipherError`) éliminant tout faux négatif de fuite.
- [x] **Garde anti-clés faibles durcie** : au moins 32 octets, au moins 16 symboles distincts, rejet des motifs périodiques jusqu'à la moitié de la taille et seuil d'entropie de Shannon $\ge 3.5$ bits/octet ; documentation de `generate_server_hmac_key()` comme seule voie supportée.
- [x] **Parité valeur vide** : `candidate_value == ""` renvoie `False` ou `[]` immédiatement et uniformément (Cipher, mémoire, SQLite) avec et sans AAD.
- [x] **Empreinte jamais renvoyée au client** : les schémas `SecretMetadata` et `SecretRead` excluent strictement `fingerprint` (`extra="forbid"`), aucune route HTTP ne l'expose.
- [x] **Isolation post-rotation** : en mode dérivé, toute tentative de vérification de fuite post-rotation échoue fail-closed (`VaultCipherError`), interdisant les faux négatifs.
- [x] **Parité SQLite / mémoire pour les lignes héritées** : détection garantie des secrets créés avant le ticket #116 via repli transparent par déchiffrement.
- [x] **Chemin unique pour AAD** : aucun repli vers une empreinte brute non liée lorsque l'AAD est fourni.

## 3. Preuve à garder pour le rapport

Exécution de la suite complète du sous-ticket #116 (36 tests unitaires et d'intégration) :

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
collected 36 items

tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_exact_formula PASSED [  2%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_stable_and_deterministic PASSED [  5%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256 PASSED [  8%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_supports_nfc_canonicalization PASSED [ 11%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_with_and_without_aad PASSED [ 13%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_input_validation PASSED [ 16%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_trivial_or_repetitive_keys PASSED [ 19%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_subtle_weak_patterns PASSED [ 22%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_candidate_value_empty_parity_cipher PASSED [ 25%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_generate_server_hmac_key PASSED [ 27%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time PASSED [ 30%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_surrogate_unicode_error PASSED [ 33%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_vault_cipher_methods PASSED [ 36%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_vault_cipher_factories_propagate_server_hmac_key_without_exposure PASSED [ 38%]
tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_find_secrets_by_fingerprint_validates_format PASSED [ 41%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision PASSED [ 44%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method PASSED [ 47%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed PASSED [ 50%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_rejects_server_hmac_key_equal_to_kek PASSED [ 52%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_default_fingerprint_key_is_distinct_from_kek PASSED [ 55%]
tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_settings_enforces_key_separation PASSED [ 58%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value PASSED [ 61%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_in_memory_store_detects_leaked_production_value PASSED [ 63%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_rejects_raw_fp_when_aad_is_provided PASSED [ 66%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_cipher_is_secret_value_matching_in_derived_mode_raises_error PASSED [ 69%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed PASSED [ 72%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true PASSED [ 75%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory PASSED [ 77%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_corrupted_fingerprint_in_database_handled_safely PASSED [ 80%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_find_secrets_matching_value_returns_only_metadata PASSED [ 83%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_candidate_value_empty_parity_stores PASSED [ 86%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_explicit_server_hmac_key_change_fails_closed PASSED [ 88%]
tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_database_find_secrets_by_fingerprint_uses_index PASSED [ 91%]
tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint PASSED [ 94%]
tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_no_http_route_exposes_fingerprint_or_leak_detection PASSED [ 97%]
tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization PASSED [100%]

============================== 36 passed in 0.71s ==============================
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Information Disclosure** — Fuite de la base de données (`vault.db`) | L'empreinte stockée dans la colonne `fingerprint` est calculée par HMAC-SHA256 avec une clé serveur de 256 bits non stockée dans la base SQLite. Contrairement à un simple SHA-256 sans clé, un attaquant disposant d'un dump de la base ne peut pas précalculer de tables arc-en-ciel ni tester des dictionnaires de mots de passe pour retrouver les valeurs originales. | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_compute_secret_hmac_is_non_reversible_and_differs_from_plain_sha256` |
| **Information Disclosure** — Attaque par dictionnaire sur clé faible | En plus des 32 octets minimaux et 16 symboles distincts, l'entropie de Shannon est validée $\ge 3.5$ bits/octet et tout motif périodique est rejeté pour neutraliser les clés répétitives du type `ABCDEFGH*4`. `generate_server_hmac_key()` est documentée comme seule voie supportée. | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_normalize_server_hmac_key_rejects_subtle_weak_patterns` |
| **Information Disclosure** — Extraction de la clé depuis l'objet cipher | La propriété `server_hmac_key` a été supprimée de `VaultCipher`. Aucun code client, composant de débogage ou appel de journalisation ne peut extraire la clé HMAC en clair depuis le chiffreur. | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_vault_cipher_server_hmac_key_property_removed` |
| **Information Disclosure** — Fuite vers le client de l'API HTTP | Les modèles FastAPI / Pydantic (`SecretMetadata`, `SecretRead`) n'incluent pas le champ `fingerprint`. Toute tentative d'adjonction est rejetée (`extra="forbid"`). Les fonctions de recherche (`find_secrets_by_fingerprint`, `find_secrets_matching_value`) ne retournent que le quadruplet `(project, env, name, status)`. | `tests/test_vault_secret_hmac.py::FingerprintNeverReturnedToClientTests::test_api_responses_never_expose_fingerprint` |
| **Information Disclosure** — Fuite par les journaux et le débogage | `server_hmac_key` dans `VaultSettings` est configurée avec `repr=False` et `exclude=True`. Elle n'apparaît jamais dans `str()`, `repr()`, `model_dump()`, ni `model_dump_json()`. | `tests/test_vault_secret_hmac.py::KeyLeakHuntTests::test_server_hmac_key_is_never_leaked_in_repr_or_serialization`, `tests/test_vault_key_leak_hunt.py` |
| **Invariant 1** — Changement non synchronisé de la clé HMAC serveur (anti-faux négatif) | En cas de changement de `HEIMDALL_VAULT_SERVER_HMAC_KEY` (rotation ou redéploiement non migré), les empreintes en base deviendraient silencieusement différentes. Le canari cryptographique `server_hmac_canary` stocké en base SQLite (`id=1`) et en mémoire détecte ce désaccord et lève immédiatement `VaultCipherError` fail-closed au lieu de renvoyer `False` (« non compromis »). | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_explicit_server_hmac_key_change_fails_closed` |
| **Invariant 1 & 5** — Invalidation post-rotation en mode dérivé (anti-fail-open) | Sans clé explicite (`server_hmac_key=None`), l'empreinte dérive de la KEK. Comme la rotation de KEK ne modifie pas les empreintes au repos (afin de préserver le non-déchiffrement des valeurs), toute vérification future recalcule une empreinte avec la nouvelle KEK qui ne correspondrait plus. Pour empêcher tout faux négatif de fuite (fail-open), les méthodes de détection de fuite (`is_secret_value_matching`, `find_secrets_matching_value`) échouent fail-closed avec `VaultCipherError` en mode dérivé. En mode clé explicite, la détection reste pérenne et valide post-rotation. | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_derived_mode_fails_closed`, `::ProductionLeakDetectionTests::test_leak_detection_post_kek_rotation_in_explicit_mode_remains_true` |
| **Invariant 5** — Séparation des clés cryptographiques | La clé HMAC serveur est strictement distincte de la KEK de chiffrement, de la clé maîtresse et du pepper d'authentification API. Les comparateurs en temps constant `server_hmac_key_matches_master_key` et `key_reuses_server_hmac_key` ainsi que les validateurs Pydantic rejettent au démarrage toute tentative de réutilisation d'entropie (fail-closed). | `tests/test_vault_secret_hmac.py::KeySeparationTests::test_server_hmac_key_matches_master_key_detects_collision`, `::KeySeparationTests::test_vault_cipher_key_reuses_server_hmac_key_method` |
| **Tampering & Timing attacks** — Comparaison en temps constant | Les vérifications d'empreinte (`verify_secret_hmac`, `is_secret_value_matching`, `constant_time_equal`) utilisent `hmac.compare_digest` pour interdire toute attaque par canal auxiliaire temporel. | `tests/test_vault_secret_hmac.py::SecretHmacCryptoTests::test_verify_secret_hmac_constant_time` |
| **Zero-Decryption Leak Detection (avec repli documenté)** | Pour savoir si un secret en production est celui qui a fuité dans Git, `is_secret_value_matching` et `find_secrets_matching_value` comparent l'empreinte de la valeur suspectée avec celle indexée en base, sans jamais déchiffrer le blob de données au repos. Pour les lignes héritées des tickets antérieurs (#25/#62) ne comportant pas d'empreinte, un repli transparent par déchiffrement est opéré avec stricte parité SQLite / mémoire pour éviter tout faux négatif. | `tests/test_vault_secret_hmac.py::ProductionLeakDetectionTests::test_sqlite_store_detects_leaked_production_value`, `::ProductionLeakDetectionTests::test_legacy_secrets_without_fingerprint_parity_sqlite_and_memory` |
| **Confinement crypto (#17)** | Aucun import `cryptography` ou `argon2` n'est autorisé hors de `heimdall/vault/crypto.py`. | `tests/test_crypto_confinement.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv Poetry local.

```sh
poetry run pytest tests/test_vault_secret_hmac.py -v
# 36 passed in 0.71s

poetry run pytest tests/test_vault_*.py tests/test_crypto_confinement.py -q
# 100% passed

poetry run ruff check heimdall tests
# All checks passed!

poetry run mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found in 51 source files

poetry run python docs/security/check_model.py
# OK: 48 STRIDE scenarios, valid scores, 10 linked risks/requirements, local links
```
