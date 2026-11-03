# T263 — preuves pour la ligne SAMM (DEK par secret et stockage chiffré)

Sous-ticket **T263** (ticket GitHub **#70**) du grand ticket `#26 « Clé
maîtresse et chiffrement par enveloppe »`, branche
`70-t263-dek-par-secret-et-stockage-chiffré`. Cette fiche fournit les couples
module + ligne et les tests qui prouvent la checklist ; elle ne remplace pas la
revue de code.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Générer une **DEK aléatoire de 32 octets** par secret | [heimdall/vault/crypto.py:97-104](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L97-L104) (`generate_dek`), [heimdall/vault/crypto.py:431-448](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L431-L448) (`encrypt_envelope` tire une DEK neuve à chaque appel) | [tests/test_vault_dek_envelope.py:53-57](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L53-L57) (64 DEK de 32 octets, toutes distinctes) | Réussi |
| Chiffrer la **valeur avec la DEK** | [heimdall/vault/crypto.py:377-395](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L377-L395) (`encrypt_with_dek`), [heimdall/vault/crypto.py:431-448](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L431-L448) (`encrypt_envelope`) | [tests/test_vault_dek_envelope.py:59-82](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L59-L82) (la valeur se déchiffre avec la DEK, pas avec la KEK seule) | Réussi |
| Chiffrer la **DEK avec la KEK** | [heimdall/vault/crypto.py:411-429](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L411-L429) (`wrap_dek`, `unwrap_dek`), label de domaine `_DEK_WRAP_AAD_PREFIX` | [tests/test_vault_dek_envelope.py:59-82](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L59-L82) (la DEK enveloppée se déchiffre avec la KEK et fait 32 octets) | Réussi |
| **Stocker les deux blobs** dans la ligne du secret | [heimdall/vault/database.py:99-115](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/database.py#L99-L115) (`encrypted_value`, `encrypted_dek`), [heimdall/vault/store.py:160-168](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L160-L168) (mémoire), [heimdall/vault/store.py:277-288](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L277-L288) (SQLite) | [tests/test_vault_dek_envelope.py:109-135](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L109-L135) (deux secrets, même valeur : deux valeurs chiffrées et deux DEK enveloppées) | Réussi |
| **Lecture** : déchiffrer la DEK avec la KEK, puis la valeur avec la DEK | [heimdall/vault/crypto.py:450-462](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L450-L462) (`decrypt_envelope`), [heimdall/vault/store.py:62-85](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L62-L85) (`_decrypt_record`) | [tests/test_vault_dek_envelope.py:137-149](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L137-L149) (relecture après réouverture du store) | Réussi |
| **Fait quand** : aucune valeur en clair dans la base (test qui lit le fichier SQLite brut) | [heimdall/vault/store.py:277-288](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L277-L288) (seuls les deux jetons base64 sont écrits) | [tests/test_vault_dek_envelope.py:151-180](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L151-L180) (lecture de `vault.db` en octets : aucun canari, aucune DEK brute) | Réussi |
| Un blob de valeur ou de DEK **déplacé vers un autre secret** échoue | AAD = triplet pour la valeur ; label de domaine + triplet pour l'enveloppe de DEK ([heimdall/vault/crypto.py:411-429](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L411-L429), [heimdall/vault/crypto.py:431-462](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L431-L462)) | [tests/test_vault_dek_envelope.py:84-103](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L84-L103) (unwrap et déchiffrement sous une autre identité ⇒ `VaultCipherError`) | Réussi |
| Les lignes **héritées** (#25/#62, sans DEK) restent lisibles | [heimdall/vault/database.py:883-907](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/database.py#L883-L907) (migration additive), [heimdall/vault/store.py:62-85](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L62-L85) (repli KEK direct) | [tests/test_vault_dek_envelope.py:197-220](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L197-L220) (ligne chiffrée directement par la KEK) | Réussi |
| Migration **sans perte** des bases existantes | [heimdall/vault/database.py:883-907](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/database.py#L883-L907) (`_ensure_secret_envelope_column`), [heimdall/vault/database.py:910-927](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/database.py#L910-L927) (`init_db`) | [tests/test_vault_dek_envelope.py:223-244](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L223-L244) (schéma antérieur, puis colonne ajoutée) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Générer une DEK par secret | `tests/test_vault_dek_envelope.py::DekGenerationTests::test_generate_dek_returns_32_random_bytes` |
| Chiffrer la valeur avec la DEK, puis la DEK avec la KEK | `tests/test_vault_dek_envelope.py::DekGenerationTests::test_envelope_wraps_value_with_dek_and_dek_with_kek` |
| Stocker les deux blobs | `tests/test_vault_dek_envelope.py::SqliteEnvelopeStorageTests::test_two_secrets_same_value_have_distinct_deks_and_blobs` |
| **Fait quand** : aucune valeur en clair dans la base | `tests/test_vault_dek_envelope.py::SqliteEnvelopeStorageTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek` |

## 3. Preuve à garder pour le rapport

Le test ouvre le fichier SQLite **brut** après création de trois secrets et
vérifie qu'aucune valeur en clair — ni aucune DEK brute — n'y apparaît :

```sh
.venv/bin/python -m pytest \
  tests/test_vault_dek_envelope.py::SqliteEnvelopeStorageTests::test_raw_sqlite_file_contains_no_plaintext_and_no_raw_dek -q
# 1 passed
```

La suite complète du sous-ticket :

```sh
.venv/bin/python -m pytest tests/test_vault_dek_envelope.py -q
# 15 passed
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Information disclosure** — une clé compromise expose tous les secrets | Chaque secret a sa propre DEK ; la KEK ne chiffre que les DEK. Une fuite de DEK ne compromet qu'un secret. | [heimdall/vault/crypto.py:97-104](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L97-L104), [heimdall/vault/crypto.py:431-448](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L431-L448) ; [tests/test_vault_dek_envelope.py:109-135](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L109-L135) |
| **Information disclosure** — la base seule révèle les valeurs ou les DEK | Les valeurs et les DEK sont chiffrées ; la KEK n'est jamais en base. Le test lit le fichier SQLite brut. | [heimdall/vault/store.py:277-288](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L277-L288) ; [tests/test_vault_dek_envelope.py:151-180](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L151-L180) |
| **Tampering** — copie d'un blob de valeur ou de DEK vers un autre secret | AAD = identité du secret pour la valeur ; label de domaine dédié + identité pour l'enveloppe de DEK. | [heimdall/vault/crypto.py:411-462](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L411-L462) ; [tests/test_vault_dek_envelope.py:84-103](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/tests/test_vault_dek_envelope.py#L84-L103) |
| **Tampering** — réutilisation du nonce AES-GCM | Inchangé depuis #67 : nonce de 96 bits tiré par `os.urandom` à chaque chiffrement, y compris pour la valeur et pour l'enveloppe de DEK. | [heimdall/vault/crypto.py:232-247](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L232-L247), [heimdall/vault/crypto.py:271-286](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L271-L286) ; `tests/test_vault_crypto.py` |
| **Information disclosure** — erreurs de déchiffrement bavardes | `VaultCipherError` générique ; `SecretStoreError` générique dans le store. | [heimdall/vault/crypto.py:250-286](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/crypto.py#L250-L286), [heimdall/vault/store.py:62-85](https://github.com/Cezar277/heimdall/blob/cf33602a3c9545882920d8f4c188efc021ff0515/heimdall/vault/store.py#L62-L85) |
| Invariant 5 — jamais la même clé pour chiffrer et authentifier | La KEK reste distincte du pepper (contrôle existant) ; la DEK n'est utilisée que pour AES-GCM, jamais comme clé HMAC. | `heimdall/vault/crypto.py` (`wrap_dek`/`encrypt_with_dek`), `heimdall/vault/app.py` (validation KEK/pepper) |
| Confinement crypto (#17) | Aucun import de `cryptography` hors `heimdall/vault/crypto.py` : le store ne manipule que des jetons opaques. | `tests/test_crypto_confinement.py` |
| Aucune primitive maison | AES-256-GCM de la bibliothèque `cryptography` (50.0.2), aucune construction AES maison. | `pyproject.toml`, `heimdall/vault/crypto.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest tests/test_vault_dek_envelope.py -q
# 15 passed
.venv/bin/python -m pytest tests/test_vault_crypto.py tests/test_vault_db.py \
  tests/test_vault_app.py tests/test_vault_dek_envelope.py -q
# 100 % des tests Vault concernés
.venv/bin/python -m pytest -q
# suite complète : succès
.venv/bin/ruff check heimdall tests
# All checks passed!
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py tests/test_vault_dek_envelope.py
# Success: no issues found
```

## 6. Écarts et hors périmètre

- **Dérivation de la KEK par Argon2id** : ticket #69 (T26.2, branche `69`), hors de
  cette fiche. La couche enveloppe consomme l'interface `VaultCipher` et reste
  compatible avec une KEK dérivée : elle ne suppose qu'une clé de 32 octets.
- **Rotation de la KEK** : ticket #71. `update_secret` accepte déjà une nouvelle
  enveloppe de DEK (`encrypted_dek`), mais aucune route ni commande de rotation
  n'est ajoutée ici.
- **Chasse aux fuites de clés** : ticket #72, hors périmètre.
- **Falsification du ciphertext** : déjà couverte par #68 pour la primitive
  AES-GCM ; cette fiche ajoute uniquement la liaison d'identité de l'enveloppe.
- **Aucun secret réel** : les tests utilisent des canaris synthétiques et une
  KEK `b"K" * 32`.

## 7. Corrections de revue (LOW)

Les trois remarques LOW de la revue de code sont fermées et pinnées par des
tests dans `tests/test_vault_dek_envelope.py` :

| Remarque | Correctif | Test de non-régression |
|---|---|---|
| `update_secret` : une chaîne vide pouvait écraser l'enveloppe | Garde applicative `ValueError` sur `encrypted_dek == ""` + SQL défensif `COALESCE(NULLIF(?, ''), encrypted_dek)` ; `None` conserve l'enveloppe | `EnvelopeUpdateTests.test_update_secret_rejects_empty_dek_without_wiping_envelope` |
| `create_secret` : défaut `""` incohérent avec la colonne nullable | Défaut `None` ; une chaîne vide explicite est normalisée en `NULL`, jamais persistée | `EnvelopeDatabaseContractTests.test_create_secret_defaults_to_null_envelope` |
| `_decrypt_record` : `ValueError` non mappée | `ValueError` ajoutée au `except` ; toute corruption du chemin enveloppe reste une `SecretStoreError` générique | `EnvelopeUpdateTests.test_value_error_from_envelope_is_mapped_to_store_error` |

Compléments de couverture ajoutés : réenveloppement non-`NULL` via
`update_secret` puis relecture par le store
(`test_update_secret_rewraps_dek_and_remains_readable`), absence de
`encrypted_value`/`encrypted_dek` dans `get_secret_metadata` et `list_secrets`
(`test_metadata_and_list_do_not_expose_envelope`), et refus du swap
`encrypted_value ↔ encrypted_dek` (`test_swapping_value_and_wrapped_dek_fails_authentication`).
