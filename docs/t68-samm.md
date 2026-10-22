# T68 — preuves pour la ligne SAMM (tests de falsification AES-256-GCM)

Sous-ticket **T68** du ticket parent `#66 « Module crypto isolé »` (grand
ticket `#26 « clé maîtresse et chiffrement par enveloppe »`), branche
`68-t2612-tests-de-falsification`. Cette fiche fournit les couples module + ligne
et les permaliens du code testé ; elle ne prétend pas modifier une feuille
externe.

Révision du code testé : `0eb5610`
(`test(vault): falsification du ciphertext, de la cle et de l'AAD (#68)`),
au-dessus du merge de `main` (`ba72b4d`, PR #164).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T68 référencé (primitive et suite de tests) est
inchangé jusqu'à la livraison : contrôle effectué avec
`git diff 0eb5610 HEAD -- heimdall/vault/crypto.py tests/test_vault_falsification.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Périmètre du sous-ticket.** La primitive AES-256-GCM
> (`heimdall/vault/crypto.py`, `VaultCipher`) a été livrée par `#25`/`#26`/`#66`.
> `#68` ne modifie **aucun code de production** : il isole et **prouve** le
> point demandé par le ticket — le déchiffrement échoue (fail-closed) au lieu de
> renvoyer une valeur fausse quand le blob, la clé ou l'AAD ne sont pas ceux du
> chiffrement. La falsification du ciphertext et de l'étiquette, renvoyée
> explicitement à ce sous-ticket par la fiche `#67`, est couverte ici.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Modifier un octet du blob → erreur** (nonce, ciphertext, tag) | [heimdall/vault/crypto.py:281–306](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L281-L306) (`decrypt` : longueur minimale puis `AESGCM.decrypt`), [heimdall/vault/crypto.py:305–306](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L305-L306) (`InvalidTag` → `VaultCipherError` générique) | [tests/test_vault_falsification.py:65–81](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/tests/test_vault_falsification.py#L65-L81) (les 54 octets du vecteur, un par un) | Réussi |
| **Mauvaise clé → erreur** | [heimdall/vault/crypto.py:228–234](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L228-L234) (KEK de 32 octets exactement), [heimdall/vault/crypto.py:281–306](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L281-L306) (étiquette liée à la clé) | [tests/test_vault_falsification.py:83–89](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/tests/test_vault_falsification.py#L83-L89) (deux KEK synthétiques distinctes, même taille) | Réussi |
| **Mauvais AAD → erreur** | [heimdall/vault/crypto.py:256–264](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L256-L264) (`VaultCipher.aad` = triplet `project/env/name`), [heimdall/vault/crypto.py:281–306](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L281-L306) (AAD authentifié avec le ciphertext) | [tests/test_vault_falsification.py:91–98](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/tests/test_vault_falsification.py#L91-L98) (autre secret et AAD absent) | Réussi |
| **Jeton vide, base64 invalide, blob tronqué ou étendu → erreur** (gardes de format/longueur, remarque de revue) | [heimdall/vault/crypto.py:289–300](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L289-L300) (refus du jeton vide, du base64 invalide et des longueurs < `nonce + tag` avant GCM) | [tests/test_vault_falsification.py:100–121](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/tests/test_vault_falsification.py#L100-L121) (6 sous-cas : vide, base64 invalide, tronqué sous le minimum, dernier caractère base64 altéré, tronqué d'un caractère, étendu) | Réussi |
| Une exception est levée, **jamais une valeur fausse renvoyée** | [heimdall/vault/crypto.py:59–60](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L59-L60) (`VaultCipherError`), [heimdall/vault/crypto.py:306](https://github.com/Cezar277/heimdall/blob/0eb561043fd98e1ba7ed9508d807a2e9a2b0e52e/heimdall/vault/crypto.py#L306) (message générique) | les tests utilisent `assertRaises(VaultCipherError)` et commencent par le contrôle du cas nominal (blob intact, bonne clé, bon AAD) | Réussi |
| **Fait quand** : les 3 tests de la checklist passent | — | `tests/test_vault_falsification.py` (4 tests, 62 sous-cas) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Modifier un octet du blob → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_one_modified_blob_byte_is_rejected` |
| Mauvaise clé → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_key_is_rejected` |
| Mauvais AAD → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_aad_is_rejected` |
| Robustesse format/longueur (revue) | `tests/test_vault_falsification.py::BlobTamperingTests::test_malformed_truncated_or_extended_blob_is_rejected` |
| **Fait quand** : les 3 tests de la checklist passent | `python -m pytest tests/test_vault_falsification.py -q` → `4 passed, 62 subtests passed` |

## 3. Preuve à garder pour le rapport

Sortie locale de la suite dédiée :

```sh
.venv/bin/python -m pytest tests/test_vault_falsification.py -v
# tests/test_vault_falsification.py::BlobTamperingTests::test_one_modified_blob_byte_is_rejected PASSED
# tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_key_is_rejected PASSED
# tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_aad_is_rejected PASSED
# tests/test_vault_falsification.py::BlobTamperingTests::test_malformed_truncated_or_extended_blob_is_rejected PASSED
# 4 passed, 62 subtests passed
```

Démonstration hors pytest (le blob intact se déchiffre, un octet modifié échoue) :

```sh
.venv/bin/python - <<'PY'
import base64
from heimdall.vault.crypto import VaultCipher, VaultCipherError

cipher = VaultCipher(b"K" * 32)                    # KEK synthétique (32 octets)
aad = VaultCipher.aad("demo", "dev", "API_TOKEN")  # identifiant du secret
blob = cipher.encrypt(b"same-secret", aad=aad)
print("déchiffrement intact :", cipher.decrypt(blob, aad=aad))

raw = bytearray(base64.urlsafe_b64decode(blob))
raw[12] ^= 0x01  # un seul octet du ciphertext
try:
    cipher.decrypt(base64.urlsafe_b64encode(bytes(raw)).decode(), aad=aad)
except VaultCipherError as exc:
    print("refusé :", exc)
PY
```

Sortie observée :

```text
déchiffrement intact : b'same-secret'
refusé : Authentification de la donnée chiffrée échouée.
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Tampering** — modification d'un octet du blob (nonce, ciphertext, tag) | L'étiquette GCM est vérifiée à chaque déchiffrement ; toute altération de l'un des 54 octets lève `VaultCipherError` | `heimdall/vault/crypto.py:305`, testé par `tests/test_vault_falsification.py:65` |
| **Tampering** — rejeu d'un blob sous une autre clé (KEK erronée ou volée) | L'étiquette dépend de la clé ; une KEK différente échoue | `heimdall/vault/crypto.py:281`, testé par `tests/test_vault_falsification.py:83` |
| **Tampering** — copie d'un blob sur un autre secret | AAD = identifiant du secret ; un AAD différent ou absent échoue | `heimdall/vault/crypto.py:256`, testé par `tests/test_vault_falsification.py:91` |
| **Tampering / DoS** — jeton vide, base64 invalide, blob tronqué ou étendu | Gardes de format et de longueur avant GCM : rejet fail-closed, jamais d'exception native ni de valeur renvoyée | `heimdall/vault/crypto.py:289`, testé par `tests/test_vault_falsification.py:100` |
| **Information disclosure** — oracle par le message d'erreur | Message générique unique, sans cause ni valeur claire | `heimdall/vault/crypto.py:306` |
| Fail-closed (DoD) | Aucune valeur n'est renvoyée sur altération : l'exception remonte | `tests/test_vault_falsification.py` (4 tests, `assertRaises`) |
| Confinement crypto (#17) | Aucun import de `cryptography` dans le test ; seule la façade `VaultCipher` est exercée | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Nonce unique (#67) | Hors périmètre de ce ticket ; le vecteur figé reste valide car le format `nonce ‖ ciphertext ‖ tag` ne change pas | `docs/t67-samm.md` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv de CI (`.venv-ci`, mêmes versions
que la CI : `cryptography` 50.0.2, `pytest` 9.1.1, `pytest-cov` 7.1.0).

```sh
python -m pytest tests/test_vault_falsification.py -q
# 4 passed, 62 subtests passed
python -m pytest
# 1441 passed, 1 skipped, 6 warnings, 4383 subtests passed
python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
# Required test coverage of 85% reached. Total coverage: 96.35 %
# heimdall/vault/crypto.py : 85 % (seuil DoD module critique : 70 %)
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 39 source files
bandit -r heimdall -q         # aucun rapport
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.

## 6. Écarts et hors périmètre

- **Aucun changement de code de production** : `heimdall/vault/crypto.py` est
  inchangé, les tests exercent la primitive existante. Aucun correctif de
  sécurité n'était nécessaire : le comportement fail-closed (GCM + `InvalidTag`
  → `VaultCipherError`) était déjà correct, il est désormais prouvé.
- **Chiffrement par enveloppe** (DEK par secret, KEK dérivée par Argon2id,
  rotation de la KEK) : grand ticket `#26`, hors de `#68`.
- **Nonce unique** : sous-ticket `#67`, livré séparément ; le vecteur figé de ce
  ticket reste valide car le format du blob est inchangé.
- **Falsification au niveau API/stockage** (valeur altérée en base SQLite) :
  couverte par les tests de store ; la troncature, l'extension et les jetons
  mal formés sont désormais prouvés sur la primitive par
  `test_malformed_truncated_or_extended_blob_is_rejected`
  (`tests/test_vault_falsification.py:100–121`).
- **Aucun secret réel** : KEK de test `b"K" * 32`, clair explicitement
  synthétique `b"t68-synthetic-secret-value"`, vecteur de test sans valeur
  exploitable.
