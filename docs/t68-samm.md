# T68 — preuves pour la ligne SAMM (tests de falsification AES-256-GCM)

Sous-ticket **T68** du ticket parent `#66 « Module crypto isolé »` (grand
ticket `#26 « clé maîtresse et chiffrement par enveloppe »`), branche
`68-t2612-tests-de-falsification`. Cette fiche fournit les couples module + ligne
et les permaliens du code testé ; elle ne prétend pas modifier une feuille
externe.

Révision du code testé : `2f7f857`
(`test(vault): falsification du ciphertext, de la cle et de l'AAD (#68)`),
au-dessus du merge de `main` (`aa875a1`, PR #165).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T68 référencé (primitive et suite de tests) est
inchangé jusqu'à la livraison : contrôle effectué avec
`git diff 2f7f857 HEAD -- heimdall/vault/crypto.py tests/test_vault_falsification.py`
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
| **Modifier un octet du blob → erreur** (nonce, ciphertext, tag) | [heimdall/vault/crypto.py:236–255](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L236-L255) (`decrypt` : longueur minimale puis `AESGCM.decrypt`), [heimdall/vault/crypto.py:254–255](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L254-L255) (`InvalidTag` → `VaultCipherError` générique) | [tests/test_vault_falsification.py:65–81](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/tests/test_vault_falsification.py#L65-L81) (les 54 octets du vecteur, un par un) | Réussi |
| **Mauvaise clé → erreur** | [heimdall/vault/crypto.py:196–202](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L196-L202) (KEK de 32 octets exactement), [heimdall/vault/crypto.py:236–255](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L236-L255) (étiquette liée à la clé) | [tests/test_vault_falsification.py:83–89](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/tests/test_vault_falsification.py#L83-L89) (deux KEK synthétiques distinctes, même taille) | Réussi |
| **Mauvais AAD → erreur** | [heimdall/vault/crypto.py:223–226](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L223-L226) (`VaultCipher.aad` = triplet `project/env/name`), [heimdall/vault/crypto.py:236–255](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L236-L255) (AAD authentifié avec le ciphertext) | [tests/test_vault_falsification.py:91–98](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/tests/test_vault_falsification.py#L91-L98) (autre secret et AAD absent) | Réussi |
| Une exception est levée, **jamais une valeur fausse renvoyée** | [heimdall/vault/crypto.py:50–51](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L50-L51) (`VaultCipherError`), [heimdall/vault/crypto.py:255](https://github.com/Cezar277/heimdall/blob/2f7f857279b9cc019eb9c74595fd532ac354b0e4/heimdall/vault/crypto.py#L255) (message générique) | les trois tests utilisent `assertRaises(VaultCipherError)` et commencent par le contrôle du cas nominal (blob intact, bonne clé, bon AAD) | Réussi |
| **Fait quand** : les 3 tests passent | — | `tests/test_vault_falsification.py` (3 tests, 56 sous-cas) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Modifier un octet du blob → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_one_modified_blob_byte_is_rejected` |
| Mauvaise clé → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_key_is_rejected` |
| Mauvais AAD → erreur | `tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_aad_is_rejected` |
| **Fait quand** : les 3 tests passent | `python -m pytest tests/test_vault_falsification.py -q` → `3 passed, 56 subtests passed` |

## 3. Preuve à garder pour le rapport

Sortie locale de la suite dédiée :

```sh
.venv/bin/python -m pytest tests/test_vault_falsification.py -v
# tests/test_vault_falsification.py::BlobTamperingTests::test_one_modified_blob_byte_is_rejected PASSED
# tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_key_is_rejected PASSED
# tests/test_vault_falsification.py::BlobTamperingTests::test_decryption_with_wrong_aad_is_rejected PASSED
# 3 passed, 56 subtests passed
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
| **Tampering** — modification d'un octet du blob (nonce, ciphertext, tag) | L'étiquette GCM est vérifiée à chaque déchiffrement ; toute altération de l'un des 54 octets lève `VaultCipherError` | `heimdall/vault/crypto.py:254`, testé par `tests/test_vault_falsification.py:65` |
| **Tampering** — rejeu d'un blob sous une autre clé (KEK erronée ou volée) | L'étiquette dépend de la clé ; une KEK différente échoue | `heimdall/vault/crypto.py:236`, testé par `tests/test_vault_falsification.py:83` |
| **Tampering** — copie d'un blob sur un autre secret | AAD = identifiant du secret ; un AAD différent ou absent échoue | `heimdall/vault/crypto.py:223`, testé par `tests/test_vault_falsification.py:91` |
| **Information disclosure** — oracle par le message d'erreur | Message générique unique, sans cause ni valeur claire | `heimdall/vault/crypto.py:255` |
| Fail-closed (DoD) | Aucune valeur n'est renvoyée sur altération : l'exception remonte | `tests/test_vault_falsification.py` (3 tests, `assertRaises`) |
| Confinement crypto (#17) | Aucun import de `cryptography` dans le test ; seule la façade `VaultCipher` est exercée | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Nonce unique (#67) | Hors périmètre de ce ticket ; le vecteur figé reste valide car le format `nonce ‖ ciphertext ‖ tag` ne change pas | `docs/t67-samm.md` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv de CI (`.venv-ci`, mêmes versions
que la CI : `cryptography` 50.0.2, `pytest` 9.1.1, `pytest-cov` 7.1.0).

```sh
python -m pytest tests/test_vault_falsification.py -q
# 3 passed, 56 subtests passed
python -m pytest
# 1425 passed, 1 skipped, 7 warnings, 4373 subtests passed
python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
# Required test coverage of 85% reached. Total coverage: 96.22 %
# heimdall/vault/crypto.py : 80 % (seuil DoD module critique : 70 %)
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
- **Falsification au niveau API/stockage** (valeur altérée en base SQLite,
  troncature du blob) : couverte par les tests de store et de `decrypt`
  (`VaultCipherError` sur longueur invalide) ; le présent ticket se limite à la
  primitive et aux trois points de sa checklist.
- **Aucun secret réel** : KEK de test `b"K" * 32`, clair explicitement
  synthétique `b"t68-synthetic-secret-value"`, vecteur de test sans valeur
  exploitable.
