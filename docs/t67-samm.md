# T67 — preuves pour la ligne SAMM (AES-256-GCM avec nonce unique)

Sous-ticket **T67** du ticket parent `#66 « Module crypto isolé »` (grand
ticket `#26 « clé maîtresse et chiffrement par enveloppe »`), branche
`67-t2611-aes-256-gcm-avec-nonce-unique`. Cette fiche fournit les couples
module + ligne et les permaliens du code testé ; elle ne prétend pas modifier
une feuille externe.

Révision du code testé : `e965db3`
(`feat(vault): nonce AES-256-GCM unique par chiffrement (#67)`), au-dessus du
merge de `main` (`3e2a7a2`, PR #163 / #65).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T67 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff e965db3 HEAD -- heimdall/vault/crypto.py tests/test_vault_crypto.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Périmètre du sous-ticket.** Le module crypto isolé
> (`heimdall/vault/crypto.py`) et la primitive AES-GCM ont été livrés par
> `#25`/`#26`/`#66`. `#67` isole et **prouve** le point précis demandé par le
> ticket : un nonce de 96 bits tiré de l'aléatoire du système, **neuf à chaque
> chiffrement**, stocké avec le ciphertext et l'étiquette, et lié par l'AAD à
> l'identifiant du secret. Rien d'autre n'est modifié (ni KEK/DEK, ni rotation,
> ni falsification du ciphertext — voir §6).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Nonce de 96 bits **aléatoire (`os.urandom`)** pour chaque chiffrement | [heimdall/vault/crypto.py:188–203](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L188-L203) (`_new_nonce`), [heimdall/vault/crypto.py:45–47](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L45-L47) (taille 12 octets + tag 16 octets) | [tests/test_vault_crypto.py:52–61](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L52-L61) (`os.urandom` est bien appelé avec 12 octets, nonce en préfixe du blob) | Réussi |
| Un nonce **neuf à chaque appel** (jamais mémorisé ni réutilisé) | [heimdall/vault/crypto.py:266–279](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L266-L279) (`encrypt` tire le nonce à chaque invocation) | [tests/test_vault_crypto.py:63–70](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L63-L70) (64 appels ⇒ 64 tirages), [tests/test_vault_crypto.py:91–97](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L91-L97) (256 nonces distincts) | Réussi |
| **Pas de compteur, pas de nonce dérivé de l'heure** (piège du ticket) | [heimdall/vault/crypto.py:188–203](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L188-L203) (source unique : `os.urandom`, le CSPRNG du noyau) | [tests/test_vault_crypto.py:121–137](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L121-L137) (horloge figée : les deux blobs diffèrent quand même), [tests/test_vault_crypto.py:99–119](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L99-L119) (nonce indépendant du texte clair et de la clé) | Réussi |
| Stocker **nonce + ciphertext + tag** ensemble | [heimdall/vault/crypto.py:266–279](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L266-L279) (blob = `nonce ‖ ciphertext ‖ tag`, encodé base64 URL-safe), [heimdall/vault/crypto.py:281–306](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L281-L306) (relecture : nonce relu, jamais regénéré) | [tests/test_vault_crypto.py:142–150](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L142-L150) (longueur exacte 12 + N + 16), [tests/test_vault_crypto.py:152–159](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L152-L159) (texte vide ⇒ 28 octets), [tests/test_vault_crypto.py:159–170](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L159-L170) (le déchiffrement relit le nonce stocké) | Réussi |
| **AAD = identifiant du secret** (un blob copié sur un autre secret échoue) | [heimdall/vault/crypto.py:255–264](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L255-L264) (`VaultCipher.aad` = triplet `project/env/name`, séparateurs NUL), [heimdall/vault/store.py:236–260](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/store.py#L236-L260) (AAD dérivé de l'identité au chiffrement) | [tests/test_vault_crypto.py:175–183](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L175-L183) (blob de A sous l'identité de B ⇒ refus), [tests/test_vault_crypto.py:185–193](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L185-L193) (autre projet / autre env ⇒ refus), [tests/test_vault_crypto.py:197–202](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L197-L202) (AAD non optionnel), [tests/test_vault_crypto.py:226–262](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L226-L262) (blob stocké en base lié à son secret) | Réussi |
| **Fait quand** : deux chiffrements du même texte donnent deux sorties différentes | [heimdall/vault/crypto.py:266–279](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L266-L279) | [tests/test_vault_crypto.py:72–89](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L72-L89) | Réussi |
| Erreur de déchiffrement **générique** (ni oracle, ni fuite du clair) | [heimdall/vault/crypto.py:289–306](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/heimdall/vault/crypto.py#L289-L306) | [tests/test_vault_crypto.py:212–221](https://github.com/Cezar277/heimdall/blob/e965db3779dd48804c21d15f45a66a8ac9b6cdd6/tests/test_vault_crypto.py#L212-L221) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Nonce de 96 bits aléatoire (`os.urandom`) pour chaque chiffrement | `tests/test_vault_crypto.py::NonceGenerationTests::test_nonce_is_96_bits_drawn_from_os_urandom`, `::test_a_fresh_nonce_is_drawn_for_every_encryption` |
| Stocker nonce + ciphertext + tag ensemble | `tests/test_vault_crypto.py::BlobLayoutTests::test_blob_contains_nonce_ciphertext_and_tag`, `::test_empty_plaintext_still_carries_a_nonce_and_a_tag`, `::test_decryption_reuses_the_stored_nonce` |
| AAD = identifiant du secret | `tests/test_vault_crypto.py::AadBindingTests::test_blob_copied_to_another_secret_fails_to_decrypt`, `::test_blob_copied_to_another_project_or_env_fails_to_decrypt`, `::test_decryption_without_aad_is_refused`, `::StoredSecretBindingTests::test_stored_blob_is_bound_to_the_secret_identity` |
| **Fait quand** : deux chiffrements du même texte donnent deux sorties différentes | `tests/test_vault_crypto.py::NonceGenerationTests::test_two_encryptions_of_the_same_text_give_two_different_blobs` |

## 3. Preuve à garder pour le rapport

Reproduit le critère « Fait quand » hors pytest (deux blobs, même clé, même AAD,
même texte) :

```sh
.venv/bin/python - <<'PY'
from heimdall.vault.crypto import VaultCipher

cipher = VaultCipher(b"K" * 32)                      # KEK synthétique (32 octets)
aad = VaultCipher.aad("demo", "dev", "API_TOKEN")    # identifiant du secret
first = cipher.encrypt(b"same-secret", aad=aad)
second = cipher.encrypt(b"same-secret", aad=aad)
print("blob 1 :", first)
print("blob 2 :", second)
print("identiques ?", first == second)
print("déchiffrement 1 :", cipher.decrypt(first, aad=aad))
PY
```

Sortie observée (les valeurs changent à chaque exécution : **c'est** la preuve
que le nonce est tiré à chaque chiffrement) :

```text
blob 1 : b5R0Z52D_cRqs6xOclv3LsZ6jGPPBlBRPONd7OuPXx7IGFELTiNr
blob 2 : YkaI8E6oNpNbEzdn_1UqPdPpwJH67aD_SprzVs6eIDDw4q_diVCG
identiques ? False
déchiffrement 1 : b'same-secret'
```

La même propriété est vérifiée par la suite automatisée, avec l'AAD en plus
(le blob 2 ne se déchiffre pas sous l'identité d'un autre secret) :

```sh
.venv/bin/python -m pytest tests/test_vault_crypto.py -q
# 15 passed
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Tampering** — réutilisation d'un nonce avec la même KEK (XOR des deux sorties, forge de l'étiquette) | Nonce de 96 bits tiré de `os.urandom` à chaque chiffrement, jamais réutilisé ; blob = `nonce ‖ ciphertext ‖ tag` ; l'étiquette GCM (16 octets) est vérifiée au déchiffrement | `heimdall/vault/crypto.py:188`, `heimdall/vault/crypto.py:266`, `heimdall/vault/crypto.py:281` ; testé par `tests/test_vault_crypto.py:52`, `:63`, `:91` |
| **Tampering** — copie d'un blob sur un autre secret | AAD = identifiant du secret (triplet `project/env/name`) : l'authentification GCM échoue si l'AAD ne correspond pas | `heimdall/vault/crypto.py:255`, `heimdall/vault/store.py:236` ; testé par `tests/test_vault_crypto.py:175`, `:185`, `:197`, `:226` |
| **Information disclosure** — nonce prévisible (compteur, horloge) permettant de rejouer ou de dériver | Source unique `os.urandom` (CSPRNG du noyau) ; horloge figée ⇒ blobs toujours différents ; le nonce ne dépend ni du texte clair ni de la clé | `heimdall/vault/crypto.py:188` ; testé par `tests/test_vault_crypto.py:99`, `:121` |
| **Information disclosure** — fuite de la valeur ou du nonce par les erreurs | Messages de déchiffrement génériques ; le clair n'apparaît ni dans le blob ni dans le fichier SQLite ni dans les exceptions | `heimdall/vault/crypto.py:289` ; testé par `tests/test_vault_crypto.py:142`, `:212`, `:226` |
| Invariant 5 (clé HMAC distincte de la clé maîtresse) | Inchangé : l'empreinte d'intégrité utilise une sous-clé HKDF dédiée, pas la KEK | `heimdall/vault/crypto.py:308` (hors périmètre de #67, non modifié) |
| Confinement crypto (ticket #17) | `cryptography` n'est importée que par `heimdall/vault/crypto.py` ; le nouveau helper `_new_nonce` n'utilise que `os` | `tests/test_crypto_confinement.py` (garde AST) |
| Aucune primitive maison | Le chiffrement reste `AESGCM` de la bibliothèque `cryptography` (50.0.2) : aucun AES maison, aucun mode maison | `heimdall/vault/crypto.py:42` (import `AESGCM`), `pyproject.toml` (version épinglée) |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local (mêmes versions que la CI :
`cryptography` 50.0.2, `pytest` 9.1.1).

```sh
python -m pytest tests/test_vault_crypto.py -q
# 15 passed
python -m pytest
# 1346 passed, 1 skipped, 1 xfailed, 4321 subtests passed
python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
# Required test coverage of 85% reached. Total coverage: 96.62 %
# heimdall/vault/crypto.py : 81 % (seuil du DoD pour un module critique : 70 %)
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 38 source files
bandit -r heimdall -q         # aucun rapport
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.

## 6. Écarts et hors périmètre

- **Falsification du ciphertext et de l'étiquette** (bit-flip, blob tronqué,
  forge de tag, rejeu d'un blob sur la même identité) : sous-ticket suivant
  `#68 « Tests de falsification »`. Cette fiche ne s'y substitue pas et n'ajoute
  aucun test de falsification.
- **Chiffrement par enveloppe** (DEK par secret, KEK dérivée par Argon2id,
  rotation de la KEK en transaction) : grand ticket `#26`, hors de `#67`. Le
  code livré ici utilise toujours la KEK unique de l'exploitant
  (`HEIMDALL_VAULT_KEK`), sans changement de format de stockage : les blobs
  existants restent déchiffrables (le format du blob est inchangé).
- **Aucune clé ni aucun secret réel dans le dépôt** : les tests utilisent une
  KEK synthétique `b"K" * 32` et des valeurs explicitement factices.
- **Aucun appel réseau** : la primitive est purement locale (`os.urandom` +
  `cryptography`), conforme à l'exigence « 100 % local ».
