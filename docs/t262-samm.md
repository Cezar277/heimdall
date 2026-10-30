# T262 — preuves pour la ligne SAMM (KEK dérivée avec Argon2id)

Sous-ticket **T262** du grand ticket `#26 « Clé maîtresse et chiffrement par
enveloppe »`, branche `69-t262-kek-dérivée-avec-argon2id`, tickets voisins
`#66` (module crypto isolé), `#70` (DEK par secret), `#71` (rotation) et `#72`
(chasse aux fuites de clés). Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `3f2cfa2`
(`fix(vault): canoniser la clé maîtresse NFC et verrouiller l'échec KDF (#262)`),
au-dessus du merge de `main` (`987a59a`, PR #168). Cette révision intègre les
remarques de revue LOW des quatre passes : comparaison du pepper à la KEK dérivée
base64, validation `master_key == pepper` dès `VaultSettings`, contrôle
maître/pepper avant la KDF, `repr=False` sur `kek_salt`, alignement du chemin
`bytes` de la clé maîtresse sur le refus des espaces de bord, canonisation NFC
de la clé maîtresse (ADR-005 §6), verrou « KDF en panne ⇒ démarrage refusé »
(fail-closed), durée de vie de la clé maîtresse documentée et tests de non-écho
étendus. Le fichier d'aide racine
(`PR_T262.md`) est retiré du livrable ; la fiche SAMM et l'ADR-005 restent les
artefacts de preuve.

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T262 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff 3f2cfa2 HEAD -- heimdall/vault/crypto.py heimdall/vault/app.py tests/test_vault_kek_derivation.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Périmètre du sous-ticket.** Cette livraison dérive la KEK de chiffrement à
> partir de la clé maîtresse du serveur avec Argon2id, documente les paramètres
> dans l'ADR-005 et branche la dérivation **une seule fois au démarrage**. Le
> chiffrement par enveloppe complet (DEK par secret, stockage des DEK, rotation
> transactionnelle) reste hors périmètre : #70 et #71.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Dérivation depuis la clé maîtresse avec `argon2-cffi`** | [heimdall/vault/crypto.py:261–284](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L261-L284) (`derive_kek_from_master_key` appelle `argon2.low_level.hash_secret_raw`), [heimdall/vault/crypto.py:69–76](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L69-L76) (paramètres et borne 128 bits), [heimdall/vault/crypto.py:389–397](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L389-L397) (`VaultCipher.from_master_key`) | [tests/test_vault_kek_derivation.py:65–85](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L65-L85) (déterminisme + interopérabilité de deux chiffreurs) | Réussi |
| **Type Argon2id réellement utilisé** | [heimdall/vault/crypto.py:276–283](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L276-L283) (`type=argon2.low_level.Type.ID`) | [tests/test_vault_kek_derivation.py:99–123](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L99-L123) (`mock` sur `hash_secret_raw` : `Type.ID`, `time_cost=3`, `memory_cost=65 536`, `parallelism=4`, `hash_len=32`) | Réussi |
| **Paramètres au moins OWASP, documentés dans un ADR** | [docs/adr/005-derivation-kek-argon2id.md](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/docs/adr/005-derivation-kek-argon2id.md) (table 64 Mio / 3 / 4 vs minimums 19 Mio / 2 / 1, justification Argon2id vs HKDF), [heimdall/vault/crypto.py:64–76](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L64-L76) (constantes de format) | [tests/test_vault_kek_derivation.py:106–111](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L106-L111) (valeurs exactes + planchers OWASP) | Réussi |
| **Sel stocké à côté, public et stable** | [heimdall/vault/crypto.py:182–220](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L182-L220) (`generate_kek_salt` 16 octets, `decode_kek_salt` base64 strict), [heimdall/vault/app.py:600–609](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L600-L609) (`HEIMDALL_VAULT_KEK_SALT`, persisté avec la clé maîtresse), [README.md:67–75](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/README.md#L67-L75) (procédure d'exploitation) | [tests/test_vault_kek_derivation.py:125–136](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L125-L136) (génération via `secrets.token_bytes`, 16 octets, 64 sels distincts), [tests/test_vault_kek_derivation.py:139–157](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L139-L157) (sels invalides refusés) | Réussi |
| **Paire maître/sel obligatoire et modes exclusifs** | [heimdall/vault/app.py:753–814](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L753-L814) (`validate_master_key`, `validate_kek_salt`, `validate_master_key_configuration`) | [tests/test_vault_kek_derivation.py:200–269](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L200-L269) (moitié de paire, KEK + maître, clé trop courte/espaces/non UTF-8, sel invalide) et `test_bytes_master_key_with_surrounding_whitespace_is_rejected` (chemin `bytes` aligné sur le chemin `str`), `test_nfc_and_nfd_master_keys_derive_the_same_kek` et `test_settings_master_key_is_stored_nfc_canonical` (formes NFC/NFD identiques) | Réussi |
| **Dérivation une seule fois au démarrage, KEK en mémoire** | [heimdall/vault/app.py:265–330](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L265-L330) (`_resolve_vault_cipher` construit `VaultCipher` une fois), [heimdall/vault/crypto.py:389–397](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L389-L397) (KEK gardée dans l'objet) | [tests/test_vault_kek_derivation.py:379–395](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L379-L395) (1 appel à `create_app`, 1 après une requête HTTP), [tests/test_vault_kek_derivation.py:397–433](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L397-L433) (KEK absente du fichier SQLite) | Réussi |
| **Fait quand : même clé maîtresse + même sel ⇒ même KEK** | [heimdall/vault/crypto.py:269–284](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L269-L284) (fonction déterministe) | [tests/test_vault_kek_derivation.py:65–74](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L65-L74) (deux appels égaux, 32 octets, différents de la clé et du sel) ; redémarrage réel [tests/test_vault_kek_derivation.py:397–433](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L397-L433) | Réussi |
| **Aucune régression : mode historique conservé** | [heimdall/vault/app.py:576–588](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L576-L588) (`HEIMDALL_VAULT_KEK` directe), [heimdall/vault/app.py:289–290](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L289-L290) (priorité au mode direct) | [tests/test_vault_kek_derivation.py:354–362](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L354-L362) (chiffrement/déchiffrement en mode historique), suite Vault existante inchangée | Réussi |
| **Un sel différent ne permet pas de relire les secrets** | [heimdall/vault/crypto.py:261–284](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/crypto.py#L261-L284) (le sel entre dans Argon2id) | [tests/test_vault_kek_derivation.py:435–468](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L435-L468) (redémarrage avec un autre sel ⇒ 500 générique, aucune fuite de valeur) | Réussi |
| **Invariant 5 : KEK, clé maîtresse et pepper distincts** | [heimdall/vault/app.py:817–845](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L817-L845) (validation de la clé maîtresse et de la KEK historique) et [heimdall/vault/app.py:298–320](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/heimdall/vault/app.py#L298-L320) (KEK dérivée brute et base64 comparées au pepper) | [tests/test_vault_kek_derivation.py:285–352](https://github.com/Cezar277/heimdall/blob/3f2cfa22a73ea234c5d85e74412c5be441f10481/tests/test_vault_kek_derivation.py#L285-L352) (KEK dérivée = pepper brute et base64 refusées, clé maîtresse = pepper refusée dès la validation puis avant la KDF en défense en profondeur, sel absent refusé) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve permanente |
|---|---|
| Dérivation depuis la clé maîtresse avec argon2-cffi | `tests/test_vault_kek_derivation.py::Argon2idDerivationTests::test_same_master_key_and_same_salt_derive_the_same_kek` et `...::test_argon2id_parameters_are_owasp_or_better_and_actually_used` |
| Sel stocké à côté, paramètres documentés dans un ADR | `heimdall/vault/crypto.py::generate_kek_salt` / `decode_kek_salt`, `docs/adr/005-derivation-kek-argon2id.md`, `tests/test_vault_kek_derivation.py::Argon2idDerivationTests::test_salt_is_generated_from_secrets_and_is_public` |
| **Fait quand** : même clé maîtresse + même sel → même KEK | `tests/test_vault_kek_derivation.py::Argon2idDerivationTests::test_same_master_key_and_same_salt_derive_the_same_kek` et `...::StartupDerivationTests::test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` |
| Dérivation une seule fois au démarrage, pas par requête | `tests/test_vault_kek_derivation.py::StartupDerivationTests::test_derivation_happens_once_at_startup_not_per_request` |
| Aucune régression du mode historique | `tests/test_vault_kek_derivation.py::VaultSettingsMasterKeyTests::test_legacy_kek_mode_still_works` |

## 3. Preuve à garder pour le rapport

Sortie locale de la suite dédiée :

```sh
.venv/bin/python -m pytest tests/test_vault_kek_derivation.py -v
# 32 passed
```

Démonstration hors pytest : deux dérivations du même couple donnent la même
KEK, un sel différent change la KEK.

```sh
.venv/bin/python - <<'PY'
from heimdall.vault.crypto import derive_kek_from_master_key, generate_kek_salt

master = "correct horse battery staple heimdall"  # phrase de passe synthétique
salt = generate_kek_salt()
first = derive_kek_from_master_key(master, salt)
second = derive_kek_from_master_key(master, salt)
print("même couple :", first == second, len(first), "octets")
print("autre sel   :", first != derive_kek_from_master_key(master, generate_kek_salt()))
PY
```

Sortie observée :

```text
même couple : True 32 octets
autre sel   : True
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Spoofing / Information disclosure** — vol de la base seule | La KEK n'est jamais écrite dans SQLite ; sans elle, les ciphertexts AES-256-GCM restent opaques | `heimdall/vault/app.py:265–330`, test `test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` (recherche des octets de la KEK dans le fichier) |
| **Information disclosure** — attaque hors ligne par force brute sur une phrase de passe | Argon2id mémoire-dur (64 Mio), 3 itérations, 4 lanes ; sel public unique de 16 octets | `heimdall/vault/crypto.py:69–76` et `:257–280`, ADR-005, test `test_argon2id_parameters_are_owasp_or_better_and_actually_used` |
| **Tampering** — altération de la configuration pour changer la KEK | Paire maître/sel obligatoire, sel validé (base64 strict, 16 octets), modes exclusifs, échec au démarrage | `heimdall/vault/app.py:753–814`, tests `test_settings_require_master_key_and_salt_together` et `test_settings_reject_legacy_kek_and_master_key_together` |
| **Repudiation / diagnostic** — fuite de secret dans les erreurs | Messages génériques, aucun écho de la clé maîtresse, du sel ou de la KEK ; `hide_input_in_errors` supprime l'`input_value` de pydantic ; `repr` de `VaultSettings` masque la clé maîtresse et le sel | `heimdall/vault/app.py:521–530` et `:753–845`, `tests/test_vault_kek_derivation.py:232–258` et `test_settings_repr_hides_master_key_salt_and_pepper` (aucune clé, sel ou pepper dans `repr`) |
| **Elevation of privilege** — réutilisation d'une même clé pour chiffrement et authentification | KEK dérivée (brute et base64) et clé maîtresse comparées au pepper en temps constant, refus si collision ; clé maîtresse contrôlée dès la validation et avant la KDF lors de la défense en profondeur | `heimdall/vault/app.py:817–845` et `:298–320`, tests `test_derived_kek_equal_to_pepper_is_rejected`, `test_derived_kek_equal_to_pepper_in_base64_is_rejected`, `test_settings_reject_master_key_equal_to_pepper` et `test_resolver_rejects_master_key_equal_to_pepper_before_kdf` |
| **Denial of service** — dérivation répétée par requête | Dérivation unique à `create_app`, KEK conservée dans `VaultCipher` | `heimdall/vault/app.py:265–330`, test `test_derivation_happens_once_at_startup_not_per_request` |
| Fail-closed (DoD) | Toute configuration incomplète ou ambiguë lève une erreur au démarrage, jamais un repli silencieux ; une panne de la KDF (`MemoryError`) traverse `create_app` sans repli éphémère ni mode historique | `tests/test_vault_kek_derivation.py` (32 tests), suite Vault existante, `test_kdf_failure_is_fail_closed_at_startup` |
| Confinement crypto (#17) | `argon2` et `cryptography` restent importés uniquement par `heimdall/vault/crypto.py` | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Non-régression | Mode historique `HEIMDALL_VAULT_KEK` accepté et testé ; les tests Vault/AES-GCM existants passent sans modification | suite complète (§5), `test_legacy_kek_mode_still_works` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local (`.venv`, mêmes versions que
la CI : `argon2-cffi` 25.1.0, `cryptography` 50.0.2, `pytest` 9.1.1 ; la
couverture `pytest-cov` est mesurée par la CI).

```sh
python -m pytest tests/test_vault_kek_derivation.py
# 32 passed

python -m pytest
# 2243 passed, 16 skipped, 4512 subtests passed

ruff check heimdall tests
# All checks passed!
python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 45 source files

# CI Linux : couverture `--cov-fail-under=85`, `bandit -r heimdall -q`
# et `python docs/security/check_model.py` (voir le workflow).
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.

## 6. Écarts et hors périmètre

- **Chiffrement par enveloppe complet** : la DEK par secret et son stockage
  chiffré sont portés par `#70` ; la rotation transactionnelle de la KEK par
  `#71`. Ce ticket ne livre que la **dérivation** de la KEK et son branchement.
- **Sel en variable d'environnement plutôt qu'en fichier sidecar** : choix
  documenté et justifié dans l'ADR-005 (le sel n'est pas secret ; éviter une
  surface TOCTOU/permissions supplémentaire à côté de SQLite).
- **Migration du mode historique vers le mode dérivé** : les deux modes
  produisent des KEK différentes ; basculer un déploiement existant exige un
  re-chiffrement, hors périmètre de #262 (voir #71). Le mode historique reste
  donc accepté pour ne pas rendre les blobs existants illisibles.
- **Chemin `secret_store` explicite de `create_app`** : réserver aux tests. Le
  contrôle « KEK dérivée == pepper » (brut + base64) n'y est pas exécuté (coût
  ~90 ms de KDF) ; il vit dans `_resolve_vault_cipher`, appelée uniquement sur
  le chemin par défaut — toujours emprunté en production (HTTP). La docstring
  de `create_app` interdit l'usage d'un store explicite en production ; risque
  résiduel accepté et à réexaminer si le pentest l'exige.
- **Zeroization mémoire** : Python ne garantit pas l'effacement fiable des
  chaînes ; la KEK dérivée est gardée en mémoire pour la durée du processus et
  n'est jamais persistée. La clé maîtresse reste également dans
  `VaultSettings`/`os.environ` (aucun log ni `model_dump`), limite assumée,
  documentée dans l'ADR-005 §5 et **acceptée formellement** ici : les tampons
  `secret` de la dérivation et `settings.master_key` survivent au processus,
  l'interdiction de sérialiser/journaliser `app.state.settings` est maintenue
  (revue LOW n°3, ADR-005 §5).
- **Aucun secret réel** : clé maîtresse et sel explicitement synthétiques,
  valeur `t262-synthetic-secret-value`, aucune donnée de déploiement.
