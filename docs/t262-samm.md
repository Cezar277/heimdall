# T262 — preuves pour la ligne SAMM (KEK dérivée avec Argon2id)

Sous-ticket **T262** du grand ticket `#26 « Clé maîtresse et chiffrement par
enveloppe »`, branche `69-t262-kek-dérivée-avec-argon2id`, tickets voisins
`#66` (module crypto isolé), `#70` (DEK par secret), `#71` (rotation) et `#72`
(chasse aux fuites de clés). Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `d431f57`
(`fix(vault): exclure les secrets de toute sérialisation des settings (#262)`),
au-dessus du merge de `main` (`987a59a`, PR #168). Cette révision intègre les
remarques de revue LOW des six passes : comparaison du pepper à la KEK dérivée
base64, validation `master_key == pepper` dès `VaultSettings`, contrôle
maître/pepper avant la KDF, `repr=False` sur `kek_salt`, alignement du chemin
`bytes` de la clé maîtresse sur le refus des espaces de bord, canonisation NFC
de la clé maîtresse (ADR-005 §6), verrou « KDF en panne ⇒ démarrage refusé »
(fail-closed), contrôle de la KEK **réelle** du chiffreur sur le chemin
`secret_store` explicite (sans dérivation, via `VaultCipher.key_reuses_pepper`),
effacement best-effort du seul tampon effaçable sans mutation d'`bytes`
(succès et échec KDF), exclusion structurelle des secrets de toute
sérialisation des settings (`Field(exclude=True)` sur `master_key`, `kek` et
`api_key_pepper`), durée de vie de la clé maîtresse documentée (risque
résiduel accepté, ADR-005 §5) et tests de non-écho étendus. Le fichier
d'aide racine (`PR_T262.md`) est retiré du livrable ; la fiche SAMM et
l'ADR-005 restent les artefacts de preuve.

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Entre `b71f1f3` et `d431f57`, le code T262 n'a bougé que
par l'exclusion des secrets à la sérialisation : contrôle effectué avec
`git diff b71f1f3 d431f57 -- heimdall/vault/crypto.py heimdall/vault/app.py tests/test_vault_kek_derivation.py`
(trois lignes de `Field` enrichies de `exclude=True` et la classe de tests
`SettingsSerializationHygieneTests` ajoutée en fin de fichier ; aucun décalage
de ligne existant, donc tous les permaliens ci-dessous restent exacts).

> **Périmètre du sous-ticket.** Cette livraison dérive la KEK de chiffrement à
> partir de la clé maîtresse du serveur avec Argon2id, documente les paramètres
> dans l'ADR-005 et branche la dérivation **une seule fois au démarrage**. Le
> chiffrement par enveloppe complet (DEK par secret, stockage des DEK, rotation
> transactionnelle) reste hors périmètre : #70 et #71.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Dérivation depuis la clé maîtresse avec `argon2-cffi`** | [heimdall/vault/crypto.py:279–313](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L279-L313) (`derive_kek_from_master_key` appelle `argon2.low_level.hash_secret_raw`), [heimdall/vault/crypto.py:65–77](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L65-L77) (paramètres et borne 128 bits), [heimdall/vault/crypto.py:419–426](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L419-L426) (`VaultCipher.from_master_key`) | [tests/test_vault_kek_derivation.py:67–87](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L67-L87) (déterminisme + interopérabilité de deux chiffreurs) | Réussi |
| **Type Argon2id réellement utilisé** | [heimdall/vault/crypto.py:301–311](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L301-L311) (`type=argon2.low_level.Type.ID`) | [tests/test_vault_kek_derivation.py:101–125](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L101-L125) (`mock` sur `hash_secret_raw` : `Type.ID`, `time_cost=3`, `memory_cost=65 536`, `parallelism=4`, `hash_len=32`) | Réussi |
| **Paramètres au moins OWASP, documentés dans un ADR** | [docs/adr/005-derivation-kek-argon2id.md](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/docs/adr/005-derivation-kek-argon2id.md) (table 64 Mio / 3 / 4 vs minimums 19 Mio / 2 / 1, justification Argon2id vs HKDF), [heimdall/vault/crypto.py:65–74](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L65-L74) (constantes de format) | [tests/test_vault_kek_derivation.py:108–113](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L108-L113) (valeurs exactes + planchers OWASP) | Réussi |
| **Sel stocké à côté, public et stable** | [heimdall/vault/crypto.py:183–221](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L183-L221) (`generate_kek_salt` 16 octets, `decode_kek_salt` base64 strict), [heimdall/vault/app.py:635–644](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L635-L644) (`HEIMDALL_VAULT_KEK_SALT`, persisté avec la clé maîtresse), [README.md:67–75](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/README.md#L67-L75) (procédure d'exploitation) | [tests/test_vault_kek_derivation.py:127–138](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L127-L138) (génération via `secrets.token_bytes`, 16 octets, 64 sels distincts), [tests/test_vault_kek_derivation.py:141–159](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L141-L159) (sels invalides refusés) | Réussi |
| **Paire maître/sel obligatoire et modes exclusifs** | [heimdall/vault/app.py:788–849](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L788-L849) (`validate_master_key`, `validate_kek_salt`, `validate_master_key_configuration`) | [tests/test_vault_kek_derivation.py:202–271](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L202-L271) (moitié de paire, KEK + maître, clé trop courte/espaces/non UTF-8, sel invalide) et `test_bytes_master_key_with_surrounding_whitespace_is_rejected` (chemin `bytes` aligné sur le chemin `str`), `test_nfc_and_nfd_master_keys_derive_the_same_kek` et `test_settings_master_key_is_stored_nfc_canonical` (formes NFC/NFD identiques) | Réussi |
| **Dérivation une seule fois au démarrage, KEK en mémoire** | [heimdall/vault/app.py:283–337](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L283-L337) (`_resolve_vault_cipher` construit `VaultCipher` une fois), [heimdall/vault/crypto.py:391–400](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L391-L400) (KEK gardée dans l'objet) | [tests/test_vault_kek_derivation.py:381–397](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L381-L397) (1 appel à `create_app`, 1 après une requête HTTP), [tests/test_vault_kek_derivation.py:399–435](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L399-L435) (KEK absente du fichier SQLite) | Réussi |
| **Fait quand : même clé maîtresse + même sel ⇒ même KEK** | [heimdall/vault/crypto.py:279–313](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L279-L313) (fonction déterministe) | [tests/test_vault_kek_derivation.py:67–76](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L67-L76) (deux appels égaux, 32 octets, différents de la clé et du sel) ; redémarrage réel [tests/test_vault_kek_derivation.py:399–435](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L399-L435) | Réussi |
| **Aucune régression : mode historique conservé** | [heimdall/vault/app.py:611–623](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L611-L623) (`HEIMDALL_VAULT_KEK` directe), [heimdall/vault/app.py:307–308](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L307-L308) (priorité au mode direct) | [tests/test_vault_kek_derivation.py:356–364](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L356-L364) (chiffrement/déchiffrement en mode historique), suite Vault existante inchangée | Réussi |
| **Un sel différent ne permet pas de relire les secrets** | [heimdall/vault/crypto.py:279–313](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L279-L313) (le sel entre dans Argon2id) | [tests/test_vault_kek_derivation.py:437–470](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L437-L470) (redémarrage avec un autre sel ⇒ 500 générique, aucune fuite de valeur) | Réussi |
| **Invariant 5 : KEK, clé maîtresse et pepper distincts** | [heimdall/vault/app.py:852–880](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L852-L880) (validation de la clé maîtresse et de la KEK historique) et [heimdall/vault/app.py:316–328](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L316-L328) (KEK dérivée brute et base64 comparées au pepper ; sur le chemin `secret_store` explicite, la KEK réelle du chiffreur via [heimdall/vault/crypto.py:428–441](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L428-L441) `VaultCipher.key_reuses_pepper`, appelé depuis [heimdall/vault/app.py:340–365](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L340-L365)) | [tests/test_vault_kek_derivation.py:287–354](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L287-L354) (KEK dérivée = pepper brute et base64 refusées, clé maîtresse = pepper refusée dès la validation puis avant la KDF en défense en profondeur, sel absent refusé, contrôle du store explicite (`test_explicit_store_rejects_cipher_key_equal_to_pepper` et `test_explicit_store_path_performs_no_kdf`)) | Réussi |

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
# 40 passed
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
| **Spoofing / Information disclosure** — vol de la base seule | La KEK n'est jamais écrite dans SQLite ; sans elle, les ciphertexts AES-256-GCM restent opaques | `heimdall/vault/app.py:283–337`, test `test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` (recherche des octets de la KEK dans le fichier) |
| **Information disclosure** — attaque hors ligne par force brute sur une phrase de passe | Argon2id mémoire-dur (64 Mio), 3 itérations, 4 lanes ; sel public unique de 16 octets | `heimdall/vault/crypto.py:65–74` et `:301–311`, ADR-005, test `test_argon2id_parameters_are_owasp_or_better_and_actually_used` |
| **Tampering** — altération de la configuration pour changer la KEK | Paire maître/sel obligatoire, sel validé (base64 strict, 16 octets), modes exclusifs, échec au démarrage | `heimdall/vault/app.py:788–849`, tests `test_settings_require_master_key_and_salt_together` et `test_settings_reject_legacy_kek_and_master_key_together` |
| **Repudiation / diagnostic** — fuite de secret dans les erreurs | Messages génériques, aucun écho de la clé maîtresse, du sel ou de la KEK ; `hide_input_in_errors` supprime l'`input_value` de pydantic ; `repr` de `VaultSettings` masque la clé maîtresse, le sel et le pepper ; `model_dump()`/`model_dump_json()` ne peuvent pas les contenir (`Field(exclude=True)`) | `heimdall/vault/app.py:556–565` et `:782–874`, `tests/test_vault_kek_derivation.py:234–260` et `test_settings_repr_hides_master_key_salt_and_pepper` (aucune clé, sel ou pepper dans `repr`), [tests/test_vault_kek_derivation.py:653–678](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L653-L678) (`test_model_dump_never_contains_master_key_kek_or_pepper`) |
| **Elevation of privilege** — réutilisation d'une même clé pour chiffrement et authentification | KEK dérivée (brute et base64) et clé maîtresse comparées au pepper en temps constant, refus si collision ; clé maîtresse contrôlée dès la validation et avant la KDF lors de la défense en profondeur | `heimdall/vault/app.py:852–880` et `:316–328`, tests `test_derived_kek_equal_to_pepper_is_rejected`, `test_derived_kek_equal_to_pepper_in_base64_is_rejected`, `test_settings_reject_master_key_equal_to_pepper` et `test_resolver_rejects_master_key_equal_to_pepper_before_kdf`, `test_explicit_store_rejects_cipher_key_equal_to_pepper`, `test_explicit_store_path_performs_no_kdf` et `test_explicit_store_still_starts_with_distinct_kek` |
| **Denial of service** — dérivation répétée par requête | Dérivation unique à `create_app`, KEK conservée dans `VaultCipher` | `heimdall/vault/app.py:283–337`, test `test_derivation_happens_once_at_startup_not_per_request` |
| Fail-closed (DoD) | Toute configuration incomplète ou ambiguë lève une erreur au démarrage, jamais un repli silencieux ; une panne de la KDF (`MemoryError`) traverse `create_app` sans repli éphémère ni mode historique | `tests/test_vault_kek_derivation.py` (40 tests), suite Vault existante, `test_kdf_failure_is_fail_closed_at_startup` |
| Confinement crypto (#17) | `argon2` et `cryptography` restent importés uniquement par `heimdall/vault/crypto.py` | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Non-régression | Mode historique `HEIMDALL_VAULT_KEK` accepté et testé ; les tests Vault/AES-GCM existants passent sans modification | suite complète (§5), `test_legacy_kek_mode_still_works` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local (`.venv`, mêmes versions que
la CI : `argon2-cffi` 25.1.0, `cryptography` 50.0.2, `pytest` 9.1.1 ; la
couverture `pytest-cov` est mesurée par la CI).

```sh
python -m pytest tests/test_vault_kek_derivation.py
# 40 passed

python -m pytest
# 2251 passed, 16 skipped, 4512 subtests passed

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
- **Chemin `secret_store` explicite de `create_app`** : réservé aux tests (la
  production HTTP passe toujours par `_resolve_vault_cipher`). Par défense en
  profondeur (invariant 5), la KEK **réellement portée** par le chiffreur du
  store est comparée au pepper (brut + base64) via
  [heimdall/vault/crypto.py:428–441](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L428-L441)
  (`VaultCipher.key_reuses_pepper`), appelé depuis
  [heimdall/vault/app.py:340–365](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/app.py#L340-L365) : une fois
  au démarrage et **sans dérivation supplémentaire** — le contrôle ne porte plus
  sur les `settings`, qui peuvent diverger du store réel. Tests :
  `test_explicit_store_rejects_cipher_key_equal_to_pepper`,
  `test_explicit_store_path_performs_no_kdf` et
  `test_explicit_store_still_starts_with_distinct_kek`.
- **Zeroization mémoire** : Python ne garantit pas l'effacement fiable des
  chaînes ; la KEK dérivée reste en mémoire pour la durée du processus et n'est
  jamais persistée. Le tampon normalisé est un `bytearray` effaçable, remis à
  zéro dans un `finally` ([heimdall/vault/crypto.py:224–235](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/heimdall/vault/crypto.py#L224-L235), `_zeroize_buffer`) après la KDF, y compris
  si elle échoue. La copie transmise à `argon2-cffi` doit être un `bytes` (API de
  la librairie) : elle est créée au dernier moment et **n'est jamais mutée** —
  muter un `bytes` via `ctypes` serait un comportement indéfini sur un objet
  potentiellement partagé, cette mutation est donc exclue. Tests :
  [tests/test_vault_kek_derivation.py:589–650](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L589-L650)
  (`test_derivation_zeroizes_normalized_buffer_after_success`,
  `test_derivation_zeroizes_buffer_on_kdf_failure`,
  `test_zeroize_buffer_clears_bytearray`,
  `test_zeroize_buffer_never_touches_immutable_bytes`).
  **Risque résiduel accepté** (revue, statu quo — non effaçable en Python) :
  la copie `bytes` transitoire exigée par `argon2-cffi`, les copies internes de
  la librairie (matrice de calcul Argon2), `settings.master_key` (`str`
  immuable) et l'entrée `HEIMDALL_VAULT_MASTER_KEY` de `os.environ`
  survivent au processus — exposition locale à un dump mémoire uniquement,
  aucune fuite ni journal réseau (`repr=False`, `hide_input_in_errors`).
  L'interdiction de sérialiser/journaliser `app.state.settings` est désormais
  structurelle : `Field(exclude=True)` sur la clé maîtresse, la KEK et le
  pepper rend `model_dump()`/`model_dump_json()` incapables de les contenir
  ([tests/test_vault_kek_derivation.py:653–678](https://github.com/Cezar277/heimdall/blob/d431f5733cc3828b49bc8575d78b24f764bdc3d3/tests/test_vault_kek_derivation.py#L653-L678)) ; limite détaillée dans
  l'ADR-005 §5.
- **Aucun secret réel** : clé maîtresse et sel explicitement synthétiques,
  valeur `t262-synthetic-secret-value`, aucune donnée de déploiement.
