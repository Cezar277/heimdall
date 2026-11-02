# T262 — preuves pour la ligne SAMM (KEK dérivée avec Argon2id)

Sous-ticket **T262** du grand ticket `#26 « Clé maîtresse et chiffrement par
enveloppe »`, branche `69-t262-kek-dérivée-avec-argon2id`, tickets voisins
`#66` (module crypto isolé), `#70` (DEK par secret), `#71` (rotation) et `#72`
(chasse aux fuites de clés). Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `ce3586f`
(`fix(vault): effacer best-effort le buffer de dérivation Argon2id (#262)`),
au-dessus du merge de `main` (`987a59a`, PR #168). Cette révision intègre les
remarques de revue LOW des cinq passes : comparaison du pepper à la KEK dérivée
base64, validation `master_key == pepper` dès `VaultSettings`, contrôle
maître/pepper avant la KDF, `repr=False` sur `kek_salt`, alignement du chemin
`bytes` de la clé maîtresse sur le refus des espaces de bord, canonisation NFC
de la clé maîtresse (ADR-005 §6), verrou « KDF en panne ⇒ démarrage refusé »
(fail-closed), contrôle « KEK dérivée == pepper » étendu au chemin
`secret_store` explicite (une dérivation au démarrage), effacement best-effort
des buffers de dérivation (succès et échec KDF), durée de vie de la clé
maîtresse documentée et tests de non-écho étendus. Le fichier d'aide racine
(`PR_T262.md`) est retiré du livrable ; la fiche SAMM et l'ADR-005 restent les
artefacts de preuve.

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T262 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff ce3586f HEAD -- heimdall/vault/crypto.py heimdall/vault/app.py tests/test_vault_kek_derivation.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Périmètre du sous-ticket.** Cette livraison dérive la KEK de chiffrement à
> partir de la clé maîtresse du serveur avec Argon2id, documente les paramètres
> dans l'ADR-005 et branche la dérivation **une seule fois au démarrage**. Le
> chiffrement par enveloppe complet (DEK par secret, stockage des DEK, rotation
> transactionnelle) reste hors périmètre : #70 et #71.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Dérivation depuis la clé maîtresse avec `argon2-cffi`** | [heimdall/vault/crypto.py:285–316](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L285-L316) (`derive_kek_from_master_key` appelle `argon2.low_level.hash_secret_raw`), [heimdall/vault/crypto.py:66–78](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L66-L78) (paramètres et borne 128 bits), [heimdall/vault/crypto.py:421–429](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L421-L429) (`VaultCipher.from_master_key`) | [tests/test_vault_kek_derivation.py:66–86](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L66-L86) (déterminisme + interopérabilité de deux chiffreurs) | Réussi |
| **Type Argon2id réellement utilisé** | [heimdall/vault/crypto.py:305–312](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L305-L312) (`type=argon2.low_level.Type.ID`) | [tests/test_vault_kek_derivation.py:100–124](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L100-L124) (`mock` sur `hash_secret_raw` : `Type.ID`, `time_cost=3`, `memory_cost=65 536`, `parallelism=4`, `hash_len=32`) | Réussi |
| **Paramètres au moins OWASP, documentés dans un ADR** | [docs/adr/005-derivation-kek-argon2id.md](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/docs/adr/005-derivation-kek-argon2id.md) (table 64 Mio / 3 / 4 vs minimums 19 Mio / 2 / 1, justification Argon2id vs HKDF), [heimdall/vault/crypto.py:66–75](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L66-L75) (constantes de format) | [tests/test_vault_kek_derivation.py:107–112](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L107-L112) (valeurs exactes + planchers OWASP) | Réussi |
| **Sel stocké à côté, public et stable** | [heimdall/vault/crypto.py:184–221](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L184-L221) (`generate_kek_salt` 16 octets, `decode_kek_salt` base64 strict), [heimdall/vault/app.py:635–644](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L635-L644) (`HEIMDALL_VAULT_KEK_SALT`, persisté avec la clé maîtresse), [README.md:67–75](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/README.md#L67-L75) (procédure d'exploitation) | [tests/test_vault_kek_derivation.py:126–137](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L126-L137) (génération via `secrets.token_bytes`, 16 octets, 64 sels distincts), [tests/test_vault_kek_derivation.py:140–158](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L140-L158) (sels invalides refusés) | Réussi |
| **Paire maître/sel obligatoire et modes exclusifs** | [heimdall/vault/app.py:788–849](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L788-L849) (`validate_master_key`, `validate_kek_salt`, `validate_master_key_configuration`) | [tests/test_vault_kek_derivation.py:201–270](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L201-L270) (moitié de paire, KEK + maître, clé trop courte/espaces/non UTF-8, sel invalide) et `test_bytes_master_key_with_surrounding_whitespace_is_rejected` (chemin `bytes` aligné sur le chemin `str`), `test_nfc_and_nfd_master_keys_derive_the_same_kek` et `test_settings_master_key_is_stored_nfc_canonical` (formes NFC/NFD identiques) | Réussi |
| **Dérivation une seule fois au démarrage, KEK en mémoire** | [heimdall/vault/app.py:284–338](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L284-L338) (`_resolve_vault_cipher` construit `VaultCipher` une fois), [heimdall/vault/crypto.py:394–400](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L394-L400) (KEK gardée dans l'objet) | [tests/test_vault_kek_derivation.py:380–396](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L380-L396) (1 appel à `create_app`, 1 après une requête HTTP), [tests/test_vault_kek_derivation.py:398–434](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L398-L434) (KEK absente du fichier SQLite) | Réussi |
| **Fait quand : même clé maîtresse + même sel ⇒ même KEK** | [heimdall/vault/crypto.py:285–316](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L285-L316) (fonction déterministe) | [tests/test_vault_kek_derivation.py:66–75](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L66-L75) (deux appels égaux, 32 octets, différents de la clé et du sel) ; redémarrage réel [tests/test_vault_kek_derivation.py:398–434](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L398-L434) | Réussi |
| **Aucune régression : mode historique conservé** | [heimdall/vault/app.py:611–623](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L611-L623) (`HEIMDALL_VAULT_KEK` directe), [heimdall/vault/app.py:308–309](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L308-L309) (priorité au mode direct) | [tests/test_vault_kek_derivation.py:355–363](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L355-L363) (chiffrement/déchiffrement en mode historique), suite Vault existante inchangée | Réussi |
| **Un sel différent ne permet pas de relire les secrets** | [heimdall/vault/crypto.py:285–316](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/crypto.py#L285-L316) (le sel entre dans Argon2id) | [tests/test_vault_kek_derivation.py:436–469](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L436-L469) (redémarrage avec un autre sel ⇒ 500 générique, aucune fuite de valeur) | Réussi |
| **Invariant 5 : KEK, clé maîtresse et pepper distincts** | [heimdall/vault/app.py:852–880](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L852-L880) (validation de la clé maîtresse et de la KEK historique) et [heimdall/vault/app.py:317–329](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L317-L329) (KEK dérivée brute et base64 comparées au pepper, y compris sur le chemin `secret_store` explicite via [heimdall/vault/app.py:341–365](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/heimdall/vault/app.py#L341-L365)) | [tests/test_vault_kek_derivation.py:286–353](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L286-L353) (KEK dérivée = pepper brute et base64 refusées, clé maîtresse = pepper refusée dès la validation puis avant la KDF en défense en profondeur, sel absent refusé) | Réussi |

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
# 36 passed
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
| **Spoofing / Information disclosure** — vol de la base seule | La KEK n'est jamais écrite dans SQLite ; sans elle, les ciphertexts AES-256-GCM restent opaques | `heimdall/vault/app.py:284–338`, test `test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` (recherche des octets de la KEK dans le fichier) |
| **Information disclosure** — attaque hors ligne par force brute sur une phrase de passe | Argon2id mémoire-dur (64 Mio), 3 itérations, 4 lanes ; sel public unique de 16 octets | `heimdall/vault/crypto.py:66–75` et `:301–316`, ADR-005, test `test_argon2id_parameters_are_owasp_or_better_and_actually_used` |
| **Tampering** — altération de la configuration pour changer la KEK | Paire maître/sel obligatoire, sel validé (base64 strict, 16 octets), modes exclusifs, échec au démarrage | `heimdall/vault/app.py:788–849`, tests `test_settings_require_master_key_and_salt_together` et `test_settings_reject_legacy_kek_and_master_key_together` |
| **Repudiation / diagnostic** — fuite de secret dans les erreurs | Messages génériques, aucun écho de la clé maîtresse, du sel ou de la KEK ; `hide_input_in_errors` supprime l'`input_value` de pydantic ; `repr` de `VaultSettings` masque la clé maîtresse et le sel | `heimdall/vault/app.py:556–565` et `:782–874`, `tests/test_vault_kek_derivation.py:233–259` et `test_settings_repr_hides_master_key_salt_and_pepper` (aucune clé, sel ou pepper dans `repr`) |
| **Elevation of privilege** — réutilisation d'une même clé pour chiffrement et authentification | KEK dérivée (brute et base64) et clé maîtresse comparées au pepper en temps constant, refus si collision ; clé maîtresse contrôlée dès la validation et avant la KDF lors de la défense en profondeur | `heimdall/vault/app.py:852–880` et `:298–320`, tests `test_derived_kek_equal_to_pepper_is_rejected`, `test_derived_kek_equal_to_pepper_in_base64_is_rejected`, `test_settings_reject_master_key_equal_to_pepper` et `test_resolver_rejects_master_key_equal_to_pepper_before_kdf`, `test_explicit_store_rejects_derived_kek_equal_to_pepper` et `test_explicit_store_still_starts_with_distinct_kek` |
| **Denial of service** — dérivation répétée par requête | Dérivation unique à `create_app`, KEK conservée dans `VaultCipher` | `heimdall/vault/app.py:284–338`, test `test_derivation_happens_once_at_startup_not_per_request` |
| Fail-closed (DoD) | Toute configuration incomplète ou ambiguë lève une erreur au démarrage, jamais un repli silencieux ; une panne de la KDF (`MemoryError`) traverse `create_app` sans repli éphémère ni mode historique | `tests/test_vault_kek_derivation.py` (36 tests), suite Vault existante, `test_kdf_failure_is_fail_closed_at_startup` |
| Confinement crypto (#17) | `argon2` et `cryptography` restent importés uniquement par `heimdall/vault/crypto.py` | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Non-régression | Mode historique `HEIMDALL_VAULT_KEK` accepté et testé ; les tests Vault/AES-GCM existants passent sans modification | suite complète (§5), `test_legacy_kek_mode_still_works` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local (`.venv`, mêmes versions que
la CI : `argon2-cffi` 25.1.0, `cryptography` 50.0.2, `pytest` 9.1.1 ; la
couverture `pytest-cov` est mesurée par la CI).

```sh
python -m pytest tests/test_vault_kek_derivation.py
# 36 passed

python -m pytest
# 2247 passed, 16 skipped, 4512 subtests passed

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
  profondeur, le contrôle « KEK dérivée == pepper » (brut + base64) y est
  désormais exécuté aussi, via `_validate_explicit_secret_store_configuration` :
  une dérivation Argon2id unique au démarrage (~90 ms), uniquement si le couple
  maître/sel et le pepper sont fournis. Risque résiduel clos ; à réexaminer
  seulement si le pentest demande une mise en cache de la dérivation.
- **Zeroization mémoire** : Python ne garantit pas l'effacement fiable des
  chaînes ; la KEK dérivée reste en mémoire pour la durée du processus et n'est
  jamais persistée. Les copies d'octets créées par la dérivation — buffer
  normalisé (`bytearray`) et copie transmise à Argon2 — sont effacées
  best-effort dans un `finally` (`_zeroize_buffer`), y compris quand la KDF
  échoue : [tests/test_vault_kek_derivation.py:570–587](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L570-L587) et
  [tests/test_vault_kek_derivation.py:589–606](https://github.com/Cezar277/heimdall/blob/ce3586fea5d9a2995a337104448255d5b81424db/tests/test_vault_kek_derivation.py#L589-L606). La clé maîtresse
  reste dans `VaultSettings`/`os.environ` (chaînes immuables, aucun log ni
  `model_dump`, `hide_input_in_errors`), limite assumée et documentée dans
  l'ADR-005 §5 ; l'interdiction de sérialiser/journaliser `app.state.settings`
  est maintenue.
- **Aucun secret réel** : clé maîtresse et sel explicitement synthétiques,
  valeur `t262-synthetic-secret-value`, aucune donnée de déploiement.
