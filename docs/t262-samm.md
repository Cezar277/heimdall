# T262 — preuves pour la ligne SAMM (KEK dérivée avec Argon2id)

Sous-ticket **T262** du grand ticket `#26 « Clé maîtresse et chiffrement par
enveloppe »`, branche `69-t262-kek-dérivée-avec-argon2id`, tickets voisins
`#66` (module crypto isolé), `#70` (DEK par secret), `#71` (rotation) et `#72`
(chasse aux fuites de clés). Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `18e5bf0`
(`feat(vault): dériver la KEK avec Argon2id (#262)`), au-dessus du merge de
`main` (`987a59a`, PR #168).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code T262 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff 18e5bf0 HEAD -- heimdall/vault/crypto.py heimdall/vault/app.py tests/test_vault_kek_derivation.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Périmètre du sous-ticket.** Cette livraison dérive la KEK de chiffrement à
> partir de la clé maîtresse du serveur avec Argon2id, documente les paramètres
> dans l'ADR-005 et branche la dérivation **une seule fois au démarrage**. Le
> chiffrement par enveloppe complet (DEK par secret, stockage des DEK, rotation
> transactionnelle) reste hors périmètre : #70 et #71.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Dérivation depuis la clé maîtresse avec `argon2-cffi`** | [heimdall/vault/crypto.py:255–278](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L255-L278) (`derive_kek_from_master_key` appelle `argon2.low_level.hash_secret_raw`), [heimdall/vault/crypto.py:69–76](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L69-L76) (paramètres et borne 128 bits), [heimdall/vault/crypto.py:383–391](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L383-L391) (`VaultCipher.from_master_key`) | [tests/test_vault_kek_derivation.py:64–84](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L64-L84) (déterminisme + interopérabilité de deux chiffreurs) | Réussi |
| **Type Argon2id réellement utilisé** | [heimdall/vault/crypto.py:270–277](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L270-L277) (`type=argon2.low_level.Type.ID`) | [tests/test_vault_kek_derivation.py:98–122](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L98-L122) (`mock` sur `hash_secret_raw` : `Type.ID`, `time_cost=3`, `memory_cost=65 536`, `parallelism=4`, `hash_len=32`) | Réussi |
| **Paramètres au moins OWASP, documentés dans un ADR** | [docs/adr/005-derivation-kek-argon2id.md](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/docs/adr/005-derivation-kek-argon2id.md) (table 64 Mio / 3 / 4 vs minimums 19 Mio / 2 / 1, justification Argon2id vs HKDF), [heimdall/vault/crypto.py:64–76](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L64-L76) (constantes de format) | [tests/test_vault_kek_derivation.py:105–110](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L105-L110) (valeurs exactes + planchers OWASP) | Réussi |
| **Sel stocké à côté, public et stable** | [heimdall/vault/crypto.py:182–220](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L182-L220) (`generate_kek_salt` 16 octets, `decode_kek_salt` base64 strict), [heimdall/vault/app.py:586–594](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L586-L594) (`HEIMDALL_VAULT_KEK_SALT`, persisté avec la clé maîtresse), [README.md:67–75](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/README.md#L67-L75) (procédure d'exploitation) | [tests/test_vault_kek_derivation.py:124–135](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L124-L135) (génération via `secrets.token_bytes`, 16 octets, 64 sels distincts), [tests/test_vault_kek_derivation.py:138–156](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L138-L156) (sels invalides refusés) | Réussi |
| **Paire maître/sel obligatoire et modes exclusifs** | [heimdall/vault/app.py:736–793](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L736-L793) (`validate_master_key`, `validate_kek_salt`, `validate_master_key_configuration`) | [tests/test_vault_kek_derivation.py:199–252](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L199-L252) (moitié de paire, KEK + maître, clé trop courte/espaces/non UTF-8, sel invalide) | Réussi |
| **Dérivation une seule fois au démarrage, KEK en mémoire** | [heimdall/vault/app.py:264–316](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L264-L316) (`_resolve_vault_cipher` construit `VaultCipher` une fois), [heimdall/vault/crypto.py:383–391](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L383-L391) (KEK gardée dans l'objet) | [tests/test_vault_kek_derivation.py:332–348](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L332-L348) (1 appel à `create_app`, 1 après une requête HTTP), [tests/test_vault_kek_derivation.py:350–386](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L350-L386) (KEK absente du fichier SQLite) | Réussi |
| **Fait quand : même clé maîtresse + même sel ⇒ même KEK** | [heimdall/vault/crypto.py:263–278](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L263-L278) (fonction déterministe) | [tests/test_vault_kek_derivation.py:64–73](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L64-L73) (deux appels égaux, 32 octets, différents de la clé et du sel) ; redémarrage réel [tests/test_vault_kek_derivation.py:350–386](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L350-L386) | Réussi |
| **Aucune régression : mode historique conservé** | [heimdall/vault/app.py:562–574](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L562-L574) (`HEIMDALL_VAULT_KEK` directe), [heimdall/vault/app.py:284–285](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L284-L285) (priorité au mode direct) | [tests/test_vault_kek_derivation.py:307–315](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L307-L315) (chiffrement/déchiffrement en mode historique), suite Vault existante inchangée | Réussi |
| **Un sel différent ne permet pas de relire les secrets** | [heimdall/vault/crypto.py:255–278](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/crypto.py#L255-L278) (le sel entre dans Argon2id) | [tests/test_vault_kek_derivation.py:388–421](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L388-L421) (redémarrage avec un autre sel ⇒ 500 générique, aucune fuite de valeur) | Réussi |
| **Invariant 5 : KEK, clé maîtresse et pepper distincts** | [heimdall/vault/app.py:293–307](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/heimdall/vault/app.py#L293-L307) (comparaisons en temps constant de la clé maîtresse et de la KEK dérivée avec le pepper) | [tests/test_vault_kek_derivation.py:268–305](https://github.com/Cezar277/heimdall/blob/18e5bf0a2559c215b7163e396b834ca8726ff19d/tests/test_vault_kek_derivation.py#L268-L305) (KEK dérivée = pepper refusée, clé maîtresse = pepper refusée, sel absent refusé) | Réussi |

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
# 25 passed
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
| **Spoofing / Information disclosure** — vol de la base seule | La KEK n'est jamais écrite dans SQLite ; sans elle, les ciphertexts AES-256-GCM restent opaques | `heimdall/vault/app.py:264–316`, test `test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` (recherche des octets de la KEK dans le fichier) |
| **Information disclosure** — attaque hors ligne par force brute sur une phrase de passe | Argon2id mémoire-dur (64 Mio), 3 itérations, 4 lanes ; sel public unique de 16 octets | `heimdall/vault/crypto.py:69–76` et `:255–278`, ADR-005, test `test_argon2id_parameters_are_owasp_or_better_and_actually_used` |
| **Tampering** — altération de la configuration pour changer la KEK | Paire maître/sel obligatoire, sel validé (base64 strict, 16 octets), modes exclusifs, échec au démarrage | `heimdall/vault/app.py:736–793`, tests `test_settings_require_master_key_and_salt_together` et `test_settings_reject_legacy_kek_and_master_key_together` |
| **Repudiation / diagnostic** — fuite de secret dans les erreurs | Messages génériques, aucun écho de la clé maîtresse, du sel ou de la KEK ; `hide_input_in_errors` supprime l'`input_value` de pydantic ; `repr` de `VaultSettings` masque la clé maîtresse | `heimdall/vault/app.py:507–516` et `:736–793`, `tests/test_vault_kek_derivation.py:231–241` |
| **Elevation of privilege** — réutilisation d'une même clé pour chiffrement et authentification | KEK dérivée et clé maîtresse comparées au pepper en temps constant, refus si collision | `heimdall/vault/app.py:293–307`, tests `test_derived_kek_equal_to_pepper_is_rejected` et `test_master_key_equal_to_pepper_is_rejected` |
| **Denial of service** — dérivation répétée par requête | Dérivation unique à `create_app`, KEK conservée dans `VaultCipher` | `heimdall/vault/app.py:264–316`, test `test_derivation_happens_once_at_startup_not_per_request` |
| Fail-closed (DoD) | Toute configuration incomplète ou ambiguë lève une erreur au démarrage, jamais un repli silencieux | `tests/test_vault_kek_derivation.py` (25 tests), suite Vault existante |
| Confinement crypto (#17) | `argon2` et `cryptography` restent importés uniquement par `heimdall/vault/crypto.py` | `tests/test_crypto_confinement.py` (garde AST, inchangé) |
| Non-régression | Mode historique `HEIMDALL_VAULT_KEK` accepté et testé ; les tests Vault/AES-GCM existants passent sans modification | suite complète (§5), `test_legacy_kek_mode_still_works` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv de CI (`.venv-ci`, mêmes versions que
la CI : `argon2-cffi` 25.1.0, `cryptography` 50.0.2, `pytest` 9.1.1,
`pytest-cov` 7.1.0).

```sh
python -m pytest tests/test_vault_kek_derivation.py -q
# 25 passed

python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
# 1702 passed, 16 skipped, 6 warnings, 4418 subtests passed
# Required test coverage of 85% reached. Total coverage: 96.28 %
# heimdall/vault/crypto.py : 90 % (seuil DoD module critique : 70 %)
# heimdall/vault/app.py : 97 %

ruff check heimdall tests
# All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 40 source files
bandit -r heimdall -q
# aucun rapport
python docs/security/check_model.py
# OK
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
- **Zeroization mémoire** : Python ne garantit pas l'effacement fiable des
  chaînes ; la KEK dérivée est gardée en mémoire pour la durée du processus et
  n'est jamais persistée. Limite assumée et documentée.
- **Aucun secret réel** : clé maîtresse et sel explicitement synthétiques,
  valeur `t262-synthetic-secret-value`, aucune donnée de déploiement.
