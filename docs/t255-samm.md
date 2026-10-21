# T255 — preuves pour la ligne SAMM (tests d'intégration TestClient)

Sous-ticket **T255** du ticket parent `#25 « Vault minimal »` (branche
`65-t255-tests-dintégration-testclient`). Cette fiche fournit les couples
module + ligne et les permaliens du code testé ; elle ne prétend pas modifier
une feuille externe.

Révision du code testé : `f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c`
(`docs(t255): renomme la fiche SAMM et resorbe la collision de numerotation`,
qui porte le code des corrections de revue), au-dessus de
`41fc0a8e4d3a60f30fe726ba2b4ee7ca6590149b`
(`test(vault): corrige les remarques de la revue sur les tests TestClient (#65)`),
`80379f91770b12cd354b0467e07a62364dacf753`
(`test(vault): ajoute les tests d'integration TestClient (#65)`) et du merge de
`main` (`24e72c1`, PR #162 / #64).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code `T255` référencé est inchangé jusqu'à la
livraison : contrôle effectué avec
`git diff f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c HEAD -- tests/test_vault_integration_testclient.py pyproject.toml requirements.lock`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Numérotation** : dans le code du Vault, `#65` désigne **uniquement** la
> limitation de débit (`heimdall/vault/ratelimit.py`,
> `docs/contracts/vault-traceability.md`). Les tests d'intégration `TestClient`
> sont le sous-ticket **T255** : la matrice ticket → module → preuve ne
> contient qu'un seul `#65` normatif (voir §5).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Cas nominal : POST puis GET sur la même base | [heimdall/vault/app.py:1135–1192](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1135-L1192), [heimdall/vault/app.py:1194–1238](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1194-L1238), [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/store.py#L235-L270) | [tests/test_vault_integration_testclient.py:261–286](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L261-L286) | Réussi |
| La réponse 201 ne contient jamais la valeur | [heimdall/vault/app.py:1187–1192](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1187-L1192) | [tests/test_vault_integration_testclient.py:288–293](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L288-L293) | Réussi |
| `Cache-Control: no-store` sur 201 et 200 | [heimdall/vault/app.py:1159](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1159), [heimdall/vault/app.py:1224](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1224) | [tests/test_vault_integration_testclient.py:295–305](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L295-L305) | Réussi |
| Clé invalide → 401 (absente, inconnue, révoquée, malformée) | [heimdall/vault/auth.py:801–853](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/auth.py#L801-L853), [heimdall/vault/auth.py:600–623](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/auth.py#L600-L623) | [tests/test_vault_integration_testclient.py:340–358](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L340-L358) | Réussi |
| 401 générique : corps identique quelle que soit la cause, aucun écho de la clé | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/auth.py#L142-L150) | [tests/test_vault_integration_testclient.py:360–375](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L360-L375) | Réussi |
| Secret d'un autre projet → 403 (avant toute recherche de ressource) | [heimdall/vault/auth.py:856–872](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/auth.py#L856-L872), [heimdall/vault/auth.py:875–904](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/auth.py#L875-L904), [heimdall/vault/app.py:1152–1158](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1152-L1158) | [tests/test_vault_integration_testclient.py:396–436](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L396-L436) | Réussi |
| Le refus 403 n'écrit rien (pas d'effet de bord) | [heimdall/vault/app.py:1152–1158](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1152-L1158) | [tests/test_vault_integration_testclient.py:419–436](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L419-L436) | Réussi |
| Le Vault respecte l'OpenAPI : corps de réponse validés contre le contrat | [openapi.yaml:22–190](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/openapi.yaml#L22-L190), [heimdall/vault/app.py:380–434](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L380-L434) | [tests/test_vault_integration_testclient.py:229–256](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L229-L256), [tests/test_vault_integration_testclient.py:455–474](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L455-L474) | Réussi |
| Schéma OpenAPI de l'application aligné sur le contrat (chemins, operationId, statuts, charges utiles) | [heimdall/vault/app.py:1120–1300](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1120-L1300) | [tests/test_vault_integration_testclient.py:491–517](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L491-L517) | Réussi |
| Écart `required` des modèles d'erreur : comparaison STRICTE, écart rendu explicite | [heimdall/vault/app.py:132–202](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L132-L202) | [tests/test_vault_integration_testclient.py:519–564](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L519-L564) (attendu-échec documenté, §5) | Écart connu (XPASS dès le correctif production) |
| La clé `default` écartée est une annotation SANS effet de validation (preuve) | [heimdall/vault/app.py:132–202](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L132-L202) | [tests/test_vault_integration_testclient.py:566–625](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L566-L625) | Réussi |
| Base temporaire par test : aucun état partagé (base, registre, empreintes) | [heimdall/vault/database.py:851–867](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/database.py#L851-L867) | [tests/test_vault_integration_testclient.py:756–787](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L756-L787), [tests/test_vault_integration_testclient.py:789–810](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L789-L810) | Réussi |
| Chiffrement au repos : la valeur en clair est absente du fichier SQLite | [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/store.py#L235-L270), [heimdall/vault/crypto.py:228–232](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/crypto.py#L228-L232) | [tests/test_vault_integration_testclient.py:307–322](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L307-L322) | Réussi |
| Permissions du fichier SQLite durcies (0o600) | [heimdall/vault/database.py:290–302](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/database.py#L290-L302) | [tests/test_vault_integration_testclient.py:324–328](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L324-L328) | Réussi |
| Origine non loopback → 403 (défense en profondeur transport) | [heimdall/vault/app.py:1035–1061](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1035-L1061) | [tests/test_vault_integration_testclient.py:630–656](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L630-L656) | Réussi |
| Débit dépassé → 429 contractuel + `Retry-After` borné 1..3600 | [heimdall/vault/app.py:958–1032](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L958-L1032), [heimdall/vault/ratelimit.py:263–299](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/ratelimit.py#L263-L299) | [tests/test_vault_integration_testclient.py:668–693](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L668-L693) | Réussi |
| Abus d'entrée : corps > 1 Mio, identifiants hors contrat, traversée de chemin, JSON mal formé | [heimdall/vault/app.py:800–877](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L800-L877), [heimdall/vault/app.py:299–327](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L299-L327) | [tests/test_vault_integration_testclient.py:698–751](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L698-L751) | Réussi |
| Localité : aucun port réseau, client présenté en `127.0.0.1` | [heimdall/vault/app.py:1035–1061](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/heimdall/vault/app.py#L1035-L1061) | [tests/test_vault_integration_testclient.py:62–64](https://github.com/Cezar277/heimdall/blob/f8904cd3dfd86da5cb0bfbdf46ec01d5daf7c14c/tests/test_vault_integration_testclient.py#L62-L64) | Réussi |

## 2. Checklist du ticket

| Point de la checklist | Preuve |
|---|---|
| Cas nominal | `tests/test_vault_integration_testclient.py::VaultNominalFlowTests::test_post_then_get_returns_the_created_secret` |
| Clé invalide → 401 | `tests/test_vault_integration_testclient.py::VaultInvalidApiKeyTests::test_missing_unknown_revoked_and_malformed_keys_are_rejected` |
| Secret d'un autre projet → 403 ou 404 | `tests/test_vault_integration_testclient.py::VaultCrossProjectAccessTests::test_reading_another_project_secret_is_forbidden` (403, choisi avant la recherche de ressource) |
| Base temporaire par test | `tests/test_vault_integration_testclient.py::VaultTestIsolationTests::test_each_test_uses_its_own_temporary_database` |

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| VLT-E (accès interprojets) | Autorisation tranchée avant toute recherche de ressource ; 403 indépendant de l'existence du secret | `heimdall/vault/auth.py:856` (`ensure_project_access`), testé par `tests/test_vault_integration_testclient.py:407–417` |
| VLT-S (réemploi de clé volée) | Clé absente, inconnue, révoquée ou malformée : 401 générique identique, jamais d'écho | `heimdall/vault/auth.py:801`, testé par `tests/test_vault_integration_testclient.py:340–375` |
| Information disclosure | 201 sans la valeur ; `Cache-Control: no-store` ; valeur absente du fichier SQLite | `heimdall/vault/app.py:1187`, `heimdall/vault/store.py:259`, testé par `tests/test_vault_integration_testclient.py:288–322` |
| Contract drift (openapi.yaml ↔ implémentation) | Corps de réponse validés contre le schéma du contrat + schéma OpenAPI de l'application comparé au contrat, comparaison STRICTE sur `required` | `tests/test_vault_integration_testclient.py:455–564` |
| Durcissement du stockage | Base temporaire en 0o600, schéma vérifié par `init_db` | `heimdall/vault/database.py:290`, `heimdall/vault/database.py:851` |
| Network exposure (defense in depth) | Origine non loopback rejetée en 403 avant tout routage | `heimdall/vault/app.py:1035`, testé par `tests/test_vault_integration_testclient.py:630–656` |
| Denial of service (débit) | Quota par clé API validée, 429 contractuel, `Retry-After` borné | `heimdall/vault/ratelimit.py:263`, testé par `tests/test_vault_integration_testclient.py:668–693` |
| Abus d'entrée (path traversal, corps surdimensionné) | Rejets 400/404 contractuels, aucune entrée reflétée | `heimdall/vault/app.py:800`, testé par `tests/test_vault_integration_testclient.py:698–751` |

## 4. Résultats locaux

Environnement : Linux, Python 3.14.7, venv reconstruit depuis `requirements.lock`
(fastapi 0.143.1, starlette 1.7.0, httpx2 2.13.1, pydantic 2.14.1) — mêmes
versions que la CI.

```sh
python -m pytest tests/test_vault_integration_testclient.py -q
# 29 passed, 1 xfailed, 36 subtests passed
python -m pytest -p no:randomly --tb=short -rN
# 1170 passed, 1 skipped, 2 xfailed, 4307 subtests passed
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 29 source files
bandit -r heimdall -q         # aucun rapport
```

## 5. Observations hors périmètre (à traiter dans un ticket dédié)

### 5.1 `required` absent du schéma OpenAPI publié sur les modèles d'erreur

Le schéma OpenAPI **publié par l'application** n'expose pas la liste
`required` des modèles d'erreur, alors que le contrat `openapi.yaml` exige
`required: [code, message]` : Pydantic n'inscrit pas les champs à valeur par
défaut dans `required`.

- Le **comportement** est conforme : les réponses produites portent toujours
  `code` et `message` (vérifié par la validation `jsonschema` du corps contre
  le contrat — `tests/test_vault_integration_testclient.py:455–489`) ;
- l'écart porte sur le **schéma publié** ;
- le correctif suppose de retirer les valeurs par défaut des modèles d'erreur
  de `heimdall/vault/app.py` : c'est une modification de code **hors périmètre**
  de T255 (ticket de tests), à ouvrir en ticket dédié.

Tant que le correctif n'est pas appliqué, la comparaison stricte est marquée
`expectedFailure` (`tests/test_vault_integration_testclient.py:519–564`) : le
marqueur saute (XPASS ⇒ échec explicite de la suite) dès que le correctif
arrive, ce qui interdit de laisser filer un drift ultérieur.

### 5.2 Numérotation `#65`

Dans le code du Vault, `#65` désigne **uniquement** la limitation de débit
(`heimdall/vault/ratelimit.py`). Les tests d'intégration `TestClient` sont le
sous-ticket **T255** (sous-ticket 5 du parent `#25`), afin que la matrice
`docs/contracts/vault-traceability.md` ne contienne qu'un seul `#65`
normatif — source d'erreur d'audit SAMM/pentest. Aucun code n'est impacté.

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
