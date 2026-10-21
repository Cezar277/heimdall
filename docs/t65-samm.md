# T65 — preuves pour la ligne SAMM (tests d'intégration TestClient)

Périmètre : ticket #65 (sous-ticket de #25 « Vault minimal »). Cette fiche
fournit les couples module + ligne et les permaliens du code testé ; elle ne
prétend pas modifier une feuille externe.

Révision du code testé : `80379f91770b12cd354b0467e07a62364dacf753`
(`test(vault): ajoute les tests d'integration TestClient (#65)`), au-dessus du
merge de `main` (`24e72c1`, PR #162 / #64).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code `#65` référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff 80379f91770b12cd354b0467e07a62364dacf753 HEAD -- tests/test_vault_integration_testclient.py pyproject.toml requirements.lock`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Note de numérotation** : le code du Vault désigne `#65` comme le ticket de
> limitation de débit (`heimdall/vault/ratelimit.py`, `docs/contracts/vault-traceability.md`).
> Le ticket livré ici est l'issue GitHub **#65 « Tests d'intégration TestClient »**,
> qui porte le même numéro. L'ambiguïté est signalée au compte rendu ; elle ne
> concerne que les libellés, pas le code.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Cas nominal : POST puis GET sur la même base | [heimdall/vault/app.py:1135–1192](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1135-L1192), [heimdall/vault/app.py:1194–1238](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1194-L1238), [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/store.py#L235-L270) | [tests/test_vault_integration_testclient.py:249–274](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L249-L274) | Réussi |
| La réponse 201 ne contient jamais la valeur | [heimdall/vault/app.py:1187–1192](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1187-L1192) | [tests/test_vault_integration_testclient.py:276–281](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L276-L281) | Réussi |
| `Cache-Control: no-store` sur 201 et 200 | [heimdall/vault/app.py:1159](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1159), [heimdall/vault/app.py:1224](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1224) | [tests/test_vault_integration_testclient.py:283–293](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L283-L293) | Réussi |
| Clé invalide → 401 (absente, inconnue, révoquée, malformée) | [heimdall/vault/auth.py:801–853](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/auth.py#L801-L853), [heimdall/vault/auth.py:600–623](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/auth.py#L600-L623) | [tests/test_vault_integration_testclient.py:328–346](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L328-L346) | Réussi |
| 401 générique : corps identique quelle que soit la cause, aucun écho de la clé | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/auth.py#L142-L150) | [tests/test_vault_integration_testclient.py:348–362](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L348-L362) | Réussi |
| Secret d'un autre projet → 403 (avant toute recherche de ressource) | [heimdall/vault/auth.py:856–872](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/auth.py#L856-L872), [heimdall/vault/auth.py:875–904](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/auth.py#L875-L904), [heimdall/vault/app.py:1152–1158](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1152-L1158) | [tests/test_vault_integration_testclient.py:384–424](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L384-L424) | Réussi |
| Le refus 403 n'écrit rien (pas d'effet de bord) | [heimdall/vault/app.py:1152–1158](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1152-L1158) | [tests/test_vault_integration_testclient.py:407–424](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L407-L424) | Réussi |
| Le Vault respecte l'OpenAPI : corps de réponse validés contre le contrat | [openapi.yaml:22–190](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/openapi.yaml#L22-L190), [heimdall/vault/app.py:380–434](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L380-L434) | [tests/test_vault_integration_testclient.py:217–243](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L217-L243), [tests/test_vault_integration_testclient.py:443–462](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L443-L462) | Réussi |
| Schéma OpenAPI de l'application aligné sur le contrat (chemins, operationId, statuts, charges utiles) | [heimdall/vault/app.py:1120–1300](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1120-L1300) | [tests/test_vault_integration_testclient.py:479–540](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L479-L540) | Réussi |
| Base temporaire par test : aucun état partagé | [heimdall/vault/database.py:851–867](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/database.py#L851-L867) | [tests/test_vault_integration_testclient.py:154–181](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L154-L181), [tests/test_vault_integration_testclient.py:545–571](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L545-L571) | Réussi |
| Chiffrement au repos : la valeur en clair est absente du fichier SQLite | [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/store.py#L235-L270), [heimdall/vault/crypto.py:228–232](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/crypto.py#L228-L232) | [tests/test_vault_integration_testclient.py:295–310](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L295-L310) | Réussi |
| Permissions du fichier SQLite durcies (0o600) | [heimdall/vault/database.py:290–302](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/database.py#L290-L302) | [tests/test_vault_integration_testclient.py:312–316](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L312-L316) | Réussi |
| Aucune origine hors boucle locale (403 du middleware) | [heimdall/vault/app.py:1035–1061](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/heimdall/vault/app.py#L1035-L1061) | [tests/test_vault_integration_testclient.py:56–60](https://github.com/Cezar277/heimdall/blob/80379f91770b12cd354b0467e07a62364dacf753/tests/test_vault_integration_testclient.py#L56-L60) (client présenté en `127.0.0.1`) | Réussi |

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
| VLT-E (accès interprojets) | Autorisation tranchée avant toute recherche de ressource ; 403 indépendant de l'existence du secret | `heimdall/vault/auth.py:856` (`ensure_project_access`), testé par `tests/test_vault_integration_testclient.py:395–405` |
| VLT-S (réemploi de clé volée) | Clé absente, inconnue, révoquée ou malformée : 401 générique identique, jamais d'écho | `heimdall/vault/auth.py:801`, testé par `tests/test_vault_integration_testclient.py:328–362` |
| Information disclosure | 201 sans la valeur ; `Cache-Control: no-store` ; valeur absente du fichier SQLite | `heimdall/vault/app.py:1187`, `heimdall/vault/store.py:259`, testé par `tests/test_vault_integration_testclient.py:276–310` |
| Contract drift (openapi.yaml ↔ implémentation) | Corps de réponse validés contre le schéma du contrat + schéma OpenAPI de l'application comparé au contrat | `tests/test_vault_integration_testclient.py:443–540` |
| Durcissement du stockage | Base temporaire en 0o600, schéma vérifié par `init_db` | `heimdall/vault/database.py:290`, `heimdall/vault/database.py:851` |

## 4. Résultats locaux

Environnement : Linux, Python 3.14.7, venv reconstruit depuis `requirements.lock`
(fastapi 0.143.1, starlette 1.7.0, httpx2 2.13.1, pydantic 2.14.1) — mêmes
versions que la CI.

```sh
python -m pytest tests/test_vault_integration_testclient.py -q
# 21 passed
python -m pytest -p no:randomly --tb=short -rN
# 1162 passed, 1 skipped, 1 xfailed, 4299 subtests passed
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 29 source files
bandit -r heimdall -q         # aucun rapport
```

## 5. Observation hors périmètre (à traiter dans un ticket dédié)

Le schéma OpenAPI **publié par l'application** n'expose pas la liste
`required` des modèles d'erreur, alors que le contrat `openapi.yaml` exige
`required: [code, message]` : Pydantic n'inscrit pas les champs à valeur par
défaut dans `required`. Le **comportement** est conforme (les réponses produites
portent toujours `code` et `message`, vérifié par la validation `jsonschema`
contre le contrat) ; l'écart porte sur le schéma publié. Le correctif
suppose de retirer les valeurs par défaut des modèles d'erreur de
`heimdall/vault/app.py` : c'est une modification de code hors périmètre du
ticket #65 (tests), signalée au compte rendu.

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
