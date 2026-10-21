# T255 — preuves pour la ligne SAMM (tests d'intégration TestClient)

Sous-ticket **T255** du ticket parent `#25 « Vault minimal »` (branche
`65-t255-tests-dintégration-testclient`). Cette fiche fournit les couples
module + ligne et les permaliens du code testé ; elle ne prétend pas modifier
une feuille externe.

Révision du code testé : `bc9fe09` (`docs(vault): resorbe la collision de
numerotation #65 (rate-limit vs tests)` — libellés uniquement, qui porte le
correctif applicatif `65ba2ca`), au-dessus de `65ba2ca`
(`fix(vault): aligne le schema OpenAPI publie sur le contrat (required)`),
`41fc0a8` (`test(vault): corrige les remarques de la revue sur les tests
TestClient (#65)`), `80379f9` (`test(vault): ajoute les tests d'integration
TestClient (#65)`) et du merge de `main` (`24e72c1`, PR #162 / #64).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code `T255` référencé est inchangé jusqu'à la
livraison : contrôle effectué avec
`git diff bc9fe09 HEAD -- tests/test_vault_integration_testclient.py heimdall/vault/app.py tests/test_vault_app.py pyproject.toml requirements.lock`
(sortie vide) ; les commits suivants ne modifient que la documentation.

> **Numérotation** : `#65` est l'issue GitHub **« Tests d'intégration TestClient »**
> (sous-ticket 5 de `#25 « Vault minimal »`, branche
> `65-t255-tests-dintégration-testclient`) : c'est elle que la PR ferme
> (`Closes #65`). La limitation de débit n'a pas d'issue GitHub propre (livrée
> dans le lot d'intégration #63) et n'est plus étiquetée `#65` : la matrice
> `docs/contracts/vault-traceability.md` ne contient qu'un seul `#65` normatif
> (voir §5.2).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Cas nominal : POST puis GET sur la même base | [heimdall/vault/app.py:1143–1200](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1143-L1200), [heimdall/vault/app.py:1202–1246](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1202-L1246), [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/store.py#L235-L270) | [tests/test_vault_integration_testclient.py:238–263](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L238-L263) | Réussi |
| La réponse 201 ne contient jamais la valeur | [heimdall/vault/app.py:1195–1200](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1195-L1200) | [tests/test_vault_integration_testclient.py:265–270](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L265-L270) | Réussi |
| `Cache-Control: no-store` sur 201 et 200 | [heimdall/vault/app.py:1167](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1167), [heimdall/vault/app.py:1232](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1232) | [tests/test_vault_integration_testclient.py:272–282](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L272-L282) | Réussi |
| Clé invalide → 401 (absente, inconnue, révoquée, malformée) | [heimdall/vault/auth.py:801–853](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/auth.py#L801-L853), [heimdall/vault/auth.py:600–623](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/auth.py#L600-L623) | [tests/test_vault_integration_testclient.py:317–335](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L317-L335) | Réussi |
| 401 générique : corps identique quelle que soit la cause, aucun écho de la clé | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/auth.py#L142-L150) | [tests/test_vault_integration_testclient.py:337–352](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L337-L352) | Réussi |
| Secret d'un autre projet → 403 (avant toute recherche de ressource) | [heimdall/vault/auth.py:856–872](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/auth.py#L856-L872), [heimdall/vault/auth.py:875–904](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/auth.py#L875-L904), [heimdall/vault/app.py:1160–1166](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1160-L1166) | [tests/test_vault_integration_testclient.py:373–413](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L373-L413) | Réussi |
| Le refus 403 n'écrit rien (pas d'effet de bord) | [heimdall/vault/app.py:1160–1166](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1160-L1166) | [tests/test_vault_integration_testclient.py:396–413](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L396-L413) | Réussi |
| Le Vault respecte l'OpenAPI : corps de réponse validés contre le contrat | [openapi.yaml:22–190](https://github.com/Cezar277/heimdall/blob/bc9fe09/openapi.yaml#L22-L190), [heimdall/vault/app.py:388–442](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L388-L442) | [tests/test_vault_integration_testclient.py:206–233](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L206-L233), [tests/test_vault_integration_testclient.py:432–451](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L432-L451) | Réussi |
| Schéma OpenAPI de l'application aligné sur le contrat (chemins, operationId, statuts, charges utiles) | [heimdall/vault/app.py:1128–1308](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1128-L1308) | [tests/test_vault_integration_testclient.py:468–493](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L468-L493) | Réussi |
| **Schéma publié strictement aligné** : `required: [code, message]` / `required: [status]` exigés par le contrat | [heimdall/vault/app.py:140–209](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L140-L209), [heimdall/vault/app.py:744–749](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L744-L749) | [tests/test_vault_integration_testclient.py:495–546](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L495-L546) | Réussi (drift corrigé, §5.1) |
| Base temporaire par test : aucun état partagé (base, registre, empreintes) | [heimdall/vault/database.py:851–867](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/database.py#L851-L867) | [tests/test_vault_integration_testclient.py:677–708](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L677-L708), [tests/test_vault_integration_testclient.py:710–731](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L710-L731) | Réussi |
| Chiffrement au repos : la valeur en clair est absente du fichier SQLite | [heimdall/vault/store.py:235–270](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/store.py#L235-L270), [heimdall/vault/crypto.py:228–232](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/crypto.py#L228-L232) | [tests/test_vault_integration_testclient.py:284–299](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L284-L299) | Réussi |
| Permissions du fichier SQLite durcies (0o600) | [heimdall/vault/database.py:290–302](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/database.py#L290-L302) | [tests/test_vault_integration_testclient.py:301–305](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L301-L305) | Réussi |
| Origine non loopback → 403 (défense en profondeur transport) | [heimdall/vault/app.py:1043–1069](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1043-L1069) | [tests/test_vault_integration_testclient.py:551–577](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L551-L577) | Réussi |
| Débit dépassé → 429 contractuel + `Retry-After` borné 1..3600 | [heimdall/vault/app.py:966–1040](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L966-L1040), [heimdall/vault/ratelimit.py:263–299](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/ratelimit.py#L263-L299) | [tests/test_vault_integration_testclient.py:589–614](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L589-L614) | Réussi |
| Abus d'entrée : corps > 1 Mio, identifiants hors contrat, traversée de chemin, JSON mal formé | [heimdall/vault/app.py:808–885](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L808-L885), [heimdall/vault/app.py:307–335](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L307-L335) | [tests/test_vault_integration_testclient.py:619–672](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L619-L672) | Réussi |
| Localité : aucun port réseau, client présenté en `127.0.0.1` | [heimdall/vault/app.py:1043–1069](https://github.com/Cezar277/heimdall/blob/bc9fe09/heimdall/vault/app.py#L1043-L1069) | [tests/test_vault_integration_testclient.py:62–64](https://github.com/Cezar277/heimdall/blob/bc9fe09/tests/test_vault_integration_testclient.py#L62-L64) | Réussi |

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
| VLT-E (accès interprojets) | Autorisation tranchée avant toute recherche de ressource ; 403 indépendant de l'existence du secret | `heimdall/vault/auth.py:856` (`ensure_project_access`), testé par `tests/test_vault_integration_testclient.py:384–394` |
| VLT-S (réemploi de clé volée) | Clé absente, inconnue, révoquée ou malformée : 401 générique identique, jamais d'écho | `heimdall/vault/auth.py:801`, testé par `tests/test_vault_integration_testclient.py:317–352` |
| Information disclosure | 201 sans la valeur ; `Cache-Control: no-store` ; valeur absente du fichier SQLite | `heimdall/vault/app.py:1195`, `heimdall/vault/store.py:259`, testé par `tests/test_vault_integration_testclient.py:265–299` |
| Contract drift (openapi.yaml ↔ implémentation) | Corps de réponse validés contre le schéma du contrat + schéma OpenAPI de l'application comparé au contrat, comparaison **STRICTE** sur toutes les contraintes (`required` inclus) | `heimdall/vault/app.py:140–209`, testé par `tests/test_vault_integration_testclient.py:432–546` |
| Durcissement du stockage | Base temporaire en 0o600, schéma vérifié par `init_db` | `heimdall/vault/database.py:290`, `heimdall/vault/database.py:851` |
| Network exposure (defense in depth) | Origine non loopback rejetée en 403 avant tout routage | `heimdall/vault/app.py:1043`, testé par `tests/test_vault_integration_testclient.py:551–577` |
| Denial of service (débit) | Quota par clé API validée, 429 contractuel, `Retry-After` borné | `heimdall/vault/ratelimit.py:263`, testé par `tests/test_vault_integration_testclient.py:589–614` |
| Abus d'entrée (path traversal, corps surdimensionné) | Rejets 400/404 contractuels, aucune entrée reflétée | `heimdall/vault/app.py:808`, testé par `tests/test_vault_integration_testclient.py:619–672` |

## 4. Résultats locaux

Environnement : Linux, Python 3.14.7, venv reconstruit depuis `requirements.lock`
(fastapi 0.143.1, starlette 1.7.0, httpx2 2.13.1, pydantic 2.14.1) — mêmes
versions que la CI.

```sh
python -m pytest tests/test_vault_integration_testclient.py -q
# 30 passed, 46 subtests passed
python -m pytest -p no:randomly --tb=short -rN
# 1171 passed, 1 skipped, 1 xfailed, 4317 subtests passed
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 29 source files
bandit -r heimdall -q         # aucun rapport
```

## 5. Écarts détectés par la suite

### 5.1 Drift de contrat `required` — CORRIGÉ dans cette livraison

Le schéma OpenAPI **publié par l'application** n'exposait pas la liste
`required` des modèles d'erreur, alors que le contrat `openapi.yaml` exige
`required: [code, message]` (openapi.yaml:412–508) : Pydantic omet les champs
à valeur par défaut de `required`.

- **Détecté par** : la comparaison du schéma publié avec le contrat
  (`tests/test_vault_integration_testclient.py:495–546`) ;
- **Corrigé dans** : `heimdall/vault/app.py` — les 19 champs `code`, `message`
  et `status` des modèles d'erreur et de `HealthResponse` ne portent plus de
  valeur par défaut (`heimdall/vault/app.py:140–209`, `:744–749`) ;
- **Impact runtime nul** : les gestionnaires d'exceptions construisent déjà
  les charges utiles explicitement (`_ERROR_PAYLOADS`,
  `heimdall/vault/app.py:127–137`), les réponses sont inchangées ;
- **Preuve** : `tests/test_vault_integration_testclient.py:495–546` compare
  désormais les schémas **sans aucune normalisation** et
  `tests/test_vault_integration_testclient.py:529–546` vérifie explicitement
  les listes `required` publiées. Un drift futur fait échouer la suite.

### 5.2 Numérotation `#65` — collision résorbée

`#65` est l'issue GitHub **« Tests d'intégration TestClient »** (sous-ticket 5
de `#25 « Vault minimal »`, branche `65-t255-tests-dintégration-testclient`) :
c'est elle que la PR ferme (`Closes #65`).

La limitation de débit n'a **pas** d'issue GitHub propre : elle a été livrée
dans le lot d'intégration du ticket #63. L'ancien libellé « #65 » employé dans
le code pour le débit désignait le *slot 5* de #25 — devenu l'issue #65 des
tests d'intégration — d'où la collision (source d'erreur pour l'audit
SAMM/pentest). Il a été remplacé partout par « lot #63 » :

- code : `heimdall/vault/ratelimit.py`, `heimdall/vault/app.py`,
  `heimdall/vault/auth.py`, `heimdall/vault/database.py`,
  `heimdall/vault/store.py`, `tests/test_vault_app.py` ;
- docs : `docs/contracts/vault-traceability.md`, `docs/contracts/vault-api.md`,
  `README.md` ;
- la matrice `docs/contracts/vault-traceability.md` ne contient plus qu'**un
  seul** `#65` normatif (les tests d'intégration), et la limitation de débit
  est étiquetée « #63 (lot d'intégration) ».

Aucun changement fonctionnel : commentaires et libellés uniquement.

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
