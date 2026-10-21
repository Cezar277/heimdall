# T64 — preuves pour la ligne SAMM (authentification par clé API de projet)

Périmètre : ticket #64 (brique « auth + registre » du Vault). Cette fiche fournit
les couples module + ligne et les permaliens du code testé ; elle ne prétend pas
modifier une feuille externe.

Révision du code testé : `e1275cec846a217c6bc2e482e911f6b58e8ad272` (merge de
`main` dans la branche #64).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code #64 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff e1275cec846a217c6bc2e482e911f6b58e8ad272 HEAD -- heimdall/vault/ heimdall/cli/vault_keys.py heimdall/cli/main.py tests/test_vault_auth.py tests/test_vault_app.py tests/test_vault_review_regressions.py`
(sortie vide) ; les commits suivants ne modifient que la documentation, et les
évolutions scanner #53 apportées par `main` sont hors de ce périmètre.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Génération d'une clé aléatoire à ≥ 256 bits (`secrets.token_urlsafe(32)`) | [heimdall/vault/auth.py:157–164](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L157-L164) | [tests/test_vault_auth.py:45–52](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L45-L52) | Réussi |
| Stockage du HACHÉ de vérification uniquement (jamais la clé brute) | [heimdall/vault/auth.py:167–180](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L167-L180), [heimdall/vault/auth.py:535–574](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L535-L574) | [tests/test_vault_auth.py:67–86](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L67-L86) | Réussi |
| Clé affichée UNE SEULE FOIS à la création (jamais conservée) | [heimdall/vault/auth.py:426–442](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L426-L442), [heimdall/vault/auth.py:576–594](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L576-L594), [heimdall/cli/vault_keys.py:81–111](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/cli/vault_keys.py#L81-L111) | [tests/test_vault_auth.py:54–65](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L54-L65), [tests/test_vault_auth.py:303–312](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L303-L312) | Réussi |
| Dépendance FastAPI qui lit l'en-tête et retrouve la clé | [heimdall/vault/auth.py:68–75](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L68-L75), [heimdall/vault/auth.py:779–831](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L779-L831) | [tests/test_vault_auth.py:116–133](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L116-L133) | Réussi |
| La clé doit appartenir AU projet demandé (403 hors projet, avant toute recherche) | [heimdall/vault/auth.py:834–850](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L834-L850), [heimdall/vault/auth.py:853–882](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L853-L882) | [tests/test_vault_auth.py:135–151](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L135-L151) | Réussi |
| Clé jamais stockée ni loguée en clair (ni corps d'erreur, ni journal) | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L142-L150), [heimdall/vault/auth.py:426–442](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L426-L442) | [tests/test_vault_auth.py:162–170](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L162-L170), [tests/test_vault_auth.py:172–194](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L172-L194) | Réussi |
| Coût de vérification comparable, sans oracle temporel (parcours exhaustif, `compare_digest`) | [heimdall/vault/auth.py:677–695](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L677-L695), [heimdall/vault/auth.py:698–726](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L698-L726) | [tests/test_vault_app.py:2158–2206](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_app.py#L2158-L2206) | Réussi |
| Révocation : la clé cesse d'authentifier, sans réactivation | [heimdall/vault/auth.py:596–619](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L596-L619), [heimdall/cli/vault_keys.py:147–169](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/cli/vault_keys.py#L147-L169) | [tests/test_vault_auth.py:217–227](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L217-L227), [tests/test_vault_auth.py:326–363](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L326-L363) | Réussi |
| Politique opérateur fail-closed (motifs triviaux, projet hors contrat, pepper public) | [heimdall/vault/auth.py:183–219](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L183-L219), [heimdall/vault/auth.py:325–386](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L325-L386), [heimdall/vault/auth.py:403–417](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/heimdall/vault/auth.py#L403-L417) | [tests/test_vault_auth.py:229–247](https://github.com/Cezar277/heimdall/blob/e1275cec846a217c6bc2e482e911f6b58e8ad272/tests/test_vault_auth.py#L229-L247) | Réussi |

## 2. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| VLT-S (réemploi de clé volée, oracle de latence) | Clé aléatoire 256 bits, empreinte seule serveur, comparaison constante, parcours exhaustif, révocation | `heimdall/vault/auth.py` (§1, lignes 677–831) |
| VLT-E (accès interprojets) | Autorisation projet décidée avant toute recherche de ressource ; 403 indépendant de l'existence | `heimdall/vault/auth.py:853` (`require_project_access`) |
| openapi.yaml:193–208 (schéma `ProjectApiKey`) | En-tête `X-Heimdall-API-Key`, `secrets.token_urlsafe(32)`, haché salé, `compare_digest`, 401 générique | `heimdall/vault/auth.py:68`, `:157`, `:167`, `:779` |
| Information disclosure | Clé brute absente de la base, des logs et des réponses d'erreur | `tests/test_vault_auth.py:67`, `:162`, `:172` |

## 3. Résultats locaux

```sh
python -m pytest tests/test_vault_auth.py -q
# 25 passed, 17 subtests passed
python -m pytest -q
# 1134 passed, 1 skipped, 1 xfailed, 4268 subtests passed
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 29 source files
bandit -r heimdall -q         # aucun rapport
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
