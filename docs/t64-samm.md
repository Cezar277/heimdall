# T64 — preuves pour la ligne SAMM (authentification par clé API de projet)

Périmètre : ticket #64 (brique « auth + registre » du Vault). Cette fiche fournit
les couples module + ligne et les permaliens du code testé ; elle ne prétend pas
modifier une feuille externe.

Révision du code testé : `7c5c576794cf80158e6130aa9bd0eb17354e7486`.

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code des modules référencés est inchangé entre cette
révision et le HEAD de livraison : contrôle effectué avec
`git diff 7c5c576794cf80158e6130aa9bd0eb17354e7486 HEAD -- heimdall/ tests/`
(sortie vide). Le commit suivant ne modifie que la documentation.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Génération d'une clé aléatoire à ≥ 256 bits (`secrets.token_urlsafe(32)`) | [heimdall/vault/auth.py:157–165](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L157-L165) | [tests/test_vault_auth.py:45–52](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L45-L52) | Réussi |
| Stockage du HACHÉ de vérification uniquement (jamais la clé brute) | [heimdall/vault/auth.py:167–181](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L167-L181), [heimdall/vault/auth.py:548–583](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L548-L583) | [tests/test_vault_auth.py:67–86](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L67-L86) | Réussi |
| Clé affichée UNE SEULE FOIS à la création (jamais conservée) | [heimdall/vault/auth.py:334–351](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L334-L351), [heimdall/vault/auth.py:484–502](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L484-L502), [heimdall/cli/vault_keys.py:80–112](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/cli/vault_keys.py#L80-L112) | [tests/test_vault_auth.py:54–65](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L54-L65), [tests/test_vault_auth.py:292–301](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L292-L301) | Réussi |
| Dépendance FastAPI qui lit l'en-tête et retrouve la clé | [heimdall/vault/auth.py:68–75](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L68-L75), [heimdall/vault/auth.py:687–740](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L687-L740) | [tests/test_vault_auth.py:116–133](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L116-L133) | Réussi |
| La clé doit appartenir AU projet demandé (403 hors projet, avant toute recherche) | [heimdall/vault/auth.py:742–759](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L742-L759), [heimdall/vault/auth.py:761–796](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L761-L796) | [tests/test_vault_auth.py:135–151](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L135-L151) | Réussi |
| Clé jamais stockée ni loguée en clair (ni corps d'erreur, ni journal) | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L142-L150), [heimdall/vault/auth.py:334–351](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L334-L351) | [tests/test_vault_auth.py:162–195](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L162-L195) | Réussi |
| Coût de vérification comparable, sans oracle temporel (parcours exhaustif, `compare_digest`) | [heimdall/vault/auth.py:585–604](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L585-L604), [heimdall/vault/auth.py:606–668](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L606-L668) | [tests/test_vault_app.py:1982–2030](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_app.py#L1982-L2030) | Réussi |
| Révocation : la clé cesse d'authentifier, sans réactivation | [heimdall/vault/auth.py:504–527](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L504-L527), [heimdall/cli/vault_keys.py:146–170](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/cli/vault_keys.py#L146-L170) | [tests/test_vault_auth.py:217–227](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L217-L227), [tests/test_vault_auth.py:315–352](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L315-L352) | Réussi |
| Politique opérateur fail-closed (motifs triviaux, projet hors contrat, pepper public) | [heimdall/vault/auth.py:183–220](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L183-L220), [heimdall/vault/auth.py:255–295](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L255-L295), [heimdall/vault/auth.py:311–332](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/heimdall/vault/auth.py#L311-L332) | [tests/test_vault_auth.py:229–256](https://github.com/Cezar277/heimdall/blob/7c5c576794cf80158e6130aa9bd0eb17354e7486/tests/test_vault_auth.py#L229-L256) | Réussi |

## 2. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| VLT-S (réemploi de clé volée, oracle de latence) | Clé aléatoire 256 bits, empreinte seule serveur, comparaison constante, parcours exhaustif, révocation | `heimdall/vault/auth.py` (§1, lignes 585–739) |
| VLT-E (accès interprojets) | Autorisation projet décidée avant toute recherche de ressource ; 403 indépendant de l'existence | `heimdall/vault/auth.py:761` (`require_project_access`) |
| openapi.yaml:186–207 (schéma `ProjectApiKey`) | En-tête `X-Heimdall-API-Key`, `secrets.token_urlsafe(32)`, haché salé, `compare_digest`, 401 générique | `heimdall/vault/auth.py:68`, `:157`, `:167`, `:697` |
| Information disclosure | Clé brute absente de la base, des logs et des réponses d'erreur | `tests/test_vault_auth.py:67`, `:162`, `:172` |

## 3. Résultats locaux

```sh
python -m pytest tests/test_vault_auth.py -q
# 25 passed
python -m pytest -q
# suite complète : aucun échec
ruff check heimdall tests      # All checks passed!
mypy heimdall                 # Success: no issues found in 26 source files
bandit -r heimdall -q         # aucun rapport
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
