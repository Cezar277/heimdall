# T64 — preuves pour la ligne SAMM (authentification par clé API de projet)

Périmètre : ticket #64 (brique « auth + registre » du Vault). Cette fiche fournit
les couples module + ligne et les permaliens du code testé ; elle ne prétend pas
modifier une feuille externe.

Révision du code testé : `e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82`
(`fix(vault): aligner la base d'authentification et durcir la validation (#64)`),
au-dessus du merge de `main` (`640df27`).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code #64 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82 HEAD -- heimdall/vault/ heimdall/cli/vault_keys.py heimdall/cli/main.py tests/test_vault_auth.py tests/test_vault_app.py tests/test_vault_review_regressions.py`
(sortie vide) ; les commits suivants ne modifient que la documentation, et les
évolutions scanner #53 apportées par `main` sont hors de ce périmètre.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Génération d'une clé aléatoire à ≥ 256 bits (`secrets.token_urlsafe(32)`) | [heimdall/vault/auth.py:157–164](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L157-L164) | [tests/test_vault_auth.py:46–53](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L46-L53) | Réussi |
| Stockage du HACHÉ de vérification uniquement (jamais la clé brute) | [heimdall/vault/auth.py:167–180](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L167-L180), [heimdall/vault/auth.py:525–577](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L525-L577) | [tests/test_vault_auth.py:68–87](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L68-L87) | Réussi |
| Clé affichée UNE SEULE FOIS à la création (jamais conservée) | [heimdall/vault/auth.py:428–444](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L428-L444), [heimdall/vault/auth.py:579–598](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L579-L598), [heimdall/cli/vault_keys.py:81–111](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/cli/vault_keys.py#L81-L111) | [tests/test_vault_auth.py:55–66](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L55-L66), [tests/test_vault_auth.py:382–391](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L382-L391) | Réussi |
| Dépendance FastAPI qui lit l'en-tête et retrouve la clé | [heimdall/vault/auth.py:68–75](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L68-L75), [heimdall/vault/auth.py:801–853](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L801-L853) | [tests/test_vault_auth.py:117–134](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L117-L134) | Réussi |
| La clé doit appartenir AU projet demandé (403 hors projet, avant toute recherche) | [heimdall/vault/auth.py:856–872](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L856-L872), [heimdall/vault/auth.py:875–904](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L875-L904) | [tests/test_vault_auth.py:136–152](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L136-L152) | Réussi |
| Clé jamais stockée ni loguée en clair (ni corps d'erreur, ni journal) | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L142-L150), [heimdall/vault/auth.py:428–444](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L428-L444) | [tests/test_vault_auth.py:218–226](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L218-L226), [tests/test_vault_auth.py:228–251](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L228-L251) | Réussi |
| Coût de vérification comparable, sans oracle temporel (parcours exhaustif, `compare_digest`) | [heimdall/vault/auth.py:695–713](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L695-L713), [heimdall/vault/auth.py:716–748](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L716-L748) | [tests/test_vault_app.py:2158–2206](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_app.py#L2158-L2206) | Réussi |
| Révocation : la clé cesse d'authentifier, sans réactivation | [heimdall/vault/auth.py:600–623](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L600-L623), [heimdall/vault/auth.py:944–959](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L944-L959), [heimdall/cli/vault_keys.py:151–173](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/cli/vault_keys.py#L151-L173) | [tests/test_vault_auth.py:273–283](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L273-L283), [tests/test_vault_auth.py:405–459](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L405-L459) | Réussi |
| Politique opérateur fail-closed (motifs triviaux, projet hors contrat, pepper public) | [heimdall/vault/auth.py:183–219](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L183-L219), [heimdall/vault/auth.py:325–386](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L325-L386), [heimdall/vault/auth.py:405–419](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L405-L419) | [tests/test_vault_auth.py:285–303](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L285-L303), [tests/test_vault_auth.py:305–315](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L305-L315) | Réussi |

## 2. Correctifs de la revue sécurité (PR #162)

| Remarque du relecteur | Correctif | Preuve permanente |
|---|---|---|
| **HIGH** — désynchronisation du chemin SQLite entre écriture (`_persist_hash`) et lecture (`find_api_key_project`) quand un `secret_store` explicite surcharge le chemin | le registre est construit avec `app.state.db_path` (chemin effectif du store), la lecture passe par `registry.db_path` — la même référence que l'écriture — et le chemin du store est normalisé en `Path` | [heimdall/vault/app.py:1330–1337](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/app.py#L1330-L1337), [heimdall/vault/app.py:1404–1413](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/app.py#L1404-L1413), [heimdall/vault/auth.py:716–748](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L716-L748) + [tests/test_vault_auth.py:163–216](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L163-L216) |
| **LOW** — `key_id` contournable par un `\n` final (`match` + `$`) puis réémis par la CLI | `validate_key_id` passe en `fullmatch` | [heimdall/vault/auth.py:389–402](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L389-L402) + [tests/test_vault_auth.py:328–338](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L328-L338) |
| **LOW** — registre instancié avec un pepper vide (`revoke_registered_key`) | plus de registre pour la révocation (écriture directe en base) **et** garde explicite : `register` / `register_hash` / `issue` lèvent sans pepper serveur | [heimdall/vault/auth.py:637–649](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L637-L649), [heimdall/vault/auth.py:944–959](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L944-L959) + [tests/test_vault_auth.py:317–326](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L317-L326), [tests/test_vault_auth.py:479–501](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L479-L501) |
| **LOW** — filtre `--project` de `list` non validé (silence « Aucune clé ») | validation de l'identifiant de projet avant listage (erreur code 2) **et** dans la bibliothèque `list_registered_keys` (défense en profondeur) | [heimdall/cli/vault_keys.py:115–147](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/cli/vault_keys.py#L115-L147), [heimdall/vault/auth.py:922–941](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/heimdall/vault/auth.py#L922-L941) + [tests/test_vault_auth.py:503–520](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L503-L520), [tests/test_vault_auth.py:522–535](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L522-L535) |
| Test manquant — cycle CLI complet `create` → 200 authentifié → `revoke` → 401 | test HTTP de bout en bout avec la vraie CLI | [tests/test_vault_auth.py:405–459](https://github.com/Cezar277/heimdall/blob/e3d4d5cd10bd87b13f09a9a8670ded9858f6aa82/tests/test_vault_auth.py#L405-L459) |

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| VLT-S (réemploi de clé volée, oracle de latence) | Clé aléatoire 256 bits, empreinte seule serveur, comparaison constante, parcours exhaustif, révocation | `heimdall/vault/auth.py` (§1, lignes 695–853) |
| VLT-E (accès interprojets) | Autorisation projet décidée avant toute recherche de ressource ; 403 indépendant de l'existence | `heimdall/vault/auth.py:856` (`ensure_project_access`) |
| openapi.yaml:193–208 (schéma `ProjectApiKey`) | En-tête `X-Heimdall-API-Key`, `secrets.token_urlsafe(32)`, haché salé, `compare_digest`, 401 générique | `heimdall/vault/auth.py:68`, `:157`, `:167`, `:801` |
| Information disclosure | Clé brute absente de la base, des logs et des réponses d'erreur | `tests/test_vault_auth.py:68`, `:218`, `:228` |
| Availability (clé valide, 401 permanent) | Une seule référence de base entre écriture et lecture d'authentification | `heimdall/vault/app.py:1404`, `heimdall/vault/auth.py:716` |

## 4. Résultats locaux

Environnement : Linux, Python 3.14.7, venv reconstruit depuis `requirements.lock`
(fastapi 0.143.1, pydantic 2.14.1) — mêmes versions que la CI.

```sh
python -m pytest tests/test_vault_auth.py -q
# 31 passed, 20 subtests passed
python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
# 1141 passed, 1 skipped, 1 xfailed, 4267 subtests passed
# couverture totale 96,30 % (seuil CI 85 %) — heimdall/vault/* : 94 % (seuil 70 %)
ruff check heimdall tests      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 29 source files
bandit -r heimdall -q         # aucun rapport
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
