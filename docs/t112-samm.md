# T112 — preuves pour la ligne SAMM (comparaison en temps constant)

Périmètre : sous-ticket **#112** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `c3bb619d6f26f57fbce83974acaf6d6d20fb802c`
(`test(vault): deplace les tests d'abus runtime hors de tests/security (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Comparaison des empreintes avec `hmac.compare_digest` | [heimdall/vault/crypto.py:148–154](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/crypto.py#L148-L154), [heimdall/vault/auth.py:739](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L739), [heimdall/vault/auth.py:775](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L775) | [tests/test_vault_constant_time.py:75–96](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L75-L96), [tests/test_vault_auth.py:118–135](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_auth.py#L118-L135) | Réussi |
| Parcours exhaustif des empreintes, sans `break` précoce | [heimdall/vault/auth.py:724–742](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L724-L742), [heimdall/vault/auth.py:745–777](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L745-L777) | [tests/test_vault_constant_time.py:75–96](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L75-L96), [tests/test_vault_review_regressions.py:430–447](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_review_regressions.py#L430-L447) | Réussi |
| Même travail pour clé inconnue et clé invalide : hachage + parcours exécutés avant le rejet de format | [heimdall/vault/auth.py:830–923](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L830-L923), [heimdall/vault/app.py:1183–1222](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/app.py#L1183-L1222) | [tests/test_vault_constant_time.py:31–72](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L31-L72) | Réussi |
| Même réponse et même code pour clé absente, inconnue, révoquée ou malformée | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L142-L150), [heimdall/vault/auth.py:830–923](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L830-L923) | [tests/test_vault_constant_time.py:130–153](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L130-L153), [tests/test_vault_auth.py:118–135](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_auth.py#L118-L135) | Réussi |
| Garde de taille bornée : clé > 512 caractères rejetée avant hachage (protection CPU/DoS), sans oracle d'existence | [heimdall/vault/auth.py:864–868](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L864-L868), [heimdall/vault/app.py:1298–1312](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/app.py#L1298-L1312) | [tests/test_vault_review_regressions.py:330–357](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_review_regressions.py#L330-L357) | Réussi |
| Aucun message ne distingue « compte inexistant » et « mauvaise clé » | [heimdall/vault/auth.py:142–150](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L142-L150) | [tests/test_vault_constant_time.py:130–153](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L130-L153) | Réussi |
| Coût du lookup `key_id` égalisé : réel sur clé valide, factice sur clé invalide | [heimdall/vault/app.py:1202–1222](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/app.py#L1202-L1222), [heimdall/vault/auth.py:919–936](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/heimdall/vault/auth.py#L919-L936) | [tests/test_vault_constant_time.py:98–128](https://github.com/Cezar277/heimdall/blob/c3bb619d6f26f57fbce83974acaf6d6d20fb802c/tests/test_vault_constant_time.py#L98-L128) | Réussi |

## 2. Détail du chemin de vérification

1. Le middleware de débit hache toute clé fournie (vide, blanche, inconnue)
   avec le pepper serveur et exécute le parcours exhaustif. Le résultat est
   mémoïsé dans `request.state` pour la dépendance d'authentification.
2. `verify_api_key` réutilise cette empreinte (comparaison avec l'en-tête brut
   pour empêcher une dépendance surchargée de réutiliser un autre hash), puis
   contrôle le format **après** le parcours. Une clé blanche ou vide ne
   court-circuite donc pas le travail.
3. Seule la garde de taille (> 512) sort avant le hachage : elle borne le coût
   CPU et ne dépend pas de l'existence d'une clé.
4. `lookup_db_api_key` et `find_api_key_project` parcourent toutes les
   empreintes sans `break`, avec `constant_time_equal` pour chaque candidat.
   Une empreinte factice est comparée quand aucune clé n'est évaluée.

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| Spoofing (oracle temporel sur l'existence d'une clé) | Parcours exhaustif, comparaison constante, empreinte factice, même 401 | `heimdall/vault/auth.py:823`, `:717`, `:738` ; `tests/test_vault_constant_time.py` |
| Information disclosure (message d'erreur distinct) | 401 générique unique, aucun écho de la clé reçue | `heimdall/vault/auth.py:142`, test `test_missing_unknown_revoked_and_malformed_share_the_same_401` |
| Denial of service (clé surdimensionnée) | Refus 401 avant hachage au-delà de 512 caractères | `heimdall/vault/auth.py:837`, `tests/test_vault_review_regressions.py:330` |
| Contrat openapi.yaml:197–208 | `compare_digest`, haché salé, 401 générique, coût comparable | `openapi.yaml` (securitySchemes.ProjectApiKey), `docs/contracts/vault-api.md:345–365` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_constant_time.py -q
# 4 passed
python -m pytest tests/test_vault_auth.py tests/test_vault_review_regressions.py -q
# passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
