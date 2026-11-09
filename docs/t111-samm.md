# T111 — preuves pour la ligne SAMM (rate-limiting par clé et par IP)

Périmètre : sous-ticket **#111** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`. Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `a299534d1399fc18299ca93d93d7f8752c276c86`
(`fix(vault): cle non hachable : parcours factice avant la decision pair/global (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Fenêtre **glissante** par clé API validée | [heimdall/vault/ratelimit.py:87–238](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L87-L238), [heimdall/vault/ratelimit.py:241–413](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L241-L413) | [tests/test_vault_ratelimit.py:21–43](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L21-L43), [tests/test_vault_ratelimit.py:102–125](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L102-L125) | Réussi |
| Fenêtre glissante par **pair réseau** (adresse du socket, jamais `X-Forwarded-For`) | [heimdall/vault/ratelimit.py:176–216](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L176-L216), [heimdall/vault/ratelimit.py:349–393](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L349-L393) | [tests/test_vault_abuse_runtime.py:89–115](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_abuse_runtime.py#L89-L115) | Réussi |
| Dépassement : **429** avec `Retry-After` borné 1..3600, calculé sur la plus ancienne admission | [heimdall/vault/ratelimit.py:76–84](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L76-L84), [heimdall/vault/app.py:1267–1326](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/app.py#L1267-L1326) | [tests/test_vault_ratelimit.py:46–64](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L46-L64), [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Pair/global consommés même quand le budget clé est plein, en une seule transaction | [heimdall/vault/ratelimit.py:218–238](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L218-L238), [heimdall/vault/ratelimit.py:395–413](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L395-L413) | [tests/test_vault_ratelimit.py:66–84](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L66-L84), [tests/test_vault_ratelimit.py:146–164](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L146-L164) | Réussi |
| Backend SQLite partagé entre workers (`rate_limit_hits`, `BEGIN IMMEDIATE`) | [heimdall/vault/ratelimit.py:241–413](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L241-L413), [heimdall/vault/database.py:168–176](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/database.py#L168-L176) | [tests/test_vault_ratelimit.py:102–125](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L102-L125), [tests/test_vault_app.py:1616–1641](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_app.py#L1616-L1641) | Réussi |
| Borne de `rate_limit_hits` sur flot de rejets : purge des expirés à chaque évaluation, rejets compris | [heimdall/vault/ratelimit.py:278–285](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L278-L285), [heimdall/vault/ratelimit.py:317](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L317), [heimdall/vault/database.py:174–175](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/database.py#L174-L175) | [tests/test_vault_ratelimit.py:167–192](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_ratelimit.py#L167-L192), [tests/test_vault_availability.py:179–205](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/tests/test_vault_availability.py#L179-L205) | Réussi |
| Limite mémoire documentée : un cache en mémoire ne suffit pas avec plusieurs processus | [docs/contracts/vault-api.md:314–324](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/docs/contracts/vault-api.md#L314-L324), [heimdall/vault/ratelimit.py:1–25](https://github.com/Cezar277/heimdall/blob/a299534d1399fc18299ca93d93d7f8752c276c86/heimdall/vault/ratelimit.py#L1-L25) | Revue de la fiche (section 2) | Réussi |

## 2. Limite mémoire et multi-processus

Le backend `RateLimiter` (mémoire) est volontairement limité au
développement/test : chaque processus possède son propre dictionnaire de
budgets. Avec `workers > 1`, la limite effective serait multipliée par le
nombre de processus. La production utilise `SqliteRateLimiter`, qui persiste
les admissions dans `rate_limit_hits` et sérialise les décisions sous
`BEGIN IMMEDIATE` : la limite est partagée, pas multipliée. `run_server`
épingle `workers=1` par défaut pour le backend mémoire.

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| Denial of service (force brute de clés) | Budget pair/global avant hachage, budget clé après validation, 429 + `Retry-After` | `heimdall/vault/ratelimit.py:173`, `:215`, `:356`, `:402` ; tests d'abus runtime |
| Contournement par `X-Forwarded-For` | Le pair est `request.client.host` (socket), XFF ignoré | `heimdall/vault/app.py:1214`, test `test_spoofed_forwarded_for_does_not_reset_the_peer_budget` |
| Fuite de clé dans les budgets | Nom de budget = empreinte HMAC, jamais la clé brute | `heimdall/vault/ratelimit.py:173`, `:356` |
| Double budget à la frontière d'une fenêtre fixe | Fenêtre glissante exacte (horodatages), test dédié | `tests/test_vault_ratelimit.py:20`, `:101` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_ratelimit.py -q
# 8 passed
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
