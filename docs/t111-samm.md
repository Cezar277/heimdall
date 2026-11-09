# T111 — preuves pour la ligne SAMM (rate-limiting par clé et par IP)

Périmètre : sous-ticket **#111** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`. Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `cbe979948ce21bfff6abe1efe59868c0376c0f2f`
(`fix(vault): purge l'audit par lots pour borner le verrou SQLite (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Fenêtre **glissante** par clé API validée | [heimdall/vault/ratelimit.py:87–258](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L87-L258), [heimdall/vault/ratelimit.py:261–439](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L261-L439) | [tests/test_vault_ratelimit.py:23–46](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L23-L46), [tests/test_vault_ratelimit.py:144–168](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L144-L168) | Réussi |
| Fenêtre glissante par **pair réseau** (adresse du socket, jamais `X-Forwarded-For`) | [heimdall/vault/ratelimit.py:196–236](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L196-L236), [heimdall/vault/ratelimit.py:369–413](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L369-L413) | [tests/test_vault_abuse_runtime.py:89–115](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_abuse_runtime.py#L89-L115) | Réussi |
| Dépassement : **429** avec `Retry-After` borné 1..3600, calculé sur la plus ancienne admission | [heimdall/vault/ratelimit.py:76–84](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L76-L84), [heimdall/vault/app.py:1272–1331](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/app.py#L1272-L1331) | [tests/test_vault_ratelimit.py:48–66](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L48-L66), [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Pair/global consommés même quand le budget clé est plein, en une seule transaction | [heimdall/vault/ratelimit.py:238–253](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L238-L253), [heimdall/vault/ratelimit.py:415–433](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L415-L433) | [tests/test_vault_ratelimit.py:68–87](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L68-L87), [tests/test_vault_ratelimit.py:188–207](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L188-L207) | Réussi |
| Backend SQLite partagé entre workers (`rate_limit_hits`, `BEGIN IMMEDIATE`) | [heimdall/vault/ratelimit.py:261–439](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L261-L439), [heimdall/vault/database.py:168–176](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/database.py#L168-L176) | [tests/test_vault_ratelimit.py:144–168](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L144-L168), [tests/test_vault_app.py:1616–1641](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_app.py#L1616-L1641) | Réussi |
| Borne de `rate_limit_hits` sur flot de rejets : purge des expirés à chaque évaluation, rejets compris | [heimdall/vault/ratelimit.py:298–305](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L298-L305), [heimdall/vault/ratelimit.py:337](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L337), [heimdall/vault/database.py:174–175](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/database.py#L174-L175) | [tests/test_vault_ratelimit.py:209–233](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L209-L233), [tests/test_vault_availability.py:179–205](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_availability.py#L179-L205) | Réussi |
| Backend mémoire : aucun bucket vide créé sur rejet, purge des expirés aussi sur rejet | [heimdall/vault/ratelimit.py:122–194](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L122-L194), [heimdall/vault/ratelimit.py:184–186](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L184-L186) | [tests/test_vault_ratelimit.py:102–140](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/tests/test_vault_ratelimit.py#L102-L140) | Réussi |
| Limite mémoire documentée : un cache en mémoire ne suffit pas avec plusieurs processus | [docs/contracts/vault-api.md:314–324](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/docs/contracts/vault-api.md#L314-L324), [heimdall/vault/ratelimit.py:1–25](https://github.com/Cezar277/heimdall/blob/cbe979948ce21bfff6abe1efe59868c0376c0f2f/heimdall/vault/ratelimit.py#L1-L25) | Revue de la fiche (section 2) | Réussi |

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
| Denial of service (force brute de clés) | Budget pair/global avant hachage, budget clé après validation, 429 + `Retry-After` | `heimdall/vault/ratelimit.py:193`, `:211`, `:367`, `:424` ; tests d'abus runtime |
| Contournement par `X-Forwarded-For` | Le pair est `request.client.host` (socket), XFF ignoré | `heimdall/vault/app.py:1214`, test `test_spoofed_forwarded_for_does_not_reset_the_peer_budget` |
| Fuite de clé dans les budgets | Nom de budget = empreinte HMAC, jamais la clé brute | `heimdall/vault/ratelimit.py:193`, `:367` |
| Double budget à la frontière d'une fenêtre fixe | Fenêtre glissante exacte (horodatages), test dédié | `tests/test_vault_ratelimit.py:23`, `:144` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_ratelimit.py -q
# 11 passed
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
