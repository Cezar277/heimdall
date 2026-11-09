# T111 — preuves pour la ligne SAMM (rate-limiting par clé et par IP)

Périmètre : sous-ticket **#111** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`. Cette fiche fournit les couples module + ligne et
les permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `ea8acece62245c77f2a9afb2618202fc505a7032`
(`feat(vault): durcit auth, rate-limiting et journal d'audit (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Fenêtre **glissante** par clé API validée | [heimdall/vault/ratelimit.py:84–235](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L84-L235), [heimdall/vault/ratelimit.py:238–420](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L238-L420) | [tests/test_vault_ratelimit.py:20–42](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L20-L42), [tests/test_vault_ratelimit.py:101–124](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L101-L124) | Réussi |
| Fenêtre glissante par **pair réseau** (adresse du socket, jamais `X-Forwarded-For`) | [heimdall/vault/ratelimit.py:173–213](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L173-L213), [heimdall/vault/ratelimit.py:356–400](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L356-L400) | [tests/security/test_vault_abuse_runtime.py:89–115](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/security/test_vault_abuse_runtime.py#L89-L115) | Réussi |
| Dépassement : **429** avec `Retry-After` borné 1..3600, calculé sur la plus ancienne admission | [heimdall/vault/ratelimit.py:73–81](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L73-L81), [heimdall/vault/app.py:1214–1272](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/app.py#L1214-L1272) | [tests/test_vault_ratelimit.py:45–63](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L45-L63), [tests/security/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/security/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Pair/global consommés même quand le budget clé est plein, en une seule transaction | [heimdall/vault/ratelimit.py:215–235](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L215-L235), [heimdall/vault/ratelimit.py:402–420](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L402-L420) | [tests/test_vault_ratelimit.py:65–83](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L65-L83), [tests/test_vault_ratelimit.py:145–163](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L145-L163) | Réussi |
| Backend SQLite partagé entre workers (`rate_limit_hits`, `BEGIN IMMEDIATE`) | [heimdall/vault/ratelimit.py:238–420](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L238-L420), [heimdall/vault/database.py:126–132](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/database.py#L126-L132) | [tests/test_vault_ratelimit.py:101–124](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_ratelimit.py#L101-L124), [tests/test_vault_app.py:1616–1641](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_app.py#L1616-L1641) | Réussi |
| Limite mémoire documentée : un cache en mémoire ne suffit pas avec plusieurs processus | [docs/contracts/vault-api.md:274–284](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/docs/contracts/vault-api.md#L274-L284), [heimdall/vault/ratelimit.py:1–25](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/ratelimit.py#L1-L25) | Revue de la fiche (section 2) | Réussi |

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
python -m pytest tests/security/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
