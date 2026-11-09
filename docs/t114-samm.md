# T114 — preuves pour la ligne SAMM (tests d'abus et de rejeu)

Périmètre : sous-ticket **#114** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea`
(`fix(vault): audite le projet demande sur list 401 sans refleter la query (#39)`).

Ce sous-ticket ne modifie pas le code de production : il attaque le Vault
existant (force brute, rejeu, charge) et archive les preuves. Les défenses
testées sont celles de #111/#112/#113.

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation / défense testée | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Force brute de clés API : 429 attendus | [heimdall/vault/ratelimit.py:196–253](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/ratelimit.py#L196-L253), [heimdall/vault/app.py:1272–1331](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/app.py#L1272-L1331) | [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Rejeu d'un POST capturé : rejet sans écrasement | [heimdall/vault/database.py:159–162](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/database.py#L159-L162), [heimdall/vault/store.py:431–484](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/store.py#L431-L484) | [tests/test_vault_abuse_runtime.py:118–152](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L118-L152) | Réussi |
| Rejeu après révocation : 401 générique | [heimdall/vault/auth.py:830–923](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/auth.py#L830-L923) | [tests/test_vault_abuse_runtime.py:154–184](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L154-L184) | Réussi |
| Charge simple : quelques centaines de requêtes sans plantage | [heimdall/vault/app.py:1694–1832](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/app.py#L1694-L1832), [heimdall/vault/audit.py:382–614](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/audit.py#L382-L614) | [tests/test_vault_abuse_runtime.py:186–208](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L186-L208), [tests/test_vault_abuse_runtime.py:210–229](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L210-L229) | Réussi |
| `X-Forwarded-For` falsifié : pas de remise à zéro du budget pair | [heimdall/vault/app.py:1272–1296](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/heimdall/vault/app.py#L1272-L1296) | [tests/test_vault_abuse_runtime.py:89–115](https://github.com/Cezar277/heimdall/blob/0c5458917c2f776bf2b6bfb82aadfe3dc992d3ea/tests/test_vault_abuse_runtime.py#L89-L115) | Réussi |
| Tous les tests d'abus passent | — | `python -m pytest tests/test_vault_abuse_runtime.py -q` → 6 passed | Réussi |

## 2. Sémantique de rejeu définie

Le contrat v1 n'ajoute ni nonce ni date de validité. La sémantique retenue et
testée est donc :

- **POST rejoué** : 409 `conflict`, la valeur d'origine reste inchangée
  (aucun écrasement, aucune écriture partielle) ;
- **GET rejoué** : idempotent, même valeur (ou 404) tant que la clé est
  valide ;
- **rejeu après révocation** : 401 générique, la révocation est l'autorité ;
- **force brute** : 401 puis 429 avec `Retry-After` borné ;
- **charge** : 300 requêtes mémoire et 50 requêtes SQLite, aucun 500, chaîne
  d'audit toujours valide.

## 3. STRIDE et abuse cases

| Abuse case | Réponse attendue | Preuve |
|---|---|---|
| Force brute de clés API | 429 après le budget pair/global, `Retry-After` 1..3600 | `test_bruteforce_is_bounded_by_peer_budget` |
| Rejeu d'une création | 409, aucune modification | `test_replayed_post_is_rejected_without_overwrite` |
| Rejeu après révocation | 401 générique | `test_replayed_request_after_revocation_is_rejected` |
| Usurpation de `X-Forwarded-For` | Budget pair inchangé | `test_spoofed_forwarded_for_does_not_reset_the_peer_budget` |
| Déni de service par rafale | Pas de 500, serveur sain, journal cohérent | `test_three_hundred_requests_do_not_crash_the_memory_backend`, `test_fifty_requests_do_not_crash_the_sqlite_backend` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
python -m pytest tests/security/test_vault_replay_bruteforce.py -q
# 2 passed (contrat statique + assertions #111/#113/#114)
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
