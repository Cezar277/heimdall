# Traçabilité du Vault — tickets, modules, preuves (SAMM)

Ce document répond à la remarque de revue « hygiène : la PR `Closes #63`
embarque #64/#65/#26/#62 ». Il rend explicite, module par module et preuve par
preuve, à quel ticket appartient chaque brique du Vault, et décrit le découpage
de la suite. La traçabilité n'est plus implicite : chaque ligne ci-dessous est
vérifiable par un fichier de test cité.

## 1. Matrice ticket → module → preuve

| Ticket | Périmètre | Modules / symboles | Preuves (tests) |
|---|---|---|---|
| #25 | Serveur minimal, boucle locale, transport durci, TLS fail-closed en production | `heimdall/vault/app.py` (`VaultSettings`, `run_server`, `BodySizeLimitMiddleware`, `DatabaseAvailabilityMiddleware`, garde loopback) | `tests/test_vault_app.py`, `tests/test_vault_availability.py`, `tests/test_vault_early_rejections.py` |
| #26 | Chiffrement au repos : AES-256-GCM, AAD, sous-clé HKDF, KEK/pepper distincts, confinement crypto | `heimdall/vault/crypto.py` (`VaultCipher`, `hash_api_key`, `generate_api_key`, `kek_matches_pepper`, `constant_time_equal`) | `tests/test_vault_app.py`, `tests/test_crypto_confinement.py` |
| #62 | Persistance SQLite : schéma, `UNIQUE`, `foreign_keys=ON`, quota atomique, registre des clés | `heimdall/vault/database.py`, `heimdall/vault/store.py` (`SqliteSecretStore`, `InMemorySecretStore`) | `tests/test_vault_db.py`, `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py` |
| #64 | Authentification par clé de projet : HMAC-SHA256 + pepper, temps constant, révocation, politique opérateur | `heimdall/vault/auth.py` (`generate_project_api_key`, `hash_project_api_key`, `validate_raw_api_key`, `validate_project_id`, `verify_api_key`, `require_project_access`, `ApiKeyRegistry`, `IssuedApiKey`), `heimdall/cli/vault_keys.py` (`heimdall vault key create/list/revoke`) | `tests/test_vault_auth.py`, `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py`, `tests/security/test_vault_replay_bruteforce.py` |
| #65 | Limitation de débit : buckets clé/pair/global, `Retry-After` borné, backend partagé SQLite | `heimdall/vault/ratelimit.py` (`RateLimiter`, `SqliteRateLimiter`), middleware de débit de `app.py` | `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py` |
| #63 | Routes `POST /api/v1/secrets` et `GET /api/v1/secrets/{project}/{env}/{name}` : validation stricte, 1 Mio, `no-store`, 201 sans `value` | `heimdall/vault/app.py` (`SecretCreate`, `SecretMetadata`, `SecretRead`, `_register_routes`), `openapi.yaml` | `tests/test_vault_app.py`, `tests/contracts/test_vault_openapi.py` |

Le contrat normatif des routes reste `openapi.yaml` (ticket #15) ; sa lecture
documentaire est `docs/contracts/vault-api.md`.

## 2. Découpage de la suite (recommandation de la revue)

La branche `63-t253-routes-post-et-get-secret` est un **lot d'intégration** : les
briques #26/#62/#64/#65 y sont matérialisées parce que les routes #63 en
dépendent (elles les exercent). Pour lever la remarque d'hygiène, la suite
recommandée est une pile de branches, chaque brique restant dans son ticket :

> **État d'avancement** : la brique #64 est désormais portée par sa propre
> branche (`64-t254-authentification-par-clé-api-de-projet`), empilée sur la
> branche #63 et relue en diff contre elle. La brique y est **isolée dans le
> module `heimdall/vault/auth.py`** (registre, dépendance FastAPI, politique
> opérateur) avec sa suite de tests `tests/test_vault_auth.py` ; `app.py` ne
> fait plus que déléguer. Les branches #26/#62/#65 restent à extraire de la
> même façon.

```bash
# Ordre de dépendance (du socle vers les routes)
git branch 26-vault-chiffrement      # crypto.py        (#26)
git branch 62-vault-stockage-sqlite  # database/store   (#62)
git branch 64-vault-auth-cles-projet # auth + registre  (#64)  <- fait
git branch 65-vault-rate-limit       # ratelimit.py     (#65)
git branch 63-routes-secrets         # app.py (routes)  (#63)  <- pile au-dessus
```

Chaque branche doit être revue contre son seul ticket, puis fusionnée dans
l'ordre. La pile est réversible : le code est déjà isolé par module (voir §1),
donc le découpage est mécanique et sans réécriture fonctionnelle. Ces branches
sont créées par l'opérateur (le robot de revue n'a pas accès à l'API GitHub
pour ouvrir ou rebaser des PR) ; la matrice ci-dessus permet de le faire sans
relire le diff.

En attendant ce découpage, chaque brique est tracée ici et son ticket reste
ouvert : rien n'est « clos » par erreur au titre de #63.

## 3. Points de vigilance clos dans cette branche

| Remarque de revue | Traitement | Preuve |
|---|---|---|
| Contournement du backend mémoire en production (store explicite) | `ValueError` fail-closed, backend aligné sur le store réel | `tests/test_vault_app.py::test_explicit_in_memory_store_forbidden_in_production` |
| Rate-limit mono-processus × workers | `SqliteRateLimiter` partagé (`BEGIN IMMEDIATE`), backend mémoire réservé au dev/test | `tests/test_vault_app.py::test_sqlite_rate_limiter_is_shared_between_workers` |
| Quota SQLite best-effort inter-workers | quota et insertion dans une seule transaction `BEGIN IMMEDIATE` | `tests/test_vault_app.py::test_sqlite_quota_is_atomic_inter_workers` |
| TLS absent | `ssl_certfile`/`ssl_keyfile` validés, `run_server` refuse de démarrer en production sans TLS | `tests/test_vault_app.py::test_run_server_requires_tls_in_production` |
| TLS « non pentesté hors boucle locale » | serveur uvicorn TLS réel : SAN IP `127.0.0.1` vérifié côté pair, client de confiance OK, client sans confiance rejeté, pas de downgrade en clair | `tests/test_vault_tls.py` (5 tests) |
| Seuil de diversité opérateur trivial | alphabet base64url (`fullmatch`) + 43 caractères + 16 distincts + aucune période répétitive + aucune suite monotone de 8+ + aucune ligne de clavier connue | `tests/test_vault_app.py::test_register_api_key_rejects_trivial_patterns`, `tests/test_vault_app.py::test_api_key_alphabet_uses_fullmatch_not_dollar` |
| `SecretValue` multiligne : `\x00` seul ou NFC | décision tranchée : NFC **et** refus du NUL, valeur jamais journalisée | `tests/test_vault_app.py::test_secret_value_is_nfc_normalized_and_nul_rejected` |
| `api_keys_lock` tenu pendant l'I/O DB | verrou de persistance distinct du verrou de snapshot : le chemin de lecture ne bloque plus | `tests/test_vault_review_regressions.py::test_registration_db_io_does_not_block_read_path` |
| 429 de capacité permanent | sémantique documentée et pinnée : retry inutile tant que la capacité est pleine (route DELETE suivie en #62) | `tests/test_vault_app.py::test_capacity_429_retry_is_useless_until_capacity_freed` |
| Quota inter-processus (suggestion de revue) | deux workers sur le même fichier, `max_secrets=2` : jamais de dépassement | `tests/test_vault_app.py::test_sqlite_quota_never_exceeded_with_two_workers` |
