# T234 — Durcissements Vault (audit M-02, M-03, M-07, M-11, M-13, F-03, F-05, F-06, F-15, F-16)

Branche : `fix/234-vault-audit-ratelimit-kek-hardening`.
Périmètre : rate-limiting local, journal d'audit, rotation KEK, clé maîtresse,
`HEIMDALL_ENV`, effacement à l'état `rote`, PRAGMA SQLite, transport uvicorn.

## Propriétés démontrées

| Finding | Code et test |
| --- | --- |
| **M-02** — un flot anonyme ne bloque plus les clients authentifiés | `ratelimit.py` sépare `anon_peer`/`anon_global` des budgets authentifiés `key`/`global` ; `app.py` ne fait le `peek` anonyme que sans clé et contrôle le global authentifié avant hachage. Tests : `test_vault_ratelimit.py::test_anonymous_flood_does_not_block_authenticated_requests`, `test_vault_review_regressions.py::test_global_rejection_precedes_hash_and_lookup`. |
| **M-03 / F-16** — les rejets ne peuvent pas purger les accès, chaîne HMAC | `audit.py` sépare les flux `access` et `rejection` (rétentions distinctes, deux points de contrôle) et signe chaque entrée avec une sous-clé HMAC dédiée (`audit_hmac_key`). Tests : `test_vault_audit.py::test_rejection_flood_does_not_prune_authenticated_events`, `::test_sqlite_rejection_flood_does_not_prune_authenticated_events`, `::test_sqlite_chain_is_hmac_keyed`. |
| **M-07 / F-04** — rotation KEK avec HMAC, erreurs distinctes, à chaud, auditée | `vault_keys.py` charge `HEIMDALL_VAULT_SERVER_HMAC_KEY`, distingue `KekHmacContinuityError`, refuse un serveur qui écoute (`--force` explicite), journalise `VAULT KEK ROTATE`, et documente que les DEK ne sont pas renouvelées. Tests : `test_vault_kek_rotation.py::VaultRotateCliTests::test_cli_rotate_with_server_hmac_key_keeps_canary`, `::test_cli_rotate_without_server_hmac_key_distinguishes_canary_error`, `::test_cli_rotate_refuses_hot_server_without_force`, `::test_cli_rotate_writes_an_audit_event`. |
| **M-11** — clé maîtresse complexe | `crypto.py` exige 32 octets, 8 symboles distincts, aucune période répétitive et une entropie minimale ; `generate_master_key()` fournit la voie sûre. Tests : `test_vault_kek_derivation.py::test_minimum_master_key_length_is_256_bits`, `::test_invalid_master_key_is_rejected`. |
| **M-13** — production par défaut, valeurs inconnues refusées | `auth.py` retourne `production` si `HEIMDALL_ENV` est absent et refuse toute valeur hors `production/prod/dev/test`. Tests : `test_vault_auth.py::test_heimdall_env_defaults_to_production_and_rejects_unknown`, `test_vault_app.py` (pepper/docs/auth en production). |
| **F-03** — valeur et DEK effacées à `rote` | `store.py` et `database.py` vident `encrypted_value` et `encrypted_dek` lors de la transition vers `rote` ; un retour manuel à `vaulte` ne restitue pas l'ancienne valeur via l'API. Ce n'est pas un effacement forensique : l'ancienne valeur peut subsister dans le WAL/journal ou des pages non réécrites jusqu'à un `VACUUM` hors ligne et une rotation des DEK. Tests : `test_vault_transitions_api.py::test_rote_clears_encrypted_value_and_dek`, `::test_rote_value_cannot_be_resurrected_by_a_status_flip`. |
| **F-05** — `secure_delete` | `database.py` exécute `PRAGMA secure_delete = ON` sur chaque connexion (écrase les pages libérées, sans garantie forensique sur le WAL). Test : `test_vault_db.py::test_secure_delete_is_enabled_by_default`. |
| **F-06** — Host et limites uvicorn | `app.py` ajoute `TrustedHostMiddleware` (loopback, `testserver` en mode test) et borne `limit_concurrency`/`timeout_keep_alive`. Tests : `test_vault_app.py::test_run_server_passes_hardened_uvicorn_arguments`, `::test_run_server_passes_tls_files_in_production`. |
| **F-15** — recul d'horloge | `ratelimit.py` borne un horodatage futur à `now` avant de calculer `Retry-After`. Test : `test_vault_ratelimit.py::SlidingWindowSqliteTests::test_sqlite_clock_rollback_bounds_retry_after`. |

## Invariants conservés

- Aucun secret, clé API complète, corps de requête ou valeur de secret dans
  les traces, logs, `repr` ou JSON.
- Fail-closed : une erreur d'audit, de rotation ou de vérification ne produit
  jamais un verdict propre.
- Les changements de schéma SQLite sont additifs et migrent les bases
  existantes (`audit_events.stream`, `audit_rejection_chain_state`).
- Les tests de non-régression Vault, audit, TLS, transitions et rotation
  passent localement ; la suite complète conserve uniquement l'échec
  pré-existant `test_env_path_with_spaces_properly_quoted_in_git_rm_command`.

## Corrections de revue

| Point | Preuve |
| --- | --- |
| **F-16** — continuité d'audit à la rotation KEK | `vault rotate-kek` refuse (code 2) sans `HEIMDALL_VAULT_AUDIT_HMAC_KEY` explicite, commune avant et après la rotation. Tests : `test_vault_kek_rotation.py::test_cli_rotate_refuses_without_explicit_audit_key`, `::test_cli_rotate_keeps_audit_chain_verifiable_with_new_kek`. |
| **F-16** — pas de repli SHA-256 silencieux | `vault audit list/verify` sortent en code 2 « clé HMAC d'audit indisponible » sans clé résolvable. Test : `test_vault_audit.py::test_verify_without_resolvable_key_exits_2_explicitly`. |
| **M-02** — budget par pair authentifié | `check_authenticated` consomme `key`, `auth_peer:<ip>` (distinct de `anon_peer`) et `global`. Test : `test_vault_ratelimit.py::test_distinct_keys_from_one_peer_share_the_peer_budget`. |
| **F-15** — recul d'horloge, deux backends | Admissions futures ignorées du comptage, `Retry-After` borné à la fenêtre. Test : `test_vault_ratelimit.py::test_clock_rollback_ignores_future_hits_and_bounds_retry`. |
| Garde anti-rotation à chaud | Sonde TCP best-effort sur `HEIMDALL_VAULT_PORT`, pas un verrou : préférer un arrêt supervisé. |
| **F-16** — bases pré-F-16 (SHA-256 nu) | Pas de migration automatique des hachages. `vault audit verify` détecte une chaîne SHA-256 historique valide et répond « migration requise » (code 1 : archiver la base puis réinitialiser le journal), distinct de « chaîne invalide » ; une chaîne historique altérée reste « invalide ». Tests : `test_vault_audit.py::LegacyAuditChainTests`. |
| **F-16** — variable d'audit vide | `HEIMDALL_VAULT_AUDIT_HMAC_KEY=""` → code 2 explicite, jamais de repli dérivé. Test : `test_vault_audit.py::test_empty_audit_key_env_is_explicit_error_not_derived_fallback`. |
| Moindre privilège store | Les stores exposent `audit_hmac_key()`, plus le chiffreur porteur de la KEK. Test : `test_vault_audit.py::StoreLeastPrivilegeTests`. |
| **F-16** — historique non vérifiable avec la clé fournie | Avant toute écriture, `vault rotate-kek` vérifie le journal existant avec `HEIMDALL_VAULT_AUDIT_HMAC_KEY` et refuse (code 2) si la chaîne n'est pas valide (serveur en clé dérivée, journal pré-F-16 ou pré-M-03). Test : `test_vault_kek_rotation.py::test_cli_rotate_refuses_when_history_uses_another_audit_key`. |
| **F-16** — pas de défaut SHA-256 | `hmac_key` est obligatoire pour `InMemoryAuditLog` et `SqliteAuditLog` : `None` (SHA-256 historique) n'est plus qu'un choix explicite. |
| **M-03** — base sans colonne `stream` | `vault audit list/verify` répondent « migration requise » (code 1) au lieu d'un échec générique. Test : `test_vault_audit.py::PreM03SchemaTests`. |
| **M-02** — rejet précoce `auth_peer` | `peek_authenticated(peer)` contrôle `auth_peer` + global avant le hachage et le parcours d'empreintes. Test : `test_vault_review_regressions.py::test_auth_peer_rejection_precedes_hash_and_lookup`. |
