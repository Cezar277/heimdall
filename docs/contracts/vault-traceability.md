# Traçabilité du Vault — tickets, modules, preuves (SAMM)

Ce document répond à la remarque de revue « hygiène : la PR `Closes #63`
embarque #64/#26/#62 et la brique de débit ». Il rend explicite, module par module et preuve par
preuve, à quel ticket appartient chaque brique du Vault, et décrit le découpage
de la suite. La traçabilité n'est plus implicite : chaque ligne ci-dessous est
vérifiable par un fichier de test cité.

## 1. Matrice ticket → module → preuve

| Ticket | Périmètre | Modules / symboles | Preuves (tests) |
|---|---|---|---|
| #25 | Serveur minimal, boucle locale, transport durci, TLS fail-closed en production | `heimdall/vault/app.py` (`VaultSettings`, `run_server`, `BodySizeLimitMiddleware`, `DatabaseAvailabilityMiddleware`, garde loopback) | `tests/test_vault_app.py`, `tests/test_vault_availability.py`, `tests/test_vault_early_rejections.py` |
| #26 | Chiffrement au repos : AES-256-GCM, AAD, sous-clé HKDF, KEK/pepper distincts, confinement crypto | `heimdall/vault/crypto.py` (`VaultCipher`, `hash_api_key`, `generate_api_key`, `kek_matches_pepper`, `constant_time_equal`) | `tests/test_vault_app.py`, `tests/test_crypto_confinement.py` |
| #70 | **DEK par secret et stockage chiffré par enveloppe** (sous-ticket de #26) : DEK aléatoire de 32 octets par secret, valeur chiffrée par la DEK puis DEK chiffrée par la KEK, deux blobs persistés (`encrypted_value`, `encrypted_dek`), aucune valeur ni DEK en clair dans le fichier SQLite, lignes héritées lisibles | `heimdall/vault/crypto.py` (`SecretEnvelope`, `generate_dek`, `VaultCipher.encrypt_envelope`, `VaultCipher.decrypt_envelope`, `VaultCipher.wrap_dek`, `VaultCipher.unwrap_dek`), `heimdall/vault/database.py` (`encrypted_dek`, `_ensure_secret_envelope_column`, `create_secret`, `get_secret`, `update_secret`), `heimdall/vault/store.py` (`_decrypt_record`, `SqliteSecretStore.create`, `InMemorySecretStore.create`) | `tests/test_vault_dek_envelope.py` (18 tests), `docs/t263-samm.md` |
| #71 | **Rotation de la KEK** (sous-ticket de #26, branche `71-t264-rotation-de-la-kek`) : colonne `kek_version` sur les secrets, rotation transactionnelle des DEK sans rechiffrer les valeurs, commande CLI `heimdall vault rotate-kek` (variables d'environnement uniquement, jamais en argv, dérivation Argon2id ou KEK directe), méthodes `rotate_kek()` sur `SqliteSecretStore` et `InMemorySecretStore`, rollback intégral en cas d'échec, zeroization des DEK déchiffrées en mémoire, refus fail-closed des secrets sans enveloppe et de clés identiques | `heimdall/vault/crypto.py` (`VaultCipher.rewrap_dek`, `VaultCipher.has_same_key_as`), `heimdall/vault/database.py` (`kek_version`, `_ensure_secret_kek_version_column`, `reenvelope_secret`, `rotate_secrets_kek`), `heimdall/vault/store.py` (`SqliteSecretStore.rotate_kek`, `InMemorySecretStore.rotate_kek`), `heimdall/cli/vault_keys.py` (`rotate_kek_command`, `_resolve_cli_cipher`) | `tests/test_vault_kek_rotation.py` (84 tests), `docs/t264-samm.md` |
| #72 | **Chasse aux fuites de clés** (sous-ticket de #26, branche `72-t265-chasse-aux-fuites-de-cles`) : vérification des logs, exceptions et `repr()` ; test runtime qui capture les logs DEBUG et grep la clé maîtresse, la KEK, le pepper, les clés API et les valeurs de secrets ; garde statique AST sur les appels de log (args + keywords, alias `logger`/`log`/`logging`/`getLogger`, attributs, objets porteurs, `model_dump()`, `print`/`echo`/`raise`, introspections `locals()`/`globals()`, receveur d'appel, base d'attribut, indices de subscript (littéral et nom), cause de `raise … from …`) | `heimdall/vault/crypto.py` (`VaultCipher.__repr__`), `heimdall/vault/auth.py` (`IssuedApiKey.__repr__`, `ApiKeyRegistry.__repr__`), `heimdall/vault/client.py` (`VaultClient.__repr__`), `heimdall/vault/app.py` (`VaultSettings` champs `repr=False`/`exclude=True`, `hide_input_in_errors=True`, handlers génériques) | `tests/test_vault_key_leak_hunt.py` (8 tests), `docs/t265-samm.md` |
| #67 | **AES-256-GCM avec nonce unique** (sous-ticket de #66 « Module crypto isolé », branche `67-t2611-aes-256-gcm-avec-nonce-unique`) : nonce de 96 bits tiré de `os.urandom` **à chaque** chiffrement (jamais un compteur, jamais l'heure), blob stocké = nonce + ciphertext + tag, AAD = identifiant du secret (triplet `project/env/name`) : un blob copié sur un autre secret échoue au déchiffrement | `heimdall/vault/crypto.py` (`_new_nonce`, `VaultCipher.encrypt`, `VaultCipher.decrypt`, `VaultCipher.aad`) | `tests/test_vault_crypto.py` (15 tests), `docs/t67-samm.md` |
| #62 | Persistance SQLite : schéma, `UNIQUE`, `foreign_keys=ON`, quota atomique, registre des clés | `heimdall/vault/database.py`, `heimdall/vault/store.py` (`SqliteSecretStore`, `InMemorySecretStore`) | `tests/test_vault_db.py`, `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py` |
| #64 | Authentification par clé de projet : HMAC-SHA256 + pepper, temps constant, révocation, politique opérateur | `heimdall/vault/auth.py` (`generate_project_api_key`, `hash_project_api_key`, `validate_raw_api_key`, `validate_project_id`, `verify_api_key`, `require_project_access`, `ApiKeyRegistry`, `IssuedApiKey`), `heimdall/cli/vault_keys.py` (`heimdall vault key create/list/revoke`) | `tests/test_vault_auth.py`, `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py`, `tests/security/test_vault_replay_bruteforce.py` |
| #63 | Routes `POST /api/v1/secrets` et `GET /api/v1/secrets/{project}/{env}/{name}` : validation stricte, 1 Mio, `no-store`, 201 sans `value` | `heimdall/vault/app.py` (`SecretCreate`, `SecretMetadata`, `SecretRead`, `_register_routes`), `openapi.yaml` | `tests/test_vault_app.py`, `tests/contracts/test_vault_openapi.py` |
| #65 | **Tests d'intégration `TestClient`** (sous-ticket 5 de #25, branche `65-t255-tests-dintégration-testclient`) : cas nominal, 401 clé invalide, 403 projet étranger, conformité OpenAPI (corps + schéma publié), refus de transport, 429 + `Retry-After`, abus d'entrée, base temporaire par test. **Corrige au passage** le drift `required` du schéma publié | `tests/test_vault_integration_testclient.py`, `heimdall/vault/app.py` (modèles d'erreur et `HealthResponse` : champs sans valeur par défaut → `required` conforme au contrat) | `tests/test_vault_integration_testclient.py` (30 tests), `docs/t255-samm.md` |
| #63 (lot d'intégration) | Limitation de débit : buckets clé/pair/global, `Retry-After` borné, backend partagé SQLite — brique **sans issue GitHub propre**, livrée dans le lot d'intégration #63 | `heimdall/vault/ratelimit.py` (`RateLimiter`, `SqliteRateLimiter`), middleware de débit de `app.py` | `tests/test_vault_app.py`, `tests/test_vault_review_regressions.py` |
| #68 | **Tests de falsification AES-256-GCM** (sous-ticket de #66 « Module crypto isolé », branche `68-t2612-tests-de-falsification`) : un octet modifié du blob (nonce, ciphertext ou étiquette), une mauvaise clé ou un mauvais AAD lèvent `VaultCipherError` ; aucune valeur fausse n'est renvoyée (fail-closed). **Aucun changement de code de production** | `heimdall/vault/crypto.py` (`VaultCipher.encrypt`, `VaultCipher.decrypt`, `VaultCipher.aad`, `VaultCipherError`) | `tests/test_vault_falsification.py` (4 tests, 62 sous-cas), `docs/t68-samm.md` |
| #262 | **KEK dérivée avec Argon2id** (sous-ticket de #26, branche `69-t262-kek-dérivée-avec-argon2id`) : dérivation 256 bits depuis la clé maîtresse avec `argon2.low_level.hash_secret_raw` en `Type.ID`, sel public de 16 octets persisté à côté, paramètres OWASP 64 Mio / 3 / 4 documentés en ADR-005, dérivation **une seule fois au démarrage**, KEK gardée en mémoire, effacement best-effort du tampon normalisé (aucune mutation d'`bytes`), contrôle de la KEK réelle du store explicite, décodage du pepper sous les deux alphabets base64 puis en hexadécimal (invariant 5), garde fail-closed `getattr` sur le chiffreur du store explicite et exclusion structurelle des secrets (dont le sel) à la sérialisation des settings (`Field(exclude=True)`, vérifiée de bout en bout sur `app.state.settings`). Mode historique `HEIMDALL_VAULT_KEK` conservé (exclusif) | `heimdall/vault/crypto.py` (`ARGON2ID_*`, `derive_kek_from_master_key`, `_zeroize_buffer`, `kek_matches_pepper`, `VaultCipher.key_reuses_pepper`, `generate_kek_salt`, `decode_kek_salt`, `VaultCipher.from_master_key`), `heimdall/vault/app.py` (`VaultSettings.master_key` (`Field(exclude=True)`), `VaultSettings.kek`, `VaultSettings.api_key_pepper`, `VaultSettings.kek_salt`, `_resolve_vault_cipher`, `_validate_explicit_secret_store_configuration`) | `tests/test_vault_kek_derivation.py` (48 tests), `docs/t262-samm.md`, `docs/adr/005-derivation-kek-argon2id.md` |
| #115 | **Table d'états et transitions** (sous-ticket 1 de #40 « États du secret dans le Vault », branche `115-t401-table-détats-et-transitions`) : formalisation du cycle de vie du secret (détecté > confirmé > vaulté > roté), matrice 5x5 complète autorisée/interdite (5 autorisées, 20 interdites avec justifications fermées), décision d'architecture sur l'état faux positif (écarté) lié à #33, terminalité de `rote`, normalisation des alias (`ecarte`), cohérence absolue avec #14 | `heimdall/vault/transitions.py` (`SecretLifecycleState`, `LIFECYCLE_STATES`, `ALLOWED_TRANSITIONS`, `FORBIDDEN_TRANSITION_REASONS`, `validate_transition`, `is_transition_allowed`, `canonicalize_state`, `get_transition_matrix`), `docs/adr/006-table-etats-et-transitions.md` | `tests/test_vault_transitions.py` (21 tests, 71 sous-cas), `docs/t115-samm.md` |

> **Numérotation** : `#65` est l'issue GitHub **« Tests d'intégration TestClient »**
> (sous-ticket 5 de `#25 « Vault minimal »`, branche
> `65-t255-tests-dintégration-testclient`) : c'est elle que la PR ferme
> (`Closes #65`), et la matrice ne contient qu'**un seul** `#65` normatif.
> La limitation de débit n'a **pas** d'issue GitHub propre : elle a été livrée
> dans le lot d'intégration du ticket #63 et est donc étiquetée
> « #63 (lot d'intégration) ». L'ancien libellé « #65 » employé dans le code
> pour le débit désignait le slot 5 de #25 — devenu l'issue #65 des tests
> d'intégration — d'où la collision signalée par la revue : il a été remplacé
> partout (code, docs, README) pour qu'aucune ligne ne prête à confusion à
> l'audit SAMM/pentest.

Le contrat normatif des routes reste `openapi.yaml` (ticket #15) ; sa lecture
documentaire est `docs/contracts/vault-api.md`.

## 2. Découpage de la suite (recommandation de la revue)

La branche `63-t253-routes-post-et-get-secret` est un **lot d'intégration** : les
briques #26/#62/#64 et la brique de débit y sont matérialisées parce que les
routes #63 en dépendent (elles les exercent). Pour lever la remarque d'hygiène, la suite
recommandée est une pile de branches, chaque brique restant dans son ticket :

> **État d'avancement** : la brique #64 est portée par sa propre branche
> (`64-t254-authentification-par-clé-api-de-projet`), désormais basée sur `main`
> après la fusion de #63 (PR #151) et relue en diff autonome contre `main`. La
> brique y est **isolée dans le module `heimdall/vault/auth.py`** (registre,
> dépendance FastAPI, politique opérateur) avec sa suite de tests
> `tests/test_vault_auth.py` ; `app.py` ne fait plus que déléguer. Les branches
> #26/#62 et la brique de débit restent à extraire de la même façon.

```bash
# Ordre de dépendance (du socle vers les routes)
git branch 26-vault-chiffrement      # crypto.py        (#26)
git branch 62-vault-stockage-sqlite  # database/store   (#62)
git branch 64-vault-auth-cles-projet # auth + registre  (#64)  <- fait
git branch 63-lot-rate-limit        # ratelimit.py     (lot #63)
git branch 63-routes-secrets         # app.py (routes)  (#63)  <- fusionnée dans main
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
