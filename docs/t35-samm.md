# T35 — Client Vault CLI push/pull/run (tickets #98–#102)

Périmètre : ticket parent #35 « Client Vault CLI push/pull/run », découpé en
sous-tickets #98 (client HTTP + configuration), #99 (`vault push`),
#100 (`vault pull`), #101 (`run -- <cmd>`), #102 (tests d'intégration
client/serveur). Cette fiche assure la traçabilité par sous-ticket exigée
par la revue « 1 PR = 1 sous-ticket » et archive la justification du
regroupement (voir §4).

## 1. Matrice ticket → module → preuve

| Ticket | Périmètre | Modules / symboles | Preuves (tests) |
|---|---|---|---|
| #98 | Client HTTP boucle locale, TLS vérifié, clé jamais en argv, `0600` + `O_NOFOLLOW` | `heimdall/vault/client.py` (`VaultClient`, `resolve_api_key`, `_validate_loopback_url`, `_read_and_check_key_file`) | `tests/test_vault_client.py`, `tests/test_vault_tls.py`, `tests/security/test_vault_replay_bruteforce.py` |
| #99 | `heimdall vault push` : `.env` → Vault, refus `\n`/`\r`/`\x00`, quoting symétrique | `heimdall/cli/vault_client.py` (`push`, `format_env_value`, `_init_client`) | `tests/test_vault_cli.py`, `tests/test_vault_integration_client_server.py::test_cli_end_to_end_push_pull_and_run` |
| #100 | `heimdall vault pull` : Vault → `.env` atomique `0600`, anti-symlink, `fsync` | `heimdall/vault/atomic.py` (`write_file_atomic`, `_open_parent_dir_secure`, `backup_file`), `heimdall/cli/vault_client.py` (`pull`) | `tests/test_vault_client.py::VaultAtomicOperationsTests`, `tests/test_vault_integration_client_server.py` |
| #101 | `heimdall run -- <cmd>` (canonique) + alias `heimdall vault run` : injection mémoire seule, allowlist locale + denylist, sans `shell=True` (voir §5) | `heimdall/cli/vault_client.py` (`vault_run`, allowlist + `shutil.which`, `RUN_CONTEXT_SETTINGS`), `heimdall/cli/main.py` (`run`), `heimdall/cli/vault_keys.py` (`vault run`) | `tests/test_vault_cli.py::test_run_and_vault_run_share_callback_and_guards`, `tests/security/test_path_traversal.py` |
| #102 | Intégration push→pull→run bout en bout (SQLite temporaire, ASGI) | `tests/test_vault_integration_client_server.py` (`SyncASGITransport`, fixture `vault_test_server`) | `tests/test_vault_integration_client_server.py` (7 scénarios) |

## 2. Correctifs LOW de la revue « APPROVE WITH COMMENTS »

| Remarque | Correctif | Preuve |
|---|---|---|
| Parents intermédiaires suivis par `mkdir(parents=True)` : échange `out/sub` → symlink non détecté (`fstat` vs `stat` coïncident) | Marcheur sécurisé `_open_parent_dir_secure` : création + ouverture composant par composant depuis `/` avec `openat`/`mkdirat` + `O_NOFOLLOW`/`O_DIRECTORY` (`ELOOP`/`ENOTDIR` → refus), `0o700` pour les créations, `fstat` vs `stat` final conservé en défense en profondeur ; plus aucun `mkdir(parents=True)` suivi sur POSIX | `heimdall/vault/atomic.py` (`_open_parent_dir_secure`, `write_file_atomic`) + `tests/test_vault_client.py::test_write_file_atomic_refuses_symlinked_intermediate_with_missing_leaf`, `::test_write_file_atomic_refuses_concurrent_intermediate_swap`, `::test_write_file_atomic_rejects_intermediate_parent_symlink_swap`, `::test_write_file_atomic_resists_parent_directory_swap` |
| Garde `transport` contournable par `PYTEST_CURRENT_TEST=1` | Suppression du paramètre en prod : `VaultClient.__init__` n'expose plus `transport` (fail-closed `TypeError` si renseigné) ; fabrique test-only `VaultClient.create_for_tests(..., transport=...)` seule autorisée ; docstring prod/test séparée ; aucun appelant prod ne renseigne `transport` (vérifié par test) | `heimdall/vault/client.py` (`__init__`, `create_for_tests`) + `tests/test_vault_client.py::test_transport_parameter_rejected_outside_test_environment`, `::test_create_for_tests_accepts_transport_hook`, `::test_prod_constructor_exposes_no_transport_hook` ; `tests/test_vault_integration_client_server.py` migré vers `create_for_tests` |
| Hygiène : 1 PR = 6 tickets (`Closes #35,#98-#102`) | Justification explicite ci-dessous (§4) + traçabilité par ticket (§1) ; revert ciblé possible par module ; ne pas reproduire | Cette fiche + description PR |
| Double exposition `run` hors ticket (`main.py` + `vault_keys.py`) | `heimdall run` canonique (#101), `heimdall vault run` alias documenté (§5) ; même callback `vault_run`, réglages uniques `RUN_CONTEXT_SETTINGS` anti-divergence | `heimdall/cli/vault_client.py` (`RUN_CONTEXT_SETTINGS`), `heimdall/cli/main.py`, `heimdall/cli/vault_keys.py` + `tests/test_vault_cli.py::test_run_and_vault_run_share_callback_and_guards` |
| Shadowing `HEIMDALL_*` dans `run` : Vault compromis écrase la credential du fils via `{**os.environ, **injected}` | Préfixe `"HEIMDALL_"` ajouté à `_DANGEROUS_ENV_PREFIXES` → `run --name HEIMDALL_API_KEY` refusé `Exit(1)` | `heimdall/cli/vault_client.py` (`_DANGEROUS_ENV_PREFIXES`) + `tests/test_vault_cli.py::test_run_rejects_heimdall_credential_shadowing` |
| `localhost` vérifié à la construction puis résolu à nouveau à la connexion (rebinding DNS local) | Pas de changement de transport (risqué) : défaut `127.0.0.1` conservé (aucune résolution), `localhost` accepté par compatibilité avec risque documenté en docstring | `heimdall/vault/client.py` (`_check_localhost_resolution`) : défaut `127.0.0.1` recommandé, fenêtre documentée |
| Lectures sans marcheur intermédiaire (`read_file_secure_no_follow`, `_read_and_check_key_file`, `backup_file` : `O_NOFOLLOW` final seul) | Nouveau `_open_file_read_fd` : parent par `_open_parent_dir_secure` (`create_missing=False`, aucune création) + `openat` `O_NOFOLLOW`/`O_NONBLOCK` ; `backup_file` et clé API migrés, `parse_*` couverts via le lecteur | `heimdall/vault/atomic.py` (`_open_file_read_fd`), `heimdall/vault/client.py` (`_read_and_check_key_file`) + `tests/test_vault_client.py::test_read_file_secure_no_follow_refuses_symlinked_intermediate`, `::test_key_file_reader_refuses_symlinked_intermediate` |
| Denylist `run` incomplète par nature (`CDPATH`/`GLOBIGNORE`/`HISTFILE`/`MAILCAPS` autorisés) | Ajout des 4 à `_DANGEROUS_ENV_EXACT` + documentation : tout nom listé localement est une entrée de confiance, la denylist reste une défense en profondeur | `heimdall/cli/vault_client.py` (`_DANGEROUS_ENV_EXACT`, docstring `vault_run`) + `tests/test_vault_cli.py::test_run_rejects_dangerous_env_vars` (4 cas ajoutés) |
| `pull`/`run` partiels sur 404 : succès affiché avec un sous-ensemble (exit 0 trompeur) | Échec franc : `VaultNotFoundError` → `Exit(1)` dans `_pull_secrets_from_vault`, jamais de `.env` partiel ni d'injection partielle/exécution enfant | `heimdall/cli/vault_client.py` (`_pull_secrets_from_vault`) + `tests/test_vault_cli.py::test_pull_missing_named_secret_exits_1_without_partial_file`, `::test_run_missing_named_secret_exits_1_without_executing_child` |
| `localhost` vérifié à la construction puis résolu à nouveau à la connexion (rebinding, récurrent) | Verrouillé par test : défaut `https://127.0.0.1:8443` (aucune résolution) + fenêtre documentée en docstring ; tout changement de défaut casse le test | `heimdall/vault/client.py` (`resolve_vault_url`, `_check_localhost_resolution`) + `tests/test_vault_client.py::test_default_vault_url_avoids_dns_and_rebinding_is_documented` |
| Repli Windows check-then-use (récurrent) | Verrouillé par test : garantie POSIX-only + `lstat` post-`replace` documentées ; cible de confinement Linux/POSIX (CI self-hosted), Windows best-effort | `heimdall/vault/atomic.py` (`_write_file_atomic_fallback`) + `tests/test_vault_client.py::test_windows_fallback_posix_only_guarantee_is_documented` |

## 3. Résultats locaux

```sh
.venv/bin/ruff check heimdall tests
# All checks passed
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 42 source files
.venv/bin/python -m pytest tests/test_vault_client.py tests/test_vault_integration_client_server.py tests/test_vault_cli.py -q
# verts (voir sortie CI)
git diff --check origin/main...HEAD
# vide (pas de whitespace)
```

## 4. Exception de regroupement

Le découpage prévoit une PR par sous-ticket. Cette branche regroupe #98–#102
sous #35 parce que `push → pull → run` forme un flux atomique indissociable :
`push` sans `pull`/`run` ne prouve pas le stockage chiffré de bout en bout,
et les tests #102 couvrent les trois commandes dans un seul scénario
(`test_cli_end_to_end_push_pull_and_run`). Un découpage en 5 PR aurait
multiplié les états intermédiaires non testables et les conflits sur
`heimdall/cli/vault_client.py` / `heimdall/vault/client.py` / `heimdall/vault/atomic.py`.

L'exception est signalée ici et dans la description PR. Elle doit être
validée explicitement par les mainteneurs avant fusion ; les prochaines
livraisons suivront une PR par sous-ticket. Le revert ciblé reste possible :
#98 → `vault/client.py`, #99/#100/#101 → `cli/vault_client.py` par commande,
#100 → `vault/atomic.py`, #102 → `tests/test_vault_integration_client_server.py`.

## 5. Voies `run` : canonique vs alias (ticket #101)

Le ticket #101 spécifie `heimdall run -- <cmd>` : c'est la voie canonique
(`heimdall/cli/main.py:53`, `app.command("run")`). `heimdall vault run`
(`heimdall/cli/vault_keys.py:50`, `vault_app.command("run")`) est un alias
de découvrabilité (`vault push` / `vault pull` / `vault run` groupés),
pas une seconde implémentation.

Garanties anti-divergence :
- même callback `vault_run` (`heimdall/cli/vault_client.py:616`), donc mêmes
  gardes : allowlist locale (nom Vault jamais utilisé), denylist étendue,
  `shutil.which` préalable, sans `shell=True`, `Exit(2)` sur commande vide ;
- mêmes réglages Typer via la source unique `RUN_CONTEXT_SETTINGS`
  (`allow_extra_args` + `ignore_unknown_options`) importée par les deux
  enregistrements ;
- test de non-divergence : `tests/test_vault_cli.py::test_run_and_vault_run_share_callback_and_guards`
  (même objet callback, mêmes `context_settings`, `Exit(2)` + « Aucune commande »
  sur les deux voies).
