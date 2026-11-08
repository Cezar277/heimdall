# T36 — Hook pre-commit et gestion de l'index : preuves SAMM

Tickets : #36 (parent), #103 (installation/désinstallation), #104 (diff
indexé uniquement), #105 (re-stage sans boucle), #106 (commit partiel).

SHA de référence du code : `061b581fb3f69d8d5e445f159e57d6c786e2ff17`.

## Garanties et preuves

| Garantie | Implémentation | Preuve automatisée |
| --- | --- | --- |
| Installation/désinstallation idempotente, hook étranger jamais écrasé | [`hook.py:419`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L419) (`install_hook`), [`hook.py:455`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L455) (`uninstall_hook`), [`hook.py:392`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L392) (`_prepare_existing_hook`) | [`test_cli_hook.py:105`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L105), [`125`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L125), [`135`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L135), [`176`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L176), [`188`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L188) |
| `core.hooksPath` et worktrees respectés | [`hook.py:170`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L170) (`_git_path`, `git rev-parse --git-path hooks`), chemin relatif confiné au dépôt | [`test_cli_hook.py:226`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L226), [`253`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L253), [`265`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L265) |
| Scan de l'index uniquement, jamais du dossier de travail | [`hook.py:276`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L276) (`_hook_script` → `scan --staged`), `heimdall/cli/scan.py` (`_collect_staged`) | [`test_cli_hook.py:316`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L316) (secret non indexé ignoré), [`332`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L332) (commit partiel) |
| Commit partiel : index final exact, reste intact dans le worktree | `scan --staged` + test à deux hunks | [`test_cli_hook.py:332`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L332) |
| Anti-récursion `HEIMDALL_IN_HOOK=1` | [`hook.py:276`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L276) (script), [`hook.py:121`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L121) (`_run_git`) | [`test_cli_hook.py:483`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L483) |
| Refus des modifications non indexées avant remédiation | [`hook.py:566`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L566) (`assert_no_unstaged_changes`), [`hook.py:634`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L634) (`apply_and_restage`) | [`test_cli_hook.py:392`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L392), [`407`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L407) |
| Ré-indexation du contenu exact, sans filtre `clean` ni hook Git | [`hook.py:608`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L608) (`restage_paths`), [`hook.py:548`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L548) (`hash-object --no-filters`), [`hook.py:121`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L121) (`core.hooksPath=os.devnull`) | [`test_cli_hook.py:455`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L455) (canaris filtre et hook absents) |
| Chemins confinés, liens sortants et `.git`/`.env` refusés | [`hook.py:482`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L482) (`_confined_paths` → `heimdall.mcp.paths.confine`) | [`test_cli_hook.py:425`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L425), [`430`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L430), [`439`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L439), [`446`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L446) |
| Écriture atomique, hook `0700`, dossier non world-writable | [`hook.py:315`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L315) (`_atomic_write`), [`hook.py:352`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/heimdall/cli/hook.py#L352) (`_ensure_hooks_directory`) | [`test_cli_hook.py:239`](https://github.com/Cezar277/heimdall/blob/061b581fb3f69d8d5e445f159e57d6c786e2ff17/tests/test_cli_hook.py#L239) |
| Hook local contournable, CI opposable | `docs/hook.md`, `heimdall/cli/scan.py` (`--ci`) | `tests/security/test_scanner_bypass.py::test_hook_bypass_requires_trusted_ci` (existant) |

## Résultat local

```text
2920 passed, 17 skipped, 5911 subtests passed
TOTAL coverage: 91.02 % (seuil 85 %)
ruff check heimdall tests scripts : OK
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py : OK
bandit -r heimdall -q : OK
```

## Limite de périmètre

La remédiation interactive (proposition, Y/N/E, application du patch) reste
portée par #30/#32. T36 fournit le hook, le scan de l'index et la primitive
`apply_and_restage` que ce moteur appellera après validation humaine.
