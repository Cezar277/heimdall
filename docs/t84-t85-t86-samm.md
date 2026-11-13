# T30.2 / T30.3 / T30.4 — preuves SAMM (#84, #85, #86)

Tickets :
[#84](https://github.com/Cezar277/heimdall/issues/84) (validation du nom de
variable),
[#85](https://github.com/Cezar277/heimdall/issues/85) (application atomique
du patch),
[#86](https://github.com/Cezar277/heimdall/issues/86) (garde de chemin et
tests), parent [#30](https://github.com/Cezar277/heimdall/issues/30).

> **Exception validée au contrat « un sous-ticket par PR » (ticket parent #30)** :
> Le regroupement de #84 (validation des noms), #85 (application atomique) et
> #86 (garde de chemin et tests) au sein d'une seule PR est une exception validée
> sous le ticket parent #30. Elle est justifiée techniquement par le partage
> direct du module `heimdall.remediation`, de la garde de chemin unique `confine`
> et des structures de données partagées, évitant du code mort intermédiaire ou
> des bifurcations transitoires. Cette exception est circonscrite à ce triptyque
> et ne constitue pas un précédent pour les autres sous-tickets.

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation**
[`1692ead9101994b21460adbb0657461b60d49b24`](https://github.com/Cezar277/heimdall/commit/1692ead9101994b21460adbb0657461b60d49b24),
jamais à une branche. Base des liens :
`https://github.com/Cezar277/heimdall/tree/1692ead9101994b21460adbb0657461b60d49b24/`

## T30.2 — Validation du nom de variable (#84)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Grammaire fermée partagée `^[A-Z][A-Z0-9_]{1,63}$` (pas de retour à la ligne, donc pas d'injection `.env`) | [`naming.py#L20`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L20) (import de `_VARIABLE`, défini en [`templates.py#L70`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/templates.py#L70)) | `test_grammars_agree_everywhere` (équivalence des 5 grammaires historiques), `test_fullmatch_strictly_rejects_trailing_newline_everywhere`, cas `A\nB` / `A\t` / `AB\n` rejetés via `fullmatch` |
| Denylist système (`PATH`, `LD_PRELOAD`, `PYTHONPATH`, préfixes `LD_`, `PYTHON`, `HEIMDALL_`…) : rejet, jamais correction | [`naming.py#L30`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L30) (`DANGEROUS_ENV_EXACT`), [`#L115`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L115) (`DANGEROUS_ENV_PREFIXES`), [`#L162`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L162) (`is_dangerous_env_var`) ; source unique réutilisée par [`vault_client.py#L31`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/cli/vault_client.py#L31) et durcie via [`#L61`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/cli/vault_client.py#L61) (`preview_name`) | `test_validate_rejects_bad_names`, `test_is_dangerous_env_var_*`, `test_dangerous_names_come_from_one_source`, `test_filter_secrets_with_non_str_key_exits_2_cleanly`, `test_pull_secrets_from_vault_with_non_str_name_exits_1_cleanly`, `test_validate_requested_names_rejects_trailing_newline_and_non_str` |
| Validation fail-closed d'une entrée LLM (`validate_variable_name` lève `TemplateError` statique, sans reflet) | [`naming.py#L172`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L172) (`validate_variable_name`) | `test_validate_accepts_safe_names`, `test_validate_rejects_bad_names` (dont `None`, non-`str`, 65 caractères) |
| Déduplication `_2`, `_3`… bornée (refus plutôt que troncature au-delà de 64 caractères) | [`naming.py#L23`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L23) (`_MAX_NAME_LENGTH`), [`#L188`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/naming.py#L188) (`deduplicate_variable_name`) | `test_deduplicate_*` (libre, `_2`, `_3`, liste, re-validation, base invalide, dépassement) |

## T30.3 — Application atomique du patch (#85)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Aucun fichier à moitié écrit : temporaire + `fsync` + `os.replace` atomique (réutilise `vault.atomic.write_file_atomic`, jamais recopié) | [`apply.py#L176`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L176) (`write_file_atomic`) | `test_apply_leaves_no_temp_or_partial_file_on_write_error` (`os.replace` simulé en panne : original intact, aucun `.tmp.*` résiduel) |
| Snapshot revérifié avant écriture (fichier modifié depuis le plan → refus, pas d'écrasement) | [`apply.py#L164-L166`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L164-L166) (`apply_replacement`, comparaison `current != plan.before`) | `test_apply_refuses_stale_snapshot`, `test_apply_refuses_missing_file`, `test_apply_refuses_manual_plan` |
| Sauvegarde préalable (`<fichier>.bak`, mode `0600` car elle contient le secret) + garde Git runtime + annulation | [`apply.py#L168`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L168) (`backup_file`), [`#L106`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L106) / [`#L174`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L174) (`_check_backup_git_status` via `is_git_tracked`/`is_git_ignored`), [`#L191`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L191) et [`#L208-L211`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L208-L211) (`undo_apply`, contrôles snapshot inverse et mode) | `test_apply_patches_and_preserves_mode_and_backup`, `test_apply_backup_warns_*`, `test_undo_restores_backup_and_second_undo_fails`, `test_undo_refuses_*` |
| Permissions d'origine conservées (pas le `0600` des secrets) | [`apply.py#L71`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L71) (`_read_current_secure` lit le mode ; `write_file_atomic(..., mode=mode)`) | `test_apply_patches_and_preserves_mode_and_backup` (`0o640` conservé, sauvegarde en `0600`) |
| Erreurs statiques sans reflet (`ApplyError` unique) ; `repr()` sans secret | [`apply.py#L53`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L53) (`ApplyError`), [`#L61-L68`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L61-L68) (`AppliedPatch`, `after` en `repr=False`), [`templates.py#L191-L198`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/templates.py#L191-L198) (`ReplacementPlan.__repr__` sans secret) | `SECRET not in repr(receipt)` dans les tests d'acceptation, `test_apply_rejects_bad_types` |

## T30.4 — Garde de chemin et tests (#86)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Un seul code de garde : `confine` (ticket #27.3.1) réutilisé, jamais recopié | [`apply.py#L161`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L161) et [`#L205`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L205) (`confine(root, …)`) | `test_confine_rejects_traversal_and_absolute`, `test_apply_rejects_symlink_escape` (lien sortant : refus, cible intacte) |
| Aucune écriture hors du dépôt (`../`, absolu, lien symbolique sortant) ; lecture `O_NOFOLLOW` | [`apply.py#L71`](https://github.com/Cezar277/heimdall/blob/1692ead9101994b21460adbb0657461b60d49b24/heimdall/remediation/apply.py#L71) via `_open_file_read_fd` (parents ouverts composant par composant avec `O_NOFOLLOW` + `O_NONBLOCK`) | mêmes tests + `test_read_refuses_fifo_without_blocking`, `test_read_refuses_parent_swapped_after_confine`, `test_apply_rejects_bad_types` |

## Résultats locaux — 12 novembre 2026

Environnement : Linux, Python 3.14, `.venv` du dépôt, aucun réseau.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_naming.py tests/test_remediation_apply.py` | 112 passed (88 + 24) |
| `pytest` sur les suites voisines (templates, vault_client, vault_cli, mcp_paths, cli_review) | 646 passed |
| `ruff check` + `ruff format --check` (paquet + tests) | succès |
| `mypy` (`heimdall/remediation/naming.py`, `apply.py`, `__init__.py`, `heimdall/cli/vault_client.py`) | aucune erreur |
| `bandit` (`heimdall/remediation/apply.py`, `naming.py`, `heimdall/cli/vault_client.py`) | 0 constat |

Toutes les valeurs des tests sont synthétiques (`SYNTHETIC_ONLY_VALUE`).
`apply` n'est exercé que sur `tmp_path` ; aucun fichier du corpus piège
n'est modifié.

## Limites assumées

- Fenêtre TOCTOU résiduelle entre la revérification du snapshot et le
  `os.replace` (un acteur local capable d'écrire dans le dépôt pourrait
  intercaler une modification) : acceptée, même modèle que `vault.atomic` ;
  la corruption partielle reste impossible (atomicité).
- `undo_apply` conserve la sauvegarde après restauration (un second `undo`
  échoue sur le contrôle snapshot plutôt que de détruire une preuve).
- Dépassement de `MAX_VARIABLE_CHARS` par suffixe `_N` : refus
  (`TemplateError`), jamais de troncature silencieuse.

## Procédure de re-pin au merge

Lors du merge de la PR #222 sur `main`, les commits intermédiaires peuvent être squashés.
Pour garantir la pérennité et la vérifiabilité des preuves SAMM sans aucun lien mort :
1. Ré-épingler la fiche sur le SHA final :
   ```sh
   python scripts/repin_samm.py --fiche docs/t84-t85-t86-samm.md --sha <sha-final>
   ```
2. Contrôler mécaniquement l'intégrité des permaliens :
   ```sh
   python scripts/repin_samm.py --fiche docs/t84-t85-t86-samm.md --check
   ```
