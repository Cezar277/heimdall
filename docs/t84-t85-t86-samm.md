# T30.2 / T30.3 / T30.4 — preuves SAMM (#84, #85, #86)

Tickets :
[#84](https://github.com/Cezar277/heimdall/issues/84) (validation du nom de
variable),
[#85](https://github.com/Cezar277/heimdall/issues/85) (application atomique
du patch),
[#86](https://github.com/Cezar277/heimdall/issues/86) (garde de chemin et
tests), parent [#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation**
[`c9b0de0b5d1a3e023666bf1b9633baefd05a70a0`](https://github.com/Cezar277/heimdall/commit/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0),
jamais à une branche. Base des liens :
`https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/`.

## T30.2 — Validation du nom de variable (#84)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Grammaire fermée partagée `^[A-Z][A-Z0-9_]{1,63}$` (pas de retour à la ligne, donc pas d'injection `.env`) | [`naming.py#L20`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L20) (import de `_VARIABLE`, défini en [`templates.py#L70`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/templates.py#L70)) | `test_grammars_agree_everywhere` (équivalence des 5 grammaires historiques), cas `A\nB` / `A\t` rejetés |
| Denylist système (`PATH`, `LD_PRELOAD`, `PYTHONPATH`, préfixes `LD_`, `PYTHON`, `HEIMDALL_`…) : rejet, jamais correction | [`naming.py#L27`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L27) (`DANGEROUS_ENV_EXACT`), [`#L112`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L112) (`DANGEROUS_ENV_PREFIXES`), [`#L159`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L159) (`is_dangerous_env_var`) ; source unique réutilisée par [`vault_client.py#L31`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/cli/vault_client.py#L31) (délégation, aucune copie) | `test_validate_rejects_bad_names`, `test_is_dangerous_env_var_*`, `test_dangerous_names_come_from_one_source` |
| Validation fail-closed d'une entrée LLM (`validate_variable_name` lève `TemplateError` statique, sans reflet) | [`naming.py#L167`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L167) | `test_validate_accepts_safe_names`, `test_validate_rejects_bad_names` (dont `None`, non-`str`, 65 caractères) |
| Déduplication `_2`, `_3`… bornée (refus plutôt que troncature au-delà de 64 caractères) | [`naming.py#L23`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L23) (borne), [`#L183`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/naming.py#L183) (`deduplicate_variable_name`) | `test_deduplicate_*` (libre, `_2`, `_3`, liste, re-validation, base invalide, dépassement) |

## T30.3 — Application atomique du patch (#85)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Aucun fichier à moitié écrit : temporaire + `fsync` + `os.replace` atomique (réutilise `vault.atomic.write_file_atomic`, jamais recopié) | [`apply.py#L128`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L128) | `test_apply_leaves_no_temp_or_partial_file_on_write_error` (`os.replace` simulé en panne : original intact, aucun `.tmp.*` résiduel) |
| Snapshot revérifié avant écriture (fichier modifié depuis le plan → refus, pas d'écrasement) | [`apply.py#L100`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L100) (`apply_replacement`, comparaison `current != plan.before`) | `test_apply_refuses_stale_snapshot`, `test_apply_refuses_missing_file`, `test_apply_refuses_manual_plan` |
| Sauvegarde préalable (`<fichier>.bak`, mode `0600` car elle contient le secret) + annulation | [`apply.py#L122`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L122) (`backup_file`), [`#L143`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L143) (`undo_apply`, contrôle snapshot inverse) | `test_apply_patches_and_preserves_mode_and_backup`, `test_undo_restores_backup_and_second_undo_fails`, `test_undo_refuses_*` |
| Permissions d'origine conservées (pas le `0600` des secrets) | [`apply.py#L58`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L58) (`_read_current_secure` lit le mode ; `write_file_atomic(..., mode=mode)`) | `test_apply_patches_and_preserves_mode_and_backup` (`0o640` conservé, sauvegarde en `0600`) |
| Erreurs statiques sans reflet (`ApplyError` unique) ; `repr()` sans secret | [`apply.py#L41`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L41) (`ApplyError`), [`#L49`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L49) (`AppliedPatch`, `after` en `repr=False`) | `SECRET not in repr(receipt)` dans les tests d'acceptation, `test_apply_rejects_bad_types` |

## T30.4 — Garde de chemin et tests (#86)

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Un seul code de garde : `confine` (ticket #27.3.1) réutilisé, jamais recopié | [`apply.py#L115`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L115) et [`#L157`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L157) (`confine(root, …)`) | `test_confine_rejects_traversal_and_absolute`, `test_apply_rejects_symlink_escape` (lien sortant : refus, cible intacte) |
| Aucune écriture hors du dépôt (`../`, absolu, lien symbolique sortant) ; lecture `O_NOFOLLOW` | [`apply.py#L58`](https://github.com/Cezar277/heimdall/blob/c9b0de0b5d1a3e023666bf1b9633baefd05a70a0/heimdall/remediation/apply.py#L58) | mêmes tests + `test_apply_rejects_bad_types` |

## Résultats locaux — 12 novembre 2026

Environnement : Linux, Python 3.14, `.venv` du dépôt, aucun réseau.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_naming.py tests/test_remediation_apply.py` | 89 passed (77 + 12) |
| `pytest` sur les suites voisines (templates, vault_client, vault_cli, mcp_paths, cli_review) | 650 passed |
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
