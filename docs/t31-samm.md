# T31 — preuves SAMM (#31)

Ticket : [#31](https://github.com/Cezar277/heimdall/issues/31) (Génération de .env.example, .env et .gitignore), parent [#4](https://github.com/Cezar277/heimdall/issues/4).
Dépend de [#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du commit d'implémentation** [`5c3a68708532c0bf9134320347486354ed6d5435`](https://github.com/Cezar277/heimdall/commit/5c3a68708532c0bf9134320347486354ed6d5435), jamais à une branche.
Base des liens : `https://github.com/Cezar277/heimdall/tree/5c3a68708532c0bf9134320347486354ed6d5435/`

## Preuves d'implémentation et de sécurité

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| `.env.example` avec noms et valeurs vides (aucun secret, invariant 8) | [`env.py#L294`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L294) (`update_env_example`), [`#L157`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L157) (`_extract_and_validate_names`) | [`test_remediation_env.py#L69`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L69) (`test_env_example_created_with_empty_values`), [`#L83`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L83) (`test_env_example_never_writes_secret_values`) |
| Idempotence de `.env.example` (préservation structure, commentaires et pas de doublon) | [`env.py#L203`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L203) (`_parse_example_lines`), [`#L294`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L294) | [`test_remediation_env.py#L101`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L101) (`test_env_example_idempotent_no_duplicates`), [`#L113`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L113) (`test_env_example_preserves_existing_comments_and_formatting`) |
| `.env` créé avec droits stricts 0600 (`os.open(..., 0o600)` et contrôle mode POSIX) | [`env.py#L60`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L60) (`_SECURE_ENV_MODE`), [`#L361`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L361) (`update_env_file`) | [`test_remediation_env.py#L152`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L152) (`test_env_file_created_with_permissions_600`), [`#L169`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L169) (`test_env_file_updates_existing_preserving_permissions`) |
| Échappement des caractères spéciaux shell dans `.env` (anti-injection) | [`env.py#L361`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L361) via `format_env_value` | [`test_remediation_env.py#L184`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L184) (`test_env_file_escapes_special_characters_safely`) |
| Ajout idempotent au `.gitignore` (détection motifs existants, aucun doublon) | [`env.py#L217`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L217) (`_is_env_covered_in_gitignore`), [`#L230`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L230) (`ensure_gitignore_ignores_env`) | [`test_remediation_env.py#L224`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L224) (`test_gitignore_creates_and_adds_env_if_missing`), [`#L235`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L235) (`test_gitignore_idempotent_no_duplicate_lines`), [`#L252`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L252) (`test_gitignore_recognizes_existing_env_patterns`) |
| Contrôle du suivi Git et proposition `git rm --cached .env` | [`env.py#L447`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L447) (`check_env_git_status`) | [`test_remediation_env.py#L279`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L279) (`test_git_status_check_warns_when_env_is_tracked`) |
| Critère d'acceptation : `git status` ne montre jamais `.env` | [`env.py#L603`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L603) (`remediate_environment`) | [`test_remediation_env.py#L299`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L299) (`test_git_status_never_shows_env_after_remediation`) |
| Confinement de chemin anti-traversée (`../`, absolu, symlink) | [`env.py#L110`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L110) (`_read_text_secure`), [`#L230`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L230), [`#L294`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L294), [`#L361`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L361) | [`test_remediation_env.py#L412`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L412) (`test_confinement_rejects_path_traversal`), [`#L194`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L194) (`test_env_file_refuses_symlink_fail_closed`), [`#L483`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L483) (`test_symlink_checks_on_all_entrypoints`) |
| Absence de fuite de secret dans le reçu (`repr()`) et messages statiques | [`env.py#L66`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L66) (`EnvRemediationError`), [`#L77`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L77) (`EnvRemediationReceipt`), [`#L96`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L96) (`__repr__`) | [`test_remediation_env.py#L332`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L332) (`test_remediate_environment_full_cycle`) |
| Planification diff pour validation humaine (T32) | [`env.py#L503`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L503) (`plan_env_example_change`), [`#L555`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/heimdall/remediation/env.py#L555) (`plan_gitignore_change`) | [`test_remediation_env.py#L370`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L370) (`test_plan_env_example_change`), [`#L389`](https://github.com/Cezar277/heimdall/blob/5c3a68708532c0bf9134320347486354ed6d5435/tests/test_remediation_env.py#L389) (`test_plan_gitignore_change`) |

## Résultats locaux — 12 novembre 2026

Environnement : Linux, Python 3.14, `.venv` du dépôt, 100 % local (aucun réseau).

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_env.py` | 29 passed (100 %) |
| Couverture de code `heimdall.remediation.env` | 83 % (DoD >= 70 %) |
| `pytest tests/test_remediation_*.py` | 423 passed |
| `pytest` suites voisines (vault, mcp, cli) | 1500+ passed |
| `ruff check` + `ruff format --check` | succès (0 erreur) |
| `mypy` strict (`heimdall/remediation/env.py`, `tests/test_remediation_env.py`) | succès (0 erreur) |
| `bandit` (`heimdall/remediation/env.py`) | 0 constat |

## Limites assumées

- Le statut Git indéterminé (hors dépôt Git ou binaire `git` absent du PATH) déclenche un avertissement explicite invitant à vérifier manuellement avec `git status`.
- Le mode 0600 est garanti sur les systèmes conformes POSIX (Linux/macOS) ; sur Windows sans support POSIX des droits, le contrôle est adapté en best-effort.

## Procédure de re-pin au merge

Lors du merge de la PR #31 sur `main`, les commits intermédiaires peuvent être squashés.
Pour garantir la pérennité et la vérifiabilité des preuves SAMM sans aucun lien mort :
1. Ré-épingler la fiche sur le SHA final :
   ```sh
   python scripts/repin_samm.py --fiche docs/t31-samm.md --sha <sha-final>
   ```
2. Contrôler mécaniquement l'intégrité des permaliens :
   ```sh
   python scripts/repin_samm.py --fiche docs/t31-samm.md --check
   ```