# T30.1 (#83) — preuves SAMM

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation** [`a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba`](https://github.com/Cezar277/heimdall/commit/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba),
jamais à une branche. Le commit inclut les correctifs de revue (refus de
`process` masqué côté JavaScript, `repr` des jetons, auto-ciblage
`os.environ`/`process.env`, directive prologue).

Base des liens :
`https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/`.

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Template Python `os.environ["NOM"]`, échec bruyant si absent | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L89) (`TEMPLATES`), [`#L245`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L245) (`replacement_expression`) | `test_templates_are_closed_and_exact`, `test_python_replaces_only_the_literal_and_adds_import` |
| Template JavaScript `process.env.NOM` | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L89), [`#L1414`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1414) (`_javascript_replacement`) | `test_templates_are_closed_and_exact`, `test_javascript_replaces_only_the_literal` |
| Détection par extension de fichier | [`templates.py#L234`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L234) (`detect_language`) | `test_language_detection_follows_extension`, `test_unknown_extensions_request_manual_remediation` |
| Remplacer le littéral, pas la ligne | [`templates.py#L599`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L599) (Python), [`#L1414`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1414) (JavaScript) | `test_python_replaces_only_the_target_literal_in_a_structure`, `test_javascript_boundaries_remain_valid` |
| Ajouter `import os` si nécessaire, sans casser docstring/futur/décorateur | [`templates.py#L545`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L545) (`_python_import_insertion`) | `test_python_import_goes_after_docstring_and_future_import`, `test_python_import_goes_before_a_decorator`, `test_python_existing_import_is_not_duplicated`, `test_python_import_after_the_target_is_completed_at_the_top` |
| Refus f-string / template literal | [`templates.py#L374`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L374) (`_ambiguous_parent`), [`#L1425`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1425) (contrôle template JS) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus concaténation explicite et implicite | [`templates.py#L434`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L434) (`_single_string_token`), [`#L1459`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1459) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus des contextes non remplaçables (docstring, annotation, clé/méthode, import statique) | [`templates.py#L355`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L355) (`_annotation_context`), [`#L1479`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1479) (clé d'objet), [`#L1501`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1501) (méthode) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Injection de code par le nom de variable | [`templates.py#L245`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L245) (`replacement_expression`) + grammaire [`#L62`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L62) | `test_variable_grammar_prevents_code_injection` |
| `os` masqué côté Python et `process` masqué côté JavaScript | [`templates.py#L472`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L472) (`_python_os_status`), [`#L1346`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1346) (`_javascript_process_shadowed`) | `test_python_refuses_shadowed_os`, `test_javascript_refuses_shadowed_process` |
| Auto-ciblage d'une clé déjà assainie et directive prologue | [`templates.py#L407`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L407) (`_environment_key_context`), [`#L1360`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1360) (`_js_process_env_key`), [`#L1391`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L1391) (`_js_standalone_string`) | `test_python_refuses_environment_key_auto_targeting`, `test_javascript_refuses_environment_key_auto_targeting`, `test_javascript_refuses_directive_prologue` |
| Fuite de la valeur par `repr` ou par message d'erreur | [`templates.py#L122`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L122) (`ReplacementPlan`), [`#L718`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L718) (`_JsToken.value` masqué), [`#L95`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L95) (`TemplateError`) | `test_repr_never_contains_the_secret_or_source`, `test_token_repr_never_contains_the_decoded_secret`, `test_invalid_api_inputs_are_static_errors` |
| Entrées hostiles bornées (mémoire, syntaxe, NUL) | [`templates.py#L51`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L51) (`MAX_SOURCE_BYTES`), [`#L599`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L599), [`#L938`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L938) (`MAX_JS_TOKENS`) | `test_invalid_api_inputs_are_static_errors`, `test_python_invalid_syntax_and_stale_line_are_manual`, `test_javascript_invalid_and_stale_lines_are_manual` |
| Aucune exécution du code analysé, aucune I/O réseau | [`templates.py`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py) (imports stdlib uniquement), [`#L599`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L599), [`#L938`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L938) | `test_module_has_no_execution_or_network_dependency` |
| Remplacement correct sur le repo piège | [`templates.py#L277`](https://github.com/Cezar277/heimdall/blob/a42c0d6d0791454e3e280ea0e3dc4bf517c5c7ba/heimdall/remediation/templates.py#L277) (`build_replacement`) | `test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo` (10/10 fuites simples) |

## Résultats locaux — 8 novembre 2026

Environnement de référence : Linux, Python 3.14.6, environnement `.venv` du
dépôt, aucune connexion réseau utilisée.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_templates.py` | 140 passed |
| `pytest tests/test_remediation_templates.py --cov=heimdall.remediation --cov-branch --cov-fail-under=70` | couverture du module 79,51 % (seuil critique 70 %) |
| `pytest --cov=heimdall --cov-branch --cov-fail-under=85` | 2960 passed, 15 skipped, 4512 sous-tests ; couverture globale 90,25 % |
| `ruff check heimdall tests scripts` | succès |
| `ruff format --check heimdall/remediation tests/test_remediation_templates.py` | succès |
| `mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py` | 52 fichiers, aucune erreur |
| `bandit -r heimdall -q` | succès (aucun constat) |

Toutes les valeurs des tests sont synthétiques. Aucun fichier du corpus piège
n'est modifié sur disque : les plans sont calculés en mémoire. La PR, la
relecture croisée et la CI distante restent à réaliser ; aucun merge sur
`main` n'est effectué par ce ticket.

## Correctifs de la revue

- `_javascript_process_shadowed` balaie les liaisons de `process`
  (paramètres, `var`/`let`/`const`, fonction/classe, imports, déstructuration,
  `catch`, affectations/incrémentations) et renvoie `SHADOWED_MODULE` ;
  `after == before`.
- `_JsToken.value` est exclu de `repr`, comme `text` : aucun secret décodé ne
  peut apparaître dans une traceback.
- `_environment_key_context` et `_js_process_env_key` refusent le
  re-ciblage d'une clé déjà assainie (`os.environ[...]`, `os.getenv(...)`,
  `process.env[...]`, `process.env.get(...)`).
- `_js_standalone_string` refuse une directive prologue (`"use strict"`) pour
  ne pas perdre sa sémantique.

## Limites assumées

- #84 : denylist sémantique des noms (`PATH`, `LD_PRELOAD`, `PYTHONPATH`…)
  et dédoublonnage `_2`/`_3` non implémentés ici.
- #85 : le plan n'écrit aucun fichier ; l'application atomique et la
  revalidation du snapshot restent à livrer.
- #86 : la garde de chemin runtime (liens symboliques, TOCTOU) reste à
  livrer ; ce module ne fait que la validation lexicale du contrat Finding.
- JSX et TypeScript sont hors périmètre : leurs extensions sont refusées en
  remédiation manuelle.
