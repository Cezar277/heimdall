# T30.1 (#83) — preuves SAMM

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation** [`3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d`](https://github.com/Cezar277/heimdall/commit/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d),
jamais à une branche. Le commit inclut les correctifs de revue (refus de
`process`/`os.environ` masqué ou réassigné côté JavaScript/Python, `repr` des
jetons, auto-ciblage `os.environ`/`process.env`, directive prologue,
chaînage optionnel `?.`, accès indirects à `os.environ`, évaluation de
littéral, clé calculée, fenêtre de contexte JavaScript bornée sur le
délimiteur ouvrant, évaluation de littéral via attribut
(`builtins.eval`, `__builtins__.exec`) ou via appel (`eval`, `Function`,
`compile`), refus des imports dynamiques Python (`__import__`,
`importlib.import_module`)) ainsi que les garde-fous des dernières revues : évaluation curryfiée Python (`getattr(__builtins__,
"eval")(...)` via `_call_resolves_to_eval`/`_callee_mentions_eval`, y compris
callee par sélection `vars(x)["eval"]`, concaténation `"ev"+"al"` repliée via
`_const_str_value`/`_folded_names_eval`, f-string `f"eval"` statique repliée
et interpolation suspecte), alias d'import (`import os as o`,
`from os import environ [as env]`, `from os import *` → `environ`/`getenv`)
et d'affectation simple, annotée (`env: dict = os.environ`), multiple
(`a = b = os.environ`), dépaquetée (`env, _ = os.environ, 1`) et walrus
(`(env := os.environ)`) suivis via `_python_os_aliases` /
`_collect_assignment_aliases` / `_assignment_target_names`,
récepteurs d'espace de noms (`vars()`/`locals()`/`globals()`/`dir()` en
`Subscript` comme en `Call`), appels d'évaluation JavaScript optionnels
(`eval?.(...)`), indirects (`(0, eval)(...)`, `(0, eval)?.(...)`, `(0, e)(...)`
par alias) et par indice (`globalThis["eval"](...)`, `window["Function"](...)`,
`obj?.["eval"](...)`, `globalThis["ev"+"al"](...)` concaténé via
`_js_subscript_evaluation_call`/`_js_matching_opener`)
avec chaînage optionnel normalisé avant les branches, fenêtres d'accès et de
clé calculée ancrées sur le délimiteur englobant puis le délimiteur
d'instruction précédent, alias `const env = process.env` /
`process["env"]` / `process?.["env"]` / `{env}` / `{env: e}` / `import {env}`
refusés (`_js_env_aliases` / `_js_destructured_env_aliases` /
`_js_imported_env_aliases` / `_js_alias_source_is_process_env` /
`_js_env_alias_key`), alias d'évaluation `const e = eval` refusés
(`_js_eval_aliases`, y compris indirect `(0, e)(...)`), et
`setTimeout`/`setInterval` à premier argument chaîne refusés comme `eval`.
Durcissement : `MAX_VARIABLE_CHARS` appliquée dans `_check_variable`,
délimiteurs JS équilibrés exigés (`_js_delimiters_balanced` → `INVALID_SYNTAX`),
`import os` à fin de ligne locale, alias `for`/`with`/défauts (`def f(env=…)`)
et point fixe, mutations dynamiques `setattr`/`Reflect` et
`globalThis.process` refusées.
Gardes récursives rendues itératives (aucun `RecursionError` sur entrée hostile).

Base des liens :
`https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/`.

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Template Python `os.environ["NOM"]`, échec bruyant si absent | [`templates.py#L91`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L91) (`TEMPLATES`), [`#L251`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L251) (`replacement_expression`) | `test_templates_are_closed_and_exact`, `test_python_replaces_only_the_literal_and_adds_import` |
| Template JavaScript `process.env.NOM` | [`templates.py#L2833`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2833), [`#L2538`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2538) (`_javascript_replacement`) | `test_templates_are_closed_and_exact`, `test_javascript_replaces_only_the_literal` |
| Détection par extension de fichier | [`templates.py#L240`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L240) (`detect_language`) | `test_language_detection_follows_extension`, `test_unknown_extensions_request_manual_remediation` |
| Remplacer le littéral, pas la ligne | [`templates.py#L1059`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1059) (Python), [`#L2808`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2808) (JavaScript) | `test_python_replaces_only_the_target_literal_in_a_structure`, `test_javascript_boundaries_remain_valid` |
| Ajouter `import os` si nécessaire, sans casser docstring/futur/décorateur | [`templates.py#L1024`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1024) (`_python_import_insertion`), [`#L1033`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1033) (`_with_python_import`, fin de ligne locale) | `test_python_import_goes_after_docstring_and_future_import`, `test_python_import_goes_before_a_decorator`, `test_python_existing_import_is_not_duplicated`, `test_python_import_after_the_target_is_completed_at_the_top`, `test_python_import_uses_local_line_ending_on_mixed_file` |
| Refus f-string / template literal | [`templates.py#L380`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L380) (`_ambiguous_parent`), [`#L2561`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2561) (contrôle template JS) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus concaténation explicite et implicite | [`templates.py#L846`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L846) (`_single_string_token`), [`#L2591`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2591) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus des contextes non remplaçables (docstring, annotation, clé/méthode, import statique) | [`templates.py#L361`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L361) (`_annotation_context`), [`#L2640`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2640) (clé d'objet), [`#L2655`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2655) (méthode) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Injection de code par le nom de variable | [`templates.py#L251`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L251) (`replacement_expression`) + grammaire [`#L64`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L64) + borne [`#L53`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L53) (`MAX_VARIABLE_CHARS`) via [`#L230`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L230) (`_check_variable`) | `test_variable_grammar_prevents_code_injection`, `test_variable_max_length_is_enforced` |
| `os` masqué côté Python (`os = …`, `os.environ = …`, `del os.environ`) et `process` masqué côté JavaScript (`process = …`, `process.env = …`, `delete process.env`) | [`templates.py#L884`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L884) (`_target_is_os_environ`), [`#L927`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L927) (`_python_os_status`), [`#L1849`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1849) (`_js_process_env_access_end`), [`#L1899`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1899) (`_js_process_env_mutated`), [`#L2061`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2061) (`_javascript_process_shadowed`) | `test_python_refuses_shadowed_os` (`os.environ = 1`, `del os.environ`), `test_javascript_refuses_shadowed_process` (`process.env = {}`, `delete process.env`) |
| Auto-ciblage d'une clé déjà assainie, directive prologue, chaînage optionnel, clé calculée | [`templates.py#L657`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L657) (`_environment_key_context`), [`#L2081`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2081) (`_js_process_env_key`), [`#L2122`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2122) (`_js_normalize_optional_chaining`), [`#L2160`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2160) (`_js_env_access_present`), [`#L2203`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2203) (`_js_computed_process_key`), [`#L2667`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2667) (`_js_standalone_string`) | `test_python_refuses_environment_key_auto_targeting`, `test_javascript_refuses_environment_key_auto_targeting`, `test_javascript_refuses_directive_prologue` |
| Évaluation curryfiée Python (`getattr(__builtins__, "eval")(...)`), callee par sélection (`vars(x)["eval"](...)`), concaténée (`"ev"+"al"`) et f-string (`f"eval"`, `f"ev{'al'}"`) et récepteurs d'espace de noms (`vars()`/`locals()`/`globals()` en `Subscript` et en `Call`) | [`templates.py#L713`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L713) (`_CODE_EVALUATION_FUNCS`), [`#L716`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L716) (`_NAMESPACE_READER_FUNCS`), [`#L719`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L719) (`_const_str_value`), [`#L760`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L760) (`_folded_names_eval`), [`#L768`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L768) (`_callee_mentions_eval`), [`#L815`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L815) (`_call_resolves_to_eval`), [`#L513`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L513) (`_call_mentions_namespace_reader`) | `test_python_refuses_ambiguous_or_absent_cases`, `test_python_refuses_namespace_reader_call_on_separate_line` (cas `getattr(__builtins__, "eval")`, `getattr(…, "ev"+"al")`, `getattr(…, f"eval")`, `vars(__builtins__)["eval"]`, `vars(__builtins__)[f"eval"]`, `vars()["NOM"]`, `locals()["NOM"]`, `getattr(vars(), "NOM")`, `vars().get("NOM")`) |
| Évaluation JavaScript optionnelle (`eval?.(...)`), indirecte (`(0, eval)(...)`, `(0, eval)?.(...)`, `(0, e)(...)` par alias), par indice (`globalThis["eval"](...)`, `window["Function"](...)`, `obj?.["eval"](...)`, `globalThis["ev"+"al"](...)` concaténé) et `setTimeout`/`setInterval` à premier argument chaîne | [`templates.py#L2691`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2691) (`_JS_EVAL_CALLEES`), [`#L2699`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2699) (`_js_code_evaluation_call`), [`#L2575`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2575) (`_js_eval_aliases`), [`#L2761`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2761) (`_js_subscript_evaluation_call`), [`#L2809`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2809) (`_js_matching_opener`) | `test_javascript_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_aliased_evaluation_call` (cas `eval?.`, `Function?.`, `(0, eval)`, `(0, eval)?.`, `(0, Function)?.`, `(0, e)`, `globalThis["eval"]`, `globalThis["ev"+"al"]`, `window["Function"]`, `window["Fu"+"nction"]`, `obj?.["eval"]`, `e("NOM")`, `setTimeout`, `setInterval`) |
| Alias d'import et d'affectation Python (`import os as o` → `o.environ[...]`, `from os import environ [as env]` / `getenv`, `from os import *` → `environ`/`getenv`, `env = os.environ` / `env: dict = os.environ` / `a = b = os.environ` (y compris hors-ordre par point fixe) / `env, _ = os.environ, 1` / `(env := os.environ)` / `for env in [os.environ]` / `def f(env=os.environ)` → `env[...]`) : la racine suit l'alias | [`templates.py#L565`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L565) (`_python_os_aliases`), [`#L529`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L529) (`_assignment_target_names`), [`#L543`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L543) (`_collect_argument_default_aliases`), [`#L657`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L657) (`_environment_key_context`) | `test_python_refuses_aliased_environment_access`, `test_python_refuses_loop_and_out_of_order_aliases`, `test_python_refuses_default_argument_aliases`, `test_python_refuses_environment_key_auto_targeting` |
| Alias `process.env` côté JavaScript (`const env = process.env` / `process["env"]` / `process?.["env"]` / `{env}` / `{env: e}` / `import {env}` / `for (const env of [process.env])` → `env[...]` / `env.get(...)`) : refusé sans dataflow (sur-refus documenté) | [`templates.py#L2518`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2518) (`_js_env_aliases`), [`#L2272`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2272) (`_js_alias_source_is_process_env`), [`#L2310`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2310) (`_js_destructured_env_aliases`), [`#L2374`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2374) (`_js_for_env_aliases`), [`#L2464`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2464) (`_js_imported_env_aliases`), [`#L2634`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L2634) (`_js_env_alias_key`) | `test_javascript_refuses_aliased_environment_key`, `test_javascript_allows_independent_key_after_process_mention`, `test_javascript_allows_independent_key_after_process_env_mention` |
| Fuite de la valeur par `repr` ou par message d'erreur | [`templates.py#L124`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L124) (`ReplacementPlan`), [`#L1212`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1212) (`_JsToken.value`), [`#L97`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L97) (`TemplateError`) | `test_repr_never_contains_the_secret_or_source`, `test_token_repr_never_contains_the_decoded_secret`, `test_invalid_api_inputs_are_static_errors` |
| Entrées hostiles bornées (mémoire, syntaxe, NUL, délimiteurs JS) | [`templates.py#L51`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L51) (`MAX_SOURCE_BYTES`), [`#L58`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L58) (`MAX_JS_TOKENS`), [`#L1487`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L1487) (`_js_delimiters_balanced` → `INVALID_SYNTAX`) | `test_invalid_api_inputs_are_static_errors`, `test_python_invalid_syntax_and_stale_line_are_manual`, `test_javascript_invalid_and_stale_lines_are_manual`, `test_javascript_unbalanced_delimiters_are_manual` |
| Aucune exécution du code analysé, aucune I/O réseau | [`templates.py`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py) (imports stdlib uniquement), [`#L39`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L39) | `test_module_has_no_execution_or_network_dependency` |
| Remplacement correct sur le repo piège | [`templates.py#L283`](https://github.com/Cezar277/heimdall/blob/3b587b37f05ed5492f83491f2f2d9ed67d0b7c0d/heimdall/remediation/templates.py#L283) (`build_replacement`) | `test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo` (10/10 fuites simples) |

## Résultats locaux — 11 novembre 2026

Environnement de référence : Linux, Python 3.14.6, environnement `.venv` du
dépôt, aucune connexion réseau utilisée.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_templates.py` | 266 passed |
| `pytest tests/test_remediation_templates.py --cov=heimdall.remediation --cov-branch --cov-fail-under=70` | couverture du module : 81 % (seuil critique 70 %) |
| `pytest --cov=heimdall --cov-branch --cov-fail-under=85` | voir ticket |
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
  `getattr(os, ...)`, `operator.getitem(os.environ, ...)`,
  `process.env[...]`, `process.env.get(...)`, `process["env"][...]`,
  `Reflect.get(process.env, ...)`).
- `_javascript_replacement` refuse la concaténation implicite (`"SECRET"
  "other"`, non reconnue par le tokenizer JS) avec `AMBIGUOUS_CONCATENATION`,
  pour ne plus rendre de patch sur entrée déjà invalide.
- `_js_standalone_string` refuse une directive prologue (`"use strict"`) pour
  ne pas perdre sa sémantique.
- `_js_env_access_present` fusionne les sauts optionnels avant analyse
  (``?.`` → saut membre, ``?[`` → saut indice) : ``process?.env["NOM"]``,
  ``process?.env?.get("NOM")``, ``process?.["env"]`` et ``process?.[...]``
  sont reconnus comme des lectures ``process.env``, avec refus
  ``AMBIGUOUS_CONTEXT`` au lieu de corruption de clé.
- `_js_computed_process_key` refuse une clé de propriété calculée
  (`process["en" + "v"]…`, `process["env"][...]`, `process?.[...]`) : la fenêtre
  littérale seule ne prouve pas la clé ``env``, le doute profite au refus. La
  fenêtre contenant un ident ``process`` alors que le littéral est en position
  d'indice, d'appel ou d'argument (potentiellement une clé remontée) déclenche
  aussi le refus.
- `_environment_key_context` (via `_python_env_access_in` et
  `_python_call_env_access`) refuse les lectures d'`os.environ` indirectes :
  curryfication (`getattr(os.environ, "get")("NOM")`, `vars(os.environ)["NOM"`,
  `getattr(os, "environ")["NOM"]`).
- `_python_code_evaluation_context` (via `_call_resolves_to_eval` et
  `_callee_mentions_eval`) refuse tout littéral dont un ancêtre d'appel
  résout une fonction d'évaluation, y compris curryfié
  (`getattr(__builtins__, "eval")("NOM")`, `getattr(b, "exec")("NOM")`) et
  par sélection (`vars(__builtins__)["eval"]("NOM")`) : la valeur d'env ne
  doit pas être ré-évaluée comme du code. Les récepteurs d'espace de noms
  (`vars()`, `locals()`, `globals()`, `dir()`) en position `Subscript` sont
  refusés de la même façon, ainsi qu'en position `Call` via
  `_call_mentions_namespace_reader` (`getattr(vars(), "NOM")`,
  `vars().get("NOM")`, `operator.getitem(locals(), "NOM")`).
- `_js_code_evaluation_call` refuse tout littéral premier argument d'un appel
  d'évaluation : formes directes (`eval("NOM")`, `Function("NOM")`),
  optionnelles (`eval?.("NOM")`, `Function?.("NOM")`, le `?.` tokenizé en `?`
  + `.` est sauté avant le test) et indirectes (`(0, eval)("NOM")`, `(0,
  eval)?.("NOM")`, séquence `,` + ident + `)` + `(`, avec normalisation du
  chaînage optionnel avant les deux branches), ainsi que
  `setTimeout("NOM", ...)` et `setInterval("NOM", ...)` dont le premier
  argument chaîne serait évalué comme du code.
- `_python_env_access_in` et `_python_call_env_access` traitent les imports
  dynamiques (`__import__("os"`, `importlib.import_module("os")`) comme des
  accès indirects à l'environnement.
- `_python_os_aliases` collecte les alias d'import (`import os as o`,
  `from os import environ [as env]` / `getenv`, `from os import *` → `environ` /
  `getenv`) et d'affectation simple (`env = os.environ`), annotée
  (`env: dict = os.environ`), multiple (`a = b = os.environ`), dépaquetée
  (`env, _ = os.environ, 1`) et walrus (`(env := os.environ)`) via
  `_collect_assignment_aliases` / `_assignment_target_names` (en un seul
  passage) : la racine suit l'alias et tout re-ciblage via alias est refusé.
- `_python_env_access_in` et `_callee_mentions_eval` sont itératives (pile
  explicite) : une chaîne d'attributs ou un callee imbriqué de plusieurs
  milliers de maillons ne lève jamais `RecursionError` — l'entrée hostile se
  solde par un refus statique, jamais un crash.
- `_js_computed_process_key` ancre sa fenêtre sur le délimiteur englobant le
  crochet, puis sur le délimiteur d'instruction précédent (`;`/`{`/`}`) :
  un `process` mentionné dans une instruction précédente ne fait plus refuser
  une clé indépendante (`config["SECRET"]` après `console.log(process…)`).
- `_js_env_aliases` collecte les alias `const/env = process.env`,
  `const env = process["env"]` / `process?.["env"]` (via
  `_js_alias_source_is_process_env`, membre supplémentaire `process.env.foo`
  exclu), la déstructuration `const {env} = process` / `const {env: e} = process`
  (via `_js_destructured_env_aliases`, clé chaîne `{"env": e}` incluse) et
  l'import nommé `import {env} from …` / `import {env as e} from …` (via
  `_js_imported_env_aliases`, sur-refus quelle que soit la source) — analyse
  syntaxique bornée, sans dataflow — et `_js_env_alias_key` refuse
  `env["NOM"]` / `env.get("NOM")` (sur-refus documenté : les alias de
  variables restent hors du périmètre fin de #83, traités comme JSX/TS).
- `_js_eval_aliases` collecte les alias `const e = eval` / `const F = Function`
  (affectation simple, chaînée `a = b = eval` incluse, ni appel ni membre) et
  `_js_code_evaluation_call` refuse `e("NOM")` comme `(0, e)("NOM")` indirect
  (sur-refus documenté : pas de dataflow, le doute profite au refus).
- `_const_str_value` / `_folded_names_eval` / `_has_str_addition` replient la
  concaténation `"ev"+"al"` et la f-string statique `f"eval"` avant le test
  d'appartenance à `_CODE_EVALUATION_FUNCS` ; toute interpolation
  (`f"ev{'al'}"`) ou concaténation non repliable à base de chaînes en position
  de callee reste suspecte et profite au refus (miroir JS par
  `_js_subscript_evaluation_call` pour `globalThis["ev"+"al"](...)`).
- `_python_os_aliases` traite `from os import *` comme liant `environ` et
  `getenv` (import étoile = racines inconnues par construction, le doute
  profite au refus plutôt qu'à une liste incomplète).
- `_js_subscript_evaluation_call` (avec `_js_matching_opener`) refuse tout
  littéral premier argument d'un callee par indice nommant une fonction
  d'évaluation (`globalThis["eval"](...)`, `window["Function"](...)`,
  `obj?.["eval"](...)`, maillons remontés un par un) : miroir exact de la
  garde Python par sélection.
- `_js_process_env_key` ancre sa fenêtre comme `_js_computed_process_key`
  (délimiteur englobant, puis délimiteur d'instruction précédent) : un
  `process.env` mentionné dans une instruction précédente ne fait plus
  refuser une clé indépendante (`f["SECRET"]` après
  `console.log(process.env.FOO)`).
- `_check_variable` applique `MAX_VARIABLE_CHARS` (64) en plus de la grammaire
  `^[A-Z][A-Z0-9_]{1,63}$` : la constante n'est plus inutilisée, `A*64` accepté
  et `A*65` lève `TemplateError` (`test_variable_max_length_is_enforced`).
- `_js_delimiters_balanced` refuse tout fichier JS aux délimiteurs déséquilibrés
  (`const x = "S"; }}`, `const x = "S"; ];` → `INVALID_SYNTAX`,
  `test_javascript_unbalanced_delimiters_are_manual`) : le patch JS, sans
  reparse complet, ne s'applique plus sur entrée déjà invalide (asymétrie
  assumée avec Python qui reparse via `ast.parse`).
- `_with_python_import` choisit la fin de ligne localement (voisinage de
  l'insertion, `test_python_import_uses_local_line_ending_on_mixed_file`) :
  un `\r\n` lointain ne contamine plus une zone LF.
- `_target_is_os_environ` + `_python_os_status` refusent toute réassignation ou
  suppression d'`os.environ` (`os.environ = 1`, `os.environ: dict = {}`,
  `os.environ += "x"`, `del os.environ`, y compris via alias `import os as o`)
  en `SHADOWED_MODULE` (`test_python_refuses_shadowed_os`) : le patch ne lit
  plus un objet écrasé. `os.environ["X"] = 1` / `del os.environ["X"]` (clé,
  pas l'objet) reste éligible.
- `_js_process_env_access_end` + `_js_process_env_mutated` refusent toute
  réassignation ou suppression de `process.env` (`process.env = {}`,
  `process["env"] = {}`, `delete process.env`, `process.env++`,
  `process.env += "x"`) en `SHADOWED_MODULE`
  (`test_javascript_refuses_shadowed_process`) : `delete` préfixe et `++`/`--`
  préfixe inclus, comparaisons (`==`, `===`, `!=`, `<=`, `>=`) et lectures
  (`process.env.FOO`, `process.env["X"]`) non bloquées.
- `_python_os_aliases` itère jusqu'à point fixe et collecte les lieurs
  `for`/`with`/compréhensions (`for env in [os.environ]`,
  `test_python_refuses_loop_and_out_of_order_aliases`), les défauts
  d'arguments (`def f(env=os.environ)`, `lambda env=os.environ`,
  `test_python_refuses_default_argument_aliases`) : les chaînes hors-ordre
  (`b = a` puis `a = os.environ`) se résolvent, le reste profite au refus.
  Côté JS, `_js_for_env_aliases` lie `for (const env of [process.env])`
  (`test_javascript_refuses_aliased_environment_key`).
- `_call_mutates_os_environ` + `_target_is_os_environ` (Subscript) refusent les
  mutations dynamiques (`setattr(os, "environ", 1)`, `delattr(os, "environ")`,
  `os.__dict__["environ"] = 1`) en `SHADOWED_MODULE`
  (`test_python_refuses_shadowed_os`).
- `_js_global_process_mutated` refuse `globalThis.process = {}` (et
  `global`/`window`/`self`, formes membre et indice) en `SHADOWED_MODULE`, et
  `_js_reflect_process_env_mutation` refuse `Reflect.set/deleteProperty` /
  `Object.defineProperty(process, "env", …)` (`test_javascript_refuses_shadowed_process`).

## Limites assumées

- #84 : denylist sémantique des noms (`PATH`, `LD_PRELOAD`, `PYTHONPATH`…)
  et dédoublonnage `_2`/`_3` non implémentés ici.
- #85 : le plan n'écrit aucun fichier ; l'application atomique et la
  revalidation du snapshot restent à livrer.
- #86 : la garde de chemin runtime (liens symboliques, TOCTOU) reste à
  livrer ; ce module ne fait que la validation lexicale du contrat Finding.
- JSX et TypeScript sont hors périmètre : leurs extensions sont refusées en
  remédiation manuelle.
