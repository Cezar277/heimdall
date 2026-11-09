# T30.1 (#83) — preuves SAMM

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation** [`5afe0af8553e981fc56a6574def1814854eb0e9a`](https://github.com/Cezar277/heimdall/commit/5afe0af8553e981fc56a6574def1814854eb0e9a),
jamais à une branche. Le commit inclut les correctifs de revue (refus de
`process` masqué côté JavaScript, `repr` des jetons, auto-ciblage
`os.environ`/`process.env`, directive prologue, chaînage optionnel `?.`,
accès indirects à `os.environ`, évaluation de littéral, clé calculée) ainsi
que les nouvelles garde-fous de la revue #83 : fenêtre de contexte
JavaScript bornée sur le délimiteur ouvrant, évaluation de littéral via
attribut (`builtins.eval`, `__builtins__.exec`) ou via appel (`eval`,
`Function`, `compile`), et refus des imports dynamiques Python
(`__import__`, `importlib.import_module`).

Base des liens :
`https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/`.

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Template Python `os.environ["NOM"]`, échec bruyant si absent | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L89) (`TEMPLATES`), [`#L245`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L245) (`replacement_expression`) | `test_templates_are_closed_and_exact`, `test_python_replaces_only_the_literal_and_adds_import` |
| Template JavaScript `process.env.NOM` | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L89), [`#L1630`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1630) (`_javascript_replacement`) | `test_templates_are_closed_and_exact`, `test_javascript_replaces_only_the_literal` |
| Détection par extension de fichier | [`templates.py#L234`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L234) (`detect_language`) | `test_language_detection_follows_extension`, `test_unknown_extensions_request_manual_remediation` |
| Remplacer le littéral, pas la ligne | [`templates.py#L693](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L693) (Python), [`#L1630`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1630) (JavaScript) | `test_python_replaces_only_the_target_literal_in_a_structure`, `test_javascript_boundaries_remain_valid` |
| Ajouter `import os` si nécessaire, sans casser docstring/futur/décorateur | [`templates.py#L639](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L639) (`_python_import_insertion`) | `test_python_import_goes_after_docstring_and_future_import`, `test_python_import_goes_before_a_decorator`, `test_python_existing_import_is_not_duplicated`, `test_python_import_after_the_target_is_completed_at_the_top` |
| Refus f-string / template literal | [`templates.py#L374](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L374) (`_ambiguous_parent`), [`#L1643](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1643) (contrôle template JS) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus concaténation explicite et implicite | [`templates.py#L528](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L528) (`_single_string_token), [`#L1676](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1676) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus des contextes non remplaçables (docstring, annotation, clé/méthode, import statique) | [`templates.py#L355](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L355) (`_annotation_context), [`#L1721](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1721) (clé d'objet), [`#L1742](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1742) (méthode) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Injection de code par le nom de variable | [`templates.py#L245](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L245) (`replacement_expression`) + grammaire [`#L62`](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L62) | `test_variable_grammar_prevents_code_injection` |
| `os` masqué côté Python et `process` masqué côté JavaScript | [`templates.py#L566](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L566) (`_python_os_status), [`#L1439](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1439) (`_javascript_process_shadowed`) | `test_python_refuses_shadowed_os`, `test_javascript_refuses_shadowed_process` |
| Auto-ciblage d'une clé déjà assainie, directive prologue, chaînage optionnel, clé calculée | [`templates.py#L474](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L474) (`_environment_key_context), [`#L1453](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1453) (`_js_process_env_key), [`#L1482](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1482) (`_js_normalize_optional_chaining), [`#L1520](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1520) (`_js_env_access_present), [`#L1563](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1563) (`_js_computed_process_key), [`#L1607](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L1607) (`_js_standalone_string`) | `test_python_refuses_environment_key_auto_targeting`, `test_javascript_refuses_environment_key_auto_targeting`, `test_javascript_refuses_directive_prologue` |
| Fuite de la valeur par `repr` ou par message d'erreur | [`templates.py#L122](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L122) (`ReplacementPlan), [`#L815](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L815) (`_JsToken.value), [`#L95](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L95) (`TemplateError`) | `test_repr_never_contains_the_secret_or_source`, `test_token_repr_never_contains_the_decoded_secret`, `test_invalid_api_inputs_are_static_errors` |
| Entrées hostiles bornées (mémoire, syntaxe, NUL) | [`templates.py#L51](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L51) (`MAX_SOURCE_BYTES), [`#L58](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L58) (`MAX_JS_TOKENS`) | `test_invalid_api_inputs_are_static_errors`, `test_python_invalid_syntax_and_stale_line_are_manual`, `test_javascript_invalid_and_stale_lines_are_manual` |
| Aucune exécution du code analysé, aucune I/O réseau | [`templates.py](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py) (imports stdlib uniquement), [`#L39](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L39) | `test_module_has_no_execution_or_network_dependency` |
| Remplacement correct sur le repo piège | [`templates.py#L277](https://github.com/Cezar277/heimdall/blob/5afe0af8553e981fc56a6574def1814854eb0e9a/heimdall/remediation/templates.py#L277) (`build_replacement`) | `test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo` (10/10 fuites simples) |

## Résultats locaux — 8 novembre 2026

Environnement de référence : Linux, Python 3.14.6, environnement `.venv` du
dépôt, aucune connexion réseau utilisée.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_templates.py` | 166 passed |
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
  (``?.`` → saut membre, ``?[`` → saut indice) : ``process?.env["NOM"]`,
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
- `_python_code_evaluation_context` refuse tout littéral dont un ancêtre
  d'appel est `eval`/`exec`/`compile`/`__import__` : la valeur d'env ne doit
  pas être ré-évaluée comme du code.
- `_javascript_replacement` refuse tout littéral passé en argument à un appel
  dont le callee est `eval`, `Function` ou `compile` (`eval("SECRET")`,
  `Function("SECRET")`) : la valeur d'environnement ne doit pas être
  ré-évaluée comme du code côté JavaScript.
- `_python_env_access_in` et `_python_call_env_access` traitent les imports
  dynamiques (`__import__("os"`, `importlib.import_module("os")`) comme des
  accès indirects à l'environnement.

## Limites assumées

- #84 : denylist sémantique des noms (`PATH`, `LD_PRELOAD`, `PYTHONPATH`…)
  et dédoublonnage `_2`/`_3` non implémentés ici.
- #85 : le plan n'écrit aucun fichier ; l'application atomique et la
  revalidation du snapshot restent à livrer.
- #86 : la garde de chemin runtime (liens symboliques, TOCTOU) reste à
  livrer ; ce module ne fait que la validation lexicale du contrat Finding.
- JSX et TypeScript sont hors périmètre : leurs extensions sont refusées en
  remédiation manuelle.
