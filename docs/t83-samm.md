# T30.1 (#83) — preuves SAMM

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous sont des **permaliens GitHub épinglés au SHA du
commit d'implémentation** [`ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef`](https://github.com/Cezar277/heimdall/commit/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef),
jamais à une branche. Le commit inclut les correctifs de revue (refus de
`process` masqué côté JavaScript, `repr` des jetons, auto-ciblage
`os.environ`/`process.env`, directive prologue, chaînage optionnel `?.`,
accès indirects à `os.environ`, évaluation de littéral, clé calculée,
fenêtre de contexte JavaScript bornée sur le délimiteur ouvrant, évaluation
de littéral via attribut (`builtins.eval`, `__builtins__.exec`) ou via appel
(`eval`, `Function`, `compile`), refus des imports dynamiques Python
(`__import__`, `importlib.import_module`)) ainsi que les garde-fous de la
dernière revue : évaluation curryfiée Python (`getattr(__builtins__,
"eval")(...)` via `_call_resolves_to_eval`), récepteurs d'espace de noms
(`vars()`/`locals()`/`globals()` en position `Subscript`), appels
d'évaluation JavaScript optionnels (`eval?.(...)`) et indirects
(`(0, eval)(...)`) via `_js_code_evaluation_call`, et `setTimeout`/
`setInterval` à premier argument chaîne refusés comme `eval`.

Base des liens :
`https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/`.

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Template Python `os.environ["NOM"]`, échec bruyant si absent | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L89) (`TEMPLATES`), [`#L245`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L245) (`replacement_expression`) | `test_templates_are_closed_and_exact`, `test_python_replaces_only_the_literal_and_adds_import` |
| Template JavaScript `process.env.NOM` | [`templates.py#L89`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L89), [`#L1734`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1734) (`_javascript_replacement`) | `test_templates_are_closed_and_exact`, `test_javascript_replaces_only_the_literal` |
| Détection par extension de fichier | [`templates.py#L234`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L234) (`detect_language`) | `test_language_detection_follows_extension`, `test_unknown_extensions_request_manual_remediation` |
| Remplacer le littéral, pas la ligne | [`templates.py#L730`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L730) (Python), [`#L1734`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1734) (JavaScript) | `test_python_replaces_only_the_target_literal_in_a_structure`, `test_javascript_boundaries_remain_valid` |
| Ajouter `import os` si nécessaire, sans casser docstring/futur/décorateur | [`templates.py#L676`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L676) (`_python_import_insertion`) | `test_python_import_goes_after_docstring_and_future_import`, `test_python_import_goes_before_a_decorator`, `test_python_existing_import_is_not_duplicated`, `test_python_import_after_the_target_is_completed_at_the_top` |
| Refus f-string / template literal | [`templates.py#L374`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L374) (`_ambiguous_parent`), [`#L1752`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1752) (contrôle template JS) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus concaténation explicite et implicite | [`templates.py#L565`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L565) (`_single_string_token`), [`#L1780`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1780) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus des contextes non remplaçables (docstring, annotation, clé/méthode, import statique) | [`templates.py#L355`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L355) (`_annotation_context`), [`#L1821`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1821) (clé d'objet), [`#L1840`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1840) (méthode) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Injection de code par le nom de variable | [`templates.py#L245`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L245) (`replacement_expression`) + grammaire [`#L62`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L62) | `test_variable_grammar_prevents_code_injection` |
| `os` masqué côté Python et `process` masqué côté JavaScript | [`templates.py#L603`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L603) (`_python_os_status`), [`#L1476`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1476) (`_javascript_process_shadowed`) | `test_python_refuses_shadowed_os`, `test_javascript_refuses_shadowed_process` |
| Auto-ciblage d'une clé déjà assainie, directive prologue, chaînage optionnel, clé calculée | [`templates.py#L471`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L471) (`_environment_key_context`), [`#L1490`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1490) (`_js_process_env_key`), [`#L1523`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1523) (`_js_normalize_optional_chaining`), [`#L1561`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1561) (`_js_env_access_present`), [`#L1604`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1604) (`_js_computed_process_key`), [`#L1650`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1650) (`_js_standalone_string`) | `test_python_refuses_environment_key_auto_targeting`, `test_javascript_refuses_environment_key_auto_targeting`, `test_javascript_refuses_directive_prologue` |
| Évaluation curryfiée Python (`getattr(__builtins__, "eval")(...)`) et récepteurs d'espace de noms (`vars()`/`locals()`/`globals()` en `Subscript`) | [`templates.py#L511`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L511) (`_CODE_EVALUATION_FUNCS`), [`#L514`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L514) (`_NAMESPACE_READER_FUNCS`), [`#L517`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L517) (`_call_resolves_to_eval`) | `test_python_refuses_ambiguous_or_absent_cases` (cas `getattr(__builtins__, "eval")`, `getattr(b, "exec")`, `vars()`, `locals()`) |
| Évaluation JavaScript optionnelle (`eval?.(...)`), indirecte (`(0, eval)(...)`) et `setTimeout`/`setInterval` à premier argument chaîne | [`templates.py#L1674`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1674) (`_JS_EVAL_CALLEES`), [`#L1682`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L1682) (`_js_code_evaluation_call`) | `test_javascript_refuses_ambiguous_or_absent_cases` (cas `eval?.`, `Function?.`, `(0, eval)`, `setTimeout`, `setInterval`) |
| Fuite de la valeur par `repr` ou par message d'erreur | [`templates.py#L122`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L122) (`ReplacementPlan`), [`#L857`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L857) (`_JsToken.value`), [`#L95`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L95) (`TemplateError`) | `test_repr_never_contains_the_secret_or_source`, `test_token_repr_never_contains_the_decoded_secret`, `test_invalid_api_inputs_are_static_errors` |
| Entrées hostiles bornées (mémoire, syntaxe, NUL) | [`templates.py#L51`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L51) (`MAX_SOURCE_BYTES`), [`#L58`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L58) (`MAX_JS_TOKENS`) | `test_invalid_api_inputs_are_static_errors`, `test_python_invalid_syntax_and_stale_line_are_manual`, `test_javascript_invalid_and_stale_lines_are_manual` |
| Aucune exécution du code analysé, aucune I/O réseau | [`templates.py`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py) (imports stdlib uniquement), [`#L39`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L39) | `test_module_has_no_execution_or_network_dependency` |
| Remplacement correct sur le repo piège | [`templates.py#L277`](https://github.com/Cezar277/heimdall/blob/ddb1bd49071e9b89cd2443d16da7f9cbcd2fb2ef/heimdall/remediation/templates.py#L277) (`build_replacement`) | `test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo` (10/10 fuites simples) |

## Résultats locaux — 11 novembre 2026

Environnement de référence : Linux, Python 3.14.6, environnement `.venv` du
dépôt, aucune connexion réseau utilisée.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_templates.py` | 176 passed |
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
- `_python_code_evaluation_context` (via `_call_resolves_to_eval`) refuse tout
  littéral dont un ancêtre d'appel résout une fonction d'évaluation, y compris
  curryfié (`getattr(__builtins__, "eval")("NOM")`, `getattr(b,
  "exec")("NOM")`) : la valeur d'env ne doit pas être ré-évaluée comme du
  code. Les récepteurs d'espace de noms (`vars()`, `locals()`, `globals()`,
  `dir()`) en position `Subscript` sont refusés de la même façon.
- `_js_code_evaluation_call` refuse tout littéral premier argument d'un appel
  d'évaluation : formes directes (`eval("NOM")`, `Function("NOM")`),
  optionnelles (`eval?.("NOM")`, `Function?.("NOM")`, le `?.` tokenizé en `?`
  + `.` est sauté avant le test) et indirectes (`(0, eval)("NOM")`, séquence
  `,` + ident + `)` + `(`), ainsi que `setTimeout("NOM", ...)` et
  `setInterval("NOM", ...)` dont le premier argument chaîne serait évalué
  comme du code.
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
