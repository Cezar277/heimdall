# T30.1 (#83) — preuves SAMM

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

Les références ci-dessous donnent **module + ligne** sur l'implémentation
livrée. Au moment d'ouvrir la PR, remplacer le chemin relatif par un permalien
GitHub épinglé au SHA du commit d'implémentation (jamais la branche).

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Template Python `os.environ["NOM"]`, échec bruyant si absent | `heimdall/remediation/templates.py:88` (`TEMPLATES`), `:244` (`replacement_expression`) | `test_templates_are_closed_and_exact`, `test_python_replaces_only_the_literal_and_adds_import` |
| Template JavaScript `process.env.NOM` | `heimdall/remediation/templates.py:88`, `:1012` (`_javascript_replacement`) | `test_templates_are_closed_and_exact`, `test_javascript_replaces_only_the_literal` |
| Détection par extension de fichier | `heimdall/remediation/templates.py:233` (`detect_language`) | `test_language_detection_follows_extension`, `test_unknown_extensions_request_manual_remediation` |
| Remplacer le littéral, pas la ligne | `heimdall/remediation/templates.py:561` (Python), `:1012` (JavaScript) | `test_python_replaces_only_the_target_literal_in_a_structure`, `test_javascript_boundaries_remain_valid` |
| Ajouter `import os` si nécessaire, sans casser docstring/futur/décorateur | `heimdall/remediation/templates.py:507` (`_python_import_insertion`) | `test_python_import_goes_after_docstring_and_future_import`, `test_python_import_goes_before_a_decorator`, `test_python_existing_import_is_not_duplicated`, `test_python_import_after_the_target_is_completed_at_the_top` |
| Refus f-string / template literal | `heimdall/remediation/templates.py:373` (`_ambiguous_parent`), `:1026` (contrôle template JS) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus concaténation explicite et implicite | `heimdall/remediation/templates.py:396` (`_single_string_token`), `:1046` | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Refus des contextes non remplaçables (docstring, annotation, clé/méthode, import statique) | `heimdall/remediation/templates.py:354` (`_annotation_context`), `:1072` (clé d'objet), `:1091` (méthode) | `test_python_refuses_ambiguous_or_absent_cases`, `test_javascript_refuses_ambiguous_or_absent_cases` |
| Injection de code par le nom de variable | `heimdall/remediation/templates.py:244` (`replacement_expression`) + grammaire `:61` | `test_variable_grammar_prevents_code_injection` |
| `os` masqué dans le fichier Python | `heimdall/remediation/templates.py:434` (`_python_os_status`) | `test_python_refuses_shadowed_os` |
| Fuite de la valeur par `repr` ou par message d'erreur | `heimdall/remediation/templates.py:121` (`ReplacementPlan`), `:94` (`TemplateError`) | `test_repr_never_contains_the_secret_or_source`, `test_invalid_api_inputs_are_static_errors` |
| Entrées hostiles bornées (mémoire, syntaxe, NUL) | `heimdall/remediation/templates.py:50` (`MAX_SOURCE_BYTES`), `:561`, `:1012` | `test_invalid_api_inputs_are_static_errors`, `test_python_invalid_syntax_and_stale_line_are_manual` |
| Aucune exécution du code analysé, aucune I/O réseau | `heimdall/remediation/templates.py` (imports stdlib uniquement), `:561`, `:895` | `test_module_has_no_execution_or_network_dependency` |
| Remplacement correct sur le repo piège | `heimdall/remediation/templates.py:276` (`build_replacement`) | `test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo` (10/10 fuites simples) |

## Résultats locaux — 8 novembre 2026

Environnement de référence : Linux, Python 3.14.6, environnement `.venv` du
dépôt, aucune connexion réseau utilisée.

| Contrôle | Résultat |
| --- | --- |
| `pytest tests/test_remediation_templates.py` | 104 passed |
| `pytest tests/test_remediation_templates.py --cov=heimdall.remediation --cov-branch --cov-fail-under=70` | couverture du module 76,73 % (seuil critique 70 %) |
| `pytest --cov=heimdall --cov-branch --cov-fail-under=85` | 2924 passed, 15 skipped, 4516 sous-tests ; couverture globale 90,32 % |
| `ruff check heimdall tests scripts` | succès |
| `ruff format --check heimdall/remediation tests/test_remediation_templates.py` | succès |
| `mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py` | 52 fichiers, aucune erreur |
| `bandit -r heimdall -q` | succès (aucun constat) |

Toutes les valeurs des tests sont synthétiques. Aucun fichier du corpus piège
n'est modifié sur disque : les plans sont calculés en mémoire. La PR, la
relecture croisée et la CI distante restent à réaliser ; aucun merge sur
`main` n'est effectué par ce ticket.

## Limites assumées

- #84 : denylist sémantique des noms (`PATH`, `LD_PRELOAD`, `PYTHONPATH`…)
  et dédoublonnage `_2`/`_3` non implémentés ici.
- #85 : le plan n'écrit aucun fichier ; l'application atomique et la
  revalidation du snapshot restent à livrer.
- #86 : la garde de chemin runtime (liens symboliques, TOCTOU) reste à
  livrer ; ce module ne fait que la validation lexicale du contrat Finding.
- JSX et TypeScript sont hors périmètre : leurs extensions sont refusées en
  remédiation manuelle.
