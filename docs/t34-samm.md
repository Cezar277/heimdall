# T34 — preuves SAMM et validation

Périmètre : #34 et #91, #92, #93, #94, #95, #96, #97, regroupés dans la
branche T34 à la demande du porteur. Cette fiche documente les preuves ;
elle ne modifie pas une feuille SAMM externe et ne remplace pas la revue humaine.

Révision de l'implémentation : `c7303327f7e87e4ff50ce01dc4c43b49733af312`.
Les liens ci-dessous sont permanents. Après squash/merge, épingler aussi
le SHA final dans le rapport et la feuille externe.

| Exigence / sous-ticket | Preuve (module + ligne) | Validation |
|---|---|---|
| Corpus, 5 commentaires, 5 chaînes/noms, 5 demandes MCP (#91–#94) | [tests/fixtures/injection/README.md:1](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/fixtures/injection/README.md#L1), [test_corpus_has_five_cases_per_family:38](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/test_prompt_injection_corpus.py#L38) | 15 fichiers ; détection réelle du jeton synthétique et masquage avant qualification |
| Isolation système/utilisateur et échappement des délimiteurs (#95) | [build_messages:111](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/heimdall/mcp/prompts/__init__.py#L111), [test de collision:101](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/test_prompt_injection_corpus.py#L101) | système inchangé ; nonce renouvelé ; fermeture forgée échappée même en cas de collision |
| Schéma fermé et refus des actions (#96) | [QualifyVerdict:112](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/heimdall/llm/qualify.py#L112), [validation JSON et appels natifs:218](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/heimdall/llm/qualify.py#L218) | champs supplémentaires, clés dupliquées et tool_calls natifs rejetés ; journal statique |
| Moindre privilège MCP (#34/#96) | [registre:57](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/heimdall/mcp/server.py#L57), [tests stdio:154](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/test_prompt_injection_corpus.py#L154) | 7 appels d'outils/arguments/chemins hostiles refusés par le serveur réel |
| Aucun secret écarté, aucun effet de bord (#97, REQ-SEC-01) | [modèle hostile:49](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/test_prompt_injection_corpus.py#L49) | 45 combinaisons payload/réponse ; Finding et fichier inchangés ; aucune valeur sensible dans les messages ou logs |
| Corpus sur chaque PR et preuve locale optionnelle (#97) | [workflow:1](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/.github/workflows/prompt-injection.yml#L1), [test llm:168](https://github.com/Cezar277/heimdall/blob/c7303327f7e87e4ff50ce01dc4c43b49733af312/tests/test_prompt_injection_corpus.py#L168) | CI déterministe ; 15 tests réels uniquement sur activation manuelle |

## Résultats locaux du 23 octobre 2026

Debian/WSL, Python 3.13.5, environnement virtuel isolé, dépendances de
`requirements.lock` installées avec vérification des hashes SHA-256.

```text
python -m pytest tests/test_prompt_injection_corpus.py tests/test_llm_qualify.py
192 passed, 15 skipped

python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
1637 passed, 16 skipped, 7 warnings, 4389 subtests passed
Total coverage: 96.18% ; qualify.py et mcp/prompts/__init__.py : 100%

python -m pytest tests/test_prompt_injection_corpus.py
60 passed, 15 skipped

python -m ruff check heimdall tests
All checks passed!

python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py
Success: no issues found in 40 source files

python -m bandit -r heimdall -q
aucun résultat, code 0

python -m pip_audit --skip-editable
No known vulnerabilities found
```

La dernière exécution du corpus inclut la variante où l'instruction se
trouve dans la valeur elle-même. Les 15 tests T34 `llm` ont été ignorés
volontairement : aucune preuve d'exécution avec le modèle réel n'est revendiquée.
Le seizième skip de la suite complète est le test Ollama existant. Les sept
avertissements concernent des connexions SQLite non fermées dans les tests
Vault existants sous Python 3.13.

La validation principale se fait sous Linux : le dépôt utilise des
primitives POSIX (`O_NOFOLLOW`, `fchmod`, etc.). Sous Windows, le lock
Linux exige en plus `colorama` et `pywin32` ; 185 tests de qualification et
de corpus sans la frontière MCP y passent également. Aucun changement de
portabilité hors périmètre n'a été ajouté.

À compléter par les humains : revue du prompt (#95), approbation par un
autre domaine, preuve des checks GitHub après publication et report des
permaliens dans la feuille SAMM. Aucun ticket n'est fermé automatiquement.
