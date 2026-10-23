# T34 — preuves SAMM et validation

Périmètre : #34 et #91, #92, #93, #94, #95, #96, #97, regroupés dans la
branche T34 à la demande du porteur. Cette fiche documente les preuves ;
elle ne modifie pas une feuille SAMM externe et ne remplace pas la revue humaine.

Révision de l'implémentation : `6bdaa89ee5230f125261bb9e2614dd480d5feb9c`.
Les liens ci-dessous sont permanents. Après squash/merge, épingler aussi
le SHA final dans la présente fiche, le rapport et la feuille externe.
Ce SHA identifie le dernier commit modifiant le code testé ; un commit
ultérieur limité à cette fiche ne change pas les preuves d’implémentation.
| Exigence / sous-ticket | Preuve (module + ligne) | Validation |
|---|---|---|
| Corpus, 5 commentaires, 5 chaînes/noms, 5 demandes MCP (#91–#94) | [tests/fixtures/injection/README.md:1](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/fixtures/injection/README.md#L1), [test_corpus_has_five_cases_per_family:72](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L72) | 15 fichiers ; détection réelle du jeton synthétique et masquage avant qualification |
| Isolation système/utilisateur et échappement des délimiteurs (#95) | [build_messages:111](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/heimdall/mcp/prompts/__init__.py#L111), [test de collision:136](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L136) | système inchangé ; nonce renouvelé ; fermeture forgée échappée même en cas de collision |
| Schéma fermé et refus des actions (#96) | [QualifyVerdict:112](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/heimdall/llm/qualify.py#L112), [validation JSON et appels natifs:218](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/heimdall/llm/qualify.py#L218) | champs supplémentaires, clés dupliquées et tool_calls natifs rejetés ; journal statique |
| Moindre privilège MCP (#34/#96) | [registre:57](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/heimdall/mcp/server.py#L57), [tests stdio:241](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L241) | 7 appels d'outils/arguments/chemins hostiles refusés par le serveur réel |
| Aucun secret écarté, aucun effet de bord (#97, REQ-SEC-01) | [modèle hostile:83](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L83) | 45 combinaisons payload/réponse ; Finding et fichier inchangés ; aucune valeur sensible dans les messages ou logs |
| Corpus sur chaque PR et preuve locale optionnelle (#97) | [workflow:1](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/.github/workflows/prompt-injection.yml#L1), [test llm:255](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L255) | CI déterministe ; 15 tests réels uniquement sur activation manuelle |
| Écriture des fixtures confinée (revue LOW) | [garde:38](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L38), [noms hostiles:55](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L55), [symlink sortant:61](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L61) | aucun séparateur, chemin traversant ou lien sortant accepté avant écriture |
| Cas limites du protocole (revue) | [balise incomplète:151](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L151), [nonce frais:159](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L159), [doublon imbriqué:188](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L188), [types tool_calls:209](https://github.com/Cezar277/heimdall/blob/6bdaa89ee5230f125261bb9e2614dd480d5feb9c/tests/test_prompt_injection_corpus.py#L209) | casse mixte, balises incomplètes et doublons imbriqués testés ; seuls None et [] autorisés pour tool_calls |

## Résultats locaux du 23 octobre 2026

Debian/WSL, Python 3.13.5, environnement virtuel isolé, dépendances de
`requirements.lock` installées avec vérification des hashes SHA-256.

```text
python -m pytest tests/test_prompt_injection_corpus.py tests/test_llm_qualify.py
220 passed, 15 skipped

python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
1665 passed, 16 skipped, 7 warnings, 4389 subtests passed
Total coverage: 96.18% ; qualify.py et mcp/prompts/__init__.py : 100%

python -m pytest tests/test_prompt_injection_corpus.py
88 passed, 15 skipped

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
trouve dans la valeur elle-même et les 28 cas de régression ajoutés après
revue. Les 15 tests T34 `llm` ont été ignorés
volontairement : aucune preuve d'exécution avec le modèle réel n'est revendiquée.
Le seizième skip de la suite complète est le test Ollama existant. Les sept
avertissements concernent des connexions SQLite non fermées dans les tests
Vault existants sous Python 3.13.

La validation principale se fait sous Linux : le dépôt utilise des
primitives POSIX (`O_NOFOLLOW`, `fchmod`, etc.). Sous Windows, le lock
Linux exige en plus `colorama` et `pywin32` ; lors de la livraison initiale,
185 tests de qualification et de corpus sans la frontière MCP y passaient.
Aucun changement de
portabilité hors périmètre n'a été ajouté.

À compléter par les humains : revue du prompt (#95), approbation par un
autre domaine, preuve des checks GitHub après publication et report des
permaliens dans la feuille SAMM. Aucun ticket n'est fermé automatiquement.

## Dérogation de regroupement

La demande explicite de traiter tous les sous-tickets de T34 sur la branche
parent est tracée [sur le ticket #34](https://github.com/Cezar277/heimdall/issues/34#issuecomment-6369558936),
hors de la description de PR. Dérogation limitée à cette livraison : la règle
« une PR = un sous-ticket » reste applicable aux autres tickets. La revue
humaine avant fusion reste obligatoire.

## Ré-épinglage après squash/merge

La [PR #168](https://github.com/Cezar277/heimdall/pull/168) n'est pas fusionnée
lors de cette validation. Son futur SHA de squash ne peut pas être renseigné
à l'avance. Après fusion :

1. Relever le SHA complet du commit de fusion affiché sur la PR fusionnée.
2. Remplacer la révision d'implémentation et les SHA des permaliens de cette
   fiche par ce SHA. Vérifier les ancres de ligne sur chaque fichier fusionné
   (un squash ou une résolution de conflit peut déplacer les lignes).
3. Reporter les mêmes couples module + ligne et permaliens dans la feuille
   SAMM externe et le rapport, puis publier la mise à jour documentaire.

Les permaliens présents restent reproductibles sur la révision corrigée
pré-fusion. Ils ne sont pas présentés comme des preuves du futur squash.
