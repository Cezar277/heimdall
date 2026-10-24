# T23 — preuves pour la ligne SAMM

Ticket : [#23](https://github.com/Cezar277/heimdall/issues/23).
Révision du code testé : `0ebc66194973c508ba5e81686d316482d3e50224`.
Cette fiche archive les preuves ; elle ne modifie pas une feuille externe.
La relecture et le merge restent à effectuer par l'équipe.

| Exigence | Implémentation permanente | Test permanent |
| --- | --- | --- |
| Shannon, alphabet hex/base64, seuils validés | [entropy_detection.py:36](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/heimdall/scanner/entropy_detection.py#L36), [détection:62](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/heimdall/scanner/entropy_detection.py#L62) | [tests/test_scanner_entropy.py:25](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/tests/test_scanner_entropy.py#L25), [seuils:44](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/tests/test_scanner_entropy.py#L44) |
| Cinq lignes de contexte avant/après, sans étendre Finding | [entropy_detection.py:122](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/heimdall/scanner/entropy_detection.py#L122) | [tests/test_scanner_entropy.py:117](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/tests/test_scanner_entropy.py#L117) |
| Affectation incomplète au-delà de 4 Kio : refus statique | [entropy_detection.py:101](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/heimdall/scanner/entropy_detection.py#L101) | [tests/test_scanner_entropy.py:140](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/tests/test_scanner_entropy.py#L140), tests existants des deux moteurs mis à jour |
| UTF-8 invalide dans un candidat : refus statique | [exclusions.py](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/heimdall/scanner/exclusions.py) | [tests/test_scanner_entropy.py:134](https://github.com/Cezar277/heimdall/blob/0ebc66194973c508ba5e81686d316482d3e50224/tests/test_scanner_entropy.py#L134) |

La mesure T21 est décrite dans [scanner-entropy.md](scanner-entropy.md) :
oracle inchangé, 34 cas, aucune fausse alerte sur les 18 non-secrets ;
`core` VP=10/FP=0/FN=0, précision=1,00, rappel=1,00 ;
`all` VP=12/FP=0/FN=4, précision=1,00, rappel=0,75.

Commandes de validation locale, depuis la racine, sous Debian/WSL
(Python 3.13.5 ; environnement de test existant) :

```sh
python -m ruff check heimdall tests scripts
python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
python -m bandit -q -r heimdall
python -m pytest --cov=heimdall --cov-branch --cov-report=term --cov-fail-under=85 --tb=short
PYTHONPATH=. python tests/measure_trap.py
```

Ruff, mypy strict et Bandit : succès local. Aucun déclenchement distant
de `/ci` n'est demandé ; la validation ci-dessus est locale.

Suite complète finale : commande terminée avec le code 0, seuil de
couverture de 85 % satisfait (couverture globale arrondie : 92 % ; nouveau
module `entropy_detection.py` : 95 %). Les tests nécessitant un Ollama local
ou une activation manuelle conservent leurs skips prévus. Les 41 tests
spécifiques de `test_scanner_entropy.py` passent également seuls.
