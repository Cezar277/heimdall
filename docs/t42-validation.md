# T42 — relevé d'exécution et preuves pour le rapport

Date : **25 octobre 2026**. Ticket [#42](https://github.com/Cezar277/heimdall/issues/42).
Code testé : `ad54f025e224c5d3cdfa824a1117b5c616cc6e13`, base de la branche
`42-t42-consolidation-samm-v1-et-matrice-d-acceptation` après `git fetch origin`.
Les changements T42 portent uniquement sur les documents et résultats archivés.

Livrables : [consolidation SAMM v1](samm-v1.md),
[matrice d'acceptation](Functional_and_security_Acceptance_Testing_Case.md),
[comptes machine](acceptance/results.json),
[vérification des permaliens historiques](acceptance/samm-link-audit.json).
La feuille externe est exclue à la demande du porteur ; aucun report dans
une application externe n'est revendiqué.

## Environnement et provenance

- Debian sous WSL, Python **3.13.5**, système POSIX conforme à la cible Vault.
- Dépôt : `/mnt/c/Users/user/project` (chemin anonymisé).
- Interpréteur : `/home/user/.venv/bin/python` (chemin anonymisé).
- Environnement virtuel existant : toutes les versions directes runtime et
  `dev` de `pyproject.toml` ont été comparées aux versions installées, sans écart.
  `pip check` réussit. Aucune nouvelle installation avec hashes n'est revendiquée
  par T42 ; le protocole d'installation vérifiée reste celui du README.
- L'import de `heimdall` pointe vers le dépôt testé, vérifié avant l'archivage.
- Les tests emploient des valeurs synthétiques, des bases temporaires et les
  transports de test du dépôt. Aucun secret utilisateur ni Vault réel utilisé.

## Résultats du 25 octobre 2026

| Contrôle | Code | Résultat |
| --- | --- | --- |
| Suite complète, couverture branches incluse | 0 | **2 211 passed, 16 skipped, 4 480 subtests passed**, 7 warnings ; 251,17 s |
| Couverture globale | 0 | **91,29 %**, seuil **85 %** atteint |
| `python -m pip check` | 0 | Aucune dépendance incompatible |
| `python -m ruff check heimdall tests` | 0 | Aucune erreur |
| `python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py` | 0 | 45 fichiers, aucune erreur |
| `python -m bandit -r heimdall -q` | 0 | Aucun résultat |
| `python docs/security/check_model.py` | 0 | 48 scénarios STRIDE, 10 risques/exigences liés, cohérence du DFD ; preuve documentaire uniquement |
| `python tests/measure_trap.py` | **1** | Précision core **55,56 %**, rappel **100 %** ; seuil de précision **90 % non atteint** |
| Permaliens des 14 fiches SAMM historiques | Conforme après correction | 744 occurrences vérifiées ; 1 plage corrigée dans T22 |
| Cohérence des nouveaux livrables | Conforme | 56 nouveaux permaliens et liens locaux vérifiés ; 25 verdicts cohérents avec le JSON, 46 modules affectés sans double compte |
| `git diff --check` | 0 | Aucun défaut d'espacement |

La [sortie pytest complète](acceptance/pytest.log) et les
[autres contrôles avec codes de sortie](acceptance/checks.log) sont archivés.
Les sept avertissements concernent des connexions SQLite non fermées dans
les tests existants ; ils ne sont pas présentés comme corrigés.
Les [comptes JSON](acceptance/results.json) proviennent du XML JUnit de cette
exécution : ventilation exhaustive par module et par groupe sans double compte.
Une seconde exécution de revue archive désormais le [XML JUnit expurgé](acceptance/junit.xml)
et sa [sortie pytest anonymisée](acceptance/pytest-replay.log). Ses comptes
par module sont comparés à ceux du relevé initial avant publication.
Le SHA-256 de ce XML figure dans `results.json` ; le hash de l'ancien XML
temporaire est conservé comme provenance historique, sans prétendre le reconstruire.
Les chemins locaux sont remplacés par des chemins génériques dans les pièces
publiées ; le nom d'hôte et les valeurs de paramètres des noms de tests sont
retirés du XML. Les verdicts et comptes ne sont pas modifiés par cette expurgation.

## Reproduire

Depuis une installation POSIX du SHA testé, suivre d'abord l'installation
avec hashes du README. Activer cet environnement puis lancer depuis la racine :

```sh
python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing \
  --cov-fail-under=85 --junitxml=/tmp/heimdall-t42-pytest.xml
python -m pip check
python -m ruff check heimdall tests
python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py
python -m bandit -r heimdall -q
python docs/security/check_model.py
python tests/measure_trap.py  # code 1 attendu : critère produit non satisfait
python docs/acceptance/recount_junit.py
git diff --check
```

L'exécution complète archivée a utilisé ces options pytest et l'interpréteur
indiqué plus haut, avec redirection vers `/tmp/heimdall-t42-pytest.log`.
La mesure du corpus a été archivée séparément dans
[`acceptance/trap-report.json`](acceptance/trap-report.json).
`checks.log` a été régénéré pendant la revue sur `160ee91` avec le même
code runtime que `ad54f025` : les modifications entre ces révisions sont
uniquement documentaires, vérifiées par `git diff ad54f025 160ee91 -- heimdall tests`.
Pour vérifier les 744 permaliens, la méthode et le périmètre exact sont
décrits dans [samm-v1.md](samm-v1.md).

La ventilation JSON se recalcule depuis les éléments JUnit `testcase` :
le module est le préfixe de `classname` jusqu'à `test_*`, converti en chemin
`.py` ; `failure`/`error`/`skipped` priment sur `passed`. Les groupes utilisent
les sélecteurs `selectors` de `results.json`. Les 46 modules sont affectés
une seule fois aux 19 groupes automatisés ; les 6 critères supplémentaires
proviennent de la mesure indépendante et de l'inspection, pas de pytest.
Le vérificateur versionné `recount_junit.py` recalcule les comptes depuis le
XML versé, vérifie son SHA-256, les sélecteurs, les verdicts des groupes et
l'affectation exhaustive sans doublon. Il ne prouve ni la couverture globale
ni l'authenticité d'une exécution distante : AC-24 reste une condition distincte.
Dans ce XML pytest, l'attribut `testsuite.tests=6707` inclut les 4 480
sous-tests : il correspond à 2 211 réussites + 16 skips + 4 480 sous-tests.
Le vérificateur ventile les 2 227 éléments `testcase` par module et vérifie
séparément cette différence ; il ne compte pas les sous-tests deux fois.

Résultat du rejeu de revue : **2 211 passed, 16 skipped, 7 warnings,
4 480 subtests passed**, couverture **91,29 %**, durée **262,76 s**.
Les verdicts de la matrice restent inchangés ; `pytest.log` et la durée
251,17 s du tableau initial restent le relevé de la première exécution.

Pour le rejeu de revue, `TMPDIR=/tmp/heimdall-t42-review` est créé puis exporté
avant pytest. Les sorties brutes restent hors des pièces versionnées ; les
chemins publiés sont anonymisés après capture, y compris ceux de la venv
dans les avertissements. Le répertoire temporaire générique ne suffit pas à
anonymiser à lui seul le chemin de l'interpréteur.

## Réserves et livraison

Les limites détaillées, critères manquants, tickets et actions sont dans
AC-07 et AC-20 à AC-25. En particulier : précision insuffisante connue depuis
T23 ; preuves Ollama réelles ignorées ; dépendance #39 ouverte et audit complet
non attesté ; remplacement/validation humaine non intégrés ; enveloppe complète
non implémentée ; trace OS zéro egress non rejouée.
La mise à jour documentaire ne tente pas de corriger ces fonctionnalités.

Le résultat attendu de T42 est un état vérifiable, y compris ses échecs.
L'acceptation globale du MVP reste **non acquise**. Le ticket #43/#125 peut
reprendre ces pièces comme annexe en conservant les réserves.
La revue croisée D, la preuve de runner éphémère et le check distant
`CI (/ci)` sur une PR restent à obtenir avant merge. Le suivi distant est
archivé séparément dans [la fiche de revue](t42-review.md) ; un lancement
de `/ci` ne vaut pas résultat vert. Aucun merge, clôture de ticket ou
approbation humaine n'est effectué ici.
