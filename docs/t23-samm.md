# T23 — preuves après revue REQUEST CHANGES

Ticket : [#23](https://github.com/Cezar277/heimdall/issues/23).
Révision corrigée : `da8c4b618ee150d39be17a318d8f204161d5bbb4`.
Cette fiche remplace les preuves de la première livraison `0ebc661` : ses
filtres digest/data URI/UUID et sa surface de contexte brut sont supprimés.
La feuille SAMM externe n'est pas modifiée ; relecture et merge restent à
effectuer par l'équipe. Aucun `/ci` distant n'est déclenché.

| Exigence | Code permanent | Preuve permanente |
| --- | --- | --- |
| Seuils validés, rejet bool/NaN/inf | [entropy_detection.py:26](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L26) | [tests/test_scanner_entropy.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py) |
| Aucune exclusion implicite digest/data URI/UUID | [entropy_detection.py:61](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L61) | [abus sur les deux moteurs:135](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L135) |
| Fenêtre multiligne : garde indépendante du fournisseur | [entropy_detection.py:106](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L106) | [Stripe/Slack/PAT/JWT/inconnu:153](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L153) |
| Entrées directes invalides : ScanError statique | [entropy_detection.py:61](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L61) | [tests/test_scanner_entropy.py:168](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L168) |
| Jeton > 4096 refusé avant Shannon/signatures, deadline intra-ligne | [entropy_detection.py:50](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L50) | [test 1 Mio:173](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L173), [deadline:183](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L183), [borne inclusive:202](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L202) |
| Source explicite, collision avec Rule.id="entropy" sans effet | [signatures/__init__.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/signatures/__init__.py) | [règle réelle renommée:231](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L231) |
| Types génériques gouvernés par l'ensemble fermé | [signatures/model.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/signatures/model.py) | [test du registre](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_signatures.py#L306) |
| Surface de contexte brut supprimée, Finding sérialisé sans clair | [entropy_detection.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py) | [absence API et json.dumps(asdict):244](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L244) |

Le contexte ±5 lignes demandé initialement est différé, conformément à la
revue : aucun consommateur ne justifie cette nouvelle surface sensible.
Le comportement UTF-8 strict déjà livré reste couvert par les tests des
fichiers et de la CLI (faux PNG : erreur code 2, jamais propre).

## Mesure T21 : résultat non masqué

[Rapport JSON archivé](t23-trap-report.json), oracle inchangé, 34 cas dont
18 non-secrets. Huit faux positifs : UUID, SHA-256, commit et intégrité,
dans chacun des deux langages.

| Périmètre | VP | FP | FN | Précision | Rappel |
| --- | --- | --- | --- | --- | --- |
| core | 10 | 8 | 0 | 55,56 % | 100 % |
| all | 12 | 8 | 4 | 60 % | 75 % |

`PYTHONPATH=. python tests/measure_trap.py` retourne **1** : le seuil de
précision T21 de 90 % est conservé et n'est pas atteint. Le test de régression
vérifie les comptes exacts, sans altérer l'oracle ni retirer des faux positifs.
Une suite pytest verte n'atteste pas l'atteinte de ce seuil. La réduction des
faux positifs exige une allowlist explicite et auditée (#24), pas une étiquette
contrôlée par le commiteur.

## Validation locale

Debian/WSL, Python 3.13.5, environnement de test existant :

```sh
python -m ruff check heimdall tests scripts
python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
python -m bandit -q -r heimdall
python -m pytest --cov=heimdall --cov-branch --cov-report=term --cov-fail-under=85 --tb=short
PYTHONPATH=. python tests/measure_trap.py  # attendu : code 1, précision < 90 %
```

Ruff, mypy strict et Bandit passent. Les 466 tests ciblés scanner, CLI et
corpus passent. Les skips de tests Ollama/manuels ne constituent pas des
preuves d'exécution du modèle local.

Suite complète sur la révision corrigée : **1937 passed, 16 skipped**,
4480 sous-tests passés, 7 avertissements ; couverture globale branches
incluses **91,98 %** (seuil 85 % satisfait), durée 204,10 s, code de sortie 0.
Le rapport de mesure T21 reste distinct et retourne 1, comme détaillé plus haut.
