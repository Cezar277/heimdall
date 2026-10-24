# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

## En une phrase

Allowlist déterministe et traçable permettant d'écarter les cas évidents
(`example`, `changeme`, `dummy`, fixtures de test) sans passer par le LLM,
avec journalisation systématique de chaque rejet (règle, fichier, ligne)
et affichage permanent du nombre de findings ignorés dans les rapports local et CI.

## Invariants de sécurité et exigences vérifiées

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`) | [`heimdall/scanner/allowlist.py:233–242`](../heimdall/scanner/allowlist.py), [`heimdall.toml:10–13`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:118–144`](../tests/test_scanner_allowlist.py) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`heimdall/scanner/allowlist.py:243–247`](../heimdall/scanner/allowlist.py), [`heimdall.toml:15–18`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:147–162`](../tests/test_scanner_allowlist.py) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`heimdall/scanner/allowlist.py:248–252`](../heimdall/scanner/allowlist.py), [`heimdall.toml:20–23`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:165–180`](../tests/test_scanner_allowlist.py) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures et mocks factices délimités aux tests | [`heimdall/scanner/allowlist.py:253–272`](../heimdall/scanner/allowlist.py), [`heimdall.toml:25–39`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:183–200`](../tests/test_scanner_allowlist.py) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`heimdall/scanner/allowlist.py:130–166`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:203–221`](../tests/test_scanner_allowlist.py) | Une vraie clé AWS sous `tests/` sans marqueur factice reste détectée et bloque |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`heimdall/scanner/allowlist.py:199–224`](../heimdall/scanner/allowlist.py), [`heimdall/scanner/detect.py:488–498`](../heimdall/scanner/detect.py) | [`tests/test_scanner_allowlist.py:224–255`](../tests/test_scanner_allowlist.py) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`heimdall/cli/scan.py:406–425`](../heimdall/cli/scan.py) | [`tests/test_scanner_allowlist.py:388–410`](../tests/test_scanner_allowlist.py) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : schéma mis à jour avec `ignored_count` et `traces` | [`schemas/scan.schema.json:13–68`](../schemas/scan.schema.json), [`heimdall/cli/scan.py:328–348`](../heimdall/cli/scan.py) | [`tests/test_scanner_allowlist.py:413–427`](../tests/test_scanner_allowlist.py), [`tests/test_cli_scan.py:1670–1690`](../tests/test_cli_scan.py) | Schéma draft 2020-12 validé ; champs exacts sans fuite |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés | [`heimdall/cli/main.py:146–152`](../heimdall/cli/main.py) | [`tests/test_scanner_allowlist.py:474–478`](../tests/test_scanner_allowlist.py) | stderr : verdict déterministe + décompte des ignorés |
| **Confinement et anti-traversal (CWE-22)** : symlinks, `..` et chemins absolus refusés | [`heimdall/scanner/allowlist.py:275–289`](../heimdall/scanner/allowlist.py), [`385–412`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:284–326`](../tests/test_scanner_allowlist.py), [`555–560`](../tests/test_scanner_allowlist.py) | `ScanError` (code 2) si symlink, path traversal ou config hors dépôt |
| **Anti-ReDoS et plafonds DoS (CWE-1333, CWE-400)** : quantificateurs imbriqués refusés, max 64 Kio | [`heimdall/scanner/allowlist.py:53–67`](../heimdall/scanner/allowlist.py), [`292–303`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:329–358`](../tests/test_scanner_allowlist.py) | Rejet fail-closed des regex à backtracking exponentiel et fichiers > 64 Kio |
| **Contrat fermé et validation stricte (CWE-20)** : clés inconnues refusées | [`heimdall/scanner/allowlist.py:306–370`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:341–356`](../tests/test_scanner_allowlist.py) | Toute clé inconnue dans `[allowlist]` ou règle lève `ScanError` |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`heimdall/scanner/allowlist.py:73–94`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:256–266`](../tests/test_scanner_allowlist.py) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |

## Fichier versionné `heimdall.toml`

Le fichier [`heimdall.toml`](../heimdall.toml) est versionné à la racine du dépôt.
Il active les quatre familles de règles requises par le ticket #24.

```toml
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "Mots-clés et jetons d'exemple évidents"
keywords = ["example", "sample", "your_key_here"]

[[allowlist.rules]]
name = "changeme-passwords"
description = "Mots de passe ou valeurs de configuration par défaut changeme"
keywords = ["changeme"]

[[allowlist.rules]]
name = "dummy-tokens"
description = "Valeurs, identifiants et jetons factices dummy"
keywords = ["dummy"]

[[allowlist.rules]]
name = "test-fixtures"
description = "Fixtures et valeurs factices explicites dans les répertoires et fichiers de test"
paths = ["tests/**", "*_test.py", "test_*.py", "**/fixtures/**", "**/support/**"]
keywords = [
  "test", "fake", "mock", "dummy", "placeholder", "synthetic", "factice", "fixture", "expected", "invalid"
]
```

## Résultats des vérifications de sécurité

Environnement : Linux, Python 3.14.6 / venv du dépôt.

```text
.venv/bin/pytest tests/test_scanner_allowlist.py -q
26 passed in 0.57s

.venv/bin/ruff check heimdall tests
All checks passed!

.venv/bin/mypy heimdall
Success: no issues found in 42 source files

.venv/bin/bandit -r heimdall -q
code retour 0, aucun rapport de vulnérabilité
```
