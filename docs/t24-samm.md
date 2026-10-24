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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`heimdall/scanner/allowlist.py:313–317`](../heimdall/scanner/allowlist.py), [`heimdall.toml:11–14`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:125–151`](../tests/test_scanner_allowlist.py) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`heimdall/scanner/allowlist.py:318–322`](../heimdall/scanner/allowlist.py), [`heimdall.toml:16–19`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:155–170`](../tests/test_scanner_allowlist.py) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`heimdall/scanner/allowlist.py:323–327`](../heimdall/scanner/allowlist.py), [`heimdall.toml:21–24`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:173–188`](../tests/test_scanner_allowlist.py) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`heimdall/scanner/allowlist.py:328–341`](../heimdall/scanner/allowlist.py), [`heimdall.toml:26–38`](../heimdall.toml) | [`tests/test_scanner_allowlist.py:191–210`](../tests/test_scanner_allowlist.py) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`heimdall/scanner/allowlist.py:180–220`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:213–233`](../tests/test_scanner_allowlist.py), [`819–841`](../tests/test_scanner_allowlist.py) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`heimdall/scanner/allowlist.py:180–220`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:783–816`](../tests/test_scanner_allowlist.py) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`heimdall/cli/scan.py:272–365`](../heimdall/cli/scan.py), [`390–405`](../heimdall/cli/scan.py), [`458–475`](../heimdall/cli/scan.py) | [`tests/test_scanner_allowlist.py:843–935`](../tests/test_scanner_allowlist.py), [`1123–1207`](../tests/test_scanner_allowlist.py) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`heimdall/scanner/allowlist.py:471–540`](../heimdall/scanner/allowlist.py), [`heimdall/scanner/interface.py:34–68`](../heimdall/scanner/interface.py) | [`tests/test_scanner_allowlist.py:303–345`](../tests/test_scanner_allowlist.py) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : interdiction des alternances quantifiées, quantificateurs adjacents, max 128 chars | [`heimdall/scanner/allowlist.py:78–90`](../heimdall/scanner/allowlist.py), [`360–380`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:990–1045`](../tests/test_scanner_allowlist.py) | Rejet des formes `(a\|aa)+`, `(.*a)+`, `a++`, `a*a*`, `\d+\d+`, `a*?`, `(a?)+` et motifs > 128 chars |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`heimdall/scanner/allowlist.py:261–285`](../heimdall/scanner/allowlist.py), [`heimdall/scanner/detect.py:465–480`](../heimdall/scanner/detect.py) | [`tests/test_scanner_allowlist.py:235–263`](../tests/test_scanner_allowlist.py) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`heimdall/cli/scan.py:615–655`](../heimdall/cli/scan.py) | [`tests/test_scanner_allowlist.py:398–417`](../tests/test_scanner_allowlist.py) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`schemas/scan.schema.json:15–78`](../schemas/scan.schema.json), [`heimdall/cli/scan.py:571–612`](../heimdall/cli/scan.py) | [`tests/test_scanner_allowlist.py:419–431`](../tests/test_scanner_allowlist.py), [`tests/test_cli_scan.py:1680–1715`](../tests/test_cli_scan.py) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`heimdall/cli/main.py:164–178`](../heimdall/cli/main.py) | [`tests/test_scanner_allowlist.py:521–530`](../tests/test_scanner_allowlist.py) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`heimdall/scanner/allowlist.py:94–115`](../heimdall/scanner/allowlist.py) | [`tests/test_scanner_allowlist.py:265–278`](../tests/test_scanner_allowlist.py), [`1060–1094`](../tests/test_scanner_allowlist.py) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |

## Fichier versionné `heimdall.toml`

Le fichier [`heimdall.toml`](../heimdall.toml) est versionné à la racine du dépôt.
Il active les quatre familles de règles requises par le ticket #24.

```toml
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "Mots-clés et jetons d'exemple évidents (ex: AKIA...EXAMPLE, your_key_here)"
keywords = ["AKIAIOSFODNN7EXAMPLE", "example", "sample", "your_key_here"]

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
paths = ["tests/**", "fixtures/**", "**/fixtures/**", "support/**", "**/support/**"]
keywords = [
  "fake",
  "mock",
  "dummy",
  "placeholder",
  "synthetic",
  "factice",
  "fixture",
]
```

## Résultats des vérifications de sécurité

Environnement : Linux, Python 3.14.6 / venv du dépôt.

```text
.venv/bin/pytest tests/test_scanner_allowlist.py -q
52 passed

.venv/bin/ruff check heimdall tests
All checks passed!

.venv/bin/mypy heimdall
Success: no issues found in 42 source files

.venv/bin/bandit -r heimdall -q
code retour 0, aucun rapport de vulnérabilité
```
