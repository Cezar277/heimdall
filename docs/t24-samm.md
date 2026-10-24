# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8`](https://github.com/Cezar277/heimdall/commit/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8).
Les permaliens du tableau épinglent cette révision. Les correctifs issus des
revues successives (frontière `_` stricte, plomberie Git, FIFO/TOCTOU,
périmètre local indicatif, contrat TOML strict) sont décrits en fin de fiche ;
leurs plages sont épinglées à la même révision.

## En une phrase

Allowlist déterministe et traçable permettant d'écarter les cas évidents
(`example`, `changeme`, `dummy`, fixtures de test) sans passer par le LLM,
avec journalisation systématique de chaque rejet (règle, fichier, ligne)
et affichage permanent du nombre de findings ignorés dans les rapports local et CI.

## Invariants de sécurité et exigences vérifiées

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`allowlist.py:619–623`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L619-L623), [`heimdall.toml:11–14`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall.toml#L11-L14) | [`tests/test_scanner_allowlist.py:164–191`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L164-L191) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`allowlist.py:624–628`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L624-L628), [`heimdall.toml:16–19`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall.toml#L16-L19) | [`tests/test_scanner_allowlist.py:194–209`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L194-L209) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`allowlist.py:629–633`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L629-L633), [`heimdall.toml:21–24`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall.toml#L21-L24) | [`tests/test_scanner_allowlist.py:212–227`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L212-L227) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`allowlist.py:634–650`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L634-L650), [`heimdall.toml:26–41`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall.toml#L26-L41) | [`tests/test_scanner_allowlist.py:230–246`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L230-L246), [`249–267`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L249-L267) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:395–413`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L395-L413), [`480–520`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L480-L520) | [`tests/test_scanner_allowlist.py:273–289`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L273-L289), [`1062–1104`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1062-L1104), [`1408–1424`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1408-L1424) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:480–520`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L480-L520) | [`tests/test_scanner_allowlist.py:908–941`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L908-L941) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:291–367`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L291-L367), [`417–426`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L417-L426), [`495–503`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L495-L503), [`579–585`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L579-L585) | [`968–1059`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L968-L1059), [`1427–1555`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1427-L1555), [`1718–1761`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1718-L1761), [`1766–1785`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1766-L1785) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:841–876`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L841-L876), [`interface.py:38–69`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/interface.py#L38-L69) | [`363–404`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L363-L404), [`815–831`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L815-L831) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:126–292`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L126-L292), [`669–705`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L669-L705) | [`1115–1136`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1115-L1136), [`1139–1168`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1139-L1168), [`834–841`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L834-L841), [`1308–1369`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1308-L1369) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:83–89`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L83-L89), [`317–368`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L317-L368), [`669–705`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L669-L705) | [`1171–1220`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1171-L1220), [`1223–1231`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1223-L1231), [`1234–1253`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1234-L1253), [`1256–1272`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1256-L1272) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:442–478`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L442-L478) | [`114–150`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L114-L150) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:563–587`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L563-L587), [`detect.py:465–478`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/detect.py#L465-L478) | [`295–322`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L295-L322), [`325–334`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L325-L334) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:641–669`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L641-L669) | [`504–522`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L504-L522), [`1372–1405`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1372-L1405) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/schemas/scan.schema.json#L15-L81), [`scan.py:597–620`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/scan.py#L597-L620) | [`525–536`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L525-L536), [`1372–1405`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1372-L1405), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/cli/main.py#L163-L176) | [`606–664`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L606-L664), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:372–392`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L372-L392), [`563–587`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L563-L587) | [`325–334`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L325-L334), [`1062–1104`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1062-L1104), [`1372–1405`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1372-L1405) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:720–742`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L720-L742), [`783–818`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L783-L818), [`756–760`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L756-L760) | [`407–470`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L407-L470), [`844–889`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L844-L889) | `[tool.foo]`, `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:841–876`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/heimdall/scanner/allowlist.py#L841-L876) | [`1766–1785`](https://github.com/Cezar277/heimdall/blob/f85bdfe2ac4fdc5cece83355d728bfaa2f37f9e8/tests/test_scanner_allowlist.py#L1766-L1785) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |

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

Environnement : Linux, Python 3.14.8 / venv du dépôt.

```text
.venv/bin/pytest tests/test_scanner_allowlist.py -q
79 passed

.venv/bin/pytest -o addopts="" -q
1952 passed, 15 skipped

.venv/bin/ruff check heimdall tests
All checks passed!

.venv/bin/mypy heimdall
Success: no issues found in 42 source files

.venv/bin/bandit -r heimdall -q
code retour 0, aucun rapport de vulnérabilité
```

## Correctifs issus de la revue

Les plages ci-dessous décrivent l'arbre de travail de la révision auditée.
Les invariants 1 (doute → signalé) et 3 (garde unique `_resolve_root` +
`O_NOFOLLOW`) restent inchangés.

### Frontière `_` stricte pour les mots-clés

[`allowlist.py:395–413`](../heimdall/scanner/allowlist.py#L395-L413) applique
désormais `\b` **dans tous les cas**, y compris pour une règle restreinte par
chemin (`tests/**`). `_` étant un caractère de mot, `fake_slack_token` et
`my_dummy_key` restent signalés ; `fake-token` ou la valeur exacte `dummy`
restent reconnus. Le test de non-régression
[`test_scanner_allowlist.py:249–267`](../tests/test_scanner_allowlist.py#L249-L267)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1408–1424`](../tests/test_scanner_allowlist.py#L1408-L1424)
verrouille la frontière (sous-chaînes rejetées, séparateurs non-mot acceptés).

### Index Git lu par la plomberie, plus par un parseur DIRC maison

[`gitdiff.py:436–528`](../heimdall/mcp/gitdiff.py#L436-L528) ajoute
`_checked_index_path` et `index_entry` :

- `git rev-parse --git-path index` localise l'index réel (dépôt standard,
  worktree lié, sous-module) ;
- le chemin passe par la garde unique `_resolve_root` puis `O_NOFOLLOW`, et
  doit être un fichier ordinaire : un `.git/index` symlinké est refusé ;
- `git ls-files -s -z -- <path>` rend `(mode, sha)` au stage 0 uniquement ;
  absent, lien symbolique, gitlink ou index en conflit sont refusés
  (`None`/`ToolFailure`), toute sortie ambiguë échoue en code 2.

[`scan.py:201–280`](../heimdall/cli/scan.py#L201-L280) conserve la vérification
anti-auto-attestation : lecture du fichier du worktree via `_resolve_root` +
`O_NOFOLLOW`, puis comparaison de l'empreinte de blob brute (SHA-1 ou SHA-256)
avec le SHA de l'index, sans exécuter de filtre Git `clean`.

Tests de non-régression : [`test_scanner_allowlist.py:1569–1714`](../tests/test_scanner_allowlist.py#L1569-L1714)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:841–876`](../heimdall/scanner/allowlist.py#L841-L876)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:1766–1785`](../tests/test_scanner_allowlist.py#L1766-L1785)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:239–280`](../heimdall/cli/scan.py#L239-L280)), le parseur les
  consomme sans relire ([`allowlist.py:821–838`](../heimdall/scanner/allowlist.py#L821-L838)),
  et un second contrôle refuse toute substitution
  ([`scan.py:291–367`](../heimdall/cli/scan.py#L291-L367),
  [`scan.py:370–387`](../heimdall/cli/scan.py#L370-L387)). Test de course :
  [`test_scanner_allowlist.py:1513–1555`](../tests/test_scanner_allowlist.py#L1513-L1555).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:1718–1761`](../tests/test_scanner_allowlist.py#L1718-L1761),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:654–666`](../heimdall/scanner/allowlist.py#L654-L666)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:815–831`](../tests/test_scanner_allowlist.py#L815-L831)
  et [`1308–1369`](../tests/test_scanner_allowlist.py#L1308-L1369).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:783–818`](../heimdall/scanner/allowlist.py#L783-L818)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:407–435`](../tests/test_scanner_allowlist.py#L407-L435).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:806–809`](../heimdall/scanner/allowlist.py#L806-L809)).
  Test : [`test_scanner_allowlist.py:438–444`](../tests/test_scanner_allowlist.py#L438-L444).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:76`](../heimdall/scanner/allowlist.py#L76),
  [`720–742`](../heimdall/scanner/allowlist.py#L720-L742),
  [`756–760`](../heimdall/scanner/allowlist.py#L756-L760)). Test :
  [`test_scanner_allowlist.py:447–470`](../tests/test_scanner_allowlist.py#L447-L470).
- **Fabriques explicites** : `Allowlist.default()` et `create_default_rules()`
  restent réservées aux tests et à l'API Python ; le chargement CLI/CI ne les
  branche pas. Sans `heimdall.toml`, `load_allowlist()` rend
  `Allowlist.empty()` ([`allowlist.py:595–604`](../heimdall/scanner/allowlist.py#L595-L604),
  [`879–912`](../heimdall/scanner/allowlist.py#L879-L912)). Test :
  [`test_scanner_allowlist.py:709–720`](../tests/test_scanner_allowlist.py#L709-L720).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:1766–1785`](../tests/test_scanner_allowlist.py#L1766-L1785)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:126–292`](../heimdall/scanner/allowlist.py#L126-L292)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1139–1154`](../tests/test_scanner_allowlist.py#L1139-L1154)
  et [`1157–1168`](../tests/test_scanner_allowlist.py#L1157-L1168) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:669–705`](../heimdall/scanner/allowlist.py#L669-L705)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:317–368`](../heimdall/scanner/allowlist.py#L317-L368)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1171–1220`](../tests/test_scanner_allowlist.py#L1171-L1220),
  [`1223–1231`](../tests/test_scanner_allowlist.py#L1223-L1231),
  [`1234–1253`](../tests/test_scanner_allowlist.py#L1234-L1253),
  [`1256–1272`](../tests/test_scanner_allowlist.py#L1256-L1272).
- **Valeur candidate bornée** : [`allowlist.py:480–520`](../heimdall/scanner/allowlist.py#L480-L520)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1234–1253`](../tests/test_scanner_allowlist.py#L1234-L1253).
- **Typage de l'API** : [`allowlist.py:442–478`](../heimdall/scanner/allowlist.py#L442-L478)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:114–150`](../tests/test_scanner_allowlist.py#L114-L150).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:109–117`](../heimdall/scanner/allowlist.py#L109-L117))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1952 passed, 15 skipped** et les 79 tests d'allowlist sont verts.
