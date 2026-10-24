# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`570b09ac40084aaeee10ab0ffcf9a7357808fbf8`](https://github.com/Cezar277/heimdall/commit/570b09ac40084aaeee10ab0ffcf9a7357808fbf8).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`allowlist.py:319–323`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L319-L323), [`heimdall.toml:11–14`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall.toml#L11-L14) | [`tests/test_scanner_allowlist.py:144–171`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L144-L171) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`allowlist.py:324–328`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L324-L328), [`heimdall.toml:16–19`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall.toml#L16-L19) | [`tests/test_scanner_allowlist.py:174–189`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L174-L189) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`allowlist.py:329–333`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L329-L333), [`heimdall.toml:21–24`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall.toml#L21-L24) | [`tests/test_scanner_allowlist.py:192–207`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L192-L207) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`allowlist.py:334–350`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L334-L350), [`heimdall.toml:26–41`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall.toml#L26-L41) | [`tests/test_scanner_allowlist.py:210–226`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L210-L226), [`229–247`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L229-L247) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:124–142`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L124-L142), [`186–220`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L186-L220) | [`tests/test_scanner_allowlist.py:253–269`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L253-L269), [`1042–1084`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1042-L1084), [`1252–1268`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1252-L1268) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:186–220`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L186-L220) | [`tests/test_scanner_allowlist.py:888–921`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L888-L921) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:291–367`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L291-L367), [`417–426`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L417-L426), [`495–503`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L495-L503), [`579–585`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L579-L585) | [`948–1039`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L948-L1039), [`1271–1410`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1271-L1410), [`1562–1605`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1562-L1605), [`1610–1629`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1610-L1629) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:519–554`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L519-L554), [`interface.py:38–69`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/interface.py#L38-L69) | [`343–384`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L343-L384), [`795–811`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L795-L811) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : interdiction des alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:87–98`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L87-L98), [`369–383`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L369-L383) | [`1095–1116`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1095-L1116), [`814–821`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L814-L821), [`1152–1213`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1152-L1213) | Rejet des formes `(a\|aa)+`, `(.*a)+`, `a++`, `a*a*`, `\d+\d+`, `a*?`, `(a?)+` et motifs > 128 chars |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:263–287`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L263-L287), [`detect.py:465–478`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/detect.py#L465-L478) | [`275–302`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L275-L302), [`305–314`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L305-L314) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:641–669`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L641-L669) | [`484–502`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L484-L502), [`1216–1249`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1216-L1249) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/schemas/scan.schema.json#L15-L81), [`scan.py:597–620`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/scan.py#L597-L620) | [`505–516`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L505-L516), [`1216–1249`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1216-L1249), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/cli/main.py#L163-L176) | [`586–644`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L586-L644), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:101–121`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L101-L121), [`263–287`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L263-L287) | [`305–314`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L305-L314), [`1042–1084`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1042-L1084), [`1216–1249`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1216-L1249) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:398–420`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L398-L420), [`461–496`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L461-L496) | [`387–450`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L387-L450), [`824–869`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L824-L869) | `[tool.foo]`, `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:519–554`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/heimdall/scanner/allowlist.py#L519-L554) | [`1610–1629`](https://github.com/Cezar277/heimdall/blob/570b09ac40084aaeee10ab0ffcf9a7357808fbf8/tests/test_scanner_allowlist.py#L1610-L1629) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |

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
73 passed

.venv/bin/pytest -o addopts="" -q
1946 passed, 15 skipped

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

[`allowlist.py:124–142`](../heimdall/scanner/allowlist.py#L124-L142) applique
désormais `\b` **dans tous les cas**, y compris pour une règle restreinte par
chemin (`tests/**`). `_` étant un caractère de mot, `fake_slack_token` et
`my_dummy_key` restent signalés ; `fake-token` ou la valeur exacte `dummy`
restent reconnus. Le test de non-régression
[`test_scanner_allowlist.py:229–247`](../tests/test_scanner_allowlist.py#L229-L247)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1252–1268`](../tests/test_scanner_allowlist.py#L1252-L1268)
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

Tests de non-régression : [`test_scanner_allowlist.py:1413–1558`](../tests/test_scanner_allowlist.py#L1413-L1558)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:519–554`](../heimdall/scanner/allowlist.py#L519-L554)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:1610–1629`](../tests/test_scanner_allowlist.py#L1610-L1629)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:239–280`](../heimdall/cli/scan.py#L239-L280)), le parseur les
  consomme sans relire ([`allowlist.py:499–516`](../heimdall/scanner/allowlist.py#L499-L516)),
  et un second contrôle refuse toute substitution
  ([`scan.py:291–367`](../heimdall/cli/scan.py#L291-L367),
  [`scan.py:370–387`](../heimdall/cli/scan.py#L370-L387)). Test de course :
  [`test_scanner_allowlist.py:1357–1399`](../tests/test_scanner_allowlist.py#L1357-L1399).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:1562–1605`](../tests/test_scanner_allowlist.py#L1562-L1605),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:354–366`](../heimdall/scanner/allowlist.py#L354-L366)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:795–811`](../tests/test_scanner_allowlist.py#L795-L811)
  et [`1152–1213`](../tests/test_scanner_allowlist.py#L1152-L1213).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:461–496`](../heimdall/scanner/allowlist.py#L461-L496)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:387–415`](../tests/test_scanner_allowlist.py#L387-L415).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:484–487`](../heimdall/scanner/allowlist.py#L484-L487)).
  Test : [`test_scanner_allowlist.py:418–424`](../tests/test_scanner_allowlist.py#L418-L424).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:71`](../heimdall/scanner/allowlist.py#L71),
  [`398–420`](../heimdall/scanner/allowlist.py#L398-L420),
  [`434–438`](../heimdall/scanner/allowlist.py#L434-L438)). Test :
  [`test_scanner_allowlist.py:427–450`](../tests/test_scanner_allowlist.py#L427-L450).
- **Fabriques explicites** : `Allowlist.default()` et `create_default_rules()`
  restent réservées aux tests et à l'API Python ; le chargement CLI/CI ne les
  branche pas. Sans `heimdall.toml`, `load_allowlist()` rend
  `Allowlist.empty()` ([`allowlist.py:294–310`](../heimdall/scanner/allowlist.py#L294-L310),
  [`557–590`](../heimdall/scanner/allowlist.py#L557-L590)). Test :
  [`test_scanner_allowlist.py:689–700`](../tests/test_scanner_allowlist.py#L689-L700).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:1610–1629`](../tests/test_scanner_allowlist.py#L1610-L1629)
  (config par défaut et `--config`, sous-processus borné).
