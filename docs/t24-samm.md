# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`834f3bfed1fe2c0a5f203b5851f4929de51f0978`](https://github.com/Cezar277/heimdall/commit/834f3bfed1fe2c0a5f203b5851f4929de51f0978).
Les permaliens du tableau épinglent cette révision. Les correctifs issus de la
revue (frontière `_` stricte, remplacement du parseur DIRC par la plomberie Git)
sont décrits en fin de fiche ; leurs plages seront ré-épinglées au SHA de
livraison.

## En une phrase

Allowlist déterministe et traçable permettant d'écarter les cas évidents
(`example`, `changeme`, `dummy`, fixtures de test) sans passer par le LLM,
avec journalisation systématique de chaque rejet (règle, fichier, ligne)
et affichage permanent du nombre de findings ignorés dans les rapports local et CI.

## Invariants de sécurité et exigences vérifiées

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`allowlist.py:313–317`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L313-L317), [`heimdall.toml:11–14`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall.toml#L11-L14) | [`test_scanner_allowlist.py:125–151`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L125-L151) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`allowlist.py:318–322`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L318-L322), [`heimdall.toml:16–19`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall.toml#L16-L19) | [`test_scanner_allowlist.py:155–170`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L155-L170) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`allowlist.py:323–327`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L323-L327), [`heimdall.toml:21–24`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall.toml#L21-L24) | [`test_scanner_allowlist.py:173–188`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L173-L188) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`allowlist.py:328–341`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L328-L341), [`heimdall.toml:26–38`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall.toml#L26-L38) | [`test_scanner_allowlist.py:191–210`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L191-L210) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; depuis le correctif post-revue, `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:180–220`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L180-L220) | [`test_scanner_allowlist.py:213–233`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L213-L233), [`819–841`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L819-L841) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:180–220`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L180-L220) | [`test_scanner_allowlist.py:783–816`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L783-L816) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:309–371`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/scan.py#L309-L371), [`402–409`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/scan.py#L402-L409), [`474–481`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/scan.py#L474-L481) | [`test_scanner_allowlist.py:843–935`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L843-L935), [`1123–1207`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L1123-L1207) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:471–540`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L471-L540), [`interface.py:34–68`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/interface.py#L34-L68) | [`test_scanner_allowlist.py:303–345`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L303-L345) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : interdiction des alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:78–90`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L78-L90), [`360–380`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L360-L380) | [`test_scanner_allowlist.py:990–1045`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L990-L1045) | Rejet des formes `(a\|aa)+`, `(.*a)+`, `a++`, `a*a*`, `\d+\d+`, `a*?`, `(a?)+` et motifs > 128 chars |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:261–285`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L261-L285), [`detect.py:465–480`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/detect.py#L465-L480) | [`test_scanner_allowlist.py:235–263`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L235-L263) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:615–643`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/scan.py#L615-L643) | [`test_scanner_allowlist.py:398–417`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L398-L417) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–78`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/schemas/scan.schema.json#L15-L78), [`scan.py:571–594`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/scan.py#L571-L594) | [`test_scanner_allowlist.py:419–431`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L419-L431), [`test_cli_scan.py:1690–1719`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_cli_scan.py#L1690-L1719) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:164–178`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/cli/main.py#L164-L178) | [`test_scanner_allowlist.py:521–530`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L521-L530) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:94–115`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/heimdall/scanner/allowlist.py#L94-L115) | [`test_scanner_allowlist.py:265–278`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L265-L278), [`1060–1094`](https://github.com/Cezar277/heimdall/blob/834f3bfed1fe2c0a5f203b5851f4929de51f0978/tests/test_scanner_allowlist.py#L1060-L1094) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |

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
65 passed

.venv/bin/pytest -o addopts="" -q
1938 passed, 15 skipped

.venv/bin/ruff check heimdall tests
All checks passed!

.venv/bin/mypy heimdall
Success: no issues found in 42 source files

.venv/bin/bandit -r heimdall -q
code retour 0, aucun rapport de vulnérabilité
```

## Correctifs issus de la revue

Les plages ci-dessous décrivent l'arbre de travail post-revue ; elles seront
ré-épinglées au SHA de livraison. Les invariants 1 (doute → signalé) et 3
(garde unique `_resolve_root` + `O_NOFOLLOW`) restent inchangés.

### Frontière `_` stricte pour les mots-clés

[`allowlist.py:117–135`](../heimdall/scanner/allowlist.py#L117-L135) applique
désormais `\b` **dans tous les cas**, y compris pour une règle restreinte par
chemin (`tests/**`). `_` étant un caractère de mot, `fake_slack_token` et
`my_dummy_key` restent signalés ; `fake-token` ou la valeur exacte `dummy`
restent reconnus. Le test de non-régression
[`test_scanner_allowlist.py:213–231`](../tests/test_scanner_allowlist.py#L213-L231)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1120–1136`](../tests/test_scanner_allowlist.py#L1120-L1136)
verrouille la frontière (sous-chaînes rejetées, séparateurs non-mot acceptés).

### Index Git lu par la plomberie, plus par un parseur DIRC maison

[`gitdiff.py:436–526`](../heimdall/mcp/gitdiff.py#L436-L526) ajoute
`_checked_index_path` et `index_entry` :

- `git rev-parse --git-path index` localise l'index réel (dépôt standard,
  worktree lié, sous-module) ;
- le chemin passe par la garde unique `_resolve_root` puis `O_NOFOLLOW`, et
  doit être un fichier ordinaire : un `.git/index` symlinké est refusé ;
- `git ls-files -s -z -- <path>` rend `(mode, sha)` au stage 0 uniquement ;
  absent, lien symbolique, gitlink ou index en conflit sont refusés
  (`None`/`ToolFailure`), toute sortie ambiguë échoue en code 2.

[`scan.py:200–273`](../heimdall/cli/scan.py#L200-L273) conserve la vérification
anti-auto-attestation : lecture du fichier du worktree via `_resolve_root` +
`O_NOFOLLOW`, puis comparaison de l'empreinte de blob brute (SHA-1 ou SHA-256)
avec le SHA de l'index, sans exécuter de filtre Git `clean`.

Tests de non-régression : [`test_scanner_allowlist.py:1236–1381`](../tests/test_scanner_allowlist.py#L1236-L1381)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).
