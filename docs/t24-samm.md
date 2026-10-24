# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`2e538f72378fdb167cc915f2d5acebd1e77b36de`](https://github.com/Cezar277/heimdall/commit/2e538f72378fdb167cc915f2d5acebd1e77b36de).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`heimdall.toml:23–26`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall.toml#L23-L26) | [`tests/test_scanner_allowlist.py:209–236`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L209-L236) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`heimdall.toml:28–31`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall.toml#L28-L31) | [`tests/test_scanner_allowlist.py:239–254`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L239-L254) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`heimdall.toml:33–36`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall.toml#L33-L36) | [`tests/test_scanner_allowlist.py:257–272`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L257-L272) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`heimdall.toml:38–53`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall.toml#L38-L53) | [`tests/test_scanner_allowlist.py:275–291`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L275-L291), [`294–312`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L294-L312) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:440–458`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L440-L458), [`536–584`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L536-L584) | [`tests/test_scanner_allowlist.py:318–334`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L318-L334), [`1568–1610`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1568-L1610), [`1932–1948`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1932-L1948) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:536–584`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L536-L584) | [`tests/test_scanner_allowlist.py:1414–1447`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1414-L1447) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:331–422`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L331-L422), [`474–483`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L474-L483), [`552–564`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L552-L564), [`644–650`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L644-L650) | [`1516–1565`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1516-L1565), [`1951–2079`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1951-L2079), [`2242–2285`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L2242-L2285), [`2290–2309`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L2290-L2309) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:868–908`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L868-L908), [`interface.py:38–71`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/interface.py#L38-L71) | [`408–441`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L408-L441), [`1321–1337`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1321-L1337) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:171–337`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L171-L337), [`680–720`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L680-L720) | [`1621–1642`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1621-L1642), [`1645–1674`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1645-L1674), [`1340–1347`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1340-L1347), [`1814–1893`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1814-L1893) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:87–105`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L87-L105), [`362–413`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L362-L413), [`680–720`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L680-L720) | [`1677–1726`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1677-L1726), [`1729–1737`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1729-L1737), [`1740–1759`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1740-L1759), [`1762–1778`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1762-L1778) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:487–534`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L487-L534) | [`159–195`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L159-L195) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:627–651`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L627-L651), [`detect.py:470–483`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/detect.py#L470-L483) | [`340–367`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L340-L367), [`370–379`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L370-L379) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:706–734`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L706-L734) | [`667–685`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L667-L685), [`1896–1929`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1896-L1929) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/schemas/scan.schema.json#L15-L81), [`scan.py:662–685`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L662-L685) | [`688–699`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L688-L699), [`1896–1929`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1896-L1929), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/main.py#L163-L176) | [`769–827`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L769-L827), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:417–437`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L417-L437), [`627–651`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L627-L651) | [`370–379`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L370-L379), [`1568–1610`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1568-L1610), [`1896–1929`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1896-L1929) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` obligatoire et typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:735–760`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L735-L760), [`805–845`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L805-L845), [`828–836`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L828-L836), [`774–778`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L774-L778) | [`514–633`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L514-L633), [`554–572`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L554-L572), [`1350–1395`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1350-L1395) | `[tool.foo]`, `version` absente ou `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:868–908`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L868-L908) | [`2290–2309`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L2290-L2309) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |
| **--CONFIG EXTERNE (CWE-345, LOW)** : `--config` hors dépôt accepté comme choix opérateur, gardes inchangées | [`allowlist.py:911–959`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L911-L959), [`scan.py:491–495`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L491-L495), [`572–576`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L572-L576) | [`444–477`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L444-L477), [`895–927`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L895-L927) | Opt-in explicite : arbre et staged hors CI acceptés, contenu invalide toujours code 2 ; sans opt-in refus fail-closed inchangé |
| **FILTRE CHEMIN BORNÉ (CWE-400, LOW)** : au plus 10 jokers `*` par motif, chemin soumis à `fnmatch` borné à 1024 | [`allowlist.py:659–677`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L659-L677), [`556–569`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L556-L569), [`100–105`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L100-L105) | [`1814–1893`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1814-L1893), [`1321–1337`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1321-L1337) | Au-delà de 10 `*` → code 2 ; chemin > 1024 non soumis au filtre, candidat reste signalé (fail-closed) ; fuzz adversarial borné (< 1 ms) |
| **FERMETURE DESCRIPTEUR FAIL-CLOSED (CWE-400, LOW)** : `os.close` en échec converti, jamais d'`OSError` brute | [`allowlist.py:900–906`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L900-L906), [`scan.py:225–247`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L225-L247) | [`950–972`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L950-L972) | `load_allowlist_from_file` → `ScanError` (invariant 11), `_read_worktree_file` → `None` (try imbriqué + `finally` + `except`, sans `return` en `finally`) |
| **GARDE ANTI AUTO-ATTESTATION STATIQUE (CWE-200, LOW)** : `rel_cfg`/`verified.path` jamais reflétés | [`scan.py:403–409`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L403-L409), [`416–420`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L416-L420), [`437–443`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L437-L443) | [`974–1002`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L974-L1002), [`1004–1022`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1004-L1022) | `str(exc)` sans nom de config, préfixe `auto-attestation` conservé ; en CLI le libellé est masqué par le message générique |
| **CONFIG ILLISIBLE = CODE 2 (REQ-SEC-07, LOW)** : `exists()` en échec → `ScanError`, pas allowlist vide | [`allowlist.py:947–956`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L947-L956) | [`1024–1045`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1024-L1045) | Seule l'absence avérée vaut « pas de config » ; docstring `load_allowlist` mise à jour |
| **FERMETURE DESCRIPTEUR ÉTENDUE (CWE-400, LOW)** : `os.close` protégé dans l'index, le lecteur et la clé | [`gitdiff.py:470–477`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/mcp/gitdiff.py#L470-L477), [`detect.py:365–371`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/detect.py#L365-L371), [`hashing.py:148–154`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/hashing.py#L148-L154), [`191–197`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/hashing.py#L191-L197) | [`2188–2207`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_mcp_units.py#L2188-L2207), [`700–715`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_detect.py#L700-L715), [`718–735`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_detect.py#L718-L735) | `ToolFailure`/`ScanError` partout, jamais d'`OSError` brute ; `_read_key` et `_create_key` couverts aussi |
| **GARDE `exists()` PROTÉGÉE (REQ-SEC-07, LOW)** : `_default_config_present` → `ScanError`, pas de contournement silencieux | [`scan.py:318–328`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L318-L328), [`381–382`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L381-L382) | [`1048–1074`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1048-L1074) | Même contrat que `load_allowlist` ; figé via API (`collect` arbre + staged) et CLI (code 2, message statique) |
| **REFUS DE GARDE DISTINGUÉS EN LOGS (CWE-345, LOW)** : 5 libellés debug statiques, verdict fail-closed inchangé | [`scan.py:116–119`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L116-L119), [`250–307`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/cli/scan.py#L250-L307) | [`1076–1137`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1076-L1137) | `None` légitime (untracked) vs panne (index illisible) vs dirty vs empreinte, en caplog ; aucun secret ni entrée reflétés |
| **CI ANTI AUTO-ATTESTATION DOCUMENTÉE (CWE-345, LOW)** : `--ci` + `heimdall.toml` versionné → 2, avec issue explicite | Paragraphe `--ci`/allowlist de [`docs/cli.md`](cli.md) (pas de permalien ligne : prose) | [`1516–1565`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1516-L1565) | `--config` externe épinglé ou `--no-allowlist` ; comportement déjà figé (`test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`), aide ajoutée sans toucher au libellé code 2 (anti-oracle) |
| **TYPES FIGÉS ANTI-TYPO (CWE-20, LOW)** : `secret_types` validé contre la grammaire Finding (`[a-z][a-z0-9_]*`, 64 max), en TOML comme en API | [`allowlist.py:128–133`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L128-L133), [`782–783`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L782-L783) | [`1219–1247`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1219-L1247), [`1301–1312`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1301-L1312) | `"AWS"`, `"../etc"`, `""`, 65 caractères → `ScanError`/code 2 (plus de règle muette) ; `("aws", "generic_password")` accepté ; miroir exact de `finding._TYPE_PATTERN` |
| **CONTRÔLES INVISIBLES REFUSÉS (CWE-20, LOW)** : `Cc`/`Cf`/`Zl`/`Zp` refusés dans `keywords`/`patterns` (TOML + API), mêmes classes que `_visible` | [`allowlist.py:113–118`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L113-L118), [`697`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L697), [`758`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L758) | [`1250–1298`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L1250-L1298) | `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2 (y compris via `"""` TOML) ; échappements `\n` acceptés ; `paths` déjà couverts par la grammaire Finding (`\n` refusé, prouvé) |
| **FABRIQUES IMPLICITES SUPPRIMÉES (CWE-345, LOW)** : `Allowlist.default()`/`create_default_rules()` n'existent plus (ni méthode, ni export) | [`allowlist.py:961–979`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/heimdall/scanner/allowlist.py#L961-L979) (`__all__` sans fabrique) | [`851–869`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L851-L869), [`2312–2332`](https://github.com/Cezar277/heimdall/blob/2e538f72378fdb167cc915f2d5acebd1e77b36de/tests/test_scanner_allowlist.py#L2312-L2332) | Helper test-local `_standard_test_allowlist()` (miroir `heimdall.toml`) ; `hasattr`/`__all__` négatifs figés ; `ignored_count == 0` sans config figé |

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
94 passed

.venv/bin/pytest -o addopts="" -q
1970 passed, 15 skipped

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

[`allowlist.py:440–458`](../heimdall/scanner/allowlist.py#L440-L458) applique
désormais `\b` **dans tous les cas**, y compris pour une règle restreinte par
chemin (`tests/**`). `_` étant un caractère de mot, `fake_slack_token` et
`my_dummy_key` restent signalés ; `fake-token` ou la valeur exacte `dummy`
restent reconnus. Le test de non-régression
[`test_scanner_allowlist.py:294–312`](../tests/test_scanner_allowlist.py#L294-L312)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1932–1948`](../tests/test_scanner_allowlist.py#L1932-L1948)
verrouille la frontière (sous-chaînes rejetées, séparateurs non-mot acceptés).

### Index Git lu par la plomberie, plus par un parseur DIRC maison

[`gitdiff.py:436–534`](../heimdall/mcp/gitdiff.py#L436-L534) ajoute
`_checked_index_path` et `index_entry` :

- `git rev-parse --git-path index` localise l'index réel (dépôt standard,
  worktree lié, sous-module) ;
- le chemin passe par la garde unique `_resolve_root` puis `O_NOFOLLOW`, et
  doit être un fichier ordinaire : un `.git/index` symlinké est refusé ;
- `git ls-files -s -z -- <path>` rend `(mode, sha)` au stage 0 uniquement ;
  absent, lien symbolique, gitlink ou index en conflit sont refusés
  (`None`/`ToolFailure`), toute sortie ambiguë échoue en code 2.

[`scan.py:207–307`](../heimdall/cli/scan.py#L207-L307) conserve la vérification
anti-auto-attestation : lecture du fichier du worktree via `_resolve_root` +
`O_NOFOLLOW`, puis comparaison de l'empreinte de blob brute (SHA-1 ou SHA-256)
avec le SHA de l'index, sans exécuter de filtre Git `clean`.

Tests de non-régression : [`test_scanner_allowlist.py:2093–2238`](../tests/test_scanner_allowlist.py#L2093-L2238)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:868–908`](../heimdall/scanner/allowlist.py#L868-L908)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:2290–2309`](../tests/test_scanner_allowlist.py#L2290-L2309)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:250–307`](../heimdall/cli/scan.py#L250-L307)), le parseur les
  consomme sans relire ([`allowlist.py:848–865`](../heimdall/scanner/allowlist.py#L848-L865)),
  et un second contrôle refuse toute substitution
  ([`scan.py:331–422`](../heimdall/cli/scan.py#L331-L422),
  [`scan.py:425–444`](../heimdall/cli/scan.py#L425-L444)). Test de course :
  [`test_scanner_allowlist.py:2037–2079`](../tests/test_scanner_allowlist.py#L2037-L2079).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:2242–2285`](../tests/test_scanner_allowlist.py#L2242-L2285),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:659–677`](../heimdall/scanner/allowlist.py#L659-L677)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:1321–1337`](../tests/test_scanner_allowlist.py#L1321-L1337)
  et [`1814–1893`](../tests/test_scanner_allowlist.py#L1814-L1893).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:805–845`](../heimdall/scanner/allowlist.py#L805-L845)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:514–542`](../tests/test_scanner_allowlist.py#L514-L542).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:828–836`](../heimdall/scanner/allowlist.py#L828-L836)).
  Test : [`test_scanner_allowlist.py:545–551`](../tests/test_scanner_allowlist.py#L545-L551).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:79`](../heimdall/scanner/allowlist.py#L79),
  [`735–760`](../heimdall/scanner/allowlist.py#L735-L760),
  [`774–778`](../heimdall/scanner/allowlist.py#L774-L778)). Test :
  [`test_scanner_allowlist.py:610–633`](../tests/test_scanner_allowlist.py#L610-L633).
- **Fabriques supprimées** : `Allowlist.default()` et `create_default_rules()`
  n'existent plus (ni méthode, ni export `__all__`) : aucune règle implicite
  ne peut être branchée par erreur. `load_allowlist()` rend
  `Allowlist.empty()` sans config ([`allowlist.py:654–656`](../heimdall/scanner/allowlist.py#L654-L656),
  [`911–959`](../heimdall/scanner/allowlist.py#L911-L959)) ; les tests utilisent
  l'helper local `_standard_test_allowlist()`. Test :
  [`test_scanner_allowlist.py:872–885`](../tests/test_scanner_allowlist.py#L872-L885).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:2290–2309`](../tests/test_scanner_allowlist.py#L2290-L2309)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:171–337`](../heimdall/scanner/allowlist.py#L171-L337)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1645–1660`](../tests/test_scanner_allowlist.py#L1645-L1660)
  et [`1663–1674`](../tests/test_scanner_allowlist.py#L1663-L1674) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:680–720`](../heimdall/scanner/allowlist.py#L680-L720)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:362–413`](../heimdall/scanner/allowlist.py#L362-L413)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1677–1726`](../tests/test_scanner_allowlist.py#L1677-L1726),
  [`1729–1737`](../tests/test_scanner_allowlist.py#L1729-L1737),
  [`1740–1759`](../tests/test_scanner_allowlist.py#L1740-L1759),
  [`1762–1778`](../tests/test_scanner_allowlist.py#L1762-L1778).
- **Valeur candidate bornée** : [`allowlist.py:536–584`](../heimdall/scanner/allowlist.py#L536-L584)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1740–1759`](../tests/test_scanner_allowlist.py#L1740-L1759).
- **Typage de l'API** : [`allowlist.py:487–534`](../heimdall/scanner/allowlist.py#L487-L534)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:159–195`](../tests/test_scanner_allowlist.py#L159-L195).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:154–162`](../heimdall/scanner/allowlist.py#L154-L162))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1970 passed, 15 skipped** et les 94 tests d'allowlist sont verts.

### Cinquième revue (LOW) — config externe, version obligatoire, littéraux, fnmatch borné

- **`--config` externe accepté hors CI** : [`scan.py:491–495`](../heimdall/cli/scan.py#L491-L495)
  et [`572–576`](../heimdall/cli/scan.py#L572-L576) passent désormais
  `allow_external=ci or config is not None` : un `--config` explicite peut
  vivre hors du dépôt scanné (choix opérateur, conformément à l'aide de la
  CLI), la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
  contrat fermé restant appliqués
  ([`allowlist.py:911–959`](../heimdall/scanner/allowlist.py#L911-L959)).
  Sans opt-in, le refus fail-closed reste la norme. Tests :
  [`444–477`](../tests/test_scanner_allowlist.py#L444-L477) (API : refus sans
  opt-in, acceptation avec opt-in, contenu invalide toujours refusé) et
  [`895–927`](../tests/test_scanner_allowlist.py#L895-L927) (CLI : arbre et
  staged hors CI, externe invalide → code 2).
- **`version` obligatoire** : [`allowlist.py:805–845`](../heimdall/scanner/allowlist.py#L805-L845)
  exige une `version` explicite ([`828–836`](../heimdall/scanner/allowlist.py#L828-L836)) —
  plus de défaut implicite `"1"` : une table `[allowlist]` sans `version`, un
  entier ou toute autre chaîne sont refusés en `ScanError` (code 2). Test :
  [`554–572`](../tests/test_scanner_allowlist.py#L554-L572).
- **Motifs à < 3 littéraux : refus maintenu, reformulation documentée** :
  `\d{3}-\d{4}`, `x{3}y{3}`, `[a-z]+`, `\w+` restent refusés (motifs
  aveugles, fail-closed) ; la reformulation `EXAMPLE-[0-9]{4}` est acceptée
  et n'ignore que la forme visée. Le contrat est documenté dans
  [`heimdall.toml`](../heimdall.toml) et [`docs/cli.md`](cli.md). Tests :
  [`574–607`](../tests/test_scanner_allowlist.py#L574-L607).
- **`fnmatch` borné des deux côtés** : au plus
  `MAX_PATH_WILDCARDS = 10` jokers `*` par motif (au-delà : code 2)
  ([`allowlist.py:659–677`](../heimdall/scanner/allowlist.py#L659-L677),
  constantes [`100–105`](../heimdall/scanner/allowlist.py#L100-L105)), et un
  chemin de plus de `MAX_MATCH_PATH_LENGTH = 1024` caractères n'est pas
  soumis au filtre — le candidat reste signalé (fail-closed)
  ([`allowlist.py:556–569`](../heimdall/scanner/allowlist.py#L556-L569)).
  Sous Python ≥ 3.13, `fnmatch.translate` produit des groupes atomiques
  (immunisé) ; sous les interpréteurs antérieurs, 20 `*` croisés à un chemin
  de 4 096 caractères coûtaient ≈ 1 s, les plafonds ramènent la passe sous
  la milliseconde. Fuzz adversarial borné en temps :
  [`1814–1893`](../tests/test_scanner_allowlist.py#L1814-L1893).
- **Non-régression** : la suite complète passe à
  **1970 passed, 15 skipped** et les 94 tests d'allowlist sont verts ; les
  plafonds `MAX_PATH_WILDCARDS = 10` et `MAX_MATCH_PATH_LENGTH = 1024` et
  l'exigence `version` sont figés par les exports vérifiés
  ([`2312–2332`](../tests/test_scanner_allowlist.py#L2312-L2332)).

### Sixième revue (LOW) — fail-closed strict et messages statiques

- **`os.close` protégé** : [`allowlist.py:900–906`](../heimdall/scanner/allowlist.py#L900-L906)
  convertit toute `OSError` en `ScanError` (contrat unique, invariant 11) ;
  [`scan.py:225–247`](../heimdall/cli/scan.py#L225-L247) rend `None`
  (fail-closed) via try imbriqué + `finally` + `except` externe — sans
  `return` en `finally` (`SyntaxWarning` évité, fermeture garantie sur
  tous les chemins). Test :
  [`950–972`](../tests/test_scanner_allowlist.py#L950-L972) (fermeture
  réelle puis panne simulée : `ScanError` d'un côté, `None` de l'autre,
  jamais d'`OSError` brute).
- **Messages de garde strictement statiques** : `rel_cfg` et `verified.path`
  (entrées opérateur normalisées) ne sont plus reflétés —
  [`scan.py:403–409`](../heimdall/cli/scan.py#L403-L409) (configuration
  stagée), [`416–420`](../heimdall/cli/scan.py#L416-L420) (worktree non
  propre en staged),
  [`437–443`](../heimdall/cli/scan.py#L437-L443) (re-contrôle anti-TOCTOU) ;
  le préfixe `auto-attestation` est conservé pour l'audit. Tests :
  [`974–1002`](../tests/test_scanner_allowlist.py#L974-L1002) (arbre, staged,
  `--config` interne : `str(exc)` sans nom de config) et
  [`1004–1022`](../tests/test_scanner_allowlist.py#L1004-L1022) (substitution
  entre garde et parsing).
- **`exists()` en échec → code 2** :
  [`allowlist.py:947–956`](../heimdall/scanner/allowlist.py#L947-L956)
  lève `ScanError` sur `OSError` (répertoire illisible) au lieu de rendre
  une allowlist vide silencieuse ; seule l'absence avérée vaut « pas de
  config » (le vide reste fail-closed). Test :
  [`1024–1045`](../tests/test_scanner_allowlist.py#L1024-L1045).
- **Non-régression** : la suite complète passe à
  **1970 passed, 15 skipped** et les 94 tests d'allowlist sont verts.

### Septième revue (LOW) — fail-closed étendu et CI documentée

- **`os.close` protégé partout** : après l'allowlist, le lecteur et la clé,
  l'index (`[`gitdiff.py:470–477`](../heimdall/mcp/gitdiff.py#L470-L477)` →
  `ToolFailure`), le lecteur d'arbre
  (`[`detect.py:365–371`](../heimdall/scanner/detect.py#L365-L371)` →
  `ScanError`) et la clé locale
  (`[`hashing.py:148–154`](../heimdall/scanner/hashing.py#L148-L154),
  [`191–197`](../heimdall/scanner/hashing.py#L191-L197)` → `ScanError`)
  convertissent `os.close` en échec. Tests :
  [`2188–2207`](../tests/test_mcp_units.py#L2188-L2207) (index),
  [`700–715`](../tests/test_scanner_detect.py#L700-L715) (lecteur) et
  [`718–735`](../tests/test_scanner_detect.py#L718-L735) (clé : lecture et
  création).
- **Garde `exists()` protégée** : [`scan.py:318–328`](../heimdall/cli/scan.py#L318-L328)
  (`_default_config_present`) convertit `OSError` en `ScanError` statique,
  comme `load_allowlist` ; l'appel [`381–382`](../heimdall/cli/scan.py#L381-L382)
  remplace le `elif exists()` nu. Test :
  [`1048–1074`](../tests/test_scanner_allowlist.py#L1048-L1074) (API arbre +
  staged et CLI → code 2, sans `OSError` brute).
- **Refus de garde distingués en logs** : [`scan.py:116–119`](../heimdall/cli/scan.py#L116-L119)
  (logger `heimdall.cli.scan`) et [`250–307`](../heimdall/cli/scan.py#L250-L307)
  journalisent chaque cause en debug avec un libellé statique — lecture
  worktree impossible, index illisible, entrée inattendue, non suivie,
  divergente, empreinte incalculable — sans refléter ni secret ni entrée ;
  le verdict reste `None` fail-closed dans tous les cas. Test :
  [`1076–1137`](../tests/test_scanner_allowlist.py#L1076-L1137) (caplog,
  quatre cas).
- **CI documentée** : `scan --ci` avec `heimdall.toml` versionné sort en 2
  sans `--config` externe ni `--no-allowlist` — c'est le choix anti
  auto-attestation documenté, pas un bypass ; [`docs/cli.md`](cli.md)
  donne désormais l'issue explicite (config externe épinglée hors dépôt,
  exemple fourni). Le comportement était déjà figé par
  `test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`
  ([`1516–1565`](../tests/test_scanner_allowlist.py#L1516-L1565)) ; le
  libellé code 2 reste générique (anti-oracle, pas de hint par cause).
- **Bruit d'audit** : `MAX_RULE_NAME_length` est déjà tout en capitales
  (vérifié mécaniquement, y compris dans l'historique) ; `Allowlist.default()`
  et `create_default_rules()` sont désormais supprimés (voir section suivante),
  le non-branchement CLI étant toujours figé par
  `test_cli_without_config_does_not_apply_default_factories`.
- **Non-régression** : la suite complète passe à
  **1970 passed, 15 skipped** et les 94 tests d'allowlist sont verts.

### Huitième revue (LOW) — typo morte interdite et fabriques supprimées

- **`secret_types` figé anti-typo** : [`allowlist.py:128–133`](../heimdall/scanner/allowlist.py#L128-L133)
  (miroir exact de `finding._TYPE_PATTERN`, 64 caractères max) + boucle de
  validation [`782–783`](../heimdall/scanner/allowlist.py#L782-L783) en TOML
  et `__post_init__` en API : `"AWS"`, `"../etc"`, `"foo bar"`, `""` ou 65
  caractères → `ScanError`/code 2, jamais une règle muette. Tests :
  [`1219–1247`](../tests/test_scanner_allowlist.py#L1219-L1247) (API + TOML,
  cas valides `aws`/`generic_password`) et
  [`1301–1312`](../tests/test_scanner_allowlist.py#L1301-L1312) (CLI).
- **Contrôles invisibles refusés** : [`allowlist.py:113–118`](../heimdall/scanner/allowlist.py#L113-L118)
  (mêmes catégories `Cc`/`Cf`/`Zl`/`Zp` que `_visible`) appliqué aux
  `keywords` ([`758`](../heimdall/scanner/allowlist.py#L758)), aux motifs
  ([`697`](../heimdall/scanner/allowlist.py#L697)) et à l'API
  (`__post_init__`) : `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2,
  y compris via `"""` TOML multiligne ; les échappements regex `\n` restent
  deux caractères ordinaires et acceptés. Les `paths` suivent la grammaire
  Finding #14 (inchangée) : `\n`/`\r`/`\t`/NUL déjà refusés, prouvé par
  `test_path_pattern_validation_errors`. Test :
  [`1250–1298`](../tests/test_scanner_allowlist.py#L1250-L1298).
- **Fabriques implicites supprimées** : `Allowlist.default()` et
  `create_default_rules()` retirés du module (ni méthode, ni export
  [`961–979`](../heimdall/scanner/allowlist.py#L961-L979)) : aucune règle
  implicite ne peut être branchée par erreur en CLI/CI. Les 4 règles
  nominales vivent dans le seul `heimdall.toml` versionné ; les tests
  utilisent l'helper local `_standard_test_allowlist()`. Figé par
  [`851–869`](../tests/test_scanner_allowlist.py#L851-L869) (règles
  versionnées + chargement) et [`2312–2332`](../tests/test_scanner_allowlist.py#L2312-L2332)
  (`hasattr`/`__all__` négatifs, `ignored_count == 0` sans config).
- **Non-régression** : la suite complète passe à
  **1970 passed, 15 skipped** et les 94 tests d'allowlist sont verts.
