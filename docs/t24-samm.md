# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`861702d35b9dcd1ae533d32d796b39b78a330474`](https://github.com/Cezar277/heimdall/commit/861702d35b9dcd1ae533d32d796b39b78a330474).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`heimdall.toml:23–29`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall.toml#L23-L29) | [`tests/test_scanner_allowlist.py:214–241`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L214-L241) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`heimdall.toml:31–35`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall.toml#L31-L35) | [`tests/test_scanner_allowlist.py:244–266`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L244-L266) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`heimdall.toml:37–41`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall.toml#L37-L41) | [`tests/test_scanner_allowlist.py:269–291`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L269-L291) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`heimdall.toml:43–58`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall.toml#L43-L58) | [`tests/test_scanner_allowlist.py:340–356`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L340-L356), [`359–377`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L359-L377) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:440–458`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L440-L458), [`548–603`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L548-L603) | [`tests/test_scanner_allowlist.py:383–399`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L383-L399), [`1633–1675`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1633-L1675), [`2046–2062`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2046-L2062) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:548–603`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L548-L603) | [`tests/test_scanner_allowlist.py:1479–1512`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1479-L1512) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:331–425`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L331-L425), [`477–486`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L477-L486), [`555–567`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L555-L567), [`647–653`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L647-L653) | [`1581–1630`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1581-L1630), [`2065–2193`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2065-L2193), [`2356–2399`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2356-L2399), [`2404–2423`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2404-L2423) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:894–934`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L894-L934), [`interface.py:38–71`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/interface.py#L38-L71) | [`473–506`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L473-L506), [`1386–1402`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1386-L1402) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:171–337`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L171-L337), [`699–739`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L699-L739) | [`1686–1707`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1686-L1707), [`1710–1739`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1710-L1739), [`1405–1412`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1405-L1412), [`1879–1958`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1879-L1958) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:87–105`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L87-L105), [`362–413`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L362-L413), [`699–739`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L699-L739) | [`1742–1791`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1742-L1791), [`1794–1802`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1794-L1802), [`1805–1824`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1805-L1824), [`1827–1843`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1827-L1843) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:492–546`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L492-L546) | [`164–200`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L164-L200) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:646–670`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L646-L670), [`detect.py:470–483`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/detect.py#L470-L483) | [`405–432`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L405-L432), [`435–444`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L435-L444) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:709–737`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L709-L737) | [`732–750`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L732-L750), [`2010–2043`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2010-L2043) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/schemas/scan.schema.json#L15-L81), [`scan.py:665–688`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L665-L688) | [`753–764`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L753-L764), [`2010–2043`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2010-L2043), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/main.py#L163-L176) | [`834–892`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L834-L892), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:417–437`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L417-L437), [`646–670`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L646-L670) | [`435–444`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L435-L444), [`1633–1675`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1633-L1675), [`2010–2043`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2010-L2043) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` obligatoire et typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:755–780`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L755-L780), [`831–871`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L831-L871), [`854–862`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L854-L862), [`794–798`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L794-L798) | [`579–698`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L579-L698), [`619–637`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L619-L637), [`1415–1460`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1415-L1460) | `[tool.foo]`, `version` absente ou `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:894–934`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L894-L934) | [`2404–2423`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2404-L2423) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |
| **--CONFIG EXTERNE (CWE-345, LOW)** : `--config` hors dépôt accepté comme choix opérateur, gardes inchangées | [`allowlist.py:937–985`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L937-L985), [`scan.py:494–498`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L494-L498), [`575–579`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L575-L579) | [`509–542`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L509-L542), [`960–992`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L960-L992) | Opt-in explicite : arbre et staged hors CI acceptés, contenu invalide toujours code 2 ; sans opt-in refus fail-closed inchangé |
| **FILTRE CHEMIN BORNÉ (CWE-400, LOW)** : au plus 10 jokers `*` par motif, chemin soumis à `fnmatch` borné à 1024 | [`allowlist.py:678–696`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L678-L696), [`568–581`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L568-L581), [`100–105`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L100-L105) | [`1879–1958`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1879-L1958), [`1386–1402`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1386-L1402) | Au-delà de 10 `*` → code 2 ; chemin > 1024 non soumis au filtre, candidat reste signalé (fail-closed) ; fuzz adversarial borné (< 1 ms) |
| **FERMETURE DESCRIPTEUR FAIL-CLOSED (CWE-400, LOW)** : `os.close` en échec converti, jamais d'`OSError` brute | [`allowlist.py:926–932`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L926-L932), [`scan.py:225–247`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L225-L247) | [`1015–1037`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1015-L1037) | `load_allowlist_from_file` → `ScanError` (invariant 11), `_read_worktree_file` → `None` (try imbriqué + `finally` + `except`, sans `return` en `finally`) |
| **GARDE ANTI AUTO-ATTESTATION STATIQUE (CWE-200, LOW)** : `rel_cfg`/`verified.path` jamais reflétés | [`scan.py:406–412`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L406-L412), [`419–423`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L419-L423), [`440–446`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L440-L446) | [`1039–1067`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1039-L1067), [`1069–1087`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1069-L1087) | `str(exc)` sans nom de config, préfixe `auto-attestation` conservé ; en CLI le libellé est masqué par le message générique |
| **CONFIG ILLISIBLE = CODE 2 (REQ-SEC-07, LOW)** : `exists()` en échec → `ScanError`, pas allowlist vide | [`allowlist.py:973–982`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L973-L982) | [`1089–1110`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1089-L1110) | Seule l'absence avérée vaut « pas de config » ; docstring `load_allowlist` mise à jour |
| **FERMETURE DESCRIPTEUR ÉTENDUE (CWE-400, LOW)** : `os.close` protégé dans l'index, le lecteur et la clé | [`gitdiff.py:470–477`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/mcp/gitdiff.py#L470-L477), [`detect.py:365–371`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/detect.py#L365-L371), [`hashing.py:148–154`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/hashing.py#L148-L154), [`191–197`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/hashing.py#L191-L197) | [`2188–2207`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_mcp_units.py#L2188-L2207), [`700–715`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_detect.py#L700-L715), [`718–735`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_detect.py#L718-L735) | `ToolFailure`/`ScanError` partout, jamais d'`OSError` brute ; `_read_key` et `_create_key` couverts aussi |
| **GARDE `exists()` PROTÉGÉE (REQ-SEC-07, LOW)** : `_default_config_present` → `ScanError`, pas de contournement silencieux | [`scan.py:318–328`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L318-L328), [`381–382`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L381-L382) | [`1113–1139`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1113-L1139) | Même contrat que `load_allowlist` ; figé via API (`collect` arbre + staged) et CLI (code 2, message statique) |
| **REFUS DE GARDE DISTINGUÉS EN LOGS (CWE-345, LOW)** : 5 libellés debug statiques, verdict fail-closed inchangé | [`scan.py:116–119`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L116-L119), [`250–307`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L250-L307) | [`1141–1202`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1141-L1202) | `None` légitime (untracked) vs panne (index illisible) vs dirty vs empreinte, en caplog ; aucun secret ni entrée reflétés |
| **CI ANTI AUTO-ATTESTATION DOCUMENTÉE (CWE-345, LOW)** : `--ci` + `heimdall.toml` versionné → 2, avec issue explicite | Paragraphe `--ci`/allowlist de [`docs/cli.md`](cli.md) (pas de permalien ligne : prose) | [`1581–1630`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1581-L1630) | `--config` externe épinglé ou `--no-allowlist` ; comportement déjà figé (`test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`), aide ajoutée sans toucher au libellé code 2 (anti-oracle) |
| **MARQUEURS EXACTS ANTI FOOTGUN (CWE-1188, MEDIUM)** : `exact_keywords` (égalité casefold) pour les règles globales sans `paths` | [`allowlist.py:484–490`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L484-L490), [`592–598`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L592-L598), [`799–803`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L799-L803) | [`244–266`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L244-L266), [`269–291`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L269-L291), [`304–338`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L304-L338) | `my-example-key-12345`, `prod-dummy-secret`, `admin:changeme`, `xoxb-dummy-12345` restent détectés ; seuls les marqueurs exacts sont ignorés (`heimdall.toml:23–29,31–35,37–41`) |
| **GARDE `endswith` RENDUE EXACTE (CWE-400, LOW)** : `subdir/heimdall.toml` stagé ne bloque plus le scan racine | [`scan.py:396–404`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L396-L404) | [`1980–2000`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1980-L2000) | Comparaison `== rel_cfg` sur chemins normalisés (arbre + `--config` interne) ; plus de faux refus de disponibilité, toujours fail-closed en 2 sur le chemin exact |
| **MARQUEURS EXACTS ANTI FOOTGUN (CWE-1188, MEDIUM)** : `exact_keywords` (égalité casefold) pour les règles globales sans `paths` | [`allowlist.py:484–490`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L484-L490), [`592–598`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L592-L598), [`799–803`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L799-L803) | [`244–266`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L244-L266), [`269–291`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L269-L291), [`304–338`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L304-L338) | `my-example-key-12345`, `prod-dummy-secret`, `admin:changeme`, `xoxb-dummy-12345` restent détectés ; seuls les marqueurs exacts sont ignorés (`heimdall.toml:23–29,31–35,37–41`) |
| **GARDE `endswith` RENDUE EXACTE (CWE-400, LOW)** : `subdir/heimdall.toml` stagé ne bloque plus le scan racine | [`scan.py:396–404`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/cli/scan.py#L396-L404) | [`1980–2000`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1980-L2000) | Comparaison `== rel_cfg` sur chemins normalisés (arbre + `--config` interne) ; plus de faux refus de disponibilité, toujours fail-closed en 2 sur le chemin exact |
| **TYPES FIGÉS ANTI-TYPO (CWE-20, LOW)** : `secret_types` validé contre la grammaire Finding (`[a-z][a-z0-9_]*`, 64 max), en TOML comme en API | [`allowlist.py:128–133`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L128-L133), [`807–808`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L807-L808) | [`1284–1312`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1284-L1312), [`1366–1377`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1366-L1377) | `"AWS"`, `"../etc"`, `""`, 65 caractères → `ScanError`/code 2 (plus de règle muette) ; `("aws", "generic_password")` accepté ; miroir exact de `finding._TYPE_PATTERN` |
| **CONTRÔLES INVISIBLES REFUSÉS (CWE-20, LOW)** : `Cc`/`Cf`/`Zl`/`Zp` refusés dans `keywords`/`patterns` (TOML + API), mêmes classes que `_visible` | [`allowlist.py:113–118`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L113-L118), [`697`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L697), [`758`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L758) | [`1315–1363`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L1315-L1363) | `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2 (y compris via `"""` TOML) ; échappements `\n` acceptés ; `paths` déjà couverts par la grammaire Finding (`\n` refusé, prouvé) |
| **FABRIQUES IMPLICITES SUPPRIMÉES (CWE-345, LOW)** : `Allowlist.default()`/`create_default_rules()` n'existent plus (ni méthode, ni export) | [`allowlist.py:987–1005`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/heimdall/scanner/allowlist.py#L987-L1005) (`__all__` sans fabrique) | [`916–934`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L916-L934), [`2426–2446`](https://github.com/Cezar277/heimdall/blob/861702d35b9dcd1ae533d32d796b39b78a330474/tests/test_scanner_allowlist.py#L2426-L2446) | Helper test-local `_standard_test_allowlist()` (miroir `heimdall.toml`) ; `hasattr`/`__all__` négatifs figés ; `ignored_count == 0` sans config figé |

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
97 passed

.venv/bin/pytest -o addopts="" -q
1973 passed, 15 skipped

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
[`test_scanner_allowlist.py:359–377`](../tests/test_scanner_allowlist.py#L359-L377)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:2046–2062`](../tests/test_scanner_allowlist.py#L2046-L2062)
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

Tests de non-régression : [`test_scanner_allowlist.py:2207–2352`](../tests/test_scanner_allowlist.py#L2207-L2352)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:894–934`](../heimdall/scanner/allowlist.py#L894-L934)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:2404–2423`](../tests/test_scanner_allowlist.py#L2404-L2423)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:250–307`](../heimdall/cli/scan.py#L250-L307)), le parseur les
  consomme sans relire ([`allowlist.py:874–891`](../heimdall/scanner/allowlist.py#L874-L891)),
  et un second contrôle refuse toute substitution
  ([`scan.py:331–425`](../heimdall/cli/scan.py#L331-L425),
  [`scan.py:428–447`](../heimdall/cli/scan.py#L428-L447)). Test de course :
  [`test_scanner_allowlist.py:2151–2193`](../tests/test_scanner_allowlist.py#L2151-L2193).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:2356–2399`](../tests/test_scanner_allowlist.py#L2356-L2399),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:678–696`](../heimdall/scanner/allowlist.py#L678-L696)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:1386–1402`](../tests/test_scanner_allowlist.py#L1386-L1402)
  et [`1879–1958`](../tests/test_scanner_allowlist.py#L1879-L1958).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:831–871`](../heimdall/scanner/allowlist.py#L831-L871)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:579–607`](../tests/test_scanner_allowlist.py#L579-L607).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:854–862`](../heimdall/scanner/allowlist.py#L854-L862)).
  Test : [`test_scanner_allowlist.py:610–616`](../tests/test_scanner_allowlist.py#L610-L616).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:79`](../heimdall/scanner/allowlist.py#L79),
  [`755–780`](../heimdall/scanner/allowlist.py#L755-L780),
  [`794–798`](../heimdall/scanner/allowlist.py#L794-L798)). Test :
  [`test_scanner_allowlist.py:675–698`](../tests/test_scanner_allowlist.py#L675-L698).
- **Fabriques supprimées** : `Allowlist.default()` et `create_default_rules()`
  n'existent plus (ni méthode, ni export `__all__`) : aucune règle implicite
  ne peut être branchée par erreur. `load_allowlist()` rend
  `Allowlist.empty()` sans config ([`allowlist.py:673–675`](../heimdall/scanner/allowlist.py#L673-L675),
  [`937–985`](../heimdall/scanner/allowlist.py#L937-L985)) ; les tests utilisent
  l'helper local `_standard_test_allowlist()`. Test :
  [`test_scanner_allowlist.py:937–950`](../tests/test_scanner_allowlist.py#L937-L950).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:2404–2423`](../tests/test_scanner_allowlist.py#L2404-L2423)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:171–337`](../heimdall/scanner/allowlist.py#L171-L337)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1710–1725`](../tests/test_scanner_allowlist.py#L1710-L1725)
  et [`1728–1739`](../tests/test_scanner_allowlist.py#L1728-L1739) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:699–739`](../heimdall/scanner/allowlist.py#L699-L739)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:362–413`](../heimdall/scanner/allowlist.py#L362-L413)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1742–1791`](../tests/test_scanner_allowlist.py#L1742-L1791),
  [`1794–1802`](../tests/test_scanner_allowlist.py#L1794-L1802),
  [`1805–1824`](../tests/test_scanner_allowlist.py#L1805-L1824),
  [`1827–1843`](../tests/test_scanner_allowlist.py#L1827-L1843).
- **Valeur candidate bornée** : [`allowlist.py:548–603`](../heimdall/scanner/allowlist.py#L548-L603)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1805–1824`](../tests/test_scanner_allowlist.py#L1805-L1824).
- **Typage de l'API** : [`allowlist.py:492–546`](../heimdall/scanner/allowlist.py#L492-L546)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:164–200`](../tests/test_scanner_allowlist.py#L164-L200).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:154–162`](../heimdall/scanner/allowlist.py#L154-L162))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts.

### Cinquième revue (LOW) — config externe, version obligatoire, littéraux, fnmatch borné

- **`--config` externe accepté hors CI** : [`scan.py:494–498`](../heimdall/cli/scan.py#L494-L498)
  et [`575–579`](../heimdall/cli/scan.py#L575-L579) passent désormais
  `allow_external=ci or config is not None` : un `--config` explicite peut
  vivre hors du dépôt scanné (choix opérateur, conformément à l'aide de la
  CLI), la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
  contrat fermé restant appliqués
  ([`allowlist.py:937–985`](../heimdall/scanner/allowlist.py#L937-L985)).
  Sans opt-in, le refus fail-closed reste la norme. Tests :
  [`509–542`](../tests/test_scanner_allowlist.py#L509-L542) (API : refus sans
  opt-in, acceptation avec opt-in, contenu invalide toujours refusé) et
  [`960–992`](../tests/test_scanner_allowlist.py#L960-L992) (CLI : arbre et
  staged hors CI, externe invalide → code 2).
- **`version` obligatoire** : [`allowlist.py:831–871`](../heimdall/scanner/allowlist.py#L831-L871)
  exige une `version` explicite ([`854–862`](../heimdall/scanner/allowlist.py#L854-L862)) —
  plus de défaut implicite `"1"` : une table `[allowlist]` sans `version`, un
  entier ou toute autre chaîne sont refusés en `ScanError` (code 2). Test :
  [`619–637`](../tests/test_scanner_allowlist.py#L619-L637).
- **Motifs à < 3 littéraux : refus maintenu, reformulation documentée** :
  `\d{3}-\d{4}`, `x{3}y{3}`, `[a-z]+`, `\w+` restent refusés (motifs
  aveugles, fail-closed) ; la reformulation `EXAMPLE-[0-9]{4}` est acceptée
  et n'ignore que la forme visée. Le contrat est documenté dans
  [`heimdall.toml`](../heimdall.toml) et [`docs/cli.md`](cli.md). Tests :
  [`639–672`](../tests/test_scanner_allowlist.py#L639-L672).
- **`fnmatch` borné des deux côtés** : au plus
  `MAX_PATH_WILDCARDS = 10` jokers `*` par motif (au-delà : code 2)
  ([`allowlist.py:678–696`](../heimdall/scanner/allowlist.py#L678-L696),
  constantes [`100–105`](../heimdall/scanner/allowlist.py#L100-L105)), et un
  chemin de plus de `MAX_MATCH_PATH_LENGTH = 1024` caractères n'est pas
  soumis au filtre — le candidat reste signalé (fail-closed)
  ([`allowlist.py:568–581`](../heimdall/scanner/allowlist.py#L568-L581)).
  Sous Python ≥ 3.13, `fnmatch.translate` produit des groupes atomiques
  (immunisé) ; sous les interpréteurs antérieurs, 20 `*` croisés à un chemin
  de 4 096 caractères coûtaient ≈ 1 s, les plafonds ramènent la passe sous
  la milliseconde. Fuzz adversarial borné en temps :
  [`1879–1958`](../tests/test_scanner_allowlist.py#L1879-L1958).
- **Non-régression** : la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts ; les
  plafonds `MAX_PATH_WILDCARDS = 10` et `MAX_MATCH_PATH_LENGTH = 1024` et
  l'exigence `version` sont figés par les exports vérifiés
  ([`2426–2446`](../tests/test_scanner_allowlist.py#L2426-L2446)).

### Sixième revue (LOW) — fail-closed strict et messages statiques

- **`os.close` protégé** : [`allowlist.py:926–932`](../heimdall/scanner/allowlist.py#L926-L932)
  convertit toute `OSError` en `ScanError` (contrat unique, invariant 11) ;
  [`scan.py:225–247`](../heimdall/cli/scan.py#L225-L247) rend `None`
  (fail-closed) via try imbriqué + `finally` + `except` externe — sans
  `return` en `finally` (`SyntaxWarning` évité, fermeture garantie sur
  tous les chemins). Test :
  [`1015–1037`](../tests/test_scanner_allowlist.py#L1015-L1037) (fermeture
  réelle puis panne simulée : `ScanError` d'un côté, `None` de l'autre,
  jamais d'`OSError` brute).
- **Messages de garde strictement statiques** : `rel_cfg` et `verified.path`
  (entrées opérateur normalisées) ne sont plus reflétés —
  [`scan.py:406–412`](../heimdall/cli/scan.py#L406-L412) (configuration
  stagée), [`419–423`](../heimdall/cli/scan.py#L419-L423) (worktree non
  propre en staged),
  [`440–446`](../heimdall/cli/scan.py#L440-L446) (re-contrôle anti-TOCTOU) ;
  le préfixe `auto-attestation` est conservé pour l'audit. Tests :
  [`1039–1067`](../tests/test_scanner_allowlist.py#L1039-L1067) (arbre, staged,
  `--config` interne : `str(exc)` sans nom de config) et
  [`1069–1087`](../tests/test_scanner_allowlist.py#L1069-L1087) (substitution
  entre garde et parsing).
- **`exists()` en échec → code 2** :
  [`allowlist.py:973–982`](../heimdall/scanner/allowlist.py#L973-L982)
  lève `ScanError` sur `OSError` (répertoire illisible) au lieu de rendre
  une allowlist vide silencieuse ; seule l'absence avérée vaut « pas de
  config » (le vide reste fail-closed). Test :
  [`1089–1110`](../tests/test_scanner_allowlist.py#L1089-L1110).
- **Non-régression** : la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts.

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
  [`1113–1139`](../tests/test_scanner_allowlist.py#L1113-L1139) (API arbre +
  staged et CLI → code 2, sans `OSError` brute).
- **Refus de garde distingués en logs** : [`scan.py:116–119`](../heimdall/cli/scan.py#L116-L119)
  (logger `heimdall.cli.scan`) et [`250–307`](../heimdall/cli/scan.py#L250-L307)
  journalisent chaque cause en debug avec un libellé statique — lecture
  worktree impossible, index illisible, entrée inattendue, non suivie,
  divergente, empreinte incalculable — sans refléter ni secret ni entrée ;
  le verdict reste `None` fail-closed dans tous les cas. Test :
  [`1141–1202`](../tests/test_scanner_allowlist.py#L1141-L1202) (caplog,
  quatre cas).
- **CI documentée** : `scan --ci` avec `heimdall.toml` versionné sort en 2
  sans `--config` externe ni `--no-allowlist` — c'est le choix anti
  auto-attestation documenté, pas un bypass ; [`docs/cli.md`](cli.md)
  donne désormais l'issue explicite (config externe épinglée hors dépôt,
  exemple fourni). Le comportement était déjà figé par
  `test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`
  ([`1581–1630`](../tests/test_scanner_allowlist.py#L1581-L1630)) ; le
  libellé code 2 reste générique (anti-oracle, pas de hint par cause).
- **Bruit d'audit** : `MAX_RULE_NAME_length` est déjà tout en capitales
  (vérifié mécaniquement, y compris dans l'historique) ; `Allowlist.default()`
  et `create_default_rules()` sont désormais supprimés (voir section suivante),
  le non-branchement CLI étant toujours figé par
  `test_cli_without_config_does_not_apply_default_factories`.
- **Non-régression** : la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts.

### Huitième revue (LOW) — typo morte interdite et fabriques supprimées

- **`secret_types` figé anti-typo** : [`allowlist.py:128–133`](../heimdall/scanner/allowlist.py#L128-L133)
  (miroir exact de `finding._TYPE_PATTERN`, 64 caractères max) + boucle de
  validation [`807–808`](../heimdall/scanner/allowlist.py#L807-L808) en TOML
  et `__post_init__` en API : `"AWS"`, `"../etc"`, `"foo bar"`, `""` ou 65
  caractères → `ScanError`/code 2, jamais une règle muette. Tests :
  [`1284–1312`](../tests/test_scanner_allowlist.py#L1284-L1312) (API + TOML,
  cas valides `aws`/`generic_password`) et
  [`1366–1377`](../tests/test_scanner_allowlist.py#L1366-L1377) (CLI).
- **Contrôles invisibles refusés** : [`allowlist.py:113–118`](../heimdall/scanner/allowlist.py#L113-L118)
  (mêmes catégories `Cc`/`Cf`/`Zl`/`Zp` que `_visible`) appliqué aux
  `keywords` ([`758`](../heimdall/scanner/allowlist.py#L758)), aux motifs
  ([`697`](../heimdall/scanner/allowlist.py#L697)) et à l'API
  (`__post_init__`) : `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2,
  y compris via `"""` TOML multiligne ; les échappements regex `\n` restent
  deux caractères ordinaires et acceptés. Les `paths` suivent la grammaire
  Finding #14 (inchangée) : `\n`/`\r`/`\t`/NUL déjà refusés, prouvé par
  `test_path_pattern_validation_errors`. Test :
  [`1315–1363`](../tests/test_scanner_allowlist.py#L1315-L1363).
- **Fabriques implicites supprimées** : `Allowlist.default()` et
  `create_default_rules()` retirés du module (ni méthode, ni export
  [`987–1005`](../heimdall/scanner/allowlist.py#L987-L1005)) : aucune règle
  implicite ne peut être branchée par erreur en CLI/CI. Les 4 règles
  nominales vivent dans le seul `heimdall.toml` versionné ; les tests
  utilisent l'helper local `_standard_test_allowlist()`. Figé par
  [`916–934`](../tests/test_scanner_allowlist.py#L916-L934) (règles
  versionnées + chargement) et [`2426–2446`](../tests/test_scanner_allowlist.py#L2426-L2446)
  (`hasattr`/`__all__` négatifs, `ignored_count == 0` sans config).
- **Non-régression** : la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts.

### Neuvième revue (1 MEDIUM + 2 LOW) — marqueurs exacts et garde exacte

- **Mots-clés globaux trop larges (MEDIUM)** : `example-placeholders`,
  `changeme` et `dummy` n'ignorent plus que leurs marqueurs exacts
  (`exact_keywords`, égalité insensible à la casse) au lieu d'un `\b`
  aveugle : `my-example-key-12345`, `prod-dummy-secret`,
  `admin:changeme` et `xoxb-dummy-12345` restent détectés (invariant 1 :
  doute → signalé). Seule la valeur exacte est ignorée ;
  `test-fixtures` garde la frontière `\b` stricte *et* ses `paths`.
  `AllowlistRule` accepte le nouveau critère en TOML comme en API
  (même validation : type, contrôles, `MIN_KEYWORD_LENGTH`), et le
  contrat aveugle reste refusé (`exact_keywords` compte comme critère
  valeur). Tests : [`244–266`](../tests/test_scanner_allowlist.py#L244-L266)
  (`changeme` exact seul), [`269–291`](../tests/test_scanner_allowlist.py#L269-L291)
  (`dummy` exact seul) et [`304–338`](../tests/test_scanner_allowlist.py#L304-L338)
  (valeurs choisies délimitées toujours détectées, marqueurs exacts ignorés).
- **Sur-blocage `endswith` (LOW)** : la garde anti auto-attestation compare
  désormais le chemin normalisé exact (`== rel_cfg`,
  [`scan.py:396–404`](../heimdall/cli/scan.py#L396-L404)) au lieu de
  `endswith("/" + rel_cfg)` : `subdir/heimdall.toml` (ou
  `subdir/custom.toml` avec `--config`) stagé ne bloque plus le scan
  (disponibilité), sans rien changer au refus fail-closed du chemin exact.
  Test : [`1980–2000`](../tests/test_scanner_allowlist.py#L1980-L2000)
  (arbre + `--config` interne).
- **Casse des plafonds (LOW)** : le fichier est byte-pour-byte tout en
  capitales (`MAX_RULE_NAME_length`, vérifié par `od`/comparaisons exactes
  à chaque revue, y compris dans l'historique) ; l'invariant est désormais
  testé en dur ([`2003–2007`](../tests/test_scanner_allowlist.py#L2003-L2007) :
  tout `MAX_*`/`MIN_*` du module doit égaler son `.upper()`), ce qui clôt
  le débat par du code plutôt que par des mots.
- **Non-régression** : la suite complète passe à
  **1973 passed, 15 skipped** et les 97 tests d'allowlist sont verts.
