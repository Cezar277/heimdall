# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`bbc51ae1d93811609ed9d12ffba467bccc4b2cb5`](https://github.com/Cezar277/heimdall/commit/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`heimdall.toml:23–29`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall.toml#L23-L29) | [`tests/test_scanner_allowlist.py:215–242`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L215-L242) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`heimdall.toml:31–35`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall.toml#L31-L35) | [`tests/test_scanner_allowlist.py:245–267`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L245-L267) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`heimdall.toml:37–41`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall.toml#L37-L41) | [`tests/test_scanner_allowlist.py:270–302`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L270-L302) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`heimdall.toml:43–66`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall.toml#L43-L66) | [`tests/test_scanner_allowlist.py:413–429`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L413-L429), [`432–498`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L432-L498) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:440–458`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L440-L458), [`555–610`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L555-L610) | [`tests/test_scanner_allowlist.py:501–520`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L501-L520), [`1796–1843`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1796-L1843), [`2217–2233`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2217-L2233) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:555–610`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L555-L610) | [`tests/test_scanner_allowlist.py:1640–1673`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1640-L1673) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:331–425`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L331-L425), [`477–486`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L477-L486), [`555–567`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L555-L567), [`647–653`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L647-L653) | [`1742–1793`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1742-L1793), [`2236–2365`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2236-L2365), [`2528–2576`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2528-L2576), [`2577–2596`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2577-L2596) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:901–941`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L901-L941), [`interface.py:38–71`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/interface.py#L38-L71) | [`591–624`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L591-L624), [`1547–1563`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1547-L1563) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:171–337`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L171-L337), [`706–746`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L706-L746) | [`1854–1875`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1854-L1875), [`1878–1907`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1878-L1907), [`1566–1573`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1566-L1573), [`2049–2147`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2049-L2147) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:87–105`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L87-L105), [`362–413`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L362-L413), [`706–746`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L706-L746) | [`1910–1960`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1910-L1960), [`1963–1971`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1963-L1971), [`1974–1994`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1974-L1994), [`1997–2013`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1997-L2013) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:492–546`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L492-L546) | [`164–201`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L164-L201) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:653–677`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L653-L677), [`detect.py:470–483`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/detect.py#L470-L483) | [`523–550`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L523-L550), [`553–565`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L553-L565) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:709–737`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L709-L737) | [`852–870`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L852-L870), [`2180–2214`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2180-L2214) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/schemas/scan.schema.json#L15-L81), [`scan.py:665–688`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L665-L688) | [`873–884`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L873-L884), [`2180–2214`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2180-L2214), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/main.py#L163-L176) | [`956–1016`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L956-L1016), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:417–437`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L417-L437), [`653–677`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L653-L677) | [`553–565`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L553-L565), [`1796–1843`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1796-L1843), [`2180–2214`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2180-L2214) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` obligatoire et typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:762–787`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L762-L787), [`838–878`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L838-L878), [`861–869`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L861-L869), [`801–805`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L801-L805) | [`697–818`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L697-L818), [`737–755`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L737-L755), [`1576–1621`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1576-L1621) | `[tool.foo]`, `version` absente ou `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:901–941`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L901-L941) | [`2577–2596`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2577-L2596) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |
| **--CONFIG EXTERNE (CWE-345, LOW)** : `--config` hors dépôt accepté comme choix opérateur, gardes inchangées | [`allowlist.py:944–992`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L944-L992), [`scan.py:494–498`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L494-L498), [`575–579`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L575-L579) | [`627–660`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L627-L660), [`1119–1151`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1119-L1151) | Opt-in explicite : arbre et staged hors CI acceptés, contenu invalide toujours code 2 ; sans opt-in refus fail-closed inchangé |
| **FILTRE CHEMIN BORNÉ (CWE-400, LOW)** : au plus 10 jokers `*` par motif, chemin soumis à `fnmatch` borné à 1024 | [`allowlist.py:685–703`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L685-L703), [`575–588`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L575-L588), [`100–105`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L100-L105) | [`2049–2147`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2049-L2147), [`1547–1563`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1547-L1563) | Au-delà de 10 `*` → code 2 ; chemin > 1024 non soumis au filtre, candidat reste signalé (fail-closed) ; fuzz adversarial borné (< 1 ms) |
| **FERMETURE DESCRIPTEUR FAIL-CLOSED (CWE-400, LOW)** : `os.close` en échec converti, jamais d'`OSError` brute | [`allowlist.py:933–939`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L933-L939), [`scan.py:225–247`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L225-L247) | [`1174–1196`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1174-L1196) | `load_allowlist_from_file` → `ScanError` (invariant 11), `_read_worktree_file` → `None` (try imbriqué + `finally` + `except`, sans `return` en `finally`) |
| **GARDE ANTI AUTO-ATTESTATION STATIQUE (CWE-200, LOW)** : `rel_cfg`/`verified.path` jamais reflétés | [`scan.py:406–412`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L406-L412), [`419–423`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L419-L423), [`440–446`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L440-L446) | [`1198–1226`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1198-L1226), [`1228–1246`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1228-L1246) | `str(exc)` sans nom de config, préfixe `auto-attestation` conservé ; en CLI le libellé est masqué par le message générique |
| **CONFIG ILLISIBLE = CODE 2 (REQ-SEC-07, LOW)** : `exists()` en échec → `ScanError`, pas allowlist vide | [`allowlist.py:980–989`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L980-L989) | [`1248–1269`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1248-L1269) | Seule l'absence avérée vaut « pas de config » ; docstring `load_allowlist` mise à jour |
| **FERMETURE DESCRIPTEUR ÉTENDUE (CWE-400, LOW)** : `os.close` protégé dans l'index, le lecteur et la clé | [`gitdiff.py:470–477`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/mcp/gitdiff.py#L470-L477), [`detect.py:365–371`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/detect.py#L365-L371), [`hashing.py:148–154`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/hashing.py#L148-L154), [`191–197`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/hashing.py#L191-L197) | [`2188–2207`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_mcp_units.py#L2188-L2207), [`700–715`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_detect.py#L700-L715), [`718–735`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_detect.py#L718-L735) | `ToolFailure`/`ScanError` partout, jamais d'`OSError` brute ; `_read_key` et `_create_key` couverts aussi |
| **GARDE `exists()` PROTÉGÉE (REQ-SEC-07, LOW)** : `_default_config_present` → `ScanError`, pas de contournement silencieux | [`scan.py:318–328`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L318-L328), [`381–382`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L381-L382) | [`1272–1298`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1272-L1298) | Même contrat que `load_allowlist` ; figé via API (`collect` arbre + staged) et CLI (code 2, message statique) |
| **REFUS DE GARDE DISTINGUÉS EN LOGS (CWE-345, LOW)** : 5 libellés debug statiques, verdict fail-closed inchangé | [`scan.py:116–119`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L116-L119), [`250–307`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L250-L307) | [`1300–1364`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1300-L1364) | `None` légitime (untracked) vs panne (index illisible) vs dirty vs empreinte, en caplog ; aucun secret ni entrée reflétés |
| **CI ANTI AUTO-ATTESTATION DOCUMENTÉE (CWE-345, LOW)** : `--ci` + `heimdall.toml` versionné → 2, avec issue explicite | Paragraphe `--ci`/allowlist de [`docs/cli.md`](cli.md) (pas de permalien ligne : prose) | [`1742–1793`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1742-L1793) | `--config` externe épinglé ou `--no-allowlist` ; comportement déjà figé (`test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`), aide ajoutée sans toucher au libellé code 2 (anti-oracle) |
| **MARQUEURS EXACTS ANTI FOOTGUN (CWE-1188, MEDIUM)** : `exact_keywords` (égalité casefold) pour les règles globales sans `paths` | [`allowlist.py:484–490`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L484-L490), [`599–605`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L599-L605), [`806–810`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L806-L810) | [`245–267`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L245-L267), [`270–302`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L270-L302), [`377–410`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L377-L410) | `my-example-key-12345`, `prod-dummy-secret`, `admin:changeme`, `xoxb-dummy-12345` restent détectés ; seuls les marqueurs exacts sont ignorés (`heimdall.toml:23–29,31–35,37–41`) |
| **GARDE `endswith` RENDUE EXACTE (CWE-400, LOW)** : `subdir/heimdall.toml` stagé ne bloque plus le scan racine | [`scan.py:396–404`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/cli/scan.py#L396-L404) | [`2150–2170`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2150-L2170) | Comparaison `== rel_cfg` sur chemins normalisés (arbre + `--config` interne) ; plus de faux refus de disponibilité, toujours fail-closed en 2 sur le chemin exact |
| **ZONE DE CLÉMENCE TESTS DOCUMENTÉE (CWE-1188, MEDIUM)** : `test-fixtures` ignore tout marqueur délimité sous `tests/` — volontaire et documenté, jamais de vrai secret hors périmètre | [`heimdall.toml:43–66`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall.toml#L43-L66) | [`453–495`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L453-L495) | `my-dummy-key-12345`/`prod-fake-token` ignorés sous `tests/`, détectés hors périmètre ; exacts (`dummy`, `changeme`, `sample`) toujours ignorés ; CI sans allowlist signale tout |
| **TYPES FIGÉS ANTI-TYPO (CWE-20, LOW)** : `secret_types` validé contre la grammaire Finding (`[a-z][a-z0-9_]*`, 64 max), en TOML comme en API | [`allowlist.py:128–133`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L128-L133), [`814–815`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L814-L815) | [`1443–1471`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1443-L1471), [`1527–1538`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1527-L1538) | `"AWS"`, `"../etc"`, `""`, 65 caractères → `ScanError`/code 2 (plus de règle muette) ; `("aws", "generic_password")` accepté ; miroir exact de `finding._TYPE_PATTERN` |
| **CONTRÔLES INVISIBLES REFUSÉS (CWE-20, LOW)** : `Cc`/`Cf`/`Zl`/`Zp` refusés dans `keywords`/`patterns` (TOML + API), mêmes classes que `_visible` | [`allowlist.py:113–118`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L113-L118), [`697`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L697), [`758`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L758) | [`1474–1524`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1474-L1524) | `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2 (y compris via `"""` TOML) ; échappements `\n` acceptés ; `paths` déjà couverts par la grammaire Finding (`\n` refusé, prouvé) |
| **FABRIQUES IMPLICITES SUPPRIMÉES (CWE-345, LOW)** : `Allowlist.default()`/`create_default_rules()` n'existent plus (ni méthode, ni export) | [`allowlist.py:994–1012`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L994-L1012) (`__all__` sans fabrique) | [`1075–1093`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1075-L1093), [`2599–2619`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L2599-L2619) | Helper test-local `_standard_test_allowlist()` (miroir `heimdall.toml`) ; `hasattr`/`__all__` négatifs figés ; `ignored_count == 0` sans config figé |
| **GLOBAL SOUMIS À RESTRICTION (CWE-1188, MEDIUM)** : `keywords`/`patterns` exigent `paths`/`secret_types` ; seuls `exact_keywords` restent globaux | [`allowlist.py:547–553`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/heimdall/scanner/allowlist.py#L547-L553) | [`305–351`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L305-L351), [`354–374`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L354-L374) | `keywords=["example"]` / `patterns=["EXAMPLE.*"]` globaux → `ScanError`/code 2 (TOML + API + CLI) ; restreints ou exacts acceptés ; `my-example-key-12345` reste détecté |
| **FICHE TOML == CONFIG (CWE-20, LOW)** : le bloc TOML de la fiche parse à l'identique de `heimdall.toml` | Bloc ```toml de [`docs/t24-samm.md`](t24-samm.md#fichier-versionné-heimdalltoml) (pas de permalien ligne : prose) | [`1041–1072`](https://github.com/Cezar277/heimdall/blob/bbc51ae1d93811609ed9d12ffba467bccc4b2cb5/tests/test_scanner_allowlist.py#L1041-L1072) | Non-régression anti-dérive : tout `keywords` global réintroduit fait échouer le parse ; comparaison règle par règle (nom, description, critères) |

## Fichier versionné `heimdall.toml`

Le fichier [`heimdall.toml`](../heimdall.toml) est versionné à la racine du dépôt.
Il active les quatre familles de règles requises par le ticket #24.

```toml
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "Mots-clés et jetons d'exemple évidents (ex: AKIA...EXAMPLE, your_key_here)"
# Marqueurs EXACTS (égalité insensible à la casse) : un secret choisi
# contenant `-example-` délimité (ex. `my-example-key-12345`) reste détecté
# (invariant 1 : doute → signalé). Ne jamais repasser en `keywords` \b.
exact_keywords = ["AKIAIOSFODNN7EXAMPLE", "example", "sample", "your_key_here"]

[[allowlist.rules]]
name = "changeme-passwords"
description = "Mots de passe ou valeurs de configuration par défaut changeme"
# Exact : `admin:changeme` reste détecté (credential par défaut = finding).
exact_keywords = ["changeme"]

[[allowlist.rules]]
name = "dummy-tokens"
description = "Valeurs, identifiants et jetons factices dummy"
# Exact : `prod-dummy-secret` ou `xoxb-dummy-12345` restent détectés.
exact_keywords = ["dummy"]

[[allowlist.rules]]
name = "test-fixtures"
description = "Fixtures et valeurs factices explicites dans les répertoires et fichiers de test"
# Frontière \b stricte, y compris avec `paths` : `_` est un caractère de mot.
# `fake_slack_token` ou `my_dummy_key` NE sont PAS ignorés (invariant 1) ;
# utiliser une valeur exacte (`dummy`) ou un séparateur non-mot (`fake-token`).
# ZONE DE CLÉMENCE DOCUMENTÉE : sous `tests/` (et `fixtures/`, `support/`),
# TOUTE valeur contenant un marqueur délimité (`my-dummy-key-12345`,
# `prod-fake-token`) est ignorée, y compris un mot de passe choisi qui
# ressemblerait à une fixture. C'est volontaire : les répertoires de test
# ne doivent jamais contenir de vrais secrets (aucun allowlist aveugle
# hors de ce périmètre) ; en CI stricte (sans `heimdall.toml`, allowlist
# vide) tout y est signalé. Ne pas élargir : ni `secret_types` global ni
# `\b` hors `paths`.
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
101 passed

.venv/bin/pytest -o addopts="" -q
1977 passed, 15 skipped

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
[`test_scanner_allowlist.py:432–498`](../tests/test_scanner_allowlist.py#L432-L498)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:2217–2233`](../tests/test_scanner_allowlist.py#L2217-L2233)
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

Tests de non-régression : [`test_scanner_allowlist.py:2379–2524`](../tests/test_scanner_allowlist.py#L2379-L2524)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:901–941`](../heimdall/scanner/allowlist.py#L901-L941)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:2577–2596`](../tests/test_scanner_allowlist.py#L2577-L2596)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:250–307`](../heimdall/cli/scan.py#L250-L307)), le parseur les
  consomme sans relire ([`allowlist.py:881–898`](../heimdall/scanner/allowlist.py#L881-L898)),
  et un second contrôle refuse toute substitution
  ([`scan.py:331–425`](../heimdall/cli/scan.py#L331-L425),
  [`scan.py:428–447`](../heimdall/cli/scan.py#L428-L447)). Test de course :
  [`test_scanner_allowlist.py:2322–2376`](../tests/test_scanner_allowlist.py#L2322-L2376).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:2528–2576`](../tests/test_scanner_allowlist.py#L2528-L2576),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:685–703`](../heimdall/scanner/allowlist.py#L685-L703)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:1547–1563`](../tests/test_scanner_allowlist.py#L1547-L1563)
  et [`2049–2147`](../tests/test_scanner_allowlist.py#L2049-L2147).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:838–878`](../heimdall/scanner/allowlist.py#L838-L878)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:697–725`](../tests/test_scanner_allowlist.py#L697-L725).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:861–869`](../heimdall/scanner/allowlist.py#L861-L869)).
  Test : [`test_scanner_allowlist.py:728–734`](../tests/test_scanner_allowlist.py#L728-L734).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:79`](../heimdall/scanner/allowlist.py#L79),
  [`762–787`](../heimdall/scanner/allowlist.py#L762-L787),
  [`801–805`](../heimdall/scanner/allowlist.py#L801-L805)). Test :
  [`test_scanner_allowlist.py:794–818`](../tests/test_scanner_allowlist.py#L794-L818).
- **Fabriques supprimées** : `Allowlist.default()` et `create_default_rules()`
  n'existent plus (ni méthode, ni export `__all__`) : aucune règle implicite
  ne peut être branchée par erreur. `load_allowlist()` rend
  `Allowlist.empty()` sans config ([`allowlist.py:680–682`](../heimdall/scanner/allowlist.py#L680-L682),
  [`944–992`](../heimdall/scanner/allowlist.py#L944-L992)) ; les tests utilisent
  l'helper local `_standard_test_allowlist()`. Test :
  [`test_scanner_allowlist.py:1096–1109`](../tests/test_scanner_allowlist.py#L1096-L1109).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:2577–2596`](../tests/test_scanner_allowlist.py#L2577-L2596)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:171–337`](../heimdall/scanner/allowlist.py#L171-L337)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1878–1893`](../tests/test_scanner_allowlist.py#L1878-L1893)
  et [`1896–1907`](../tests/test_scanner_allowlist.py#L1896-L1907) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:706–746`](../heimdall/scanner/allowlist.py#L706-L746)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:362–413`](../heimdall/scanner/allowlist.py#L362-L413)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1910–1960`](../tests/test_scanner_allowlist.py#L1910-L1960),
  [`1963–1971`](../tests/test_scanner_allowlist.py#L1963-L1971),
  [`1974–1994`](../tests/test_scanner_allowlist.py#L1974-L1994),
  [`1997–2013`](../tests/test_scanner_allowlist.py#L1997-L2013).
- **Valeur candidate bornée** : [`allowlist.py:555–610`](../heimdall/scanner/allowlist.py#L555-L610)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1974–1994`](../tests/test_scanner_allowlist.py#L1974-L1994).
- **Typage de l'API** : [`allowlist.py:492–546`](../heimdall/scanner/allowlist.py#L492-L546)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:164–201`](../tests/test_scanner_allowlist.py#L164-L201).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:154–162`](../heimdall/scanner/allowlist.py#L154-L162))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

### Cinquième revue (LOW) — config externe, version obligatoire, littéraux, fnmatch borné

- **`--config` externe accepté hors CI** : [`scan.py:494–498`](../heimdall/cli/scan.py#L494-L498)
  et [`575–579`](../heimdall/cli/scan.py#L575-L579) passent désormais
  `allow_external=ci or config is not None` : un `--config` explicite peut
  vivre hors du dépôt scanné (choix opérateur, conformément à l'aide de la
  CLI), la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
  contrat fermé restant appliqués
  ([`allowlist.py:944–992`](../heimdall/scanner/allowlist.py#L944-L992)).
  Sans opt-in, le refus fail-closed reste la norme. Tests :
  [`627–660`](../tests/test_scanner_allowlist.py#L627-L660) (API : refus sans
  opt-in, acceptation avec opt-in, contenu invalide toujours refusé) et
  [`1119–1151`](../tests/test_scanner_allowlist.py#L1119-L1151) (CLI : arbre et
  staged hors CI, externe invalide → code 2).
- **`version` obligatoire** : [`allowlist.py:838–878`](../heimdall/scanner/allowlist.py#L838-L878)
  exige une `version` explicite ([`861–869`](../heimdall/scanner/allowlist.py#L861-L869)) —
  plus de défaut implicite `"1"` : une table `[allowlist]` sans `version`, un
  entier ou toute autre chaîne sont refusés en `ScanError` (code 2). Test :
  [`737–755`](../tests/test_scanner_allowlist.py#L737-L755).
- **Motifs à < 3 littéraux : refus maintenu, reformulation documentée** :
  `\d{3}-\d{4}`, `x{3}y{3}`, `[a-z]+`, `\w+` restent refusés (motifs
  aveugles, fail-closed) ; la reformulation `EXAMPLE-[0-9]{4}` est acceptée
  et n'ignore que la forme visée. Le contrat est documenté dans
  [`heimdall.toml`](../heimdall.toml) et [`docs/cli.md`](cli.md). Tests :
  [`757–791`](../tests/test_scanner_allowlist.py#L757-L791).
- **`fnmatch` borné des deux côtés** : au plus
  `MAX_PATH_WILDCARDS = 10` jokers `*` par motif (au-delà : code 2)
  ([`allowlist.py:685–703`](../heimdall/scanner/allowlist.py#L685-L703),
  constantes [`100–105`](../heimdall/scanner/allowlist.py#L100-L105)), et un
  chemin de plus de `MAX_MATCH_PATH_LENGTH = 1024` caractères n'est pas
  soumis au filtre — le candidat reste signalé (fail-closed)
  ([`allowlist.py:575–588`](../heimdall/scanner/allowlist.py#L575-L588)).
  Sous Python ≥ 3.13, `fnmatch.translate` produit des groupes atomiques
  (immunisé) ; sous les interpréteurs antérieurs, 20 `*` croisés à un chemin
  de 4 096 caractères coûtaient ≈ 1 s, les plafonds ramènent la passe sous
  la milliseconde. Fuzz adversarial borné en temps :
  [`2049–2147`](../tests/test_scanner_allowlist.py#L2049-L2147).
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts ; les
  plafonds `MAX_PATH_WILDCARDS = 10` et `MAX_MATCH_PATH_LENGTH = 1024` et
  l'exigence `version` sont figés par les exports vérifiés
  ([`2599–2619`](../tests/test_scanner_allowlist.py#L2599-L2619)).

### Sixième revue (LOW) — fail-closed strict et messages statiques

- **`os.close` protégé** : [`allowlist.py:933–939`](../heimdall/scanner/allowlist.py#L933-L939)
  convertit toute `OSError` en `ScanError` (contrat unique, invariant 11) ;
  [`scan.py:225–247`](../heimdall/cli/scan.py#L225-L247) rend `None`
  (fail-closed) via try imbriqué + `finally` + `except` externe — sans
  `return` en `finally` (`SyntaxWarning` évité, fermeture garantie sur
  tous les chemins). Test :
  [`1174–1196`](../tests/test_scanner_allowlist.py#L1174-L1196) (fermeture
  réelle puis panne simulée : `ScanError` d'un côté, `None` de l'autre,
  jamais d'`OSError` brute).
- **Messages de garde strictement statiques** : `rel_cfg` et `verified.path`
  (entrées opérateur normalisées) ne sont plus reflétés —
  [`scan.py:406–412`](../heimdall/cli/scan.py#L406-L412) (configuration
  stagée), [`419–423`](../heimdall/cli/scan.py#L419-L423) (worktree non
  propre en staged),
  [`440–446`](../heimdall/cli/scan.py#L440-L446) (re-contrôle anti-TOCTOU) ;
  le préfixe `auto-attestation` est conservé pour l'audit. Tests :
  [`1198–1226`](../tests/test_scanner_allowlist.py#L1198-L1226) (arbre, staged,
  `--config` interne : `str(exc)` sans nom de config) et
  [`1228–1246`](../tests/test_scanner_allowlist.py#L1228-L1246) (substitution
  entre garde et parsing).
- **`exists()` en échec → code 2** :
  [`allowlist.py:980–989`](../heimdall/scanner/allowlist.py#L980-L989)
  lève `ScanError` sur `OSError` (répertoire illisible) au lieu de rendre
  une allowlist vide silencieuse ; seule l'absence avérée vaut « pas de
  config » (le vide reste fail-closed). Test :
  [`1248–1269`](../tests/test_scanner_allowlist.py#L1248-L1269).
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

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
  [`1272–1298`](../tests/test_scanner_allowlist.py#L1272-L1298) (API arbre +
  staged et CLI → code 2, sans `OSError` brute).
- **Refus de garde distingués en logs** : [`scan.py:116–119`](../heimdall/cli/scan.py#L116-L119)
  (logger `heimdall.cli.scan`) et [`250–307`](../heimdall/cli/scan.py#L250-L307)
  journalisent chaque cause en debug avec un libellé statique — lecture
  worktree impossible, index illisible, entrée inattendue, non suivie,
  divergente, empreinte incalculable — sans refléter ni secret ni entrée ;
  le verdict reste `None` fail-closed dans tous les cas. Test :
  [`1300–1364`](../tests/test_scanner_allowlist.py#L1300-L1364) (caplog,
  quatre cas).
- **CI documentée** : `scan --ci` avec `heimdall.toml` versionné sort en 2
  sans `--config` externe ni `--no-allowlist` — c'est le choix anti
  auto-attestation documenté, pas un bypass ; [`docs/cli.md`](cli.md)
  donne désormais l'issue explicite (config externe épinglée hors dépôt,
  exemple fourni). Le comportement était déjà figé par
  `test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`
  ([`1742–1793`](../tests/test_scanner_allowlist.py#L1742-L1793)) ; le
  libellé code 2 reste générique (anti-oracle, pas de hint par cause).
- **Bruit d'audit** : `MAX_RULE_NAME_length` est déjà tout en capitales
  (vérifié mécaniquement, y compris dans l'historique) ; `Allowlist.default()`
  et `create_default_rules()` sont désormais supprimés (voir section suivante),
  le non-branchement CLI étant toujours figé par
  `test_cli_without_config_does_not_apply_default_factories`.
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

### Huitième revue (LOW) — typo morte interdite et fabriques supprimées

- **`secret_types` figé anti-typo** : [`allowlist.py:128–133`](../heimdall/scanner/allowlist.py#L128-L133)
  (miroir exact de `finding._TYPE_PATTERN`, 64 caractères max) + boucle de
  validation [`814–815`](../heimdall/scanner/allowlist.py#L814-L815) en TOML
  et `__post_init__` en API : `"AWS"`, `"../etc"`, `"foo bar"`, `""` ou 65
  caractères → `ScanError`/code 2, jamais une règle muette. Tests :
  [`1443–1471`](../tests/test_scanner_allowlist.py#L1443-L1471) (API + TOML,
  cas valides `aws`/`generic_password`) et
  [`1527–1538`](../tests/test_scanner_allowlist.py#L1527-L1538) (CLI).
- **Contrôles invisibles refusés** : [`allowlist.py:113–118`](../heimdall/scanner/allowlist.py#L113-L118)
  (mêmes catégories `Cc`/`Cf`/`Zl`/`Zp` que `_visible`) appliqué aux
  `keywords` ([`758`](../heimdall/scanner/allowlist.py#L758)), aux motifs
  ([`697`](../heimdall/scanner/allowlist.py#L697)) et à l'API
  (`__post_init__`) : `\n`/`\r`/`\t`/RLO/DEL littéraux → `ScanError`/code 2,
  y compris via `"""` TOML multiligne ; les échappements regex `\n` restent
  deux caractères ordinaires et acceptés. Les `paths` suivent la grammaire
  Finding #14 (inchangée) : `\n`/`\r`/`\t`/NUL déjà refusés, prouvé par
  `test_path_pattern_validation_errors`. Test :
  [`1474–1524`](../tests/test_scanner_allowlist.py#L1474-L1524).
- **Fabriques implicites supprimées** : `Allowlist.default()` et
  `create_default_rules()` retirés du module (ni méthode, ni export
  [`994–1012`](../heimdall/scanner/allowlist.py#L994-L1012)) : aucune règle
  implicite ne peut être branchée par erreur en CLI/CI. Les 4 règles
  nominales vivent dans le seul `heimdall.toml` versionné ; les tests
  utilisent l'helper local `_standard_test_allowlist()`. Figé par
  [`1075–1093`](../tests/test_scanner_allowlist.py#L1075-L1093) (règles
  versionnées + chargement) et [`2599–2619`](../tests/test_scanner_allowlist.py#L2599-L2619)
  (`hasattr`/`__all__` négatifs, `ignored_count == 0` sans config).
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

### Neuvième revue (1 MEDIUM + 2 LOW) — global restreint et fiche resynchronisée

- **Globaux restreints (MEDIUM)** : un `keywords` ou un `patterns` sans
  `paths` ni `secret_types` est désormais refusé en `ScanError` (code 2),
  en TOML comme en API ([`allowlist.py:547–553`](../heimdall/scanner/allowlist.py#L547-L553)) :
  seuls les `exact_keywords` peuvent être globaux. `keywords=["example"]`
  et `patterns=["EXAMPLE.*"]` globaux ne peuvent plus ignorer
  silencieusement `my-example-key-12345` (invariant 1). Les règles
  restreintes (`paths` et/ou `secret_types`) sont inchangées, y compris
  `test-fixtures`. Tests :
  [`305–351`](../tests/test_scanner_allowlist.py#L305-L351) (TOML + API,
  cas restreints acceptés) et
  [`354–374`](../tests/test_scanner_allowlist.py#L354-L374) (CLI : global
  → 2, restreint → verdict normal).
- **Fiche TOML resynchronisée (LOW)** : le bloc TOML de la fiche montrait
  encore des `keywords` globaux, réintroduisant par copier-coller le
  footgun corrigé. Il est remplacé par le contenu réel de `heimdall.toml`
  (`exact_keywords`), et un test fige l'égalité règle par règle :
  [`1041–1072`](../tests/test_scanner_allowlist.py#L1041-L1072). Tout
  `keywords` global réintroduit fait échouer le parse — la dérive est
  impossible sans casser la suite.
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

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
  valeur). Tests : [`245–267`](../tests/test_scanner_allowlist.py#L245-L267)
  (`changeme` exact seul), [`270–302`](../tests/test_scanner_allowlist.py#L270-L302)
  (`dummy` exact seul) et [`377–410`](../tests/test_scanner_allowlist.py#L377-L410)
  (valeurs choisies délimitées toujours détectées, marqueurs exacts ignorés).
- **Sur-blocage `endswith` (LOW)** : la garde anti auto-attestation compare
  désormais le chemin normalisé exact (`== rel_cfg`,
  [`scan.py:396–404`](../heimdall/cli/scan.py#L396-L404)) au lieu de
  `endswith("/" + rel_cfg)` : `subdir/heimdall.toml` (ou
  `subdir/custom.toml` avec `--config`) stagé ne bloque plus le scan
  (disponibilité), sans rien changer au refus fail-closed du chemin exact.
  Test : [`2150–2170`](../tests/test_scanner_allowlist.py#L2150-L2170)
  (arbre + `--config` interne).
- **Casse des plafonds (LOW)** : le fichier est byte-pour-byte tout en
  capitales (`MAX_RULE_NAME_length`, vérifié par `od`/comparaisons exactes
  à chaque revue, y compris dans l'historique) ; l'invariant est désormais
  testé en dur ([`2173–2177`](../tests/test_scanner_allowlist.py#L2173-L2177) :
  tout `MAX_*`/`MIN_*` du module doit égaler son `.upper()`), ce qui clôt
  le débat par du code plutôt que par des mots.
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.

### Onzième revue (1 MEDIUM + 2 LOW) — clémence tests documentée, casse et arbre figés

- **Zone de clémence `tests/` documentée (MEDIUM)** : `test-fixtures` ignore
  tout marqueur délimité sous `tests/`/`fixtures/`/`support/` — y compris un
  mot de passe choisi comme `my-dummy-key-12345` — et c'est écrit noir sur
  blanc dans [`heimdall.toml`](../heimdall.toml) : ces répertoires ne doivent
  jamais contenir de vrais secrets, et la CI stricte (sans `heimdall.toml`,
  allowlist vide) y signale tout. Ni `secret_types` (non discriminant : un
  faux et un vrai secret partagent le même type) ni `exact_keywords`
  (faux-positifs sur chaque fixture variée) ne conviennent : la restriction
  par `paths` reste le bon instrument, explicite et auditable. Test :
  [`453–495`](../tests/test_scanner_allowlist.py#L453-L495) (ignoré sous
  `tests/`, détecté hors périmètre, exacts toujours ignorés).
- **Casse des plafonds (LOW)** : `MAX_RULE_NAME_length` est byte-pour-byte
  tout en capitales (`od`/comparaisons exactes à chaque revue, y compris
  dans l'historique : `UUU_UUUU_UUUU_UUUUUU`, aucun identifiant mixte dans
  le dépôt) ; l'invariant est testé en dur
  ([`2173–2177`](../tests/test_scanner_allowlist.py#L2173-L2177) : tout
  `MAX_*`/`MIN_*` du module doit égaler son `.upper()`).
- **Arbre local non-CI (LOW)** : le comportement indicatif est figé tel quel
  (déjà couvert par
  [`test_tree_scan_dirty_or_untracked_config_is_advisory_but_ci_and_staged_refuse`](../tests/test_scanner_allowlist.py#L2528-L2572)
  : `EXIT_CLEAN` en arbre avec config dirty/untracked, code 2 en `--ci` et
  `--staged`) et documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes) ; étendre le contrôle
  casserait le diagnostic local sans gain de sécurité opposable.
- **Non-régression** : la suite complète passe à
  **1977 passed, 15 skipped** et les 101 tests d'allowlist sont verts.
