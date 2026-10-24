# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`35713ca64e1defad1c18514ef2364e48dd00d423`](https://github.com/Cezar277/heimdall/commit/35713ca64e1defad1c18514ef2364e48dd00d423).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`allowlist.py:642–646`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L642-L646), [`heimdall.toml:23–26`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall.toml#L23-L26) | [`tests/test_scanner_allowlist.py:166–193`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L166-L193) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`allowlist.py:647–651`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L647-L651), [`heimdall.toml:28–31`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall.toml#L28-L31) | [`tests/test_scanner_allowlist.py:196–211`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L196-L211) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`allowlist.py:652–656`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L652-L656), [`heimdall.toml:33–36`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall.toml#L33-L36) | [`tests/test_scanner_allowlist.py:214–229`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L214-L229) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`allowlist.py:657–673`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L657-L673), [`heimdall.toml:38–53`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall.toml#L38-L53) | [`tests/test_scanner_allowlist.py:232–248`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L232-L248), [`251–269`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L251-L269) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:410–428`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L410-L428), [`495–543`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L495-L543) | [`tests/test_scanner_allowlist.py:275–291`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L275-L291), [`1335–1377`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1335-L1377), [`1699–1715`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1699-L1715) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:495–543`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L495-L543) | [`tests/test_scanner_allowlist.py:1181–1214`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1181-L1214) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:296–387`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L296-L387), [`439–448`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L439-L448), [`517–529`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L517-L529), [`609–615`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L609-L615) | [`1241–1332`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1241-L1332), [`1718–1846`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1718-L1846), [`2009–2052`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L2009-L2052), [`2057–2076`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L2057-L2076) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:875–915`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L875-L915), [`interface.py:38–71`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/interface.py#L38-L71) | [`365–398`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L365-L398), [`1088–1104`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1088-L1104) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:141–307`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L141-L307), [`698–734`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L698-L734) | [`1388–1409`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1388-L1409), [`1412–1441`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1412-L1441), [`1107–1114`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1107-L1114), [`1581–1660`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1581-L1660) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:86–104`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L86-L104), [`332–383`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L332-L383), [`698–734`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L698-L734) | [`1444–1493`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1444-L1493), [`1496–1504`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1496-L1504), [`1507–1526`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1507-L1526), [`1529–1545`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1529-L1545) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:457–493`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L457-L493) | [`116–152`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L116-L152) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:586–610`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L586-L610), [`detect.py:465–478`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/detect.py#L465-L478) | [`297–324`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L297-L324), [`327–336`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L327-L336) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:671–699`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L671-L699) | [`624–642`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L624-L642), [`1663–1696`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1663-L1696) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/schemas/scan.schema.json#L15-L81), [`scan.py:627–650`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L627-L650) | [`645–656`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L645-L656), [`1663–1696`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1663-L1696), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/main.py#L163-L176) | [`726–784`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L726-L784), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:387–407`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L387-L407), [`586–610`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L586-L610) | [`327–336`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L327-L336), [`1335–1377`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1335-L1377), [`1663–1696`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1663-L1696) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` obligatoire et typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:749–771`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L749-L771), [`812–852`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L812-L852), [`835–843`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L835-L843), [`785–789`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L785-L789) | [`471–590`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L471-L590), [`511–529`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L511-L529), [`1117–1162`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1117-L1162) | `[tool.foo]`, `version` absente ou `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:875–915`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L875-L915) | [`2057–2076`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L2057-L2076) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |
| **--CONFIG EXTERNE (CWE-345, LOW)** : `--config` hors dépôt accepté comme choix opérateur, gardes inchangées | [`allowlist.py:918–965`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L918-L965), [`scan.py:456–460`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L456-L460), [`537–541`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L537-L541) | [`401–434`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L401-L434), [`850–882`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L850-L882) | Opt-in explicite : arbre et staged hors CI acceptés, contenu invalide toujours code 2 ; sans opt-in refus fail-closed inchangé |
| **FILTRE CHEMIN BORNÉ (CWE-400, LOW)** : au plus 10 jokers `*` par motif, chemin soumis à `fnmatch` borné à 1024 | [`allowlist.py:677–695`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L677-L695), [`515–528`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L515-L528), [`99–104`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L99-L104) | [`1581–1660`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1581-L1660), [`1088–1104`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L1088-L1104) | Au-delà de 10 `*` → code 2 ; chemin > 1024 non soumis au filtre, candidat reste signalé (fail-closed) ; fuzz adversarial borné (< 1 ms) |
| **FERMETURE DESCRIPTEUR FAIL-CLOSED (CWE-400, LOW)** : `os.close` en échec converti, jamais d'`OSError` brute | [`allowlist.py:907–913`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L907-L913), [`scan.py:219–241`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L219-L241) | [`905–927`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L905-L927) | `load_allowlist_from_file` → `ScanError` (invariant 11), `_read_worktree_file` → `None` (try imbriqué + `finally` + `except`, sans `return` en `finally`) |
| **GARDE ANTI AUTO-ATTESTATION STATIQUE (CWE-200, LOW)** : `rel_cfg`/`verified.path` jamais reflétés | [`scan.py:368–374`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L368-L374), [`381–385`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L381-L385), [`402–408`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/cli/scan.py#L402-L408) | [`929–957`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L929-L957), [`959–977`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L959-L977) | `str(exc)` sans nom de config, préfixe `auto-attestation` conservé ; en CLI le libellé est masqué par le message générique |
| **CONFIG ILLISIBLE = CODE 2 (REQ-SEC-07, LOW)** : `exists()` en échec → `ScanError`, pas allowlist vide | [`allowlist.py:954–963`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/heimdall/scanner/allowlist.py#L954-L963) | [`979–1000`](https://github.com/Cezar277/heimdall/blob/35713ca64e1defad1c18514ef2364e48dd00d423/tests/test_scanner_allowlist.py#L979-L1000) | Seule l'absence avérée vaut « pas de config » ; docstring `load_allowlist` mise à jour |

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
89 passed

.venv/bin/pytest -o addopts="" -q
1962 passed, 15 skipped

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

[`allowlist.py:410–428`](../heimdall/scanner/allowlist.py#L410-L428) applique
désormais `\b` **dans tous les cas**, y compris pour une règle restreinte par
chemin (`tests/**`). `_` étant un caractère de mot, `fake_slack_token` et
`my_dummy_key` restent signalés ; `fake-token` ou la valeur exacte `dummy`
restent reconnus. Le test de non-régression
[`test_scanner_allowlist.py:251–269`](../tests/test_scanner_allowlist.py#L251-L269)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1699–1715`](../tests/test_scanner_allowlist.py#L1699-L1715)
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

[`scan.py:201–285`](../heimdall/cli/scan.py#L201-L285) conserve la vérification
anti-auto-attestation : lecture du fichier du worktree via `_resolve_root` +
`O_NOFOLLOW`, puis comparaison de l'empreinte de blob brute (SHA-1 ou SHA-256)
avec le SHA de l'index, sans exécuter de filtre Git `clean`.

Tests de non-régression : [`test_scanner_allowlist.py:1860–2005`](../tests/test_scanner_allowlist.py#L1860-L2005)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:875–915`](../heimdall/scanner/allowlist.py#L875-L915)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:2057–2076`](../tests/test_scanner_allowlist.py#L2057-L2076)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:244–285`](../heimdall/cli/scan.py#L244-L285)), le parseur les
  consomme sans relire ([`allowlist.py:855–872`](../heimdall/scanner/allowlist.py#L855-L872)),
  et un second contrôle refuse toute substitution
  ([`scan.py:296–387`](../heimdall/cli/scan.py#L296-L387),
  [`scan.py:390–409`](../heimdall/cli/scan.py#L390-L409)). Test de course :
  [`test_scanner_allowlist.py:1804–1846`](../tests/test_scanner_allowlist.py#L1804-L1846).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:2009–2052`](../tests/test_scanner_allowlist.py#L2009-L2052),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:677–695`](../heimdall/scanner/allowlist.py#L677-L695)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:1088–1104`](../tests/test_scanner_allowlist.py#L1088-L1104)
  et [`1581–1660`](../tests/test_scanner_allowlist.py#L1581-L1660).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:812–852`](../heimdall/scanner/allowlist.py#L812-L852)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:471–499`](../tests/test_scanner_allowlist.py#L471-L499).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:835–843`](../heimdall/scanner/allowlist.py#L835-L843)).
  Test : [`test_scanner_allowlist.py:502–508`](../tests/test_scanner_allowlist.py#L502-L508).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:79`](../heimdall/scanner/allowlist.py#L79),
  [`749–771`](../heimdall/scanner/allowlist.py#L749-L771),
  [`785–789`](../heimdall/scanner/allowlist.py#L785-L789)). Test :
  [`test_scanner_allowlist.py:567–590`](../tests/test_scanner_allowlist.py#L567-L590).
- **Fabriques explicites** : `Allowlist.default()` et `create_default_rules()`
  restent réservées aux tests et à l'API Python ; le chargement CLI/CI ne les
  branche pas. Sans `heimdall.toml`, `load_allowlist()` rend
  `Allowlist.empty()` ([`allowlist.py:618–627`](../heimdall/scanner/allowlist.py#L618-L627),
  [`918–965`](../heimdall/scanner/allowlist.py#L918-L965)). Test :
  [`test_scanner_allowlist.py:829–840`](../tests/test_scanner_allowlist.py#L829-L840).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:2057–2076`](../tests/test_scanner_allowlist.py#L2057-L2076)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:141–307`](../heimdall/scanner/allowlist.py#L141-L307)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1412–1427`](../tests/test_scanner_allowlist.py#L1412-L1427)
  et [`1430–1441`](../tests/test_scanner_allowlist.py#L1430-L1441) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:698–734`](../heimdall/scanner/allowlist.py#L698-L734)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:332–383`](../heimdall/scanner/allowlist.py#L332-L383)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1444–1493`](../tests/test_scanner_allowlist.py#L1444-L1493),
  [`1496–1504`](../tests/test_scanner_allowlist.py#L1496-L1504),
  [`1507–1526`](../tests/test_scanner_allowlist.py#L1507-L1526),
  [`1529–1545`](../tests/test_scanner_allowlist.py#L1529-L1545).
- **Valeur candidate bornée** : [`allowlist.py:495–543`](../heimdall/scanner/allowlist.py#L495-L543)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1507–1526`](../tests/test_scanner_allowlist.py#L1507-L1526).
- **Typage de l'API** : [`allowlist.py:457–493`](../heimdall/scanner/allowlist.py#L457-L493)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:116–152`](../tests/test_scanner_allowlist.py#L116-L152).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:124–132`](../heimdall/scanner/allowlist.py#L124-L132))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1962 passed, 15 skipped** et les 89 tests d'allowlist sont verts.

### Cinquième revue (LOW) — config externe, version obligatoire, littéraux, fnmatch borné

- **`--config` externe accepté hors CI** : [`scan.py:456–460`](../heimdall/cli/scan.py#L456-L460)
  et [`537–541`](../heimdall/cli/scan.py#L537-L541) passent désormais
  `allow_external=ci or config is not None` : un `--config` explicite peut
  vivre hors du dépôt scanné (choix opérateur, conformément à l'aide de la
  CLI), la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
  contrat fermé restant appliqués
  ([`allowlist.py:918–965`](../heimdall/scanner/allowlist.py#L918-L965)).
  Sans opt-in, le refus fail-closed reste la norme. Tests :
  [`401–434`](../tests/test_scanner_allowlist.py#L401-L434) (API : refus sans
  opt-in, acceptation avec opt-in, contenu invalide toujours refusé) et
  [`850–882`](../tests/test_scanner_allowlist.py#L850-L882) (CLI : arbre et
  staged hors CI, externe invalide → code 2).
- **`version` obligatoire** : [`allowlist.py:812–852`](../heimdall/scanner/allowlist.py#L812-L852)
  exige une `version` explicite ([`835–843`](../heimdall/scanner/allowlist.py#L835-L843)) —
  plus de défaut implicite `"1"` : une table `[allowlist]` sans `version`, un
  entier ou toute autre chaîne sont refusés en `ScanError` (code 2). Test :
  [`511–529`](../tests/test_scanner_allowlist.py#L511-L529).
- **Motifs à < 3 littéraux : refus maintenu, reformulation documentée** :
  `\d{3}-\d{4}`, `x{3}y{3}`, `[a-z]+`, `\w+` restent refusés (motifs
  aveugles, fail-closed) ; la reformulation `EXAMPLE-[0-9]{4}` est acceptée
  et n'ignore que la forme visée. Le contrat est documenté dans
  [`heimdall.toml`](../heimdall.toml) et [`docs/cli.md`](cli.md). Tests :
  [`531–564`](../tests/test_scanner_allowlist.py#L531-L564).
- **`fnmatch` borné des deux côtés** : au plus
  `MAX_PATH_WILDCARDS = 10` jokers `*` par motif (au-delà : code 2)
  ([`allowlist.py:677–695`](../heimdall/scanner/allowlist.py#L677-L695),
  constantes [`99–104`](../heimdall/scanner/allowlist.py#L99-L104)), et un
  chemin de plus de `MAX_MATCH_PATH_LENGTH = 1024` caractères n'est pas
  soumis au filtre — le candidat reste signalé (fail-closed)
  ([`allowlist.py:515–528`](../heimdall/scanner/allowlist.py#L515-L528)).
  Sous Python ≥ 3.13, `fnmatch.translate` produit des groupes atomiques
  (immunisé) ; sous les interpréteurs antérieurs, 20 `*` croisés à un chemin
  de 4 096 caractères coûtaient ≈ 1 s, les plafonds ramènent la passe sous
  la milliseconde. Fuzz adversarial borné en temps :
  [`1581–1660`](../tests/test_scanner_allowlist.py#L1581-L1660).
- **Non-régression** : la suite complète passe à
  **1962 passed, 15 skipped** et les 89 tests d'allowlist sont verts ; les
  plafonds `MAX_PATH_WILDCARDS = 10` et `MAX_MATCH_PATH_LENGTH = 1024` et
  l'exigence `version` sont figés par les exports vérifiés
  ([`2079–2100`](../tests/test_scanner_allowlist.py#L2079-L2100)).

### Sixième revue (LOW) — fail-closed strict et messages statiques

- **`os.close` protégé** : [`allowlist.py:907–913`](../heimdall/scanner/allowlist.py#L907-L913)
  convertit toute `OSError` en `ScanError` (contrat unique, invariant 11) ;
  [`scan.py:219–241`](../heimdall/cli/scan.py#L219-L241) rend `None`
  (fail-closed) via try imbriqué + `finally` + `except` externe — sans
  `return` en `finally` (`SyntaxWarning` évité, fermeture garantie sur
  tous les chemins). Test :
  [`905–927`](../tests/test_scanner_allowlist.py#L905-L927) (fermeture
  réelle puis panne simulée : `ScanError` d'un côté, `None` de l'autre,
  jamais d'`OSError` brute).
- **Messages de garde strictement statiques** : `rel_cfg` et `verified.path`
  (entrées opérateur normalisées) ne sont plus reflétés —
  [`scan.py:368–374`](../heimdall/cli/scan.py#L368-L374) (configuration
  stagée), [`381–385`](../heimdall/cli/scan.py#L381-L385) (worktree non
  propre en staged),
  [`402–408`](../heimdall/cli/scan.py#L402-L408) (re-contrôle anti-TOCTOU) ;
  le préfixe `auto-attestation` est conservé pour l'audit. Tests :
  [`929–957`](../tests/test_scanner_allowlist.py#L929-L957) (arbre, staged,
  `--config` interne : `str(exc)` sans nom de config) et
  [`959–977`](../tests/test_scanner_allowlist.py#L959-L977) (substitution
  entre garde et parsing).
- **`exists()` en échec → code 2** :
  [`allowlist.py:954–963`](../heimdall/scanner/allowlist.py#L954-L963)
  lève `ScanError` sur `OSError` (répertoire illisible) au lieu de rendre
  une allowlist vide silencieuse ; seule l'absence avérée vaut « pas de
  config » (le vide reste fail-closed). Test :
  [`979–1000`](../tests/test_scanner_allowlist.py#L979-L1000).
- **Non-régression** : la suite complète passe à
  **1962 passed, 15 skipped** et les 89 tests d'allowlist sont verts.
