# T24 — preuves pour la ligne SAMM

Périmètre : ticket #24 « Allowlist déterministe », sous-ticket de l'épic #3
« Scanner de secrets ». Cette fiche fournit les couples **module + ligne** et les
preuves des exigences vérifiées pour le rapport d'audit SAMM.

Révision du code auditée : [`42a4ee6086cbca3b90c8d63365b9f8798e022bfe`](https://github.com/Cezar277/heimdall/commit/42a4ee6086cbca3b90c8d63365b9f8798e022bfe).
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
| **Règle example** : écarte les jetons et placeholders évidents (`example`, `sample`, `your_key_here`, `AKIAIOSFODNN7EXAMPLE`) | [`allowlist.py:642–646`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L642-L646), [`heimdall.toml:23–26`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall.toml#L23-L26) | [`tests/test_scanner_allowlist.py:167–194`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L167-L194) | Clés AWS/jetons d'exemple écartés avec trace `example-placeholders` |
| **Règle changeme** : écarte les mots de passe et configs changeme | [`allowlist.py:647–651`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L647-L651), [`heimdall.toml:28–31`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall.toml#L28-L31) | [`tests/test_scanner_allowlist.py:197–212`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L197-L212) | Mots de passe par défaut écartés avec trace `changeme-passwords` |
| **Règle dummy** : écarte les jetons et identifiants factices dummy | [`allowlist.py:652–656`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L652-L656), [`heimdall.toml:33–36`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall.toml#L33-L36) | [`tests/test_scanner_allowlist.py:215–230`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L215-L230) | Jetons factices écartés avec trace `dummy-tokens` |
| **Règle test-fixtures** : fixtures factices délimitées aux tests (sans mot-clé générique `test`) | [`allowlist.py:657–673`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L657-L673), [`heimdall.toml:38–53`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall.toml#L38-L53) | [`tests/test_scanner_allowlist.py:233–249`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L233-L249), [`252–270`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L252-L270) | Fixtures factices sous `tests/` écartées avec trace `test-fixtures` ; `_fake_`/`_dummy_` restent signalés |
| **PIÈGE ÉVITÉ (CWE-1188)** : aucun secret réel dans `tests/` n'est ignoré | [`allowlist.py:410–428`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L410-L428), [`495–543`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L495-L543) | [`tests/test_scanner_allowlist.py:276–292`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L276-L292), [`1428–1470`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1428-L1470), [`1792–1808`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1792-L1808) | Une vraie clé AWS sous `tests/` ou nommée `latest_token` reste détectée et bloque |
| **ABSENCE DE CONTOURNEMENT PAR COMMENTAIRE (Invariant 1, CRITICAL)** : évaluation sur `value` uniquement | [`allowlist.py:495–543`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L495-L543) | [`tests/test_scanner_allowlist.py:1274–1307`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1274-L1307) | `key = "AKIA..." # dummy` reste détecté à 100 % en arbre et staged |
| **ANTI AUTO-ATTESTATION (CWE-345, HIGH)** : refus de l'allowlist du dépôt sans --config en CI, refus staged et vérification worktree propre | [`scan.py:331–422`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L331-L422), [`474–483`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L474-L483), [`552–564`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L552-L564), [`644–650`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L644-L650) | [`1334–1425`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1334-L1425), [`1811–1939`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1811-L1939), [`2102–2145`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L2102-L2145), [`2150–2169`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L2150-L2169) | `ScanError` (code 2) si commit/staged modifie `heimdall.toml` ou `--config` custom, si worktree dirty/untracked en `--staged`, ou en `--ci` sans `--config` externe / `--no-allowlist` |
| **GARDE DE CHEMIN UNIQUE (Invariant 3, MEDIUM)** : réutilisation centrale de `_resolve_root` | [`allowlist.py:875–915`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L875-L915), [`interface.py:38–71`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/interface.py#L38-L71) | [`366–399`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L366-L399), [`1181–1197`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1181-L1197) | Pas de garde divergente ; résolution stricte et ouverture par descripteur |
| **ANTI-REDOS STRICT (CWE-1333, MEDIUM)** : analyse structurelle des groupes, alternances quantifiées, quantificateurs adjacents, max 128 chars | [`allowlist.py:141–307`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L141-L307), [`698–734`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L698-L734) | [`1481–1502`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1481-L1502), [`1505–1534`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1505-L1534), [`1200–1207`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1200-L1207), [`1674–1753`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1674-L1753) | Rejet de `(a\|aa)+`, `((a|aa))+$`, `(a|(b|c))+$`, `(?:(a|aa))+$`, `(a+)+`, `a++`, `a*?`, `(a?)+`, backrefs et motifs > 128 chars |
| **ANTI-ALLOWLIST AVEUGLE (CWE-1188, MEDIUM)** : refus des motifs universels et exigence de littéraux | [`allowlist.py:86–104`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L86-L104), [`332–383`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L332-L383), [`698–734`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L698-L734) | [`1537–1586`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1537-L1586), [`1589–1597`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1589-L1597), [`1600–1619`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1600-L1619), [`1622–1638`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1622-L1638) | `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` refusés ; chaque branche d'alternance doit porter ≥ 3 littéraux |
| **TYPAGE API (Invariant 11)** : `patterns` doit contenir des regex compilées, jamais des chaînes | [`allowlist.py:457–493`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L457-L493) | [`117–153`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L117-L153) | `AllowlistRule(patterns=("x",))` → `ScanError`, jamais `AttributeError` |
| **CRITÈRE D'ACCEPTATION : traçabilité univoque** : aucun rejet sans règle nommée | [`allowlist.py:586–610`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L586-L610), [`detect.py:470–483`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/detect.py#L470-L483) | [`298–325`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L298-L325), [`328–337`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L328-L337) | Chaque finding ignoré émet `AllowlistTrace(rule, file, line)` |
| **Transparence du rapport** : affiche TOUJOURS le nombre de findings ignorés | [`scan.py:706–734`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L706-L734) | [`625–643`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L625-L643), [`1756–1789`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1756-L1789) | 0 ignoré affiché si vide, liste détaillée des rejets sinon |
| **Contrat JSON machine** : rétrocompatible v1 avec `ignored_count`, `traces` et `config_hash` | [`scan.schema.json:15–81`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/schemas/scan.schema.json#L15-L81), [`scan.py:662–685`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L662-L685) | [`646–657`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L646-L657), [`1756–1789`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1756-L1789), [`test_cli_scan.py:1690–1722`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_cli_scan.py#L1690-L1722) | Schéma draft 2020-12 validé ; champs rétrocompatibles |
| **Mode CI headless** : résumé sur stderr avec nombre d'ignorés et hash SHA-256 complet de config | [`main.py:163–176`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/main.py#L163-L176) | [`727–785`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L727-L785), [`test_cli_scan.py:1742–1748`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_cli_scan.py#L1742-L1748) | stderr : verdict déterministe + décompte des ignorés + sha256 complet de config |
| **Confidentialité absolue (CWE-200, Invariant 8)** : aucun secret dans les traces ou les logs | [`allowlist.py:387–407`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L387-L407), [`586–610`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L586-L610) | [`328–337`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L328-L337), [`1428–1470`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1428-L1470), [`1756–1789`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1756-L1789) | La valeur brute n'apparaît ni dans la trace, ni dans les logs, ni dans le rapport |
| **CONTRAT TOML STRICT (CWE-20)** : clés racine fermées, `version` obligatoire et typée `"1"`, mots-clés ≥ 3 caractères | [`allowlist.py:749–771`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L749-L771), [`812–852`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L812-L852), [`835–843`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L835-L843), [`785–789`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L785-L789) | [`472–591`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L472-L591), [`512–530`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L512-L530), [`1210–1255`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1210-L1255) | `[tool.foo]`, `version` absente ou `version = 1` et `keywords = ["a"]` refusés en `ScanError` (code 2) |
| **DISPONIBILITÉ CONFIG (CWE-400)** : FIFO refusé sans blocage | [`allowlist.py:875–915`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L875-L915) | [`2150–2169`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L2150-L2169) | `O_NONBLOCK` + `S_ISREG` : FIFO par défaut ou `--config` → code 2 sans attente |
| **--CONFIG EXTERNE (CWE-345, LOW)** : `--config` hors dépôt accepté comme choix opérateur, gardes inchangées | [`allowlist.py:918–965`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L918-L965), [`scan.py:491–495`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L491-L495), [`572–576`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L572-L576) | [`402–435`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L402-L435), [`851–883`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L851-L883) | Opt-in explicite : arbre et staged hors CI acceptés, contenu invalide toujours code 2 ; sans opt-in refus fail-closed inchangé |
| **FILTRE CHEMIN BORNÉ (CWE-400, LOW)** : au plus 10 jokers `*` par motif, chemin soumis à `fnmatch` borné à 1024 | [`allowlist.py:677–695`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L677-L695), [`515–528`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L515-L528), [`99–104`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L99-L104) | [`1674–1753`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1674-L1753), [`1181–1197`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1181-L1197) | Au-delà de 10 `*` → code 2 ; chemin > 1024 non soumis au filtre, candidat reste signalé (fail-closed) ; fuzz adversarial borné (< 1 ms) |
| **FERMETURE DESCRIPTEUR FAIL-CLOSED (CWE-400, LOW)** : `os.close` en échec converti, jamais d'`OSError` brute | [`allowlist.py:907–913`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L907-L913), [`scan.py:225–247`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L225-L247) | [`906–928`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L906-L928) | `load_allowlist_from_file` → `ScanError` (invariant 11), `_read_worktree_file` → `None` (try imbriqué + `finally` + `except`, sans `return` en `finally`) |
| **GARDE ANTI AUTO-ATTESTATION STATIQUE (CWE-200, LOW)** : `rel_cfg`/`verified.path` jamais reflétés | [`scan.py:403–409`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L403-L409), [`416–420`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L416-L420), [`437–443`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L437-L443) | [`930–958`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L930-L958), [`960–978`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L960-L978) | `str(exc)` sans nom de config, préfixe `auto-attestation` conservé ; en CLI le libellé est masqué par le message générique |
| **CONFIG ILLISIBLE = CODE 2 (REQ-SEC-07, LOW)** : `exists()` en échec → `ScanError`, pas allowlist vide | [`allowlist.py:954–963`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/allowlist.py#L954-L963) | [`980–1001`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L980-L1001) | Seule l'absence avérée vaut « pas de config » ; docstring `load_allowlist` mise à jour |
| **FERMETURE DESCRIPTEUR ÉTENDUE (CWE-400, LOW)** : `os.close` protégé dans l'index, le lecteur et la clé | [`gitdiff.py:470–477`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/mcp/gitdiff.py#L470-L477), [`detect.py:365–371`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/detect.py#L365-L371), [`hashing.py:148–154`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/hashing.py#L148-L154), [`191–197`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/scanner/hashing.py#L191-L197) | [`2188–2207`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_mcp_units.py#L2188-L2207), [`700–715`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_detect.py#L700-L715), [`718–735`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_detect.py#L718-L735) | `ToolFailure`/`ScanError` partout, jamais d'`OSError` brute ; `_read_key` et `_create_key` couverts aussi |
| **GARDE `exists()` PROTÉGÉE (REQ-SEC-07, LOW)** : `_default_config_present` → `ScanError`, pas de contournement silencieux | [`scan.py:318–328`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L318-L328), [`381–382`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L381-L382) | [`1004–1030`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1004-L1030) | Même contrat que `load_allowlist` ; figé via API (`collect` arbre + staged) et CLI (code 2, message statique) |
| **REFUS DE GARDE DISTINGUÉS EN LOGS (CWE-345, LOW)** : 5 libellés debug statiques, verdict fail-closed inchangé | [`scan.py:116–119`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L116-L119), [`250–307`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/heimdall/cli/scan.py#L250-L307) | [`1032–1093`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1032-L1093) | `None` légitime (untracked) vs panne (index illisible) vs dirty vs empreinte, en caplog ; aucun secret ni entrée reflétés |
| **CI ANTI AUTO-ATTESTATION DOCUMENTÉE (CWE-345, LOW)** : `--ci` + `heimdall.toml` versionné → 2, avec issue explicite | Paragraphe `--ci`/allowlist de [`docs/cli.md`](cli.md) (pas de permalien ligne : prose) | [`1334–1425`](https://github.com/Cezar277/heimdall/blob/42a4ee6086cbca3b90c8d63365b9f8798e022bfe/tests/test_scanner_allowlist.py#L1334-L1425) | `--config` externe épinglé ou `--no-allowlist` ; comportement déjà figé (`test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`), aide ajoutée sans toucher au libellé code 2 (anti-oracle) |

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
91 passed

.venv/bin/pytest -o addopts="" -q
1967 passed, 15 skipped

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
[`test_scanner_allowlist.py:252–270`](../tests/test_scanner_allowlist.py#L252-L270)
couvre `_fake_`/`_dummy_` sous `tests/`, et
[`test_scanner_allowlist.py:1792–1808`](../tests/test_scanner_allowlist.py#L1792-L1808)
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

Tests de non-régression : [`test_scanner_allowlist.py:1953–2098`](../tests/test_scanner_allowlist.py#L1953-L2098)
couvre index v4, worktree lié, gitlink/sous-module, index symlinké (code 2),
chemins invalides (`..`, NUL, absolu) et sorties `ls-files` malformées
(paramétrage fuzz).

### Deuxième revue (LOW) — disponibilité et TOCTOU

- **FIFO à l'ouverture de la config** : [`allowlist.py:875–915`](../heimdall/scanner/allowlist.py#L875-L915)
  ouvre désormais avec `O_NONBLOCK` (comme le worktree et l'index) ; le
  `fstat` + `S_ISREG` existant refuse un FIFO en code 2 sans blocage.
  Test borné par sous-processus :
  [`test_scanner_allowlist.py:2150–2169`](../tests/test_scanner_allowlist.py#L2150-L2169)
  (config par défaut et `--config`).
- **TOCTOU garde → parsing** : la garde rend les octets vérifiés
  ([`scan.py:250–307`](../heimdall/cli/scan.py#L250-L307)), le parseur les
  consomme sans relire ([`allowlist.py:855–872`](../heimdall/scanner/allowlist.py#L855-L872)),
  et un second contrôle refuse toute substitution
  ([`scan.py:331–422`](../heimdall/cli/scan.py#L331-L422),
  [`scan.py:425–444`](../heimdall/cli/scan.py#L425-L444)). Test de course :
  [`test_scanner_allowlist.py:1897–1939`](../tests/test_scanner_allowlist.py#L1897-L1939).
- **Arbre local indicatif** : hors `--ci`/`--staged`, seule une configuration
  stagée est refusée ; la propreté du fichier du worktree (dirty/untracked)
  n'est pas vérifiée. Ce périmètre est documenté comme non opposable dans
  [`docs/cli.md`](cli.md#limites-connues-honnêtes). Le comportement est figé
  par [`test_scanner_allowlist.py:2102–2145`](../tests/test_scanner_allowlist.py#L2102-L2145),
  qui vérifie aussi que `--ci` et `--staged` refusent la même configuration.
- **Fuzz des `paths`** : [`allowlist.py:677–695`](../heimdall/scanner/allowlist.py#L677-L695)
  réutilise la grammaire du contrat Finding #14 (refus de `..`, absolu,
  `C:/`, antislash, NUL, segment vide) ; les motifs glob longs restent
  non bloquants. Tests : [`test_scanner_allowlist.py:1181–1197`](../tests/test_scanner_allowlist.py#L1181-L1197)
  et [`1674–1753`](../tests/test_scanner_allowlist.py#L1674-L1753).

### Troisième revue (LOW) — contrat TOML strict et permaliens

- **Permaliens** : le tableau et la ligne de révision sont ré-épinglés au SHA
  de livraison ; les plages ci-dessus sont celles de cet arbre.
- **Clés racine fermées** : [`allowlist.py:812–852`](../heimdall/scanner/allowlist.py#L812-L852)
  refuse toute table racine hors `{"allowlist"}` (`[tool.foo]`, faute de
  frappe) en `ScanError` (code 2). Tests :
  [`test_scanner_allowlist.py:472–500`](../tests/test_scanner_allowlist.py#L472-L500).
- **Version typée** : `version = 1` (int) est refusé ; seul le littéral
  `"1"` est accepté ([`allowlist.py:835–843`](../heimdall/scanner/allowlist.py#L835-L843)).
  Test : [`test_scanner_allowlist.py:503–509`](../tests/test_scanner_allowlist.py#L503-L509).
- **Mots-clés trop courts** : `keywords = ["a"]` et `["ab"]` sont refusés,
  minimum `MIN_KEYWORD_LENGTH = 3`
  ([`allowlist.py:79`](../heimdall/scanner/allowlist.py#L79),
  [`749–771`](../heimdall/scanner/allowlist.py#L749-L771),
  [`785–789`](../heimdall/scanner/allowlist.py#L785-L789)). Test :
  [`test_scanner_allowlist.py:568–591`](../tests/test_scanner_allowlist.py#L568-L591).
- **Fabriques explicites** : `Allowlist.default()` et `create_default_rules()`
  restent réservées aux tests et à l'API Python ; le chargement CLI/CI ne les
  branche pas. Sans `heimdall.toml`, `load_allowlist()` rend
  `Allowlist.empty()` ([`allowlist.py:618–627`](../heimdall/scanner/allowlist.py#L618-L627),
  [`918–965`](../heimdall/scanner/allowlist.py#L918-L965)). Test :
  [`test_scanner_allowlist.py:830–841`](../tests/test_scanner_allowlist.py#L830-L841).
- **FIFO** : le correctif `O_NONBLOCK` + `S_ISREG` reste couvert par
  [`test_scanner_allowlist.py:2150–2169`](../tests/test_scanner_allowlist.py#L2150-L2169)
  (config par défaut et `--config`, sous-processus borné).

### Quatrième revue (MEDIUM) — ReDoS imbriqué et motifs universels

- **Analyse structurelle anti-ReDoS** : [`allowlist.py:141–307`](../heimdall/scanner/allowlist.py#L141-L307)
  suit la pile des groupes, ignore échappements et classes, et refuse toute
  imbrication réelle sous quantificateur. `((a|aa))+$`, `(a|(b|c))+$` et
  `(?:(a|aa))+$` sont refusés, contrairement à l'ancien filtre `[^)]*` qui ne
  traversait pas `)`. Les références arrière (`\1`, `(?P=nom)`), les groupes
  conditionnels, les commentaires `(?#...)` et le mode verbose `(?x)` sont
  également refusés ; `MAX_PATTERN_LENGTH = 128` reste appliqué. Tests :
  [`test_scanner_allowlist.py:1505–1520`](../tests/test_scanner_allowlist.py#L1505-L1520)
  et [`1523–1534`](../tests/test_scanner_allowlist.py#L1523-L1534) (fuzz ancré
  borné en temps).
- **Motifs universels** : [`allowlist.py:698–734`](../heimdall/scanner/allowlist.py#L698-L734)
  compile puis refuse tout motif qui matche la chaîne vide, et exige au moins
  `MIN_PATTERN_LITERALS = 3` caractères littéraux par branche d'alternance
  ([`allowlist.py:332–383`](../heimdall/scanner/allowlist.py#L332-L383)).
  `.`, `.*`, `^`, `^.*$`, `\w+`, `[a-z]+`, `[^x]+` sont refusés en
  `ScanError`/code 2. Tests TOML :
  [`1537–1586`](../tests/test_scanner_allowlist.py#L1537-L1586),
  [`1589–1597`](../tests/test_scanner_allowlist.py#L1589-L1597),
  [`1600–1619`](../tests/test_scanner_allowlist.py#L1600-L1619),
  [`1622–1638`](../tests/test_scanner_allowlist.py#L1622-L1638).
- **Valeur candidate bornée** : [`allowlist.py:495–543`](../heimdall/scanner/allowlist.py#L495-L543)
  n'évalue les regex que si `len(value) <= MAX_REGEX_VALUE_LENGTH = 256` ;
  au-delà, l'évaluation est **omise** et le candidat reste signalé
  (fail-closed, sans troncature). Test :
  [`test_scanner_allowlist.py:1600–1619`](../tests/test_scanner_allowlist.py#L1600-L1619).
- **Typage de l'API** : [`allowlist.py:457–493`](../heimdall/scanner/allowlist.py#L457-L493)
  valide `patterns` (regex `str` compilées), `keywords`, `paths` et
  `secret_types`. `AllowlistRule(patterns=("x",))` lève `ScanError`, jamais
  `AttributeError` (invariant 11). Test :
  [`test_scanner_allowlist.py:117–153`](../tests/test_scanner_allowlist.py#L117-L153).
- **Seconde barrière** : les 7 motifs `_REDOS_DANGEROUS_PATTERNS` restent en
  place ([`allowlist.py:124–132`](../heimdall/scanner/allowlist.py#L124-L132))
  et couvrent les répétitions d'atomes (`a*a*`, `\d+\d+`, `[0-9]+[0-9]+`)
  que l'analyse structurelle ne cible pas directement.
- **Non-régression** : les motifs réalistes (`^AKIA.*EXAMPLE$`, `^ghp_...`,
  `^sk-...`) restent acceptés ; la suite complète passe à
  **1967 passed, 15 skipped** et les 91 tests d'allowlist sont verts.

### Cinquième revue (LOW) — config externe, version obligatoire, littéraux, fnmatch borné

- **`--config` externe accepté hors CI** : [`scan.py:491–495`](../heimdall/cli/scan.py#L491-L495)
  et [`572–576`](../heimdall/cli/scan.py#L572-L576) passent désormais
  `allow_external=ci or config is not None` : un `--config` explicite peut
  vivre hors du dépôt scanné (choix opérateur, conformément à l'aide de la
  CLI), la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
  contrat fermé restant appliqués
  ([`allowlist.py:918–965`](../heimdall/scanner/allowlist.py#L918-L965)).
  Sans opt-in, le refus fail-closed reste la norme. Tests :
  [`402–435`](../tests/test_scanner_allowlist.py#L402-L435) (API : refus sans
  opt-in, acceptation avec opt-in, contenu invalide toujours refusé) et
  [`851–883`](../tests/test_scanner_allowlist.py#L851-L883) (CLI : arbre et
  staged hors CI, externe invalide → code 2).
- **`version` obligatoire** : [`allowlist.py:812–852`](../heimdall/scanner/allowlist.py#L812-L852)
  exige une `version` explicite ([`835–843`](../heimdall/scanner/allowlist.py#L835-L843)) —
  plus de défaut implicite `"1"` : une table `[allowlist]` sans `version`, un
  entier ou toute autre chaîne sont refusés en `ScanError` (code 2). Test :
  [`512–530`](../tests/test_scanner_allowlist.py#L512-L530).
- **Motifs à < 3 littéraux : refus maintenu, reformulation documentée** :
  `\d{3}-\d{4}`, `x{3}y{3}`, `[a-z]+`, `\w+` restent refusés (motifs
  aveugles, fail-closed) ; la reformulation `EXAMPLE-[0-9]{4}` est acceptée
  et n'ignore que la forme visée. Le contrat est documenté dans
  [`heimdall.toml`](../heimdall.toml) et [`docs/cli.md`](cli.md). Tests :
  [`532–565`](../tests/test_scanner_allowlist.py#L532-L565).
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
  [`1674–1753`](../tests/test_scanner_allowlist.py#L1674-L1753).
- **Non-régression** : la suite complète passe à
  **1967 passed, 15 skipped** et les 91 tests d'allowlist sont verts ; les
  plafonds `MAX_PATH_WILDCARDS = 10` et `MAX_MATCH_PATH_LENGTH = 1024` et
  l'exigence `version` sont figés par les exports vérifiés
  ([`2172–2193`](../tests/test_scanner_allowlist.py#L2172-L2193)).

### Sixième revue (LOW) — fail-closed strict et messages statiques

- **`os.close` protégé** : [`allowlist.py:907–913`](../heimdall/scanner/allowlist.py#L907-L913)
  convertit toute `OSError` en `ScanError` (contrat unique, invariant 11) ;
  [`scan.py:225–247`](../heimdall/cli/scan.py#L225-L247) rend `None`
  (fail-closed) via try imbriqué + `finally` + `except` externe — sans
  `return` en `finally` (`SyntaxWarning` évité, fermeture garantie sur
  tous les chemins). Test :
  [`906–928`](../tests/test_scanner_allowlist.py#L906-L928) (fermeture
  réelle puis panne simulée : `ScanError` d'un côté, `None` de l'autre,
  jamais d'`OSError` brute).
- **Messages de garde strictement statiques** : `rel_cfg` et `verified.path`
  (entrées opérateur normalisées) ne sont plus reflétés —
  [`scan.py:403–409`](../heimdall/cli/scan.py#L403-L409) (configuration
  stagée), [`416–420`](../heimdall/cli/scan.py#L416-L420) (worktree non
  propre en staged),
  [`437–443`](../heimdall/cli/scan.py#L437-L443) (re-contrôle anti-TOCTOU) ;
  le préfixe `auto-attestation` est conservé pour l'audit. Tests :
  [`930–958`](../tests/test_scanner_allowlist.py#L930-L958) (arbre, staged,
  `--config` interne : `str(exc)` sans nom de config) et
  [`960–978`](../tests/test_scanner_allowlist.py#L960-L978) (substitution
  entre garde et parsing).
- **`exists()` en échec → code 2** :
  [`allowlist.py:954–963`](../heimdall/scanner/allowlist.py#L954-L963)
  lève `ScanError` sur `OSError` (répertoire illisible) au lieu de rendre
  une allowlist vide silencieuse ; seule l'absence avérée vaut « pas de
  config » (le vide reste fail-closed). Test :
  [`980–1001`](../tests/test_scanner_allowlist.py#L980-L1001).
- **Non-régression** : la suite complète passe à
  **1967 passed, 15 skipped** et les 91 tests d'allowlist sont verts.

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
  [`1004–1030`](../tests/test_scanner_allowlist.py#L1004-L1030) (API arbre +
  staged et CLI → code 2, sans `OSError` brute).
- **Refus de garde distingués en logs** : [`scan.py:116–119`](../heimdall/cli/scan.py#L116-L119)
  (logger `heimdall.cli.scan`) et [`250–307`](../heimdall/cli/scan.py#L250-L307)
  journalisent chaque cause en debug avec un libellé statique — lecture
  worktree impossible, index illisible, entrée inattendue, non suivie,
  divergente, empreinte incalculable — sans refléter ni secret ni entrée ;
  le verdict reste `None` fail-closed dans tous les cas. Test :
  [`1032–1093`](../tests/test_scanner_allowlist.py#L1032-L1093) (caplog,
  quatre cas).
- **CI documentée** : `scan --ci` avec `heimdall.toml` versionné sort en 2
  sans `--config` externe ni `--no-allowlist` — c'est le choix anti
  auto-attestation documenté, pas un bypass ; [`docs/cli.md`](cli.md)
  donne désormais l'issue explicite (config externe épinglée hors dépôt,
  exemple fourni). Le comportement était déjà figé par
  `test_self_attestation_committed_heimdall_toml_in_ci_fails_loud`
  ([`1334–1425`](../tests/test_scanner_allowlist.py#L1334-L1425)) ; le
  libellé code 2 reste générique (anti-oracle, pas de hint par cause).
- **Bruit d'audit** : `MAX_RULE_NAME_length` est déjà tout en capitales
  (vérifié mécaniquement, y compris dans l'historique) ; `Allowlist.default()`
  et `create_default_rules()` restent des fabriques test/API, le non-branchement
  CLI étant figé par `test_cli_without_config_does_not_apply_default_factories`
  — aucun renommage ni suppression requis.
- **Non-régression** : la suite complète passe à
  **1967 passed, 15 skipped** et les 91 tests d'allowlist sont verts.
