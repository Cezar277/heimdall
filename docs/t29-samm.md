# T29 — preuves pour la ligne SAMM

Périmètre : ticket #29 « Squelette heimdall scan », sous-ticket de l'épic #6
« CLI, hook et CI headless ». Cette fiche fournit les couples **module +
ligne** et les permaliens du code testé ; elle ne prétend pas modifier une
feuille externe.

Révision du code testé : `0bb1136148066de02986ff0042656893686af66d`
(« fix(t29): correctifs de la 4e revue — flux borné, cap intra-fichier,
streaming, $id, symlink »), qui contient la livraison initiale (`96b5800`,
revue APPROVE WITH COMMENTS), ses premiers durcissements (`ae0b1c7`), les
correctifs de la seconde revue (`593021c`, run 39838145119), ceux de la
troisième revue (`251fd18`, run 39841323251) et la présente passe
(run 39844814050). Les permaliens ci-dessous épinglent ce SHA : un lien vers
la branche changerait de lignes au fil des commits. Les septième à quinzième
passes (courantes, voir plus bas) seront re-pinnées sur le SHA final du
squash/merge.

Base : `aa875a1` (fusion de #165, `main` au moment de la livraison), qui
contient le scanner #22 (`2ba3ebf…`) et l'accès git confiné #27. Le diff
`git diff aa875a1 43d63c9 -- heimdall tests schemas` porte **toute** la
livraison #29 :
la CLI (`heimdall/cli/scan.py`, `heimdall/cli/main.py`), la lecture des blobs
de l'index (`heimdall/mcp/gitdiff.py`), le mode strict et les bornes du
scanner (`heimdall/scanner/exclusions.py`, `heimdall/scanner/detect.py`) et
les tests (`tests/test_cli_scan.py`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Commande branchée** : `heimdall scan` rend un verdict au lieu du stub « commande non branchée » | [heimdall/cli/main.py:72–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L72-L137), [heimdall/cli/scan.py:108–117](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L108-L117) | [tests/test_cli_scan.py:206–243](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L206-L243) | dépôt propre → 0 ; secret → 1 ; racine absente → 2 ; aucune écriture |
| **Codes de sortie documentés** : 0 / 1 / 2, jamais 0 après une erreur (invariant 11, REQ-SEC-07) | [heimdall/cli/scan.py:49–51](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L49-L51), [heimdall/cli/main.py:9–13](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L9-L13), [125–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:206–243](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L206-L243), [tests/security/test_scanner_bypass.py:64–71](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/security/test_scanner_bypass.py#L64-L71) | `ScanError`/`ToolFailure` → 2 ; panic → 2 ; jamais 1 sans secret avéré |
| **Rendu fail-closed** (revue #166, LOW) : un échec de rendu ou du résumé `--ci` sort en 2, jamais en 1 | [heimdall/cli/main.py:106–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L106-L137) | [tests/test_cli_scan.py:246–262](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L246-L262) | rendu planté → code 2 + message statique, pas de traceback en 1 |
| **Écriture d'erreur best-effort** (seconde revue, LOW) : stderr fermé (EPIPE) dans un handler ne fait jamais sortir 1 | [heimdall/cli/main.py:46–59](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:265–292](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L265-L292) | `BrokenPipeError` sur stderr (chemin d'erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 |
| **Re-contrôle anti-TOCTOU de l'index** (seconde revue, LOW) : un `git add` concurrent après le snapshot refuse le scan | [heimdall/cli/scan.py:196–201](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L196-L201) | [tests/test_cli_scan.py:572–597](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L572-L597) | index muté pendant le scan → 2 + message statique, jamais 0/1 sur snapshot périmé |
| **HIGH (revue #165) — mode `--staged` : aucun blob ajouté ou modifié n'est exclu de chemin** | [heimdall/cli/scan.py:159–223](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L159-L223) | [tests/test_cli_scan.py:352–368](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L352-L368) | `vendor/evil.py` et `package-lock.json` → Finding + code 1 (alors que `is_excluded()` les excluait) |
| **HIGH (revue #165) — mode strict de l'arbre de travail** : `vendor/`, `third_party/` et lockfiles sont analysés | [heimdall/scanner/exclusions.py:37–75](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/exclusions.py#L37-L75), [161–197](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/exclusions.py#L161-L197), [heimdall/scanner/detect.py:156–189](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L156-L189), [239–254](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L239-L254), [heimdall/cli/scan.py:138–156](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L138-L156) | [tests/test_cli_scan.py:327–346](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L327-L346) | secret dans `vendor/` et dans un lockfile → code 1 ; `node_modules/` (exclusion technique) → code 0 ; politique #59 inchangée par défaut (suite #22 verte) |
| **Bornes du scan** (revues #166 + 3e + 4e revue, LOW) : refus au-delà de 50 000 fichiers / 256 Mio / 10 000 Findings (arbre) ou 1000 blobs / 32 Mio / 10 000 Findings / 8 Mio d'énumération (`--staged`), 1 Mio par fichier | [heimdall/scanner/detect.py:45–54](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L45-L54), [55–57](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L55-L57), [210–219](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L210-L219), [226–228](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L226-L228), [heimdall/cli/scan.py:62–66](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L62-L66), [67–71](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L67-L71), [177–186](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L177-L186), [202–209](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L202-L209) | [tests/test_cli_scan.py:295–321](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L295-L321), [494–499](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L494-L499), [790–804](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L790-L804), [807–818](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L807-L818), [757–773](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L757-L773), [776–787](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L776-L787) | trop de fichiers/octets/blob trop gros/rafale de candidats/flux trop gros → 2 ; jamais un résultat tronqué présenté comme complet |
| **Plafond Findings par candidat** (4e revue, LOW) : un seul fichier/blob dense ne fait jamais gonfler la liste — vérifié dans `_append` des deux moteurs, conservé entre fichiers | [heimdall/scanner/detect.py:359–386](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L359-L386), [heimdall/scanner/signature_engine.py:64–73](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L64-L73), [157–161](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L157-L161) | [tests/test_cli_scan.py:821–835](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L821-L835), [838–845](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L838-L845), [863–872](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L863-L872) | 300 candidats sur une ligne → refus au 101e hachage (compteur exact) ; moteur capé → refus au 6e ; blob dense en `--staged` → 2 |
| **Énumération bornée en flux + streaming** (4e revue, LOW) : l'index est lu par tronçons de 8 Mio (kill + refus au-delà), chaque blob est scanné puis oublié (≤ 1 Mio en mémoire) | [heimdall/mcp/gitdiff.py:95–101](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L95-L101), [449–497](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L449-L497), [heimdall/cli/scan.py:180–217](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L180-L217) | [tests/test_cli_scan.py:757–773](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L757-L773), [776–787](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L776-L787) | flux coupé avant bufferisation (plafond ridicule → 2) ; 1 100 entrées → 2 par le compteur |
| **Racine symlink refusée dans les deux périmètres** (4e + 5e revue, LOW) : garde **unique** (`Scanner._resolve_root` réutilisée, `_refuse_symlinked_root` supprimée), racine figée résolue, re-contrôlée en fin de scan | [heimdall/mcp/gitdiff.py:247–256](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L247-L256), [294–296](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L294-L296), [heimdall/cli/scan.py:120–135](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L120-L135) | [tests/test_cli_scan.py:527–537](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L527-L537), [600–634](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L600-L634), [673–729](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L673-L729), [732–742](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L732-L742) | racine symlinkée → 2 en arbre comme en `--staged` ; échange mid-scan → 2 ; comparaison divergente → 2 |
| **Dépôt exigé en mode arbre** (5e revue, LOW) : hors dépôt (répertoire, fichier isolé) → erreur 2, jamais un 0 silencieux pour une CI mal configurée | [heimdall/cli/scan.py:151–153](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L151-L153) | [tests/test_cli_scan.py:459–472](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L459-L472) | répertoire quelconque et fichier isolé → 2 ; scan unitaire en bibliothèque inchangé |
| **Le blob indexé est lu en entier**, pas seulement ses lignes modifiées | [heimdall/mcp/gitdiff.py:428–524](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L428-L524) | [tests/test_cli_scan.py:422–436](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L422-L436) | secret laissé tel quel dans un fichier modifié → toujours signalé (code 1) |
| **Polyglotte binaire + texte** (seconde revue) : en-tête PNG + secret en clair (sans NUL) → **scanné**, pas sauté | [heimdall/cli/scan.py:183–187](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L183-L187) | [tests/test_cli_scan.py:555–569](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L555-L569) | faux PNG portant un secret → Finding + code 1, secret absent de la sortie |
| **Lecture de l'index confinée** : argv figé, SHA validé (SHA-1 **et** SHA-256), sortie illisible refusée | [heimdall/mcp/gitdiff.py:87–112](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L87-L112), [544–567](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L544-L567), [570–647](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L570-L647) | [tests/test_cli_scan.py:875–886](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L875-L886), [1018–1079](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L1018-L1079) | `--upload-pack=…` refusé avant l'argv ; index en conflit, SHA invalide, chemin hors contrat → refus ; dépôt SHA-256 (64 hexa) accepté |
| **Gitlink stagé ignoré** (3e revue, LOW) : le SHA d'une entrée 160000 désigne un commit, pas un blob — aucun texte à scanner | [heimdall/mcp/gitdiff.py:599–647](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L599-L647) | [tests/test_cli_scan.py:511–524](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L511-L524), [540–552](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L540-L552), [1039–1072](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L1039-L1072) | sous-module stagé → 0 (pas d'exit 2 systématique) ; secret voisin → 1 ; `T` gitlink → fichier scanné |
| **Chemins représentables** (revue #166, LOW) : contrat Finding #14 (4096), pas la limite MCP (1024) | [heimdall/mcp/gitdiff.py:599–647](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L599-L647) | [tests/test_cli_scan.py:371–410](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L371-L410) | espace/Unicode et chemin > 1024 analysés ; > 4096 refusé (jamais tronqué) |
| **100 % local** : aucun fetch, même dans un clone partiel | [heimdall/mcp/gitdiff.py:134](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L134) | [tests/test_network_isolation.py:492–513](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_network_isolation.py#L492-L513) | `GIT_NO_LAZY_FETCH=1` ; scan réel sous garde réseau : aucune connexion hors boucle locale |
| **Aucun LLM en CI** (REQ-SEC-02) : le module de scan n'importe aucun module réseau | [heimdall/cli/scan.py:31–45](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L31-L45) | [tests/security/test_prompt_injection.py:472–499](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/security/test_prompt_injection.py#L472-L499) | garde AST étendue à `heimdall/cli/scan.py` : ni `socket`, ni `subprocess`, ni `os` hors garde de chemin |
| **Aucun secret en clair** (invariant 8) : la sortie ne porte qu'empreinte et entropie | [heimdall/cli/scan.py:226–268](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L226-L268) | [tests/test_cli_scan.py:217–226](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L217-L226), [892–917](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L892-L917) | la valeur du secret est absente de stdout comme de stderr ; le JSON porte les 7 champs du contrat #14 |
| **Sortie JSON déterministe** (`--json`), combinable avec `--ci --staged` | [heimdall/cli/scan.py:226–245](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L226-L245), [heimdall/cli/main.py:113–124](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L113-L124) | [tests/test_cli_scan.py:892–917](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L892-L917), [994–1015](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L994-L1015) | contrat `heimdall.scan.v1` : `schema`, `scope`, `count`, `findings` (7 champs) ; stdout parseable seul, résumé sur stderr |
| **Contrat machine figé par schéma** (3e + 4e revue, LOW) : `schemas/scan.schema.json` (objet fermé, `schema` en const, `scope` en enum, items Finding v1 par `$ref` ; `$id` alignés, résolvable depuis le filesystem sans registre câblé) | [schemas/scan.schema.json](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/schemas/scan.schema.json) | [tests/test_cli_scan.py:930–933](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L930-L933), [936–955](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L936-L955), [958–974](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L958-L974) | sortie `--json` réelle validée (champs exacts, `count` cohérent, NaN refusé, `$id` épinglés) ; 6 documents invalides refusés |
| **Mode `--ci` headless** : le verdict est le code de sortie, résumé déterministe sur stderr | [heimdall/cli/main.py:117–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L117-L137) | [tests/test_cli_scan.py:977–983](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L977-L983) | sortie humaine ou JSON sur stdout, résumé sur stderr, code 0/1 |
| **Documentation à jour** (DoD) | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/docs/cli.md), [docs/scanner.md](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/docs/scanner.md), [README.md](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/README.md) | — | contrat CLI, codes de sortie, JSON, bornes, blobs binaires et limites documentés |

## Résultats locaux

Environnement : Linux, Python 3.14.8, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_cli_scan.py -q
98 passed

.venv/bin/python -m pytest
1546 passed, 4321 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
Total coverage: 95,89 % (seuil 85 % atteint)
heimdall/cli/scan.py : 99 % ; heimdall/cli/main.py : 98 % ;
heimdall/mcp/gitdiff.py : 96 % ; heimdall/scanner/detect.py : 89 % ;
heimdall/scanner/exclusions.py : 95 % ;
heimdall/scanner/signature_engine.py : 100 %

.venv/bin/ruff check heimdall tests        # All checks passed!
.venv/bin/mypy heimdall                     # Success: no issues found in 39 source files
.venv/bin/bandit -r heimdall -q             # code retour 0, aucun rapport
```

Démonstration manuelle (dépôt de test hors dépôt Heimdall) :

```console
$ heimdall scan --staged /tmp/demo-repo
heimdall scan : périmètre index git (blobs ajoutés ou modifiés, aucune exclusion de chemin)
1 secret(s) détecté(s) :
  vendor/evil.py:1  type=aws  entropie=3.6842  empreinte=6bf349c39402…  source=regex
Codes de sortie : 0 = aucun secret, 1 = secrets détectés, 2 = erreur d'outillage.
$ echo $?
1
```

Sur le dépôt Heimdall lui-même, le scan signale **17 candidats**, tous
synthétiques (clé d'exemple AWS, en-têtes PEM et jetons d'exemple des
corpus de test) : le détecteur fait son travail sur un vrai dépôt, et un job
de CI devra les traiter par allowlist (#24).

## Correctifs de la revue #166

| Remarque (APPROVE WITH COMMENTS) | Correctif | Preuve |
|---|---|---|
| LOW — rendu hors du try fail-closed | rendu et résumé `--ci` déplacés dans le même try que `collect()` ; toute panne → code 2 | [main.py:106–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L106-L137) + [test_cli_scan.py:246–262](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L246-L262) |
| LOW — arbre sans plafond total | `MAX_FILES` (50 000) et `MAX_TOTAL_BYTES` (256 Mio) dans `Scanner` ; `_read_text` rend la taille lue | [detect.py:45–54](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L45-L54), [210–219](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L210-L219) + [test_cli_scan.py:295–321](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L295-L321) |
| LOW — dépôts SHA-256 rejetés | `_OBJECT_PATTERN` accepte 40 **ou** 64 hexa ; SHA nul reconnu dans les deux formats | [gitdiff.py:544–554](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L544-L554) + [test_cli_scan.py:397–410](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L397-L410) |
| LOW — binaires sautés en silence, doc dit « aucune » exclusion | doc : « aucune exclusion **de chemin** » + binaires explicitement listés comme limite dans les deux périmètres | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/docs/cli.md) |
| LOW — doubles limites de chemin (1024 vs 4096) | `_staged_change` valide avec `validate_relative_path` (contrat Finding, 4096) | [gitdiff.py:599–647](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L599-L647) + [test_cli_scan.py:371–410](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L371-L410) |
| Tests manquants — combinaison `--ci --json --staged` | test dédié : stdout JSON parseable, résumé sur stderr, code 1 | [test_cli_scan.py:994–1012](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L994-L1012) |
| Tests manquants — chemins espace/Unicode et > 1024 | deux tests e2e + cas parseur > 4096 refusé | [test_cli_scan.py:371–394](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L371-L394), [1073–1079](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L1073-L1079) |
| Tests manquants — dépôt SHA-256 | `GitRepo(object_format="sha256")` + e2e `--staged` (skip si git ne le supporte pas) | [test_cli_scan.py:397–410](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L397-L410) |

## Correctifs de la seconde revue (run 39838145119, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `echo` d'erreur non protégé contre EPIPE | écriture de secours best-effort (`_echo_stderr_best_effort`) dans les deux handlers : stderr fermé → 2 garanti, jamais 1 ni traceback | [main.py:46–59](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/main.py#L125-L137) + [test_cli_scan.py:265–292](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L265-L292) |
| LOW — TOCTOU index entre snapshot et verdict `--staged` | lectures adressées par SHA (incorruptibles) + **relecture de l'index après l'analyse** : toute divergence refuse le scan (code 2), pas de verdict sur snapshot périmé (solution `write-tree` écartée : elle écrirait dans `.git`, contraire au scan lecture seule) | [scan.py:196–201](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L196-L201) + [test_cli_scan.py:572–597](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L572-L597) |
| LOW — docstrings obsolètes 40 vs 40/64 | `STAGED_RAW_ARGUMENTS` et `StagedChange` disent « 40 (SHA-1) ou 64 (SHA-256) » | [gitdiff.py:87–112](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L87-L112), [221–231](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L221-L231) |
| Tests manquants — stderr fermé / `BrokenPipeError` | `echo` stderr qui lève sur les trois chemins (erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 | [test_cli_scan.py:265–292](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L265-L292) |
| Tests manquants — mutation concurrente de l'index | snapshot simulé divergent au second appel → 2, jamais 0/1 | [test_cli_scan.py:572–597](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L572-L597) |
| Tests manquants — polyglotte binaire + texte | faux PNG (magie + secret en clair, sans NUL) → Finding + code 1, fige `decode_text` → scanné | [test_cli_scan.py:555–569](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L555-L569) |

## Correctifs de la troisième revue (run 39841323251, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — gitlink stagé (sous-module) fait échouer tout scan `--staged` en 2 | `_staged_change` ignore les entrées dont le mode indexé est `160000` (le SHA désigne un commit, pas un blob — aucun texte à scanner), comme les suppressions ; seul le mode indexé compte (`T` gitlink → fichier scanné) | [gitdiff.py:599–647](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L599-L647) + [test_cli_scan.py:511–524](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L511-L524), [540–552](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L540-L552), [1039–1072](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L1039-L1072) |
| LOW — contrat machine `heimdall.scan.v1` sans schéma | `schemas/scan.schema.json` (draft 2020-12, objet fermé, `schema` en const, `scope` en enum, items Finding v1 par `$ref` sans duplication) | [schemas/scan.schema.json](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/schemas/scan.schema.json) + [test_cli_scan.py:930–974](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L930-L974) |
| LOW — nombre de Findings non borné, seul le volume d'entrée l'est | `MAX_FINDINGS` (arbre, fail-fast dans la boucle) et `MAX_STAGED_FINDINGS` (`--staged`, cible par cible, même ordre de tri) à 10 000 ; au-delà, refus 2 | [detect.py:55–57](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L55-L57), [226–228](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L226-L228) + [scan.py:67–71](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L67-L71), [202–209](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L202-L209) |
| Tests manquants — stagé d'un submodule | e2e `update-index --cacheinfo 160000` : skip → 0, secret voisin → 1 ; parseur : skip 160000, `T` vers fichier scanné | [test_cli_scan.py:511–552](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L511-L552), [1039–1072](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L1039-L1072) |
| Tests manquants — validation JSON contre le schéma | schéma valide, sortie `--json` réelle validée (`count` cohérent, NaN refusé), 6 documents invalides refusés | [test_cli_scan.py:930–974](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L930-L974) |
| Tests manquants — rafale de Findings | plafonds monkeypatchés → refus 2 en arbre comme en `--staged` | [test_cli_scan.py:790–872](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L790-L872) |

## Correctifs de la quatrième revue (run 39844814050, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — sortie `diff --cached --raw -z` bufferisée sans borne | `_read_capped()` : lecture en flux borné (`MAX_STAGED_RAW_BYTES`, 8 Mio — pire cas légitime ~4 Mio), même motif argv/environnement/délai que `staged_diff()`, kill + refus au-delà, sans coupe partielle rendue | [gitdiff.py:95–101](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L95-L101), [449–497](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L449-L497) + [test_cli_scan.py:757–787](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L757-L787) |
| LOW — plafond Findings contournable par un seul fichier dense | compteur vérifié **par candidat dans `_append`** des deux moteurs (`SignatureEngine` gagne un paramètre optionnel `max_findings`, rétrocompatible), **conservé entre fichiers** : les deux granularités sont nécessaires — la suppression du contrôle de boucle faisait retomber à exit 1, attrapé par les tests | [detect.py:359–386](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/detect.py#L359-L386), [signature_engine.py:64–73](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L64-L73), [157–161](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L157-L161) + [test_cli_scan.py:821–872](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L821-L872) |
| LOW — `--staged` retient tous les textes avant analyse | boucle restructurée : chaque blob est lu, décodé, scanné puis oublié avant le suivant (≤ 1 Mio en mémoire) ; même ordre de tri | [scan.py:180–217](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L180-L217) |
| LOW — `$id` incohérents, `$ref` non résolvable sans registre | `$id` du scan aligné sur la base du contrat Finding ; test de résolution depuis le filesystem via récupération locale (jamais de réseau, `$id` épinglés) | [schemas/scan.schema.json](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/schemas/scan.schema.json) + [test_cli_scan.py:936–955](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L936-L955) |
| LOW — racine symlink acceptée en `--staged`, refusée en arbre | `_refuse_symlinked_root()` dans `GitAccess.__init__` (lstat, comme `_resolve_root`) : parité des deux périmètres, sans changement pour les racines absentes ni le MCP (racine déjà résolue au démarrage) | [gitdiff.py:217–220](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L217-L220) + [test_cli_scan.py:527–537](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L527-L537) |
| Tests manquants — index volumineux | flux coupé (plafond ridicule → 2 sans parser) ; 1 100 entrées → 2 par le compteur | [test_cli_scan.py:757–787](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L757-L787) |
| Tests manquants — blob dense intra-fichier | compteur exact au hachage près (300 candidats → refus au 101e ; moteur capé → refus au 6e) | [test_cli_scan.py:821–872](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L821-L872) |
| Tests manquants — schéma sans registre + racine symlink | résolution filesystem par les `$id` déclarés ; parité `scan` / `scan --staged` sur racine symlinkée | [test_cli_scan.py:936–955](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L936-L955), [527–537](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L527-L537) |

## Correctifs de la cinquième revue (run 39844814050, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — seconde garde racine sans contrôle resolve-égalité | `GitAccess.__init__` réutilise **la garde unique** (`Scanner._resolve_root`) ; `_refuse_symlinked_root` **supprimée** (pas de divergence possible). Racine figée résolue + re-contrôle en fin de scan des deux périmètres | [gitdiff.py:247–256](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L247-L256), [294–296](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L294-L296), [scan.py:120–135](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L120-L135) + [test_cli_scan.py:527–537](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L527-L537), [600–634](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L600-L634), [673–729](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L673-L729), [732–742](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L732-L742) |
| LOW — mode arbre sans exigence « dépôt git » | `_collect_tree()` exige `is_repository()` comme `--staged` : hors dépôt → 2, jamais un 0 silencieux | [scan.py:151–153](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L151-L153) + [test_cli_scan.py:459–472](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L459-L472) |
| Tests manquants — racine remplacée mid-scan | échanges déterministes (index identique pour isoler le re-contrôle racine ; wrapper post-analyse côté arbre) → 2 ; comparaison divergente → 2 | [test_cli_scan.py:600–634](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L600-L634), [673–729](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L673-L729), [732–742](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L732-L742) |
| Tests manquants — arbre hors dépôt | répertoire quelconque et fichier isolé → 2 figé ; garde réseau adaptée (allowlist git locale `Popen` + `posix_spawn`, témoins, dépôt initialisé hors garde) | [test_cli_scan.py:459–472](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L459-L472) |

## Correctifs de la sixième revue (APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — racine épinglée par chemin résolu seul, pas par identité | `GitAccess` fige (`st_dev`, `st_ino`) via `os.stat` après `_resolve_root` (avec refus `is_symlink` entre les deux) et l'expose ; `_verify_root_unchanged` compare chemin résolu ET identité en fin des deux collectes : un dossier remplacé par un autre au même chemin refuse le verdict | [gitdiff.py:269](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L269-L269), [299–301](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/mcp/gitdiff.py#L299-L301), [scan.py:134–135](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/cli/scan.py#L134-L135) + [test_cli_scan.py:637–670](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L637-L670), [703–729](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L703-L729) |
| LOW — SignatureEngine non borné par défaut | la constante `MAX_FINDINGS` vit dans le moteur (couche core, pas d'inversion), `detect.py` la réexporte (compatibilité) ; défaut `max_findings=MAX_FINDINGS` (la septième revue ferme l'échappatoire `None`) : tout futur appelant direct est fail-closed | [signature_engine.py:43](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L43-L43), [70](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/heimdall/scanner/signature_engine.py#L70-L70) + [test_cli_scan.py:848–860](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L848-L860) |
| Tests manquants — remplacement à chemin identique | sosie à index identique (isole le re-contrôle d'identité) puis dossier vide, dans les deux périmètres → 2 | [test_cli_scan.py:637–670](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L637-L670), [703–729](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L703-L729) |
| Tests manquants — moteur sans argument sur blob dense | blob de 11 000 candidats → refus ; `None` explicite retombe désormais sur le défaut borné (septième revue, ci-dessous) | [test_cli_scan.py:848–860](https://github.com/Cezar277/heimdall/blob/0bb1136148066de02986ff0042656893686af66d/tests/test_cli_scan.py#L848-L860) |

## Correctifs de la septième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge
(comme pour les passes précédentes).

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — taille du blob non re-vérifiée après lecture en `--staged` | après `blob_bytes`, `len(data)` doit être **exactement** la taille annoncée par `cat-file -s` (sinon refus avant décodage) et rester sous 1 Mio ; la taille négative est refusée avant d'incrémenter `total` | `heimdall/cli/scan.py` (`_collect_staged`), `tests/test_cli_scan.py::test_scan_staged_refuses_blob_size_mismatch`, `::test_scan_staged_refuses_negative_blob_size` |
| LOW — `blob_size` sans plancher | `GitAccess.blob_size` refuse une taille négative (`ToolFailure`) ; zéro reste valide (blob vide, aucun candidat) | `heimdall/mcp/gitdiff.py` (`blob_size`), `tests/test_cli_scan.py::test_blob_size_refuses_negative_git_output`, `::test_blob_size_accepts_empty_blob` |
| LOW — deux libellés stderr pour le code 2 | un seul message statique (`_SCAN_ERROR_MESSAGE`) pour `ScanError`/`ToolFailure` et pour toute panne inattendue : l'observateur ne distingue plus une panne anticipée d'une panne inattendue | `heimdall/cli/main.py`, `tests/test_cli_scan.py::test_scan_tool_failure_uses_the_same_static_message`, `::test_scan_render_failure_exits_two_not_one` |
| LOW — `max_findings=None` désactivait la borne | `None` retombe sur `MAX_FINDINGS` ; il n'existe **aucun** opt-out non borné, comme pour `Scanner` | `heimdall/scanner/signature_engine.py`, `tests/test_cli_scan.py::test_signature_engine_bounded_by_default` |

## Correctifs de la huitième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — confinement binaire comparé à l'entrée brute | `GitAccess` compare le binaire résolu à `self._root` (forme figée), plus à `root.resolve()` : une seule référence canonique, pas de seconde fenêtre TOCTOU | `heimdall/mcp/gitdiff.py` (`GitAccess.__init__`), `tests/test_mcp_units.py::GitAccessDirectTests::test_git_binary_under_the_pinned_root_is_refused_with_dotdot_input` |
| LOW — `_collect_tree` re-résout la racine | `TreeScanner(access.root, strict=True)` : le scanner reçoit la forme déjà figée par `GitAccess`, une seule résolution et une seule identité épinglée | `heimdall/cli/scan.py` (`_collect_tree`), `tests/test_cli_scan.py::test_collect_tree_uses_the_pinned_root` |
| LOW — bornes `Scanner` désactivables par entier géant | `None` retombe sur le plafond courant ; une borne explicite doit être un entier dans `1..plafond` (`ValueError` sinon). Même validation pour `SignatureEngine(max_findings=...)` | `heimdall/scanner/detect.py` (`_checked_bound`), `heimdall/scanner/signature_engine.py` ; `tests/test_cli_scan.py::test_scanner_refuses_invalid_explicit_bounds`, `::test_signature_engine_refuses_invalid_explicit_cap` |

## Correctifs de la neuvième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — garde de chemin dupliquée (`detect` vs contrat #14) | `detect._validate_relative_path` n'a plus de grammaire locale : elle appelle `finding.validate_relative_path` et traduit `ValueError` en `ScanError`. Une seule garde, donc aucune divergence possible | `heimdall/scanner/detect.py`, `tests/test_scanner_detect.py::test_detect_path_guard_is_the_finding_contract` |
| LOW — suffixe binaire prioritaire sur le contenu en strict | en strict, `is_excluded` ne tranche plus sur le suffixe seul : le contenu est lu d'abord ; le suffixe ne sert de repli qu'après échec de `decode_text` (binaire réel). Un texte `evil.png` est scanné comme en `--staged` | `heimdall/scanner/exclusions.py` (`has_technical_suffix`, `is_excluded`), `heimdall/scanner/detect.py` (`_decode_data`, `_read_text`) ; `tests/test_cli_scan.py::test_scan_tree_strict_scans_text_with_binary_suffix`, `::test_scan_tree_strict_still_skips_real_binary_suffix`, `tests/test_scanner_detect.py::test_exclusions_cover_gitignore_lockfiles_vendor_and_binaries` |
| LOW — `count == len(findings)` non opposable aux parseurs | la `description` de `count` impose au parseur CI de refuser un document incohérent ; `docs/cli.md` explicite les deux étages (schéma puis égalité). Test avec le helper de validation recommandé | `schemas/scan.schema.json`, `docs/cli.md`, `tests/test_cli_scan.py::test_scan_count_mismatch_is_refused_by_the_recommended_validator` |

## Correctifs de la dixième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `build/`, `dist/`, `target/` textuels exclus en strict | `build`, `dist`, `target`, `bower_components` et `htmlcov` rejoignent les répertoires **textuels** : exclus par la politique #59 seule, scannés en strict comme `--staged`. Les exclusions techniques restent limitées aux métadonnées, caches, environnements et `node_modules` | `heimdall/scanner/exclusions.py` (`TECHNICAL_DIRECTORIES`, `TEXT_DIRECTORIES`), `tests/test_cli_scan.py::test_scan_tree_strict_scans_build_outputs`, `tests/test_scanner_detect.py::test_exclusions_cover_gitignore_lockfiles_vendor_and_binaries` |
| LOW — binaire inconnu à suffixe technique sauté en strict | le repli `_decode_data` n'est armé que pour un binaire **connu** (`is_known_binary` : magie connue + ratio ≥ 0,5). NUL + magie inconnue + texte reste `ScanError` en arbre strict comme en `--staged` (code 2) | `heimdall/scanner/exclusions.py` (`is_known_binary`), `heimdall/scanner/detect.py` (`_decode_data`) ; `tests/test_cli_scan.py::test_scan_tree_strict_refuses_unknown_binary_suffix` |
| LOW — durée totale non bornée en `--staged` | deadline globale `MAX_STAGED_SECONDS` (120 s) : refus code 2 avant de lancer de nouvelles lectures au-delà ; chaque appel git garde son timeout unitaire de 30 s | `heimdall/cli/scan.py` (`_collect_staged`), `docs/cli.md` ; `tests/test_cli_scan.py::test_scan_staged_refuses_global_deadline` |

## Correctifs de la onzième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `blob_bytes` bufferisé sans borne avant contrôle | `blob_bytes` passe par `_read_capped(..., MAX_FILE_BYTES)` : lecture streamée, processus tué au-delà de 1 Mio, `ToolFailure` → code 2. Le contrôle `len(data) == size` reste en place | `heimdall/mcp/gitdiff.py` (`blob_bytes`, `_read_capped`), `tests/test_cli_scan.py::test_scan_staged_caps_blob_bytes_before_buffering`, `tests/test_mcp_units.py::GitAccessDirectTests::test_blob_access_uses_end_of_options_and_a_capped_read` |
| LOW — `cat-file` sans marqueur de fin d'options | construction centralisée `_cat_file_arguments` : `cat-file <mode> -- <sha validé>`, donc aucune valeur ne peut être relue comme option même si la garde SHA évolue | `heimdall/mcp/gitdiff.py` (`_cat_file_arguments`, `blob_size`, `blob_bytes`), `tests/test_mcp_units.py::GitAccessDirectTests::test_blob_access_uses_end_of_options_and_a_capped_read` |
| LOW — « lecture seule » contredit par la clé HMAC | docstring et `docs/cli.md` précisent : lecture seule **sur le dépôt**, seule écriture autorisée = clé locale hors dépôt (`$XDG_DATA_HOME/heimdall/snippet-hmac.key`, 0600). HOME/FS en lecture seule → code 2, jamais 0 | `heimdall/cli/scan.py` (docstring), `docs/cli.md` ; `tests/test_cli_scan.py::test_scan_ci_creates_the_local_key_outside_the_repository`, `::test_scan_ci_fails_closed_when_the_local_key_cannot_be_created` |

## Correctifs de la douzième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — deadline non opposable à la seconde énumération ni au timeout unitaire | `_call_timeout(deadline)` vérifie la deadline **avant** chaque appel et propage le restant comme timeout (`min(restant, 30 s)`) à `is_repository`, `staged_changes`, `blob_size` et `blob_bytes`, y compris la relecture finale de l'index ; un appel lent ne dépasse plus la deadline de plus que son timeout unitaire | `heimdall/cli/scan.py` (`_call_timeout`, `_collect_staged`), `heimdall/mcp/gitdiff.py` (`execute`, `staged_changes`, `_read_capped`, `blob_size`, `blob_bytes`) ; `tests/test_cli_scan.py::test_scan_staged_checks_deadline_before_the_final_enumeration`, `tests/test_mcp_units.py::GitAccessDirectTests::test_execute_and_read_capped_propagate_the_remaining_timeout` |
| LOW — `blob_size` bufferisé sans borne | `blob_size` passe par `_read_capped(..., MAX_BLOB_SIZE_OUTPUT_BYTES=64)` : une sortie git anormale est tuée/refusée avant bufferisation, puis `int()` et plancher négatif restent appliqués | `heimdall/mcp/gitdiff.py` (`blob_size`, `_read_capped`), `tests/test_mcp_units.py::GitAccessDirectTests::test_blob_access_uses_end_of_options_and_a_capped_read`, `::test_blob_size_refuses_an_oversized_stdout` |
| LOW — compatibilité `cat-file --` non figée | test e2e réel `blob_size`+`blob_bytes` sur un blob indexé (git de CI), en plus du test d'argv ; `docs/cli.md` documente le séparateur et son test | `tests/test_mcp_units.py::GitAccessDirectTests::test_blob_access_round_trips_with_end_of_options`, `docs/cli.md` |

## Correctifs de la treizième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — arbre sans deadline globale | `MAX_TREE_SECONDS` (120 s) et `Scanner.scan(deadline=...)` : contrôle avant le premier fichier, entre chaque fichier et avant le rendu ; `_collect_tree` passe la deadline, borne `is_repository` par le restant et re-contrôle avant la vérification de racine | `heimdall/cli/scan.py` (`MAX_TREE_SECONDS`, `_collect_tree`), `heimdall/scanner/detect.py` (`Scanner.scan`), `docs/cli.md` ; `tests/test_cli_scan.py::test_scan_tree_refuses_global_deadline`, `tests/test_scanner_detect.py::test_scanner_refuses_an_expired_deadline` |
| LOW — garde réseau de test allowlist trop lâche | `_git_argv_ok` compare désormais l'**argv complet** : `rev-parse --show-toplevel`, `DIFF_ARGUMENTS`, `STAGED_RAW_ARGUMENTS`, `check-ignore -q -- <chemin>`, `cat-file (-s|blob) -- <sha 40/64>`. Toute option supplémentaire ou sous-commande non listée est refusée | `tests/test_network_isolation.py` (`_git_argv_ok`), `tests/test_network_isolation.py::test_git_allowlist_accepts_only_exact_product_argv` |
| LOW — README « lecture seule » sans l'exception clé HMAC | README aligné sur `docs/cli.md` : lecture seule **sur le dépôt**, seule écriture autorisée = clé locale hors dépôt (`0600`), HOME/FS en lecture seule → code 2, jamais 0 | `README.md`, `docs/cli.md` ; tests `tests/test_cli_scan.py::test_scan_ci_creates_the_local_key_outside_the_repository`, `::test_scan_ci_fails_closed_when_the_local_key_cannot_be_created` |

## Correctifs de la quatorzième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — deadline aveugle intra-fichier | `Scanner._scan_text` reçoit la deadline et la vérifie tous les 256 tours de lignes ; `_append` la vérifie aussi tous les 256 Findings, avant le hachage HMAC. Un seul fichier de 1 Mio dense ne peut donc plus ignorer l'échéance | `heimdall/scanner/detect.py` (`_scan_text`, `_append`), `tests/test_scanner_detect.py::test_scan_text_checks_deadline_intra_file` |
| LOW — relecture d'index sensible à l'ordre | la seconde énumération est comparée par **ensemble** (`set` de `StagedChange`) : une permutation à contenu identique ne provoque plus un faux 2 ; une divergence réelle reste refusée | `heimdall/cli/scan.py` (`_collect_staged`), `tests/test_cli_scan.py::test_scan_staged_accepts_a_reordered_second_enumeration` |
| LOW — double résolution de racine persistante | documenté : `TreeScanner` rejoue la garde unique sur la forme canonique `access.root` (idempotente) ; toute substitution entre les deux est rattrapée par `_verify_root_unchanged` (`st_dev`/`st_ino`). Pas de mode « racine déjà résolue » qui contournerait la garde | `heimdall/cli/scan.py` (commentaire `_collect_tree`), `docs/cli.md` ; `tests/test_cli_scan.py::test_tree_scanner_resolves_the_same_root_from_raw_or_pinned` |

## Correctifs de la quinzième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `scope` non typé, index direct dans `_SCOPE_LABELS` | `Scope = Literal["working-tree", "staged"]`, `ScanReport.scope: Scope`, `_SCOPE_LABELS: dict[Scope, str]` ; garde runtime `__post_init__` pour les appelants non typés (jamais de `KeyError` hors contrat) | `heimdall/cli/scan.py` (`Scope`, `ScanReport`), `tests/test_cli_scan.py::test_scan_report_refuses_an_unknown_scope` |
| LOW — chemins non-UTF8 refusés en `--staged`, acceptés en arbre | `validate_relative_path` rejette explicitement la plage des surrogates (`0xD800..0xDFFF`) : `os.walk` et le parseur d'index convergent vers le même refus 2, documenté dans `docs/cli.md` | `heimdall/scanner/finding.py` (`validate_relative_path`), `docs/cli.md` ; `tests/test_cli_scan.py::test_scan_refuses_non_utf8_paths_in_both_scopes` |

## Correctifs de la seizième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — réutilisation d'inode contourne le re-contrôle d'identité racine | `root_id` = (`st_dev`, `st_ino`, `st_ctime_ns`) : le ctime n'est pas forgeable par `utime` et distingue le dossier neuf d'un inode recyclé. Revers POSIX documenté (cf. Limites assumées) | `heimdall/mcp/gitdiff.py` (`GitAccess.__init__`, `root_id`), `heimdall/cli/scan.py` (`_verify_root_unchanged`) ; `tests/test_cli_scan.py::test_scan_tree_recycled_inode_exits_two` |
| LOW — `_read_capped` peut dépasser la deadline (jusqu'à 2 ×) | lecture et attente partagent le même instant de référence : `wait` ne reçoit que `deadline - now`, le minuteur étant annulé avant `wait` | `heimdall/mcp/gitdiff.py` (`_read_capped`) ; `tests/test_mcp_units.py::GitAccessDirectTests::test_read_capped_never_outlives_its_deadline` (horloge simulée), `::test_execute_and_read_capped_propagate_the_remaining_timeout` |
| LOW — `HOME` = racine : le dépôt scanné fournit son `~/.config/git/` | **vérifié par exécution** : avec `HOME` = racine, `check-ignore` ignorait `secret.txt` via `<racine>/.config/git/ignore` (rc=0) ; avec `HOME` = `os.devnull`, rc=1 et `rev-parse` fonctionne. Le dépôt ne peut plus se masquer | `heimdall/mcp/gitdiff.py` (`confined_environment`) ; `tests/test_mcp_units.py::GitAccessDirectTests::test_repository_cannot_supply_its_own_user_excludes`, `::ConfinedEnvironmentTests::test_minimal_and_redirection_free` ; `tests/test_cli_scan.py::test_scan_never_reads_or_writes_a_hostile_repository_config` |

## Correctifs de la dix-septième revue (APPROVE WITH COMMENTS)

Les liens de cette passe seront re-pinnés sur le SHA final du squash/merge.

Trois remarques LOW, chacune reproduite avant correction. Mutants réinjectés
(plafond recalculé à l'appel, `is_repository` sans garde, racine résolue à
l'appel, affichage brut) : chacun est attrapé par le test indiqué.

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — plafond de découverte recalculé à chaque appel | reproduit : après un échange de la racine par un lien, `GIT_CEILING_DIRECTORIES` passait de `…/rep` à `…/evil`. `GitAccess.__init__` calcule `_ceiling` (parent de la racine figée) une fois ; `confined_environment(ceiling)` ne fait plus de `resolve()` à l'appel | `heimdall/mcp/gitdiff.py` (`GitAccess.__init__`, `confined_environment`) ; `tests/test_mcp_units.py::ConfinedEnvironmentTests::test_discovery_ceiling_is_frozen_at_construction` |
| LOW — `is_repository()` peut lever hors contrat | reproduit : `Path.resolve()` lève `RuntimeError` sur une boucle de liens en Python 3.10, plancher supporté (non levé en 3.14, d'où le test par injection). Le `resolve()` du `top` est enveloppé : `OSError`/`RuntimeError`/`ValueError` → `ToolFailure("INTERNAL")`. La comparaison se fait à la racine figée : un dépôt substitué n'est plus accepté | `heimdall/mcp/gitdiff.py` (`is_repository`) ; `tests/test_mcp_units.py::GitAccessDirectTests::test_unresolvable_toplevel_is_a_tool_failure_not_a_raw_error` (échoue sans le correctif), `::test_swapped_root_is_not_a_repository_any_more` ; `tests/test_cli_scan.py::test_scan_unresolvable_toplevel_exits_two` (le test CLI seul ne discrimine pas : le `except Exception` de `main.py` masquait l'exception en code 2) |
| LOW — spoofing bidirectionnel du chemin affiché | reproduit en arbre et en `--staged` : `vendor/\u202egp.yvne:1` s'affichait brut. Le schéma Finding v1 autorise ces noms : on ne refuse pas le chemin (un tel nom bloquerait tout scan, donc un DoS), on l'échappe **à l'affichage**. `_visible()` échappe les catégories Cc/Cf/Zl/Zp dans `render_text` ; le JSON ne change pas | `heimdall/cli/scan.py` (`_visible`, `render_text`) ; `tests/test_cli_scan.py::test_scan_shows_bidi_paths_escaped_never_raw` (RLO, RLM, LRI × arbre, index) |

## Limites assumées

- `git -C <racine>` résout encore le chemin à chaque appel : pendant une
  substitution, `rev-parse` répond le dépôt substitué. Le plafond reste figé et
  la comparaison se fait à la racine figée, donc ce dépôt n'est pas accepté comme
  périmètre ; c'est le re-contrôle d'identité final qui refuse le verdict (code 2).
  Fermer complètement cette fenêtre demanderait d'ouvrir la racine par descripteur,
  hors périmètre de cette passe.
- Sous POSIX, ajouter ou supprimer une entrée **directe** de la racine pendant
  un scan refuse le verdict (code 2) : l'identité racine épingle le `ctime`,
  seul champ qu'un `utime` ne peut pas forger, pour détecter un dossier neuf
  qui réobtient le même inode. Fail-closed, jamais un faux 0.
- La validation humaine Y/N/E et le remplacement du secret ne sont pas dans ce
  ticket : `scan` signale, il ne répare pas (#32).
- Les exclusions **techniques** restent (binaires, `node_modules/`, `.venv/`,
  `__pycache__/`, caches) : un secret qui y est copié n'est pas signalé. Les
  sorties de build textuelles (`build/`, `dist/`, `target/`) sont scannées en
  strict. Un blob binaire reconnu est sauté dans les **deux** périmètres
  (limite documentée).
- `--staged` analyse l'index, pas l'historique : un secret déjà commité n'est
  pas re-détecté par ce mode.
- La trace `strace` d'un scan opérationnel reste à archiver côté CI
  (`docs/security/zero-egress.md`) : la preuve jointe ici est le test
  d'isolation réseau au niveau Python. C'est un reste à faire de #37, pas de
  #29.

## Relecture et PR

- PR : [#166](https://github.com/Cezar277/heimdall/pull/166) sur la branche
  `29-t29-squelette-heimdall-scan`, `Closes #29` (épic #6).
- Revues : APPROVE WITH COMMENTS (run 39798719373), 5 points LOW et 3 tests
  manquants corrigés par `ae0b1c7` ; seconde revue APPROVE WITH COMMENTS
  (run 39838145119), 3 points LOW et 3 tests manquants corrigés par `593021c` ;
  troisième revue APPROVE WITH COMMENTS (run 39841323251), 3 points LOW et
  3 tests manquants corrigés par `251fd18` ; quatrième revue APPROVE WITH
  COMMENTS (run 39844814050), 5 points LOW et 4 tests manquants corrigés par
  `43d63c9` ; cinquième revue APPROVE WITH COMMENTS (run 39844814050), 2 points
  LOW et 2 tests manquants corrigés par `e691984` ; sixième revue APPROVE WITH
  COMMENTS, 2 points LOW et 2 tests manquants corrigés par `0bb1136` ; septième
  revue APPROVE WITH COMMENTS, 4 points LOW et leurs tests de non-régression
  ajoutés ; huitième revue APPROVE WITH COMMENTS, 3 points LOW et leurs tests
  de non-régression ajoutés ; neuvième revue APPROVE WITH COMMENTS, 3 points
  LOW et leurs tests ajoutés ; dixième revue APPROVE WITH COMMENTS, 3 points
  LOW et leurs tests ajoutés ; onzième revue APPROVE WITH COMMENTS, 3 points
  LOW et leurs tests ajoutés ; douzième revue APPROVE WITH COMMENTS, 3 points
  LOW et leurs tests ajoutés ; treizième revue APPROVE WITH COMMENTS, 3 points
  LOW et leurs tests ajoutés ; quatorzième revue APPROVE WITH COMMENTS,
  3 points LOW et leurs tests ajoutés ; quinzième revue APPROVE WITH
  COMMENTS, 2 points LOW et leurs tests de non-régression ajoutés dans la
  passe courante (voir les quinze tableaux ci-dessus).
- La feuille SAMM externe n'est pas accessible depuis le dépôt : reporter les
  lignes ci-dessus avec le lien de la PR et le SHA final du squash/merge
  (**re-pinner les permaliens sur ce SHA final** si le squash crée un SHA
  neuf).
