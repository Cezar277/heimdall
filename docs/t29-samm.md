# T29 — preuves pour la ligne SAMM

Périmètre : ticket #29 « Squelette heimdall scan », sous-ticket de l'épic #6
« CLI, hook et CI headless ». Cette fiche fournit les couples **module +
ligne** et les permaliens du code testé ; elle ne prétend pas modifier une
feuille externe.

Révision du code testé : `593021cacc1c48f935dcd38aed0e821b4baaf2c3`
(« fix(t29): correctifs de la revue #166 — EPIPE, TOCTOU index, docstrings
SHA »), qui contient la livraison initiale (`96b5800`, revue APPROVE WITH
COMMENTS), ses premiers durcissements (`ae0b1c7`) et les correctifs de la
seconde revue (run 39838145119). Les permaliens ci-dessous épinglent ce SHA :
un lien vers la branche changerait de lignes au fil des commits.

Base : `aa875a1` (fusion de #165, `main` au moment de la livraison), qui
contient le scanner #22 (`2ba3ebf…`) et l'accès git confiné #27. Le diff
`git diff aa875a1 593021c -- heimdall tests` porte **toute** la livraison #29 :
la CLI (`heimdall/cli/scan.py`, `heimdall/cli/main.py`), la lecture des blobs
de l'index (`heimdall/mcp/gitdiff.py`), le mode strict et les bornes du
scanner (`heimdall/scanner/exclusions.py`, `heimdall/scanner/detect.py`) et
les tests (`tests/test_cli_scan.py`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Commande branchée** : `heimdall scan` rend un verdict au lieu du stub « commande non branchée » | [heimdall/cli/main.py:72–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L72-L137), [heimdall/cli/scan.py:101–110](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L101-L110) | [tests/test_cli_scan.py:73–110](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L73-L110) | dépôt propre → 0 ; secret → 1 ; racine absente → 2 ; aucune écriture |
| **Codes de sortie documentés** : 0 / 1 / 2, jamais 0 après une erreur (invariant 11, REQ-SEC-07) | [heimdall/cli/scan.py:49–51](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L49-L51), [heimdall/cli/main.py:9–13](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L9-L13), [125–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:73–110](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L73-L110), [tests/security/test_scanner_bypass.py:64–71](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/security/test_scanner_bypass.py#L64-L71) | `ScanError`/`ToolFailure` → 2 ; panic → 2 ; jamais 1 sans secret avéré |
| **Rendu fail-closed** (revue #166, LOW) : un échec de rendu ou du résumé `--ci` sort en 2, jamais en 1 | [heimdall/cli/main.py:106–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L106-L137) | [tests/test_cli_scan.py:113–129](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L113-L129) | rendu planté → code 2 + message statique, pas de traceback en 1 |
| **Écriture d'erreur best-effort** (seconde revue, LOW) : stderr fermé (EPIPE) dans un handler ne fait jamais sortir 1 | [heimdall/cli/main.py:46–59](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:132–159](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L132-L159) | `BrokenPipeError` sur stderr (chemin d'erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 |
| **Re-contrôle anti-TOCTOU de l'index** (seconde revue, LOW) : un `git add` concurrent après le snapshot refuse le scan | [heimdall/cli/scan.py:162–167](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L162-L167) | [tests/test_cli_scan.py:377–402](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L377-L402) | index muté pendant le scan → 2 + message statique, jamais 0/1 sur snapshot périmé |
| **HIGH (revue #165) — mode `--staged` : aucun blob ajouté ou modifié n'est exclu de chemin** | [heimdall/cli/scan.py:124–167](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L124-L167) | [tests/test_cli_scan.py:219–235](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L219-L235) | `vendor/evil.py` et `package-lock.json` → Finding + code 1 (alors que `is_excluded()` les excluait) |
| **HIGH (revue #165) — mode strict de l'arbre de travail** : `vendor/`, `third_party/` et lockfiles sont analysés | [heimdall/scanner/exclusions.py:37–75](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/exclusions.py#L37-L75), [161–197](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/exclusions.py#L161-L197), [heimdall/scanner/detect.py:151–174](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L151-L174), [217–244](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L217-L244), [heimdall/cli/scan.py:113–121](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L113-L121) | [tests/test_cli_scan.py:194–213](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L194-L213) | secret dans `vendor/` et dans un lockfile → code 1 ; `node_modules/` (exclusion technique) → code 0 ; politique #59 inchangée par défaut (suite #22 verte) |
| **Bornes du scan** (revue #166, LOW) : refus au-delà de 50 000 fichiers / 256 Mio (arbre) ou 1000 blobs / 32 Mio (`--staged`), 1 Mio par fichier | [heimdall/scanner/detect.py:44–53](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L44-L53), [194–203](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L194-L203), [heimdall/cli/scan.py:62–66](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L62-L66), [142–150](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L142-L150) | [tests/test_cli_scan.py:162–188](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L162-L188), [343–348](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L343-L348) | trop de fichiers/octets/blob trop gros → 2 ; jamais un résultat tronqué présenté comme complet |
| **Le blob indexé est lu en entier**, pas seulement ses lignes modifiées | [heimdall/mcp/gitdiff.py:379–419](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L379-L419) | [tests/test_cli_scan.py:289–303](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L289-L303) | secret laissé tel quel dans un fichier modifié → toujours signalé (code 1) |
| **Polyglotte binaire + texte** (seconde revue) : en-tête PNG + secret en clair (sans NUL) → **scanné**, pas sauté | [heimdall/cli/scan.py:153–157](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L153-L157) | [tests/test_cli_scan.py:360–374](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L360-L374) | faux PNG portant un secret → Finding + code 1, secret absent de la sortie |
| **Lecture de l'index confinée** : argv figé, SHA validé (SHA-1 **et** SHA-256), sortie illisible refusée | [heimdall/mcp/gitdiff.py:85–102](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L85-L102), [439–462](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L439-L462), [465–532](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L465-L532) | [tests/test_cli_scan.py:417–428](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L417-L428), [513–555](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L513-L555) | `--upload-pack=…` refusé avant l'argv ; index en conflit, SHA invalide, chemin hors contrat → refus ; dépôt SHA-256 (64 hexa) accepté |
| **Chemins représentables** (revue #166, LOW) : contrat Finding #14 (4096), pas la limite MCP (1024) | [heimdall/mcp/gitdiff.py:492–532](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L492-L532) | [tests/test_cli_scan.py:238–277](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L238-L277) | espace/Unicode et chemin > 1024 analysés ; > 4096 refusé (jamais tronqué) |
| **100 % local** : aucun fetch, même dans un clone partiel | [heimdall/mcp/gitdiff.py:124](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L124) | [tests/test_network_isolation.py:403–422](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_network_isolation.py#L403-L422) | `GIT_NO_LAZY_FETCH=1` ; scan réel sous garde réseau : aucune connexion hors boucle locale |
| **Aucun LLM en CI** (REQ-SEC-02) : le module de scan n'importe aucun module réseau | [heimdall/cli/scan.py:31–45](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L31-L45) | [tests/security/test_prompt_injection.py:472–499](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/security/test_prompt_injection.py#L472-L499) | garde AST étendue à `heimdall/cli/scan.py` : ni `socket`, ni `subprocess`, ni `os` hors garde de chemin |
| **Aucun secret en clair** (invariant 8) : la sortie ne porte qu'empreinte et entropie | [heimdall/cli/scan.py:170–212](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L170-L212) | [tests/test_cli_scan.py:84–93](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L84-L93), [434–459](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L434-L459) | la valeur du secret est absente de stdout comme de stderr ; le JSON porte les 7 champs du contrat #14 |
| **Sortie JSON déterministe** (`--json`), combinable avec `--ci --staged` | [heimdall/cli/scan.py:170–189](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L170-L189), [heimdall/cli/main.py:113–124](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L113-L124) | [tests/test_cli_scan.py:434–459](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L434-L459), [489–507](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L489-L507) | contrat `heimdall.scan.v1` : `schema`, `scope`, `count`, `findings` (7 champs) ; stdout parseable seul, résumé sur stderr |
| **Mode `--ci` headless** : le verdict est le code de sortie, résumé déterministe sur stderr | [heimdall/cli/main.py:117–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L117-L137) | [tests/test_cli_scan.py:472–478](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L472-L478) | sortie humaine ou JSON sur stdout, résumé sur stderr, code 0/1 |
| **Documentation à jour** (DoD) | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/docs/cli.md), [docs/scanner.md](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/docs/scanner.md), [README.md](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/README.md) | — | contrat CLI, codes de sortie, JSON, bornes, blobs binaires et limites documentés |

## Résultats locaux

Environnement : Linux, Python 3.14.8, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_cli_scan.py -q
43 passed

.venv/bin/python -m pytest
1466 passed, 4317 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
Total coverage: 96,02 % (seuil 85 % atteint)
heimdall/cli/scan.py : 100 % ; heimdall/cli/main.py : 98 % ;
heimdall/mcp/gitdiff.py : 97 % ; heimdall/scanner/detect.py : 90 %

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
| LOW — rendu hors du try fail-closed | rendu et résumé `--ci` déplacés dans le même try que `collect()` ; toute panne → code 2 | [main.py:106–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L106-L137) + [test_cli_scan.py:113–129](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L113-L129) |
| LOW — arbre sans plafond total | `MAX_FILES` (50 000) et `MAX_TOTAL_BYTES` (256 Mio) dans `Scanner` ; `_read_text` rend la taille lue | [detect.py:44–53](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L44-L53), [194–203](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/scanner/detect.py#L194-L203) + [test_cli_scan.py:162–188](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L162-L188) |
| LOW — dépôts SHA-256 rejetés | `_OBJECT_PATTERN` accepte 40 **ou** 64 hexa ; SHA nul reconnu dans les deux formats | [gitdiff.py:439–449](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L439-L449) + [test_cli_scan.py:264–277](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L264-L277) |
| LOW — binaires sautés en silence, doc dit « aucune » exclusion | doc : « aucune exclusion **de chemin** » + binaires explicitement listés comme limite dans les deux périmètres | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/docs/cli.md) |
| LOW — doubles limites de chemin (1024 vs 4096) | `_staged_change` valide avec `validate_relative_path` (contrat Finding, 4096) | [gitdiff.py:492–532](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L492-L532) + [test_cli_scan.py:238–277](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L238-L277) |
| Tests manquants — combinaison `--ci --json --staged` | test dédié : stdout JSON parseable, résumé sur stderr, code 1 | [test_cli_scan.py:489–507](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L489-L507) |
| Tests manquants — chemins espace/Unicode et > 1024 | deux tests e2e + cas parseur > 4096 refusé | [test_cli_scan.py:238–261](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L238-L261), [549–555](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L549-L555) |
| Tests manquants — dépôt SHA-256 | `GitRepo(object_format="sha256")` + e2e `--staged` (skip si git ne le supporte pas) | [test_cli_scan.py:264–277](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L264-L277) |

## Correctifs de la seconde revue (run 39838145119, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `echo` d'erreur non protégé contre EPIPE | écriture de secours best-effort (`_echo_stderr_best_effort`) dans les deux handlers : stderr fermé → 2 garanti, jamais 1 ni traceback | [main.py:46–59](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/main.py#L125-L137) + [test_cli_scan.py:132–159](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L132-L159) |
| LOW — TOCTOU index entre snapshot et verdict `--staged` | lectures adressées par SHA (incorruptibles) + **relecture de l'index après l'analyse** : toute divergence refuse le scan (code 2), pas de verdict sur snapshot périmé (solution `write-tree` écartée : elle écrirait dans `.git`, contraire au scan lecture seule) | [scan.py:162–167](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/cli/scan.py#L162-L167) + [test_cli_scan.py:377–402](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L377-L402) |
| LOW — docstrings obsolètes 40 vs 40/64 | `STAGED_RAW_ARGUMENTS` et `StagedChange` disent « 40 (SHA-1) ou 64 (SHA-256) » | [gitdiff.py:85–102](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L85-L102), [211–221](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/heimdall/mcp/gitdiff.py#L211-L221) |
| Tests manquants — stderr fermé / `BrokenPipeError` | `echo` stderr qui lève sur les trois chemins (erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 | [test_cli_scan.py:132–159](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L132-L159) |
| Tests manquants — mutation concurrente de l'index | snapshot simulé divergent au second appel → 2, jamais 0/1 | [test_cli_scan.py:377–402](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L377-L402) |
| Tests manquants — polyglotte binaire + texte | faux PNG (magie + secret en clair, sans NUL) → Finding + code 1, fige `decode_text` → scanné | [test_cli_scan.py:360–374](https://github.com/Cezar277/heimdall/blob/593021cacc1c48f935dcd38aed0e821b4baaf2c3/tests/test_cli_scan.py#L360-L374) |

## Limites assumées

- La validation humaine Y/N/E et le remplacement du secret ne sont pas dans ce
  ticket : `scan` signale, il ne répare pas (#32).
- Les exclusions **techniques** restent (binaires, `node_modules/`, `build/`,
  `dist/`, `.venv/`) : un secret qui y est copié n'est pas signalé. Un blob
  binaire reconnu est sauté dans les **deux** périmètres (limite documentée).
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
  manquants corrigés par `ae0b1c7`, puis seconde revue APPROVE WITH COMMENTS
  (run 39838145119), 3 points LOW et 3 tests manquants corrigés par `593021c`
  (voir les deux tableaux ci-dessus).
- La feuille SAMM externe n'est pas accessible depuis le dépôt : reporter les
  lignes ci-dessus avec le lien de la PR et le SHA final du squash/merge
  (**re-pinner les permaliens sur ce SHA final** si le squash crée un SHA
  neuf).
