# T29 — preuves pour la ligne SAMM

Périmètre : ticket #29 « Squelette heimdall scan », sous-ticket de l'épic #6
« CLI, hook et CI headless ». Cette fiche fournit les couples **module +
ligne** et les permaliens du code testé ; elle ne prétend pas modifier une
feuille externe.

Révision du code testé : `ae0b1c7afbc1773535b770a0dfa4580b852be8a9`
(« fix(t29): durcissements de la revue #166 »), qui contient la livraison
initiale (`96b5800`, revue APPROVE WITH COMMENTS) et ses correctifs. Les
permaliens ci-dessous épinglent ce SHA : un lien vers la branche changerait
de lignes au fil des commits.

Base : `aa875a1` (fusion de #165, `main` au moment de la livraison), qui
contient le scanner #22 (`2ba3ebf…`) et l'accès git confiné #27. Le diff
`git diff aa875a1 ae0b1c7 -- heimdall tests` porte **toute** la livraison #29 :
la CLI (`heimdall/cli/scan.py`, `heimdall/cli/main.py`), la lecture des blobs
de l'index (`heimdall/mcp/gitdiff.py`), le mode strict et les bornes du
scanner (`heimdall/scanner/exclusions.py`, `heimdall/scanner/detect.py`) et
les tests (`tests/test_cli_scan.py`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Commande branchée** : `heimdall scan` rend un verdict au lieu du stub « commande non branchée » | [heimdall/cli/main.py:56–119](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L56-L119), [heimdall/cli/scan.py:100–109](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L100-L109) | [tests/test_cli_scan.py:72–110](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L72-L109) | dépôt propre → 0 ; secret → 1 ; racine absente → 2 ; aucune écriture |
| **Codes de sortie documentés** : 0 / 1 / 2, jamais 0 après une erreur (invariant 11, REQ-SEC-07) | [heimdall/cli/scan.py:49–51](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L49-L51), [heimdall/cli/main.py:9–13](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L9-L13), [109–119](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L109-L119) | [tests/test_cli_scan.py:72–110](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L72-L109), [tests/security/test_scanner_bypass.py:64–71](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/security/test_scanner_bypass.py#L64-L71) | `ScanError`/`ToolFailure` → 2 ; panic → 2 ; jamais 1 sans secret avéré |
| **Rendu fail-closed** (revue #166, LOW) : un échec de rendu ou du résumé `--ci` sort en 2, jamais en 1 | [heimdall/cli/main.py:90–119](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L90-L119) | [tests/test_cli_scan.py:112–129](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L112-L128) | rendu planté → code 2 + message statique, pas de traceback en 1 |
| **HIGH (revue #165) — mode `--staged` : aucun blob ajouté ou modifié n'est exclu de chemin** | [heimdall/cli/scan.py:123–155](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L123-L155) | [tests/test_cli_scan.py:188–206](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L188-L204) | `vendor/evil.py` et `package-lock.json` → Finding + code 1 (alors que `is_excluded()` les excluait) |
| **HIGH (revue #165) — mode strict de l'arbre de travail** : `vendor/`, `third_party/` et lockfiles sont analysés | [heimdall/scanner/exclusions.py:37–75](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/exclusions.py#L37-L75), [161–197](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/exclusions.py#L161-L197), [heimdall/scanner/detect.py:151–174](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L151-L174), [217–244](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L217-L244), [heimdall/cli/scan.py:112–120](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L112-L120) | [tests/test_cli_scan.py:163–186](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L163-L182) | secret dans `vendor/` et dans un lockfile → code 1 ; `node_modules/` (exclusion technique) → code 0 ; politique #59 inchangée par défaut (suite #22 verte) |
| **Bornes du scan** (revue #166, LOW) : refus au-delà de 50 000 fichiers / 256 Mio (arbre) ou 1000 blobs / 32 Mio (`--staged`), 1 Mio par fichier | [heimdall/scanner/detect.py:44–53](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L44-L53), [194–203](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L194-L203), [heimdall/cli/scan.py:62–66](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L62-L66), [134–142](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L134-L142) | [tests/test_cli_scan.py:131–160](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L131-L157), [312–339](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L312-L338) | trop de fichiers/octets/blob trop gros → 2 ; jamais un résultat tronqué présenté comme complet |
| **Le blob indexé est lu en entier**, pas seulement ses lignes modifiées | [heimdall/mcp/gitdiff.py:377–417](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L377-L417) | [tests/test_cli_scan.py:258–273](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L258-L272) | secret laissé tel quel dans un fichier modifié → toujours signalé (code 1) |
| **Lecture de l'index confinée** : argv figé, SHA validé (SHA-1 **et** SHA-256), sortie illisible refusée | [heimdall/mcp/gitdiff.py:85–101](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L85-L101), [437–460](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L440-L460), [463–529](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L463-L530) | [tests/test_cli_scan.py:341–356](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L341-L352), [437–480](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L437-L479) | `--upload-pack=…` refusé avant l'argv ; index en conflit, SHA invalide, chemin hors contrat → refus ; dépôt SHA-256 (64 hexa) accepté |
| **Chemins représentables** (revue #166, LOW) : contrat Finding #14 (4096), pas la limite MCP (1024) | [heimdall/mcp/gitdiff.py:490–529](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L490-L530) | [tests/test_cli_scan.py:207–246](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L207-L246) | espace/Unicode et chemin > 1024 analysés ; > 4096 refusé (jamais tronqué) |
| **100 % local** : aucun fetch, même dans un clone partiel | [heimdall/mcp/gitdiff.py:123](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L123) | [tests/test_network_isolation.py:403–424](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_network_isolation.py#L403-L422) | `GIT_NO_LAZY_FETCH=1` ; scan réel sous garde réseau : aucune connexion hors boucle locale |
| **Aucun LLM en CI** (REQ-SEC-02) : le module de scan n'importe aucun module réseau | [heimdall/cli/scan.py:30–46](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L31-L45) | [tests/security/test_prompt_injection.py:472–499](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/security/test_prompt_injection.py#L472-L499) | garde AST étendue à `heimdall/cli/scan.py` : ni `socket`, ni `subprocess`, ni `os` hors garde de chemin |
| **Aucun secret en clair** (invariant 8) : la sortie ne porte qu'empreinte et entropie | [heimdall/cli/scan.py:158–200](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L158-L200) | [tests/test_cli_scan.py:83–93](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L83-L92), [358–394](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L358-L393) | la valeur du secret est absente de stdout comme de stderr ; le JSON porte les 7 champs du contrat #14 |
| **Sortie JSON déterministe** (`--json`), combinable avec `--ci --staged` | [heimdall/cli/scan.py:158–177](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/scan.py#L158-L177), [heimdall/cli/main.py:97–104](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L97-L108) | [tests/test_cli_scan.py:358–394](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L358-L393), [413–435](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L413-L431) | contrat `heimdall.scan.v1` : `schema`, `scope`, `count`, `findings` (7 champs) ; stdout parseable seul, résumé sur stderr |
| **Mode `--ci` headless** : le verdict est le code de sortie, résumé déterministe sur stderr | [heimdall/cli/main.py:105–119](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L101-L119) | [tests/test_cli_scan.py:396–435](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L396-L401) | sortie humaine ou JSON sur stdout, résumé sur stderr, code 0/1 |
| **Documentation à jour** (DoD) | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/docs/cli.md), [docs/scanner.md](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/docs/scanner.md), [README.md](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/README.md) | — | contrat CLI, codes de sortie, JSON, bornes, blobs binaires et limites documentés |

## Résultats locaux

Environnement : Linux, Python 3.14.8, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_cli_scan.py -q
40 passed

.venv/bin/python -m pytest
1463 passed, 4317 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
Total coverage: 96,01 % (seuil 85 % atteint)
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
| LOW — rendu hors du try fail-closed | rendu et résumé `--ci` déplacés dans le même try que `collect()` ; toute panne → code 2 | [main.py:90–119](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/cli/main.py#L90-L119) + [test_cli_scan.py:112–129](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L112-L128) |
| LOW — arbre sans plafond total | `MAX_FILES` (50 000) et `MAX_TOTAL_BYTES` (256 Mio) dans `Scanner` ; `_read_text` rend la taille lue | [detect.py:44–53](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L44-L53), [194–203](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/scanner/detect.py#L194-L203) + [test_cli_scan.py:131–160](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L131-L157) |
| LOW — dépôts SHA-256 rejetés | `_OBJECT_PATTERN` accepte 40 **ou** 64 hexa ; SHA nul reconnu dans les deux formats | [gitdiff.py:437–449](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L440-L448) + [test_cli_scan.py:233–246](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L233-L246) |
| LOW — binaires sautés en silence, doc dit « aucune » exclusion | doc : « aucune exclusion **de chemin** » + binaires explicitement listés comme limite dans les deux périmètres | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/docs/cli.md) |
| LOW — doubles limites de chemin (1024 vs 4096) | `_staged_change` valide avec `validate_relative_path` (contrat Finding, 4096) | [gitdiff.py:490–529](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/heimdall/mcp/gitdiff.py#L490-L530) + [test_cli_scan.py:207–246](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L207-L246) |
| Tests manquants — combinaison `--ci --json --staged` | test dédié : stdout JSON parseable, résumé sur stderr, code 1 | [test_cli_scan.py:413–435](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L413-L431) |
| Tests manquants — chemins espace/Unicode et > 1024 | deux tests e2e + cas parseur > 4096 refusé | [test_cli_scan.py:207–231](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L207-L230), [473–480](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L473-L479) |
| Tests manquants — dépôt SHA-256 | `GitRepo(object_format="sha256")` + e2e `--staged` (skip si git ne le supporte pas) | [test_cli_scan.py:233–246](https://github.com/Cezar277/heimdall/blob/ae0b1c7afbc1773535b770a0dfa4580b852be8a9/tests/test_cli_scan.py#L233-L246) |

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
- Revue : APPROVE WITH COMMENTS (run 39798719373), 5 points LOW et 3 tests
  manquants corrigés par `ae0b1c7` (voir tableau ci-dessus).
- La feuille SAMM externe n'est pas accessible depuis le dépôt : reporter les
  lignes ci-dessus avec le lien de la PR et le SHA final du squash/merge
  (**re-pinner les permaliens sur ce SHA final** si le squash crée un SHA
  neuf).
