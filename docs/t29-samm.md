# T29 — preuves pour la ligne SAMM

Périmètre : ticket #29 « Squelette heimdall scan », sous-ticket de l'épic #6
« CLI, hook et CI headless ». Cette fiche fournit les couples **module +
ligne** et les permaliens du code testé ; elle ne prétend pas modifier une
feuille externe.

Révision du code testé : `96b58008e0f974f6bb37cacfb9ddce62a43990c4`
(« feat(t29): branche la CLI `heimdall scan` sur le scanner (#29) »). Les
permaliens ci-dessous épinglent ce SHA : un lien vers la branche changerait
de lignes au fil des commits.

Base : `aa875a1` (fusion de #165, `main` au moment de la livraison), qui
contient le scanner #22 (`2ba3ebf…`) et l'accès git confiné #27. Le diff
`git diff aa875a1 96b5800 -- heimdall tests` porte **toute** la livraison #29 :
la CLI (`heimdall/cli/scan.py`, `heimdall/cli/main.py`), la lecture des blobs
de l'index (`heimdall/mcp/gitdiff.py`), le mode strict des exclusions
(`heimdall/scanner/exclusions.py`, `heimdall/scanner/detect.py`) et les tests
(`tests/test_cli_scan.py`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Commande branchée** : `heimdall scan` rend un verdict au lieu du stub « commande non branchée » | [heimdall/cli/main.py:56–113](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/main.py#L56-L113), [heimdall/cli/scan.py:100–109](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L100-L109) | [tests/test_cli_scan.py:72–113](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L72-L113) | dépôt propre → 0 ; secret → 1 ; racine absente → 2 ; aucune écriture |
| **Codes de sortie documentés** : 0 / 1 / 2, jamais 0 après une erreur (invariant 11, REQ-SEC-07) | [heimdall/cli/scan.py:49–51](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L49-L51), [heimdall/cli/main.py:9–13](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/main.py#L9-L13), [90–100](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/main.py#L90-L100) | [tests/test_cli_scan.py:72–113](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L72-L113), [tests/security/test_scanner_bypass.py:64–71](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/security/test_scanner_bypass.py#L64-L71) | `ScanError`/`ToolFailure` → 2 ; panic → 2 ; jamais 1 sans secret avéré |
| **HIGH (revue #165) — mode `--staged` : aucun blob ajouté ou modifié n'est exclu de chemin** | [heimdall/cli/scan.py:123–155](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L123-L155) | [tests/test_cli_scan.py:140–158](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L140-L158) | `vendor/evil.py` et `package-lock.json` → Finding + code 1 (alors que `is_excluded()` les excluait) |
| **HIGH (revue #165) — mode strict de l'arbre de travail** : `vendor/`, `third_party/` et lockfiles sont analysés | [heimdall/scanner/exclusions.py:37–75](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/scanner/exclusions.py#L37-L75), [161–197](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/scanner/exclusions.py#L161-L197), [heimdall/scanner/detect.py:142–161](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/scanner/detect.py#L142-L161), [194–217](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/scanner/detect.py#L194-L217), [heimdall/cli/scan.py:112–120](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L112-L120) | [tests/test_cli_scan.py:115–138](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L115-L138) | secret dans `vendor/` et dans un lockfile → code 1 ; `node_modules/` (exclusion technique) → code 0 ; politique #59 inchangée par défaut (suite #22 verte) |
| **Le blob indexé est lu en entier**, pas seulement ses lignes modifiées | [heimdall/mcp/gitdiff.py:376–417](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/mcp/gitdiff.py#L376-L417) | [tests/test_cli_scan.py:168–184](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L168-L184) | secret laissé tel quel dans un fichier modifié → toujours signalé (code 1) |
| **Lecture de l'index confinée** : argv figé, SHA validé, sortie illisible refusée | [heimdall/mcp/gitdiff.py:84–101](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/mcp/gitdiff.py#L84-L101), [445–482](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/mcp/gitdiff.py#L445-L482), [484–517](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/mcp/gitdiff.py#L484-L517) | [tests/test_cli_scan.py:251–265](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L251-L265), [326–359](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L326-L359) | `--upload-pack=…` refusé avant l'argv ; index en conflit, SHA invalide, chemin hors contrat → refus |
| **100 % local** : aucun fetch, même dans un clone partiel | [heimdall/mcp/gitdiff.py:117–122](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/mcp/gitdiff.py#L117-L122) | [tests/test_network_isolation.py:403–424](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_network_isolation.py#L403-L424) | `GIT_NO_LAZY_FETCH=1` ; scan réel sous garde réseau : aucune connexion hors boucle locale |
| **Aucun LLM en CI** (REQ-SEC-02) : le module de scan n'importe aucun module réseau | [heimdall/cli/scan.py:30–46](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L30-L46) | [tests/security/test_prompt_injection.py:472–499](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/security/test_prompt_injection.py#L472-L499) | garde AST étendue à `heimdall/cli/scan.py` : ni `socket`, ni `subprocess`, ni `os` hors garde de chemin |
| **Aucun secret en clair** (invariant 8) : la sortie ne porte qu'empreinte et entropie | [heimdall/cli/scan.py:158–200](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L158-L200) | [tests/test_cli_scan.py:83–93](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L83-L93), [268–304](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L268-L304) | la valeur du secret est absente de stdout comme de stderr ; le JSON porte les 7 champs du contrat #14 |
| **Sortie JSON déterministe** (`--json`) | [heimdall/cli/scan.py:158–177](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L158-L177), [heimdall/cli/main.py:101–104](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/main.py#L101-L104) | [tests/test_cli_scan.py:268–304](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L268-L304) | contrat `heimdall.scan.v1` : `schema`, `scope`, `count`, `findings` (7 champs) |
| **Mode `--ci` headless** : le verdict est le code de sortie, résumé déterministe sur stderr | [heimdall/cli/main.py:105–113](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/main.py#L105-L113) | [tests/test_cli_scan.py:306–324](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L306-L324) | sortie humaine sur stdout, résumé sur stderr, code 0/1 |
| **Bornes du scan staged** : fichier > 1 Mio, plus de 1000 blobs, volume > 32 Mio → refus | [heimdall/cli/scan.py:62–66](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L62-L66), [134–142](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/heimdall/cli/scan.py#L134-L142) | [tests/test_cli_scan.py:222–248](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/tests/test_cli_scan.py#L222-L248) | blob trop gros → 2 ; trop de fichiers → 2 ; jamais un résultat tronqué présenté comme complet |
| **Documentation à jour** (DoD) | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/docs/cli.md), [docs/scanner.md](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/docs/scanner.md), [README.md](https://github.com/Cezar277/heimdall/blob/96b58008e0f974f6bb37cacfb9ddce62a43990c4/README.md) | — | contrat CLI, codes de sortie, JSON, limites et mode strict documentés |

## Résultats locaux

Environnement : Linux, Python 3.14.8, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_cli_scan.py -q
30 passed

.venv/bin/python -m pytest
1453 passed, 4317 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
Total coverage: 95,94 % (seuil 85 % atteint)
heimdall/cli/scan.py : 100 % ; heimdall/cli/main.py : 92 % ; heimdall/mcp/gitdiff.py : 97 %

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

## Limites assumées

- La validation humaine Y/N/E et le remplacement du secret ne sont pas dans ce
  ticket : `scan` signale, il ne répare pas (#32).
- Les exclusions **techniques** restent (binaires, `node_modules/`, `build/`,
  `dist/`, `.venv/`) : un secret qui y est copié n'est pas signalé.
- `--staged` analyse l'index, pas l'historique : un secret déjà commité n'est
  pas re-détecté par ce mode.
- La trace `strace` d'un scan opérationnel reste à archiver côté CI
  (`docs/security/zero-egress.md`) : la preuve jointe ici est le test
  d'isolation réseau au niveau Python.

## Relecture et PR

- PR : à ouvrir sur la branche `29-t29-squelette-heimdall-scan` avec
  `Closes #29` (épic #6).
- Relecture inter-domaines et check `CI (/ci)` restent requis avant fusion.
- La feuille SAMM externe n'est pas accessible depuis le dépôt : reporter les
  lignes ci-dessus avec le lien de la PR et le SHA final du squash/merge
  (**re-pinner les permaliens sur ce SHA final** si le squash crée un SHA
  neuf).
