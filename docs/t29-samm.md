# T29 — preuves pour la ligne SAMM

Périmètre : ticket #29 « Squelette heimdall scan », sous-ticket de l'épic #6
« CLI, hook et CI headless ». Cette fiche fournit les couples **module +
ligne** et les permaliens du code testé ; elle ne prétend pas modifier une
feuille externe.

Révision du code testé : `251fd187e09ae794030c3c34ae78db3a82ba8836`
(« fix(t29): correctifs de la 3e revue — gitlink, schéma scan.v1, plafond
Findings »), qui contient la livraison initiale (`96b5800`, revue APPROVE
WITH COMMENTS), ses premiers durcissements (`ae0b1c7`), les correctifs de la
seconde revue (`593021c`, run 39838145119) et ceux de la troisième revue
(run 39841323251). Les permaliens ci-dessous épinglent ce SHA : un lien vers
la branche changerait de lignes au fil des commits.

Base : `aa875a1` (fusion de #165, `main` au moment de la livraison), qui
contient le scanner #22 (`2ba3ebf…`) et l'accès git confiné #27. Le diff
`git diff aa875a1 251fd18 -- heimdall tests schemas` porte **toute** la
livraison #29 :
la CLI (`heimdall/cli/scan.py`, `heimdall/cli/main.py`), la lecture des blobs
de l'index (`heimdall/mcp/gitdiff.py`), le mode strict et les bornes du
scanner (`heimdall/scanner/exclusions.py`, `heimdall/scanner/detect.py`) et
les tests (`tests/test_cli_scan.py`).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Commande branchée** : `heimdall scan` rend un verdict au lieu du stub « commande non branchée » | [heimdall/cli/main.py:72–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L72-L137), [heimdall/cli/scan.py:107–116](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L107-L116) | [tests/test_cli_scan.py:115–152](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L115-L152) | dépôt propre → 0 ; secret → 1 ; racine absente → 2 ; aucune écriture |
| **Codes de sortie documentés** : 0 / 1 / 2, jamais 0 après une erreur (invariant 11, REQ-SEC-07) | [heimdall/cli/scan.py:49–51](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L49-L51), [heimdall/cli/main.py:9–13](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L9-L13), [125–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:115–152](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L115-L152), [tests/security/test_scanner_bypass.py:64–71](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/security/test_scanner_bypass.py#L64-L71) | `ScanError`/`ToolFailure` → 2 ; panic → 2 ; jamais 1 sans secret avéré |
| **Rendu fail-closed** (revue #166, LOW) : un échec de rendu ou du résumé `--ci` sort en 2, jamais en 1 | [heimdall/cli/main.py:106–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L106-L137) | [tests/test_cli_scan.py:155–171](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L155-L171) | rendu planté → code 2 + message statique, pas de traceback en 1 |
| **Écriture d'erreur best-effort** (seconde revue, LOW) : stderr fermé (EPIPE) dans un handler ne fait jamais sortir 1 | [heimdall/cli/main.py:46–59](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L125-L137) | [tests/test_cli_scan.py:174–201](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L174-L201) | `BrokenPipeError` sur stderr (chemin d'erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 |
| **Re-contrôle anti-TOCTOU de l'index** (seconde revue, LOW) : un `git add` concurrent après le snapshot refuse le scan | [heimdall/cli/scan.py:162–167](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L162-L167) | [tests/test_cli_scan.py:450–475](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L450-L475) | index muté pendant le scan → 2 + message statique, jamais 0/1 sur snapshot périmé |
| **HIGH (revue #165) — mode `--staged` : aucun blob ajouté ou modifié n'est exclu de chemin** | [heimdall/cli/scan.py:130–189](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L130-L189) | [tests/test_cli_scan.py:261–277](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L261-L277) | `vendor/evil.py` et `package-lock.json` → Finding + code 1 (alors que `is_excluded()` les excluait) |
| **HIGH (revue #165) — mode strict de l'arbre de travail** : `vendor/`, `third_party/` et lockfiles sont analysés | [heimdall/scanner/exclusions.py:37–75](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/exclusions.py#L37-L75), [161–197](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/exclusions.py#L161-L197), [heimdall/scanner/detect.py:160–193](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L160-L193), [241–256](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L241-L256), [heimdall/cli/scan.py:119–127](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L119-L127) | [tests/test_cli_scan.py:236–255](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L236-L255) | secret dans `vendor/` et dans un lockfile → code 1 ; `node_modules/` (exclusion technique) → code 0 ; politique #59 inchangée par défaut (suite #22 verte) |
| **Bornes du scan** (revues #166 + 3e revue, LOW) : refus au-delà de 50 000 fichiers / 256 Mio / 10 000 Findings (arbre) ou 1000 blobs / 32 Mio / 10 000 Findings (`--staged`), 1 Mio par fichier | [heimdall/scanner/detect.py:44–53](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L44-L53), [54–61](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L54-L61), [214–223](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L214-L223), [226–230](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L226-L230), [heimdall/cli/scan.py:62–66](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L62-L66), [67–71](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L67-L71), [148–156](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L148-L156), [168–176](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L168-L176) | [tests/test_cli_scan.py:204–230](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L204-L230), [385–390](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L385-L390), [490–504](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L490-L504), [507–518](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L507-L518) | trop de fichiers/octets/blob trop gros/rafale de candidats → 2 ; jamais un résultat tronqué présenté comme complet |
| **Le blob indexé est lu en entier**, pas seulement ses lignes modifiées | [heimdall/mcp/gitdiff.py:379–421](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L379-L421) | [tests/test_cli_scan.py:331–345](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L331-L345) | secret laissé tel quel dans un fichier modifié → toujours signalé (code 1) |
| **Polyglotte binaire + texte** (seconde revue) : en-tête PNG + secret en clair (sans NUL) → **scanné**, pas sauté | [heimdall/cli/scan.py:153–157](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L153-L157) | [tests/test_cli_scan.py:433–447](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L433-L447) | faux PNG portant un secret → Finding + code 1, secret absent de la sortie |
| **Lecture de l'index confinée** : argv figé, SHA validé (SHA-1 **et** SHA-256), sortie illisible refusée | [heimdall/mcp/gitdiff.py:85–102](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L85-L102), [441–464](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L441-L464), [467–544](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L467-L544) | [tests/test_cli_scan.py:521–532](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L521-L532), [658–719](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L658-L719) | `--upload-pack=…` refusé avant l'argv ; index en conflit, SHA invalide, chemin hors contrat → refus ; dépôt SHA-256 (64 hexa) accepté |
| **Gitlink stagé ignoré** (3e revue, LOW) : le SHA d'une entrée 160000 désigne un commit, pas un blob — aucun texte à scanner | [heimdall/mcp/gitdiff.py:496–544](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L496-L544) | [tests/test_cli_scan.py:402–415](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L402-L415), [418–430](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L418-L430), [679–695](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L679-L695) | sous-module stagé → 0 (pas d'exit 2 systématique) ; secret voisin → 1 ; `T` gitlink → fichier scanné |
| **Chemins représentables** (revue #166, LOW) : contrat Finding #14 (4096), pas la limite MCP (1024) | [heimdall/mcp/gitdiff.py:496–544](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L496-L544) | [tests/test_cli_scan.py:280–319](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L280-L319) | espace/Unicode et chemin > 1024 analysés ; > 4096 refusé (jamais tronqué) |
| **100 % local** : aucun fetch, même dans un clone partiel | [heimdall/mcp/gitdiff.py:124](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L124) | [tests/test_network_isolation.py:403–422](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_network_isolation.py#L403-L422) | `GIT_NO_LAZY_FETCH=1` ; scan réel sous garde réseau : aucune connexion hors boucle locale |
| **Aucun LLM en CI** (REQ-SEC-02) : le module de scan n'importe aucun module réseau | [heimdall/cli/scan.py:31–45](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L31-L45) | [tests/security/test_prompt_injection.py:472–499](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/security/test_prompt_injection.py#L472-L499) | garde AST étendue à `heimdall/cli/scan.py` : ni `socket`, ni `subprocess`, ni `os` hors garde de chemin |
| **Aucun secret en clair** (invariant 8) : la sortie ne porte qu'empreinte et entropie | [heimdall/cli/scan.py:192–234](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L192-L234) | [tests/test_cli_scan.py:126–135](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L126-L135), [538–563](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L538-L563) | la valeur du secret est absente de stdout comme de stderr ; le JSON porte les 7 champs du contrat #14 |
| **Sortie JSON déterministe** (`--json`), combinable avec `--ci --staged` | [heimdall/cli/scan.py:192–211](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L192-L211), [heimdall/cli/main.py:113–124](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L113-L124) | [tests/test_cli_scan.py:538–563](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L538-L563), [634–652](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L634-L652) | contrat `heimdall.scan.v1` : `schema`, `scope`, `count`, `findings` (7 champs) ; stdout parseable seul, résumé sur stderr |
| **Contrat machine figé par schéma** (3e revue, LOW) : `schemas/scan.schema.json` (objet fermé, `schema` en const, `scope` en enum, items Finding v1 par `$ref`) | [schemas/scan.schema.json](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/schemas/scan.schema.json) | [tests/test_cli_scan.py:576–579](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L576-L579), [582–595](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L582-L595), [598–614](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L598-L614) | sortie `--json` réelle validée (champs exacts, `count` cohérent, NaN refusé) ; 6 documents invalides refusés |
| **Mode `--ci` headless** : le verdict est le code de sortie, résumé déterministe sur stderr | [heimdall/cli/main.py:117–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L117-L137) | [tests/test_cli_scan.py:617–623](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L617-L623) | sortie humaine ou JSON sur stdout, résumé sur stderr, code 0/1 |
| **Documentation à jour** (DoD) | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/docs/cli.md), [docs/scanner.md](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/docs/scanner.md), [README.md](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/README.md) | — | contrat CLI, codes de sortie, JSON, bornes, blobs binaires et limites documentés |

## Résultats locaux

Environnement : Linux, Python 3.14.8, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_cli_scan.py -q
51 passed

.venv/bin/python -m pytest
1474 passed, 4317 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
Total coverage: 96,04 % (seuil 85 % atteint)
heimdall/cli/scan.py : 100 % ; heimdall/cli/main.py : 98 % ;
heimdall/mcp/gitdiff.py : 97 % ; heimdall/scanner/detect.py : 91 %

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
| LOW — rendu hors du try fail-closed | rendu et résumé `--ci` déplacés dans le même try que `collect()` ; toute panne → code 2 | [main.py:106–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L106-L137) + [test_cli_scan.py:155–171](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L155-L171) |
| LOW — arbre sans plafond total | `MAX_FILES` (50 000) et `MAX_TOTAL_BYTES` (256 Mio) dans `Scanner` ; `_read_text` rend la taille lue | [detect.py:44–53](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L44-L53), [214–223](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L214-L223) + [test_cli_scan.py:204–230](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L204-L230) |
| LOW — dépôts SHA-256 rejetés | `_OBJECT_PATTERN` accepte 40 **ou** 64 hexa ; SHA nul reconnu dans les deux formats | [gitdiff.py:441–451](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L441-L451) + [test_cli_scan.py:306–319](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L306-L319) |
| LOW — binaires sautés en silence, doc dit « aucune » exclusion | doc : « aucune exclusion **de chemin** » + binaires explicitement listés comme limite dans les deux périmètres | [docs/cli.md](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/docs/cli.md) |
| LOW — doubles limites de chemin (1024 vs 4096) | `_staged_change` valide avec `validate_relative_path` (contrat Finding, 4096) | [gitdiff.py:496–544](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L496-L544) + [test_cli_scan.py:280–319](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L280-L319) |
| Tests manquants — combinaison `--ci --json --staged` | test dédié : stdout JSON parseable, résumé sur stderr, code 1 | [test_cli_scan.py:634–652](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L634-L652) |
| Tests manquants — chemins espace/Unicode et > 1024 | deux tests e2e + cas parseur > 4096 refusé | [test_cli_scan.py:280–303](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L280-L303), [713–719](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L713-L719) |
| Tests manquants — dépôt SHA-256 | `GitRepo(object_format="sha256")` + e2e `--staged` (skip si git ne le supporte pas) | [test_cli_scan.py:306–319](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L306-L319) |

## Correctifs de la seconde revue (run 39838145119, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `echo` d'erreur non protégé contre EPIPE | écriture de secours best-effort (`_echo_stderr_best_effort`) dans les deux handlers : stderr fermé → 2 garanti, jamais 1 ni traceback | [main.py:46–59](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L46-L59), [125–137](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/main.py#L125-L137) + [test_cli_scan.py:174–201](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L174-L201) |
| LOW — TOCTOU index entre snapshot et verdict `--staged` | lectures adressées par SHA (incorruptibles) + **relecture de l'index après l'analyse** : toute divergence refuse le scan (code 2), pas de verdict sur snapshot périmé (solution `write-tree` écartée : elle écrirait dans `.git`, contraire au scan lecture seule) | [scan.py:162–167](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L162-L167) + [test_cli_scan.py:450–475](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L450-L475) |
| LOW — docstrings obsolètes 40 vs 40/64 | `STAGED_RAW_ARGUMENTS` et `StagedChange` disent « 40 (SHA-1) ou 64 (SHA-256) » | [gitdiff.py:85–102](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L85-L102), [211–221](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L211-L221) |
| Tests manquants — stderr fermé / `BrokenPipeError` | `echo` stderr qui lève sur les trois chemins (erreur, `--ci` nominal, nominal sans `--ci`) → 2, 2, 0 | [test_cli_scan.py:174–201](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L174-L201) |
| Tests manquants — mutation concurrente de l'index | snapshot simulé divergent au second appel → 2, jamais 0/1 | [test_cli_scan.py:450–475](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L450-L475) |
| Tests manquants — polyglotte binaire + texte | faux PNG (magie + secret en clair, sans NUL) → Finding + code 1, fige `decode_text` → scanné | [test_cli_scan.py:433–447](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L433-L447) |

## Correctifs de la troisième revue (run 39841323251, APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — gitlink stagé (sous-module) fait échouer tout scan `--staged` en 2 | `_staged_change` ignore les entrées dont le mode indexé est `160000` (le SHA désigne un commit, pas un blob — aucun texte à scanner), comme les suppressions ; seul le mode indexé compte (`T` gitlink → fichier scanné) | [gitdiff.py:496–544](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/mcp/gitdiff.py#L496-L544) + [test_cli_scan.py:402–415](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L402-L415), [418–430](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L418-L430), [679–695](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L679-L695) |
| LOW — contrat machine `heimdall.scan.v1` sans schéma | `schemas/scan.schema.json` (draft 2020-12, objet fermé, `schema` en const, `scope` en enum, items Finding v1 par `$ref` sans duplication) | [schemas/scan.schema.json](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/schemas/scan.schema.json) + [test_cli_scan.py:576–614](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L576-L614) |
| LOW — nombre de Findings non borné, seul le volume d'entrée l'est | `MAX_FINDINGS` (arbre, fail-fast dans la boucle) et `MAX_STAGED_FINDINGS` (`--staged`, cible par cible, même ordre de tri) à 10 000 ; au-delà, refus 2 | [detect.py:54–61](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L54-L61), [226–230](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/scanner/detect.py#L226-L230) + [scan.py:67–71](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L67-L71), [168–176](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/heimdall/cli/scan.py#L168-L176) |
| Tests manquants — stagé d'un submodule | e2e `update-index --cacheinfo 160000` : skip → 0, secret voisin → 1 ; parseur : skip 160000, `T` vers fichier scanné | [test_cli_scan.py:402–430](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L402-L430), [679–695](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L679-L695) |
| Tests manquants — validation JSON contre le schéma | schéma valide, sortie `--json` réelle validée (`count` cohérent, NaN refusé), 6 documents invalides refusés | [test_cli_scan.py:576–614](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L576-L614) |
| Tests manquants — rafale de Findings | plafonds monkeypatchés → refus 2 en arbre comme en `--staged` | [test_cli_scan.py:490–518](https://github.com/Cezar277/heimdall/blob/251fd187e09ae794030c3c34ae78db3a82ba8836/tests/test_cli_scan.py#L490-L518) |

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
  manquants corrigés par `ae0b1c7` ; seconde revue APPROVE WITH COMMENTS
  (run 39838145119), 3 points LOW et 3 tests manquants corrigés par `593021c` ;
  troisième revue APPROVE WITH COMMENTS (run 39841323251), 3 points LOW et
  3 tests manquants corrigés par `251fd18` (voir les trois tableaux
  ci-dessus).
- La feuille SAMM externe n'est pas accessible depuis le dépôt : reporter les
  lignes ci-dessus avec le lien de la PR et le SHA final du squash/merge
  (**re-pinner les permaliens sur ce SHA final** si le squash crée un SHA
  neuf).
