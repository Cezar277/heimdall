# T59 — preuves pour la ligne SAMM

Périmètre : ticket #59 « Exclusions de fichiers », sous-ticket de l'épic #22.
Cette fiche fournit les couples **module + ligne**, les tests et les permaliens
du code livré ; elle ne prétend pas modifier une feuille SAMM externe.

Révision du code et des tests : `02bdc2db82aa9559b0042655d1c74dfcaed88e54`
(`test(scanner): couvre les bornes et pannes de l'exclusion Git (#59)`),
au-dessus de
`d007418d83ea45e1777c0fffe05afc3b5534e19b`
(`fix(scanner): durcit les exclusions Git et couvre les noms techniques (#59)`)
et de la livraison initiale
`ee8871a6830d82c309d98c49b15c4c36f3cf3640`
(`feat(scanner): exclusions Git sûres et observables (#59)`).

Les permaliens de cette fiche épinglent `02bdc2d…`, la révision qui contient
le code **et** les tests cités. Après une fusion par squash, re-pincer la fiche
sur le SHA présent dans `main` :

```sh
python scripts/repin_samm.py --fiche docs/t59-samm.md --sha <sha-final>
python scripts/repin_samm.py --fiche docs/t59-samm.md --check
```

## 1. Décision de sécurité (correctif du point HIGH #165)

Une exclusion **par le nom** est un contournement : `evil.png`,
`package-lock.json` ou `vendor/evil.py` suffiraient à faire disparaître un
secret du rapport. La revue de #165 a classé ce point **HIGH**. Le ticket #59
est donc livré sans aucune liste nominale :

- un fichier **suivi** est **toujours** scanné, même si un `.gitignore` le
  matche (`git add -f`) ou s'il vit dans un répertoire ignoré ;
- un fichier **non suivi et non ignoré** est scanné : il peut partir dans le
  prochain commit ;
- un fichier **non suivi et ignoré** par un `.gitignore` du dépôt est écarté :
  il ne peut pas être commité sans devenir suivi, et sera alors scanné.

Les catégories demandées (`vendor/`, `node_modules/`, lockfiles, binaires)
sont donc écartées **uniquement lorsque Git les déclare non suivies et
ignorées**. La liste est configurable par le dépôt : ce sont ses fichiers
`.gitignore` (versionnés ou locaux), motifs imbriqués et négations compris.

## 2. Traçabilité du ticket

| Exigence du ticket | Implémentation (module + ligne) | Tests et preuve permanente | Résultat local |
|---|---|---|---|
| Respecter `.gitignore` (racine, imbriqué, négations) | [gitignore.py:318–386](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L318-L386), [detect.py:322–366](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L322-L366) | [test_scanner_gitignore.py:339–361](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L339-L361) | `.gitignore` imbriqué appliqué ; `!keep.log` réintègre le fichier |
| `.env` ignoré : aucun Finding dans un fichier exclu | [detect.py:616–621](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L621) | [test_scanner_gitignore.py:101–111](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L101-L111) | `scan() == []`, `git_ignored == 1`, fichier jamais lu |
| `vendor/` ignoré | [gitignore.py:370–385](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L370-L385) | [test_scanner_gitignore.py:114–122](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L114-L122) | Répertoire élagué, compté une entrée |
| `node_modules/` ignoré | [gitignore.py:370–385](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L370-L385) | [test_scanner_gitignore.py:125–133](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L125-L133) | Répertoire élagué, aucun paquet lu |
| Lockfile ignoré | [detect.py:616–621](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L621) | [test_scanner_gitignore.py:136–144](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L136-L144) | `package.lock` écarté par `*.lock`, sans règle nominale |
| Binaire ignoré | [detect.py:616–621](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L621) | [test_scanner_gitignore.py:147–155](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L147-L155) | Écarté **avant** décodage : aucun code 2 |
| Fichier surdimensionné ignoré | [detect.py:616–621](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L621) | [test_scanner_gitignore.py:158–166](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L158-L166) | Jamais ouvert au-delà de la borne |
| Liste configurable par le dépôt, pas par la machine | [gitignore.py:101–121](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L101-L121), [gitignore.py:347–360](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L347-L360) | [test_scanner_gitignore.py:223–263](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L223-L263) | `.git/info/exclude` et `core.excludesFile` **non** honorés |
| Fichier suivi qui matche un motif : toujours scanné | [gitignore.py:370–385](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L370-L385) | [test_scanner_gitignore.py:169–179](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L169-L179) | `git add -f config.py` → Finding `config.py`, `git_ignored == 0` |
| Fichier suivi dans un répertoire ignoré : répertoire non élagué | [gitignore.py:306–315](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L306-L315), [gitignore.py:373–379](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L373-L379) | [test_scanner_gitignore.py:182–199](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L182-L199) | `vendor/keep.py` détecté, `vendor/secret.py` voisin écarté |
| Aucun nom technique n'exclut à lui seul (correctif #165) | [detect.py:598–655](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L598-L655), [detect.py:657–721](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L657-L721) | [test_scanner_gitignore.py:300–325](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L300-L325), [test_cli_scan.py:621–635](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L621-L635) | `vendor/evil.py`, `node_modules/evil.js`, `package-lock.json`, `evil.png`, `dist/evil.txt` non ignorés → tous détectés |
| Le `.gitignore` lui-même reste scanné | [detect.py:598–655](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L598-L655), [detect.py:657–721](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L657-L721) | [test_scanner_gitignore.py:213–220](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L213-L220) | Un secret dans `.gitignore` est signalé |
| Fichier unique explicite : toujours scanné | [detect.py:322–349](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L322-L349) | [test_scanner_gitignore.py:328–336](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L328-L336) | Aucune consultation de `.gitignore` en mode fichier |
| Lien symbolique ignoré : jamais suivi | [detect.py:616–629](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L629) | [test_scanner_gitignore.py:364–381](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L364-L381) | Lien ignoré écarté avant la garde `symlink` |

## 3. Invariants de sécurité et durcissement

| Invariant | Implémentation (module + ligne) | Test / preuve |
|---|---|---|
| Git résolu hors `PATH` hérité, argv figé, sans shell | [gitignore.py:48–51](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L48-L51), [gitignore.py:181–191](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L181-L191) | [test_network_isolation.py:639–643](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_network_isolation.py#L639-L643) : argv exact accepté, aucune variante réseau |
| Environnement reconstruit : pas de `GIT_DIR`/config héritée, `fsmonitor` désactivé | [gitignore.py:65–76](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L65-L76), [gitignore.py:101–121](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L101-L121) | [test_scanner_gitignore.py:243–263](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L243-L263) |
| Timeout unitaire, deadline de scan, sortie bornée | [gitignore.py:53–60](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L53-L60), [gitignore.py:124–131](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L124-L131), [gitignore.py:134–152](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L134-L152), [gitignore.py:210–244](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L210-L244) | [test_scanner_gitignore.py:454–479](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L454-L479), [test_scanner_gitignore.py:482–521](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L482-L521) | Deadline franchie → `ScanError` ; timeout, erreur d'attente et sortie hors plafond → Git tué puis parcours complet |
| Panne Git : parcours complet, jamais un skip silencieux | [gitignore.py:169–244](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L169-L244), [gitignore.py:318–386](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L318-L386) | [test_scanner_gitignore.py:266–277](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L266-L277), [test_scanner_gitignore.py:401–416](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L401-L416) | Git absent, binaire cassé, racine relative ou hors dépôt → tout l'arbre est lu |
| Parsing strict de la sortie Git ; forme inattendue → parcours complet | [gitignore.py:247–303](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L247-L303) | [test_scanner_gitignore.py:428–443](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L428-L443) | NUL final, UTF-8, chemin valide, étiquette connue exigés |
| Défense en profondeur : un fichier suivi n'est jamais exclu | [gitignore.py:373–385](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/gitignore.py#L373-L385) | [test_scanner_gitignore.py:524–547](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L524-L547) | Même une sortie Git incohérente ne peut pas exclure `config.py` |
| Identité de racine re-vérifiée avant/après la collecte Git | [detect.py:322–349](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L322-L349) | [test_scanner_detect.py](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_detect.py) (garde de racine) | Racine substituée → `ScanError`, jamais un verdict sur un autre arbre |
| Politique d'exclusion strictement booléenne | [detect.py:228–234](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L228-L234) | [test_scanner_gitignore.py:291–297](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L291-L297) | `"yes"`, `1`, `0`, `None` → `ValueError` à la construction |
| Nombre d'exclusions observable et remis à zéro | [detect.py:308–320](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L308-L320), [detect.py:423–430](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L423-L430) | [test_scanner_gitignore.py:384–395](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_scanner_gitignore.py#L384-L395) | Deux scans successifs ne cumulent pas |
| Aucun secret dans le rapport, les erreurs ou les traces | [scan.py:791–832](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L791-L832) | Tests CLI : la clé AWS synthétique est absente de `stdout`/`stderr` | Le compteur ne contient jamais de chemin ni de valeur |

## 4. CLI, JSON et CI

| Point | Implémentation (module + ligne) | Test / preuve |
|---|---|---|
| `--no-gitignore` restaure le parcours intégral | [main.py:109–116](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/main.py#L109-L116), [main.py:159–168](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/main.py#L159-L168) | [test_cli_scan.py:638–678](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L638-L678) |
| Mode arbre : option propagée, compteur rendu | [scan.py:180–217](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L180-L217), [scan.py:557–584](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L557-L584) | [test_cli_scan.py:681–697](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L681-L697) |
| `--staged` : aucune exclusion de chemin | [scan.py:601–624](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L601-L624) | [test_cli_scan.py:741–757](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L741-L757) | `.env` ignoré mais `git add -f` → Finding avec ou sans `--no-gitignore` |
| Champ JSON `git_ignored` et schéma | [scan.py:742–770](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L742-L770), [scan.schema.json:88–92](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/schemas/scan.schema.json#L88-L92) | [test_cli_scan.py:1930–1998](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L1930-L1998) |
| Texte et résumé `--ci` : exclusion toujours visible | [scan.py:818–830](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L818-L830), [main.py:178–191](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/main.py#L178-L191) | [test_cli_scan.py:659–665](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L659-L665) |
| `--ci` refuse un arbre sans aucun contenu lu | [scan.py:565–573](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L565-L573) | [test_cli_scan.py:718–738](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L718-L738) | Code 2, jamais un faux « propre » |
| Binaire ignoré : skip sans code 2 ; sans exclusion : refus | [detect.py:616–621](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/scanner/detect.py#L616-L621), [scan.py:693–703](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/heimdall/cli/scan.py#L693-L703) | [test_cli_scan.py:700–715](https://github.com/Cezar277/heimdall/blob/02bdc2db82aa9559b0042655d1c74dfcaed88e54/tests/test_cli_scan.py#L700-L715) |

## 5. Documentation livrée

- [docs/scanner.md](scanner.md) : périmètre #59, sémantique suivi/non suivi,
  confinement Git, compteur et limites.
- [docs/cli.md](cli.md) : `--no-gitignore`, champs JSON `git_ignored`, mode
  `--staged` sans exclusion et garde `--ci`.
- [docs/security/requirements.md](security/requirements.md) : REQ-SEC-07 mis à
  jour avec la règle « aucun nom n'exclut » et l'exception Git sûre.
- [README.md](../README.md) : `heimdall/scanner/gitignore.py` ajouté à la
  structure.

## 6. Résultats locaux

Environnement : Linux, Python 3.14.6 (`.venv` du dépôt), 31 octobre 2026.

```text
.venv/bin/python -m pytest tests/test_scanner_gitignore.py
46 passed

.venv/bin/python -m pytest tests/test_scanner_gitignore.py tests/test_cli_scan.py
192 passed

.venv/bin/python -m pytest
2523 passed, 15 skipped, 4480 subtests passed

.venv/bin/python -m pytest tests/test_scanner_gitignore.py \
  --cov=heimdall.scanner.gitignore --cov-branch --cov-report=term-missing
heimdall/scanner/gitignore.py : 96 %

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall                    # Success: no issues found in 46 source files
.venv/bin/bandit -r heimdall -q            # code retour 0, aucun rapport
```

Les 46 tests de `test_scanner_gitignore.py` couvrent chaque catégorie du
ticket, les cas de sûreté (suivi, non ignoré, négation, imbriqué, lien),
les pannes Git, les bornes (deadline, timeout, sortie) et la remise à zéro du
compteur. Les tests CLI prouvent le JSON, le texte, `--ci`, `--staged` et
`--no-gitignore`.

## 7. Limites assumées

- Le mode arbre ne couvre pas l'**historique** : un secret déjà commité n'est
  pas re-détecté par un scan d'arbre. `--staged` couvre ce que le commit va
  contenir, pas les commits passés.
- Une entrée non suivie et ignorée n'est **pas lue** : un secret qui y serait
  présent ne produit aucun Finding. C'est l'exclusion demandée par le ticket,
  et elle ne peut pas cacher un secret commité : `git add -f` rend le fichier
  suivi, donc scanné. Les binaires ignorés sont écartés avant décodage ; les
  binaires suivis ou non ignorés restent fail-closed (code 2).
- Les exclusions **globales** de la machine ne sont pas honorées
  (`.git/info/exclude`, `core.excludesFile`, `~/.config/git/ignore`) : elles
  rendraient le verdict dépendant du poste. Pour les appliquer, les recopier
  dans un `.gitignore` du dépôt.
- Le snapshot Git est pris **avant** le parcours. Une modification
  concurrente de l'index (par exemple `git add -f` pendant le scan) n'est pas
  détectée par le mode arbre ; c'est le périmètre `--staged` qui fait foi pour
  le contenu réellement commité.
- Un répertoire ignoré élagué compte pour **une** entrée dans `git_ignored`,
  pas pour le nombre de fichiers qu'il contient.
- Sans Git, le scanner lit **plus** (tout l'arbre) : le verdict reste
  fail-closed sur les binaires et les fichiers illisibles, mais aucune
  exclusion `.gitignore` n'est appliquée.

## 8. Relecture et PR

- Branche : `59-t223-exclusions-de-fichiers`.
- PR à ouvrir avec `Closes #59` et `Refs #22`.
- La CI `CI (/ci)` et une relecture par un membre d'un autre domaine restent
  requises avant fusion.
- Commentaire de ticket à publier : `Temps: 1h30` et lien de la PR.
- Après fusion, re-pincer cette fiche sur le SHA de `main` avec
  `scripts/repin_samm.py --fiche docs/t59-samm.md --sha <sha-final>` puis
  vérifier avec `--check`.
- Aucun secret réel, même expiré, n'est présent dans le code ou les tests :
  les valeurs sont synthétiques (`AKIAIOSFODNN7EXAMPLE` pour AWS).
