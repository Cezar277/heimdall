# T59 — preuves pour la ligne SAMM

Périmètre : ticket #59 « Exclusions de fichiers », sous-ticket de l'épic #22.
Cette fiche fournit les couples **module + ligne**, les tests et les permaliens
du code livré ; elle ne prétend pas modifier une feuille SAMM externe.

Révision du code et des tests : `cae99ece77a4dbdbec8e0da9a2dee56c624bcbec`
(`fix(scanner): rétablit le câblage --no-gitignore et vérifie l'index (#59)`),
au-dessus de
`d8c0eafc9d6adadeda2e5322825c91fc78ce77cd`
(`Fix(scanner): déclaration de _respect_gitignore dans les __slots__`),
de
`81b676b08835664cbc7e3cee0eb0f6667e20e07f`
(`Fix(scanner): restauration du paramètre respect_gitignore écrasé au merge`),
de
`2df4ba113a32459dfac61f13f11a6478c6471234`
(`fix(scanner): résout Git hors des entrées relatives de os.defpath (#59)`),
de
`02bdc2db82aa9559b0042655d1c74dfcaed88e54`
(`test(scanner): couvre les bornes et pannes de l'exclusion Git (#59)`),
de
`d007418d83ea45e1777c0fffe05afc3b5534e19b`
(`fix(scanner): durcit les exclusions Git et couvre les noms techniques (#59)`)
et de la livraison initiale
`ee8871a6830d82c309d98c49b15c4c36f3cf3640`
(`feat(scanner): exclusions Git sûres et observables (#59)`).

Les permaliens de cette fiche épinglent `cae99ec…`, la révision qui contient
le code **et** les tests cités. Le correctif de revue « racine épinglée par
descripteur » est décrit dans [scanner.md](scanner.md) ; les permaliens
ci-dessous restent ceux de la révision `cae99ec…`. Après une fusion par
squash, re-pincer la fiche sur le SHA présent dans `main` :

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
| Respecter `.gitignore` (racine, imbriqué, négations) | [gitignore.py:352–420](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L352-L420), [detect.py:329–397](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L329-L397) | [test_scanner_gitignore.py:340–362](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L340-L362) | `.gitignore` imbriqué appliqué ; `!keep.log` réintègre le fichier |
| `.env` ignoré : aucun Finding dans un fichier exclu | [detect.py:661–666](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L666) | [test_scanner_gitignore.py:102–112](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L102-L112) | `scan() == []`, `git_ignored == 1`, fichier jamais lu |
| `vendor/` ignoré | [gitignore.py:404–419](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L404-L419) | [test_scanner_gitignore.py:115–123](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L115-L123) | Répertoire élagué, compté une entrée |
| `node_modules/` ignoré | [gitignore.py:404–419](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L404-L419) | [test_scanner_gitignore.py:126–134](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L126-L134) | Répertoire élagué, aucun paquet lu |
| Lockfile ignoré | [detect.py:661–666](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L666) | [test_scanner_gitignore.py:137–145](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L137-L145) | `package.lock` écarté par `*.lock`, sans règle nominale |
| Binaire ignoré | [detect.py:661–666](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L666) | [test_scanner_gitignore.py:148–156](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L148-L156) | Écarté **avant** décodage : aucun code 2 |
| Fichier surdimensionné ignoré | [detect.py:661–666](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L666) | [test_scanner_gitignore.py:159–167](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L159-L167) | Jamais ouvert au-delà de la borne |
| Liste configurable par le dépôt, pas par la machine | [gitignore.py:135–155](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L135-L155), [gitignore.py:381–394](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L381-L394) | [test_scanner_gitignore.py:224–264](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L224-L264) | `.git/info/exclude` et `core.excludesFile` **non** honorés |
| Fichier suivi qui matche un motif : toujours scanné | [gitignore.py:404–419](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L404-L419) | [test_scanner_gitignore.py:170–180](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L170-L180) | `git add -f config.py` → Finding `config.py`, `git_ignored == 0` |
| Fichier suivi dans un répertoire ignoré : répertoire non élagué | [gitignore.py:340–349](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L340-L349), [gitignore.py:407–413](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L407-L413) | [test_scanner_gitignore.py:183–200](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L183-L200) | `vendor/keep.py` détecté, `vendor/secret.py` voisin écarté |
| Aucun nom technique n'exclut à lui seul (correctif #165) | [detect.py:643–700](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L643-L700), [detect.py:702–766](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L702-L766) | [test_scanner_gitignore.py:301–326](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L301-L326), [test_cli_scan.py:621–635](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L621-L635) | `vendor/evil.py`, `node_modules/evil.js`, `package-lock.json`, `evil.png`, `dist/evil.txt` non ignorés → tous détectés |
| Le `.gitignore` lui-même reste scanné | [detect.py:643–700](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L643-L700), [detect.py:702–766](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L702-L766) | [test_scanner_gitignore.py:214–221](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L214-L221) | Un secret dans `.gitignore` est signalé |
| Fichier unique explicite : toujours scanné | [detect.py:329–353](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L329-L353) | [test_scanner_gitignore.py:329–337](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L329-L337) | Aucune consultation de `.gitignore` en mode fichier |
| Lien symbolique ignoré : jamais suivi | [detect.py:661–674](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L674) | [test_scanner_gitignore.py:365–382](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L365-L382) | Lien ignoré écarté avant la garde `symlink` |

## 3. Invariants de sécurité et durcissement

| Invariant | Implémentation (module + ligne) | Test / preuve |
|---|---|---|
| Git résolu hors `PATH` hérité, argv figé, sans shell | [gitignore.py:68–71](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L68-L71), [gitignore.py:214–225](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L214-L225) | [test_network_isolation.py:639–643](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_network_isolation.py#L639-L643) : argv exact accepté, aucune variante réseau |
| Git jamais résolu dans un répertoire relatif (`os.defpath` Windows `.;…`) | [gitignore.py:49–65](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L49-L65) | [test_scanner_gitignore.py:488–525](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L488-L525) | Entrée `.` ignorée, résultat non absolu refusé → `None` (parcours complet), jamais un `git` fourni par le dépôt |
| Environnement reconstruit : pas de `GIT_DIR`/config héritée, `fsmonitor` désactivé | [gitignore.py:85–96](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L85-L96), [gitignore.py:135–155](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L135-L155) | [test_scanner_gitignore.py:244–264](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L244-L264) |
| Timeout unitaire, deadline de scan, sortie bornée | [gitignore.py:73–80](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L73-L80), [gitignore.py:158–165](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L158-L165), [gitignore.py:168–186](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L168-L186), [gitignore.py:246–278](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L246-L278) | [test_scanner_gitignore.py:563–588](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L563-L588), [test_scanner_gitignore.py:591–630](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L591-L630) | Deadline franchie → `ScanError` ; timeout, erreur d'attente et sortie hors plafond → Git tué puis parcours complet |
| Panne Git : parcours complet, jamais un skip silencieux | [gitignore.py:203–278](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L203-L278), [gitignore.py:352–420](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L352-L420) | [test_scanner_gitignore.py:267–278](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L267-L278), [test_scanner_gitignore.py:470–485](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L470-L485) | Git absent, binaire cassé, racine relative ou hors dépôt → tout l'arbre est lu |
| Parsing strict de la sortie Git ; forme inattendue → parcours complet | [gitignore.py:281–337](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L281-L337) | [test_scanner_gitignore.py:537–552](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L537-L552) | NUL final, UTF-8, chemin valide, étiquette connue exigés |
| Défense en profondeur : un fichier suivi n'est jamais exclu | [gitignore.py:407–419](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L407-L419) | [test_scanner_gitignore.py:633–656](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L633-L656) | Même une sortie Git incohérente ne peut pas exclure `config.py` |
| Identité de racine re-vérifiée avant/après la collecte Git | [detect.py:329–353](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L329-L353) | [test_scanner_detect.py](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_detect.py) (garde de racine) | Racine substituée → `ScanError`, jamais un verdict sur un autre arbre |
| Second snapshot après parcours : une entrée sautée devenue suivie refuse le scan | [detect.py:362–380](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L362-L380), [gitignore.py:120–133](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/gitignore.py#L120-L133) | [test_scanner_gitignore.py:399–431](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L399-L431) | `git add -f` entre snapshot et parcours → `ScanError`, jamais un 0 silencieux |
| Politique d'exclusion strictement booléenne | [detect.py:233–239](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L233-L239) | [test_scanner_gitignore.py:292–298](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L292-L298) | `"yes"`, `1`, `0`, `None` → `ValueError` à la construction |
| Nombre d'exclusions observable et remis à zéro | [detect.py:315–327](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L315-L327), [detect.py:459–466](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L459-L466) | [test_scanner_gitignore.py:385–396](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_scanner_gitignore.py#L385-L396) | Deux scans successifs ne cumulent pas |
| Aucun secret dans le rapport, les erreurs ou les traces | [scan.py:824–865](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L824-L865) | Tests CLI : la clé AWS synthétique est absente de `stdout`/`stderr` | Le compteur ne contient jamais de chemin ni de valeur |

## 4. CLI, JSON et CI

| Point | Implémentation (module + ligne) | Test / preuve |
|---|---|---|
| `--no-gitignore` restaure le parcours intégral | [main.py:113–120](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/main.py#L113-L120), [main.py:163–172](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/main.py#L163-L172) | [test_cli_scan.py:638–678](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L638-L678) |
| Mode arbre : option propagée, compteur rendu | [scan.py:181–223](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L181-L223), [scan.py:581–617](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L581-L617) | [test_cli_scan.py:681–710](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L681-L710) |
| `--staged` : aucune exclusion de chemin | [scan.py:634–657](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L634-L657) | [test_cli_scan.py:819–835](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L819-L835) | `.env` ignoré mais `git add -f` → Finding avec ou sans `--no-gitignore` |
| Champ JSON `git_ignored` et schéma | [scan.py:775–803](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L775-L803), [scan.schema.json:88–92](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/schemas/scan.schema.json#L88-L92) | [test_cli_scan.py:2008–2076](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L2008-L2076) |
| Texte et résumé `--ci` : exclusion toujours visible | [scan.py:851–863](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L851-L863), [main.py:182–195](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/main.py#L182-L195) | [test_cli_scan.py:659–665](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L659-L665) |
| `--ci` refuse un arbre sans aucun contenu lu | [scan.py:592–604](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L592-L604) | [test_cli_scan.py:726–756](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L726-L756), [test_cli_scan.py:796–816](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L796-L816) | Code 2 pour `git_ignored > 0` comme pour `vcs_ignored > 0`, jamais un faux « propre » |
| Binaire ignoré : skip sans code 2 ; sans exclusion : refus | [detect.py:661–666](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/scanner/detect.py#L661-L666), [scan.py:726–736](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/heimdall/cli/scan.py#L726-L736) | [test_cli_scan.py:778–793](https://github.com/Cezar277/heimdall/blob/5161272829c335f096d1f09cb273a4af7f65660b/tests/test_cli_scan.py#L778-L793) |

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

Environnement : Linux, Python 3.14.6 (`.venv` du dépôt), 1er novembre 2026.

```text
.venv/bin/python -m pytest tests/test_scanner_gitignore.py
49 passed

.venv/bin/python -m pytest tests/test_scanner_gitignore.py tests/test_cli_scan.py
195 passed

.venv/bin/python -m pytest
2526 passed, 15 skipped, 4480 subtests passed

.venv/bin/python -m pytest tests/test_scanner_gitignore.py \
  --cov=heimdall.scanner.gitignore --cov-branch --cov-report=term-missing
heimdall/scanner/gitignore.py : 96 %

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall                    # Success: no issues found in 46 source files
.venv/bin/bandit -r heimdall -q            # code retour 0, aucun rapport
```

Les 49 tests de `test_scanner_gitignore.py` couvrent chaque catégorie du
ticket, les cas de sûreté (suivi, non ignoré, négation, imbriqué, lien),
les pannes Git, les bornes (deadline, timeout, sortie), la résolution sûre du
binaire et la remise à zéro du compteur. Les tests CLI prouvent le JSON, le
texte, `--ci`, `--staged` et `--no-gitignore`.

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
- Le snapshot Git est pris **avant** le parcours, puis **re-vérifié après**
  le parcours : si une entrée sautée n'est plus ignorée (par exemple
  `git add -f` pendant le scan), le scan est refusé (code 2) au lieu de rendre
  un verdict périmé. La fenêtre résiduelle après ce second snapshot reste
  couverte par `--staged`, seul périmètre opposable pour le contenu
  réellement commité.
- La racine du snapshot est épinglée par un descripteur
  `O_DIRECTORY|O_NOFOLLOW` vérifié : Git reçoit `/proc/self/fd/N` (ou
  `/dev/fd/N`) et lit l'inode déjà contrôlé, jamais le chemin re-résolu. Un
  échange `A → B → A` du chemin autour de l'appel Git ne peut donc pas
  substituer `B`. Si l'épinglage échoue alors que la plateforme le permet
  (lien symbolique, droits, course), le parcours est complet, sans repli par
  chemin. Sur une plateforme sans descripteur de répertoire (Windows), le
  repli par chemin conserve la double vérification `lstat` et la précondition
  « racine et index figés pendant le scan » documentée dans
  [scanner.md](scanner.md).
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
