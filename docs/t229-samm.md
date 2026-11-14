# T229 — Preuves du correctif fail-closed après revue

Ticket #229, audit E-01. Révision de code actuelle : `7eda6e2bffdebcb7499568e5e816a98a9b2ac974`.
Base de la branche : `6bbe7da` (intégration de #228 / #240).
Les premiers permaliens ci-dessous conservent le SHA du correctif critique
`aba5eb3`. Les durcissements complémentaires sont épinglés séparément sur
leurs révisions respectives, sans modifier la propriété de verdict démontrée.

## Propriété démontrée

Une exclusion visible ne prouve pas l'absence de secret. Le premier état de
la PR autorisait un code 0 avec un rapport partiel : cette propriété était
insuffisante et a été corrigée après REQUEST CHANGES.

Les commandes `scan` et `deep-scan` appliquent désormais le même verdict,
avec ou sans `--ci`, et sans nécessiter `--strict` :

- findings présents : code 1, même si le rapport est partiel ;
- aucun finding et aucune exclusion de contenu : code 0 ;
- aucun finding et rapport partiel : code 2 ;
- erreur d'outillage ou refus strict : code 2.

La combinaison code 0 / `complete: false` est interdite. Le rapport reste
disponible pour le diagnostic, mais un pipeline ou un hook ne lisant que
le code de sortie reste bloqué. Cette garantie ne signifie pas « aucun secret
manqué » : les limites algorithmiques et les périmètres Git restent documentés.

## Preuves permanentes

| Remarque de revue | Implémentation et témoin |
| --- | --- |
| CRITICAL : exclusion devenue verdict propre | [`main.py:229`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/cli/main.py#L229) et [`main.py:306`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/cli/main.py#L306) : calcul du verdict dans la garde d'erreurs. [`test_scanner_fail_closed.py:64`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L64) : 28 combinaisons adverses sur arbre, index, diff et historique, jamais de code 0. |
| HIGH : NUL, jeton long, jointure multiligne | Même témoin : secret préfixé de NUL, noyé sans séparateur dans un jeton >4096, ou coupé sur une jointure >4096. Les portions non analysées rendent le rapport incomplet et le code 2. Aucun blanchiment de contenu n'autorise un verdict propre. |
| HIGH : bruit de contrôle | [`exclusions.py:227`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/scanner/exclusions.py#L227) : plus de filtre de ratio imprimable sur le texte UTF-8 sans BOM ou le repli CP1252. Le témoin CI vérifie un finding et le code 1 malgré le bruit, sur les quatre périmètres. |
| MEDIUM : budget volumétrique | [`detect.py:571`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/scanner/detect.py#L571), [`detect.py:878`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/scanner/detect.py#L878) et [`scan.py:724`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/cli/scan.py#L724) : les tailles des fichiers/blobs trop gros sont comptées avant de les écarter, sans lecture de contenu. [`test_scanner_fail_closed.py:144`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L144) et [:153](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L153) : deux fichiers dépassant chacun 1 Mio épuisent le budget, lecture de blobs interdite. |
| MEDIUM : coût du prétraitement | [`policy.py:35`](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/heimdall/scanner/policy.py#L35) : parcours par ligne, pas de recomptage des préfixes, taille UTF-8 calculée une fois par ligne. [:178](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L178) : environ 1 Mio de jetons longs, travail borné et traces conservées ; [:192](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L192) : ligne exacte d'un jeton situé après plusieurs lignes. |
| LOW : défauts incohérents | `Scanner`, `scan`, `find_candidates`, `collect` et `collect_history` sont stricts par défaut. La tolérance exige `strict=False`. [:103](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L103) vérifie les cinq API sur un contenu adverse. La CLI collecte explicitement les traces avant d'appliquer le verdict sûr. |
| Pas de régression sur les findings et les hooks | [:120](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L120) : partialité + finding = code 1. [:91](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L91) et [:169](https://github.com/Cezar277/heimdall/blob/aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe/tests/test_scanner_fail_closed.py#L169) : liens et rapports partiels hors CI restent en code 2. |

## Durcissements complémentaires après approbation avec commentaires

| Remarque | Correction et preuve permanente |
| --- | --- |
| Cold start : deux compteurs de couverture | [`main.py:276`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/heimdall/cli/main.py#L276) contrôle `skipped_files` et `scan.complete`. [`cold_start.py:204`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/heimdall/cli/cold_start.py#L204) rend aussi le JSON externe incomplet. [`test_scanner_fail_closed.py:202`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/tests/test_scanner_fail_closed.py#L202) simule une couverture interne incomplète et un collecteur historique vide : code 2 et `complete: false`. |
| Helpers privés stricts | Les quatre helpers `_collect_tree`, `_scan_changes`, `_collect_staged`, `_collect_diff` ont désormais `strict=True` par défaut. [`test_scanner_fail_closed.py:219`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/tests/test_scanner_fail_closed.py#L219) les appelle directement sans option sur un contenu adverse ; tous refusent. |
| Volume historique | [`history.py:219`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/heimdall/cli/history.py#L219) consomme la taille annoncée avant le test d'exclusion, sur chaque défaut de cache. `bytes_scanned` conserve son sens d'octets effectivement lus. [`test_scanner_fail_closed.py:242`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/tests/test_scanner_fail_closed.py#L242) : deux blobs distincts trop gros épuisent le budget sans être lus. |
| Borne des traces staged/diff | [`scan.py:683`](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/heimdall/cli/scan.py#L683) borne le collecteur à `MAX_STAGED_FINDINGS`, avant usage puis après chaque ajout binaire, taille ou préparation de texte. Les témoins [:262](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/tests/test_scanner_fail_closed.py#L262) et [:276](https://github.com/Cezar277/heimdall/blob/2f60301ec4427899a41fb3f45be21727050a49d7/tests/test_scanner_fail_closed.py#L276) couvrent ces trois chemins et un collecteur initial déjà hors borne. |

## Décodeur, traces d'arbre, racines et contrat JSON

Révision : `624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f`.

- [`exclusions.py:227`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/heimdall/scanner/exclusions.py#L227) : `decode_text` est strict par défaut. Tous les appels de production indiquent leur mode ; l'appel implicite du cold start a été rendu explicitement tolérant pour conserver sa relecture Latin-1. Les témoins [:295](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L295) et [`test_cold_start.py:84`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_cold_start.py#L84) vérifient le refus par défaut et la qualification conservée sur le contexte non UTF-8.
- [`detect.py:579`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/heimdall/scanner/detect.py#L579) : les ajouts de `prepare_text` respectent `_max_files`, avec annulation des ajouts du fichier courant en cas de dépassement. [:302](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L302) abaisse la borne à deux traces et vérifie le refus du deuxième fichier à deux traces, sans débordement résiduel, sur les deux modes de parcours.
- [`interface.py:64`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/heimdall/scanner/interface.py#L64) refuse `os.fspath(root)` vide avant conversion en `Path`. [`main.py:54`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/heimdall/cli/main.py#L54) refuse aussi l'argument CLI vide avant normalisation. Les témoins [:323](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L323) et [:346](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L346) couvrent les chaînes, les `PathLike` vides et les trois commandes.
- Le point de revue `collect(Path(""))` nécessite une précision : `Path("") == Path(".")` et `os.fspath(Path("")) == "."`. Il est impossible de distinguer ces valeurs après construction. Le répertoire courant explicite reste valide ; [:335](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L335) fixe cette sémantique, sans prétendre retrouver la chaîne initiale.
- [`scan.schema.json:15`](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/schemas/scan.schema.json#L15) documente l'absence de `complete` comme `true`, de `skipped_count` comme `0` et de `skipped` comme `[]`, avec les annotations `default`. [:355](https://github.com/Cezar277/heimdall/blob/624f8d74b2cb1c34eb5e28e6ed73ece17ea8db1f/tests/test_scanner_fail_closed.py#L355) valide les rapports complets et partiels et l'interprétation de la valeur absente.

## Comptage, repli sans perte et verdict humain

Révision : `7eda6e2bffdebcb7499568e5e816a98a9b2ac974`.

- [`main.py:231`](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/heimdall/cli/main.py#L231) affiche le nombre de traces et celui des fichiers distincts. Le témoin [`test_scanner_fail_closed.py:386`](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/tests/test_scanner_fail_closed.py#L386) vérifie deux traces pour un fichier, `skipped_count == 1` et le résumé stderr.
- [`exclusions.py:269`](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/heimdall/scanner/exclusions.py#L269) décode CP1252 sans remplacement. Les cinq octets non définis rendent le contenu non analysable : trace `binary`, couverture partielle, jamais un verdict propre. Le témoin [:379](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/tests/test_scanner_fail_closed.py#L379) couvre les cinq octets ; la charge `cp1252_split` de [:59](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/tests/test_scanner_fail_closed.py#L59) vérifie le code 2 sur arbre, index, diff et historique. La propriété n'est pas la reconstruction d'un secret altéré.
- [`scan.py:1052`](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/heimdall/cli/scan.py#L1052) termine le rapport partiel sans finding par « ANALYSE PARTIELLE : ne pas déployer (code 2). » Le témoin [:396](https://github.com/Cezar277/heimdall/blob/7eda6e2bffdebcb7499568e5e816a98a9b2ac974/tests/test_scanner_fail_closed.py#L396) vérifie la dernière ligne et le code réel.

## Validation

Le correctif critique avait été validé par **3925 tests**, 18 ignorés et
6911 sous-tests sur `aba5eb3`. La nouvelle passe ciblée incluant les dix cas
de défense en profondeur passe : **366 tests**, en 17,92 secondes.
Ruff, MyPy (57 fichiers) et Bandit passent sur `2f60301`.
La suite complète est relancée après ce dernier commit de code et passe :
**3935 passed, 18 skipped, 6911 subtests passed**, en **336,29 secondes**.
Les 14 avertissements existants concernent les tests de sauvegardes de
remédiation. Aucun code ni test n'a changé après ce rejeu ; seuls les
documents de preuve ont été mis à jour ensuite pour cette révision `2f60301`.

La passe ciblée du durcissement précédent `624f8d7` passe : **309 tests**, en
6,56 secondes, avec treize nouveaux cas. Ruff, MyPy et Bandit passent. La
suite complète, rejouée après ce dernier commit de code, passe : **3948 tests,
6911 sous-tests, 18 ignorés**, sans échec ni erreur, en **336,212 secondes**
(rapport JUnit). Aucun code ni test n'a changé après ce rejeu.

Transcription : [acceptance/t229-validation.txt](acceptance/t229-validation.txt).
Rapport JUnit de `624f8d7` : `/home/nathan/heimdall-t229-decoder-root-final.xml`.
La révision `7eda6e2` passe la sélection ciblée : **294 tests en 15,11 s**,
dont onze nouveaux cas. Le rejeu complet après le commit de code passe :
**3959 tests, 6911 sous-tests, 18 ignorés**, en **339,68 s**. Les 14
avertissements existants concernent les sauvegardes de remédiation.
Ruff, MyPy (57 fichiers) et Bandit passent ; Bandit conserve ses avertissements
de lecture des anciens commentaires `nosec`, sans alerte de sécurité.
Rapport JUnit final : `/home/nathan/heimdall-t229-report-decoding-final.xml`.
Aucun code ni test n'a changé après ce rejeu ; seuls les documents de preuve
ont été mis à jour.
Les anciennes passes archivées correspondent à l'état initial de la PR et
ne constituent pas une preuve de cette correction fail-closed.

Environnement : Debian WSL, Python 3.13, dépendances de l'environnement
existant. La CI aux versions verrouillées n'a pas été déclenchée.

## Limites

Les contenus exclus ne sont pas déclarés exempts de secrets. Ils bloquent
le verdict propre. Les binaires ne sont pas décompressés ou OCRisés, les
liens ne sont pas suivis, les portions hors borne ne sont pas déclarées
analysées. Les exclusions Git/VCS restent celles du périmètre documenté.
Voir [la politique utilisateur](scanner-tolerance.md).

Après une fusion squash, re-pinner avec
`python scripts/repin_samm.py --sha <SHA> --fiche docs/t229-samm.md`, puis
vérifier avec `python scripts/repin_samm.py --check --fiche docs/t229-samm.md`.
