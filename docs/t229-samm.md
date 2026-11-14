# T229 — Preuves du correctif fail-closed après revue

Ticket #229, audit E-01. Révision de code : `aba5eb3047d2b9f0cfcee552050fc1e2c9b67cbe`.
Base de la branche : `6bbe7da` (intégration de #228 / #240).

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

## Validation

Les 47 cas adverses et les tests associés du scanner passent dans une
passe ciblée de **708 tests**. Ruff, MyPy (57 fichiers) et Bandit passent.
La suite complète a été relancée après le dernier commit de code ci-dessus :
**3925 passed, 18 skipped, 6911 subtests passed**, en **336,74 secondes**.
Les 14 avertissements proviennent des tests existants de sauvegardes de
remédiation. Aucun changement de code ou de test n'a suivi ce rejeu ; seule
la documentation des résultats et des preuves est actualisée ensuite.

Transcription : [acceptance/t229-validation.txt](acceptance/t229-validation.txt).
Rapport JUnit final : `/home/nathan/heimdall-t229-review-full.xml`.
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
