# T230 — Audit E-02 : détection et allowlist

Ticket #230. Révision corrigée : `a95a1f00a221c1df1dd2af93c8155487db765f1c`.
`main` intégré : `4d5bdf8` (merge local `f2711ce`). Le commit initial
`d50d0f6` contient `Closes #230` ; ses preuves historiques restent ci-dessous.

## Correction après REQUEST CHANGES

- [`signatures/__init__.py:155`](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/heimdall/scanner/signatures/__init__.py#L155) déduplique uniquement `(secret_type, value)`. Le bloc de déduplication inter-types a été supprimé : une vue `credential` n'est plus effacée par une vue de service. Les [deux cas CLI local/CI](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_issue230_scanner_allowlist.py#L297) vérifient les deux vues avant allowlist, une règle limitée à `service_token`, la survie de `credential`, le code 1, une seule trace et l'absence de valeur brute en sortie.
- [`service_tokens.py:21`](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/heimdall/scanner/signatures/service_tokens.py#L21) relève à 16 la charge minimale de `npm_`. [Identifiants ordinaires](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_issue230_scanner_allowlist.py#L326) et frontières 15/16 sont testés. Les noms longs restent une source possible de faux positifs, documentée.
- La [politique](t230-scanner-allowlist.md) explicite les résiduels : jetons nus de 20–22 caractères auxquels manque une des trois classes, affectations non citées de moins de quatre caractères et clé `pin` hors vocabulaire. Des témoins négatifs figent ces limites ; aucune couverture universelle n'est revendiquée.
- [`fix.py:154`](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/heimdall/cli/fix.py#L154) regroupe seulement les remédiations physiques après filtrage typé, par fichier/ligne/empreinte. Le [témoin de double vue](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_issue230_scanner_allowlist.py#L349) applique un seul patch et vérifie le rescan propre. Les résultats du scanner restent distincts par type ; les gardes de racine de #233 sont conservées.
- [`atomic.py:737`](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/heimdall/vault/atomic.py#L737) corrige la découverte de racine depuis un sous-dossier sans élargir le plafond Git : recherche du marqueur le plus proche sur les ancêtres validés, puis `GitAccess` depuis cette racine. [Sous-dossier avec espaces](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_issue230_scanner_allowlist.py#L372) et [marqueur symbolique refusé avant exécution](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_issue230_scanner_allowlist.py#L380) sont couverts. Le test historique `.env` avec espaces passe désormais.
- Le [témoin ctime](https://github.com/Cezar277/heimdall/blob/a95a1f00a221c1df1dd2af93c8155487db765f1c/tests/test_hook_commit_index.py#L255) attend 20 ms avant sa réécriture pour ne pas rester dans le même tick. L'assertion ctime, la restauration du mtime et les gardes d'index de production ne sont pas affaiblies.

## Validation de la correction

Après intégration : **1350 tests ciblés passent en 35,10 s**. Le premier
rejeu global sur `5eee07e` donne **4396 passés, 1 échec, 18 ignorés,
7124 sous-tests passés**, en 380,12 s : l'unique échec est la précondition
ctime du témoin #228. Après stabilisation, les quatre modules ciblés passent :
**440 tests en 22,99 s**, avec les cinq avertissements `.bak` existants.
Ruff, MyPy (69 fichiers) et Bandit passent ; les avertissements de lecture
des anciens commentaires `nosec` restent présents, sans alerte de sécurité.

La validation globale finale utilise le rejeu local
`/home/nathan/heimdall-t230-typed-review-final.xml` et le check **CI (/ci)**
de la [PR #253](https://github.com/Cezar277/heimdall/pull/253), déclenché par
`/ci` après la poussée de la tête corrigée. Lire son statut et sa conclusion
sur la révision courante ; les résultats locaux ne remplacent pas ce check.

## Propriétés initiales — historique `d50d0f6`


| Périmètre | Code et témoins |
| --- | --- |
| Préfixes de services | [`service_tokens.py:9`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/service_tokens.py#L9) ajoute sept préfixes, bornes et exemples vérifiés à l'import. [Inventaire indépendant dans le test](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L246). |
| URL, Authorization, affectations | [`credentials.py:64`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/credentials.py#L64), règles bornées ; [`LiteralRule`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/credentials.py#L51) distingue les valeurs citées des expressions non citées. [Candidats sans valeur brute dans les findings](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L90), [quatre parcours CLI](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L196), [littéraux versus expressions](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L241). |
| Jetons courts | [`entropy_detection.py:35`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/entropy_detection.py#L35) et [:165](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/entropy_detection.py#L165) : correction de seuil configurable pour 20–22 caractères, sous condition minuscules/majuscules/chiffres ; [réglages et refus des valeurs invalides](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L98). |
| Regex quasi universelles | [`allowlist.py:405`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/allowlist.py#L405) calcule le minimum de littéraux obligatoires ; les assertions et atomes/groupes optionnels n'y contribuent pas. Les alternances sont analysées par groupe. [Contournements, y compris bornes zéro avec zéros initiaux](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L134), [marqueurs spécifiques acceptés](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L152), [refus CLI](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L225). La longueur maximale et les gardes anti-ReDoS sont conservées. |
| Globs de chemin | [`allowlist.py:465`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/allowlist.py#L465) : seuls les segments `**` traversent les répertoires, casse explicite et refus des segments de traversée. [Tests directs](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L174) et [configuration valide en CLI : top-level ignoré, nested signalé](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L264). |
| Jointures et contrat d'erreur | [`detect.py:915`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/detect.py#L915) et [`signature_engine.py:150`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signature_engine.py#L150) partagent le résultat de fenêtre avant l'entropie des fragments, sans fabriquer de clé sur une frontière. [Témoin de commentaire adjacent](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L286). [Overflow de compilation](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L258) et [Unicode invalide](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L281) deviennent des `ScanError` statiques. |

## Mesures et limites

Le [corpus E-02](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L76)
contient 75 positifs synthétiques et 15 négatifs : 74 vrais positifs,
1 faux négatif (jeton court) et 1 faux positif (UUID, entropie historique).
Rappel et précision : **98,67 % sur ce seul corpus**.

Le corpus historique T21 et son oracle restent inchangés. Les candidats
`changeme` et mocks à nom sensible augmentent ses faux positifs de 8 à 12 :
`core` TP=10, FP=12, FN=0, précision 45,45 %, rappel 100 % ; `all` TP=12,
FP=12, FN=4, précision 50 %, rappel 75 %. Le script de mesure historique
garde son seuil de 90 % et retourne 1. Aucune exclusion silencieuse n'est
ajoutée pour embellir ces résultats.

La propriété prouvée est l'élargissement des formats et le refus des
contournements d'allowlist couverts, pas « aucun secret manqué ». Les
heuristiques et bornes sont décrites dans
[t230-scanner-allowlist.md](t230-scanner-allowlist.md). Aucun nouveau réseau,
shell, chiffrement ou paquet externe ; les fixtures sont synthétiques.

## Validation initiale — historique `d50d0f6`

Les six modules ciblés passent : **776 tests en 13,81 s**. Sur le commit
figé, les commandes de contrôle de la CI passent localement : Ruff,
MyPy (66 fichiers) et Bandit (aucune alerte, avertissements `nosec`
existants). Le rejeu complet après le commit de code passe : **4056 tests,
7125 sous-tests, 18 ignorés**, en **361,50 s**. Les 14 avertissements
existants concernent les sauvegardes de remédiation. Aucun code ni test
n'a changé après ce rejeu ; seuls les documents de preuve ont été actualisés.
Rapport JUnit : `/home/nathan/heimdall-t230-final.xml`.

Environnement : Debian WSL, Python 3.13, dépendances locales existantes ;
aucune revendication d'exécution native Windows/macOS. La CI n'a pas été
déclenchée et aucune fusion n'a été effectuée.
Transcription : [acceptance/t230-validation.txt](acceptance/t230-validation.txt).

Après une fusion squash, re-pinner avec
`python scripts/repin_samm.py --sha <SHA> --fiche docs/t230-samm.md`, puis
vérifier avec `python scripts/repin_samm.py --check --fiche docs/t230-samm.md`.
