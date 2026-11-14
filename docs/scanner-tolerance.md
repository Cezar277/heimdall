# Tolérance du scanner — audit E-01 (#229)

`heimdall scan` et `heimdall deep-scan` tolèrent désormais les contenus
qui empêchaient auparavant toute analyse du dépôt. Les erreurs de lecture,
les objets incohérents, les conflits d'index, les racines invalides et les
dépassements des budgets globaux restent des erreurs d'outillage (code 2).
Cette tolérance permet de rendre les résultats et les traces ; elle ne
permet jamais un verdict propre sur un rapport partiel, en CI comme hors CI.

```sh
heimdall scan --ci --no-allowlist .
heimdall scan --staged --json .
heimdall scan --ci --diff main --no-allowlist --json .
heimdall scan --strict --ci --no-allowlist .
heimdall deep-scan --ci --strict .
```

## Politique de contenu

| Contenu | Mode par défaut | Mode `--strict` |
| --- | --- | --- |
| Texte UTF-8, UTF-16 ou UTF-32 | analysé, avec ou sans BOM lorsque l'heuristique est applicable | analysé avec les gardes de décodage historiques |
| Texte Latin-1 / CP1252 | repli CP1252 sans remplacement ; octets non définis : exclusion `binary`, rapport partiel ; candidats ASCII préservés avec du bruit décodable | UTF-8 invalide refusé |
| Binaire connu ou contenu sans décodage textuel plausible | ignoré, trace `binary` | code 2 |
| Fichier/blob > 1 Mio (ou plafond explicitement abaissé) | ignoré sans lire son contenu, trace `too_large` | code 2 |
| Lien rencontré dans l'arbre de travail | jamais suivi, trace `symlink` | code 2 |
| Jeton lexical > 4096 caractères | jeton découpé en fenêtres chevauchantes de 4096 caractères (chevauchement 2048 : toute sous-chaîne ≤ 2048 est entière dans une fenêtre), trace `long_token` avec sa ligne ; au-delà de 2048, une signature concaténée sans frontière peut encore échapper aux motifs | code 2 |
| Jointure de deux lignes > 4096 octets UTF-8 | lignes analysées séparément, trace `multiline_limit` | refus conservateur historique si la jointure pourrait porter un candidat |

Le suffixe ne décide jamais de l'exclusion : un texte Latin-1 portant un
secret dans `image.png` reste analysé. Les textes UTF-16/32 sont essayés
avant de classer comme binaire un contenu contenant des NUL. Une signature
de format suivie de texte ne suffit pas à ignorer ce texte si le décodage
reste plausible. Aucun contenu n'est exécuté.

Les racines et leurs ancêtres symboliques restent refusés. Les symlinks
internes sont écartés avant toute résolution ou ouverture de leur cible.
Dans l'index ou l'historique, le blob Git d'un lien contient son nom de
cible : ce texte peut être analysé sans suivre le lien sur le disque.

## Rapport et codes de sortie

Les exclusions sont distinctes des rejets d'allowlist et des exclusions Git.
Le rapport humain annonce **Analyse partielle** et liste les chemins relatifs,
les motifs et, pour les limites de texte, les lignes concernées. Les chemins
sont échappés à l'affichage. Aucun extrait de contenu ou secret n'est ajouté.

Le JSON `heimdall.scan.v1` émet toujours `complete: true/false`,
`skipped_count` (nombre de fichiers distincts) et `skipped`, tableau
d'objets `{file, reason, line}` (vide sans exclusion). Un consommateur doit
vérifier la couverture en plus des findings : `count == 0` seul ne signifie
jamais « propre ». Pour le producteur actuel, exiger `complete is True`
et aucun finding ; vérifier aussi le code de sortie en CLI.
Depuis #229, le schéma exige `complete` : un document sans ce champ est
invalide. Si `complete` vaut `false`, `skipped` doit être non vide et
`skipped_count` au moins 1 ; un rapport partiel sans trace est refusé par
le schéma. Les `default` restent des annotations, pas des valeurs insérées
automatiquement.
L'historique utilise ses champs existants `complete` et `skipped`, avec
un chemin, un commit, un motif et une `line` pour chaque occurrence, y compris
après réutilisation du cache de blobs sous un autre chemin. `line` est le
numéro de ligne pour `long_token` / `multiline_limit`, sinon `null`.
Dans l'API bibliothèque, chaque entrée `HistoryReport.skipped` est désormais
un tuple `(file, commit, reason, line)` ; les consommateurs doivent intégrer
ce quatrième élément. Le JSON ajoute le champ `line` et le rendu humain
l'affiche après le chemin quand il est connu.

- `0` : aucun candidat détecté et aucune exclusion de contenu.
- `1` : au moins un candidat détecté, même si d'autres contenus ont été écartés.
- `2` : erreur d'outillage, refus strict, ou rapport partiel sans candidat détecté.

La combinaison `complete: false` et code 0 est interdite, y compris sans
`--ci` : les hooks et automatismes existants restent bloqués. Les binaires,
archives, portions de texte hors borne et cibles de liens ne sont pas
couverts. Les traces sont informatives ; leur lecture n'est jamais nécessaire
pour empêcher un pipeline vert sur une analyse partielle. `--strict` permet
de refuser dès la rencontre du contenu concerné, plutôt que de poursuivre
les autres fichiers. `--no-allowlist` ne désactive pas cette garde.

Un texte UTF-8 sans BOM ou décodé par le repli CP1252 est analysé sans seuil
de caractères imprimables : ajouter du bruit non imprimable autour d'un
candidat ASCII ne le transforme pas en exclusion. Les décodages avec BOM
et le choix UTF-16/32 conservent leurs gardes ; un rejet rend le rapport
incomplet et ne permet jamais un code 0.
Les tailles annoncées des gros fichiers et blobs exclus consomment aussi
les budgets globaux de l'arbre et de l'index, sans lecture de leur contenu.
L'historique compte lui aussi la taille de chaque blob absent du cache,
même s'il est exclu ; `bytes_scanned` reste le compteur des octets lus.
Le rapport historique expose aussi `bytes_budgeted` : somme des tailles
annoncées imputées à `MAX_READ_BYTES` sur chaque défaut de cache, exclusions
comprises. Ces deux compteurs figurent dans le JSON, le texte et l'API
`HistoryReport`. Par exemple, deux blobs distincts exclus de 100 octets et
un texte lu de 5 octets donnent `bytes_scanned: 5`, `bytes_budgeted: 205`.
Comparer `bytes_budgeted` au plafond de volume, et non `bytes_scanned`.
Un blob réutilisé depuis le cache n'est pas à nouveau imputé ; une relecture
après éviction l'est. `bytes_budgeted` est un champ ajouté au contrat
`heimdall.history.v1` ; les anciens rapports peuvent ne pas le contenir.
Les traces d'exclusion de l'index et du diff sont plafonnées à
`MAX_STAGED_FINDINGS`, y compris avec un collecteur déjà rempli.
Dans les trois périmètres (arbre, index, diff), `scanned_files` compte les
fichiers entièrement analysés : un fichier portant une ou plusieurs traces
de contenu n'est pas compté. Dans l'API arbre, `Scanner.files_scanned`
applique la même règle, y compris avec `long_token` / `multiline_limit`.

Un jeton lexical de plus de 4096 caractères est découpé en fenêtres
chevauchantes de 4096 caractères avant analyse : l'intérieur n'est plus
blanchi en bloc. Le chevauchement de moitié garantit qu'une sous-chaîne de
longueur ≤ 2048 est entièrement contenue dans une fenêtre. Au-delà, une
signature concaténée sans frontière peut encore échapper aux motifs ; le mode
tolérant conserve alors la trace `long_token` et déclare le rapport partiel
(code 2 sans autre finding). Le mode strict le refuse. Le schéma impose
`complete` et refuse un rapport partiel sans `skipped` : un consommateur ne
peut donc pas traiter `count == 0` seul comme propre.

## Bibliothèque et autres commandes

Le résumé stderr distingue le nombre de traces d'exclusion et le nombre
de fichiers concernés. Le JSON `skipped_count` compte les fichiers distincts ;
`len(skipped)` compte les traces (un fichier peut en porter plusieurs).
Un rapport humain partiel sans conclusion se termine par
« ANALYSE PARTIELLE : ne pas déployer (code 2). »

Les octets CP1252 non définis (`81`, `8D`, `8F`, `90`, `9D` en hexadécimal)
ne sont jamais remplacés par U+FFFD. Même insérés dans un candidat ASCII,
ils entraînent une exclusion `binary` tracée et empêchent le verdict propre.
Il ne s'agit pas de reconstruire un secret corrompu : le contenu est déclaré
non analysable, avec code 2 sans autre conclusion (ou 1 avec conclusions).

`Scanner(root)`, `scan(root)`, `find_candidates(root)`, `collect(...)` et
`collect_history(...)` sont stricts par défaut, ainsi que les helpers privés
de collecte, d'analyse des blobs et `decode_text`. La tolérance doit être
demandée explicitement par `strict=False` ; un appelant doit alors exploiter
le rapport de couverture (`scanner.skipped` / `report.complete`). La CLI
demande explicitement cette collecte pour rendre les traces puis applique
la garde de code de sortie ci-dessus. Le moteur de signatures et les
primitives d'entropie restent également stricts par défaut.

Le cold start conserve son contrat de rapport incomplet : son collecteur
`skipped_files` inclut les exclusions rencontrées et sa CLI retourne 2 si
ce collecteur n'est pas vide ou si son rapport de scan interne est incomplet,
même avec un collecteur historique vide. Le JSON externe reste cohérent
avec cette couverture. La seconde passe locale applique le même prétraitement
tolérant que la première et conserve les findings analysables ainsi que leur
qualification. Un finding accompagné d'un jeton long reste un rapport partiel :
le cold start conserve son code 2 d'incomplétude, sans prétendre que le contenu
a été modifié. Les vérifications de racine et de présence des findings restent
actives.
Les traces de cette seconde passe sont comparées à celles de la première :
une exclusion nouvelle ou déplacée provoque `ScanError` (« contenu modifié
depuis le scan déterministe ») avant qualification, avec code 2 en CLI.
Un rapport initialement complet ne peut ainsi rester complet après l'ajout
d'un jeton long ou d'une nouvelle jointure hors borne entre les passes.
`deep-scan` rend son rapport et retourne 2
s'il est partiel sans finding, ou 1 si un finding est présent. Le prétraitement
des jetons traite chaque ligne une fois et calcule sa taille UTF-8 une fois ;
aucun préfixe du fichier n'est recompté pour chaque jeton.
Les traces ajoutées par le prétraitement de l'arbre respectent aussi
`max_files` : en cas de dépassement, les ajouts du fichier courant sont
annulés et le scan refuse sans rendre de résultat réussi.

Les arguments CLI vides et les chaînes/objets `PathLike` dont `os.fspath`
est vide sont refusés avant conversion en `Path`. `Path("")` vaut déjà
`Path(".")`, et `os.fspath(Path(""))` vaut `"."` : aucune API ne peut
retrouver la chaîne d'origine. Cette valeur normalisée reste une demande
valide d'analyser le répertoire courant, comme `Path(".")` ; elle n'est
pas présentée comme une racine vide détectable après coup.

## Vérification sur Heimdall

`heimdall scan --ci --no-allowlist .` termine désormais sans erreur
d'outillage sur `docs/security/dfd.png`. Le code 1 reste attendu sur ce
dépôt : les fixtures synthétiques et les empreintes de fichiers du projet
produisent des candidats quand toute allowlist est désactivée. Cette
vérification ne signifie ni que ces candidats sont des secrets réels, ni
que le dépôt est déclaré propre.

Les tests de `tests/test_scanner_tolerance.py` couvrent les trois périmètres,
les encodages, les binaires connus/inconnus, les gros fichiers non lus, les
jetons longs avec un candidat distinct sur la même ligne, les symlinks
sans suivi, les rapports JSON et le cache historique.
