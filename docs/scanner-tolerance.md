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
| Texte Latin-1 / CP1252 | repli CP1252, remplacement des octets non définis ; candidats ASCII préservés même avec du bruit de contrôle | UTF-8 invalide refusé |
| Binaire connu ou contenu sans décodage textuel plausible | ignoré, trace `binary` | code 2 |
| Fichier/blob > 1 Mio (ou plafond explicitement abaissé) | ignoré sans lire son contenu, trace `too_large` | code 2 |
| Lien rencontré dans l'arbre de travail | jamais suivi, trace `symlink` | code 2 |
| Jeton lexical > 4096 caractères | jeton remplacé par des espaces pour l'analyse, trace `long_token` avec sa ligne ; les autres candidats restent analysés | code 2 |
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

Quand du contenu est écarté, le JSON `heimdall.scan.v1` ajoute les champs
optionnels `complete: false`, `skipped_count` (nombre de fichiers distincts)
et `skipped`, tableau d'objets `{file, reason, line}`. Le schéma versionné
accepte ces champs. Les rapports sans exclusion gardent leur forme précédente.
Pour ces rapports v1, l'absence de `complete` signifie `true`, l'absence
de `skipped_count` signifie `0` et l'absence de `skipped` signifie `[]`.
Les `default` du schéma sont des annotations : un consommateur JSON applique
ces valeurs, par exemple `payload.get("complete", True)`. Le producteur
émet toujours `complete: false` lorsqu'il existe une exclusion de contenu.
L'historique utilise ses champs existants `complete` et `skipped`, avec
un chemin et un commit pour chaque occurrence, y compris après réutilisation
du cache de blobs.

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
Les traces d'exclusion de l'index et du diff sont plafonnées à
`MAX_STAGED_FINDINGS`, y compris avec un collecteur déjà rempli.

## Bibliothèque et autres commandes

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
avec cette couverture. `deep-scan` rend son rapport et retourne 2
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
