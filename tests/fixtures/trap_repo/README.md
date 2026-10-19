# Corpus d'acceptation T21

Tickets #21, #49, #50, #51, #52. Oracle indépendant du scanner T22 :
[`expected.json`](expected.json) fige les positions **indexées à partir de 1**,
les types et les attentes avant son implémentation.

## Cas

- 10 leaks synthétiques : AWS, Stripe, JWT, PAT GitHub et PEM, en Python et JS.
- 18 non-leaks : UUID, SHA-256, hash de commit, intégrité de lockfile,
  `example`, `changeme`, `your_key_here`, image GIF base64 et mocks dans `tests/`.
- 6 leaks obfusqués : base64, concaténation et reconstruction depuis deux
  variables, dans les deux langages. Attente `limite_connue` : le scanner de
  signatures ne promet ni décodage ni analyse du flux des variables. La ligne
  de référence est celle qui contient la valeur encodée ou l'assemblage final.

`type` décrit la famille de la vérité terrain (aws, stripe, jwt, pat, pem),
sans imposer ces noms aux types du scanner : le contrat T14 autorise aussi
des catégories génériques. La comparaison demandée par #52 porte uniquement
sur `(file, line)`, jamais sur la valeur ou le type. Chaque Finding réel est
validé contre le schéma T14 avant mesure.

## Sécurité et génération

Seuls les gabarits `.tmpl` et les métadonnées sont versionnés. Les jetons
sont assemblés par `tests/support/trap_corpus.py` dans `tmp_path` / un dossier
temporaire système, jamais dans ce dépôt. Les charges sont déterministes et
étiquetées dans le générateur comme factices : aucun fournisseur n'est appelé,
le JWT a une signature invalide et est expiré, le PEM n'est pas un DER valide.
Les fichiers produits sont du texte de test, jamais exécuté.
Le générateur refuse les gabarits symlinks et les chemins source résolus hors
fixtures ; les chemins de sortie résolus doivent rester sous le dossier temporaire.

La CI T20 exécute pytest et n'a actuellement pas de scanner de secrets sur le
dépôt. Il n'y a donc **aucune exclusion globale à ajouter** pour ces gabarits.
Lors du branchement de T22 à la CI, exclure explicitement ce seul dossier
`tests/fixtures/trap_repo/` du scan du dépôt si nécessaire. Cette exclusion
ne doit jamais s'appliquer au corpus temporaire scanné par l'acceptation.
Ne pas ignorer globalement `tests/` : ses mocks font partie des non-leaks.

## Exécution

Après l'installation vérifiée décrite dans le README racine :

```sh
python -m pytest tests/test_trap_acceptance.py -s -rx
python tests/measure_trap.py
```

Sous Windows, utiliser `.venv/Scripts/python.exe`.

Le script retourne 0 si les seuils sont atteints, 1 si précision ou rappel
principal < 0,90, et 2 si T22 n'est pas livré ou si la mesure échoue (scan,
validation Finding, disque, création/nettoyage du dossier temporaire).
L'import des dépendances est aussi couvert : dépendance absente => code 2.
Le code 1 est réservé aux seuils. La frontière CLI affiche un message fixe
sans traceback ni contenu d'exception ; les erreurs restent propagées par
`scan_corpus` pour ses autres appelants. Aucun scan incomplet ne devient propre.

Le test d'intégration est un `xfail` limité à `NotImplementedError` tant que
T22 est un squelette. Une sortie vide, une autre exception, un Finding invalide
ou des métriques sous le seuil sont de vrais échecs. Dès que T22 passe, pytest
signale XPASS : retirer alors le marqueur. Aucun chiffre de performance du
scanner n'est annoncé tant qu'il n'est pas implémenté.

## Métriques

VP = positions positives trouvées ; FP = positions signalées sans leak ;
FN = positions positives manquées. Les doublons de détection à une même
position ne gonflent pas les scores, et toute alerte hors oracle compte comme
FP. Précision = VP/(VP+FP), rappel = VP/(VP+FN). Un dénominateur nul donne 0,
afin de ne pas annoncer une qualité parfaite sans observations.

Le rapport `core` applique le seuil de 0,90 hors **positions obfusquées**.
Le rapport `all` inclut leurs FN, et `known_limits_missed` les détaille.
Les fichiers contenant une obfuscation ne sont pas exclus en entier : une
fausse alerte ailleurs dans ces fichiers reste comptée. Détecter une ancienne
limite améliore le total sans faire échouer les tests.

Les tests unitaires utilisent un petit exemple calculé à la main : VP=1,
FP=2, FN=1, précision=1/3 et rappel=1/2. Ce sont des preuves du calcul,
**pas des résultats du scanner**. Les tests vérifient aussi la reproductibilité,
les positions, la syntaxe Python et la propagation des erreurs.
