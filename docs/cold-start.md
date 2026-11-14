# Cold start et historique (T38)

## Entonnoir (#107)

```console
heimdall cold-start .
heimdall cold-start . --no-llm --json
heimdall cold-start . --ci --json
```

Le premier scan d'un dépôt existant passe par le scanner déterministe complet
(regex, entropie, allowlist et ses garde-fous). Seuls les findings résultants
sont qualifiés par Ollama local : cinq lignes de contexte de chaque côté,
128 caractères au plus par ligne après masquage, moins de 2000 caractères
par appel. Les lignes portant des candidats sont entièrement masquées.
Le fichier est relu sans suivre de lien et les candidats sont revérifiés
avant la qualification. Aucun fichier entier n'est envoyé au modèle.
La relecture refuse aussi une modification de taille ou de `mtime_ns`
entre les deux `fstat` du descripteur, y compris une réécriture de même taille.
Cette garde est celle de la lecture, pas un verrou du fichier entre les passes ;
le re-scan d'appartenance reste appliqué aux candidats.

Un avis `faux_positif` est une proposition, affichée et journalisée via T33.
Il ne retire jamais un finding et ne change pas le code de sortie : 0 propre,
1 candidats présents, 2 erreur d'outillage. Un modèle indisponible conserve
le candidat. `--ci` interdit le modèle et son journal, même avec `--llm`.
Le dépôt reste en lecture seule ; le journal éventuel est un état opérateur
hors dépôt. Le mode LLM est plafonné à 256 candidats (au-delà : code 2).

La phase de qualification dispose d'une échéance globale de **300 secondes**,
vérifiée entre fichiers et avant/après chaque candidat, y compris dans un même
fichier. Le re-scan reçoit cette échéance. Un appel Ollama déjà en cours garde
le timeout réseau de T28 (**60 secondes**) : l'échéance peut donc être dépassée
par cet appel, mais aucun candidat suivant ne démarre après expiration.
Le dépassement produit une erreur d'outillage (code 2), jamais un rapport propre.

L'identité de la racine est figée avant la première passe, puis revérifiée
entre les passes, avant les relectures et en fin de qualification. Une substitution
de la racine est refusée même avec un contenu identique. Une garde de chemin
échouée devient une `ScanError` au message statique pour les appelants bibliothèque.
Le re-scan est volontairement sans allowlist : c'est un sur-ensemble ; seuls les
findings conservés par la première passe doivent y figurer. Les deux moteurs
partagent la configuration d'entropie par défaut et la même clé HMAC locale.

Preuves et mapping SAMM : [t38-samm.md](t38-samm.md).

Tests : `python -m pytest tests/test_cold_start.py`.
Sous Windows, si Git n'est pas dans `os.defpath`, le produit refuse de prendre
un exécutable dans le PATH hérité. Pour les tests de cette machine uniquement :

```powershell
.venv\Scripts\python.exe -c "import os,pytest; os.defpath += os.pathsep + r'C:\Program Files\Git\cmd'; raise SystemExit(pytest.main(['tests/test_cold_start.py','-q']))"
```

Ce réglage désigne l'installation système de Git, jamais un binaire du dépôt.

## Historique complet (#108)

```console
heimdall deep-scan .
heimdall deep-scan . --ci --json
heimdall deep-scan . --no-llm --max-file-bytes 524288
heimdall cold-start . --ci --max-file-bytes 524288
```

`cold-start` analyse les fichiers actuels ; `deep-scan` analyse les snapshots
de tous les commits accessibles depuis les branches, tags et HEAD détaché.
Exécuter les deux pour vérifier le présent et le passé. Les références sont
figées au début et relues avant le verdict : une divergence produit une
`ScanError` statique et un code 2. Cette vérification compare les ensembles de
SHA observés aux deux instants ; ce n'est pas un verrou des références. Une
écriture après la vérification finale nécessite de relancer le scan.
La seconde passe du cold start ne relit que les fichiers porteurs de findings,
mais l'état Git du worktree (fichiers suivis et non suivis) est comparé avant
et après : un fichier propre modifié entre les passes provoque `ScanError`.
Pour un verdict opposable, figer le dépôt (checkout CI, worktree dédié) ou
relancer le cold start.
Les commits sont énumérés par lots de 128 ; un seul arbre et
un seul blob sont lus à la fois. Cette variante de `rev-list` puis lecture
des snapshots permet aussi d'associer les commits où le secret reste inchangé
et de couvrir les merges, renommages et fichiers supprimés.

Un même triplet type/empreinte HMAC/fichier produit un finding, avec la liste
des commits qui contiennent cette valeur dans ce fichier. Les copies dans deux
fichiers, même si elles partagent le même blob Git, restent deux findings.
Un renommage conserve donc les deux noms avec leurs commits respectifs.
La ligne du finding est représentative dans le fichier ; il ne s'agit pas
d'une liste de toutes les lignes de chaque snapshot. La qualification LLM
reste dédoublonnée par type/valeur et ne supprime aucun emplacement.
Le rendu texte affiche au plus dix SHA par finding, puis `… (+N)` pour les
commits supplémentaires. `--json` conserve la liste complète des commits.
Les erreurs de décodage ASCII et de validation des SHA lus depuis les
références, HEAD et `rev-list` deviennent une `ScanError` statique.
Les sept champs Finding v1 restent inchangés ; les commits et l'alerte sont
dans l'enveloppe JSON `heimdall.history.v1`. L'allowlist du présent n'est pas
appliquée au passé : elle ne peut pas masquer rétroactivement un secret.
Le LLM voit uniquement un contexte masqué des candidats distincts ; ses avis
restent consultatifs, affichés et journalisés via T33. `--ci` désactive tout
appel et toute journalisation LLM, y compris avec `--llm`.

Le scan ne fait aucun checkout, fetch, filtre textconv ou réécriture.
Les variables Git héritées, les remplacements et les grafts locaux sont
neutralisés. Les symlinks ne sont jamais suivis sur le disque : leur blob Git
`120000`, qui contient le texte de leur cible, est scanné comme en `--staged`.
Les commits de sous-modules (`160000`) sont exclus. Les binaires et contenus
hors borne sont désormais signalés dans `skipped` avec leur chemin et leur
commit, et rendent `complete: false` (#229). `deep-scan --strict` les refuse.
Sans `--strict`, un rapport historique partiel produit 1 si un candidat est
détecté, 2 sinon ; il ne produit jamais 0. L'API `collect_history` reste
stricte par défaut ; `strict=False` est un choix explicite de collecte.
`cold-start` est tolérant par défaut ; `cold-start --strict` refuse les
contenus exclus (code 2) dès la collecte. Sans `--strict`, un rapport
partiel est refusé par le code 2, jamais présenté comme propre.
Les objets absents, clones superficiels, sorties invalides et dépassements
de budget restent des erreurs d'outillage. Voir la
[politique de tolérance](scanner-tolerance.md).

Les commits devenus
inaccessibles (objets pendants, reflogs seuls) et les dépôts de sous-modules
ne font pas partie de ce périmètre.

Le nom du fichier n'autorise aucune exclusion : le contenu et ses limites
décident du traitement, avec des traces ou un refus en mode strict. Le parseur d'arbres convertit aussi les noms non UTF-8
et chemins invalides en `ScanError` statique.

`complete=True` signifie complet dans ce périmètre : aucun binaire ou blob
indécodable ne peut produire un rapport propre. Les fichiers trop volumineux
sont signalés dans `skipped`, avec `complete=False` et un code de sortie 2.

## Taille, lots et mémoire (#109)

`--max-file-bytes` est configurable entre 1 octet et **1 Mio**, valeur par défaut,
pour `cold-start` et `deep-scan`. La taille du blob est vérifiée avant sa lecture.
Un fichier trop volumineux est signalé avec son chemin échappé et, en historique,
son commit. Le JSON indique `complete: false` et la CLI sort en **2**, même si
des secrets ont aussi été détectés. Un fichier ignoré ne vaut pas scan propre.
Le contrat normal de `heimdall scan` conserve son refus immédiat sur fichier
trop volumineux.

Le traitement est séquentiel : un seul processus Git à la fois, aucun pool
non borné. Un cache LRU conserve au plus 4096 objets et 10 000 findings,
uniquement les résultats hachés, jamais les contenus bruts. Les autres budgets
du deep scan sont : 100 000 commits, 1 000 000 entrées d'arbre cumulées,
256 Mio de blobs effectivement lus, 10 000 constats type/valeur/fichier,
1 000 000 associations constat/commit et 10 000 exclusions de taille.
Chaque arbre Git est plafonné à 8 Mio avant parsing ; chaque lecture de blob
reste plafonnée à 1 Mio. Au-delà : code 2, aucun rapport tronqué présenté comme complet.

La deadline globale est de 300 s, transmise au moteur et aux commandes Git
(au plus 30 s chacune, réduites au temps restant). En mode LLM, la limite de
256 qualifications reste applicable et une requête Ollama déjà commencée
conserve son timeout T28, comme pour `cold-start`.

Les API `collect`, `collect_cold_start` et `collect_history` convertissent
les pannes Git (`ToolFailure`) en `ScanError` statique. `collect` valide aussi
la limite de taille explicite avant de déléguer au scanner, y compris avec
`staged=True`. Les erreurs propres au journal conservent leur type `JournalError`.

En bibliothèque, `collect_history(..., journal=RejectionJournal(chemin))`
permet de rediriger le journal des propositions de rejet, comme le cold start.
Sans journal injecté, le chemin opérateur par défaut reste utilisé hors CI.
`ci=True` interdit aussi toute écriture dans le journal injecté.

Hors CI avec LLM activé (par défaut), les propositions `faux_positif` sont
journalisées et synchronisées sur disque au chemin opérateur par défaut,
même sans journal injecté. `--ci` ou `--no-llm` désactive ce journal pour
`cold-start` et `deep-scan` ; ces options ne désactivent pas la détection.
L'aide des deux commandes mentionne cette écriture. L'API `qualify_target`
accepte aussi `ci=True` et le transmet à `qualify_finding`, sans appel au
modèle ni écriture journal, même lorsqu'elle est appelée directement.

Dans l'API `collect`, les options `max_file_bytes` et `skipped_files` sont
réservées au mode arbre : les fournir avec `staged=True` est refusé avant
tout accès Git (`ScanError("limite de fichier invalide")`). Le mode staged
conserve sa limite de taille fixe. `collect_cold_start` et `collect_history`
n'exposent pas de paramètre `staged`.

## Alerte et temps (#110)

Chaque finding historique affiche : « Secret trouvé dans l'historique
(commits …) : considéré compromis, à révoquer et remplacer. » Retirer le
secret du code ne suffit pas. Révoquer le secret chez son fournisseur,
le remplacer et examiner les accès ; une éventuelle réécriture de l'historique
reste une décision humaine coordonnée avec l'équipe.

Le rapport inclut `elapsed_seconds`, `commits_scanned`, `entries_scanned` et
`bytes_scanned`. Les temps et pics mémoire mesurés sont consignés dans
[t38-completion.md](t38-completion.md), avec les refus de sécurité rencontrés.

Tests complets de ce périmètre :

```console
python -m pytest tests/test_history.py tests/test_cold_start.py
```
