# T38 — complément #108, #109 et #110

## État constaté avant modification

Le clone neuf de `38-t38-cold-start-et-deep-scan-de-l-historique` part de
`7894235`. Seul #107 est implémenté ; [t38-samm.md](t38-samm.md) limite
explicitement ses preuves à T38.1. Ce complément apporte le code et les
preuves locales des trois autres sous-tickets. Les validations humaines et
la CI distante ne sont pas déclarées acquises.

## Preuves par exigence — état initial du complément

| Ticket / menace | Implémentation | Vérification |
| --- | --- | --- |
| #108 : secret supprimé toujours accessible | `heimdall/cli/history.py`, `collect_history`, ligne 95 ; snapshots de toutes les références figées, pagination par lots | `test_deleted_secret_deduplicates_all_snapshots`, branches/tags/HEAD détaché, merges, renommages, SHA-256 |
| #108 : doublons | `HistoricalFinding`, ligne 36 ; regroupement type/HMAC avec liste unique des commits | 2 puis 4 snapshots d'un même secret : un finding, tous les commits conservés ; test d'éviction LRU |
| #109 : consommation mémoire / disponibilité | `history.py`, budgets lignes 22–30 ; lecture bornée, cache des résultats, exécution séquentielle ; `scanner/detect.py`, `_read_text` | Gros blob refusé avant lecture ; limites commits, entrées, octets, résultats, occurrences et délai ; charge 504 999 entrées |
| #109 : exclusion de taille explicite | `cold_start.py`, `ColdStartReport.skipped_files` ; `history.py`, `HistoryReport.complete` ; CLI `--max-file-bytes` | JSON `complete: false`, chemin ignoré visible, code 2 pour cold-start et historique |
| #108 : altération du périmètre / exécution de contenu | `history.py`, `_tips` et `_entries` ; `mcp/gitdiff.py`, environnement confiné | Clone superficiel refusé ; chemins malformés refusés ; symlinks et gitlinks non suivis ; replace et graft ne cachent pas un secret |
| #110 : secret déjà compromis | `history.py`, `render_history`, ligne 235 | Alerte « compromis, à révoquer et remplacer » avec commits ; absence de valeur brute dans les sorties |
| #110 : mesure reproductible | `scripts/bench_history.py`, `scripts/bench_history_fixture.py` et `bench-results/t38-*.json` | Temps, mémoire maximale et résultat conservés ci-dessous |
| LLM consultatif, sans pouvoir en CI | Réutilisation de `qualify_target` et T33, contexte intégralement masqué avant sélection | Aucun appel en CI, dédoublonnage des appels, rejet affiché et journalisé sans supprimer le finding |

Ce tableau décrit le premier complément (`64ccb9b`). Le mapping corrigé et
les liens permanents actuels sont dans [t38-samm.md](t38-samm.md).
La PR #193 couvre désormais explicitement tout T38 (#107–#110), conformément
à la demande utilisateur ; son périmètre initial #107 seul est remplacé.

La branche de livraison `32-t32-diff-interactif-yne` (PR #192) intègre ce
même ensemble T38 par fusion des commits ci-dessus : code, tests et preuves
sont identiques, sans réécriture ni nouveau snapshot. Les mesures ci-dessous
restent celles des commits d'origine.

## Mesures du 26 octobre 2026

Machine : AMD Ryzen 7 9800X3D (8 cœurs / 16 threads), WSL2 Debian,
Linux 6.6.87.2, 15 Gio disponibles dans WSL, Python 3.13.5.
Les scans sont déterministes (`ci=True`), sans Ollama ni appel réseau.
Les clones publics complets sont téléchargés avant le chronométrage.
Les mesures sont exécutées sur le système de fichiers Linux, avec d'autres
contrôles locaux en parallèle ; elles ne constituent pas un benchmark isolé.
Le RSS est celui du processus Python ; celui des enfants est enregistré
séparément dans les JSON (ce n'est pas la somme des processus).

| Dépôt / périmètre | Temps | RSS Python maximal | Résultat |
| --- | ---: | ---: | --- |
| Fixture reproductible : 5 000 commits, 504 999 entrées d'arbre | 36,343 s | 77,51 Mio | Complet, 78 925 octets effectivement lus grâce au cache, 1 finding synthétique, aucune exclusion |
| `pallets/flask`, clone complet, 5 603 commits accessibles | 39,876 s | 96,04 Mio | Refus de sécurité du moteur déterministe ; aucun verdict propre ni temps de scan complet revendiqué |
| `pallets/click`, clone complet, 3 384 commits accessibles | 66,229 s | 113,63 Mio | Refus de sécurité du moteur déterministe ; aucun verdict propre ni temps de scan complet revendiqué |

Révisions HEAD mesurées : Flask `d086db856be187255b8ec61ef409357393020f32`,
Click `2247b35ea1c47c727d7a06e51fa280e12a863ff6`.
Les références distantes et tags sont également inclus dans ces clones.
La fixture contient uniquement la clé d'exemple publique AWS
`AKIAIOSFODNN7EXAMPLE`, supprimée au dernier commit ; elle reste détectée
dans les 4 999 commits précédents. Aucun secret réel n'est utilisé.

Flask atteint notamment le refus conservateur de jointure multiligne dans
`entropy_detection.check_multiline_overflow`. La mesure Click ne classe pas
la cause exacte au-delà du refus de sécurité. Les garde-fous du scanner
existant ne sont pas assouplis pour obtenir artificiellement un scan complet.
Cette limite reste applicable aux dépôts contenant des entrées que le moteur
ne sait pas analyser ; la CLI rend alors 2.

Reproduction sous Linux, depuis la racine du projet :

```console
python -m scripts.bench_history_fixture /tmp/t38-new-synthetic
python -m scripts.bench_history /tmp/t38-new-synthetic
git clone https://github.com/pallets/flask.git /tmp/t38-new-flask
python -m scripts.bench_history /tmp/t38-new-flask
```

Le script de mesure imprime seulement les métadonnées et compteurs. Un refus
produit `status: refused`, `complete: false` et des compteurs inconnus à `null`.
La fixture est volumineuse en historique et en entrées, avec peu d'octets
uniques : elle vérifie surtout la pagination, le cache et les associations.

## Validation locale

Environnement : Python 3.13.5, environnement de développement existant
`/home/nathan/heimdall-t33-venv`, imports du clone neuf. Les tests LLM sont
simulés ; aucun serveur Ollama n'est contacté par les tests ciblés.

| Contrôle | Résultat |
| --- | --- |
| `python -m pytest tests/test_history.py tests/test_cold_start.py --cov=heimdall.cli.history --cov=heimdall.cli.cold_start --cov-branch --cov-report=term-missing --cov-fail-under=85` | **43 passed**, couverture **95,25 %** |
| `ruff check heimdall tests scripts` | Succès |
| `ruff format --check` sur les huit fichiers Python nouveaux ou modifiés hors environnement Git | Succès |
| `mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py` | **48 fichiers**, aucune erreur |
| `bandit -r heimdall -q` | Succès |
| `python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85` | **2254 passed**, **16 skipped**, **4480 subtests passed**, 7 avertissements ; couverture **91,47 %**, **243,75 s** |

Journaux conservés dans `bench-results/t38-targeted-tests.txt` et
`bench-results/t38-full-tests.txt`. La régression complète finale utilise
un fichier de couverture distinct pour éviter toute interférence avec
les contrôles ciblés exécutés séparément.

La CI distante, la relecture croisée et la fermeture des tickets ne sont
pas effectuées par cette livraison locale.

## Correction de revue — 26 octobre 2026

Code et tests : `78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe`.

- Repli binaire aligné sur `Scanner._decode_data` : le suffixe technique
  exige aussi un binaire connu. Les données indécodables inconnues sont refusées.
- `_entries` transforme noms non UTF-8 et chemins invalides en `ScanError`
  statique ; aucun `ValueError` ou `UnicodeDecodeError` brut n'est revendiqué
  comme contrat de parsing.
- `max_file_bytes` est validé avant tout accès et appliqué à la relecture.
- Les références sont comparées aux SHA de départ avant le verdict. Un commit
  concurrent observé produit une erreur ; ce contrôle ne verrouille pas Git
  et ne couvre pas une écriture après sa dernière observation.
- Les titres, périmètres et preuves de la PR sont alignés sur #107–#110.

Tests ciblés : **54 passed**, couverture **95,40 %**, journal
`bench-results/t38-review-targeted-tests.txt` ; Ruff, Mypy strict
(48 fichiers) et Bandit passent. Format des quatre fichiers Python corrigés
vérifié avec Ruff ; `git diff --check` passe.

Régression complète après correction : **2265 passed**, **16 skipped**,
**4480 subtests passed**, 7 avertissements, couverture **91,51 %**, durée
**247,31 s**. Journal : `bench-results/t38-review-full-tests.txt`.
Les deux fichiers de couverture sont distincts. Aucun `/ci` ni déclenchement
manuel de CI distante n'est effectué.

## Complément de revue LOW — 26 octobre 2026

Commit : `7000236ef4e584d3b6604a206da65f95db07c606`.
Un décodeur commun valide les SHA des références, de HEAD et de `rev-list` :
`UnicodeDecodeError` et `ToolFailure` de validation deviennent une `ScanError`
au message statique « historique non analysable ». La CLI conserve son code 2.
Le texte affiche au plus dix SHA par finding puis le nombre restant ; le JSON
conserve toutes les associations.

Six nouveaux cas couvrent les trois sources avec un octet non ASCII ou un
SHA ASCII invalide, en API et en CLI. Six autres couvrent l'affichage de
10, 11 et 10 000 commits en SHA-1 et SHA-256, avec une sortie texte de moins
de 1200 octets pour le finding testé et un JSON exhaustif.

Validation : **66 passed**, couverture ciblée **95,54 %** ; Ruff, Mypy strict
(48 fichiers) et Bandit passent. Journal : `bench-results/t38-low-targeted-tests.txt`.
Le mapping SAMM dispose de liens permanents vers ce code et ces tests.
La suite complète n'est pas relancée pour ce complément limité au décodage
des identifiants et au rendu ; son dernier résultat archivé ci-dessus reste
**2265 passed**, couverture **91,51 %**, pour le correctif précédent.
Aucun `/ci` n'est envoyé.

## Complément d'audit : fichiers, erreurs, journal et liens

Code et tests : `359155d191fd758431594addbff0a6870213f1d8`.

Les constats sont regroupés par type/HMAC/fichier. Chaque fichier reste visible
en texte et en JSON, avec ses commits, y compris pour les blobs identiques
et pour les deux noms d'un fichier renommé. Le modèle reste qualifié une seule
fois par type/valeur ; son avis ne retire aucun emplacement.

Les trois collecteurs publics convertissent les pannes Git en `ScanError`
statique. `collect` valide également `max_file_bytes` avant le moteur, en arbre
comme en index. Le benchmark n'a plus besoin de catcher `ToolFailure`.
Les erreurs du journal restent des `JournalError`, distinctes des pannes Git.
`collect_history` accepte et propage `journal=...` ; les tests de faux positif
utilisent un journal temporaire, et le test CI vérifie qu'il n'est pas créé.

La divergence des symlinks est confirmée et corrigée : un blob de mode
`120000` est lu via `cat-file` et scanné comme en `--staged`, sans accès au
chemin de la cible ni suivi du lien sur disque. Les gitlinks `160000` restent
exclus. Cette décision remplace l'exclusion des blobs de liens des premières
versions décrites dans les tableaux historiques ci-dessus.

Validation ciblée : **93 passed**, couverture **95,69 %**, journal
`bench-results/t38-audit-targeted-tests.txt`. Ruff, Mypy strict (48 fichiers)
et Bandit passent. Les nouveaux tests vérifient les deux fichiers après
suppression, les deux formes de blobs, les pannes Git des trois API, les
limites invalides, la taille de blob négative, le journal injecté et le blob
de lien supprimé, comparé au scan staged.

Régression complète après ce complément : **2304 passed**, **16 skipped**,
**4480 subtests passed**, 7 avertissements, couverture **91,54 %**,
durée **247,93 s**. Journal : `bench-results/t38-audit-full-tests.txt`.
Le format des cinq fichiers Python modifiés et `git diff --check` passent.
Aucune CI distante n'est lancée. Le SHA de merge devra être renseigné après une fusion
effective ; cette correction ne fusionne pas la PR.

## Complément LOW : HEAD explicite et décodage de relecture

Code et tests : `1de5b13dc9790d9836cf27778e2cccdfe03d75e9`.
La lecture `rev-parse --verify HEAD` reçoit désormais explicitement
`--no-replace-objects`, en complément de `GIT_NO_REPLACE_OBJECTS=1` dans
l'environnement confiné. Les tests de HEAD non ASCII/invalide vérifient cette option.
Un `ScanError` de décodage pendant la relecture du cold start est converti
en `ScanError` au message exact « contenu modifié depuis le scan déterministe ».
Le cas de mutation vers des octets indécodables teste le vrai décodeur,
le contrat bibliothèque et le refus CLI en code 2.

**94 tests ciblés passent**, couverture **95,72 %** ; journal
`bench-results/t38-head-decode-tests.txt`. Ruff, format des quatre fichiers
Python corrigés, Mypy strict (48 fichiers), Bandit et `git diff --check` passent.
La suite complète n'est pas relancée pour ces deux correctifs locaux ; le
dernier résultat global reste **2304 passed**, **91,54 %**, avant ce complément.
Les permaliens SAMM sont actualisés pour ces deux exigences. Aucun `/ci`
n'est envoyé et aucun SHA de merge n'est inventé avant fusion.

## Complément LOW : environnement Git et mtime à la lecture

Code et tests : `9a757e6d06e00d40d9832b193ac7a694286e88ce`.
`ConfinedEnvironmentTests.test_minimal_and_redirection_free` exige maintenant
`GIT_NO_REPLACE_OBJECTS=1` et `GIT_GRAFT_FILE=os.devnull`. La suppression de
chaque clé par un patch en mémoire fait échouer ce test comme attendu,
sans altération de la configuration réelle. Résultats dans
`bench-results/t38-env-mutation-check.txt`.

`_read_worktree_file` compare après lecture la taille et `mtime_ns` aux
métadonnées initiales du descripteur, en plus de la longueur effectivement lue.
Une modification de même taille avec changement de mtime renvoie `None`,
donc le cold start refuse avec son `ScanError` statique / code 2. Le test
réécrit réellement le fichier pendant la relecture et vérifie aussi l'absence
d'appel LLM. Cette garde ne prétend pas verrouiller le fichier entre les
passes ni détecter une altération dont l'auteur restaure les métadonnées.

Validation ciblée : **99 passed**, couverture cold start + historique **95,72 %** ;
journal `bench-results/t38-mtime-targeted-tests.txt`. Ruff, Mypy strict
(48 fichiers), Bandit et format des trois fichiers Python corrigés passent.
Régression complète après ce complément : **2307 passed**, **16 skipped**,
**4480 subtests passed**, 7 avertissements, couverture **91,56 %**, durée
**244,93 s**. Journal : `bench-results/t38-mtime-full-tests.txt`.
Les fichiers de couverture des tests ciblés et de la suite complète sont distincts.

La relecture croisée et la CI verte restent des conditions bloquantes avant
fusion. Le SHA final de merge sera renseigné après fusion effective, avec
vérification des liens permanents. Les cases PR correspondantes restent
décochées tant que leurs preuves externes ne sont pas acquises ; aucune
approbation ni CI n'est déclarée à partir des seuls tests locaux.

## Vérification sur la branche de livraison `32-t32-diff-interactif-yne`

Après fusion de l'ensemble T38 dans cette branche, la suite complète a été
relancée : **2324 passed**, **15 skipped**, **4480 subtests passed**, aucune
couverture recalculée ici. `ruff check heimdall tests scripts`, `mypy` strict
(49 fichiers) et `bandit -r heimdall` passent. Contrôles fonctionnels :
un secret supprimé du code est retrouvé une seule fois avec ses trois commits,
un blob au-delà de `--max-file-bytes` est signalé « taille maximale
dépassée » avec code 2, et l'alerte « considéré compromis, à révoquer et
remplacer » ainsi que le temps de scan sont affichés. Ces vérifications
locales ne valent pas CI verte ni relecture croisée.
