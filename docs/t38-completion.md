# T38 — complément #108, #109 et #110

## État constaté avant modification

Le clone neuf de `38-t38-cold-start-et-deep-scan-de-l-historique` part de
`7894235`. Seul #107 est implémenté ; [t38-samm.md](t38-samm.md) limite
explicitement ses preuves à T38.1. Ce complément apporte le code et les
preuves locales des trois autres sous-tickets. Les validations humaines et
la CI distante ne sont pas déclarées acquises.

## Preuves par exigence

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

Les références module/ligne correspondent à la livraison locale ; les liens
permanents GitHub avec SHA et les PR par sous-ticket restent à établir lors
de la publication et de la relecture.

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
