# T233 — Corrections après approbation avec commentaires

Ticket #233. Branche : `fix/233-vault-cli-remediation-hardening`.
Base revue : `8d9298d`. Code testé : `440ae9ee2b4143bc23466613bba717567fddd2d9`.

## Propriétés démontrées

| Remarque | Code et preuve |
| --- | --- |
| Options contradictoires | [`fix.py:147`](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/heimdall/cli/fix.py#L147) refuse `config_path` avec `no_allowlist` par `ScanError` avant accès au dépôt. La [garde CLI](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/heimdall/cli/fix.py#L298) rend un message statique et le code 2, sans appeler `run_fix`. Les [quatre cas CLI](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/tests/test_issue233_hardening.py#L66) couvrent CI/local et JSON/texte, et vérifient contenu, mtime, modes et liste des fichiers inchangés. Le [cas API](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/tests/test_issue233_hardening.py#L93) vérifie l'absence de contrôle du chemin, de collecte et de revue. |
| Noms précédés de `export` | [`fix.py:49`](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/heimdall/cli/fix.py#L49) retire le préfixe exact `export ` ou `export\t` après indentation, puis utilise la validation existante. Les [six cas](https://github.com/Cezar277/heimdall/blob/440ae9ee2b4143bc23466613bba717567fddd2d9/tests/test_issue233_hardening.py#L117) couvrent espace, tabulation, indentation, affectation sans préfixe, identifiant `exportFOO` non tronqué et retour au fallback si le nom est invalide. |

Ces corrections assurent la cohérence de la sélection d'allowlist et des
noms proposés. Elles n'ajoutent aucune exécution shell, aucun accès réseau
et aucune nouvelle dépendance. Les autres durcissements de la branche
restent couverts par `tests/test_issue233_hardening.py` ; cette fiche ne
prétend pas remplacer leur revue complète.

La [documentation de remédiation](remediation-env.md) précise les deux
comportements. La transcription des commandes et résultats est archivée
dans [acceptance/t233-validation.txt](acceptance/t233-validation.txt).

## Validation locale

Environnement : Debian WSL, Python 3.13, environnement Python local existant.
Les versions verrouillées de CI n'ont pas été réinstallées pour cette passe.
`test_issue233_hardening.py` : **185 tests passent en 3,37 s**, dont onze
nouveaux cas. Cinq avertissements existants concernent les sauvegardes de
remédiation. Ruff sur le dépôt, MyPy (57 fichiers) et Bandit sur `fix.py`
passent.

Le rejeu complet sur le commit figé donne **4083 tests et 7124 sous-tests
passés, 18 ignorés, 2 échecs**, en **405,90 s** (19 avertissements existants).
La suite complète n'est donc pas verte :

- `test_env_path_with_spaces_properly_quoted_in_git_rm_command` échoue
  aussi isolément sur la base `8d9298d` dans un checkout séparé. Les modules
  concernés et ce test ne sont pas modifiés par ces deux corrections.
- `test_selected_index_changed_on_the_same_inode_is_refused[content]`
  échoue sur son assertion préalable de changement de `ctime_ns` dans la
  passe complète, puis passe isolément sur le code testé et sur la base.

Le rejeu isolé des deux cas donne 1 passé / 1 échec sur chaque révision.
Ces résultats ne justifient pas de présenter la CI comme verte ni de
modifier ici les gardes Git ou le témoin d'horodatage de #228.
Rapport JUnit : `/home/nathan/heimdall-t233-review-final.xml`.
Aucun code ni test n'a été modifié après le rejeu complet ; seuls les
documents de preuve ont été actualisés.
La CI n'a pas été déclenchée ; aucune fusion n'a été effectuée.

Après une fusion squash, re-pinner avec
`python scripts/repin_samm.py --sha <SHA> --fiche docs/t233-samm.md`, puis
vérifier avec `python scripts/repin_samm.py --check --fiche docs/t233-samm.md`.
