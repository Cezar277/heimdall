# T228 — Hook pre-commit : preuves de correction de l'audit

Ticket : #228, constats C-01 / M-01 / F-17 / F-19.

Révision du code : `1531698c40872ace1be06de1c17925cc8e8fd6a5`.
Cette fiche est ajoutée dans un commit de documentation séparé.

## Menace et garanties

STRIDE : altération du périmètre analysé et élévation de privilèges par
contournement du contrôle des secrets. Git peut fournir au hook un index
temporaire différent de `.git/index`. Ignorer cet index produisait un
verdict sur des blobs qui n'étaient pas ceux du commit. Une variable
`HEIMDALL_IN_HOOK=1` héritée produisait aussi une sortie réussie sans scan.

| Constat | Correction et preuve permanente |
| --- | --- |
| C-01 : index effectif | [`gitdiff.py:382`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/heimdall/mcp/gitdiff.py#L382) : validation dans le Git dir du worktree courant, fichier régulier sans lien, nom autorisé ; [`gitdiff.py:418`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/heimdall/mcp/gitdiff.py#L418) : propagation aux commandes Git après revalidation ; [`scan.py:751`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/heimdall/cli/scan.py#L751) : sélection uniquement dans le scan staged. |
| C-01 : preuve réelle | [`test_hook_commit_index.py:45`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_hook_commit_index.py#L45) : vrais commits `-a`, chemin explicite, `-p`, `--amend -a`, `--only`, `--include`, secrets bloqués puis commits propres acceptés. |
| C-01 : confinement et configuration | [`test_hook_commit_index.py:66`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_hook_commit_index.py#L66) : index absolu/relatif utilisé pour scan, diff et `ls-files` ; [`test_hook_commit_index.py:93`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_hook_commit_index.py#L93) : index invalides refusés ; [`test_hook_commit_index.py:166`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_hook_commit_index.py#L166) : garde de configuration sur le même index. |
| M-01 : récursion | [`hook.py:402`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/heimdall/cli/hook.py#L402) : variable héritée refusée en code 2, quelle que soit sa valeur ; [`test_cli_hook.py:854`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_cli_hook.py#L854) : vrai commit avec variable externe bloqué. |
| F-17 : modification de configuration | [`test_hook_commit_index.py:151`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/tests/test_hook_commit_index.py#L151) : `hook install --no-allowlist` conserve le blocage des secrets et permet un commit de configuration propre. Le processus de revue est décrit dans [hook.md](hook.md#modifier-la-configuration-avec-revue). |
| F-19 : Git système | [`gitdiff.py:197`](https://github.com/Cezar277/heimdall/blob/1531698c40872ace1be06de1c17925cc8e8fd6a5/heimdall/mcp/gitdiff.py#L197) : chemins système Homebrew/Nix ajoutés sans hériter du PATH ; garde de refus des binaires sous dépôt/cwd conservée. |

Les tests utilisent la fixture synthétique déjà présente dans le dépôt.
Le diff du scan et ses messages n'affichent pas les secrets ; `git commit -p`
affiche lui-même son patch interactif, indépendamment de Heimdall.

## Validation locale

Environnement : Debian sous WSL, Python 3.13, environnement de test isolé
hors du dépôt. Les dépendances de l'environnement existant ont été réutilisées ;
la résolution complète des versions verrouillées reste à effectuer en CI.

```sh
python -m pytest tests/test_hook_commit_index.py tests/test_cli_hook.py \
  tests/security/test_prompt_injection.py -o addopts= -q
# 126 passed
python -m ruff check heimdall tests scripts
python -m mypy heimdall
python -m bandit -q -r heimdall/cli/hook.py heimdall/cli/scan.py heimdall/mcp/gitdiff.py
```

Ruff, MyPy (56 fichiers) et Bandit : succès.

Passe de régression élargie :

```sh
python -m pytest tests/test_cli_scan.py tests/test_cli_scan_diff.py \
  tests/test_mcp_read_diff.py tests/test_mcp_hardening.py tests/test_mcp_units.py \
  tests/test_hook_commit_index.py tests/test_cli_hook.py \
  tests/security/test_prompt_injection.py -o addopts= -q
# 545 passed, 750 subtests passed in 93.42s
python -m pytest tests/security/test_samm_permalinks.py -o addopts= -q
# 12 passed
python scripts/repin_samm.py --check --fiche docs/t228-samm.md
# succès
```

La première passe complète a donné `3833 passed, 18 skipped, 6911 subtests
passed` avec un unique échec de la garde AST qui interdisait la nouvelle
lecture de `GIT_INDEX_FILE`. Cette garde a ensuite été corrigée avec une
exception limitée à cette seule clé et un témoin négatif pour les autres
lectures. Le rejeu du cas échoué passe (`1 passed`), ainsi que les 545 tests
de la passe élargie finale, qui inclut les tests ajoutés après le lancement
de la suite complète. La suite complète n'a pas été relancée intégralement.

Les rapports JUnit locaux sont conservés hors dépôt dans l'environnement
WSL : `/home/nathan/heimdall-t228-full.xml`,
`/home/nathan/heimdall-t228-replay.xml`,
`/home/nathan/heimdall-t228-targeted-final.xml` et
`/home/nathan/heimdall-t228-regressions.xml`.

## Limites

Le hook reste local et désactivable par les options explicites de Git.
La CI déterministe reste la barrière de la branche partagée. Réinstaller
les hooks existants avec `heimdall hook install` pour mettre à jour leur script.
Le mode strict est un chemin de proposition de configuration ; l'approbation
humaine des exclusions en PR reste nécessaire. Les préfixes système Git ont
été vérifiés par tests sous Linux, sans exécution native macOS ou Nix.
Les permaliens du commit local seront accessibles sur GitHub après push.
En cas de squash, re-pinner cette fiche sur le SHA final avec
`scripts/repin_samm.py --sha <SHA> --fiche docs/t228-samm.md`, puis vérifier
avec `--check`.
