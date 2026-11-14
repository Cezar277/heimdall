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

## Durcissements après revue

Révision de code : `bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a`.
Les preuves ci-dessus restent celles de la livraison initiale ; cette
section couvre les remarques faibles de la revue.

| Remarque | Correction et preuve permanente |
| --- | --- |
| Remédiation sur le mauvais index | [`hook.py:544`](https://github.com/Cezar277/heimdall/blob/bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a/heimdall/cli/hook.py#L544) : refus statique en `HookError` de toute variable `GIT_INDEX_FILE` présente dans les opérations de remédiation. [`test_hook_commit_index.py:196`](https://github.com/Cezar277/heimdall/blob/bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a/tests/test_hook_commit_index.py#L196) : index `index.lock`, `next-index-123.lock`, `index` et variable vide ; refus avant callback ; contenu du worktree et des deux index inchangé. La garde et la primitive interne de ré-indexation sont également testées directement. |
| Identité d'index insuffisante | [`gitdiff.py:421`](https://github.com/Cezar277/heimdall/blob/bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a/heimdall/mcp/gitdiff.py#L421) : comparaison de `st_dev`, `st_ino`, `st_ctime_ns`, `st_mtime_ns` et `st_size` avant chaque commande. [`test_hook_commit_index.py:229`](https://github.com/Cezar277/heimdall/blob/bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a/tests/test_hook_commit_index.py#L229) : réécriture par un autre index Git valide, de même taille, même inode et mtime restauré ; modification de mtime ; changement de taille. Tous sont refusés. |
| Confiance dans les préfixes Git ajoutés | [Conditions de déploiement](hook.md#preuves) : préfixes, parents et cible résolue administrateur-écrits seuls pour une confiance indépendante du compte utilisateur. Cette condition n'est pas un contrôle automatique de permissions. [`test_hook_commit_index.py:265`](https://github.com/Cezar277/heimdall/blob/bbd3e90fbf01fa2508a0f16e0c98c8c8de0bb47a/tests/test_hook_commit_index.py#L265) : Git système prioritaire face à un faux Git dans un préfixe `/usr/local/bin` simulé ; repli vers un lien de ce préfixe pointant dans le dépôt refusé par `GitAccess` et par le hook. |

La remédiation d'un index effectif imposé reste volontairement indisponible
jusqu'à son intégration explicite avec #30/#32. Le scan staged continue à
prendre en charge les index temporaires. Les nouveaux tests de résolution
s'exécutent sous Linux avec des préfixes simulés ; aucune preuve native
macOS/Nix n'est revendiquée.

Validation après revue : même commande de régression élargie que ci-dessus,
`553 passed, 750 subtests passed in 90.16s`. Le témoin de réécriture d'un
index valide avec mtime restauré a été renforcé pendant cette passe puis
rejoué avec les deux autres cas d'identité : `3 passed`. Ruff, MyPy
(56 fichiers), Bandit et la vérification des permaliens passent. Rapport
JUnit local : `/home/nathan/heimdall-t228-review.xml`. La suite complète
n'a pas été rejouée pour ces durcissements.

## Contrôle automatique des préfixes supplémentaires

Révision de code : `da0a649d176349aec40eba70867c6ad18c70417c`.
Cette section remplace l'ancienne limite « exigence de déploiement sans
contrôle automatique » pour les quatre préfixes Git ajoutés.

- [`gitdiff.py:212`](https://github.com/Cezar277/heimdall/blob/da0a649d176349aec40eba70867c6ad18c70417c/heimdall/mcp/gitdiff.py#L212) : `verify_git_prefix` exige `st_uid == 0` sur le binaire, ses parents lexicaux, les liens et leurs cibles résolues avec leurs parents ; les fichiers et répertoires doivent avoir `mode & 0022 == 0`. Les permissions des liens ne remplacent pas le contrôle de leurs parents et cibles. Un fichier absent, illisible ou non régulier est refusé.
- Appel avant toute exécution dans [`GitAccess`, ligne 410](https://github.com/Cezar277/heimdall/blob/da0a649d176349aec40eba70867c6ad18c70417c/heimdall/mcp/gitdiff.py#L410) et dans [`hook.py:145`](https://github.com/Cezar277/heimdall/blob/da0a649d176349aec40eba70867c6ad18c70417c/heimdall/cli/hook.py#L145). Erreurs statiques `ToolFailure(INTERNAL)` / `HookError`, traduites en code 2 par la CLI, sans reflet du chemin.
- [`test_hook_commit_index.py:320`](https://github.com/Cezar277/heimdall/blob/da0a649d176349aec40eba70867c6ad18c70417c/tests/test_hook_commit_index.py#L320) : dix cas simulant un déploiement protégé, puis propriétaire non root sur le lien, le préfixe, son parent, la cible ou son parent ; écriture groupe/autres ; cible absente. Chaque refus est vérifié dans le hook et dans `GitAccess`, sans exécuter le faux Git.

La priorité du Git système et le refus des chemins sous dépôt/cwd restent
couverts. Un Homebrew appartenant au compte utilisateur est maintenant
refusé ; utiliser un Git système protégé. Les autres emplacements du chemin
système conservent la politique historique. La CI doit toujours fournir sa
propre installation Git de confiance. Les contrôles ajoutés portent sur
l'appartenance et les bits de permission POSIX ; les tests restent simulés
sous Linux. Aucune exécution native macOS/NixOS n'est revendiquée.

Validation : même commande de régression élargie, `563 passed, 750 subtests
passed in 90.81s`. Les dix nouveaux cas de permissions passent aussi dans
un rejeu ciblé. Ruff, MyPy (56 fichiers), Bandit et la vérification des
permaliens passent. Rapport JUnit local :
`/home/nathan/heimdall-t228-prefix-trust.xml`. La suite complète n'a pas été
relancée pour ce durcissement.
