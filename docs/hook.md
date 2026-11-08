# Hook pre-commit et gestion de l'index (#36, #103-#106)

Statut : livré. Le hook local est une **aide** : il reste contournable par
`git commit --no-verify`. La barrière opposable reste la CI déterministe
(`heimdall scan --ci`, REQ-SEC-08).

## Utilisation

```sh
heimdall hook install [CHEMIN]    # installe ou met à jour le hook
heimdall hook uninstall [CHEMIN]  # retire le hook et restaure le précédent
```

`CHEMIN` est la racine du dépôt Git (`.` par défaut). Les commandes échouent
en code 2 si la racine n'est pas un dépôt, si le hook existant ne peut pas
être conservé, ou si l'écriture échoue. Les messages sont statiques : aucun
chemin ni contenu n'est reflété.

## Ce que fait le hook installé

Le script généré exécute, dans cet ordre :

1. le hook précédent s'il a été conservé et s'il est exécutable ;
2. `python -m heimdall.cli.main scan --staged .` avec l'interpréteur absolu
   qui a installé Heimdall.

Le hook précédent passe **avant** Heimdall : s'il modifie l'index, le scan
juge l'état final qui sera réellement commité. Un code de sortie non nul du
hook précédent bloque le commit sans lancer Heimdall. Le code de sortie de
Heimdall est propagé : `0` (propre), `1` (secrets détectés), `2` (erreur
d'outillage) bloquent le commit pour `1` et `2`.

Le scan `--staged` lit **uniquement les blobs de l'index** (`git diff
--cached` puis `git cat-file blob <sha>`), jamais le fichier du dossier de
travail. Une modification non indexée n'est donc jamais scannée (#104), et
un commit partiel (`git add -p`) ne peut pas faire juger des lignes qui ne
seront pas commitées (#106).

## Hooks existants, `core.hooksPath` et worktrees

Le dossier de hooks est celui rendu par `git rev-parse --git-path hooks` :
il respecte `core.hooksPath` et les worktrees liés.

- hook absent : Heimdall écrit `pre-commit` ;
- hook Heimdall déjà présent : mise à jour idempotente ;
- hook étranger : il est renommé en `pre-commit.heimdall-legacy`, puis
  chaîné s'il est un fichier régulier exécutable. Il n'est jamais écrasé ;
- une sauvegarde `pre-commit.heimdall-legacy` existe déjà : un nouveau hook
  étranger est refusé (code 2) plutôt que d'écraser la sauvegarde ;
- `uninstall` retire le hook Heimdall et restaure la sauvegarde si elle
  existe ; un hook étranger non géré n'est jamais touché.

Le hook est écrit atomiquement (fichier temporaire, `fsync`, `os.replace`)
avec le mode `0700`. Un lien symbolique de hook n'est jamais suivi : il est
déplacé comme sauvegarde et n'est pas chaîné.

## Anti-récursion

Le script pose `HEIMDALL_IN_HOOK=1` avant d'exécuter le hook précédent et le
scan. Si la variable vaut déjà `1`, il sort immédiatement en `0`. Un hook
hérité qui relancerait Heimdall, ou une future remédiation qui ré-indexe,
ne déclenche donc pas de boucle (#105).

## Ré-indexation après remédiation

La primitive `heimdall.cli.hook.apply_and_restage(root, paths, apply)` est
fournie pour le moteur de remédiation (#30/#32) :

1. `assert_no_unstaged_changes` vérifie **avant** l'application qu'aucun
   fichier cible n'a de modification non indexée. Sinon la remédiation
   automatique est refusée (`UnstagedChangesError`) : un `git add` après
   coup indexerait des lignes que le développeur n'a pas choisies ;
2. `apply()` applique le patch ;
3. `restage_paths` ré-indexe le contenu exact des seuls fichiers cibles.

La ré-indexation n'exécute **ni filtre `clean` ni hook Git** du dépôt :
le contenu est lu par Heimdall (`O_NOFOLLOW`, taille bornée), haché par
`git hash-object -w --no-filters --stdin`, puis écrit par un unique
`git update-index --add --cacheinfo`. Les commandes git internes utilisent
un argv figé, `core.fsmonitor=false` et `core.hooksPath=os.devnull` ; les
chemins passent par la garde unique `heimdall.mcp.paths.confine` (résolution
réelle, confinement à la racine, refus des liens sortants). Les chemins
`.git/**` et `.env*` (sauf `.env.example`) sont refusés.

Le hook installé se contente de scanner et bloquer : le branchement du
moteur de remédiation interactif reste le ticket #30/#32.

## Preuves

`tests/test_cli_hook.py` couvre notamment :

- installation, mise à jour idempotente, désinstallation et restauration ;
- hook existant conservé et chaîné, refus d'écraser une sauvegarde ;
- `core.hooksPath` relatif/absolu et worktree lié ;
- blocage d'un secret indexé, ignore d'un secret non indexé ;
- commit partiel avec deux hunks : l'index reste exactement celui préparé,
  le second hunk reste intact dans le dossier de travail ;
- refus des modifications non indexées avant remédiation ;
- ré-indexation sans exécuter les filtres `clean` ni le hook
  `post-index-change` ;
- anti-récursion `HEIMDALL_IN_HOOK=1`.

```sh
.venv/bin/python -m pytest tests/test_cli_hook.py -v
.venv/bin/ruff check heimdall tests scripts
.venv/bin/mypy heimdall
```
