# Hook pre-commit et gestion de l'index (#36, #103-#106)

Statut : livré. Le hook local est une **aide** : il reste contournable par
`git commit --no-verify`. La barrière opposable reste la CI déterministe
(`heimdall scan --ci`, REQ-SEC-08).

## Utilisation

```sh
heimdall hook install [CHEMIN] [--force]    # installe ou met à jour le hook
heimdall hook uninstall [CHEMIN] [--force]  # retire le hook et restaure le précédent
```

`CHEMIN` est la racine du dépôt Git (`.` par défaut). Les commandes échouent
en code 2 si la racine n'est pas un dépôt, si le hook existant ne peut pas
être conservé, ou si l'écriture échoue. Les messages sont statiques : aucun
chemin ni contenu n'est reflété. `--force` est requis pour un
`core.hooksPath` absolu qui sort du dépôt **et** du répertoire Git commun
(worktrees liés).

## Ce que fait le hook installé

Le script généré exécute, dans cet ordre :

1. le hook précédent s'il a été conservé et s'il est exécutable ;
2. `heimdall scan --staged .` avec le script console absolu (ou, à défaut,
   `python -I -m heimdall.cli.main`) qui a installé Heimdall. `-I` isole
   l'interpréteur du `PYTHONPATH` et du dépôt : un `heimdall/` local ne peut
   pas détourner l'import.

Le hook précédent est localisé **relativement au script** (`dirname "$0"`) :
déplacer le dépôt ne casse pas le chaînage. Il passe **avant** Heimdall :
s'il modifie l'index, le scan juge l'état final qui sera réellement commité. Un code de sortie non nul du
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
il respecte `core.hooksPath` et les worktrees liés. Le chemin est **résolu**
(liens symboliques suivis) avant contrôle. Un `core.hooksPath` relatif doit
rester dans le dépôt ; un absolu doit rester dans le dépôt ou dans le
répertoire Git commun, sinon `--force` est exigé. Sans `--force`, la commande
refuse en code 2 avant toute écriture.

- hook absent : Heimdall écrit `pre-commit` ;
- hook Heimdall déjà présent : mise à jour idempotente ;
- hook étranger : il est renommé en `pre-commit.heimdall-legacy`, puis
  chaîné s'il est un fichier régulier exécutable. Il n'est jamais écrasé ;
- une sauvegarde `pre-commit.heimdall-legacy` existe déjà : un nouveau hook
  étranger est refusé (code 2) plutôt que d'écraser la sauvegarde ;
- `uninstall` retire le hook Heimdall et restaure la sauvegarde si elle
  existe ; un hook étranger non géré n'est jamais touché.

Le hook est écrit atomiquement (fichier temporaire, `fsync`, `os.replace`)
avec le mode `0700`. Le dossier de hooks doit être un sous-dossier dédié,
distinct de la racine du dépôt et de `.git` ; il ne doit être inscriptible ni
par le groupe ni par les autres : un umask `0002` rend `.git/hooks` groupe-inscriptible
et l'installation refuse alors en code 2 ; faire `chmod g-w .git/hooks` (ou
utiliser un `core.hooksPath` dédié en `0700`). Un lien symbolique de hook
n'est jamais suivi : il est déplacé comme sauvegarde et n'est pas chaîné.

## Anti-récursion

Le script pose `HEIMDALL_IN_HOOK=1` avant d'exécuter le hook précédent et le
scan. Si la variable vaut déjà `1`, il affiche un avertissement sur stderr
puis sort immédiatement en `0`. Un hook hérité qui relancerait Heimdall, ou
une future remédiation qui ré-indexe, ne déclenche donc pas de boucle (#105).

Poser `HEIMDALL_IN_HOOK=1` dans l'environnement **contourne le hook** :
c'est équivalent à `git commit --no-verify`. L'avertissement rend le
contournement visible, mais ne le bloque pas. La CI `--ci` reste la barrière
(REQ-SEC-08).

## Ré-indexation après remédiation

La primitive `heimdall.cli.hook.apply_and_restage(root, paths, apply)` est
fournie pour le moteur de remédiation (#30/#32) :

1. `assert_no_unstaged_changes` vérifie **avant** l'application qu'aucun
   fichier cible n'a de modification non indexée. Sinon la remédiation
   automatique est refusée (`UnstagedChangesError`) : un `git add` après
   coup indexerait des lignes que le développeur n'a pas choisies ;
2. `apply()` applique le patch ;
3. `_restage_paths` (interne) ré-indexe le contenu exact des seuls fichiers cibles.

La ré-indexation n'exécute **ni filtre `clean` ni hook Git** du dépôt :
le contenu est lu par Heimdall (`O_NOFOLLOW`, taille bornée), haché par
`git hash-object -w --no-filters --stdin`, puis écrit dans un **index
temporaire** par `git update-index --add --cacheinfo`. Le verrou Git
`index.lock` est pris **avant** la copie de l'index, puis l'index réel est
remplacé atomiquement (`os.replace`) après vérification des entrées
(`git ls-files -s -z`) : ni panne médiane ni `git add` concurrent ne laisse
l'index partiellement modifié ou n'écrase une mise à jour concurrente. Les commandes git internes utilisent
un argv figé, `core.fsmonitor=false` et `core.hooksPath=os.devnull` ; les
chemins passent par la garde unique `heimdall.mcp.paths.confine` (résolution
réelle, confinement à la racine, refus des liens sortants). Les chemins
contenant un composant `.git` ou `.env*` sont refusés, quel que soit leur
niveau ; seul le **fichier** exact `.env.example` (dernier composant,
**casse incluse**) est accepté, un répertoire `.env.example/` ou un nom
`.ENV.EXAMPLE` est refusé.

Le binaire `git` est résolu hors `PATH` hérité et refusé s'il est situé dans
le dépôt ou dans le répertoire courant. L'environnement des commandes
internes n'accepte qu'une variable supplémentaire, `GIT_INDEX_FILE`, avec un
chemin absolu ; toute autre variable (`GIT_DIR`, `GIT_WORK_TREE`,
`GIT_CONFIG_*`…) est refusée.

Le hook installé se contente de scanner et bloquer : le branchement du
moteur de remédiation interactif reste le ticket #30/#32.

## Limites

- `git commit --no-verify` contourne le hook.
- `HEIMDALL_IN_HOOK=1` contourne le hook (avertissement sur stderr) ; c'est
  le mécanisme d'anti-récursion, pas une garantie de sécurité.
- Le hook est local et mono-utilisateur ; la CI déterministe reste la seule
  barrière opposable pour une branche partagée.

## Preuves

`tests/test_cli_hook.py` couvre notamment :

- installation, mise à jour idempotente, désinstallation et restauration ;
- hook existant conservé et chaîné, refus d'écraser une sauvegarde ;
- `core.hooksPath` relatif/absolu, `--force` hors dépôt, symlink résolu et
  worktree lié ;
- blocage d'un secret indexé, ignore d'un secret non indexé ;
- contournement documenté `HEIMDALL_IN_HOOK=1` sur un vrai `git commit` ;
- commit partiel avec deux hunks : l'index reste exactement celui préparé,
  le second hunk reste intact dans le dossier de travail ;
- refus des modifications non indexées avant remédiation ;
- ré-indexation sans exécuter les filtres `clean` ni le hook
  `post-index-change`, avec verrou `index.lock` pris avant copie, échec
  `update-index` sans modification de l'index réel et refus si le verrou
  est déjà pris ;
- chemins commençant par `-` refusés, `.env.example/` répertoire refusé,
  restauration d'un legacy symlink ou refus d'un legacy répertoire ;
- détection « notre hook » ancrée au préambule, pas à une sous-chaîne ;
- chaînage du legacy par chemin relatif au hook, prouvé après déplacement
  du dépôt ;
- anti-récursion `HEIMDALL_IN_HOOK=1`.

```sh
.venv/bin/python -m pytest tests/test_cli_hook.py -v
.venv/bin/ruff check heimdall tests scripts
.venv/bin/mypy heimdall
```
