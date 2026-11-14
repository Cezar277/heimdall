# Hook pre-commit et gestion de l'index (#36, #103-#106)

Statut : livré. Le hook local est une **aide** : il reste contournable par
`git commit --no-verify`. La barrière opposable reste la CI déterministe
(`heimdall scan --ci`, REQ-SEC-08).

## Utilisation

```sh
heimdall hook install [CHEMIN] [--force] [--no-allowlist]
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
2. `heimdall scan --staged "$PWD"` avec le script console absolu ou, à
defaut, `python -I -P -m heimdall.cli.main` (Python ≥ 3.11). `PYTHONSAFEPATH=1`
est exporté et `-P` empêche le préfixe du cwd : un `heimdall/` local ne peut
pas détourner l'import. Sur Python 3.10, `-P` n'existe pas : le script
console **hors du dépôt** est alors obligatoire, sinon `hook install` refuse
en code 2. Sous Windows, Python ≥ 3.11 est requis (le hook n'utilise pas
`heimdall.exe`), donc `hook install` refuse en code 2 sur Python 3.10. Git lance les hooks avec `cwd` = racine ; si le script est invoqué
depuis un sous-dossier, `$PWD` n'est pas une racine de dépôt et le scan
échoue en code 2 (fail-closed), jamais un périmètre partiel. Un console
script situé sous la racine, même s'il pointe par lien vers l'extérieur (venv
dans le dépôt), est refusé. L'interpréteur Python doit lui aussi être **hors
du dépôt** : `hook install` refuse en code 2 si `sys.executable` est sous la
racine, pour qu'un dépôt piégé ne puisse pas remplacer l'interpréteur exécuté
à chaque commit.

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

Depuis #228, le scan respecte `GIT_INDEX_FILE` pour `git commit -a`,
`git commit <chemin>`, `-p`, `--amend`, `--only` et `--include`. Seul un
fichier régulier directement dans le répertoire Git du worktree courant,
nommé `index`, `index.lock` ou `next-index-<pid>.lock`, est accepté. Les
chemins relatifs sont résolus depuis la racine du dépôt ; les liens,
fichiers absents, répertoires et chemins externes sont refusés en code 2.
Le même index est utilisé pour le diff, `ls-files`, la garde anti
auto-attestation et la vérification finale. Les autres variables Git
héritées restent ignorées. Les accès MCP ne reprennent aucun index hérité.

## Modifier la configuration avec revue

La configuration stagée ne peut pas autoriser ses propres exclusions.
Pour proposer un changement de `heimdall.toml`, installer explicitement
le hook en mode strict, puis préparer un commit de configuration séparé :

```sh
heimdall hook install --no-allowlist .
git add heimdall.toml
git commit -m "chore(config): propose reviewed allowlist changes"
heimdall hook install .
```

Ce mode scanne tous les blobs concernés sans appliquer aucune exclusion
d'allowlist, y compris celles de la configuration proposée. Tout secret
détecté bloque toujours le commit. Le mode reste actif jusqu'à la prochaine
installation du hook sans `--no-allowlist`. La PR doit faire approuver les
exclusions par un relecteur et passer la CI avec `--ci --no-allowlist` ou
une configuration externe approuvée. Ce mécanisme ne valide pas à lui seul
la pertinence des nouvelles exclusions.

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
Hors zone autorisée (`--force`), tout parent existant du dossier de hooks doit
aussi être non inscriptible par le groupe et les autres, sauf bit sticky
(comme `/tmp`) ; sinon l'installation refuse en code 2 avant de créer quoi que
ce soit. Les parents manquants sont créés en `0700`.

## Anti-récursion

Le script pose `HEIMDALL_IN_HOOK=1` avant d'exécuter le hook précédent et le
scan. Si la variable est déjà présente, quelle que soit sa valeur (même
vide), il refuse en code 2 avec un diagnostic statique sur stderr. Un hook
hérité qui lance un commit récursif est donc bloqué ; une variable externe
ne peut plus obtenir un verdict propre sans scan (#228). Les écritures
internes de ré-indexation neutralisent déjà les hooks via `core.hooksPath`.
Retirer une variable exportée par erreur avec `unset HEIMDALL_IN_HOOK`
avant de relancer un commit normal.

## Ré-indexation après remédiation

La primitive `heimdall.cli.hook.apply_and_restage(root, paths, apply)` est
fournie pour le moteur de remédiation (#30/#32) :

1. `assert_no_unstaged_changes` vérifie **avant** l'application qu'aucun
   fichier cible n'a de modification non indexée. Sinon la remédiation
   automatique est refusée (`UnstagedChangesError`) : un `git add` après
   coup indexerait des lignes que le développeur n'a pas choisies ;
2. `apply()` applique le patch ;
3. `_restage_paths` (interne) ré-indexe le contenu exact des seuls fichiers
   cibles. Les `ConfinedPath` assertés sont figés et repassés : si un chemin
   a été échangé contre un lien vers un autre fichier entre 1 et 3, la
   ré-indexation refuse (`HookError`) au lieu de stager la cible. Seuls les
   fichiers **déjà suivis** sont acceptés : un chemin non suivi ou absent
   est refusé (pas de `git add` implicite de lignes non revues).

La ré-indexation n'exécute **ni filtre `clean` ni hook Git** du dépôt :
le contenu est lu par Heimdall (`O_NOFOLLOW`, taille bornée), haché par
`git hash-object -w --no-filters --stdin`, puis écrit dans un **index
temporaire** par `git update-index --add --cacheinfo`. Le verrou Git
`index.lock` est pris **avant** la copie de l'index ; la source est ouverte
avec `O_NOFOLLOW` et la copie passe par le descripteur du verrou (jamais par
une réouverture du nom, donc pas de suivi de lien), puis l'index réel est
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
chemin absolu qui doit être **exactement** le verrou `index.lock` du dépôt ;
toute autre variable (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_*`…) ou un
index hors de ce verrou est refusée.

Le hook installé se contente de scanner et bloquer : le branchement du
moteur de remédiation interactif reste le ticket #30/#32.

## Limites

- `git commit --no-verify` contourne le hook.
- Toute variable `HEIMDALL_IN_HOOK` héritée bloque le hook (code 2).
- Le hook est local et mono-utilisateur ; la CI déterministe reste la seule
  barrière opposable pour une branche partagée.
- L'interpréteur Python doit être hors du dépôt : un venv local est refusé
  à l'installation (code 2). Le script console sous la racine est également
  refusé. Sur Python 3.10, un console script hors dépôt est obligatoire
  (pas de `-P`) ; sur 3.11+, le repli `-P`/`PYTHONSAFEPATH` est sûr.
- Les garanties anti-lien (`O_NOFOLLOW`) ne sont disponibles que sur les
  plateformes qui l'exposent. Ailleurs (Windows), les lectures et écritures
  d'index sensibles refusent en code 2 au lieu de suivre un lien : la
  remédiation (`apply_and_restage`) n'y est pas disponible.

## Preuves

`tests/test_cli_hook.py` couvre notamment :

- installation, mise à jour idempotente, désinstallation et restauration ;
- hook existant conservé et chaîné, refus d'écraser une sauvegarde ;
- `core.hooksPath` relatif/absolu, `--force` hors dépôt, symlink résolu et
  worktree lié ;
- blocage d'un secret indexé, ignore d'un secret non indexé ;
- refus de `HEIMDALL_IN_HOOK=1` sur un vrai `git commit` ;
- commit partiel avec deux hunks : l'index reste exactement celui préparé,
  le second hunk reste intact dans le dossier de travail ;
- refus des modifications non indexées avant remédiation ;
- ré-indexation sans exécuter les filtres `clean` ni le hook
  `post-index-change`, avec verrou `index.lock` pris avant copie, source
  ouverte en `O_NOFOLLOW`, copie via descripteur, échec `update-index` sans
  modification de l'index réel et refus si le verrou est déjà pris ou
  remplacé par un symlink ;
- chemins commençant par `-` refusés, `.env.example/` répertoire refusé,
  restauration d'un legacy symlink ou refus d'un legacy répertoire ;
- détection « notre hook » ancrée au préambule, pas à une sous-chaîne ;
- chaînage du legacy par chemin relatif au hook, prouvé après déplacement
  du dépôt ;
- console script sous la racine (même lien vers l'extérieur) refusé,
  interpréteur Python sous la racine refusé à l'installation, repli `-P`
  uniquement sur 3.11+ (refus sur 3.10 sans console), et commit depuis un
  sous-dossier toujours bloqué par le scan de la racine ;
- chemins assertés figés : un échange `a` → lien vers `b` entre l'assert et
  la ré-indexation est refusé sans stager `b` ;
- fichiers non suivis ou absents refusés par l'assert (pas de `git add`
  implicite) ;
- anti-récursion : toute valeur héritée est refusée ;
- `tests/test_hook_commit_index.py` : vrais commits avec index temporaire,
  commits propres, worktree lié, index invalides, configuration et mode
  strict `--no-allowlist` (#228).

Git est cherché dans `os.defpath` puis, sur POSIX, dans `/opt/homebrew/bin`,
`/usr/local/bin`, `/run/current-system/sw/bin` et
`/nix/var/nix/profiles/default/bin`. Le `PATH` hérité n'est jamais utilisé.
Une installation Nix disponible uniquement dans un profil utilisateur doit
exposer Git via un de ces chemins système. Un binaire dans le dépôt ou le
répertoire courant reste refusé.

```sh
.venv/bin/python -m pytest tests/test_cli_hook.py -v
.venv/bin/ruff check heimdall tests scripts
.venv/bin/mypy heimdall
```
