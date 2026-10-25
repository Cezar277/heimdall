# CLI `heimdall scan` (#29)

Statut : livré par le ticket #29 (sous-ticket de l'épic #6 « CLI, hook et CI
headless »). La commande est **branchée** sur le scanner déterministe #22 et
sur l'accès git confiné #27. Elle est **en lecture seule sur le dépôt** :
elle signale, elle ne répare rien (la remédiation et la validation Y/N/E
arrivent avec #32). La seule écriture autorisée est la clé d'empreinte locale
hors dépôt, créée au premier run (voir Invariants).

Références :

- contrat de sortie : [Finding v1](contracts/finding.md) et
  [`schemas/finding.schema.json`](../schemas/finding.schema.json) (#14) ;
- scanner : [scanner.md](scanner.md) (#22) et
  [scanner-interface.md](scanner-interface.md) (#53) ;
- accès git confiné : [`heimdall/mcp/gitdiff.py`](../heimdall/mcp/gitdiff.py) ;
- implémentation : [`heimdall/cli/scan.py`](../heimdall/cli/scan.py) (logique)
  et [`heimdall/cli/main.py`](../heimdall/cli/main.py) (codes de sortie) ;
- preuves : [`docs/t29-samm.md`](t29-samm.md).

## En une phrase

`heimdall scan` analyse un dépôt à la recherche de secrets et rend un verdict
**déterministe**, porté par son **code de sortie** : 0 (aucun secret), 1
(secrets détectés), 2 (erreur d'outillage — jamais 0 après une erreur).

## Utilisation

```sh
heimdall scan [CHEMIN]              # arbre de travail (mode strict)
heimdall scan --staged [CHEMIN]     # blobs ajoutés ou modifiés dans l'index
heimdall scan --ci [CHEMIN]         # mode CI headless (verdict = code de sortie)
heimdall scan --json [CHEMIN]       # rapport JSON sur stdout
```

| Option | Effet |
| --- | --- |
| `--staged` | change le **périmètre** : les blobs **ajoutés ou modifiés** de l'index git, lus blob par blob, **sans aucune exclusion de chemin** |
| `--ci` | mode **headless** : aucun dialogue, aucun LLM, aucun réseau ; le verdict est le code de sortie, et un résumé déterministe est écrit sur stderr (avec décompte des secrets ignorés par l'allowlist) |
| `--json` | le rapport humain est remplacé par le document JSON `heimdall.scan.v1` (stdout) ; inclut les traces et décomptes d'allowlist (#24) ; les erreurs restent sur stderr |
| `--config PATH` | spécifie un fichier de configuration alternatif (par défaut : `heimdall.toml` à la racine du dépôt) ; un chemin **hors du dépôt** est accepté : choix opérateur explicite, soumis aux mêmes gardes (`_resolve_root` + `O_NOFOLLOW`, plafond de taille, contrat fermé) |
| `--no-allowlist` | désactive l'allowlist déterministe pour le scan courant |

En `--ci`, l'allowlist du dépôt ne peut jamais s'auto-attester : si un
`heimdall.toml` est présent dans le dépôt scanné (versionné à la racine,
comme ici), `scan --ci` sans option sort en code 2. L'opérateur a deux
choix explicites : `--config` vers un fichier **hors du dépôt** épinglé
par l'équipe (mêmes gardes et contrat fermé, recommandé), ou
`--no-allowlist` (aucune ignorance, verdict maximal). Exemple :
`heimdall scan --ci --config /opt/ci/allowlist.toml .`

Le fichier d'allowlist est un **contrat fermé** : seule la table racine
`[allowlist]` est acceptée, `version` est **obligatoire** et doit être le
littéral `"1"` (un entier `1`, ou une `version` simplement omise, sont
refusés), et chaque mot-clé doit faire au moins 3 caractères. Toute
clé racine inconnue (`[tool.foo]`, faute de frappe), tout type incorrect ou
tout mot-clé trop court est une erreur d'outillage (code 2), jamais un
passage silencieux. Un `secret_types` doit suivre la grammaire des types
du contrat Finding (`[a-z][a-z0-9_]*`, 64 caractères max, ex. `aws`) :
`"AWS"` ou `"../etc"` sont refusés en code 2 au lieu de rendre la règle
muette. Le critère `exact_keywords` (optionnel) compare à égalité
insensible à la casse : c'est le SEUL critère valeur autorisé sans
restriction — le choix auditable pour les marqueurs globaux sans `paths`
(`example`, `changeme`, `dummy`) : `my-example-key` reste détecté, seul le
marqueur exact est ignoré. Les `keywords` classiques gardent la frontière
`\b` stricte mais exigent une restriction conjointe (`paths` et/ou
`secret_types`, ex. fixtures de test) : une règle `keywords`/`patterns`
globale est refusée en code 2, jamais silencieusement ignorante.

Les `patterns` ne peuvent pas rendre l'allowlist aveugle : via TOML, chaque
chaîne est compilée puis validée ; via l'API Python, seules des expressions
déjà compilées sont acceptées. Un motif qui matche la chaîne vide (`.`, `.*`,
`^`, `^.*$`…) est refusé, et chaque branche d'alternance doit porter au moins
3 caractères **littéraux** : `EXAMPLE-[0-9]{4}` est accepté, tandis que
`[a-z]+`, `\w+`, `\d{3}-\d{4}` ou `x{3}y{3}` sont refusés (motif trop large
pour être auditable) — reformuler en portant les marqueurs concrets visés.
Aucun mot-clé ni motif ne peut porter de caractère de contrôle ou invisible
(`\n` littéral, tabulation, RLO…) : faute de frappe refusée en code 2
(les échappements regex `\n` restent deux caractères ordinaires et acceptés).
Les constructions à backtracking non borné (alternance ou groupe imbriqué
sous quantificateur, quantificateurs consécutifs, références arrière) sont
refusées en `ScanError` (code 2). Une valeur candidate de plus de 256
caractères n'est pas soumise aux regex : elle reste signalée (fail-closed),
ce qui borne l'exposition résiduelle.

Le filtre de chemins est borné des deux côtés : un motif `paths` porte au
plus 10 jokers `*` (au-delà : code 2), et un chemin de plus de 1024
caractères n'est pas soumis à `fnmatch` (fail-closed : il reste signalé).
Sous Python ≥ 3.13, `fnmatch` complète cette borne avec des groupes
atomiques natifs.

`CHEMIN` vaut `.` par défaut. Il doit être la **racine** d'un dépôt git,
dans les deux périmètres (sinon : erreur, code 2) : hors dépôt —
répertoire quelconque, fichier isolé — il n'y a pas de verdict « propre »,
pour qu'une CI mal configurée (mauvais chemin) échoue loud au lieu de
rendre 0 en silence. Le scan de fichier isolé reste possible en
bibliothèque (`Scanner`, #22), hors contrat hook/CI.

## Les deux périmètres

| Périmètre | Ce qui est analysé | Exclusions |
| --- | --- | --- |
| `working-tree` (défaut) | l'arbre de travail, en **mode strict** | **base VCS seule** (`.git/`, `.hg/`, `.svn/` : métadonnées, pas du contenu). Tout le reste (`vendor/`, `node_modules/`, `.venv/`, lockfiles, sorties de build) est lu par contenu ; binaire, lien ou fichier illisible rend le rapport incomplet et sort en **2** |
| `staged` (`--staged`) | le contenu **indexé** de chaque fichier ajouté ou modifié | **aucune exclusion de chemin** : `vendor/`, `third_party/`, `package-lock.json`, `.gitignore`… sont analysés |

« Aucune exclusion de **chemin** » ne veut pas dire « aucune exclusion du
tout » : un contenu dont la signature magique **et** la majorité sont
binaires (PNG, PDF, ZIP, ELF…) n'a pas de texte à analyser. En mode arbre, il
est **tracé** et rend le rapport incomplet : la CLI refuse alors le verdict
propre (code 2). En `--staged`, le blob binaire connu est sauté — un secret
placé dans un binaire reste un faux négatif, documenté dans les limites
ci-dessous. Un contenu inconnu (NUL + texte) reste fail-closed : jamais sauté
sur simple suffixe.

Le mode strict est une correction issue de la revue de #165 (point HIGH) :
la politique #59 excluait `vendor/`, `node_modules/` et les lockfiles, donc un
secret posé dans `vendor/evil.py` n'était **jamais** signalé. Un secret y est
un secret : aucun nom de fichier ou de répertoire de contenu n'exclut plus rien,
et le contenu décide. Seule la base VCS est hors du périmètre audité.
L'historique VCS (.git/) n'est jamais parcouru par le mode arbre ; l'analyse de l'historique est couverte exclusivement par l'option --staged.

En mode `--staged`, c'est le **blob indexé** qui est lu, pas la copie de
travail : c'est ce que le commit va contenir qui est jugé. Le blob entier est
analysé, pas seulement les lignes modifiées — un secret déjà présent dans le
fichier et laissé tel quel reste signalé. Les dépôts **SHA-1 et SHA-256**
(`--object-format=sha256`) sont supportés : les noms d'objets de 40 ou 64
caractères hexadécimaux sont acceptés.

Les lectures sont adressées par SHA : un `git add` concurrent ne peut pas
corrompre un blob déjà lu, mais la **liste** figée au départ peut devenir
périmée (un fichier ajouté après le snapshot serait committé sans avoir été
scanné). L'index est donc **relu après l'analyse**, et toute divergence
refuse le scan (code 2) : un verdict sur un snapshot périmé ne vaut ni 0
ni 1. Les appels `cat-file` sont figés (`cat-file <mode> -- <sha>`) : le
séparateur `--` est accepté par le git de CI et figé par un test e2e
(`tests/test_mcp_units.py`).

La **racine elle-même est re-contrôlée** après l'analyse, dans les deux
périmètres : la garde unique (refus symlink, égalité du résolu) est rejouée
sur le chemin demandé et comparée à la forme figée à l'entrée — chemin
résolu **et** identité (`st_dev`, `st_ino`, `st_ctime_ns` épinglés à la
construction). Un lien remplacé pendant le scan, comme un dossier remplacé
par un autre au même chemin (même résolu, autre identité), refuse le verdict
au lieu de juger le mauvais périmètre. Le `ctime` est nécessaire : un
`rm -rf` suivi d'un `mkdir` peut réattribuer le même inode, mais le dossier
neuf a un `ctime` postérieur, qu'un `utime` ne peut pas forger. Revers
assumé sous POSIX : ajouter ou supprimer une entrée **directe** de la racine
pendant le scan refuse le verdict (code 2, fail-closed) ; sous Windows, le
`ctime` est la date de création et ce revers n'existe pas. Le scanner d'arbre
rejoue sa garde sur la forme canonique déjà figée (opération idempotente) ; ce
second passage n'ouvre pas
de bypass : toute substitution entre les deux est rattrapée par le
re-contrôle d'identité final.

Les suppressions et les **gitlinks** (sous-modules, mode `160000`) sont
ignorés : une suppression n'a plus de blob à scanner, et le SHA d'un gitlink
désigne un **commit**, pas un blob — aucun texte à analyser (`cat-file blob`
échouerait). C'est une impossibilité technique documentée, pas une
exclusion de chemin : un `submodule add` stagé ne fait pas échouer le scan,
et un secret voisin reste signalé. Seul le mode **indexé** compte : un
passage gitlink → fichier (`T` vers `100644`) porte un vrai blob et reste
scanné.

## Bornes

Le scan est **borné** dans les deux périmètres : au-delà, il est refusé
(code 2), jamais tronqué ni présenté comme complet.

| Périmètre | Borne par fichier | Nombre de fichiers | Volume total | Findings |
| --- | --- | --- | --- | --- |
| `working-tree` | 1 Mio ([`MAX_FILE_BYTES`](../heimdall/scanner/detect.py)) | 50 000 ([`MAX_FILES`](../heimdall/scanner/detect.py)) | 256 Mio ([`MAX_TOTAL_BYTES`](../heimdall/scanner/detect.py)) | 10 000 ([`MAX_FINDINGS`](../heimdall/scanner/detect.py)) |
| `staged` | 1 Mio | 1 000 ([`MAX_STAGED_FILES`](../heimdall/cli/scan.py)) | 32 Mio ([`MAX_STAGED_BYTES`](../heimdall/cli/scan.py)) | 10 000 ([`MAX_STAGED_FINDINGS`](../heimdall/cli/scan.py)) |

En `--staged`, la taille annoncée par `git cat-file -s` est un oracle
**re-vérifié après lecture** : le contenu relu doit faire exactement cette
taille (et rester sous 1 Mio). Un écart — store incohérent, objet échangé —
est refusé (code 2) avant tout décodage, jamais scanné partiellement. Une
taille négative est également refusée ; zéro reste valide (blob vide, aucun
candidat).

Les deux périmètres ont aussi une **deadline globale** de 120 s :
[`MAX_TREE_SECONDS`](../heimdall/cli/scan.py) en arbre (vérifiée entre chaque
fichier, périodiquement à l'intérieur d'un fichier dense, et avant le rendu),
[`MAX_STAGED_SECONDS`](../heimdall/cli/scan.py) en `--staged` (vérifiée entre
blobs **et** à l'intérieur d'un blob, toutes les 256 lignes et 256 candidats,
comme en arbre : un blob d'1 Mio de lignes vides coûte ~10 s de moteur). En
arbre, les plafonds de volume ne bornent pas le temps de
regex + HMAC ; en `--staged`, chaque blob coûte deux appels `git cat-file`
séquentiels, et 1 000 blobs représenteraient 2 000 processus. Au-delà de la
deadline, refus (code 2), jamais un job CI qui s'éternise sans verdict. En
`--staged`, le restant de deadline est propagé comme timeout à chaque appel
git (borné au timeout unitaire de 30 s), y compris la seconde énumération de
l'index. La lecture de la sortie et l'attente de fin partagent ce délai : un
appel git ne dépasse jamais le restant de deadline qui lui a été passé.

Les bornes d'entrée ne suffisent pas : des blobs denses en candidats
feraient gonfler la liste des Findings et le tri final en mémoire et en
temps CI. Le compteur est vérifié à deux granularités — **par candidat**
(un seul fichier ou blob dense ne fait jamais gonfler la liste) **et entre
fichiers** (l'accumulation sur tout le périmètre reste bornée) : au-delà,
refus (code 2), jamais un rapport tronqué présenté comme complet. 10 000
Findings sont déjà inexploitables par un humain comme par un journal CI.
Il n'existe pas d'opt-out non borné : `SignatureEngine(max_findings=None)`
retombe sur le plafond par défaut, comme `Scanner`.

L'énumération de l'index elle-même est lue en **flux borné** (8 Mio,
[`MAX_STAGED_RAW_BYTES`](../heimdall/mcp/gitdiff.py)) : un index adverse de
100 000 entrées est coupé avant d'être bufferisé, puis refusé. Le pire cas
légitime (1 000 entrées × ~128 octets d'en-tête + chemin) tient large sous
ce plafond.

Les deux bornes totales protègent la CI d'un dépôt adverse (100 000 petits
fichiers, ou 50 000 fichiers de 1 Mio) : sans elles, le job durerait sans
rendre de verdict. Les constantes sont volontairement généreuses pour un
dépôt réel tout en restant déterministes.

## Codes de sortie

| Code | Signification |
| --- | --- |
| `0` | aucun secret détecté — **le périmètre a été analysé en entier** |
| `1` | au moins un secret détecté |
| `2` | erreur d'outillage : le périmètre n'a **pas** pu être analysé en entier |

Le code 2 est le refus par défaut : racine absente ou illisible, index en
conflit de fusion, blob illisible ou trop gros, index modifié pendant le
scan, clé d'empreinte indisponible, git absent, erreur inattendue. **Jamais
0 après une erreur** : en CI, un scan raté ne doit pas laisser passer le
pipeline (REQ-SEC-07, invariant 11). Le code 1 est réservé aux secrets
avérés : une panne d'outillage ne sort jamais en 1 — y compris quand
l'écriture du rapport ou du résumé échoue elle-même (EPIPE, stderr fermé) :
les messages d'erreur sont écrits en best-effort et le code 2 reste
garanti.

## Sortie

### Humain (stdout)

```text
heimdall scan : périmètre index git (blobs ajoutés ou modifiés, aucune exclusion de chemin)
1 secret(s) détecté(s) :
  vendor/evil.py:1  type=aws  entropie=3.6842  empreinte=6bf349c39402…  source=regex
Codes de sortie : 0 = aucun secret, 1 = secrets détectés, 2 = erreur d'outillage.
```

**Aucun secret n'est affiché**, jamais en entier, jamais en extrait : un
Finding ne porte qu'une empreinte HMAC-SHA-256 et une entropie. L'empreinte
affiche un préfixe de 12 caractères (le JSON porte la valeur complète) : elle
permet de rapprocher deux scans du même candidat sans le révéler.

Le **chemin** affiché à l'humain est échappé : les caractères de contrôle et
les caractères invisibles ou directionnels (U+202A-E, U+2066-9, U+200B-F,
U+FEFF…) s'affichent en `\uXXXX`. Un nom contenant U+202E (RLO) ne peut donc
pas faire lire `vendor/evil.py` là où le secret est dans un autre fichier.
Le contrat autorise ces noms : le chemin n'est pas refusé, seul son affichage
change. Le JSON garde le chemin exact.

### JSON (`--json`, stdout)

```json
{
  "count": 1,
  "findings": [
    {
      "entropy": 3.6842,
      "file": "vendor/evil.py",
      "line": 1,
      "snippet_hash": "6bf349c394023ce70c4a8e37c9a5fba3aefb17df8e20eaa0683da8c980f48852",
      "source": "regex",
      "status": "detecte",
      "type": "aws"
    }
  ],
  "schema": "heimdall.scan.v1",
  "scope": "staged"
}
```

Le document porte le périmètre (`scope`), le nombre de Findings (`count`) et
les Findings eux-mêmes, avec **exactement les sept champs** du contrat
Finding v1 (#14). Il n'y a rien d'autre : pas de valeur de secret, pas de
champ libre, pas d'extrait de ligne.

Le contrat machine est figé par [`schemas/scan.schema.json`](../schemas/scan.schema.json)
(draft 2020-12) : objet fermé (`additionalProperties: false`), `schema` en
constante `heimdall.scan.v1`, `scope` en enum, `count` entier ≥ 0, et chaque
élément de `findings` validé contre le contrat Finding v1 par `$ref` (sans
duplication : toute dérive du Finding casse la validation). Les deux `$id`
sont alignés sur la même base (`https://github.com/Cezar277/heimdall/schemas/`),
donc le `$ref` relatif se résout sans registre câblé, depuis le filesystem.
La cohérence `count == len(findings)`, inexprimable en JSON Schema pur, est
vérifiée par le test. Un parseur CI DOIT valider le schéma **puis** refuser le
document si `count != len(findings)` (contrainte explicitée dans la
`description` du schéma, pas seulement dans les tests).

## Invariants

- **Lecture seule sur le dépôt** : un scan n'écrit rien dans le dépôt ni à
  côté. La seule écriture autorisée est la clé d'empreinte locale hors dépôt
  (`$XDG_DATA_HOME/heimdall/snippet-hmac.key`, `0600`, créée au premier
  run), comme documenté dans
  [scanner.md](scanner.md#empreinte-et-entropie). Si sa création ou sa
  lecture est impossible (HOME/FS en lecture seule, clé invalide), le scan
  est refusé en code 2 — jamais un verdict 0.
- **Aucun secret en clair** : ni dans la sortie, ni dans un message d'erreur,
  ni dans une traceback (invariant 8).
- **Messages d'erreur statiques** : le chemin fourni n'est jamais reflété.
- **100 % local** : aucun appel réseau. En mode `--staged`, `git cat-file`
  est appelé avec `GIT_NO_LAZY_FETCH=1` : dans un clone partiel, l'objet
  manquant est une erreur, jamais un download.
- **Aucune exécution du contenu analysé** : le dépôt scanné ne peut pas
  faire exécuter une commande (les options git `--no-ext-diff` et
  `--no-textconv` neutralisent `diff.external` et les filtres `textconv`).
- **Racine sans lien symbolique, dans les deux périmètres** : une seule
  garde (celle du mode arbre, `Scanner._resolve_root`), rejouée à
  l'entrée comme en fin de scan. `scan` et `scan --staged` disent la même
  chose sur la même entrée — jamais de verdict sur un périmètre échangé.

## Limites connues (honnêtes)

- Le contenu **binaire** n'est pas analysé : un secret placé dans un
  commentaire PNG ou une archive n'est pas détecté. En mode arbre, le fichier
  est tracé et la CLI sort en **2** (verdict propre refusé) ; en `--staged`,
  le blob binaire connu est sauté et un `0` peut être rendu. C'est une
  impossibilité technique documentée, pas une exclusion de chemin. Les
  répertoires et fichiers textuels de `node_modules/`, `vendor/`, `.venv/`,
  `build/`, `dist/`, `target/` ou `htmlcov/` sont, eux, scannés dans les deux
  périmètres.
- La fenêtre multi-ligne reste bornée à 4 Kio : un secret coupé par un
  retour à la ligne au-delà de cette borne n'est pas recherché.
- Le mode `--staged` analyse l'**index**, pas l'historique : un secret déjà
  commité n'est pas re-détecté par `--staged` (c'est le rôle de
  `heimdall scan` sur l'arbre de travail, et du job de CI de #37).
- Un chemin de fichier doit être représentable dans le contrat
  [Finding v1](contracts/finding.md) : au-delà de **4096 caractères**, le
  scan est refusé (code 2), jamais un chemin tronqué. Un nom **non-UTF8**
  (surrogates issus de `os.walk`, octets invalides en index) est également
  refusé en code 2 dans les deux périmètres. Les noms contenant une espace ou
  des caractères Unicode valides sont, eux, parfaitement acceptés.
- Le scanner de signatures ne décode ni base64 ni concaténation de chaînes :
  ces obfuscations restent des `limite_connue` (#23/#24), comme documenté dans
  [scanner.md](scanner.md#limites-connues-honnêtes).
- Le corpus de test du projet Heimdall lui-même contient des valeurs
  **synthétiques** à forme réaliste (clé d'exemple AWS `AKIA…EXAMPLE`,
  en-tête PEM, jetons d'exemple Slack) : un scan du dépôt Heimdall les
  signale, comme il le doit. Un job de CI sur ce dépôt devra donc traiter ces
  fixtures (allowlist, #24) — sinon il échouerait à chaque exécution. C'est un
  choix assumé : mieux vaut un faux positif visible qu'un secret caché.
- **Zone de clémence `tests/` (allowlist, #24)** : avec un `heimdall.toml`
  contenant la règle `test-fixtures`, toute valeur sous `tests/`,
  `fixtures/` ou `support/` qui contient un marqueur délimité (`dummy`,
  `fake`, `mock`…) est ignorée — y compris un mot de passe choisi comme
  `my-dummy-key-12345`. C'est volontaire et documenté dans le fichier lui-même :
  les répertoires de test ne doivent jamais contenir de vrais secrets. En CI
  stricte (sans `heimdall.toml`, allowlist vide), tout y est signalé.
- **Non-atomicité assumée du mode arbre (`working-tree`) vs atomicité stricte de `--staged`** :
  L'arbre de travail est un parcours direct du système de fichiers (`os.walk`), par nature
  **non atomique** (best-effort). Le re-contrôle final d'identité racine (`st_dev`, `st_ino`,
  `st_ctime_ns`) détecte tout remplacement ou altération des entrées directes de la racine,
  mais la mutation d'un fichier imbriqué (ex. substitution walk -> open où un processus
  concurrent remplace un fichier piégé par un fichier propre avant sa lecture) ne modifie pas
  le `ctime` racine et aboutit à un verdict propre (0 mélangé). En revanche, le mode
  `--staged` est **strictement atomique** : il lit des objets immuables dans le dépôt git,
  adressés par SHA (`cat-file blob <sha>`), et re-vérifie l'état complet de l'index avant de
  rendre son verdict (toute modification concurrente refuse en code 2). Seul `--staged` est
  atomique et fait donc foi pour les barrières de sécurité bloquantes (hook de pré-commit et CI).
- **Mode arbre local indicatif, pas une barrière** : hors `--ci` et hors `--staged`,
  `heimdall scan` refuse une configuration **stagée**, mais ne vérifie pas que le
  fichier `heimdall.toml` (ou un `--config` interne) du worktree est propre et suivi
  dans l'index. Un fichier de configuration local dirty/untracked peut donc fausser le
  verdict local (jusqu'à 0). Seuls `--ci` (refus de toute configuration interne) et
  `--staged` (configuration propre et suivie, contenu vérifié lié au parseur) sont
  opposables ; le hook de pré-commit et la CI doivent utiliser ces modes.
- **Course résiduelle à l'initialisation de la racine (re-contrôle final garant)** :
  Dans `GitAccess.__init__`, entre `_resolve_root` et `os.stat`, un échange rapide
  `dossier` -> `symlink` -> `autre dossier` à la racine pourrait théoriquement échapper
  au `is_symlink` immédiat si le lien est retiré avant le `stat`. Cette fenêtre résiduelle est
  assumée : le nouveau dossier porte une identité (`st_ctime_ns` / `st_ino`) différente, et
  le re-contrôle d'identité final en fin de passe (`_verify_root_unchanged`) refuse
  systématiquement en code 2 dans les deux périmètres (`working-tree` et `--staged`).
- La validation humaine (Y/N/E) et le remplacement du secret ne sont pas
  dans ce ticket : `scan` signale, il ne répare pas (#32).

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_cli_scan.py -v
.venv/bin/python -m pytest tests/test_cli_scan.py \
  --cov=heimdall.cli --cov-branch --cov-report=term-missing
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall
```
