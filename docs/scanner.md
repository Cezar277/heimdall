# Scanner déterministe de secrets (#22)

Statut : livré par le ticket #22 (sous-tickets #53 interface/Finding, #54
signatures, #59 exclusions, #60 tests). Contrat de sortie : [Finding v1](contracts/finding.md)
et [`schemas/finding.schema.json`](../schemas/finding.schema.json). La commande
CLI `heimdall scan` est branchée par #29 (voir [cli.md](cli.md)) ; le scanner
est aussi utilisable comme bibliothèque et par les tests d'acceptation T21.

## API

```python
from heimdall.scanner import Finding, find_candidates
from heimdall.scanner.detect import Scanner as TreeScanner

findings: list[Finding] = TreeScanner(".").scan()
payload: list[dict[str, object]] = find_candidates(".")  # contrat #14

# Mode strict : refuse les exclusions de contenu (#229).
# Les exclusions Git et VCS restent identiques dans les deux modes.
strict: list[Finding] = TreeScanner(".", strict=True).scan()

# La base VCS est élaguée par politique, sans ScanError. Le compteur rend
# cet élagage observable : un [] ne prouve jamais un historique propre.
scanner = TreeScanner(".")
findings = scanner.scan()
bases_vcs_ignorees: int = scanner.vcs_ignored
fichiers_lus: int = scanner.files_scanned  # contenu réellement analysé

# Exclusions Git sûres (#59) : seules les entrées non suivies et ignorées
# par un .gitignore du dépôt sont écartées. Un fichier suivi reste scanné.
entrees_ignorees_git: int = scanner.git_ignored
integral: list[Finding] = TreeScanner(".", respect_gitignore=False).scan()
```

La CLI propage ces compteurs dans `ScanReport.vcs_ignored` et
`ScanReport.git_ignored`, les champs `vcs_ignored` et `git_ignored` du JSON
`--json`, le texte et le résumé `--ci` sur stderr (voir [cli.md](cli.md)).
En mode `--ci`, un arbre dont **aucun** contenu n'a été lu alors qu'une
exclusion a été appliquée (`vcs_ignored > 0` ou `git_ignored > 0`, et
`files_scanned == 0`) est refusé (code 2) : un code 0 ne peut plus être
confondu avec « non parcouru » par une automatisation qui ne lit que le code
de sortie.

Le scanner d'arbre est `heimdall.scanner.detect.Scanner` (alias
`TreeScanner` ci-dessus) : c'est lui qui porte `vcs_ignored` et les bornes de
parcours. `heimdall.scanner.Scanner` est une autre surface, la **façade de
cibles** `DiffTarget`/`FileTarget` avec un moteur injecté (voir
[scanner-interface.md](scanner-interface.md)) ; `find_candidates()` reste le
raccourci public pour obtenir directement les dictionnaires du contrat #14.

`TreeScanner` accepte un répertoire ou un fichier régulier explicite. `root` est
résolu une fois, **sans suivre de lien symbolique** : la racine elle-même et
chacun de ses ancêtres sont vérifiés par `lstat`, et un lien dans ce chemin
lève `ScanError` (la cible n'est pas lue à la place de la racine). La racine
parcourue est re-contrôlée, **ancêtres compris**, puis **ouverte** en
`O_NOFOLLOW|O_DIRECTORY` ; son identité (`st_dev`, `st_ino`) doit être celle
figée à la construction. Le parcours et chaque lecture sont ensuite ancrés sur
des descripteurs de répertoire (`openat`/`scandir(fd)`) : un ancêtre, la racine
ou un sous-répertoire remplacé par un lien ou un autre répertoire entre la
vérification et la lecture ne peut pas détourner le périmètre. Sur une
plateforme sans descripteurs de répertoire, le repli par chemin conserve les
gardes par fichier (résolution sous la racine, `O_NOFOLLOW`, identité
`dev/ino`, taille et `mtime_ns` avant/après lecture).

Un Finding contient exactement : `file`, `line`, `type`, `entropy`,
`snippet_hash`, `status` (`detecte`) et `source` (`regex` ou `entropy`). **La valeur brute
n'est jamais conservée** : seule une empreinte HMAC-SHA-256 est produite.

La détection générique par entropie (#23), ses seuils et ses limites
sont documentés dans [scanner-entropy.md](scanner-entropy.md).

## Signatures (#54)

| Règle | Type Finding | Forme attendue |
| --- | --- | --- |
| `aws_access_key_id` | `aws` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 caractères majuscules/chiffres |
| `aws_secret_access_key` | `aws` | affectation `aws_secret_access_key` + 40 caractères |
| `stripe_secret_key` | `stripe` | `sk_live_`/`sk_test_`/`rk_live_`/`rk_test_` + charge |
| `slack_token` | `slack` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `slack_app_token` | `slack` | `xapp-` (app-level), `xwfp-` (workflow) |
| `slack_rotating_token` | `slack` | `xoxe.` (jeton app-level rotatif) |
| `github_classic_pat` | `pat` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 caractères |
| `github_fine_grained_pat` | `pat` | `github_pat_` + charge |
| `jwt` | `jwt` | trois segments base64url, en-tête `eyJ`, charge ≤ 64 Kio |
| `pem_private_key` | `pem` | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, OPENSSH, PGP, chiffrée) |

Les motifs sont linéaires et bornés : pas de quantification imbriquée, pas de
`.*`, bornes explicites pour les charges. Les tests anti-ReDoS exécutent le
scanner sur des lignes proches de 1 Mio (`tests/test_scanner_detect.py`).

Les familles Slack couvertes sont celles publiées par Slack
([docs.slack.dev,Tokens](https://docs.slack.dev/authentication/tokens),
consultées le 2026-10-20) : `xoxb-` (bot), `xoxp-` (user), `xapp-` (app-level),
`xwfp-` (workflow), `xoxe.` (app-level rotatif) et les familles historiques
`xoxa-`, `xoxr-`, `xoxs-`. Une famille ajoutée ultérieurement par Slack ne
serait pas couverte avant #23/#24.

**Fenêtre multi-ligne bornée.** Chaque ligne est analysée seule, puis
jointure avec la ligne suivante (sans séparateur) si la fenêtre totale ne
dépasse pas **4 Kio**. Un secret coupé par un retour à la ligne
(`aws_secret_access_key =` puis la valeur à la ligne suivante) est donc
détecté, et le Finding porte la ligne où la correspondance commence. Au-delà
de 4 Kio, la jointure n'est pas faite. Un délimiteur d'affectation (`:`/`=`)
ou un jeton de longueur candidate sur une des lignes lève `ScanError` (#23),
quel que soit le fournisseur. Un jeton individuel > 4096 caractères est
également refusé avant calcul d'entropie (y compris les longues charges JWT).

Une ligne peut produire plusieurs Findings de types différents. Deux **valeurs
distinctes** du même type sur la même ligne produisent **deux** Findings
(chacun avec son `entropy` et son `snippet_hash`) : le contrat Finding ne porte
pas de colonne, mais un candidat ne doit jamais disparaître. Seule une valeur
strictement identique, déjà vue sur la même ligne, est dédupliquée.

## Périmètre (#59)

Le **contenu** décide, jamais le nom. Aucune extension, aucun lockfile et
aucun répertoire de tiers (`vendor/`, `node_modules/`, `.venv/`, sorties de
build…) n'est exclu **par son nom** : un secret y est un secret. Un fichier
texte nommé `evil.png` est lu et scanné comme un `.txt`. La seule exclusion
automatique de contenu est l'état Git décrit ci-dessous, et elle ne peut
jamais viser un fichier suivi.

### Exclusions Git sûres (#59)

Le scanner d'arbre écarte les entrées **non suivies et ignorées par un
`.gitignore` du dépôt** (motifs imbriqués et négations compris). Git est
l'unique juge : le code ne contient aucune liste de noms, d'extensions ou de
répertoires. La règle de sûreté est celle du commit :

- un fichier **suivi** est **toujours** scanné, même si un `.gitignore` le
  matche (`git add -f`) ou s'il vit dans un répertoire ignoré : c'est lui qui
  peut partir dans un commit ;
- un fichier **non suivi et non ignoré** est scanné : il peut être ajouté au
  prochain commit ;
- un fichier **non suivi et ignoré** est écarté : il ne peut pas partir dans
  un commit sans devenir suivi, et sera alors scanné.

Une seule commande Git (`git ls-files -t -z --cached --others --ignored
--exclude-per-directory=.gitignore --directory`) rend un **snapshot unique**
des entrées suivies et ignorées. Les fichiers suivis sont retirés des
exclusions, et un répertoire ignoré qui contient un fichier suivi n'est
jamais élagué. La liste est **configurable par le dépôt** : ses fichiers
`.gitignore` (versionnés ou locaux), lus par Git. Les exclusions **globales**
de la machine (`.git/info/exclude`, `core.excludesFile`, `~/.config/git/ignore`)
ne sont **pas** honorées : elles varient d'un poste à l'autre et rendraient le
verdict non déterministe. Pour les appliquer, l'opérateur les recopie dans un
`.gitignore` du dépôt.

Le snapshot initial ne fige pas l'**index** : un `git add -f` concurrent
pourrait promouvoir une entrée déjà sautée, qui serait alors absente du
rapport tout en pouvant partir dans un commit. Après le parcours, un second
snapshot vérifie donc que **toutes** les exclusions appliquées sont encore
ignorées ; toute divergence (ou un second snapshot impossible) lève
`ScanError` (code 2), jamais un verdict périmé. Ce contrôle ne s'exécute que
si au moins une entrée a été sautée. La fenêtre résiduelle après ce second
snapshot relève de la même limite que tout scan d'arbre : `--staged` reste le
périmètre opposable pour ce que le commit va réellement contenir.

La racine du snapshot est **épinglée par descripteur** : elle est ouverte en
`O_DIRECTORY|O_NOFOLLOW`, son identité `(st_dev, st_ino)` est vérifiée, puis
Git reçoit ce descripteur via `/proc/self/fd/N` (ou `/dev/fd/N`) et non le
chemin re-résolu. Un échange `A → B → A` du chemin autour de l'appel Git ne
peut donc pas faire calculer les exclusions sur `B` alors que les deux
`lstat` voient `A`. Si l'épinglage échoue alors que la plateforme le permet
(lien symbolique, droits, course), aucune exclusion n'est calculée : parcours
complet, jamais un repli silencieux par chemin. Sur une plateforme sans
descripteur de répertoire (Windows), le repli par chemin conserve la double
vérification `lstat` avant/après ; la précondition **« racine et index figés
pendant le scan »** y reste alors explicite. Dans tous les cas, un index promu
pendant le parcours est refusé par le second snapshot.

L'appel Git est confiné (binaire résolu hors `PATH` hérité, argv figé, sans
shell, environnement reconstruit, configuration système/globale neutralisée,
`core.fsmonitor` et `core.untrackedCache` désactivés, stdin fermé, timeout
et sortie bornés). Une **panne de Git** (binaire absent, dépôt invalide,
sortie hors bornes) désactive les exclusions et **parcourt tout l'arbre** :
le scanner lit plus, jamais moins. Seul le dépassement de l'échéance du scan
lève `ScanError` (fail-closed).

`TreeScanner.git_ignored` compte les entrées écartées lors du dernier scan
(une par fichier ignoré, une par répertoire ignoré élagué) ; il est remis à
zéro à chaque scan et vaut 0 avec `respect_gitignore=False`. Le mode
**fichier unique** ne consulte jamais `.gitignore` : un fichier passé
explicitement est toujours scanné. La CLI expose ce compteur dans
`ScanReport.git_ignored`, le JSON `--json`, le texte et le résumé `--ci`, et
`--no-gitignore` rétablit un parcours intégral (voir [cli.md](cli.md)).

La **base VCS** (`.git/`, `.hg/`, `.svn/`) est également élaguée : ce n'est
pas le contenu du dépôt, et son historique n'est jamais parcouru par le mode
arbre. Cet élagage est une politique, pas un échec de lecture : il ne lève
pas `ScanError`, mais il est **compté** dans `TreeScanner.vcs_ignored` pour
que l'appelant distingue « aucune base VCS » de « base VCS non parcourue ».
Un `[]` vaut donc « rien trouvé dans le périmètre lu », jamais « historique
propre » ; `--staged` couvre le contenu indexé (ce que le commit va
contenir), pas les commits déjà écrits.

`TreeScanner.files_scanned` expose le nombre de fichiers de contenu
effectivement lus. Un dépôt vide (seule la base VCS existe) reste un verdict
0 **en bibliothèque et en local** : il est réellement vide, pas illisible. Un
arbre réduit à `.git/config` rend donc 0 avec `vcs_ignored == 1` et
`files_scanned == 0` en mode local ; un arbre dont toutes les entrées sont
non suivies et ignorées rend 0 avec `git_ignored > 0` et
`files_scanned == 0`. **En `--ci`**, ces deux arbres sont refusés (code 2)
car aucun contenu n'a été lu. C'est pourquoi `--staged` est le périmètre
opposable pour le contenu indexé et que le résumé `--ci` rappelle toujours
les nombres de bases élaguées et d'entrées ignorées. Dès qu'au moins un
fichier de contenu a été lu, ces exclusions restent une politique observable
sans transformer un dépôt réel en erreur.

Un fichier régulier nommé `.git` est un **gitlink** légitime (worktree,
sous-module : `gitdir: …`), pas le répertoire `.git/` : seul un segment
**parent** de chemin peut classer hors périmètre. Son contenu est lu comme
celui de tout autre fichier.

Depuis #229, `Scanner(root)` et la CLI tolèrent les binaires, les fichiers
trop gros et les liens symboliques internes sans les suivre. Les exclusions
de contenu sont exposées dans `scanner.skipped` et dans le rapport de la CLI.
`strict=True` / `--strict` rétablit le refus des exclusions de contenu ; la
base VCS et les exclusions Git sûres restent identiques dans les deux modes.
Les helpers qui ne rendent qu'une liste (`scan`, `find_candidates`) restent
stricts par défaut afin de ne pas perdre les informations de couverture.

### Encodages et limites de contenu

Voir la [politique complète de tolérance E-01](scanner-tolerance.md) pour les
encodages UTF-8/16/32, le repli CP1252/Latin-1, les binaires et les limites
de taille et de jetons. Un texte portant un suffixe d'image reste scanné.
Les binaires ne sont pas ouverts au-delà du plafond ; les portions écartées
sont signalées avec leur chemin et un motif, jamais avec leur contenu.

L'API `is_known_binary` reste dépréciée et sans autorité : le scanner utilise
`decode_text`, dont le résultat et le mode strict déterminent le traitement.
Un appelant ne doit jamais décider du périmètre à partir du seul suffixe.

## Comportement fail-closed

Les erreurs de lecture et les refus du mode strict lèvent `ScanError` avec un message statique
`scan impossible : entrée non analysable`, sans chemin ni extrait de fichier :

| Situation | Résultat |
| --- | --- |
| racine absente, non régulière ou illisible | `ScanError` |
| racine ou fichier unique symlinké (ou ancêtre symlinké) | `ScanError` |
| racine non canonique (ex. `/tmp` symlinké vers `/private/tmp` sur macOS) | `ScanError` — passer un chemin canonique (sans lien) |
| fichier non régulier (FIFO, device) | `ScanError` |
| fichier > 1 Mio | trace `too_large` ; `ScanError` en mode strict |
| plus de 50 000 fichiers, ou plus de 256 Mio lus au total | `ScanError` (bornes #29) |
| borne explicite `max_files`/`max_bytes`/`max_findings` hors de `1..plafond` | `ValueError` à la construction (surcharge jamais silencieuse) |
| fichier modifié pendant la lecture | `ScanError` |
| nom de fichier hors contrat (`..`, `:`, contrôle) | `ScanError` |
| clé HMAC absente, illisible, trop permissive ou impossible à créer | `ScanError` |
| clé HMAC demandée avec `..` dans le chemin | `ScanError` |
| contenu non décodable en texte | trace `binary` ; `ScanError` en mode strict |
| fichier ou répertoire symlinké **interne** au périmètre | trace `symlink`, jamais suivi ; `ScanError` en mode strict |
| base VCS `.git/`, `.hg/`, `.svn/` | élaguée par politique, comptée dans `TreeScanner.vcs_ignored` |
| entrée **non suivie et ignorée** par un `.gitignore` du dépôt | écartée et comptée dans `TreeScanner.git_ignored` ; un fichier **suivi** n'est jamais écarté |
| Git absent, dépôt invalide ou sortie Git hors bornes | exclusions désactivées, **parcours complet** (le scanner lit plus, jamais moins) |
| arbre vide (seule la base VCS existe) en bibliothèque/local | liste vide (0) : arbre réellement vide, `files_scanned == 0` et `vcs_ignored == 1` |
| arbre dont toutes les entrées sont exclues (base VCS ou `.gitignore`) en `--ci` | `ScanError` (code 2) : aucun contenu lu, un 0 serait ambigu |
| fichier régulier nommé `.git` (gitlink) | lu par contenu, comme tout fichier |
| scan réussi sans signature | liste vide (**périmètre lu** propre ; l'historique VCS n'est pas couvert) |

> **Garde d'usage (hook/CI) :** le scanner d'arbre bibliothèque lit tous les
> noms par contenu ; un `[]` vaut « rien trouvé dans le périmètre lu », jamais
> « historique propre ». La base VCS est élaguée par politique et comptée
> dans `TreeScanner.vcs_ignored`, les entrées non suivies ignorées dans
> `TreeScanner.git_ignored` (+ `files_scanned` pour savoir si un contenu a
> été lu). Pour un hook ou une CI, c'est la CLI `heimdall scan` qu'il faut
> utiliser avec `--strict` pour refuser (code 2) les exclusions de contenu ; elle
> analyse **sans aucune exclusion de chemin** les blobs de l'index en mode
> `--staged` (voir [cli.md](cli.md)). Un scan incomplet sort en 2, jamais en
> 0 ; un arbre vide reste un 0 assumé en local, mais `--ci` refuse (2) un
> arbre réduit à des exclusions (base VCS ou `.gitignore`) sans contenu lu.
> C'est `--staged` qui couvre le contenu indexé.

Une erreur d'outillage ne devient donc jamais un rapport réussi. Depuis
#29, la CLI est branchée : `ScanError` produit le code 2 (erreur d'outillage),
jamais 0 ni 1.

## Empreinte et entropie

- `entropy` : Shannon sur les octets UTF-8 du candidat, 0 à 8 bits/octet.
  La détection générique par seuil est livrée par [#23](scanner-entropy.md).
- `snippet_hash` : HMAC-SHA-256 avec une clé locale de 32 octets hors dépôt
  (`$HEIMDALL_SNIPPET_HMAC_KEY` en hexadécimal ou fichier XDG en `0600`). Le
  fichier doit être un fichier régulier, appartenir à l'utilisateur courant et
  n'être lisible par personne d'autre ; son répertoire parent est durci en
  `0700` et un parent symlink est refusé. Un chemin de clé contenant `..`
  (`$HEIMDALL_SNIPPET_HMAC_KEY_FILE`) est refusé : le fichier réellement
  utilisé ne doit pas pouvoir différer du fichier demandé.
- Si la clé ne peut être ni lue ni créée (stockage indisponible, permissions
  trop larges, propriétaire étranger), le scan lève `ScanError` : **aucune clé
  éphémère** ne vient masquer la panne, et les empreintes restent stables
  entre deux exécutions.
- La primitive `hmac`/`hashlib` de la bibliothèque standard n'est pas la crypto
  du Vault : l'invariant 5 (qui confine `cryptography`/`argon2` à
  `heimdall/vault/crypto.py`) reste intact. La KEK et les clés API restent
  l'affaire du Vault (ADR-001/ADR-002, clarification T22).

## Limites connues (honnêtes)

- Le scanner de signatures ne décode pas les base64 et n'analyse pas le flux
  des variables : les cas reconstruits de T21 restent des `limite_connue`. Depuis #23,
  deux valeurs encodées sont détectées par entropie, sans décodage :
  rappel 0,75 sur `all`, 1,0 sur `core`. L'allowlist relève de #24.
- Les binaires ne sont pas analysés : ils produisent une trace et un rapport
  partiel, ou un refus avec `--strict`. Aucun verdict de couverture complète
  ne doit être déduit du code 0 seul ; voir [E-01](scanner-tolerance.md).
- La jointure multiligne est bornée à 4 Kio et les jetons individuels à
  4096 caractères. Le dépassement est tracé dans le rapport tolérant ; le
  mode strict conserve les refus conservateurs sans exception par fournisseur.
- Le motif de signature JWT accepte une charge de 64 Kio et un en-tête de
  1 Kio, mais un jeton lexical > 4096 caractères est écarté avec trace ou
  refusé en mode strict, y compris pour un JWT. Les autres
  préfixes AWS (au-delà de `AKIA`/`ASIA`/`ABIA`/`ACCA`) ne sont pas couverts.
- Seules les familles de jetons Slack publiées par Slack sont couvertes
  (`xoxb-`, `xoxp-`, `xapp-`, `xwfp-`, `xoxe.` et les historiques `xoxa-`,
  `xoxr-`, `xoxs-`) : une famille ajoutée par Slack n'est pas couverte avant
  #23/#24.
- La détection PEM porte sur la ligne d'en-tête ; le corps multiligne n'est
  pas hashé. Le Finding ne fuit donc aucune valeur, mais deux clés différentes
  partagent l'empreinte de leur en-tête.
- Le scan est fichier par fichier, sans snapshot Git : le branchement diff/index
  et la protection contre les attributs Git (`textconv`) restent à faire avec
  #30 (le mode `--staged` de #29 lit l'index par blob, sans filtre
  `textconv` : `git cat-file` rend le contenu brut indexé).
- La CLI `heimdall scan` est branchée (#29) : elle prouve propre => 0, secret
  avéré => 1, erreur => 2, **sans écriture** (voir [cli.md](cli.md)). La
  validation humaine Y/N/E et le remplacement du secret restent à faire
  (#32).

## Allowlist déterministe (#24)

L'allowlist déterministe écarte les cas évidents (`example`, `changeme`, `dummy`, fixtures de test) sans passer par le LLM, utilisable en local comme en mode CI headless.

- **Fichier de configuration versionné** : [`heimdall.toml`](../heimdall.toml) à la racine du dépôt.
- **Traçabilité stricte** : aucun rejet sans règle nommée. Chaque rejet émet une trace contenant exactement : règle, fichier, ligne.
- **Transparence** : le rapport affiche toujours le nombre de findings ignorés par l'allowlist.
- **Sécurité et anti-piège** : pas d'allowlist aveugle de `tests/` — un secret réel placé dans un fichier de test reste détecté s'il ne correspond pas à une règle spécifique de factice.
- Voir [t24-samm.md](t24-samm.md) pour les preuves SAMM détaillées.

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
.venv/bin/python tests/measure_trap.py
```

Résultats historiques de la livraison #22 : **122 tests passés**, couverture du paquet
`heimdall/scanner` **91,31 %** (branches incluses), suite complète **936 tests
passés**, couverture globale **96,69 %**, mesure T21 `core` précision **1,00**,
rappel **1,00**, aucune fausse alerte sur les 18 non-leaks à cette révision.
Depuis la correction de revue #23, les étiquettes digest/data URI et UUID
ne taisent plus les candidats : huit faux positifs sont comptés honnêtement
sur ce corpus. Les résultats actuels et le seuil de précision non atteint
sont dans [scanner-entropy.md](scanner-entropy.md).
Les liens permanents et la fiche SAMM de l'épic sont dans [t22-samm.md](t22-samm.md) ;
les preuves dédiées aux exclusions #59 (module + ligne, tests et limites) sont
dans [t59-samm.md](t59-samm.md).
