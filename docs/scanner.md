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

# Mode strict (#29) : accepté pour compatibilité ; seule la base VCS est
# écartée, quel que soit le mode. Tous les autres noms sont lus par contenu.
strict: list[Finding] = TreeScanner(".", strict=True).scan()

# La base VCS est élaguée par politique, sans ScanError. Le compteur rend
# cet élagage observable : un [] ne prouve jamais un historique propre.
scanner = TreeScanner(".")
findings = scanner.scan()
bases_vcs_ignorees: int = scanner.vcs_ignored
fichiers_lus: int = scanner.files_scanned  # contenu réellement analysé
```

La CLI propage ce compteur dans `ScanReport.vcs_ignored`, le champ
`vcs_ignored` du JSON `--json` et le résumé `--ci` sur stderr (voir
[cli.md](cli.md)).

Le scanner d'arbre est `heimdall.scanner.detect.Scanner` (alias
`TreeScanner` ci-dessus) : c'est lui qui porte `vcs_ignored` et les bornes de
parcours. `heimdall.scanner.Scanner` est une autre surface, la **façade de
cibles** `DiffTarget`/`FileTarget` avec un moteur injecté (voir
[scanner-interface.md](scanner-interface.md)) ; `find_candidates()` reste le
raccourci public pour obtenir directement les dictionnaires du contrat #14.

`TreeScanner` accepte un répertoire ou un fichier régulier explicite. `root` est
résolu une fois, **sans suivre de lien symbolique** : la racine elle-même et
chacun de ses ancêtres sont vérifiés par `lstat`, et un lien dans ce chemin
lève `ScanError` (la cible n'est pas lue à la place de la racine). Chaque
fichier est ensuite revérifié à l'usage (identité du descripteur, chemin résolu
sous la racine, refus des liens symboliques). La racine parcourue est
re-contrôlée avant le walk, **ancêtres compris**, et son identité
(`st_dev`, `st_ino`) doit être celle figée à la construction : un ancêtre
remplacé par un lien ou un répertoire substitué au même chemin est refusé
avant toute lecture.

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
build…) n'est exclu du scan : un secret y est un secret. Un fichier texte
nommé `evil.png` est lu et scanné comme un `.txt`.

Seule la **base VCS** (`.git/`, `.hg/`, `.svn/`) est élaguée : ce n'est pas le
contenu du dépôt, et son historique n'est jamais parcouru par le mode arbre.
Cet élagage est une politique, pas un échec de lecture : il ne lève pas
`ScanError`, mais il est **compté** dans `TreeScanner.vcs_ignored` pour que
l'appelant distingue « aucune base VCS » de « base VCS non parcourue ». Un
`[]` vaut donc « rien trouvé dans le périmètre lu », jamais « historique
propre » ; `--staged` couvre le contenu indexé (ce que le commit va
contenir), pas les commits déjà écrits.

`TreeScanner.files_scanned` expose le nombre de fichiers de contenu
effectivement lus. Un dépôt vide (seule la base VCS existe) reste un verdict
0 : il est réellement vide, pas illisible. Un arbre réduit à `.git/config`
rend donc 0 avec `vcs_ignored == 1` et `files_scanned == 0` ; c'est pourquoi
`--staged` est le périmètre opposable pour le contenu indexé et que le résumé
`--ci` rappelle toujours le nombre de bases élaguées. Dès qu'au moins un
fichier de contenu a été lu, l'élagage VCS reste une politique observable
sans transformer un dépôt réel en erreur.

Un fichier régulier nommé `.git` est un **gitlink** légitime (worktree,
sous-module : `gitdir: …`), pas le répertoire `.git/` : seul un segment
**parent** de chemin peut classer hors périmètre. Son contenu est lu comme
celui de tout autre fichier.

`strict` reste accepté pour compatibilité ; il ne change plus le périmètre
(seule la base VCS est écartée dans tous les modes). C'est la correction du
point HIGH relevé à la revue de #165 : la politique #59 laissait passer un
secret posé dans `vendor/evil.py`, sans jamais le signaler.

Un contenu binaire **connu** (signature magique et majorité binaire) n'est pas
silencieusement ignoré : le scanner lève `ScanError`. Un binaire inconnu
(NUL + texte) reste fail-closed de la même façon : le nom ni le suffixe ne
convertissent jamais un doute en skip silencieux.

> **API dépréciée, sans autorité.** `heimdall.scanner.exclusions.is_known_binary`
> reste importable pour compatibilité historique, mais le scanner ne l'appelle
> **jamais** : `decode_text` passe par le helper interne `_is_known_binary`.
> Il ne figure pas dans `__all__` du module, et aucun nouvel appelant ne doit
> s'en servir pour décider qu'un fichier est « ignorable par son nom » : le
> contenu décide, et un binaire non reconnu lève `ScanError`. Un appelant qui
> l'utiliserait pour exclure un fichier sans analyser son contenu
> réintroduirait le contournement corrigé par #59. Sa suppression est prévue
> dans un ticket dédié ; d'ici là, seul le contenu décide.

### Encodage des fichiers lus

Les fichiers texte sont décodés, pas ignorés :

| Cas | Traitement |
| --- | --- |
| UTF-8 (avec ou sans BOM) | décodage strict ; octet invalide → `ScanError` (#23) |
| UTF-16 / UTF-32 avec BOM | décodage strict, fichier scanné |
| UTF-16 / UTF-32 sans BOM | heuristique bornée (proportion ASCII puis caractères imprimables), fichier scanné |
| signature binaire **et** contenu majoritairement binaire (≥ 50 % d'octets non textuels) | `ScanError` (binaire connu, jamais un skip silencieux) en arbre **comme** en `--staged` |
| signature binaire suivie de texte clair | `ScanError` (fail-closed) |
| contenu NUL non décodable | `ScanError` (fail-closed) |

Un secret encodé en UTF-16/UTF-32 est donc détecté ; il n'est plus sauté
silencieusement. Quatre octets de signature binaire (`PK\x03\x04`, en-tête
PNG…) ne suffisent plus à faire ignorer un fichier : la signature n'est retenue
que si le contenu est réellement majoritairement binaire, sinon le fichier est
refusé (`ScanError`) plutôt que sauté.

## Comportement fail-closed

Toute situation non analysable lève `ScanError` avec un message statique
`scan impossible : entrée non analysable`, sans chemin ni extrait de fichier :

| Situation | Résultat |
| --- | --- |
| racine absente, non régulière ou illisible | `ScanError` |
| racine ou fichier unique symlinké (ou ancêtre symlinké) | `ScanError` |
| racine non canonique (ex. `/tmp` symlinké vers `/private/tmp` sur macOS) | `ScanError` — passer un chemin canonique (sans lien) |
| fichier non régulier (FIFO, device) | `ScanError` |
| fichier > 1 Mio | `ScanError` |
| plus de 50 000 fichiers, ou plus de 256 Mio lus au total | `ScanError` (bornes #29) |
| borne explicite `max_files`/`max_bytes`/`max_findings` hors de `1..plafond` | `ValueError` à la construction (surcharge jamais silencieuse) |
| fichier modifié pendant la lecture | `ScanError` |
| nom de fichier hors contrat (`..`, `:`, contrôle) | `ScanError` |
| clé HMAC absente, illisible, trop permissive ou impossible à créer | `ScanError` |
| clé HMAC demandée avec `..` dans le chemin | `ScanError` |
| contenu NUL non décodable (y compris un binaire connu) | `ScanError` |
| fichier ou répertoire symlinké **interne** au périmètre | `ScanError` (jamais suivi) |
| base VCS `.git/`, `.hg/`, `.svn/` | élaguée par politique, comptée dans `TreeScanner.vcs_ignored` |
| arbre vide (seule la base VCS existe) | liste vide (0) : arbre réellement vide, `files_scanned == 0` et `vcs_ignored == 1` |
| fichier régulier nommé `.git` (gitlink) | lu par contenu, comme tout fichier |
| scan réussi sans signature | liste vide (**périmètre lu** propre ; l'historique VCS n'est pas couvert) |

> **Garde d'usage (hook/CI) :** le scanner d'arbre bibliothèque lit tous les
> noms par contenu ; un `[]` vaut « rien trouvé dans le périmètre lu », jamais
> « historique propre ». La base VCS est élaguée par politique et comptée
> dans `TreeScanner.vcs_ignored` (+ `files_scanned` pour savoir si un contenu
> a été lu). Pour un hook ou une CI, c'est la CLI `heimdall scan` qu'il faut
> utiliser : elle refuse (code 2) tout fichier du périmètre non analysable et
> analyse **sans aucune exclusion de chemin** les blobs de l'index en mode
> `--staged` (voir [cli.md](cli.md)). Un scan incomplet sort en 2, jamais en
> 0 ; un arbre vide reste un 0 assumé, c'est `--staged` qui couvre le
> contenu indexé.

Un scan incomplet ne devient donc jamais une liste vide ou partielle. Depuis
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
- Les fichiers binaires connus ne sont pas analysés : un secret placé dans un
  binaire reste un faux négatif. Dans **les deux périmètres**, le scanner
  **refuse** le fichier ou le blob (`ScanError`, code 2 pour la CLI) au lieu
  de l'ignorer silencieusement. Les répertoires et fichiers textuels de
  `node_modules/`, `vendor/`, `.venv/`, `build/`, `dist/`, `target/` ou
  `htmlcov/` sont, eux, scannés dans les deux périmètres : aucun nom de
  fichier ou de répertoire de contenu n'exclut plus rien. Seule la base VCS
  est élaguée, et ce n'est pas du contenu.
- La jointure multi-ligne est bornée à 4 Kio. Une affectation ou un jeton de
  longueur candidate sur une des lignes provoque `ScanError` lorsque cette
  borne est dépassée, sans exception par fournisseur. Les jetons individuels
  > 4096 caractères provoquent également `ScanError`, jamais un skip.
- Le motif de signature JWT accepte une charge de 64 Kio et un en-tête de
  1 Kio, mais le moteur refuse désormais tout jeton lexical > 4096 caractères
  (`ScanError`, y compris pour un JWT). Les autres
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
Les liens permanents et la fiche SAMM sont dans [t22-samm.md](t22-samm.md).
