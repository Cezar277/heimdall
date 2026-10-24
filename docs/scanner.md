# Scanner déterministe de secrets (#22)

Statut : livré par le ticket #22 (sous-tickets #53 interface/Finding, #54
signatures, #59 exclusions, #60 tests). Contrat de sortie : [Finding v1](contracts/finding.md)
et [`schemas/finding.schema.json`](../schemas/finding.schema.json). La commande
CLI `heimdall scan` est branchée par #29 (voir [cli.md](cli.md)) ; le scanner
est aussi utilisable comme bibliothèque et par les tests d'acceptation T21.

## API

```python
from heimdall.scanner import Finding, Scanner, find_candidates

findings: list[Finding] = Scanner(".").scan()
payload: list[dict[str, object]] = find_candidates(".")  # contrat #14

# Mode strict (#29) : seules les exclusions techniques restent, les
# répertoires et fichiers tiers textuels (vendor/, lockfiles) sont analysés.
strict: list[Finding] = Scanner(".", strict=True).scan()
```

`Scanner` accepte un répertoire ou un fichier régulier explicite. `root` est
résolu une fois, **sans suivre de lien symbolique** : la racine elle-même et
chacun de ses ancêtres sont vérifiés par `lstat`, et un lien dans ce chemin
lève `ScanError` (la cible n'est pas lue à la place de la racine). Chaque
fichier est ensuite revérifié à l'usage (identité du descripteur, chemin résolu
sous la racine, refus des liens symboliques).

Un Finding contient exactement : `file`, `line`, `type`, `entropy`,
`snippet_hash`, `status` (`detecte`) et `source` (`regex` ou `entropy`). **La valeur brute
n'est jamais conservée** : seule une empreinte HMAC-SHA-256 est produite.

La détection générique par entropie (#23), ses seuils et le contexte local
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
de 4 Kio, la jointure n'est pas faite. Une affectation AWS sans valeur
reconnue sur la ligne courante lève alors `ScanError` (#23).

Une ligne peut produire plusieurs Findings de types différents. Deux **valeurs
distinctes** du même type sur la même ligne produisent **deux** Findings
(chacun avec son `entropy` et son `snippet_hash`) : le contrat Finding ne porte
pas de colonne, mais un candidat ne doit jamais disparaître. Seule une valeur
strictement identique, déjà vue sur la même ligne, est dédupliquée.

## Exclusions (#59)

Politique explicite, jamais une heuristique :

- fichiers de contrôle : `.gitignore`, `.gitattributes`, `.dockerignore`,
  `.npmignore`, `.coverage` ;
- répertoires : `.git`, `.hg`, `.svn`, environnements virtuels (`.venv`, `venv`,
  `virtualenv`), `vendor`, `node_modules`, `third_party`, `build`, `dist`,
  `target`, `bower_components`, `htmlcov`, caches Python ;
- lockfiles : suffixe `.lock`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `go.sum`, `bun.lockb` ;
- binaires : extension connue, ou signature magique connue **et** contenu
  majoritairement binaire (ELF, PNG, PDF, ZIP…).

Un répertoire nommé `env/` n'est **pas** exclu : seuls les environnements
virtuels connus le sont. Un dossier de sources `env/` est donc scanné.

`.env`, `.env.example`, `requirements.txt`, les fichiers sans extension et les
`.pem`/`.key` sont scannés. Les mocks de `tests/` ne sont **pas** exclus
globalement : ils font partie du corpus de non-régression T21.

### Deux familles d'exclusions, et le mode strict (#29)

Les exclusions ci-dessus se répartissent en deux familles, et cette
répartition fonde le mode **strict** livré par #29 (`heimdall scan`) :

| Famille | Contenu | Mode strict |
| --- | --- | --- |
| **technique** | binaires, dépendances et environnements (`.git`, `node_modules`, `.venv`, `__pycache__`, caches…), `.coverage`, `bun.lockb` | **exclus** (ils sont illisibles ou illisibles par des expressions de texte) |
| **contenu texte** | `vendor/`, `third_party/`, `third-party/`, sorties de build (`build/`, `dist/`, `target/`, `bower_components/`, `htmlcov/`), lockfiles, `.gitignore` et autres fichiers de contrôle | **analysés** (un secret y est un secret) |

`Scanner(root, strict=True)` (et `scan(root, strict=True)`) ne conserve que la
première famille. C'est la correction du point HIGH relevé à la revue de #165 :
la politique #59 seule laissait passer un secret posé dans `vendor/evil.py`,
sans jamais le signaler. Le mode strict est le comportement par défaut de la
CLI `heimdall scan` (voir [cli.md](cli.md)).

En strict, l'extension binaire ne prime plus sur le contenu : un fichier texte
nommé `evil.png` est lu et scanné, comme en `--staged`. Un vrai binaire reste
exclu par sa signature **connue** (magie + majorité binaire). Un binaire
inconnu (NUL + texte) reste fail-closed comme en `--staged` : le suffixe ne
convertit jamais un doute en skip silencieux.

### Encodage des fichiers lus

Les fichiers texte sont décodés, pas ignorés :

| Cas | Traitement |
| --- | --- |
| UTF-8 (avec ou sans BOM) | décodage strict ; octet invalide → `ScanError` (#23) |
| UTF-16 / UTF-32 avec BOM | décodage strict, fichier scanné |
| UTF-16 / UTF-32 sans BOM | heuristique bornée (proportion ASCII puis caractères imprimables), fichier scanné |
| signature binaire **et** contenu majoritairement binaire (≥ 50 % d'octets non textuels) | ignoré par politique |
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
| contenu NUL non décodable (hors binaire réellement binaire) | `ScanError` |
| fichier ou répertoire symlinké **interne** au périmètre | ignoré par politique (non suivi, non signalé ; voir #59) |
| fichier exclu ou binaire connu | ignoré par politique |
| scan réussi sans signature | liste vide (réellement propre **hors exclusions** — voir limites) |

> **Garde d'usage (hook/CI) :** le `Scanner` bibliothèque reste en politique
> #59 (exclusions de contenu texte comprises) : un `[]` sur dépôt complet y
> vaut « propre **hors exclusions** ». Pour un hook ou une CI, c'est la CLI
> `heimdall scan` qu'il faut utiliser : elle applique le **mode strict** sur
> l'arbre de travail et analyse **sans aucune exclusion** les blobs de l'index
> en mode `--staged` (voir [cli.md](cli.md)). Un scan incomplet y sort en 2,
> jamais en 0.

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
- Les fichiers binaires, lockfiles et répertoires tiers sont ignorés par
  la politique #59 **de la bibliothèque** : un secret qui y serait copié n'est
  pas signalé. En mode dépôt complet, `[]` vaut donc « propre hors
  exclusions », jamais « propre absolu ». Depuis #29, la **CLI** applique le
  mode strict (arbre de travail) ou l'analyse **sans exclusion** des blobs
  indexés (`--staged`) : ce blocage est levé pour la CLI, il reste entier
  pour l'usage bibliothèque, et #59 garde la main sur la politique.
- La jointure multi-ligne est bornée à 4 Kio. Une affectation AWS sans
  valeur reconnue dont la jointure dépasse cette borne lève `ScanError`
  depuis #23 ; les autres reconstructions ne sont pas interprétées.
- La charge d'un JWT est bornée à 64 Kio et l'en-tête à 1 Kio : un jeton
  conforme est détecté, un jeton hors de ces bornes ne l'est pas. Les autres
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

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
.venv/bin/python tests/measure_trap.py
```

Résultats de la livraison : **122 tests passés**, couverture du paquet
`heimdall/scanner` **91,31 %** (branches incluses), suite complète **936 tests
passés**, couverture globale **96,69 %**, mesure T21 `core` précision **1,00**,
rappel **1,00**, aucune fausse alerte sur les 18 non-leaks.
Les liens permanents et la fiche SAMM sont dans [t22-samm.md](t22-samm.md).
