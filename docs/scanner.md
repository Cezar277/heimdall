# Scanner déterministe de secrets (#22)

Statut : livré par le ticket #22 (sous-tickets #53 interface/Finding, #54
signatures, #59 exclusions, #60 tests). Contrat de sortie : [Finding v1](contracts/finding.md)
et [`schemas/finding.schema.json`](../schemas/finding.schema.json). La commande
CLI `heimdall scan` sera branchée par #29 ; le scanner est déjà utilisable comme
bibliothèque et par les tests d'acceptation T21.

## API

```python
from heimdall.scanner import Finding, RapportScan, ScannerRacine, find_candidates

scanner = ScannerRacine(".")
findings: list[Finding] = scanner.scan()
rapport: RapportScan = scanner.analyser()   # Findings + ce qui n'a pas été lu
payload: list[dict[str, object]] = find_candidates(".")  # contrat #14
```

`ScannerRacine` accepte un répertoire ou un fichier régulier explicite. `root` est
résolu une fois, **sans suivre de lien symbolique** : la racine elle-même et
chacun de ses ancêtres sont vérifiés par `lstat`, et un lien dans ce chemin
lève `ScanError` (la cible n'est pas lue à la place de la racine). Chaque
fichier est ensuite revérifié à l'usage (identité du descripteur, chemin résolu
sous la racine, refus des liens symboliques).

Un Finding contient exactement : `file`, `line`, `type`, `entropy`,
`snippet_hash`, `status` (`detecte`) et `source` (`regex`). **La valeur brute
n'est jamais conservée** : seule une empreinte HMAC-SHA-256 est produite.

### Le rapport de scan : ce qui a été lu, ce qui ne l'a pas été

`ScannerRacine.analyser()` rend un `RapportScan` : les Findings **et** les
compteurs de ce que le scan n'a pas pu analyser. Un verdict « propre » n'est
fondé que si `RapportScan.complet` est vrai.

| Champ | Signification |
| --- | --- |
| `findings` | les Findings détectés, triés |
| `binaires_ignores` | fichiers au contenu binaire connu : ignorés par politique, **tracés** |
| `non_analyses` | fichiers du périmètre que le scan n'a pas pu lire (illisibles, hors borne, modifiés) |
| `hors_perimetre` | répertoires non parcourus (base VCS) |
| `liens_ignores` | liens symboliques non suivis |

Chaque élément ignoré est **journalisé sur `stderr`** (une ligne par fichier :
le chemin seul, jamais de contenu ; les caractères de contrôle du nom sont
neutralisés pour ne pas injecter de fausse ligne de journal). La trace est
injectable (`ScannerRacine(root, journal=...)`) et le verdict sort sur `stdout`,
jamais sur `stderr`.

Règle pour #29 (à implémenter avec le branchement CLI) : **code 2** si le scan
n'est pas `complet` ou si le moteur échoue, **jamais 0** ; les compteurs du
rapport sont affichés à l'auditeur.

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

Le point (`foo.xapp-…`, `foo.xoxe.…`) n'est **pas** un frontière de mot : un
jeton collé à un préfixe de domaine ou à une concaténation reste détecté. En
revanche, le préfixe rotatif `xoxe.` est traité comme un préfixe : le jeton
qu'il contient n'est signalé qu'une fois (une seule empreinte, donc une seule
entrée Vault à révoquer).

**Fenêtre multi-ligne bornée.** Chaque ligne est analysée seule, puis
jointure avec les lignes **suivantes et contiguës** (au plus trois lignes
jointes, sans séparateur) si la fenêtre totale ne dépasse pas **4 Kio**. Un
secret coupé par un retour à la ligne (`aws_secret_access_key =` puis la
valeur à la ligne suivante) est donc détecté, et le Finding porte la ligne où
la correspondance commence. Une **ligne vide intercalée** est couverte de la
même façon (`aws_secret_access_key =`, ligne vide, puis la valeur) : la
fenêtre joint trois lignes. Au-delà de 4 Kio, ou au-delà de trois lignes
jointes, la jointure n'est pas faite : c'est une limite documentée et figée
par un test.

Une ligne peut produire plusieurs Findings de types différents. Deux **valeurs
distinctes** du même type sur la même ligne produisent **deux** Findings
(chacun avec son `entropy` et son `snippet_hash`) : le contrat Finding ne porte
pas de colonne, mais un candidat ne doit jamais disparaître. Seule une valeur
strictement identique, déjà vue sur la même ligne, est dédupliquée.

## Périmètre et politique de contenu (#59)

**Aucun nom de fichier n'exclut un fichier du scan.** Une exclusion nominale
est un contournement trivial : il suffit de renommer le fichier
(`evil.png`, `package-lock.json`, `vendor/secret.txt`…) pour qu'un secret ne
soit ni signalé ni refusé. C'est le **contenu** qui décide :

| Contenu | Traitement |
| --- | --- |
| texte (UTF-8, UTF-16, UTF-32, avec ou sans BOM) | décodé puis **scanné** |
| binaire connu (signature magique **et** contenu majoritairement binaire) | ignoré par politique, **tracé** (chemin journalisé + compteur) |
| contenu NUL non décodable, BOM invalide | `ScanError` (fail-closed) dans le périmètre strict, tracé ailleurs |

Un `evil.png` qui contient du texte est donc lu, décodé et scanné ; un vrai
PNG est ignoré, mais il laisse une trace : un dépôt propre et un dépôt dont
un binaire n'a pas été lu ne sont jamais confondus.

Les répertoires sont classés en trois régimes :

| Régime | Répertoires | Traitement |
| --- | --- | --- |
| **strict** | le contenu du dépôt | un fichier non analysable **interrompt** le scan (`ScanError`) |
| **tiers** | `.venv`, `venv`, `virtualenv`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.nox`, `htmlcov`, `node_modules`, `bower_components`, `vendor`, `third-party`, `third_party`, `build`, `dist`, `target` | **parcourus** (un secret y est un secret) ; un fichier non analysable est **tracé**, pas fatal |
| **hors périmètre** | `.git`, `.hg`, `.svn` | base VCS : ce n'est pas le contenu du dépôt ; **non parcourue**, mais **tracée** (compteur `hors_perimetre`) |

Le nom du répertoire ne sert donc qu'à qualifier la **conséquence** d'un échec
de lecture (interrompre le scan ou le tracer) : il ne dispense jamais de lire
le fichier.

Un répertoire nommé `env/` n'est **pas** un cas particulier : seuls les
environnements virtuels connus sont des arbres de tiers, et ils sont lus.

`.env`, `.env.example`, `requirements.txt`, les fichiers sans extension et les
`.pem`/`.key` sont scannés. Les mocks de `tests/` ne sont **pas** exclus
globalement : ils font partie du corpus de non-régression T21.

### Encodage des fichiers lus

Les fichiers texte sont décodés, pas ignorés :

| Cas | Traitement |
| --- | --- |
| UTF-8 (avec ou sans BOM) | décodage strict avec BOM, remplacement sans BOM |
| UTF-16 / UTF-32 avec BOM | décodage strict, fichier scanné |
| UTF-16 / UTF-32 sans BOM | heuristique bornée (proportion ASCII puis caractères imprimables), fichier scanné |
| signature binaire **et** contenu majoritairement binaire (≥ 50 % d'octets non textuels) | ignoré par politique, tracé |
| signature binaire suivie de texte clair | refus (`ScanError` strict, tracé ailleurs) |
| contenu NUL non décodable | refus (`ScanError` strict, tracé ailleurs) |

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
| fichier non régulier (FIFO, device) | `ScanError` (tracé dans un arbre de tiers) |
| fichier > 1 Mio | `ScanError` (tracé dans un arbre de tiers) |
| fichier modifié pendant la lecture | `ScanError` (tracé dans un arbre de tiers) |
| nom de fichier hors contrat (`..`, `:`, contrôle) | `ScanError` (tracé dans un arbre de tiers) |
| clé HMAC absente, illisible, trop permissive ou impossible à créer | `ScanError` |
| clé HMAC demandée avec `..` dans le chemin | `ScanError` |
| contenu NUL non décodable (hors binaire réellement binaire) | `ScanError` (tracé dans un arbre de tiers) |
| binaire connu | ignoré par politique, **tracé** (compteur `binaires_ignores`) |
| lien symbolique | jamais suivi, **tracé** (compteur `liens_ignores`) |
| base VCS (`.git/`, `.hg/`, `.svn/`) | non parcourue, **tracée** (compteur `hors_perimetre`) |
| scan réussi sans signature | liste vide (réellement propre) |

Un scan incomplet ne devient donc jamais une liste vide ou partielle. Quand
#29 branchera la CLI, `ScanError` devra produire le code 2 (erreur d'outillage),
jamais 0 ou 1.

> **Garde d'usage (hook/CI) :** ne pas utiliser ce scanner bibliothèque tel
> quel pour un hook ou une CI. Un `[]` sur dépôt complet peut masquer un secret
> contenu dans un **binaire** (contenu non lu, tracé mais pas signalé) ou
> coupé au-delà de la fenêtre 4 Kio ; dans un arbre de tiers, un fichier non
> analysable est tracé, pas fatal. #29 doit scanner tout blob stagé et
> prouver 0/1/2 end-to-end ; en attendant, aucun usage CI du scan réel n'est
> autorisé (la CLI reste en stub, sortie 2). Voir limites ci-dessous.

## Empreinte et entropie

- `entropy` : Shannon sur les octets UTF-8 du candidat, 0 à 8 bits/octet.
  Cette valeur est une métadonnée ; la détection par seuil appartient à #23.
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
  des variables : les six cas obfusqués de T21 restent des `limite_connue`
  (rappel 0,625 sur `all`, 1,0 sur le périmètre `core`). Le décodage/entropie
  relève de #23 et l'allowlist de #24.
- Un **binaire** n'est pas analysé : un secret glissé dans un commentaire ZIP
  ou PNG n'est pas signalé. Le fichier est **tracé** (chemin journalisé,
  compteur `binaires_ignores`), donc l'auditeur le voit, mais le contenu n'est
  pas lu. C'est la seule catégorie de contenu non analysable tolérée.
- La **base VCS** (`.git/`, `.hg/`, `.svn/`) n'est pas parcourue : ses objets
  sont compressés et l'historique n'est pas le contenu du dépôt (c'est le
  travail de #29/#30, sur le diff indexé). Le répertoire est **tracé**
  (compteur `hors_perimetre`).
- Un fichier **non analysable** dans un arbre de tiers (`.venv`,
  `node_modules`, `vendor`…) est tracé, pas fatal : ces arbres sont massifs et
  tiers. Un secret y placed dans un binaire ou un fichier hors borne n'est donc
  pas signalé — c'est le prix de la robustesse sur des arbres non audités.
- La jointure multi-ligne est bornée à 4 Kio et à **trois lignes jointes** : un
  secret coupé par plus de deux retours à la ligne consécutifs n'est pas
  recherché. C'est une limite figée par un test.
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
  #29/#30.
- La CLI `heimdall scan` reste en stub (sortie 2, « voir #29 ») : aucun usage
  CI du scan réel n'est autorisé avant #29, qui devra prouver propre => 0,
  secret avéré => 1, erreur => 2, sans écriture.

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_scanner_interface.py tests/test_scanner_signatures.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
.venv/bin/python tests/measure_trap.py
```

Résultats de la livraison : **445 tests passés**, couverture du paquet
`heimdall/scanner` **98,36 %** (branches incluses), suite complète **1 455 tests
passés** (+ 4 317 sous-tests), couverture globale **96,59 %**, mesure T21
`core` précision **1,00**, rappel **1,00**, aucune fausse alerte sur les 18
non-leaks.
Les liens permanents et la fiche SAMM sont dans [t22-samm.md](t22-samm.md).
