# Scanner déterministe de secrets (#22)

Statut : livré par le ticket #22 (sous-tickets #53 interface/Finding, #54
signatures, #59 exclusions, #60 tests). Contrat de sortie : [Finding v1](contracts/finding.md)
et [`schemas/finding.schema.json`](../schemas/finding.schema.json). La commande
CLI `heimdall scan` sera branchée par #29 ; le scanner est déjà utilisable comme
bibliothèque et par les tests d'acceptation T21.

## API

```python
from heimdall.scanner import Finding, Scanner, find_candidates

findings: list[Finding] = Scanner(".").scan()
payload: list[dict[str, object]] = find_candidates(".")  # contrat #14
```

`Scanner` accepte un répertoire ou un fichier régulier explicite. `root` est
résolu une fois ; chaque fichier est revérifié à l'usage (identité du
descripteur, chemin résolu sous la racine, refus des liens symboliques).

Un Finding contient exactement : `file`, `line`, `type`, `entropy`,
`snippet_hash`, `status` (`detecte`) et `source` (`regex`). **La valeur brute
n'est jamais conservée** : seule une empreinte HMAC-SHA-256 est produite.

## Signatures (#54)

| Règle | Type Finding | Forme attendue |
| --- | --- | --- |
| `aws_access_key_id` | `aws` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 caractères majuscules/chiffres |
| `aws_secret_access_key` | `aws` | affectation `aws_secret_access_key` + 40 caractères |
| `stripe_secret_key` | `stripe` | `sk_live_`/`sk_test_`/`rk_live_`/`rk_test_` + charge |
| `slack_token` | `slack` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `github_classic_pat` | `pat` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 caractères |
| `github_fine_grained_pat` | `pat` | `github_pat_` + charge |
| `jwt` | `jwt` | trois segments base64url, en-tête `eyJ`, charge ≤ 64 Kio |
| `pem_private_key` | `pem` | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, OPENSSH, PGP, chiffrée) |

Les motifs sont linéaires et bornés : pas de quantification imbriquée, pas de
`.*`, bornes explicites pour les charges. Les tests anti-ReDoS exécutent le
scanner sur des lignes proches de 1 Mio (`tests/test_scanner_detect.py`).

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
  `target`, caches Python ;
- lockfiles : suffixe `.lock`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `go.sum`, `bun.lockb` ;
- binaires : extension connue ou signature magique connue (ELF, PNG, PDF, ZIP…).

Un répertoire nommé `env/` n'est **pas** exclu : seuls les environnements
virtuels connus le sont. Un dossier de sources `env/` est donc scanné.

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
| contenu NUL non décodable et sans signature binaire | `ScanError` (fail-closed) |
| binaire à extension connue ou à signature magique | ignoré par politique |

Un secret encodé en UTF-16/UTF-32 est donc détecté ; il n'est plus sauté
silencieusement.

## Comportement fail-closed

Toute situation non analysable lève `ScanError` avec un message statique
`scan impossible : entrée non analysable`, sans chemin ni extrait de fichier :

| Situation | Résultat |
| --- | --- |
| racine absente, non régulière ou illisible | `ScanError` |
| fichier non régulier (FIFO, device) | `ScanError` |
| fichier > 1 Mio | `ScanError` |
| fichier modifié pendant la lecture | `ScanError` |
| nom de fichier hors contrat (`..`, `:`, contrôle) | `ScanError` |
| clé HMAC absente, illisible, trop permissive ou impossible à créer | `ScanError` |
| contenu NUL non décodable (hors binaire connu) | `ScanError` |
| fichier exclu ou binaire connu | ignoré par politique |
| scan réussi sans signature | liste vide (réellement propre) |

Un scan incomplet ne devient donc jamais une liste vide ou partielle. Quand
#29 branchera la CLI, `ScanError` devra produire le code 2 (erreur d'outillage),
jamais 0 ou 1.

## Empreinte et entropie

- `entropy` : Shannon sur les octets UTF-8 du candidat, 0 à 8 bits/octet.
  Cette valeur est une métadonnée ; la détection par seuil appartient à #23.
- `snippet_hash` : HMAC-SHA-256 avec une clé locale de 32 octets hors dépôt
  (`$HEIMDALL_SNIPPET_HMAC_KEY` en hexadécimal ou fichier XDG en `0600`). Le
  fichier doit être un fichier régulier, appartenir à l'utilisateur courant et
  n'être lisible par personne d'autre ; son répertoire parent est durci en
  `0700` et un parent symlink est refusé.
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
- Les fichiers binaires, lockfiles et répertoires tiers sont ignorés par
  politique : un secret qui y serait copié n'est pas signalé.
- La charge d'un JWT est bornée à 64 Kio et l'en-tête à 1 Kio : un jeton
  conforme est détecté, un jeton hors de ces bornes ne l'est pas. Les autres
  préfixes AWS (au-delà de `AKIA`/`ASIA`/`ABIA`/`ACCA`) ne sont pas couverts.
- La détection PEM porte sur la ligne d'en-tête ; le corps multiligne n'est
  pas hashé. Le Finding ne fuit donc aucune valeur, mais deux clés différentes
  partagent l'empreinte de leur en-tête.
- Le scan est fichier par fichier, sans snapshot Git : le branchement diff/index
  et la protection contre les attributs Git (`textconv`) restent à faire avec
  #29/#30.

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
.venv/bin/python tests/measure_trap.py
```

Résultats de la livraison : **102 tests passés**, couverture du paquet
`heimdall/scanner` **90,66 %** (branches incluses), suite complète **916 tests
passés**, mesure T21 `core` précision **1,00**, rappel **1,00**, aucune fausse
alerte sur les 18 non-leaks.
Les liens permanents et la fiche SAMM sont dans [t22-samm.md](t22-samm.md).
