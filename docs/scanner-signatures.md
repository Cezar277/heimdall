# Signatures de secrets (#54)

Statut : livré par le ticket #54 et ses quatre sous-tickets #55 à #58. Ce
document décrit le **registre déclaratif** des signatures et le **moteur
déterministe** qui le branche sur l'interface du scanner (#53).

Références :

- registre : [`heimdall/scanner/signatures/`](../heimdall/scanner/signatures/)
  (un fichier par famille) ;
- modèle et validation : [`model.py`](../heimdall/scanner/signatures/model.py) ;
- moteur : [`signature_engine.py`](../heimdall/scanner/signature_engine.py) ;
- empreinte : [`hashing.py`](../heimdall/scanner/hashing.py) ; entropie :
  [`entropy.py`](../heimdall/scanner/entropy.py) ;
- interface et sortie : [scanner-interface.md](scanner-interface.md), contrat
  [Finding v1](contracts/finding.md) et
  [`schemas/finding.schema.json`](../schemas/finding.schema.json) ;
- tests : [`tests/test_scanner_signatures.py`](../tests/test_scanner_signatures.py) ;
- preuves SAMM : [t54-samm.md](t54-samm.md).

## En une phrase

Le registre est la **seule source de vérité** des signatures : dix règles
réparties en quatre familles, chacune avec un exemple positif et un exemple
négatif vérifiés **à l'import** ; le moteur les applique aux cibles déjà
validées par #53 et ne rend que des `Finding` sans valeur brute.

## Périmètre

| Famille | Fichier | Sous-ticket | Règles |
| --- | --- | --- | --- |
| AWS / cloud | [`aws_cloud.py`](../heimdall/scanner/signatures/aws_cloud.py) | #55 | 2 |
| Stripe / Slack | [`stripe_slack.py`](../heimdall/scanner/signatures/stripe_slack.py) | #56 | 4 |
| GitHub PAT / JWT | [`github_jwt.py`](../heimdall/scanner/signatures/github_jwt.py) | #57 | 3 |
| Clés privées PEM | [`pem.py`](../heimdall/scanner/signatures/pem.py) | #58 | 1 |

Total : **10 règles**. Les autres fournisseurs cloud (GCP, Azure,
DigitalOcean) ne sont pas inclus : leurs formats ne sont pas spécifiés par le
découpage et une règle trop large produirait plus de faux positifs que de
détections utiles. Les exclusions de fichiers, le parcours du dépôt et la
détection par entropie restent hors de ce ticket (#59/#60).

## Le contrat d'une règle

Une règle est une dataclass figée avec exactement les champs suivants :

| Champ | Rôle |
| --- | --- |
| `id` | identifiant stable en `snake_case`, unique dans le registre, ≤ 64 caractères |
| `description` | ce que la règle reconnaît, en une phrase |
| `regex` | motif compilé, avec un groupe nommé `value` qui isole le candidat |
| `secret_type` | valeur du champ `type` du Finding (`aws`, `stripe`, `slack`, `pat`, `jwt`, `pem`) |
| `keywords` | mots-clés de contexte optionnels, comparés sans tenir compte de la casse |
| `positive_example` | exemple **synthétique** qui doit être reconnu |
| `negative_example` | exemple **synthétique** qui ne doit produire aucune correspondance |

La validation est **fail-closed au chargement du module** :

- identifiant et type Finding conformes à la grammaire `snake_case` bornée ;
- description, motif et exemples non vides ;
- regex compilable et contenant le groupe nommé `value` ;
- exemple positif reconnu, exemple négatif ignoré ;
- registre non vide et identifiants uniques.

Une règle qui ment sur ses exemples empêche donc l'import du scanner : le
registre ne peut pas être silencieusement faux. `make_rule()` construit la
règle **positionnellement** pour que le SAST (Bandit B106) ne confonde pas le
nom du champ `secret_type` avec un mot de passe codé en dur.

## Les dix règles

Les valeurs complètes des exemples ne figurent pas dans ce document : les
motifs ci-dessous décrivent l'ancrage et les bornes, pas un secret utilisable.

| Règle | Famille | `type` | Ancrage et borne | Mots-clés |
| --- | --- | --- | --- | --- |
| `aws_access_key_id` | AWS #55 | `aws` | préfixe `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 caractères `[0-9A-Z]`, frontières alphanumériques | — |
| `aws_secret_access_key` | AWS #55 | `aws` | paramètre `aws_secret_access_key` puis 40 caractères `[A-Za-z0-9/+=]` | `aws_secret_access_key`, `aws_secret_key`, `secret_access_key` |
| `stripe_secret_key` | Stripe/Slack #56 | `stripe` | `sk_` ou `rk_`, puis `live`/`test`, puis 16 à 247 caractères `[A-Za-z0-9]` | — |
| `slack_token` | Stripe/Slack #56 | `slack` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-` ou `xoxs-` + 10 à 250 caractères `[A-Za-z0-9-]` | — |
| `slack_app_token` | Stripe/Slack #56 | `slack` | `xapp-` ou `xwfp-` + 10 à 250 caractères `[A-Za-z0-9-]` | — |
| `slack_rotating_token` | Stripe/Slack #56 | `slack` | `xoxe.` + 10 à 250 caractères `[A-Za-z0-9-]` | — |
| `github_classic_pat` | GitHub/JWT #57 | `pat` | `ghp_`, `gho_`, `ghu_`, `ghs_` ou `ghr_` + exactement 36 caractères `[A-Za-z0-9]` | — |
| `github_fine_grained_pat` | GitHub/JWT #57 | `pat` | `github_pat_` + 22 à 255 caractères `[A-Za-z0-9_]` | — |
| `jwt` | GitHub/JWT #57 | `jwt` | en-tête `eyJ` puis trois segments base64url bornés (1024 / 65 536 / 1024) | — |
| `pem_private_key` | PEM #58 | `pem` | `-----BEGIN` + qualificatif ≤ 64 caractères + `PRIVATE KEY-----` (ou `PRIVATE KEY BLOCK-----`) | — |

Chaque motif est ancré sur un **préfixe publié** ou sur un **nom de paramètre
explicite**. Une chaîne aléatoire de 40 caractères **sans préfixe ni nom de
paramètre**, un UUID, un hash SHA-256 ou une image base64 ne sont jamais
signalés par ces règles.

## Comment un candidat devient un Finding

1. `find_signature_matches(line)` parcourt les règles dans l'ordre stable du
   registre, applique le filtre de mots-clés s'il existe, puis `finditer()`.
2. Les correspondances sont dédupliquées par `(type, valeur)` : une même
   valeur répétée sur la même ligne ne produit qu'un candidat, mais deux
   valeurs distinctes du même type restent deux candidats.
3. `SignatureEngine.analyser(cible)` analyse chaque ligne de la cible, puis
   joint la ligne suivante **si la somme fait au plus 4 Kio** (voir ci-dessous).
4. Chaque candidat devient un `Finding` #53 : `status="detecte"`,
   `source="regex"`, le type de la règle, l'entropie de Shannon du candidat et
   son empreinte HMAC-SHA-256.
5. La façade `Scanner` revalide les Findings, les trie et garantit qu'aucune
   valeur brute ne sort du moteur.

Le moteur ne lit **aucun fichier** : la cible `DiffTarget` ou `FileTarget` a
déjà été validée par #53. Le parcours du dépôt, les exclusions et la lecture
confinée appartiennent à #59.

### Secret coupé sur deux lignes

Un secret peut être coupé par un retour à la ligne, par exemple un paramètre
suivi de sa valeur entre guillemets sur la ligne suivante. Le moteur joint donc
deux lignes consécutives, dans une fenêtre **bornée à 4 Kio** :

- si `len(ligne) + len(ligne_suivante) > 4096`, aucune jointure n'est faite ;
- une correspondance qui commence après la frontière appartient à la ligne
  suivante et est ignorée lors de la jointure, pour ne pas produire de doublon ;
- le Finding est attribué à la ligne de **début** de la correspondance.

Cette fenêtre est volontairement limitée : elle couvre les coupures de mise en
forme courantes sans transformer le scanner en analyseur de fichier entier.
Un secret étalé sur trois lignes ou au-delà de 4 Kio n'est pas détecté par
cette version ; la limite est testée.

## Jamais de valeur brute

Le Finding ne contient ni `value`, ni extrait, ni `snippet` :

- `snippet_hash` est un HMAC-SHA-256 hexadécimal du candidat (ADR-001) ;
- `entropy` est une métadonnée (0 à 8 bits par octet), pas une valeur ;
- les exceptions et les `repr` ne reflètent jamais le contenu analysé.

La clé HMAC fait 32 octets et vit **hors du dépôt** :
`$HEIMDALL_SNIPPET_HMAC_KEY` (hexadécimal) ou, à défaut,
`$XDG_DATA_HOME/heimdall/snippet-hmac.key` (défaut
`~/.local/share/heimdall/snippet-hmac.key`). Le fichier est créé en `0600`,
son répertoire parent est durci en `0700`, et une clé lisible par un autre
utilisateur est refusée. Aucune clé éphémère ne masque une panne : une lecture
ou une création impossible lève `ScanError`. Une même clé produit donc des
empreintes stables entre deux exécutions, sans jamais permettre de retrouver
la valeur.

## Anti-ReDoS

Le contenu scanné est contrôlé par un attaquant (fichier ou diff piégé). Une
regex qui explose en backtracking bloquerait le scanner ; les règles respectent
donc trois contraintes :

- **ancrage** sur un préfixe ou un nom de paramètre, jamais sur « 40
  caractères ressemblant à un secret » ;
- **bornes explicites** sur toute répétition de contenu arbitraire (Stripe,
  Slack, GitHub fine-grained, JWT, PEM) ;
- **aucun quantificateur imbriqué** : les répétitions sont plates et les
  frontières `(?<!…)` / `(?!…)` sont de largeur fixe.

Le test paramétré applique chaque règle à deux lignes hostiles de
**100 000 caractères** : un remplissage sans correspondance et un préfixe PEM
qui force le moteur à parcourir la borne. Le budget est de 2 secondes par
règle ; la mesure locale du 21 octobre 2026 donne un pire cas de **5,47 ms**
(`pem_private_key`). Ce test est une borne d'exécution, pas une preuve
formelle : toute nouvelle règle doit rester linéaire et passer ce budget.

## Faux positifs verrouillés

Le corpus T21 fournit des non-fuites qui ne doivent rien déclencher : UUID,
SHA-256, hash de commit, intégrité `sha512-`, image GIF en base64, valeur
d'exemple, `changeme`, `your_key_here`, jeton de test, préfixes tronqués
(`AKIA1234`, `ghp_`), JWT incomplet, clé publique et certificat. Le test
`test_known_false_positives_are_not_reported` verrouille ces cas.

Deux limites restent assumées :

- un vrai secret **sans préfixe reconnaissable** (mot de passe générique,
  clé d'un fournisseur non couvert) n'est pas détecté par ces règles ;
- une chaîne synthétique qui imite exactement un préfixe publié est signalée,
  même dans une documentation. C'est le comportement attendu d'une signature :
  l'exclusion de fichiers ou de lignes relève de #59.

## Limites explicites

- Pas de parcours de dépôt ni d'exclusion : le moteur reçoit une cible déjà
  construite (#59).
- Pas de détection par entropie seule : `entropy` est une métadonnée du
  Finding, pas un déclencheur.
- Jointure limitée à deux lignes et 4 Kio.
- PEM : seul l'en-tête `BEGIN … PRIVATE KEY` est reconnu ; le corps n'est pas
  parsé et un en-tête seul est signalé (c'est le signal utile).
- Aucune validation auprès du fournisseur, aucun appel réseau, aucun checksum
  de clé : le scanner reste hors ligne et déterministe.
- Les formats des fournisseurs évoluent : une règle peut devenir obsolète.
  Toute évolution se fait dans le fichier de famille, avec de nouveaux
  exemples et la mise à jour de ce document.
- La valeur candidate transite en mémoire Python le temps du hachage ; elle
  n'est jamais sérialisée, journalisée ou rendue.

## Ajouter ou modifier une règle

1. Choisir le fichier de la famille concernée (ou en créer un et l'ajouter à
   `FAMILIES` dans `signatures/__init__.py`).
2. Déclarer la règle avec `make_rule()`, un groupe `value`, un exemple positif
   et un exemple négatif **synthétiques**.
3. Garder le motif ancré et borné ; ne jamais utiliser de quantificateur
   imbriqué ni de borne ouverte sur un contenu arbitraire.
4. Lancer `pytest tests/test_scanner_signatures.py` : les exemples sont relus
   automatiquement, et la règle passe le test anti-ReDoS.
5. Mettre à jour le tableau ci-dessus et la fiche [t54-samm.md](t54-samm.md).

## Reproduire les preuves

```sh
.venv/bin/python -m pytest tests/test_scanner_signatures.py
.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing
.venv/bin/ruff check heimdall tests
.venv/bin/ruff format --check heimdall/scanner tests/test_scanner_signatures.py
.venv/bin/mypy heimdall
.venv/bin/bandit -r heimdall -q
```

Résultats locaux du 21 octobre 2026 : **76 passed** pour le fichier ciblé,
**1185 passed, 1 xfailed** pour la suite complète (le `xfail` est celui de T21,
qui attend le branchement réel du scanner #59). Les couples module + ligne et
les permaliens sont dans [t54-samm.md](t54-samm.md).
