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
| `secret_type` | valeur du champ `type` du Finding, prise dans l'**ensemble fermé** `aws`, `stripe`, `slack`, `pat`, `jwt`, `pem` |
| `keywords` | mots-clés de contexte optionnels, comparés sans tenir compte de la casse |
| `positive_example` | exemple **synthétique** qui doit être reconnu |
| `negative_example` | exemple **synthétique** qui ne doit produire aucune correspondance |

La validation est **fail-closed au chargement du module** :

- identifiant et type Finding conformes à la grammaire `snake_case` bornée ;
- description, motif et exemples non vides ;
- regex compilable et contenant le groupe nommé `value` ;
- exemple positif reconnu, exemple négatif ignoré ;
- registre non vide et identifiants uniques ;
- `secret_type` de chaque règle **dans l'ensemble fermé** `aws` / `stripe` /
  `slack` / `pat` / `jwt` / `pem` (`ALLOWED_SECRET_TYPES` dans
  [`model.py`](../heimdall/scanner/signatures/model.py)) : un type que rien
  ne documente ne peut pas produire de Finding.

À l'exécution, `Rule.matches()` applique la même logique fail-closed : une
ligne qui n'est pas un `str` lève une `ScanError` au lieu de rendre un
`miss` silencieux. L'interface #53 refuse déjà toute ligne non textuelle
(`interface._check_lines`), donc cette garde est une défense en profondeur —
mais une ligne jamais analysée ne doit pas pouvoir passer pour une ligne
propre.

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
| `aws_secret_access_key` | AWS #55 | `aws` | nom de paramètre `aws_secret_access_key`, `aws_secret_key` ou `secret_access_key` (casse ignorée), puis `:` ou `=`, puis 40 caractères `[A-Za-z0-9/+=]` | `aws_secret_access_key`, `aws_secret_key`, `secret_access_key` |
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

Les mots-clés d'une règle et son motif ne peuvent pas diverger : un
mot-clé déclaré mais absent du motif est une **couverture annoncée plus
large que le code**, donc un faux sentiment de sécurité suivi d'un faux
négatif. Pour la règle AWS, les trois noms acceptés
(`aws_secret_access_key`, `aws_secret_key`, `secret_access_key`) sont donc
présents **dans les deux**, et le test paramétré les verrouille un par un
(voir [Verrouiller le périmètre AWS](#verrouiller-le-périmètre-aws)).

Le nom du paramètre AWS est reconnu quelle que soit la forme de
l'affectation : `aws_secret_access_key = "…"`, `AWS_SECRET_ACCESS_KEY=…`,
`"aws_secret_access_key": "…"` (JSON/TOML) et
`os.environ["AWS_SECRET_ACCESS_KEY"] = "…"` (Python). Le guillemet fermant
et le crochet de subscription sont donc optionnels après le nom. En
revanche, un nom hors périmètre (`aws_secret_access_keys`,
`aws_secret_access_key_hash`, `access_key_secret`…) reste muet : l'ancrage
reste sur le nom exact, jamais sur une sous-chaîne.

## Comment un candidat devient un Finding

1. `find_signature_matches(line)` parcourt les règles dans l'ordre stable du
   registre, applique le filtre de mots-clés s'il existe, puis `finditer()`.
2. Les correspondances sont dédupliquées par `(type, valeur)` : une même
   valeur répétée sur la même ligne ne produit qu'un candidat, mais deux
   valeurs distinctes du même type restent deux candidats.
3. `SignatureEngine.analyser(cible)` analyse chaque ligne de la cible, puis
   joint la ligne suivante **si elle est contiguë et si la somme fait au plus
   4 Kio (4096 octets UTF-8)** (voir ci-dessous).
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
deux lignes **dont les numéros se suivent**, dans une fenêtre **bornée à
4096 octets UTF-8** :

- si `len((ligne + ligne_suivante).encode("utf-8")) > 4096`, aucune jointure
  n'est faite (la mesure est en octets, pas en caractères : une ligne pleine
  d'accents ne peut pas élargir la borne) ;
- si les deux entrées ne sont pas contiguës (`numéro_suivant != numéro_courant
  + 1`), aucune jointure n'est faite : une `DiffTarget` ne contient que les
  lignes *ajoutées* du diff, et joindre les lignes 12 et 15 fabriquerait une
  chaîne absente de tout fichier ;
- une correspondance qui commence après la frontière appartient à la ligne
  suivante et est ignorée lors de la jointure, pour ne pas produire de doublon ;
- le Finding est attribué à la ligne de **début** de la correspondance.

Cette fenêtre est volontairement limitée : elle couvre les coupures de mise en
forme courantes sans transformer le scanner en analyseur de fichier entier.
Un secret étalé sur trois lignes ou au-delà de 4096 octets UTF-8 n'est pas
détecté par cette version ; la limite est testée.

## Jamais de valeur brute

Le Finding ne contient ni `value`, ni extrait, ni `snippet` :

- `snippet_hash` est un HMAC-SHA-256 hexadécimal du candidat (ADR-001) ;
- `entropy` est une métadonnée (0 à 8 bits par octet), pas une valeur ;
- les exceptions et les `repr` ne reflètent jamais le contenu analysé.

Cette règle couvre aussi les objets intermédiaires :

- `SignatureMatch.value` est exclu du `repr` (`field(repr=False)`) et le
  `repr` explicite se limite à `type`, `signature` et `start` ;
- `Rule.matches()` rend des `RuleMatch`, qui délèguent l'API de `re.Match`
  mais masquent le candidat dans leur `repr` (un `re.Match` brut afficherait
  `match='...'`) ;
- `SignatureMatch.value`, `RuleMatch.group("value")` et `RuleMatch.string`
  restent des **données sensibles** : le moteur les hache immédiatement et
  aucun appelant ne doit les journaliser, les sérialiser ni les transmettre à
  un LLM. `find_signature_matches()` est volontairement absente de `__all__`
  pour cette raison (import explicite réservé au moteur et aux tests).

La durée de vie de la valeur candidate est **bornée à son hachage** :

- le moteur déduplique sur `(ligne, type, empreinte)`, **pas** sur
  `(ligne, type, valeur)` : l'ensemble de déduplication ne retient donc
  aucun secret en clair pendant toute l'analyse de la cible ;
- la valeur n'est conservée que le temps de calculer son empreinte et son
  entropie, puis abandonnée ;
- elle n'est jamais sérialisée, journalisée ni rendue.

La clé HMAC fait 32 octets et vit **hors du dépôt** :
`$HEIMDALL_SNIPPET_HMAC_KEY` (hexadécimal) ou, à défaut,
`$XDG_DATA_HOME/heimdall/snippet-hmac.key` (défaut
`~/.local/share/heimdall/snippet-hmac.key`). Le chemin doit être absolu et
sans `..` ; après résolution, il doit être **exactement** le chemin demandé,
donc aucun composant — même intermédiaire — ne peut être un lien symbolique.
Le fichier est créé en `0600`, son répertoire parent est durci en `0700`, et
une clé lisible par un autre utilisateur ou appartenant à un autre
propriétaire est refusée. Un répertoire partagé accessible en écriture au
monde (par exemple `/tmp`) est **refusé** plutôt que chmodé, pour ne jamais
modifier les permissions d'un répertoire hors du périmètre de l'application.
Aucune clé éphémère ne masque une panne : une lecture ou une création
impossible lève `ScanError`. Une même clé produit donc des empreintes stables
entre deux exécutions, sans jamais permettre de retrouver la valeur.

Cette garde est une dérogation assumée à l'invariant 3 (garde de chemin
unique du MCP) : le chemin est un **état local** fourni par l'opérateur
(`XDG_DATA_HOME` / `HEIMDALL_SNIPPET_HMAC_KEY_FILE`), jamais une entrée du
dépôt ou du LLM, et il reste vérifié fail-closed.

### Scan en CI : exporter la clé, n'écrire aucun fichier

Sans `HEIMDALL_SNIPPET_HMAC_KEY`, le **premier scan écrit un fichier** :
`$XDG_DATA_HOME/heimdall/snippet-hmac.key` (créé en `0600`). C'est le
comportement nominal en poste, mais en CI c'est un piège :

- sur un runner éphémère dont le `$HOME` (ou le `$XDG_DATA_HOME`) est **en
  lecture seule**, la création échoue et le scan se termine en `ScanError`
  (code de sortie 2) : pas de résultat partiel, jamais un verdict « propre »
  ;
- sur un runner éphémère **inscriptible**, la clé est régénérée à chaque
  run : les `snippet_hash` d'un même secret changent d'un run à l'autre, et
  deux rapports successifs ne sont plus comparables.

La CI doit donc **exporter la clé** dans l'environnement du job :

```sh
export HEIMDALL_SNIPPET_HMAC_KEY="$(openssl rand -hex 32)"  # 64 caractères hexadécimaux
```

- le scan n'écrit **aucun** fichier : la clé vient de l'environnement, le
  chemin local n'est jamais touché ;
- les `snippet_hash` sont **stables** d'un run à l'autre, à condition que la
  même clé soit exportée d'un run à l'autre (à conserver comme variable
  secrète du dépôt ; une clé régénérée à chaque run perd la comparaison
  entre runs) ;
- la clé reste **hors du dépôt** : elle n'est jamais committée, et la
  variable d'environnement n'est jamais journalisée.

Le comportement fail-closed est **conservé** : une clé d'environnement
malformée (qui ne fait pas exactement 32 octets **hexadécimaux, sans
séparateur**), un fichier de clé illisible ou un répertoire non inscriptible
lèvent une `ScanError`. Aucune clé éphémère ne remplace une clé manquante —
elle masquerait la panne et produirait des empreintes instables sans que
l'opérateur ne le voie.

Le format de la clé d'environnement est **strict** : exactement 64 caractères
hexadécimaux, sans espace ni saut de ligne. `bytes.fromhex` ignore ces
séparateurs, donc une faute de frappe (`"41 42 …"`) produirait sinon une clé
*différente* de celle que l'opérateur croyait fournir, acceptée sans bruit.
La clé est donc refusée avant tout décodage, avec le message statique
`clé d'empreinte locale invalide`.

Ce point est verrouillé par
`test_ci_scan_with_an_exported_key_writes_no_file` (clé exportée,
`XDG_DATA_HOME` en lecture seule : le scan passe et **aucun** fichier n'est
créé) et par `test_scan_without_any_usable_key_fails_closed` (ni clé ni
répertoire inscriptible : `ScanError`).

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

Le test paramétré applique chaque règle à deux lignes hostiles génériques de
**100 000 caractères** (remplissage sans correspondance, préfixe PEM) et à un
payload **ancré sur le préfixe réel de chaque règle** (`AKIA`, `sk_live_`,
`xoxb-`, `github_pat_`, `eyJ`, `-----BEGIN`, …). Sans ce troisième cas, neuf
règles sur dix seraient rejetées dès le premier caractère et le parcours de
leurs bornes ne serait pas exercé. Le budget est de 2 secondes par règle ; la
mesure locale du 21 octobre 2026 donne un pire cas de l'ordre de **quelques
millisecondes** (≈ 1,7 ms pour neuf règles, ≈ 4 ms pour
`aws_secret_access_key`, devenue la plus lente après l'élargissement de son
ancrage ; l'ordre exact dépend de la machine et de la charge). Ce test est
une borne d'exécution, pas une preuve formelle : toute nouvelle règle doit
rester linéaire et passer ce budget.

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

## Verrouiller le périmètre AWS

La règle `aws_secret_access_key` est le seul cas où le périmètre est
**nommé** plutôt que déduit d'un préfixe : le périmètre est donc écrit dans
le motif, dans les mots-clés et dans les tests, et les trois doivent dire la
même chose.

Le test `test_every_declared_aws_parameter_name_is_really_covered` vérifie
que chacun des trois noms annoncés — et ses variantes de casse — donne
exactement **une** correspondance, avec la valeur complète de 40 caractères.
Le test
`test_a_parameter_name_outside_the_announced_scope_stays_silent` vérifie
le contraire : un nom hors périmètre (`aws_secret_access_keys`,
`aws_secret_access_key_hash`, `aws_secret_key_rotation`,
`secret_access_keys`, `access_key_secret`) reste muet, en affectation simple
comme en JSON. Le test
`test_aws_secret_is_detected_in_every_common_assignment_form` verrouille les
formes d'écriture (`=`, `:`, JSON, subscription `os.environ[...]`).

Un mot-clé déclaré sans effet dans le motif resterait invisible à ces
tests : c'est pourquoi le test relit **aussi** la liste des mots-clés
(`test_keywords_are_a_context_filter`) et que la règle ne déclare que des
noms qu'elle reconnaît effectivement.

## Limites explicites

- Pas de parcours de dépôt ni d'exclusion : le moteur reçoit une cible déjà
  construite (#59).
- Pas de détection par entropie seule : `entropy` est une métadonnée du
  Finding, pas un déclencheur.
- Jointure limitée à deux lignes **contiguës** et 4096 octets UTF-8.
- PEM : seul l'en-tête `BEGIN … PRIVATE KEY` est reconnu ; le corps n'est pas
  parsé et un en-tête seul est signalé (c'est le signal utile).
- Aucune validation auprès du fournisseur, aucun appel réseau, aucun checksum
  de clé : le scanner reste hors ligne et déterministe.
- Les formats des fournisseurs évoluent : une règle peut devenir obsolète.
  Toute évolution se fait dans le fichier de famille, avec de nouveaux
  exemples et la mise à jour de ce document.
- La valeur candidate transite en mémoire Python **le temps de son hachage**
  (empreinte + entropie), puis elle est abandonnée : la déduplication du
  moteur porte sur l'empreinte, jamais sur la valeur. Elle n'est jamais
  sérialisée, journalisée ou rendue.
- Le type d'un Finding produit par le registre est **borné** à l'ensemble
  `aws` / `stripe` / `slack` / `pat` / `jwt` / `pem` : un nouveau fournisseur
  implique d'ajouter son type à `ALLOWED_SECRET_TYPES` et de le documenter ici.

## Ajouter ou modifier une règle

1. Choisir le fichier de la famille concernée (ou en créer un et l'ajouter à
   `FAMILIES` dans `signatures/__init__.py`).
2. Déclarer la règle avec `make_rule()`, un groupe `value`, un exemple positif
   et un exemple négatif **synthétiques**.
3. Si le type de Finding est nouveau, l'ajouter à `ALLOWED_SECRET_TYPES` dans
   `signatures/model.py` et le documenter dans le tableau ci-dessus.
4. Garder le motif ancré et borné ; ne jamais utiliser de quantificateur
   imbriqué ni de borne ouverte sur un contenu arbitraire.
5. Lancer `pytest tests/test_scanner_signatures.py` : les exemples sont relus
   automatiquement, et la règle passe le test anti-ReDoS.
6. Mettre à jour le tableau ci-dessus et la fiche [t54-samm.md](t54-samm.md).

## Reproduire les preuves

```sh
.venv/bin/python -m pytest tests/test_scanner_signatures.py
.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing
.venv/bin/ruff check heimdall tests
.venv/bin/ruff format --check heimdall/scanner tests/test_scanner_signatures.py
.venv/bin/mypy heimdall
.venv/bin/bandit -r heimdall -q
```

Résultats locaux du 21 octobre 2026 (après les correctifs de relecture) :
**158 passed** pour le fichier ciblé, **1269 passed, 1 xfailed** pour la suite
complète (le `xfail` est celui de T21, qui attend le branchement réel du
scanner #59). Les couples module + ligne et les permaliens sont dans
[t54-samm.md](t54-samm.md).
