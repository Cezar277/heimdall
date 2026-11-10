# Vault API v1 — contrat OpenAPI

## Gestion de capacité et pagination (#158)

`GET /api/v1/secrets?project=demo&limit=50&offset=0` retourne
`{"items": [...], "next_offset": 50}`. La clé doit appartenir au projet demandé.
Chaque élément contient exclusivement `project`, `env`, `name`, `status` :
aucune valeur, empreinte, DEK ou donnée chiffrée n'est chargée pour le listage.
`limit` vaut 50 par défaut et accepte 1 à 100 ; `offset` vaut 0 par défaut et
accepte 0 à 1 000 000. Les paramètres invalides retournent 400.
L'ordre est lexicographique ASCII par `env`, puis `name`. `next_offset` vaut
`null` sur la dernière page, y compris une page vide. La pagination par offset
renvoie également `null` si l'offset suivant dépasserait 1 000 000 : tout
`next_offset` non nul est réutilisable avec le même `limit`, sans erreur 400.
Ce plafond arrête la navigation même s'il reste des métadonnées au-delà.
La pagination par offset ne garantit pas un instantané entre requêtes si des créations/suppressions
concurrentes modifient la collection.

`DELETE /api/v1/secrets/{project}/{env}/{name}` vérifie l'accès au projet avant
toute recherche, supprime sans déchiffrer et retourne **204 sans corps** avec
`Cache-Control: no-store`, comme le listage. Une ressource absente (ou déjà
supprimée) retourne 404 ; une clé absente/invalide retourne 401 et une clé
d'un autre projet retourne 403, que le secret existe ou non.
La suppression libère les quotas global et par projet, également entre workers
SQLite. Un doublon reste 409, même lorsque le quota est atteint.

Le **429 de capacité** de POST conserve `Retry-After: 60` pour le contrat ;
attendre ne libère pas de capacité. Lister puis supprimer un secret permet de
recréer avec **201**. Le **429 de débit** est transitoire : son `Retry-After`
indique le temps restant de la fenêtre du limiteur (1 à 3600 secondes).
DELETE et le listage sont soumis à ce même limiteur de débit.

Preuves : `tests/test_vault_capacity.py` (deux backends, quota libéré,
pagination bornée, canari absent, autorisation avant stockage et visibilité
inter-workers) ; `tests/contracts/test_vault_openapi.py` (contrat indépendant)
et `tests/test_vault_integration_testclient.py` (schéma runtime).

| Garantie | Implémentation | Preuve automatisée |
| --- | --- | --- |
| Autorisation avant accès au stockage | `heimdall/vault/app.py:1387`, `heimdall/vault/app.py:1419` | `tests/test_vault_capacity.py:131` |
| Libération atomique des quotas | `heimdall/vault/store.py:200`, `heimdall/vault/store.py:480` | `tests/test_vault_capacity.py:59`, `tests/test_vault_capacity.py:145` |
| Pagination bornée et absence de valeur | `heimdall/vault/database.py:1376`, `heimdall/vault/app.py:1387` | `tests/test_vault_capacity.py:76`, `tests/test_vault_capacity.py:116` |

Ticket #15 · Porteur : C · Relecteur : A · Estimation : 6 h.

Source contract-first : [openapi.yaml](../../openapi.yaml), OpenAPI 3.1.0.
Le fichier est écrit indépendamment de FastAPI. Le serveur Vault, le chiffrement
au repos (AES-256-GCM via KEK, enveloppe DEK par secret depuis #70) et la
persistance SQLite sont implémentés dans #25/#26/#62/#70 ; la gestion de clés
par identifiant (`encrypt_at_rest`/`key_id`) et la révocation restent suivies
dans leurs tickets dédiés.

La traçabilité ticket → module → preuve de ce lot est dans
[vault-traceability.md](./vault-traceability.md) : chaque brique livrée ici
(chiffrement #26, stockage/quota #62, authentification #64, débit livré dans le
lot #63, routes #63) est rattachée à son ticket et à ses tests, et le découpage en PR
distinctes est décrit au même endroit.

## Routes et décisions à relire

| Méthode | Route | Succès | Contenu |
| --- | --- | --- | --- |
| POST | `/api/v1/secrets` | 201 | Création sans écrasement ; réponse de métadonnées |
| GET | `/api/v1/secrets/{project}/{env}/{name}` | 200 | Métadonnées et valeur courante |
| GET | `/api/v1/secrets/{project}/{env}/{name}/state` | 200 | Métadonnées sans valeur |
| GET | `/api/v1/health` | 200 | Seulement `{"status":"ok"}` ; 503 si indisponible |

L'identité du secret est le triplet `(project, env, name)`, pas le
`snippet_hash` local du Finding. Les identifiants dans les chemins ne doivent
pas contenir de secret : `project` et `env` sont des slugs ASCII, `name` est
un nom de variable d'environnement aligné sur `EnvVarName` du MCP :
`^[A-Z][A-Z0-9_]{1,63}(?![\s\S])`, soit 2 à 64 caractères et une lettre initiale.
Les segments, slashs, caractères de
contrôle et fins de ligne non conformes sont rejetés, y compris après
décodage de l'URL. Ces identifiants ne sont pas des chemins de fichiers.

La valeur n'apparaît que dans le corps POST et dans la réponse GET autorisée.
Elle accepte les clés multilignes et est limitée à 65536 caractères Unicode.
Le serveur **DOIT (MUST) canoniser la valeur en Unicode NFC avant stockage**
(décision #62, tranchée) : une forme canonique unique garantit que deux
écritures visuellement identiques d'un même secret ne peuvent ni diverger en
base, ni produire deux empreintes d'intégrité différentes. L'octet NUL (`\x00`)
reste **interdit** (HTTP 400) car il tronque les valeurs dans les outils texte.
Les retours à la ligne restent autorisés : la valeur **ne doit jamais être
journalisée** (log injection, fuite en clair) — c'est une obligation
d'implémentation, pas une option.
Le serveur **DOIT (MUST) rejeter avec HTTP 400 tout corps de requête supérieur
à 1 Mio (1 048 576 octets), avant le parsing JSON**, avec
`{"code":"bad_request","message":"Requête invalide"}`. Il DOIT compter les
octets effectivement reçus, y compris sans `Content-Length` ou en transfert
segmenté, et interrompre la lecture dès dépassement. Un `Content-Length`
annoncé supérieur à cette limite permet un rejet anticipé ; il ne remplace
pas le comptage du flux. Cette exigence runtime ne s'exprime pas avec
`maxLength` OpenAPI et ne peut pas être prouvée par le schéma de la valeur seule.

POST n'accepte pas d'état choisi par le client. Il retourne `vaulte` après
persistance chiffrée. Le Finding côté CLI ne peut passer à `vaulte` qu'après
vérification supplémentaire de la remédiation locale (#14). `rote` est réservé
à une rotation vérifiée par le composant responsable (#40). Aucun endpoint
de rotation ou de modification d'état n'est ajouté en v1. La lecture d'une
ancienne valeur révoquée est interdite et doit retourner 404 ; la nouvelle
version courante est servie après une rotation achevée.

## Authentification et transport

Toutes les routes de secrets requièrent `X-Heimdall-API-Key`. La clé est liée
à un projet et à ses droits sur les environnements et opérations. Valider la
clé et les droits **avant** de chercher une ressource : une clé d'un autre
projet obtient 403 quelle que soit l'existence du secret. Un accès autorisé à
une ressource inexistante obtient 404. Pas de clé dans l'URL, les exemples,
les traces ou le corps d'erreur.

Le serveur **DOIT (MUST) stocker les clés API uniquement sous forme de hachés
salés de vérification**, jamais leur valeur brute (base, sauvegardes et
journaux inclus). Chaque clé est générée à **au moins 256 bits d'entropie via
`secrets.token_urlsafe(32)`**, jamais dérivée de données prédictibles
(identifiant, horodatage, compteur), et n'est affichée qu'une seule fois à
la création. Le sel est unique par clé ; à défaut, un HMAC avec un pepper
serveur **distinct de la KEK** de chiffrement est admis. La fonction de
hachage et la gestion du sel sont documentées pour #25.

Politique de pepper retenue pour #64/#25 : `hash_api_key` exige un pepper
explicite, sans valeur publique par défaut ni repli silencieux. Le pepper doit
comporter **au moins 32 octets (256 bits)** ; un secret d'un caractère ou trop
court est refusé par `VaultSettings` (`ValidationError`) comme par
`hash_api_key` (`ValueError`), en défense en profondeur si les empreintes
stockées et le pepper fuient.
`HEIMDALL_VAULT_API_KEY_PEPPER` est **obligatoire** lorsque
`HEIMDALL_ENV=production` ou `prod` (échec explicite au démarrage sinon).
Hors production, son absence génère un pepper aléatoire éphémère au démarrage
avec avertissement : les empreintes ne sont alors pas stables entre
redémarrages, et un déploiement doit fournir un pepper persisté. La constante
publique `heimdall_default_vault_pepper_dev_only` est refusée sauf
`HEIMDALL_ENV=test` explicite (fixtures déterministes). Le pepper n'est jamais
journalisé ni renvoyé au client. En production, `HEIMDALL_VAULT_REQUIRE_AUTH=false`
est refusé au démarrage (`ValidationError`, fail-closed), comme le backend `memory`
interdit et la KEK obligatoire pour SQLite.

Émission et cycle de vie (ticket #64) : la clé est émise par le Vault, jamais
déduite par l'opérateur. La commande `heimdall vault key create --project <id>`
génère la clé avec `secrets.token_urlsafe(32)` (256 bits), **persiste uniquement
son empreinte** et l'affiche **une seule fois** ; `heimdall vault key list`
expose les métadonnées seules (jamais la clé ni son empreinte) et
`heimdall vault key revoke --key-id <id>` révoque une clé, qui cesse alors
d'authentifier immédiatement (401 générique). Le pepper serveur est **explicite
et obligatoire** pour ces opérations : un pepper éphémère (généré au
démarrage) ne survivrait pas au redémarrage et rendrait la clé inutilisable.
La révocation est persistée dans la base, qui reste la source de vérité y
compris pour un serveur déjà démarré ; ré-enregistrer une clé révoquée ne la
réactive pas.

Les clés opérateur enregistrées via `register_api_key` **DOIVENT** provenir de
`generate_api_key()` (`secrets.token_urlsafe(32)`, 256 bits). L'enregistrement
applique six contrôles cumulatifs, fail-closed et sans écho de la valeur :

| Contrôle | Règle | Motifs refusés |
|---|---|---|
| Alphabet | token base64url strict `A-Z a-z 0-9 _ -` | espaces, contrôles, ponctuation |
| Longueur | `43 <= len <= 512` caractères | clés courtes ou surdimensionnées |
| Diversité | `>= 16` caractères distincts | `"a" * 43`, `"abcdefghijkl" * 4` |
| Motif | aucune période répétitive (la clé n'est pas la répétition d'un bloc plus court) | `"abab…"`, `"0123456789…"`, `"abcdefghijklmnop" * 3` |
| Suite | aucune suite monotone de 8+ caractères | `"abcdefgh…"`, `"0123456789…"`, `"ZYXW…"`, `"abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE"` |
| Clavier | aucune ligne de clavier connue QWERTY/AZERTY/QWERTZ (deux sens, insensible à la casse) | `"qwertyuiop…"`, `"azerty…"`, `"qwerty"`, `"yxcvbnm…"` |

Ces contrôles filtrent les **motifs triviaux** ; ils ne mesurent pas l'entropie
et ne remplacent pas `generate_api_key()` côté opérateur, qui reste EXIGÉ :
toute clé opérateur DOIT provenir du générateur (256 bits aléatoires) — un
contournement manuel, même passant les six contrôles, est une faute
opérationnelle (en cas de fuite des empreintes et du pepper, seul un token
aléatoire résiste au brute-force hors ligne). Un refus lève `ValueError`
avec un message générique (jamais l'écho de la clé). La matrice de tests est dans
`tests/test_vault_app.py` (`test_register_api_key_rejects_weak_caller_key`,
`test_register_api_key_rejects_trivial_patterns`,
`test_register_api_key_rejects_non_base64url_alphabet`).

L'enregistrement est une opération d'**amorçage** : il sérialise ses écritures
avec un verrou de persistance distinct du verrou de snapshot qui protège la
copie en mémoire des empreintes. L'E/S SQLite n'est jamais tenue sous le
verrou de snapshot : le parcours exhaustif d'authentification (chemin de
requête) reste servi pendant un enregistrement. Ces deux verrous, le registre
des clés et la dépendance FastAPI vivent dans `heimdall/vault/auth.py` (ticket
#64), seul module responsable de l'authentification ; `heimdall/vault/app.py`
délègue et se limite au serveur (configuration, middlewares, routes).

Le contrôle d'accès est une **dépendance FastAPI** : `verify_api_key` lit
l'en-tête, retrouve la clé et retourne le projet lié ;
`require_project_access()` vérifie en plus que la clé appartient AU projet
demandé par la route (403 sur un autre projet) — la décision est prise **avant**
toute recherche de ressource, donc l'existence d'un secret n'est jamais
révélée à une clé étrangère. Un identifiant de projet hors contrat est
rejeté en 400 avant toute décision d'autorisation.

`create()` retourne uniquement les métadonnées ; le plaintext n'est déchiffré
que par la lecture autorisée et n'est jamais renvoyé au POST.

Chiffrement au repos : le backend SQLite (défaut en production) applique un
**chiffrement par enveloppe** (ticket #70). Chaque secret reçoit une DEK
aléatoire de 32 octets ; la valeur est chiffrée avec la DEK (AES-256-GCM), puis
la DEK est chiffrée avec la KEK, **distincte du pepper** et jamais stockée dans
la base. La KEK est soit fournie directement (`HEIMDALL_VAULT_KEK`, mode
historique), soit **dérivée une seule fois au démarrage** avec Argon2id depuis
`HEIMDALL_VAULT_MASTER_KEY` + `HEIMDALL_VAULT_KEK_SALT` (ticket #262, 64 Mio /
3 itérations / 4 lanes, sel public de 16 octets) ; les deux modes sont exclusifs.
La dérivation est documentée dans
[ADR-005](../adr/005-derivation-kek-argon2id.md). Les deux blobs sont persistés
dans la ligne du secret (`encrypted_value`, `encrypted_dek`) : la KEK ne chiffre
donc que des clés, et la fuite d'une DEK ne compromet qu'un secret. Les lignes
antérieures (chiffrées directement par la KEK, sans `encrypted_dek`) restent
lisibles via un repli explicite ; `init_db` ajoute la colonne nullable aux bases
existantes. Tout accès direct au fichier (outil d'administration via
`db_session`) doit donc exécuter `init_db` ou passer par `SqliteSecretStore` ;
`get_secret` lève une `RuntimeError` actionnable si la colonne manque, plutôt
qu'un `OperationalError` brut. La séparation avec le pepper est vérifiée sur
l'entropie décodée
(KEK brute vs pepper UTF-8) : deux représentations d'une même clé sont refusées,
pas seulement la copie exacte des chaînes (invariant 5). Chaque ciphertext est
lié par AAD au triplet `(project, env, name)` ; l'enveloppe de DEK utilise en
plus un label de domaine dédié, donc un blob de DEK ne peut pas être rejoué
comme une valeur. La contrainte SQLite
`UNIQUE(project_id, env, name)` assure l'anti-écrasement entre workers. Le nonce
AES-GCM de 96 bits est tiré de l'aléatoire du système (`os.urandom`) **à chaque
chiffrement** (ticket #67) : il n'est ni un compteur ni dérivé de l'heure, donc
jamais réutilisé avec la même clé, et le blob stocké contient
`nonce + ciphertext + tag` (l'étiquette GCM de 16 octets est déjà en fin de
ciphertext). Deux chiffrements de la même valeur donnent donc deux blobs
différents, et un blob copié sur un autre secret échoue à l'authentification
(AAD différent). Le backend
mémoire, réservé aux tests/développement, chiffre aussi son dictionnaire avec une
KEK éphémère mais reste strictement mono-processus (`workers=1`). Aucune KEK
éphémère n'est acceptée pour des données SQLite persistées : démarrage fail-closed.
L'empreinte d'intégrité persistée (`fingerprint`) est calculée via une sous-clé
HKDF-SHA256 dédiée (`info=b"heimdall-vault-fingerprint-v1"`) et liée au triplet :
la KEK n'est jamais réutilisée directement comme clé HMAC (invariant 5) et un
lecteur de la seule base ne peut pas corréler deux valeurs égales stockées sous
des triplets distincts. Une rotation de KEK rend ces empreintes auxiliaires
obsolètes — elles se recalculent après déchiffrement, aucun secret n'est perdu.

Les opérations SQLite des requêtes (store, authentification et débit) sont
exécutées via `asyncio.to_thread` : une attente de verrou SQLite ne bloque pas
la boucle événementielle. Le store SQLite s'appuie sur ses transactions, sans
verrou asyncio local. Les verrous asyncio restent réservés au store mémoire.
Chaque connexion SQLite utilise un timeout explicite de 250 ms. Une contention
au-delà de ce délai ou une panne d'accès (ouverture, transaction, commit) est
traduite en **503 unavailable**, avec `Retry-After: 1`, `Connection: close` et
`Cache-Control: no-store`. Aucun détail SQL, chemin ou secret n'est renvoyé ;
un avertissement générique signale l'indisponibilité dans les logs. Cette
politique couvre les buckets de débit, l'authentification et le store. Le 429
reste réservé aux budgets de débit/quota effectivement dépassés et le 409 à
un secret déjà présent. La session DB d'administration conserve ses exceptions
natives ; la session serveur normalise uniquement les pannes d'accès.
Les empreintes `api_keys.key_hash` ont un index UNIQUE ; leur persistance utilise
`ON CONFLICT(key_hash) DO NOTHING`, puis vérifie le projet dans la même
transaction. Réenregistrer une clé pour le même projet est idempotent et ne
réactive pas une clé révoquée ; la lier à un autre projet lève une `ValueError`
générique et conserve l'association initiale, en mémoire comme en SQLite. `init_db` ajoute cet index aux bases existantes ; s'il existe déjà
des empreintes dupliquées, l'initialisation échoue sans suppression automatique.
La génération du pepper et les comparaisons sensibles sont confinées dans
`heimdall/vault/crypto.py`.

Rate-limiting débit (lot #63, **fenêtre glissante** #111) : chaque admission
est horodatée et seule la fenêtre `[now - window, now]` est comptée, par clé API
validée, par pair réseau et globalement. Contrairement à une fenêtre fixe, un
attaquant ne peut pas doubler son budget à cheval sur deux fenêtres. Un `peek`
pair/global en lecture seule (sans consommation ni verrou d'écriture) précède le
hachage et le parcours d'authentification ; leur rejet 429 ne déclenche aucun
lookup de clé. Après résolution de l'empreinte, `check_authenticated` consomme
pair/global + clé en une seule transaction (mémoire : une seule section
critique ; SQLite : un seul `BEGIN IMMEDIATE`), sans fenêtre inter-transactions
ni double verrou d'écriture. Sémantique préservée : pair/global restent
consommés même quand le budget clé est plein. Les 400/401 consomment les
budgets pair/global, une clé absente ou invalide ne crée pas de budget
arbitraire, et `X-Forwarded-For` reste ignoré. Le délai `Retry-After` est
calculé sur la plus ancienne admission encore dans la fenêtre, puis borné à
1..3600 s.
Le choix du bucket par clé (`auth.find_api_key_project_cached`) emprunte le même
parcours complet à coût comparable que `verify_api_key` (parcours exhaustif
du backend actif, sans `break` précoce) et le mémoïse dans l'état de la
requête : l'authentification réutilise ce résultat, soit un seul full-scan par
requête (anti-amplification CPU) ; l'existence d'une clé n'est pas observable
par le temps de réponse du middleware. Plafond opérationnel : le coût est
linéaire en nombre de clés (N `compare_digest` + 1 SELECT complet par requête,
même invalide) — dimensionné pour une faible cardinalité (pinné à N=25 en
test) ; au-delà, prévoir un cache LRU d'empreintes inconnues avec TTL court
dans le lot #63, sans réintroduire d'oracle temporel. Le quota de stockage (capacité du store)
ne doit pas être présenté comme cette mitigation de débit : les deux mécanismes
sont distincts et testés séparément. Le quota SQLite est vérifié dans la même
transaction que l'insertion, sous `BEGIN IMMEDIATE` : le verrou d'écriture est
acquis avant le comptage, ce qui empêche tout dépassement inter-workers. Un 429
de capacité n'est pas transitoire : le retry reste refusé tant que la capacité
est pleine, même si `Retry-After` reste contractuel. Le client ne doit donc pas
boucler sur ce 429 : il doit d'abord libérer un emplacement via
`DELETE /api/v1/secrets/{project}/{env}/{name}` (#158). Ce 429 de capacité est
distinct du 429 de débit (rate-limit), lui transitoire.
Les rejets avant lecture du corps répondent `Connection: close` : 400 du
middleware de taille, 429 de débit (pair/global et clé), 403 loopback et 401 pour
une clé surdimensionnée. Les tests socket uvicorn/h11 vérifient la fermeture,
l'absence de réponse à la requête pipelinée et le fonctionnement d'une nouvelle
connexion. L'en-tête de clé est limité à 512 caractères avant tout hachage ou
lookup (401 générique), après admission pair/global. La même borne s'applique
à l'enregistrement des clés opérateur.

En mode SQLite, la base est l'unique autorité d'authentification : une clé
révoquée ou supprimée reste refusée en 401 même si son empreinte existe
dans le dictionnaire mémoire. Une erreur de lecture est distinguée d'une clé
inconnue et renvoie 503, sans repli mémoire. La mémoïsation ne dure qu'une requête. Le mode
mémoire consulte uniquement son dictionnaire ; le snapshot de lecture et
l'enregistrement partagent un `threading.Lock`, libéré avant les comparaisons.
L'API de révocation est livrée en #64 : `heimdall vault key revoke` marque la
clé dans la table `api_keys` (`revoked_at`), la base reste la seule autorité
et la clé refusée répond 401 générique — y compris pour un serveur déjà
démarré, dont la lecture en base voit la révocation à la requête suivante.
Ré-enregistrer une clé révoquée ne la réactive pas.

Backend de débit (lot #63, fenêtre glissante #111) : avec le stockage SQLite,
les admissions sont persistées dans `rate_limit_hits(name, hit_at)` et
comptées/insérées sous `BEGIN IMMEDIATE` : la limite (clé/pair/global) est
partagée entre workers et n'est jamais multipliée par leur nombre. Le backend
mémoire, réservé au développement/test, reste strictement mono-processus et
`run_server` épingle `workers=1` par défaut. **Un cache en mémoire ne suffit
pas avec plusieurs processus** : chaque worker aurait son propre compteur et la
limite effective serait multipliée par le nombre de workers ; la production
utilise donc le backend SQLite. Le quota de stockage reste indépendant de cette
limite de débit.

Les admissions expirées de toutes les fenêtres sont purgées à chaque évaluation,
rejets compris (index `idx_rate_limit_hits_at`) : la table ne retient que la
fenêtre courante. Sa taille est bornée par la somme des budgets actifs
(clé + pair + global) : `consume_on_reject` n'insère que si le budget
correspondant n'est pas plein, donc un flot de rejets avec un budget clé plein
s'arrête à cette somme, sans croître au rythme des requêtes. Le backend mémoire
applique la même règle : un bucket n'est créé qu'au moment où une admission est
réellement consommée (chemin autorisé, ou pair/global consommés sur un rejet
clé), et la purge des budgets expirés a lieu sur les deux chemins. Un flot de
rejets avec des empreintes de clé distinctes ne laisse donc pas une entrée vide
par hash.

## Journal d'audit (#113)

Chaque accès au Vault produit un événement dans `audit_events`, **y compris les
refus 401/403 et les limitations 429**. Le journal est consultable avec
`heimdall vault audit list --db-path <base>` (option `--project`, `--limit`,
`--json`) et vérifiable avec `heimdall vault audit verify --db-path <base>`.

Colonnes persistées : `occurred_at`, `key_id`, `key_fingerprint`, `project`,
`peer`, `action`, `target`, `status_code`, `outcome`, `previous_hash`,
`entry_hash`.

- **Aucun secret** : le corps de requête, les en-têtes et la valeur d'un secret
  ne sont jamais lus par le module d'audit. La clé API n'est jamais persistée,
  même partiellement : `key_id` est l'identifiant interne public (`key_...`,
  jamais la clé) et `key_fingerprint` est une **empreinte tronquée** de 16
  caractères hexadécimaux (HMAC calculé avec le pepper serveur) qui permet de
  corréler les accès d'une même clé, y compris pour une clé inconnue.
- **Chaînage par hash** : `entry_hash = SHA-256(charge canonique JSON)` et
  `previous_hash` référence l'événement précédent (`GENESIS` pour le premier).
  Modifier, insérer ou supprimer une ligne casse la chaîne ; `verify` localise
  la première ligne invalide. On parle de journal **résistant à l'altération**,
  pas « inviolable » : un attaquant qui contrôle toute la base peut recalculer
  la chaîne ou le point de contrôle. La protection contre la suppression
  totale relève de la sauvegarde externe.
- **Rétention bornée** : `MAX_AUDIT_EVENTS` (100 000) borne la table. Au-delà,
  les plus anciens événements sont purgés et leur dernier `entry_hash` est
  conservé dans `audit_chain_state.checkpoint_hash` ; le premier événement
  retenu pointe dessus, donc `verify` reste valide sans charger tout
  l'historique. La purge SQLite procède par lots de 1000, chaque lot dans sa
  propre transaction, pour ne pas tenir le verrou d'écriture pendant une
  suppression massive. La purge est testée par patch du seuil (mémoire et
  SQLite), y compris avec un excès bien supérieur à un lot.
- **Listage borné** : `list_events` applique le même bornage aux deux backends,
  `max(1, min(MAX_LIST_LIMIT, int(limit)))` (1 à 1000). Une limite négative ou
  nulle retombe sur 1 et une limite supérieure à 1000 est plafonnée : un appel
  direct ne charge jamais tout l'historique mémoire.
- **Panne SQLite** : une contention ou une erreur d'ouverture/commit du
  rate-limiter ou du journal est traduite en **503** (`Retry-After: 1`,
  `Connection: close`, `Cache-Control: no-store`), jamais en 500.
- **Fail-closed** : si l'écriture d'audit échoue, la réponse devient un 503
  générique (`Retry-After: 1`, `Connection: close`, `Cache-Control: no-store`)
  au lieu de laisser passer un accès non journalisé.
- **Cible** : `target` est renseignée par le handler (`projet/env/nom` pour
  créer, lire et lire l'état ; `projet` pour la liste), y compris pour un
  refus 403 cross-projet. Une requête rejetée avant le handler n'a pas de
  cible : c'est le cas du 401 sur `POST /api/v1/secrets` (le corps n'est pas
  lu avant l'authentification). Pour `GET /api/v1/secrets?project=`, le repli
  du middleware lit le query-param `project` et le valide avec
  `validate_project_id` : un 401 porte donc le projet demandé, et une valeur
  invalide n'est jamais recopiée (`target` reste vide). La corrélation ne
  dépend plus uniquement de `action`, `peer` et `status_code`.
- **Pas de log injection** : les champs texte sont filtrés (caractères non
  imprimables supprimés) et bornés avant persistance.
- **Backends** : `SqliteAuditLog` en production (table partagée entre workers,
  écriture sous `BEGIN IMMEDIATE`) ; `InMemoryAuditLog` pour le backend mémoire
  de développement/test, strictement mono-processus et perdu au redémarrage.
  Les identifiants d'événements ne sont jamais réutilisés, y compris après
  purge (compteur monotone dans `InMemoryAuditLog`, `AUTOINCREMENT` en SQLite).
- **Résiduel accepté : amplification des 429** : chaque 429, y compris le
  refus issu du contrôle de débit en lecture seule (peek), produit une ligne
  d'audit écrite sous `BEGIN IMMEDIATE`. Un processus local qui émet des
  requêtes rejetées peut donc sérialiser des écritures et saturer le verrou
  SQLite au détriment du trafic légitime. C'est un déni de service local, sans
  élévation de privilège : le fail-closed reste tenu (503 générique, jamais
  500) et la table reste bornée par `MAX_AUDIT_EVENTS`. Chaque écriture inclut
  un `COUNT(*)` sur la table. Mesure locale (un processus, une machine de
  développement, table pleine à 100 000 lignes) : environ 1,6 ms par écriture,
  soit au plus environ 600 écritures d'audit par seconde en série. Quand le
  verrou reste indisponible plus de 250 ms (`busy_timeout`), les requêtes qui
  attendent reçoivent un 503 générique, sans 500. Mitigations si la cadence l'exige : coalescence des 429 ou alerte sur la
  taille de la base. Une mesure sur matériel de production reste à faire.
- **Health et clé API** : l'en-tête `X-Heimdall-API-Key` n'est jamais consommé
  sur cette route publique (seules les limites pair/global s'appliquent), mais
  son empreinte est mémoïsée pour l'audit. Un health avec clé valide porte donc
  `key_fingerprint` (16 hexadécimaux) et reste corrélable à une clé ; un health
  anonyme garde `key_fingerprint` vide. Aucun `key_id` n'est recherché sur cette
  route, pour ne pas ajouter de lookup d'identifiant à un endpoint de santé.

## Rejeu de requête (#114)

Le contrat v1 n'ajoute ni nonce ni date de validité : la sémantique anti-rejeu
est portée par les routes existantes et doit être vérifiée par des tests
d'abus runtime :

- un **POST rejoué** ne remplace jamais un secret existant : 409
  `conflict`, la valeur d'origine reste inchangée ;
- un **GET rejoué** est idempotent et renvoie la même valeur (ou 404) tant que
  la clé est valide ;
- une **requête capturée rejouée après révocation** de la clé est refusée en
  401 générique ;
- la force brute de clés API est bornée par le budget pair/global puis par le
  budget clé, avec 429 et `Retry-After` ;
- une charge de quelques centaines de requêtes ne doit produire ni 500 ni
  arrêt du serveur.

Transport (#25) : en production, `run_server` refuse de démarrer sans
`HEIMDALL_VAULT_SSL_CERTFILE` et `HEIMDALL_VAULT_SSL_KEYFILE` (fail-closed) et
transmet les deux chemins à uvicorn. Le HTTP en clair reste confiné à la boucle
locale en développement ; le certificat doit porter le SAN IP `127.0.0.1` pour
`https://127.0.0.1:8443`. Le transport est vérifié de bout en bout dans
`tests/test_vault_tls.py` : SAN IP contrôlé côté pair, client de confiance
accepté, client sans confiance rejeté (aucun repli non vérifié), pas de
downgrade en clair, TLS 1.3 observé. La révocation des clés API reste suivie
séparément.

Cette règle porte sur les clés d'authentification du serveur ; le
client doit conserver son credential dans un stockage local protégé pour
pouvoir s'authentifier. Le serveur DOIT comparer des empreintes de même type
et de longueur fixe via `hmac.compare_digest`, sans comparaison `==` des
valeurs sensibles.

Pour une clé absente, inconnue, invalide ou révoquée, le serveur DOIT renvoyer
le même HTTP 401 et `{"code":"unauthorized","message":"Authentification requise"}`,
avec les mêmes en-têtes observables d'authentification. Le chemin de
vérification DOIT avoir un coût comparable : utiliser une empreinte factice
si la clé manque ou n'existe pas et effectuer la comparaison avant de rejeter
une clé révoquée. Aucun retour anticipé ne doit révéler l'existence d'une clé.
Cette règle s'applique aux échecs d'authentification après les garde-fous
globaux de taille et de débit ; un rejet préalable 400 ou 429 reste possible.

L'objectif est l'absence d'oracle temporel exploitable, pas une durée réseau
strictement identique à chaque requête. `compare_digest` ne suffit pas à
garantir cette propriété pour la recherche en base et le handler complet :
#25 DOIT vérifier le chemin de traitement et comparer les distributions de
latence des différents cas à charge comparable, en plus des tests fonctionnels.

Le serveur et le client utilisent TLS sur le réseau privé, avec validation
du certificat. `https://127.0.0.1:8443` est une adresse de développement
configurable, pas un appel vers Internet. `/api/v1/health` est public sur ce
réseau et ne divulgue aucune configuration ; elle est aussi limitée et peut
retourner 429 avec `Retry-After`. Les dépendances des tests se
téléchargent lors de l'installation uniquement ; les tests restent hors ligne.

Le client **DOIT (MUST) vérifier la chaîne de confiance et l'identité du
serveur**, même en développement et dans les tests d'intégration. Il est
interdit de désactiver cette vérification avec `verify=False`, `-k`,
`ssl._create_unverified_context` ou un équivalent. Utiliser une CA interne
explicitement approuvée ; pour `https://127.0.0.1`, le certificat doit contenir
`127.0.0.1` en SAN de type IP. Pour une adresse DNS privée, le SAN doit
correspondre au nom configuré. Un certificat autosigné n'autorise aucun
contournement : configurer explicitement la confiance appropriée. Un échec
de vérification TLS DOIT interrompre la connexion, sans repli non vérifié.

Les réponses de succès contenant des métadonnées ou une valeur portent
`Cache-Control: no-store`. Le Header Object partagé `NoStore` impose
`required: true` sur le POST 201 et les deux GET 200 de secrets. Le serveur doit aussi protéger ses logs, les
traces middleware et les erreurs de validation : jamais de corps de requête,
clé, valeur déchiffrée ou entrée utilisateur reflétée. Le MCP/LLM n'a aucun
outil pour lire une valeur Vault.

## Erreurs communes

Chaque erreur retourne `application/json`, un objet strict `{code, message}`.
Chaque réponse HTTP référence un schéma dédié avec `code` et `message` en
`const` et `additionalProperties: false`. Le statut impose donc le couple
exact : par exemple un 401 ne peut pas contenir `forbidden`, même avec le
message correspondant. `default` utilise lui aussi `InternalError`.
Les messages suivants sont les seules valeurs autorisées ; une autre chaîne
ou un message constant associé au mauvais code est rejeté.

| HTTP | `code` | `message` constant |
| --- | --- | --- |
| 400 | `bad_request` | Requête invalide |
| 401 | `unauthorized` | Authentification requise |
| 403 | `forbidden` | Accès interdit |
| 404 | `not_found` | Ressource introuvable |
| 405 | `method_not_allowed` | Méthode non autorisée |
| 409 | `conflict` | Secret déjà existant |
| 429 | `rate_limited` | Trop de requêtes |
| 503 | `unavailable` | Service indisponible |
| 500 / autre erreur inattendue | `internal_error` | Erreur interne |

404 concerne uniquement les lectures : le POST de collection ne renvoie pas
404. **405 est déclaré sur chaque opération** : une méthode non déclarée sur
une route existante (ex. `DELETE /api/v1/secrets`) renvoie
`{"code":"method_not_allowed","message":"Méthode non autorisée"}`.
Les erreurs du routeur (route inconnue → 404 `not_found`, méthode non
déclarée → 405) **DOIVENT** passer par des handlers catch-all Starlette qui
renvoient ce format ; l'enveloppe `{"detail": ...}` du framework est
interdite sur le fil (fingerprint). Prouvé par
`test_router_errors_use_contract_format_without_detail` (client ASGI en
mémoire, avec et sans clé).
Chaque route déclare aussi explicitement 500 avec le schéma `InternalError`,
qui n'accepte que `{"code":"internal_error","message":"Erreur interne"}`.
Le handler global DOIT intercepter les exceptions inattendues, renvoyer ce
JSON et désactiver les réponses de debug HTML/traceback. `default` reste un
filet documentaire ; il n'autorise pas une réponse non conforme au 500 explicite.

## Limitation de débit et proxies (#25)

Le bucket des requêtes authentifiées est lié à l'identifiant interne de la
clé API validée. Les erreurs 400 et 401 doivent consommer le budget applicable,
au même titre que les succès ; une erreur ne contourne jamais la limitation.
Une clé absente, invalide ou révoquée n'offre pas de bucket arbitraire : ces
requêtes sont limitées par l'adresse du pair réseau et une limite globale.
Health utilise ces limites publiques. Ne jamais stocker la valeur brute de
la clé dans le bucket ni créer un bucket pour chaque clé fournie par l'attaquant.

`X-Forwarded-For` est ignoré par défaut. Son usage n'est autorisé que derrière
un proxy explicitement approuvé, avec liste de pairs de confiance, suppression
des en-têtes fournis par le client et parsing contrôlé de la chaîne de proxies.
Les tests runtime #25 devront montrer qu'un header falsifié ou un changement
de clé invalide ne remet pas le compteur à zéro. Les quotas précis sont une
configuration du serveur ; toutes les routes ont une limite globale.

`Retry-After` DOIT être un délai entier de **1 à 3600 secondes incluses**,
pas une date HTTP. Son Header Object partagé impose `required: true` pour
toutes les réponses 429 **et pour la 503 de health** : en indisponibilité,
un client sans signal de backoff boucle sans délai et aggrave l'incident
(retry storm). Le serveur DOIT respecter cette borne. Un client recevant
une valeur absente, mal formée ou hors bornes DOIT signaler une erreur de
protocole : il ne doit ni attendre le délai aberrant ni recommencer aussitôt
automatiquement. Les retries conformes doivent également rester bornés.

Exemple sans donnée utilisateur :

```json
{"code":"bad_request","message":"Requête invalide"}
```

En #25, remplacer le 422 par défaut de FastAPI et les erreurs HTTP de
Starlette par ce format, avec des handlers qui ne reflètent jamais les
entrées (le 404/405 routeur est déjà verrouillé ici par la réponse 405
déclarée sur chaque opération et le handler catch-all de la fixture).
Le schéma OpenAPI ne configure pas les handlers runtime. Les
réponses `default` documentent les erreurs inattendues ; elles ne doivent
pas être utilisées pour contourner les codes ci-dessus.

## Vérifier le contrat

Depuis la racine du dépôt, Python 3.10 ou supérieur, Node.js 22 ou 24+ (requis par Spectral 6.17.0) et npm/npx :

Windows / PowerShell :

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes -r tests/contracts/requirements.txt
.venv/Scripts/python.exe -m unittest discover -s tests/contracts -v
.venv/Scripts/python.exe -m bandit tests/contracts/fastapi_contract_fixture.py
.venv/Scripts/python.exe -m ruff check --select S tests/contracts/fastapi_contract_fixture.py
npm ci --no-audit --no-fund
npm run test:js
./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
git diff --check
```

Linux/macOS :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r tests/contracts/requirements.txt
.venv/bin/python -m unittest discover -s tests/contracts -v
.venv/bin/bandit tests/contracts/fastapi_contract_fixture.py
.venv/bin/ruff check --select S tests/contracts/fastapi_contract_fixture.py
npm ci --no-audit --no-fund
npm run test:js
./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
git diff --check
```

`npm ci` applique `engine-strict=true` (`.npmrc`) : une version de Node non
supportée échoue immédiatement.

`tests/contracts/requirements.txt` est compilé avec hashes SHA-256
(`requirements.in` + `pip-compile --generate-hashes`, LOW-4) et installé
avec `--require-hashes`. Il inclut bandit + ruff pour le SAST de la fixture.
Spectral est figé par `package.json` +
`package-lock.json` et installé via `npm ci` (intégrité vérifiée).

[.spectral.yaml](../../.spectral.yaml) active les règles OpenAPI standard.
Les exemples de valeur sont des placeholders explicites, jamais des clés
réalistes, même expirées.

Le workflow [Vault contract](../../.github/workflows/vault-contract.yml) installe
les dépendances, exécute tous les tests de contrats et le lint Spectral sur
un runner Ubuntu GitHub à chaque modification du contrat sur cette PR.
Son résultat distant reste à vérifier après push ; les résultats locaux
ne permettent pas de cocher « CI verte ».
Les trois actions GitHub sont épinglées à leurs SHA de commit officiels
avec commentaire de version, pour éviter les changements de tags mutables.

## Comparaison avec FastAPI et limites de la preuve

[fastapi_contract_fixture.py](../../tests/contracts/fastapi_contract_fixture.py)
est une fixture indépendante, sans lecture du YAML, sans stockage et sans
port réseau. Les handlers métier lèvent `NotImplementedError`. Le garde
d'authentification utilise `APIKeyHeader(auto_error=False)` et une exception
dédiée, transformée manuellement en JSON 401 sans enveloppe `detail`. En
l'absence de registre de clés, il refuse **toutes** les clés : aucune clé
factice ne permet un accès. Ne pas copier les réponses automatiques
d'authentification/validation de FastAPI (403/401/422 selon version) ; #25
doit brancher la vérification réelle et les handlers conformes au contrat.
Cette fixture ne doit pas être utilisée comme application Vault.

Le test compare les documents après résolution des références locales :
routes et méthodes, operationId, paramètres, corps, modèles, contraintes,
codes de réponse, en-têtes et sécurité. Seules les annotations documentaires
et l'ordre des champs obligatoires sont normalisés. Un test de mutation
vérifie qu'une contrainte ou méthode supplémentaire fait diverger le contrat,
ainsi que la suppression de `additionalProperties: false` ou l'élargissement
du message d'erreur en chaîne libre.
Les tests vérifient aussi la présence des en-têtes obligatoires et détectent
la suppression de l'en-tête, la suppression de `required` ou son passage à
`false`. Une matrice de tous les couples code/message est vérifiée contre
chaque réponse d'erreur déclarée. Le test ASGI d'authentification s'exécute
en mémoire via HTTPX, sans socket ni TLS : il prouve uniquement le JSON 401
de la fixture pour une clé absente, vide ou factice. L'absence de 422 dans
l'OpenAPI généré est testée ; les vrais handlers 400 restent à prouver dans #25.

Les patterns stricts utilisent des regex Python compilées dans la fixture,
car le moteur Rust de Pydantic ne gère pas les lookaheads. Il faut conserver
ces contraintes dans l'application réelle ou un filtre équivalent testé.

La comparaison n'est pas encore une preuve de conformité du serveur #25.
À son arrivée, remplacer `build_app()` par sa vraie factory et ajouter les
tests HTTP de 400/401/403/404/409/429/500, isolement interprojets, health limité,
headers proxy falsifiés, no-store et
handlers sans fuite. Le chiffrement SQLite, la limitation de débit partagée et
le démarrage TLS fail-closed en production sont implémentés et testés ; la
révocation des clés reste une exigence à prouver par son ticket dédié.
Vérifier aussi les 401 indistinguables, le stockage haché des clés, les
certificats non approuvés et SAN incorrects rejetés, `Retry-After` borné et le
500 JSON constant sur une exception injectée (mode debug désactivé).

Test runtime obligatoire dans #25 pour la taille du corps : vérifier le rejet
400 au-delà de 1 048 576 octets avant tout appel au parser JSON, avec et sans
`Content-Length` et en transfert segmenté. Vérifier aussi qu'un corps JSON
valide à la limite, respectant les contraintes de champs, n'est pas rejeté
pour sa seule taille. Aucun octet du corps rejeté ne doit apparaître dans
la réponse ni les logs. Ce test nécessite le serveur réel et reste hors
périmètre de la fixture de contrat.

## Relecture et preuves

- [ ] Contrat relu par A (pseudo à renseigner dans la PR)
- [ ] Tests et lint archivés avec lien de la PR
- [ ] Ligne SAMM : module + ligne et permalink au SHA final
- [ ] Temps réel reporté sur le ticket avec `Temps: XhY`

Références de rédaction : [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html)
et [génération OpenAPI FastAPI](https://fastapi.tiangolo.com/how-to/extending-openapi/).
