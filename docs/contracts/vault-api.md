# Vault API v1 — contrat OpenAPI

Ticket #15 · Porteur : C · Relecteur : A · Estimation : 6 h.

Source contract-first : [openapi.yaml](../../openapi.yaml), OpenAPI 3.1.0.
Le fichier est écrit indépendamment de FastAPI. Le serveur Vault, le chiffrement
au repos (AES-256-GCM via KEK) et la persistance SQLite sont implémentés dans
#25/#26/#62 ; la gestion de clés par identifiant (`encrypt_at_rest`/`key_id`) et
la révocation restent suivies dans leurs tickets dédiés.

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
explicite, sans valeur publique par défaut ni repli silencieux.
`HEIMDALL_VAULT_API_KEY_PEPPER` est **obligatoire** lorsque
`HEIMDALL_ENV=production` ou `prod` (échec explicite au démarrage sinon).
Hors production, son absence génère un pepper aléatoire éphémère au démarrage
avec avertissement : les empreintes ne sont alors pas stables entre
redémarrages, et un déploiement doit fournir un pepper persisté. La constante
publique `heimdall_default_vault_pepper_dev_only` est refusée sauf
`HEIMDALL_ENV=test` explicite (fixtures déterministes). Le pepper n'est jamais
journalisé ni renvoyé au client.

Chiffrement au repos : le backend SQLite (défaut en production) chiffre chaque
valeur avec AES-256-GCM et une KEK `HEIMDALL_VAULT_KEK` de 32 octets encodée
base64, **distincte du pepper** et jamais stockée dans la base. Chaque ciphertext
est lié par AAD au triplet `(project, env, name)` ; la contrainte SQLite
`UNIQUE(project_id, env, name)` assure l'anti-écrasement entre workers. Le backend
mémoire, réservé aux tests/développement, chiffre aussi son dictionnaire avec une
KEK éphémère mais reste strictement mono-processus (`workers=1`). Aucune KEK
éphémère n'est acceptée pour des données SQLite persistées : démarrage fail-closed.
L'empreinte d'intégrité persistée (`fingerprint`) est calculée via une sous-clé
HKDF-SHA256 dédiée (`info=b"heimdall-vault-fingerprint-v1"`) et liée au triplet :
la KEK n'est jamais réutilisée directement comme clé HMAC (invariant 5) et un
lecteur de la seule base ne peut pas corréler deux valeurs égales stockées sous
des triplets distincts. Une rotation de KEK rend ces empreintes auxiliaires
obsolètes — elles se recalculent après déchiffrement, aucun secret n'est perdu.

Rate-limiting débit (#65) : fenêtres fixes par clé API validée, par pair réseau
et globale. Les 400/401 consomment les buckets pair/global, une clé absente ou
invalide ne crée pas de bucket arbitraire, et `X-Forwarded-For` reste ignoré.
Le choix du bucket par clé (`_find_api_key_project`) emprunte le même parcours
complet à coût comparable que `verify_api_key` (parcours exhaustif mémoire puis
SQLite, sans `break` précoce) : l'existence d'une clé n'est pas observable par
le temps de réponse du middleware. Le quota de stockage (capacité du store) ne
doit pas être présenté comme cette mitigation de débit : les deux mécanismes
sont distincts et testés séparément. Tout rejet 400 du middleware de taille
répond `Connection: close` (aucun octet non drainé réutilisé en keep-alive).

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

Depuis la racine du dépôt, Python 3.10 ou supérieur, Node.js et npm/npx :

Windows / PowerShell :

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes -r tests/contracts/requirements.txt
.venv/Scripts/python.exe -m unittest discover -s tests/contracts -v
.venv/Scripts/python.exe -m bandit tests/contracts/fastapi_contract_fixture.py
.venv/Scripts/python.exe -m ruff check --select S tests/contracts/fastapi_contract_fixture.py
npm ci --no-audit --no-fund
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
./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
git diff --check
```

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
handlers sans fuite. Le chiffrement SQLite et la limitation de débit sont
implémentés et testés ; TLS et la révocation restent des exigences à prouver
par leurs tickets dédiés.
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
