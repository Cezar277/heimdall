# Vault API v1 — contrat OpenAPI

Ticket #15 · Porteur : C · Relecteur : A · Estimation : 6 h.

Source contract-first : [openapi.yaml](../../openapi.yaml), OpenAPI 3.1.0.
Le fichier est écrit indépendamment de FastAPI. L'application Vault réelle,
le chiffrement et la gestion des clés seront implémentés dans #25 et les
tickets associés. Ce ticket ne fournit pas de serveur fonctionnel.

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
de vérification**, jamais leur valeur brute (base, sauvegardes et journaux
inclus). Cette règle porte sur les clés d'authentification du serveur ; le
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
`Cache-Control: no-store`. Le serveur doit aussi protéger ses logs, les
traces middleware et les erreurs de validation : jamais de corps de requête,
clé, valeur déchiffrée ou entrée utilisateur reflétée. Le MCP/LLM n'a aucun
outil pour lire une valeur Vault.

## Erreurs communes

Chaque erreur retourne `application/json`, un objet strict `{code, message}`.
Le schéma impose un message constant par code via `enum` et `allOf` conditionnel.
Les messages suivants sont les seules valeurs autorisées ; une autre chaîne
ou un message constant associé au mauvais code est rejeté.

| HTTP | `code` | `message` constant |
| --- | --- | --- |
| 400 | `bad_request` | Requête invalide |
| 401 | `unauthorized` | Authentification requise |
| 403 | `forbidden` | Accès interdit |
| 404 | `not_found` | Ressource introuvable |
| 409 | `conflict` | Secret déjà existant |
| 429 | `rate_limited` | Trop de requêtes |
| 503 | `unavailable` | Service indisponible |
| 500 / autre erreur inattendue | `internal_error` | Erreur interne |

404 concerne uniquement les lectures : le POST de collection ne renvoie pas
404. Le serveur reste responsable d'associer le bon code HTTP à l'erreur.
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
pas une date HTTP. Le serveur DOIT respecter cette borne. Un client recevant
une valeur absente, mal formée ou hors bornes DOIT signaler une erreur de
protocole : il ne doit ni attendre le délai aberrant ni recommencer aussitôt
automatiquement. Les retries conformes doivent également rester bornés.

Exemple sans donnée utilisateur :

```json
{"code":"bad_request","message":"Requête invalide"}
```

En #25, remplacer le 422 par défaut de FastAPI et les erreurs HTTP de
Starlette par ce format, avec des handlers qui ne reflètent jamais les
entrées. Le schéma OpenAPI ne configure pas les handlers runtime. Les
réponses `default` documentent les erreurs inattendues ; elles ne doivent
pas être utilisées pour contourner les codes ci-dessus.

## Vérifier le contrat

Depuis la racine du dépôt, Python 3.10 ou supérieur, Node.js et npm/npx :

Windows / PowerShell :

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r tests/contracts/requirements.txt
.venv/Scripts/python.exe -m unittest discover -s tests/contracts -v
npx --yes @stoplight/spectral-cli@6.15.0 lint openapi.yaml --fail-severity warn
git diff --check
```

Linux/macOS :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r tests/contracts/requirements.txt
.venv/bin/python -m unittest discover -s tests/contracts -v
npx --yes @stoplight/spectral-cli@6.15.0 lint openapi.yaml --fail-severity warn
git diff --check
```

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
serveur lancé. Ses handlers lèvent `NotImplementedError`. Elle ne doit pas
être utilisée comme application Vault.

Le test compare les documents après résolution des références locales :
routes et méthodes, operationId, paramètres, corps, modèles, contraintes,
codes de réponse, en-têtes et sécurité. Seules les annotations documentaires
et l'ordre des champs obligatoires sont normalisés. Un test de mutation
vérifie qu'une contrainte ou méthode supplémentaire fait diverger le contrat,
ainsi que la suppression de `additionalProperties: false` ou l'élargissement
du message d'erreur en chaîne libre.

Les patterns stricts utilisent des regex Python compilées dans la fixture,
car le moteur Rust de Pydantic ne gère pas les lookaheads. Il faut conserver
ces contraintes dans l'application réelle ou un filtre équivalent testé.

La comparaison n'est pas encore une preuve de conformité du serveur #25.
À son arrivée, remplacer `build_app()` par sa vraie factory et ajouter les
tests HTTP de 400/401/403/404/409/429/500, isolement interprojets, health limité,
headers proxy falsifiés, no-store et
handlers sans fuite. Le chiffrement, TLS, la limitation de débit et la
révocation sont des exigences, pas des propriétés prouvées par cette PR.
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
