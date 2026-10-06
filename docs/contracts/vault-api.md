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
un nom de variable d'environnement. Les segments, slashs, caractères de
contrôle et fins de ligne non conformes sont rejetés, y compris après
décodage de l'URL. Ces identifiants ne sont pas des chemins de fichiers.

La valeur n'apparaît que dans le corps POST et dans la réponse GET autorisée.
Elle accepte les clés multilignes et est limitée à 65536 caractères Unicode.
Le serveur doit également borner la taille totale du corps en octets (limite
proposée : 1 Mio, réponse 400 générique) avant parsing. Cette limite runtime
ne peut pas être garantie par le schéma de la valeur seule.

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

Le serveur et le client utilisent TLS sur le réseau privé, avec validation
du certificat. `https://localhost:8443` est une adresse de développement
configurable, pas un appel vers Internet. `/api/v1/health` est public sur ce
réseau et ne divulgue aucune configuration. Les dépendances des tests se
téléchargent lors de l'installation uniquement ; les tests restent hors ligne.

Les réponses de succès contenant des métadonnées ou une valeur portent
`Cache-Control: no-store`. Le serveur doit aussi protéger ses logs, les
traces middleware et les erreurs de validation : jamais de corps de requête,
clé, valeur déchiffrée ou entrée utilisateur reflétée. Le MCP/LLM n'a aucun
outil pour lire une valeur Vault.

## Erreurs communes

Chaque erreur retourne `application/json`, un objet strict `{code, message}`.
Le message est générique et constant pour sa classe d'erreur.

| HTTP | `code` | Signification |
| --- | --- | --- |
| 400 | `bad_request` | JSON, paramètre, champ ou taille invalide |
| 401 | `unauthorized` | Clé absente, invalide ou révoquée |
| 403 | `forbidden` | Projet, environnement ou action non autorisés |
| 404 | `not_found` | Ressource absente après autorisation |
| 409 | `conflict` | POST sur une identité existante, sans écrasement |
| 429 | `rate_limited` | Limitation ; `Retry-After` en secondes entières positives |
| 503 | `unavailable` | Health indisponible |
| 500 / autre erreur inattendue | `internal_error` | Échec générique, sans détail interne |

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

## Comparaison avec FastAPI et limites de la preuve

[fastapi_contract_fixture.py](../../tests/contracts/fastapi_contract_fixture.py)
est une fixture indépendante, sans lecture du YAML, sans stockage et sans
serveur lancé. Ses handlers lèvent `NotImplementedError`. Elle ne doit pas
être utilisée comme application Vault.

Le test compare les documents après résolution des références locales :
routes et méthodes, operationId, paramètres, corps, modèles, contraintes,
codes de réponse, en-têtes et sécurité. Seules les annotations documentaires
et l'ordre des champs obligatoires sont normalisés. Un test de mutation
vérifie qu'une contrainte ou méthode supplémentaire fait diverger le contrat.

Les patterns stricts utilisent des regex Python compilées dans la fixture,
car le moteur Rust de Pydantic ne gère pas les lookaheads. Il faut conserver
ces contraintes dans l'application réelle ou un filtre équivalent testé.

La comparaison n'est pas encore une preuve de conformité du serveur #25.
À son arrivée, remplacer `build_app()` par sa vraie factory et ajouter les
tests HTTP de 400/401/403/404/409/429, isolement interprojets, no-store et
handlers sans fuite. Le chiffrement, TLS, la limitation de débit et la
révocation sont des exigences, pas des propriétés prouvées par cette PR.

## Relecture et preuves

- [ ] Contrat relu par A (pseudo à renseigner dans la PR)
- [ ] Tests et lint archivés avec lien de la PR
- [ ] Ligne SAMM : module + ligne et permalink au SHA final
- [ ] Temps réel reporté sur le ticket avec `Temps: XhY`

Références de rédaction : [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html)
et [génération OpenAPI FastAPI](https://fastapi.tiangolo.com/how-to/extending-openapi/).
