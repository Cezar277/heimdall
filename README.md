# heimdall

Local-first DevSecOps sentry. Deterministic secret interception, local agentic remediation (MCP/Ollama), and encrypted on-premise vault synchronization.

Heimdall est un outil **100 % local** (aucun appel vers Internet) qui empêche
les secrets (mots de passe, clés API, clés privées) de finir dans Git.
Le LLM local propose, le programme vérifie, l'humain valide (`Y / N / E`) ;
en CI (`heimdall scan --ci`), un secret en clair fait échouer le pipeline.

## Installation

Python 3.10 ou supérieur. Voie vérifiée **en premier** (hashes SHA-256) :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps --no-build-isolation
```

Windows / PowerShell : remplacer `.venv/bin/python` par `.venv\Scripts\python.exe`.

> Avertissement supply-chain : `pip install -e .[dev]` seul résout sans
> vérification d'intégrité — pratique pour développer, **jamais pour une
> preuve** (preuve = bloc vérifié ci-dessus).

Builds reproductibles : versions en `==` dans `pyproject.toml`
(voir [ADR-002](docs/adr/002-stack-python.md)), gel transitif **avec hashes
SHA-256** dans `requirements.lock` (en-tête du fichier = commandes exactes).

## Usage

```sh
heimdall --help
heimdall --version
heimdall scan             # bloqué tant que le scanner #22 n'est pas livré (fail-closed)
heimdall scan --ci        # idem : refuse par défaut plutôt que d'inventer un verdict
heimdall mcp --root .     # serveur MCP stdio (outils en lecture seule, #27)
```

### Serveur Vault

Le serveur Vault démarre sur la boucle locale (`127.0.0.1:8443` par défaut) via son lanceur dédié, seul point d'entrée supporté garantissant l'application de l'allowlist d'hôte et le durcissement du transport :

```sh
# Initialisation à froid de la base de données SQLite (#62) :
# Chemin par défaut hors dépôt : $XDG_DATA_HOME/heimdall/vault.db
# (sinon ~/.local/share/heimdall/vault.db) ; surcharge par argument
# ou via $HEIMDALL_VAULT_DB_PATH.
# Chemin ABSOLU exigé (CLI et serveur) : un chemin relatif dépend du répertoire
# courant et ferait diverger la CLI et le serveur sans erreur.
# Codes de retour : 0 (succès), 1 (erreur d'initialisation ou permissions),
# 2 (chemin relatif, ou ':memory:' : réservé aux tests via API, interdit en CLI,
#   via $HEIMDALL_VAULT_DB_PATH et côté serveur — fail-closed)
python -m heimdall.vault.init_db

# Variables minimales d'un déploiement réel (aucune valeur publique par défaut) :
# KEK : python -c "from heimdall.vault.crypto import generate_encryption_key; print(generate_encryption_key())"
export HEIMDALL_ENV=production
export HEIMDALL_VAULT_API_KEY_PEPPER='<pepper aléatoire persistant, distinct de la KEK>'
export HEIMDALL_VAULT_KEK='<KEK AES-256 base64, 32 octets, distincte du pepper>'
# TLS obligatoire en production : certificat avec SAN IP 127.0.0.1 + clé privée.
export HEIMDALL_VAULT_SSL_CERTFILE='/chemin/absolu/server.crt'
export HEIMDALL_VAULT_SSL_KEYFILE='/chemin/absolu/server.key'
# Backend par défaut en production : sqlite (chiffré, partagé entre workers).
# Hors production : memory (chiffré éphémère, strictement mono-processus).
# export HEIMDALL_VAULT_STORAGE_BACKEND=sqlite

# Lancement du serveur Vault (point d'entrée unique, boucle locale vérifiée) :
python -m heimdall.vault.app
```

Le backend SQLite chiffre chaque valeur avec AES-256-GCM et une KEK qui ne
réside jamais dans la base ; `UNIQUE(project_id, env, name)` garantit le 409
inter-workers et `PRAGMA foreign_keys=ON` protège l'intégrité référentielle.
Le backend mémoire, réservé aux tests/développement, chiffre également les
valeurs dans son dictionnaire mais reste strictement mono-processus (workers=1).
Le pepper (`HEIMDALL_VAULT_API_KEY_PEPPER`) doit comporter au moins 32 octets
(256 bits) et rester distinct de la KEK : la politique complète (émission,
révocation, empreintes) est décrite dans la section « Clés API de projet »
ci-dessous.

> **Environnement cible (POSIX requis)** :
> Heimdall Vault requiert un système POSIX (Linux, macOS, BSD) pour garantir le durcissement fail-closed des permissions (`0600` pour la base, `0700` pour les répertoires). Sous Windows, ces permissions ne sont pas applicables nativement : l'ouverture de la base refuse fail-closed (`RuntimeError`, aucun avertissement suivi de poursuite) — Windows est strictement hors cible de déploiement en production.

> **Note sécurité & dette technique (contrat OpenAPI #15)** :
> Ce squelette minimal (#25) est strictement confiné à la boucle locale (`127.0.0.1`, `::1`, `localhost`).
> Ne jamais exposer ce serveur en clair hors de localhost ni réutiliser ce montage HTTP au-delà du squelette minimal (#25). Les exigences runtime suivantes sont tracées et attribuées aux tickets du Vault :
> - **Rejet fail-closed HTTP 403 sur IP non-loopback** : garde middleware en défense en profondeur (niveau transport/socket), volontairement maintenue hors du contrat OpenAPI applicatif (`/api/v1/health` étant publique sans clé).
> - **TLS avec SAN IP (`https://127.0.0.1:8443`)** : obligatoire en production
>   (`HEIMDALL_VAULT_SSL_CERTFILE` + `HEIMDALL_VAULT_SSL_KEYFILE`), HTTP en clair
>   réservé au développement local.
> - **Authentification par clé API de projet (`X-Heimdall-API-Key`)** : livrée par
>   le ticket #64 (empreinte HMAC-SHA256 + pepper, clé affichée une seule fois,
>   révocation).
> - **Rejet HTTP 400 avant parsing au-delà de 1 Mio (1 048 576 octets)** : ticket #63.
> - **En-tête `Cache-Control: no-store`** : ticket #63.
> - **Rate-limit débit par clé validée, pair réseau et global avec `Retry-After`** : ticket #65.
> - **Chiffrement au repos et persistance SQLite** : tickets #26 / #62.

> **Limites de déploiement à l'état #63** :
> - **Transport** : le lanceur `python -m heimdall.vault.app` refuse de démarrer
>   en production sans certificat et clé TLS (`HEIMDALL_VAULT_SSL_CERTFILE`,
>   `HEIMDALL_VAULT_SSL_KEYFILE`). Le HTTP en clair reste réservé à la boucle
>   locale en développement. La révocation de clés est livrée (#64).
> - **Rate-limit partagé avec SQLite** : les buckets (clé validée, pair réseau,
>   global) sont persistés dans la base sous transaction `BEGIN IMMEDIATE`, donc
>   partagés entre workers sans multiplication du débit. Le backend mémoire reste
>   strictement mono-processus ; `run_server` épingle `workers=1` par défaut.
> - **Quota de stockage atomique** : avec plusieurs workers SQLite, la capacité
>   `max_secrets`/`max_secrets_per_project` est vérifiée sous transaction
>   `BEGIN IMMEDIATE` (verrou d'écriture acquis avant le comptage), donc sans
>   dépassement inter-workers. L'unicité `UNIQUE(project_id, env, name)` reste
>   garantie ; un 429 de capacité n'est pas transitoire tant qu'aucune route
>   DELETE n'existe (retry inutile documenté, #62).

Vérifier la santé minimale (`/api/v1/health` contractuel) :

```sh
curl http://127.0.0.1:8443/api/v1/health
# {"status": "ok"}
```

### Clés API de projet (ticket #64)

Seul un projet muni de sa clé API peut lire ou écrire ses secrets. La clé est
transmise dans l'en-tête `X-Heimdall-API-Key` ; le serveur n'en conserve que
son **empreinte de vérification** (HMAC-SHA256 avec le pepper serveur) : la clé
brute n'est **jamais** stockée, journalisée ni renvoyée après sa création.

```sh
# 1. Émettre une clé pour un projet (affichée UNE SEULE FOIS : à copier aussitôt).
#    Le pepper serveur est EXPLICITE : un pepper éphémère rendrait la clé morte
#    au redémarrage du serveur.
export HEIMDALL_VAULT_API_KEY_PEPPER='<pepper aléatoire persistant, distinct de la KEK>'
heimdall vault key create --project demo
# Clé API de projet émise — affichée UNE SEULE FOIS, à copier maintenant :
# gWEWT-9b8Rzs0_dGpW1PEu-w7hIBN9_iViXwI2LwrhE
# Identifiant : key_edb63e52fce048669734ddf21aa06cbf
# Projet      : demo

# 2. Lister les clés enregistrées (métadonnées seules : ni la clé ni son empreinte).
heimdall vault key list --project demo
# key_edb63e52fce048669734ddf21aa06cbf  projet=demo  créée=...  état=active

# 3. Révoquer une clé : elle cesse d'authentifier immédiatement (401 générique).
heimdall vault key revoke key_edb63e52fce048669734ddf21aa06cbf
```

Puis, côté serveur, chaque requête porte la clé du projet concerné :

```sh
curl -H "X-Heimdall-API-Key: <clé du projet>" \
  http://127.0.0.1:8443/api/v1/secrets/demo/dev/DEMO_PASSWORD
```

Comportement fail-closed appliqué par `heimdall/vault/auth.py` :

| Situation | Réponse |
|---|---|
| clé absente, inconnue, révoquée ou invalide | `401 unauthorized` (message générique, jamais d'écho de la clé) |
| clé valide d'un **autre** projet | `403 forbidden` (décidé **avant** toute recherche de secret : l'existence d'une ressource n'est pas révélée) |
| identifiant de projet hors contrat | `400 bad_request` |

Le pepper (`HEIMDALL_VAULT_API_KEY_PEPPER`) doit comporter au moins 32 octets
(256 bits) et rester **distinct de la KEK** de chiffrement ; les clés opérateur
enregistrées doivent être générées par `generate_api_key()` : l'enregistrement
est fail-closed et refuse tout token qui n'est pas un base64url strict
(`A-Z a-z 0-9 _ -`, `fullmatch` : un `\n` final est refusé), qui fait moins de
43 caractères, qui compte moins de 16 caractères distincts, qui est la
répétition d'un bloc plus court, qui contient une suite monotone de 8+
caractères ou une ligne de clavier connue (`"a" * 43`, `"abcdefghijkl" * 4`,
`"abcdefgh…"`, `"qwertyuiop…"` : refusés). La valeur d'un secret est
canonisée en Unicode NFC avant stockage et l'octet NUL y est interdit ; elle
n'est jamais journalisée. La traçabilité ticket → module → preuve est dans
[`docs/contracts/vault-traceability.md`](docs/contracts/vault-traceability.md).

## Structure

```text
heimdall/            paquet unique (#17)
  scanner/           détection déterministe regex + entropie (#22, contrat #14)
    interface.py     cible (diff indexé ou fichier) + scan(cible) -> list[Finding] (#53)
    finding.py       sortie Finding conforme au schéma #14 par construction (#53)
  mcp/               serveur MCP stdio, 4 outils lecture seule (#27, contrat #16)
    prompts/         prompt système versionné du trieur (qualify_v1, #80)
  llm/               client Ollama local, sortie JSON contrainte (#80, T28.2), candidat fail-closed (#81)
  vault/             Vault chiffré ; crypto CONFINÉE à vault/crypto.py (#25, contrat #15)
  cli/               entrée `heimdall` (Typer)
tests/               fumée paquet + confinement crypto + tests/contracts/
                     + tests d'intégration Vault (TestClient, #65)
docs/                adr/, contracts/, meetings/
schemas/             finding.schema.json, mcp-tools.schema.json
openapi.yaml         contrat Vault API v1 (#15)
```

## Contrats et décisions

- [Vault API v1 et vérification OpenAPI](docs/contracts/vault-api.md)
- [Finding v1 et machine d'états du secret](docs/contracts/finding.md)
- [Interface du scanner et sortie Finding](docs/scanner-interface.md)
- [Outils MCP exposés au LLM (surface strictement limitée)](docs/contracts/mcp-tools.md)
- [Serveur MCP stdio : lancement, outils, invariants (#27)](docs/mcp-server.md)
- [ADR-001 : Finding et faux positifs](docs/adr/001-finding-et-etats.md)
- [ADR-002 : Stack Python et structure du dépôt](docs/adr/002-stack-python.md)
- [ADR-003 : Serveur MCP, décisions et limites (#27)](docs/adr/003-serveur-mcp.md)
- [ADR-004 : Choix du modèle LLM local Ollama, prompt du trieur (#79/#80)](docs/adr/004-choix-modele-ollama.md)
- [Modèle de menaces : DFD, actifs, STRIDE et risques prioritaires (T18)](docs/security/README.md)

## Intégration continue (CI)

Le workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (« CI Security
& Quality ») exécute ruff, mypy (strict), bandit, les tests avec un seuil de
couverture de 85 % (`pytest-cov`) et `pip-audit`, sur un runner **self-hosted**
(comme les autres workflows) : zéro minute GitHub consommée.

Il ne tourne volontairement **pas** à chaque push de branche (quota GitHub et
bruit contenus) : sur une PR, deux déclencheurs équivalents, réservés aux
collaborateurs de confiance (garde `author_association`) :

1. **Commande `/ci`** : commenter `/ci` seul ou suivi d'un espace ou d'un
   retour à la ligne sur une PR du dépôt (espaces initiaux retirés ; `/ciX`
   est refusé).
   Le job de contexte vérifie la commande exactement avant de lancer les tests ;
   le check `CI (/ci)` apparaît sur la PR.
2. **Approbation d'un relecteur** : approuver la PR (`pull_request_review`,
   état `approved`) la lance aussi.

Dans les deux cas, le workflow publie lui-même le check **`CI (/ci)`** sur le
commit de merge (`refs/pull/<n>/merge`) : c'est **ce nom** que la protection
de `main` doit exiger. Pourquoi publié via l'API plutôt que le check du job ?
GitHub n'évalue pour une PR que les checks des runs déclenchés par `push` /
`pull_request*` / `deployment*` : les checks des jobs d'un run déclenché par un
commentaire ne comptent pas (docs *Troubleshooting required status checks*) —
sans publication explicite, `/ci` ne bloquerait ni ne débloquerait rien.
La publication du check est faite par deux jobs dédiés (`resolve`, `report`)
qui n'exécutent **jamais** le code de la PR ; le job de test n'a que
`contents: read` — un test malveillant ne peut donc ni lire un token
privilégié ni forger `CI (/ci)` (séparation des privilèges).

Conséquence voulue : **sans `/ci` ni approbation, le check est absent et la PR
reste bloquée** (« Waiting for status to be reported »). Les PR provenant d'un
fork ne sont jamais exécutées sur le runner self-hosted ; elles doivent être
proposées depuis une branche du dépôt pour passer cette CI. Après un nouveau
commit (y compris « Update branch »), relancer `/ci` (ou ré-approuver) — le
check repart « en attente » puis passe au vert si tout passe.

En dehors des PR : `push` sur `main` (preuve « pipeline vert sur main ») et
`workflow_dispatch` sur `main` uniquement (bouton *Run workflow*, pour
déboguer — il ne publie pas le check, donc ne débloque pas une PR ; disponible
une fois le workflow sur `main`). Les autres workflows (`Vault contract`, `Security model`,
`OpenCode review`) gardent leurs propres déclencheurs.

### Exception réseau documentée : `pip-audit`

Heimdall est 100 % local : ni l'outil ni le serveur MCP ne font d'appel réseau.
Seule exception, **en CI uniquement** (build-time) : l'étape `pip-audit` du
workflow interroge l'API publique PyPI pour confronter nos dépendances aux CVE
connues. Seuls les **noms et versions des paquets** installés sont transmis —
aucun code source, aucun secret, aucune métadonnée du projet. Aucun appel
réseau n'a lieu à l'exécution de `heimdall` (y compris `heimdall scan --ci`).

La preuve et sa limite actuelle sont archivées dans
[`docs/security/zero-egress.md`](docs/security/zero-egress.md) : le test CI
interdit les connexions Python hors loopback et n'autorise, comme exception
journalisée, que l'IPC local `AF_UNIX` (réserve : un relais inter-processus
reste hors du garde et n'apparaît dans la trace que s'il ressort en IP). Il
refuse aussi le lancement de processus enfants par les wrappers Python
(`subprocess.Popen` par attribut, `os.*`) ; les alias précoces
(`from subprocess import Popen`), les chemins C (`_posixsubprocess`) et un
binaire ou une extension native appelant directement `fork(2)`/`execve(2)`
relèvent de la trace `strace -f`. Le
scan réel reste bloqué par le squelette du scanner #22 ; la trace disponible
prouve uniquement l'absence de connexion sur ce chemin fail-closed, pas encore
sur un scan opérationnel.

### Réglages GitHub du dépôt (une fois, non versionnables)

- **Code security** : activer *Dependabot alerts* et *Dependabot security
  updates* (gratuits, dépôts privés inclus). *Secret scanning* et *push
  protection* sont gratuits sur un dépôt public mais payants sur un dépôt
  privé (GitHub Advanced Security / Secret Protection) — à activer si le plan
  le permet.
- **Protection de `main`** : PR obligatoire + 1 approbation ; exiger les
  checks `Security model` et **`CI (/ci)`** — ⚠️ **pas** `Lint, Typecheck,
  Audit & Test` (le nom du job) : sur un run déclenché par commentaire il
  n'est pas rattaché à la PR et bloquerait à vie. `CI (/ci)` devient
  sélectionnable après le premier run qui le publie (une approbation ou un
  `/ci`). Pas de force-push. Ne pas exiger `Vault contract` : ses filtres de
  chemins le laisseraient « en attente » sur les PR sans fichiers de contrat.
- **Actions** (Settings > Actions > General) : garder l'approbation requise
  pour les workflows déclenchés depuis un fork (« Require approval for all
  outside collaborators »). **Exigence bloquante** — le runner `self-hosted`
  exécute le code de la PR (après `/ci` ou approbation) : VM d'équipe
  **dédiée et jetable** (ou restaurée par snapshot avant chaque run),
  utilisateur dédié non-root, aucun secret ni donnée personnelle dessus ;
  considérée comme compromise après chaque run. Les PR de forks ne tournent
  pas sur ce runner. Jamais une machine perso.
  **Avant merge**, joindre à la preuve SAMM la configuration attestant le
  mode éphémère (par ex. runner enregistré avec `--ephemeral` ou snapshot
  restauré/nettoyage post-job) ; le label `self-hosted` seul ne le prouve pas.
- **Option** : « Require branches to be up to date before merging » augmente
  les re-runs — chaque « Update branch » exige de relancer `/ci` (ou
  ré-approuver) pour re-signaler le check. À n'activer que si nécessaire.

## Vérifier

Corpus d'acceptation T21 : [34 cas synthétiques et mesure précision/rappel](tests/fixtures/trap_repo/README.md).
Exécuter `python -m pytest tests/test_trap_acceptance.py -s -rx` ; l'acceptation
du scanner reste explicitement en attente tant que T22 n'est pas implémenté.

```sh
.venv/bin/python -m pytest                      # squelette + contrats
.venv/bin/python -m unittest discover -s tests/contracts -v   # contrats seuls
.venv/bin/python -m pytest tests/test_vault_integration_testclient.py -q   # Vault (TestClient)
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
.venv/bin/bandit -r heimdall -q
.venv/bin/python -m pytest --cov=heimdall --cov-branch \
    --cov-report=term-missing --cov-fail-under=85   # idem CI (#20)
.venv/bin/pip-audit --skip-editable             # comme la CI : requête réseau (PyPI)
git diff --check
```

Tests d'intégration du Vault (sous-ticket T255 de #25) : le `TestClient` de
FastAPI pilote l'application **en mémoire, sans port réseau**, sur une **base
SQLite temporaire créée par test** (aucun état partagé : ni base, ni registre
de clés, ni secrets). La suite vérifie le cas nominal (POST puis GET), le refus
401 d'une clé invalide, le refus 403 d'un secret appartenant à un autre
projet, la conformité des réponses au contrat `openapi.yaml`, le refus 403
d'une origine hors boucle locale, le 429 de débit avec `Retry-After` borné, et
le refus des abus d'entrée (corps > 1 Mio, identifiants hors contrat,
traversée de chemin). Preuves : [`docs/t255-samm.md`](docs/t255-samm.md).

Règles de contribution : [CONTRIBUTING.md](CONTRIBUTING.md).
Jamais de vrai secret dans le dépôt, même expiré ; seul `.env.example`
(noms sans valeurs) est versionné — `.env` est ignoré (voir `.gitignore`).
