# heimdall

Local-first DevSecOps sentry. Deterministic secret interception, local agentic remediation (MCP/Ollama), and encrypted on-premise vault synchronization.

Heimdall est un outil **100 % local** (aucun appel vers Internet) qui empêche
les secrets (mots de passe, clés API, clés privées) de finir dans Git.
Le LLM local propose, le programme vérifie, l'humain valide (`Y / N / E`) ;
en CI (`heimdall scan --ci`), un secret en clair fait échouer le pipeline.

## Démarrage rapide

Une fois Heimdall installé (voir [Installation](#installation)), dans votre dépôt :

```sh
heimdall init     # hook pre-commit + .env ignoré par Git + premier scan
heimdall fix      # déplace chaque secret trouvé vers .env (validation Y/N)
```

Désormais, un commit qui contient un secret est bloqué. En CI :
`heimdall scan --ci` (code 1 si un secret est trouvé).

**Coffre chiffré local (optionnel)**, sans rien configurer à la main :

```sh
heimdall vault init                                  # clés, certificat TLS, config client
heimdall vault serve                                 # démarre le Vault (laisser tourner)
heimdall vault key create --project monprojet --save # dans un autre terminal
heimdall vault push --project monprojet              # envoie votre .env chiffré
heimdall run --project monprojet -- npm start        # secrets injectés en mémoire
```

`vault init` écrit tout dans `~/.config/heimdall` (droits privés) et n'écrase
jamais rien. **Sauvegardez `~/.config/heimdall/server/server.env`** : sans lui,
les secrets du Vault sont illisibles. Pour Docker :
`heimdall vault init --docker <dossier du dépôt Heimdall>`.

En cas d'erreur, ajoutez `--debug` pour voir la cause et l'action à faire
(jamais de valeur secrète).

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
Le lock runtime minimal de l'image Docker est `requirements-runtime.lock`
(régénéré par `scripts/regen_runtime_lock.py`).

### Vault Docker (Linux)

Le Vault peut être lancé dans un conteneur durci (non root, lecture seule,
dépendances hashées, TLS obligatoire) via Docker Compose :

```sh
test ! -e .env || { echo ".env existe déjà : sauvegarder avant d'écraser" >&2; exit 1; }
install -m 600 .env.example .env
# Générer les valeurs avec docs/install.md §3 (umask 077, openssl rand,
# `sudo chown -R --no-dereference 10001:"$(id -g)" data secrets` + `750`/`640`
# pour l'UID figé, certificat lisible hôte).
# Exécuter les gardes docs/install.md §4 avant tout `up`, jamais en root hôte.
# Le compose fige `user: "10001:10001"` : aucun `up` ne peut démarrer en root.
docker compose up -d --build
curl --cacert secrets/vault_tls_cert.pem https://127.0.0.1:8443/api/v1/health
```

Guide complet, génération des secrets/TLS, garde de démarrage non-root (§4),
premier scan et dépannage : [`docs/install.md`](docs/install.md). Ne jamais
surcharger `user:` (figé à `10001:10001`). Le Vault reste **loopback-only** :
`network_mode: host` est requis, et Docker Desktop macOS/Windows n'est pas
supporté pour ce montage.

## Usage

```sh
heimdall --help
heimdall --version
heimdall scan             # scan de l'arbre de travail (mode strict, #29)
heimdall scan --staged    # blobs ajoutés ou modifiés dans l'index git (#29)
heimdall scan --ci        # mode CI headless : le code de sortie est le verdict
heimdall cold-start . --ci # premier scan déterministe du dépôt existant
heimdall deep-scan . --ci  # historique complet accessible, alerte de révocation
heimdall scan --json      # rapport JSON sur stdout (contrat heimdall.scan.v1)
heimdall mcp --root .     # serveur MCP stdio (outils en lecture seule, #27)
```

`heimdall scan` est **en lecture seule sur le dépôt** et **déterministe** :
codes de sortie `0` (aucun secret), `1` (secrets détectés), `2` (erreur
d'outillage — jamais `0` après une erreur). La seule écriture autorisée est la
clé d'empreinte locale hors dépôt
(`$XDG_DATA_HOME/heimdall/snippet-hmac.key`, `0600`) ; si elle ne peut pas
être créée ou lue (HOME/FS en lecture seule), le scan sort en `2`, jamais en
`0`. Aucun secret n'est jamais affiché en clair. Le protocole complet est
dans [docs/cli.md](docs/cli.md).

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
# KEK (recommandé, ticket #262) : dérivée au démarrage par Argon2id depuis cette
# clé maîtresse (phrase de passe >= 16 octets) et ce sel public de 16 octets.
# Générer le sel UNE fois puis le conserver avec la clé maîtresse :
#   python -c "from heimdall.vault.crypto import generate_kek_salt; print(generate_kek_salt())"
export HEIMDALL_ENV=production
export HEIMDALL_VAULT_API_KEY_PEPPER='<pepper aléatoire persistant, distinct de la KEK>'
export HEIMDALL_VAULT_MASTER_KEY='<phrase de passe longue et unique>'
export HEIMDALL_VAULT_KEK_SALT='<sel base64 URL-safe de 16 octets, persisté>'
# Mode historique (compatibilité uniquement) : KEK 32 octets utilisée SANS
# dérivation. Mutuellement exclusif avec HEIMDALL_VAULT_MASTER_KEY.
# export HEIMDALL_VAULT_KEK='<KEK AES-256 base64, 32 octets, distincte du pepper>'
# TLS obligatoire en production : certificat avec SAN IP 127.0.0.1 + clé privée.
export HEIMDALL_VAULT_SSL_CERTFILE='/chemin/absolu/server.crt'
export HEIMDALL_VAULT_SSL_KEYFILE='/chemin/absolu/server.key'
# Backend par défaut en production : sqlite (chiffré, partagé entre workers).
# Hors production : memory (chiffré éphémère, strictement mono-processus).
# export HEIMDALL_VAULT_STORAGE_BACKEND=sqlite

# Lancement du serveur Vault (point d'entrée unique, boucle locale vérifiée) :
python -m heimdall.vault.app
```

Le backend SQLite chiffre chaque valeur avec AES-256-GCM et une DEK propre au
secret, elle-même chiffrée par une KEK qui ne réside jamais dans la base. La KEK
est **dérivée une seule fois au démarrage** avec Argon2id (64 Mio, 3 itérations,
4 lanes, sel public de 16 octets) depuis `HEIMDALL_VAULT_MASTER_KEY` +
`HEIMDALL_VAULT_KEK_SALT`, puis conservée en mémoire ; les requêtes ne
recalculent jamais la KDF. Le mode historique `HEIMDALL_VAULT_KEK` (KEK 32
octets directe) reste accepté pour les données existantes, mais les deux modes
sont exclusifs. Détails et justification du choix Argon2id vs HKDF :
[ADR-005](docs/adr/005-derivation-kek-argon2id.md).
`UNIQUE(project_id, env, name)` garantit le 409 inter-workers et
`PRAGMA foreign_keys=ON` protège l'intégrité référentielle.
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
> - **Rate-limit débit par clé validée, pair réseau et global avec `Retry-After`** :
>   livré dans le lot d'intégration #63 (pas d'issue GitHub propre).
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

Puis, côté serveur, chaque requête porte la clé du projet concerné. La clé ne
doit jamais apparaître dans `argv` (`ps`, historique) : utilisez un fichier
d'en-tête `600` lu par `curl -K`.

```bash
read -rsp "Clé API: " HEIMDALL_API_KEY; echo
[[ "$HEIMDALL_API_KEY" =~ ^[A-Za-z0-9_-]{43,}$ ]] || {
  echo "clé API invalide" >&2
  exit 1
}
umask 077
AUTH_HEADER="$(mktemp /tmp/heimdall-auth.XXXXXX)"
trap 'rm -f "$AUTH_HEADER"' EXIT INT TERM HUP
chmod 600 "$AUTH_HEADER"
printf 'header = "X-Heimdall-API-Key: %s"\n' "$HEIMDALL_API_KEY" \
  > "$AUTH_HEADER"
unset HEIMDALL_API_KEY

curl --cacert /chemin/server.crt -K "$AUTH_HEADER" \
  https://127.0.0.1:8443/api/v1/secrets/demo/dev/DEMO_PASSWORD
rm -f "$AUTH_HEADER"
trap - EXIT INT TERM HUP
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
    exclusions.py    périmètre et politique de contenu (#22 / #59)
    gitignore.py     exclusions Git sûres : non suivies + ignorées (#59)
    detect.py        parcours confiné d'une racine + rapport de scan (#22 / #59)
  mcp/               serveur MCP stdio, 4 outils lecture seule (#27, contrat #16)
    prompts/         prompt système versionné du trieur (qualify_v1, #80)
  llm/               client Ollama local, sortie JSON contrainte (#80, T28.2), candidat fail-closed (#81)
  vault/             Vault chiffré ; crypto CONFINÉE à vault/crypto.py (#25, contrat #15)
  cli/               entrée `heimdall` (Typer)
    scan.py          logique du scan (périmètres, verdicts, rendu) (#29)
tests/               fumée paquet + confinement crypto + tests/contracts/
                     + tests d'intégration Vault (TestClient, #65 / T255)
                     + tests de la CLI scan (#29)
docs/                adr/, contracts/, meetings/
schemas/             finding.schema.json, mcp-tools.schema.json
openapi.yaml         contrat Vault API v1 (#15)
```

## Contrats et décisions

- [Vault API v1 et vérification OpenAPI](docs/contracts/vault-api.md)
- [Finding v1 et machine d'états du secret](docs/contracts/finding.md)
- [Interface du scanner et sortie Finding](docs/scanner-interface.md)
- [Scanner déterministe : signatures, exclusions, Finding (#22)](docs/scanner.md)
- [CLI `heimdall scan` : périmètres, codes de sortie, sortie JSON (#29)](docs/cli.md)
- [Journal des propositions de rejet du LLM : consultation, intégrité et CI (#33)](docs/llm-rejections.md)
- [Outils MCP exposés au LLM (surface strictement limitée)](docs/contracts/mcp-tools.md)
- [Serveur MCP stdio : lancement, outils, invariants (#27)](docs/mcp-server.md)
- [ADR-001 : Finding et faux positifs](docs/adr/001-finding-et-etats.md)
- [ADR-002 : Stack Python et structure du dépôt](docs/adr/002-stack-python.md)
- [ADR-003 : Serveur MCP, décisions et limites (#27)](docs/adr/003-serveur-mcp.md)
- [ADR-004 : Choix du modèle LLM local Ollama, prompt du trieur (#79/#80)](docs/adr/004-choix-modele-ollama.md)
- [ADR-006 : Table d'états et transitions du cycle de vie d'un secret (#40, #115)](docs/adr/006-table-etats-et-transitions.md)
- [Défense contre l'injection de prompt et corpus de tests (T34, #91–#97)](docs/prompt-injection.md)
- [Modèle de menaces : DFD, actifs, STRIDE et risques prioritaires (T18)](docs/security/README.md)

## Intégration continue (CI)

Le workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (« CI Security
& Quality ») exécute ruff, mypy (strict), bandit, les tests avec un seuil de
couverture de 85 % (`pytest-cov`) et `pip-audit`, sur les runners **hébergés par
GitHub** (`ubuntu-latest`, Python 3.10 épinglé), comme les autres workflows :
chaque job tourne dans une VM jetable, aucune machine du projet n'exécute le
code d'une PR (gratuit pour un dépôt public).

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
fork ne sont pas lancées par `/ci` ; elles doivent être proposées depuis une
branche du dépôt pour passer cette CI. Après un nouveau
commit (y compris « Update branch »), relancer `/ci` (ou ré-approuver) — le
check repart « en attente » puis passe au vert si tout passe.

En dehors des PR : `push` sur `main` (preuve « pipeline vert sur main ») et
`workflow_dispatch` sur `main` uniquement (bouton *Run workflow*, pour
déboguer — il ne publie pas le check, donc ne débloque pas une PR ; disponible
une fois le workflow sur `main`). Les autres workflows (`Vault contract`, `Security model`,
`Prompt injection corpus`) gardent leurs propres déclencheurs. La revue IA
`OpenCode review` est désactivée : son workflow est archivé en
`.github/workflows/opencode-review.yml.bak` (GitHub n'exécute que les `.yml` /
`.yaml`) ; le renommer en `.yml` et recréer le secret `OPENCODE_API_KEY` la
réactive.

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
relèvent de la trace `strace -f`. Depuis #29, le scan n'est plus un squelette :
`tests/test_network_isolation.py::test_scan_ci_never_attempts_external_traffic`
exerce un **scan réel** (`heimdall scan --ci`) sous le garde réseau, et
prouve l'absence de connexion sur ce chemin opérationnel.

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
- **Merge réservé au mainteneur** : ruleset `Merge réservé au mainteneur`
  (cible `~DEFAULT_BRANCH`) avec la seule règle *Restrict updates* et
  `Cezar277` comme unique acteur de contournement. Conséquence : **seul le
  mainteneur peut mettre à jour `main`**, donc seul il peut merger — un auteur
  de PR ne peut plus merger la sienne, même après approbation, et le bouton
  *Merge* reste bloqué pour tous les autres collaborateurs. Le contournement
  étant limité à ce ruleset, `Protection Main` (PR + approbation + checks)
  continue de s'appliquer au mainteneur. Recréation (idempotente, à rejouer si
  le ruleset est supprimé) :

  ```bash
  gh api -X POST repos/Cezar277/heimdall/rulesets --input - <<'JSON'
  {"name":"Merge réservé au mainteneur","target":"branch","enforcement":"active",
   "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
   "rules":[{"type":"update"}],
   "bypass_actors":[{"actor_id":82095388,"actor_type":"User","bypass_mode":"always"}]}
  JSON
  ```

  Rappel : ce ruleset ne remplace pas la revue humaine — il empêche seulement
  l'auteur de merger sa propre PR.
- **Actions** (Settings > Actions > General) : exiger l'approbation des
  workflows déclenchés depuis un fork (« Require approval for all external
  contributors ») ; *Workflow permissions* sur « Read repository contents » ;
  décocher « Allow GitHub Actions to create and approve pull requests ».
  Aucun runner self-hosted : tous les workflows tournent sur `ubuntu-latest`
  (VM jetable par job) et
  `tests/security/test_ci_workflow_static.py::test_aucun_workflow_actif_sur_runner_self_hosted`
  bloque toute régression. Ne jamais enregistrer de runner self-hosted sur ce
  dépôt public (une PR de fork y exécuterait son code).
- **Option** : « Require branches to be up to date before merging » augmente
  les re-runs — chaque « Update branch » exige de relancer `/ci` (ou
  ré-approuver) pour re-signaler le check. À n'activer que si nécessaire.

## Vérifier

Consolidation T42 : [SAMM v1 et preuves datées](docs/samm-v1.md),
[matrice d'acceptation fonctionnelle et de sécurité](docs/Functional_and_security_Acceptance_Testing_Case.md)
et [résultats d'exécution](docs/t42-validation.md). Les résultats distinguent
les tests de régression réussis des critères produit encore non satisfaits.

Corpus d'acceptation T21 : [34 cas synthétiques et mesure précision/rappel](tests/fixtures/trap_repo/README.md).
Exécuter `python -m pytest tests/test_trap_acceptance.py -s -rx` ; la CLI
`heimdall scan` (#29) est branchée sur ce scanner — voir
[docs/cli.md](docs/cli.md).

```sh
.venv/bin/python -m pytest                      # squelette + contrats
.venv/bin/python -m unittest discover -s tests/contracts -v   # contrats seuls
.venv/bin/python -m pytest tests/test_vault_integration_testclient.py -q   # Vault (TestClient)
.venv/bin/python -m pytest tests/test_cli_scan.py -q   # CLI scan (#29)
.venv/bin/python -m pytest tests/test_vault_crypto.py -q               # Vault (AES-256-GCM, nonce unique)
.venv/bin/python -m pytest tests/test_vault_falsification.py -q           # Vault (falsification AES-GCM)
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
projet, la conformité des réponses au contrat `openapi.yaml` **et du schéma
OpenAPI publié par l'application** (comparaison stricte, `required` compris),
le refus 403 d'une origine hors boucle locale, le 429 de débit avec
`Retry-After` borné, et le refus des abus d'entrée (corps > 1 Mio, identifiants
hors contrat, traversée de chemin). Preuves :
[`docs/t255-samm.md`](docs/t255-samm.md).

Chiffrement au repos (sous-ticket T67 de #26, via #66 « Module crypto isolé ») :
le nonce AES-GCM de 96 bits est tiré de `os.urandom` **à chaque** chiffrement
(jamais un compteur, jamais l'heure), le blob stocké contient
`nonce + ciphertext + tag`, et l'AAD est l'identifiant du secret
(`project/env/name`) : un blob copié sur un autre secret échoue à
l'authentification. Deux chiffrements du même texte donnent donc deux blobs
différents — c'est la preuve archivée pour le rapport. Preuves :
[`docs/t67-samm.md`](docs/t67-samm.md).

Chiffrement par enveloppe (sous-ticket T263 de #26) : chaque secret reçoit une
DEK aléatoire de 32 octets ; la valeur est chiffrée avec la DEK, puis la DEK
est chiffrée avec la KEK. Les deux blobs sont stockés dans la même ligne
(`encrypted_value`, `encrypted_dek`). Une fuite de DEK ne compromet donc qu'un
secret, et la KEK ne chiffre que des clés. Les lignes héritées, chiffrées
directement par la KEK avant #70, restent lisibles. Preuves :
[`docs/t263-samm.md`](docs/t263-samm.md),
`tests/test_vault_dek_envelope.py`.

Falsification du chiffrement au repos (sous-ticket T68 de #26, via #66
« Module crypto isolé ») : un seul octet modifié du blob (nonce, ciphertext ou
étiquette), une mauvaise clé ou un mauvais AAD font lever `VaultCipherError` —
jamais une valeur fausse. La suite utilise un vecteur figé (aucun tirage
aléatoire à l'exécution), vérifie le cas nominal avant chaque falsification et
couvre les 54 octets du blob un par un. Les jetons vides, base64 invalides,
tronqués ou étendus sont également refusés (gardes de format/longueur).
Preuves : [`docs/t68-samm.md`](docs/t68-samm.md).

Règles de contribution : [CONTRIBUTING.md](CONTRIBUTING.md).
Signaler une vulnérabilité (en privé) : [SECURITY.md](SECURITY.md).
Jamais de vrai secret dans le dépôt, même expiré ; seul `.env.example`
(noms sans valeurs) est versionné — `.env` est ignoré (voir `.gitignore`).

## Licence

Heimdall est distribué sous licence [Apache 2.0](LICENSE). Voir aussi [NOTICE](NOTICE).
