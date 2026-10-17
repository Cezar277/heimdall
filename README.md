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
# Lancement du serveur Vault (point d'entrée unique, boucle locale vérifiée) :
python -m heimdall.vault.app
```

> **Note sécurité & dette technique (contrat OpenAPI #15)** :
> Ce squelette minimal (#25) est strictement confiné à la boucle locale (`127.0.0.1`, `::1`, `localhost`).
> Ne jamais exposer ce serveur en clair hors de localhost ni réutiliser ce montage HTTP au-delà du squelette minimal (#25). Les exigences runtime suivantes sont tracées et attribuées aux tickets du Vault :
> - **Rejet fail-closed HTTP 403 sur IP non-loopback** : garde middleware en défense en profondeur (niveau transport/socket), volontairement maintenue hors du contrat OpenAPI applicatif (`/api/v1/health` étant publique sans clé).
> - **TLS avec SAN IP obligatoire (`https://127.0.0.1:8443`)** : tickets #64 / #65.
> - **Authentification par clé API de projet (`X-Heimdall-API-Key`)** : ticket #64.
> - **Rejet HTTP 400 avant parsing au-delà de 1 Mio (1 048 576 octets)** : ticket #63.
> - **En-tête `Cache-Control: no-store`** : ticket #63.
> - **Rate-limit par bucket avec `Retry-After`** : ticket #64.

Vérifier la santé minimale (`/api/v1/health` contractuel) :

```sh
curl http://127.0.0.1:8443/api/v1/health
# {"status": "ok"}
```

## Structure

```text
heimdall/            paquet unique (#17)
  scanner/           détection déterministe regex + entropie (#22, contrat #14)
  mcp/               serveur MCP stdio, 4 outils lecture seule (#27, contrat #16)
    prompts/         prompt système versionné du trieur (qualify_v1, #80)
  llm/               client Ollama local, sortie JSON contrainte (#80, T28.2), candidat fail-closed (#81)
  vault/             Vault chiffré ; crypto CONFINÉE à vault/crypto.py (#25, contrat #15)
  cli/               entrée `heimdall` (Typer)
tests/               fumée paquet + confinement crypto + tests/contracts/
docs/                adr/, contracts/, meetings/
schemas/             finding.schema.json, mcp-tools.schema.json
openapi.yaml         contrat Vault API v1 (#15)
```

## Contrats et décisions

- [Vault API v1 et vérification OpenAPI](docs/contracts/vault-api.md)
- [Finding v1 et machine d'états du secret](docs/contracts/finding.md)
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
interdit les connexions Python hors loopback. Le scan réel reste bloqué par le
squelette du scanner #22 ; la trace disponible prouve uniquement l'absence de
connexion sur ce chemin fail-closed, pas encore sur un scan opérationnel.

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

```sh
.venv/bin/python -m pytest                      # squelette + contrats
.venv/bin/python -m unittest discover -s tests/contracts -v   # contrats seuls
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
.venv/bin/bandit -r heimdall -q
.venv/bin/python -m pytest --cov=heimdall --cov-branch \
    --cov-report=term-missing --cov-fail-under=85   # idem CI (#20)
.venv/bin/pip-audit --skip-editable             # comme la CI : requête réseau (PyPI)
git diff --check
```

Règles de contribution : [CONTRIBUTING.md](CONTRIBUTING.md).
Jamais de vrai secret dans le dépôt, même expiré ; seul `.env.example`
(noms sans valeurs) est versionné — `.env` est ignoré (voir `.gitignore`).
