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
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps
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
  llm/               client Ollama local, sortie JSON contrainte (#80, T28.2)
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

## Vérifier

```sh
.venv/bin/python -m pytest                      # squelette + contrats
.venv/bin/python -m unittest discover -s tests/contracts -v   # contrats seuls
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
.venv/bin/bandit -r heimdall -q
git diff --check
```

Règles de contribution : [CONTRIBUTING.md](CONTRIBUTING.md).
Jamais de vrai secret dans le dépôt, même expiré ; seul `.env.example`
(noms sans valeurs) est versionné — `.env` est ignoré (voir `.gitignore`).
