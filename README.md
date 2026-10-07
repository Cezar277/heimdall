# heimdall

Local-first DevSecOps sentry. Deterministic secret interception, local agentic remediation (MCP/Ollama), and encrypted on-premise vault synchronization.

Heimdall est un outil **100 % local** (aucun appel vers Internet) qui empêche
les secrets (mots de passe, clés API, clés privées) de finir dans Git.
Le LLM local propose, le programme vérifie, l'humain valide (`Y / N / E`) ;
en CI (`heimdall scan --ci`), un secret en clair fait échouer le pipeline.

## Installation

Python 3.10 ou supérieur :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .        # runtime
.venv/bin/python -m pip install -e .[dev]    # + pytest, ruff, mypy, bandit, validateurs de contrats
```

Windows / PowerShell : remplacer `.venv/bin/python` par `.venv\Scripts\python.exe`.

Builds reproductibles : versions en `==` dans `pyproject.toml`
(voir [ADR-002](docs/adr/002-stack-python.md)), gel transitif **avec hashes
SHA-256** dans `requirements.lock` :

```sh
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install -e . --no-deps
```

## Usage

```sh
heimdall --help
heimdall --version
heimdall scan             # bloqué tant que le scanner #22 n'est pas livré (fail-closed)
heimdall scan --ci        # idem : refuse par défaut plutôt que d'inventer un verdict
```

## Structure

```text
heimdall/            paquet unique (#17)
  scanner/           détection déterministe regex + entropie (#22, contrat #14)
  mcp/               serveur MCP stdio, 4 outils lecture seule (#27, contrat #16)
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
- [ADR-001 : Finding et faux positifs](docs/adr/001-finding-et-etats.md)
- [ADR-002 : Stack Python et structure du dépôt](docs/adr/002-stack-python.md)

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
