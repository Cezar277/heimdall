# ADR-002 — Stack Python et structure du dépôt

Statut : proposé. Ticket : #17. Porteur : D · Relecteur : B · Sprint S1.
Précédent : [ADR-001](001-finding-et-etats.md) (contrat Finding, inchangé).

## Contexte

Sans structure commune, l'équipe perd des jours en conflits d'imports et de
configuration (#20, #22, #25, #27 sont bloqués par ce ticket). Le projet est
100 % local (aucun appel Internet depuis l'outil), pentesté par une équipe
adverse (2 exploits minimum) : chaque choix doit être testé, documenté et
justifié par une preuve (module + ligne).

Contraintes : Python partout, reproductibilité des builds (versions
verrouillées + lock), `pip install -e .` et `pytest` verts sur Python ≥ 3.10.

## Décision : layout

```
heimdall/                  paquet unique, une frontière par composant
  scanner/  detect.py      détection déterministe (#22, contrat #14)
  mcp/      server.py      serveur stdio, 4 outils lecture seule (#27, contrat #16)
  vault/    crypto.py      SEUL module crypto (voir ci-dessous)
            client.py      client HTTPS, vérification TLS non désactivable
  cli/      main.py        entrée `heimdall` (Typer), `scan --ci` fail-closed
tests/  test_package.py, test_crypto_confinement.py + tests/contracts/ existants
docs/   adr/, contracts/, meetings/
pyproject.toml             manifeste unique (dépendances ==, extras [dev], entrée console)
requirements.lock          gel transitif horodaté (régénéré par `pip freeze`)
```

Un seul paquet (pas de monorepo multi-paquets) : imports absolus
`heimdall.scanner…`, zéro conflit de noms, `pip install -e .` suffit.
Alternative écartée : `src/`-layout — inutile à cette taille, il complique
`unittest discover` et les liens SAMM module + ligne.

## Décision : dépendances (versions au 2026-10-07, `==` dans pyproject.toml)

| Besoin | Choix | Pourquoi / écarté |
|---|---|---|
| API Vault (#25) | FastAPI 0.142.2 | Contrat #15 prouvé contre cette version exacte (fixture + comparaison wire). Écarté : Flask (OpenAPI non native, plus de code de validation à prouver). Aligné au `==` près avec `tests/contracts/requirements.txt`. |
| Modèles/validation | Pydantic 2.13.5 | Imposé par FastAPI ; `extra="forbid"` + `Literal` portent les erreurs `{code,message}` en `const`. |
| Serveur Vault | Uvicorn 0.54.0 | ASGI de référence pour FastAPI, réseau privé + TLS uniquement. Écarté : Gunicorn (orienté multi-worker réseau, inutile en local). |
| Serveur MCP (#27) | SDK `mcp` 2.3.0 | SDK officiel (stdio, registre fermé de 4 outils). Écarté : protocole maison (surface à prouver, contre l'invariant « surface minimale » de #16). |
| LLM local | `ollama` 0.6.3 | Client du démon local ; le code n'appelle jamais d'URL distante (garde-fou d'audit : `grep -rn "http" heimdall/` ne doit montrer que le Vault privé). Écarté : tout SDK cloud (interdit par « 100 % local »). |
| Chiffre au repos | `cryptography` 50.0.2 | Primitive auditée (AES-GCM). **Confinée à `heimdall/vault/crypto.py`** (test `test_crypto_confinement.py`). Écarté : `pycryptodome` (moins bon suivi des recettes AEAD), crypto maison (interdite). |
| Dérivation/hachage | `argon2-cffi` 25.1.0 | Argon2id (OWASP) pour dérivation et hachés salés des clés API. Confiné idem. Écarté : bcrypt (coût GPU moins favorable), `hashlib` seul (pas de KDF mémoire-dure). |
| HTTP sortant/tests | `httpx` 0.28.1 | Client ASGI en mémoire des tests + futur client Vault (`verify` toujours actif). Écarté : `requests` (sync seul, pas de transport ASGI). |
| CLI | Typer 0.27.3 | Typer au-dessus de Click : `--help` typé, `scan --ci` fail-closed testé par `CliRunner`. Écarté : `argparse` nu (plus de code, plus de preuves). |
| Tests | pytest 9.1.1 | Collecte aussi les `TestCase` unittest des contrats : une seule commande `pytest` couvre squelette + contrats. `unittest discover` reste supporté (CI contrat). |
| Lint | Ruff 0.16.10 | Remplace flake8/isort (vitesse, une config). Règles `E,F,I,UP,B,S,PL`. |
| Types | Mypy 2.4.0, `strict = true` | Le `strict` fige les stubs (`-> None`, pas de `Any` implicite) avant #22/#25/#27. Fixtures de contrats exclues (`ignore_errors`). |
| SAST | Bandit 1.9.4 | Garde-fou `subprocess`/`shell` (critique : `read_diff` bannit `shell=True`, #16 §4.1). |

## Décision : reproductibilité

- Toutes les dépendances sont en `==` dans `pyproject.toml` (+ `[dev]`).
- `requirements.lock` = `pip freeze` complet après `pip install -e .[dev]`,
  horodaté en en-tête, régénéré par la commande qui y figure.
- `tests/contracts/requirements.txt` garde ses `==` + **hashes SHA-256**
  (`--require-hashes` en CI) ; Spectral est figé via `package.json` +
  `package-lock.json` + `npm ci` (voir correctif LOW-4 dans la PR).

## Conséquences

- `pip install -e .[dev]` puis `pytest` : vert = critères d'acceptation #17.
- La crypto est testable en isolement (`vault/crypto.py`) ; tout import
  crypto hors `vault/` casse `test_crypto_confinement.py` et la revue.
- Risque : épinglage strict → mises à jour manuelles (dépendances de #20 :
  `pip install --upgrade` + régénération du lock + CI verte, dans un ticket
  dédié, jamais en passant).
- 100 % local vérifiable : aucune dépendance cloud ; le seul HTTP du socle
  est le Vault privé en TLS vérifié (voir `VaultClient`, `verify` non
  désactivable, #25 prouvera le rejet des certificats non approuvés).

## Preuve pour le rapport (partie 1 : cycle de vie)

- `pyproject.toml` (entrée `heimdall`, `==`, extras `[dev]`, configs
  pytest/ruff/mypy), `heimdall/` + `tests/test_package.py` +
  `tests/test_crypto_confinement.py`, `requirements.lock`.
- Lier la PR (`Closes #17`), coller `pip install -e .[dev]` + `pytest` verts,
  renseigner la feuille SAMM avec liens permanents au SHA (touche `y`).
