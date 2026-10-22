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
requirements.lock          gel transitif vérifié (compilé par `pip-compile --generate-hashes`)
```

Un seul paquet (pas de monorepo multi-paquets) : imports absolus
`heimdall.scanner…`, zéro conflit de noms, `pip install -e .` suffit.
Alternative écartée : `src/`-layout — inutile à cette taille, il complique
`unittest discover` et les liens SAMM module + ligne.

## Décision : dépendances (versions au 2026-10-07, `==` dans pyproject.toml)

| Besoin | Choix | Pourquoi / écarté |
|---|---|---|
| API Vault (#25) | FastAPI 0.143.1 | Contrat #15 prouvé contre cette version exacte (fixture + comparaison wire). Écarté : Flask (OpenAPI non native, plus de code de validation à prouver). Aligné au `==` près avec `tests/contracts/requirements.txt`. |
| Modèles/validation | Pydantic 2.14.1 | Imposé par FastAPI ; `extra="forbid"` + `Literal` portent les erreurs `{code,message}` en `const`. |
| Serveur Vault | Uvicorn 0.54.0 | ASGI de référence pour FastAPI, réseau privé + TLS uniquement. Écarté : Gunicorn (orienté multi-worker réseau, inutile en local). |
| Serveur MCP (#27) | SDK `mcp` 2.3.0 | SDK officiel (stdio, registre fermé de 4 outils). Écarté : protocole maison (surface à prouver, contre l'invariant « surface minimale » de #16). |
| LLM local | `ollama` 0.6.3 | Client du démon local ; le code n'appelle jamais d'URL distante (garde-fou d'audit : `grep -rn "http" heimdall/` ne doit montrer que le Vault privé). Écarté : tout SDK cloud (interdit par « 100 % local »). |
| Chiffre au repos | `cryptography` 50.0.2 | Primitive auditée (AES-GCM). **Confinée à `heimdall/vault/crypto.py`** (test `test_crypto_confinement.py`). Écarté : `pycryptodome` (moins bon suivi des recettes AEAD), crypto maison (interdite). |
| Dérivation/hachage | `argon2-cffi` 25.1.0 | Argon2id (OWASP) pour dérivation et hachés salés des clés API. Confiné idem. Écarté : bcrypt (coût GPU moins favorable), `hashlib` seul (pas de KDF mémoire-dure). |
| HTTP sortant/tests | `httpx` 0.28.1 | Client ASGI en mémoire des tests + futur client Vault (`verify` toujours actif). Écarté : `requests` (sync seul, pas de transport ASGI). |
| CLI | Typer 0.27.3 | Typer au-dessus de Click : `--help` typé, `scan --ci` fail-closed testé par `CliRunner`. Écarté : `argparse` nu (plus de code, plus de preuves). |
| Tests | pytest 9.1.1 | Collecte aussi les `TestCase` unittest des contrats : une seule commande `pytest` couvre squelette + contrats. `unittest discover` reste supporté (CI contrat). |
| Lint | Ruff 0.16.10 | Remplace flake8/isort (vitesse, une config). Règles `E,F,I,UP,B,S,PL`. |
| Types | Mypy 2.4.0, `strict = true` | Le `strict` fige les stubs (`-> None`, pas de `Any` implicite) avant #22/#25/#27, fixture de contrat incluse. Seul le reformat ruff est gelé sur `tests/contracts/`. |
| SAST | Bandit 1.9.4 | Garde-fou `subprocess`/`shell` (critique : `read_diff` bannit `shell=True`, #16 §4.1). |

## Décision : reproductibilité

- Toutes les dépendances sont en `==` dans `pyproject.toml` (+ `[dev]`).
- `requirements.lock` est compilé avec
  `pip-compile --allow-unsafe --generate-hashes --extra dev -o requirements.lock pyproject.toml`
  (hashes SHA-256) et s'installe avec
  `pip install --require-hashes -r requirements.lock` puis
  `pip install -e . --no-deps --no-build-isolation`. `pip` et `setuptools`
  sont inclus avec hashes (génération `--allow-unsafe`) ; l'en-tête du lock
  donne les commandes exactes.
- `tests/contracts/requirements.txt` garde ses `==` + **hashes SHA-256**
  (`--require-hashes` en CI) ; Spectral est figé via `package.json` +
  `package-lock.json` + `npm ci` (voir correctif LOW-4 dans la PR).

## Conséquences

- `pip install -e .[dev]` puis `pytest` : vert = critères d'acceptation #17.
- La crypto est testable en isolement (`vault/crypto.py`) ; tout import
  `cryptography`/`argon2` hors `vault/crypto.py` casse
  `test_crypto_confinement.py` et la revue.
- **Clarification de l'invariant 5 (T22)** : l'invariant porte sur les
  bibliothèques crypto `cryptography`/`argon2`, pas sur la bibliothèque
  standard. L'empreinte HMAC-SHA-256 du Finding (`hmac`/`hashlib`, plus
  `secrets` pour la génération de clé) est autorisée hors Vault, dans
  `heimdall/scanner/hashing.py` seul : elle est non réversible, locale et sans
  rapport avec la KEK ni les clés API. Aucune primitive de chiffrement, de
  dérivation de clé ou de hachage salé n'est introduite hors
  `heimdall/vault/crypto.py`.
- Risque : épinglage strict → mises à jour manuelles (dépendances de #20 :
  mise à jour des pins, régénération hashée du lock avec
  `pip-compile --allow-unsafe`, CI verte, dans un ticket dédié, jamais en passant).
- 100 % local vérifiable : aucune dépendance cloud ; le seul HTTP du socle
  est le Vault privé en TLS vérifié (voir `VaultClient`, `verify` non
  désactivable, #25 prouvera le rejet des certificats non approuvés).

## Preuve pour le rapport (partie 1 : cycle de vie)

- `pyproject.toml` (entrée `heimdall`, `==`, extras `[dev]`, configs
  pytest/ruff/mypy), `heimdall/` + `tests/test_package.py` +
  `tests/test_crypto_confinement.py`, `requirements.lock`.
- Lier la PR (`Closes #17`), coller `pip install -e .[dev]` + `pytest` verts,
  renseigner la feuille SAMM avec liens permanents au SHA (touche `y`).

## Suivi review (correctifs post-relecture)

- **Build reproductible de bout en bout** : `setuptools==83.0.0` épinglé
  dans `[build-system]` (un `>=` laissait le backend se résoudre
  différemment demain) ; `requirements.lock` est compilé avec
  `pip-compile --allow-unsafe --generate-hashes` depuis les extras `[dev]` et s'installe
  avec `pip install --require-hashes -r requirements.lock` puis
  `pip install -e . --no-deps --no-build-isolation` (l'editable local n'est pas hachable).
- **Codes de sortie CLI** (invariant 11 : 0 propre, 1 secrets, 2 erreur) :
  `scan` non implémenté sort en **2** (panne d'outillage), jamais 1 réservé
  aux secrets avérés ; testé (`test_scan_is_fail_closed_until_22`,
  `test_scan_reports_on_stderr`, isolation du cwd + aucun fichier créé).
- **VaultClient confiné au local** (invariant 12) : allowlist
  `127.0.0.1`/`::1`/`localhost` via `urllib.parse`, credentials en URL
  refusés, `repr()` redacté (`api_key=<REDACTED>`), clé conservée en mémoire
  uniquement pour s'authentifier et jamais journalisée (stockage mode 600
  en #26). Gardes de type : URL non-chaîne et clé vide/blanche rejetées en
  `ValueError` (jamais de `TypeError`) ; formes `%XX`, query/fragment, ports
  hors 1-65535 refusés ; URL stockée canonique reconstruite depuis hôte+port
  (IPv6 re-crocheté) ; messages d'exception des stubs statiques, sans
  interpolation d'entrée (invariant 8). Testé contre `https://evil.example`,
  `https://127.0.0.1.evil.example`, `http://…` et `https://user:…@…`.
- **Confinement crypto prouvé par AST** : le garde analyse
  `Import`/`ImportFrom`/`__import__`/`importlib.import_module` et n'autorise
  que `heimdall/vault/crypto.py` (fichier exact, pas le dossier) ; méta-tests
  sur extraits piégés + arborescence synthétique.
- **Outillage sur `tests/contracts/`** : seul le reformat ruff est gelé
  (refs SAMM stables) — `mypy --strict` couvre aussi la fixture
  (`NoReturn`, handlers typés) et le SAST y est appliqué en CI
  (`vault-contract.yml` : `bandit` + `ruff --select S` sur la fixture).
  La preuve de format reste portée par les tests de schémas eux-mêmes
  (comparaison wire + matrice code/message) + Spectral. En revanche les
  FICHIERS DE TESTS des contrats restent hors SAST par construction : ils
  embarquent volontairement des faux réalistes (`sk_live_x` en
  `test_mcp_tools_schema.py:234` pour tester le masquage), donc
  `bandit`/`ruff-S` y lèvent B106/S106 par design — forcer le gate exigerait
  des `noqa` dans les preuves gelées #14/#16. Leur garde est la validation
  de schémas, pas le scan de secrets. Pas de section `coverage` avant
  #20 (seuil CI à définir en réunion, cf. DEFINITION_OF_DONE).
