# T21 — preuves de validation

Validation locale du 19 octobre 2026, Windows, Python 3.11.9.
Base : `d789457` (branche T21 créée depuis `main`).

## Tests écrits avant le support de corpus

Premier lancement de `python -m pytest tests/test_trap_acceptance.py` : échec
de collecte `ModuleNotFoundError: No module named 'support.trap_corpus'`.
Le générateur et le calcul de mesure ont ensuite été implémentés, sans
modifier le scanner de production.

## Résultats ciblés

```text
.venv/Scripts/python.exe -m pytest tests/test_trap_acceptance.py -s -rx
17 passed, 1 xfailed
```

Le seul XFAIL est l'appel réel au scanner T22, qui lève encore
`NotImplementedError`. Il ne représente pas un scanner validé.
`python tests/measure_trap.py` retourne 2 et annonce des métriques indisponibles.
Les seuils de précision et rappel (0,90 chacun) sont exécutables dès que T22
est livré. Les six obfuscations restent visibles dans le bilan global.

Contrôles supplémentaires :

- `ruff check heimdall tests` : réussi.
- `bandit -r heimdall -q` : réussi.
- `mypy --platform linux heimdall tests/contracts/fastapi_contract_fixture.py` :
  réussi, 22 fichiers. Sans `--platform linux`, neuf erreurs préexistantes
  concernent `O_NOFOLLOW`, `O_CLOEXEC`, `O_NONBLOCK` et `fchmod`.
- `git diff --check` : réussi.
- `pip check` : réussi.

L'environnement utilise `requirements.lock` avec `--require-hashes`.
Deux dépendances spécifiques à Windows, absentes du lock Linux, ont été
ajoutées dans un complément local non versionné : `colorama==0.4.6` et
`pywin32==312`, chacune avec le SHA-256 de son wheel PyPI. Le lock du projet
n'a pas été modifié.

## Suite complète sous Windows

Commande : `python -m pytest --cov=heimdall --cov-branch
--cov-report=term-missing --cov-fail-under=85`.

Résultat : **612 passed, 131 failed, 102 skipped, 1 xfailed**, plus 3755
sous-tests réussis. Couverture : **74,46 %**, inférieure au seuil CI de 85 %.
Cette exécution n'est donc pas verte et ne remplace pas la CI Linux.

Contre-vérification dans un worktree détaché du commit d'origine `d789457` :
**595 passed, 131 failed, 102 skipped**, plus 3755 sous-tests réussis.
Les listes d'échecs sont identiques avant/après T21 ; la différence est
exactement les 17 nouveaux succès et le XFAIL attendu du scanner.

Les échecs sont dans les suites existantes : hypothèses LF/CRLF, permissions
de création des liens symboliques Windows, serveur MCP/Vault exigeant POSIX,
garde réseau utilisant des appels POSIX et installation T17 supposant
`venv/bin/python`. Aucun fichier de production ni test existant n'a changé.

## Traçabilité

- #49 : gabarits Python/JS et génération synthétique dans
  `tests/fixtures/trap_repo/` et `tests/support/trap_corpus.py`.
- #50 : UUID, hashes, intégrité, placeholders, image base64 et mocks, avec
  `leak: false` dans `tests/fixtures/trap_repo/expected.json`.
- #51 : six cas `limite_connue` dans cet oracle, inclus dans les FN globaux.
- #52 : `measure` et `scan_corpus` dans `tests/support/trap_corpus.py`, commande
  `tests/measure_trap.py`, seuils et tests dans `tests/test_trap_acceptance.py`.

Pour le rapport, utiliser le SHA du commit de livraison dans les liens
GitHub permanents et les lignes des fonctions correspondantes. Relecture
inter-domaines et CI Linux restent nécessaires avant fusion.
