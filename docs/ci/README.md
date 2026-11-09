# Modèles CI headless (#37)

Heimdall fournit deux modèles de pipeline à copier dans le dépôt à protéger :

- [`github-actions.yml`](github-actions.yml) pour GitHub Actions ;
- [`gitlab-ci.yml`](gitlab-ci.yml) pour GitLab CI.

Les deux exécutent le même verdict :

```sh
heimdall scan --ci --diff "origin/<branche-cible>" --no-allowlist --json
```

## Ce que fait le mode `--ci --diff REF`

- **Différentiel** : `git diff REF...HEAD` (trois points) part de l'ancêtre
  commun. Seuls les blobs ajoutés ou modifiés par la branche courante sont
  scannés ; un secret déjà présent sur la branche cible n'est pas re-signalé,
  un secret supprimé par la branche courante n'a plus de blob à scanner.
- **Headless** : aucun dialogue, aucun LLM, aucun réseau. Le verdict est le
  code de sortie : `0` propre, `1` secret(s) détecté(s), `2` erreur
  d'outillage (historique incomplet, référence absente, blob illisible…).
- **Sans exclusion de chemin** : `vendor/`, les lockfiles et les fichiers
  générés sont scannés s'ils changent. Un binaire connu est refusé (code 2),
  jamais sauté en silence.
- **Borné** : 1 000 fichiers, 32 Mio, 10 000 Findings, 120 s (mêmes bornes
  que `--staged`). Au-delà, code 2, jamais un rapport tronqué présenté comme
  complet.
- **JSON** : `--json` écrit le contrat `heimdall.scan.v1` sur stdout, avec
  `scope: "diff"`. Aucun secret n'y figure : seulement des empreintes HMAC.

## Les trois pièges à éviter

1. **Clone superficiel** : sans historique complet, git ne trouve pas
   l'ancêtre commun et le scan sort en 2. Les modèles imposent
   `fetch-depth: 0` (GitHub) et `GIT_DEPTH: "0"` (GitLab). Ne pas les
   retirer pour gagner du temps : un job vert sur un historique incomplet
   serait un faux négatif.
2. **Référence égale à `HEAD`** : `--diff HEAD` produit une plage vide et
   donc un verdict 0. Ce n'est pas un scan complet : utiliser la branche
   cible (`origin/main`, `origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`).
3. **Allowlist du dépôt** : en `--ci`, un `heimdall.toml` du dépôt scanné ne
   peut pas s'auto-attester. Les modèles utilisent `--no-allowlist` (verdict
   maximal). Pour une allowlist d'équipe, utiliser `--config` vers un fichier
   **hors du dépôt** :

   ```sh
   heimdall scan --ci --diff origin/main \
     --config /opt/heimdall/allowlist.toml --json
   ```

## GitHub Actions

Copier [`github-actions.yml`](github-actions.yml) dans
`.github/workflows/heimdall.yml`, puis remplacer `<sha>` par un commit
Heimdall vérifié (jamais une branche mobile). Le workflow :

- se déclenche sur `pull_request` (pas de `pull_request_target`) ;
- demande seulement `contents: read` ;
- épingle `actions/checkout` par SHA ;
- compare `origin/${{ github.base_ref }}` à `HEAD` ;
- écrit le JSON dans le journal via `tee`, avec `set -o pipefail` pour que
  l'exit 1/2 échoue bien l'étape.

## GitLab CI

Inclure [`gitlab-ci.yml`](gitlab-ci.yml) dans `.gitlab-ci.yml`, puis
remplacer `<sha>`. Le job :

- ne s'exécute que sur `merge_request_event` ;
- impose `GIT_DEPTH: "0"` et recharge la branche cible ;
- compare `origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME` à `HEAD` ;
- publie `heimdall-scan.json` en artefact même en cas d'échec
  (`when: always`).

## Vérifier localement

```sh
git fetch origin main
heimdall scan --ci --diff origin/main --no-allowlist --json
echo $?   # 0 propre, 1 secret, 2 outillage
```

Pour l'acceptation « repo piégé rouge / repo propre vert », ajouter un
secret synthétique sur une branche et vérifier le code 1, puis le retirer et
vérifier le code 0. Les tests `tests/test_cli_scan_diff.py` couvrent ces deux
cas, le clone superficiel, le JSON et les bornes.
