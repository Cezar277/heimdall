# T41 — preuves Docker, compose et installation

Périmètre : ticket parent **#41 « Docker, compose et doc d'installation »** et
ses sous-tickets #119 à #122. Cette fiche archive les commandes, les fichiers
et les résultats vérifiés pour l'audit croisé.

Révision du code testé : `9a21373f0124d8a5089a833cf61f466dc9966aa7`.

## 1. Correspondance ticket → livrable → preuve

| Ticket | Livrable | Preuve |
|---|---|---|
| **#119** Dockerfile durci du Vault | [Dockerfile](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/Dockerfile#L12-L66), [.dockerignore](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/.dockerignore#L1-L40), [docker/healthcheck.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker/healthcheck.py#L21-L47), [requirements-runtime.lock](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/requirements-runtime.lock#L1-L5) | Build multi-étapes, `USER 10001:10001`, `HEALTHCHECK`, dépendances hashées, aucun secret dans l'image ; [tests/test_docker_assets.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/tests/test_docker_assets.py#L46-L98) |
| **#120** docker-compose | [docker-compose.yml](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L20-L52), [.env.example](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/.env.example#L1-L12) | `network_mode: host` (loopback), `read_only`, `cap_drop: ALL`, `no-new-privileges`, limites, volume `./data`, secrets TLS montés en lecture seule ; `docker compose config` valide ; [tests/test_docker_assets.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/tests/test_docker_assets.py#L100-L165) |
| **#121** Guide d'installation | [docs/install.md](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docs/install.md#L44-L312) | Procédure pas à pas testée : génération des secrets/TLS, `docker compose up`, health, clé API, secret, audit, premier scan ; [tests/test_docker_assets.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/tests/test_docker_assets.py#L167-L186) |
| **#122** Test à froid | [docs/t122-cold-test.md](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docs/t122-cold-test.md#L1-L65) | Protocole et résultats du test à froid ; validation par une personne externe à signer avant l'audit |

## 2. Invariants de sécurité vérifiés

| Invariant | Implémentation | Preuve |
|---|---|---|
| **Le Vault reste loopback-only** | `network_mode: host`, aucun `ports`, `HEIMDALL_VAULT_HOST=127.0.0.1` | [docker-compose.yml:20](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L20), test `test_vault_is_loopback_only_via_host_network` ; health et secrets testés sur `127.0.0.1:8443` |
| **Conteneur non root** | `USER 10001:10001` dans l'image, `user: "${HEIMDALL_UID}:${HEIMDALL_GID}"` dans compose, entrypoint refusant `euid == 0` | [Dockerfile:57](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/Dockerfile#L57), [docker-compose.yml:25](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L25), [docker/entrypoint.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker/entrypoint.py#L1-L26), tests `test_entrypoint_refuses_root`, `test_image_runs_as_non_root_and_has_healthcheck` ([tests/test_docker_assets.py:264](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/tests/test_docker_assets.py#L264)) |
| **Système de fichiers en lecture seule** | `read_only: true`, `tmpfs /tmp`, volume `./data` seul inscriptible | [docker-compose.yml:21](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L21), test `test_container_is_hardened` |
| **Moindre privilège** | `cap_drop: ALL`, `no-new-privileges:true`, `pids_limit`, `mem_limit` | [docker-compose.yml:41](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L41), test `test_container_is_hardened` |
| **Aucun secret dans l'image** | `.dockerignore` exclut `.env`, `secrets/`, `*.key`, `*.pem` ; Dockerfile ne définit aucune variable secrète | [.dockerignore](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/.dockerignore#L1-L40), tests `test_no_secret_or_dev_tool_is_baked_into_the_image`, `test_dockerignore_excludes_secrets_and_dev_context` |
| **Dépendances runtime hashées** | `requirements-runtime.lock` généré depuis `requirements.lock`, sans pytest/mypy/ruff/bandit/pip-audit ; `setuptools` retiré de l'image runtime | [scripts/regen_runtime_lock.py](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/scripts/regen_runtime_lock.py#L1-L20), [Dockerfile:28-29](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/Dockerfile#L28-L29), test `test_runtime_lock_excludes_dev_tools` |
| **TLS fail-closed** | certificat/clé obligatoires en production, montés depuis `./secrets` en lecture seule | [docker-compose.yml:34](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker-compose.yml#L34), [docs/install.md](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docs/install.md#L44-L83), healthcheck HTTPS avec vérification du certificat |
| **Healthcheck sans secret** | `docker/healthcheck.py` interroge `/api/v1/health`, vérifie le certificat local, message d'échec générique | [docker/healthcheck.py:21](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docker/healthcheck.py#L21), test `HealthcheckTests` |
| **Bind mounts sans symlink** | `test ! -L data && test ! -L secrets` avant `mkdir`, puis `chmod 700` | [docs/install.md](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docs/install.md#L50-L58), test `test_guide_covers_the_cold_start_path` |
| **Aucun secret dans le dépôt** | `.env`, `data/`, `secrets/`, `*.key`, `*.pem` ignorés ; `.env.example` à valeurs vides | [.gitignore](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/.gitignore#L21-L40), [.env.example](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/.env.example#L1-L12), test `test_env_example_has_no_real_secret` |
| **Clé API hors `argv`** | guide : `read -rsp`, validation charset, `mktemp`, fichier d'en-tête `600`, `curl -K`, jamais `curl -H "...$KEY"` | [docs/install.md](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/docs/install.md#L117-L166), test `test_guide_covers_the_cold_start_path` |
| **Image de base immuable** | `FROM python:3.12-slim@sha256:...` (builder et runtime) | [Dockerfile:12,32](https://github.com/Cezar277/heimdall/blob/9a21373f0124d8a5089a833cf61f466dc9966aa7/Dockerfile#L12), test `test_image_is_multi_stage_and_pinned` |

## 3. Commandes vérifiées

### Build et démarrage

```sh
docker compose config --quiet
docker compose build --pull
docker compose up -d --build
docker compose ps
docker compose logs --tail=50 vault
```

Résultat observé : build réussi, conteneur `Up ... (healthy)`, logs
`Uvicorn running on https://127.0.0.1:8443`.

### Santé

```sh
curl --cacert secrets/vault_tls_cert.pem \
  https://127.0.0.1:8443/api/v1/health
# {"status":"ok"}
```

### Clé API, secret et audit

```sh
docker compose exec -T vault heimdall vault key create --project demo
# clé affichée une seule fois

read -rsp "Clé API: " HEIMDALL_API_KEY; echo
[[ "$HEIMDALL_API_KEY" =~ ^[A-Za-z0-9_-]{43,}$ ]] || {
  echo "clé API invalide" >&2
  exit 1
}
umask 077
AUTH_HEADER="$(mktemp /tmp/heimdall-auth.XXXXXX)"
trap 'rm -f "$AUTH_HEADER"' EXIT
chmod 600 "$AUTH_HEADER"
printf 'header = "X-Heimdall-API-Key: %s"\n' "$HEIMDALL_API_KEY" \
  > "$AUTH_HEADER"
unset HEIMDALL_API_KEY

curl --cacert secrets/vault_tls_cert.pem \
  -K "$AUTH_HEADER" \
  -H 'Content-Type: application/json' \
  -d '{"project":"demo","env":"dev","name":"DEMO_PASSWORD","value":"valeur-de-demonstration"}' \
  https://127.0.0.1:8443/api/v1/secrets
# 201

curl --cacert secrets/vault_tls_cert.pem \
  -K "$AUTH_HEADER" \
  https://127.0.0.1:8443/api/v1/secrets/demo/dev/DEMO_PASSWORD
# 200 avec la valeur

docker compose exec -T vault heimdall vault audit list --limit 5
# événements 201/200, aucune valeur de secret
```

### Premier scan local

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-runtime.lock
.venv/bin/pip install -e . --no-deps --no-build-isolation

mkdir -p /tmp/heimdall-clean && cd /tmp/heimdall-clean
git init -q
/path/vers/heimdall/.venv/bin/heimdall scan .
# exit 0

printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' > demo.txt
git add demo.txt
/path/vers/heimdall/.venv/bin/heimdall scan .
# exit 1, valeur jamais affichée en clair
```

## 4. Tests automatisés

```sh
python -m pytest tests/test_docker_assets.py -q
ruff check heimdall tests scripts
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
```

Les tests Docker sont **statiques** : ils ne nécessitent pas de démon Docker
en CI. Le test à froid réel est archivé dans `docs/t122-cold-test.md`.

## 5. Limites connues

- `network_mode: host` est requis par la garde loopback : le Vault Docker est
  supporté sur Linux, pas sur Docker Desktop macOS/Windows.
- Le certificat fourni par le guide est auto-signé pour un usage local ; un
  déploiement réel doit utiliser un certificat interne avec SAN
  `IP:127.0.0.1`.
- Le scan n'est pas exécuté dans l'image Vault (pas de `git` dans l'image
  minimale) : la CLI locale est installée dans un venv dédié.
- Le test à froid par une personne externe reste à signer par l'opérateur
  avant l'audit ; le protocole et les résultats automatisés sont fournis.
