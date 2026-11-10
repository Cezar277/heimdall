# syntax=docker/dockerfile:1.7
# Digest de base : mettre à jour avec
#   docker buildx imagetools inspect python:3.12-slim
# puis remplacer le @sha256 ci-dessous après test du build.
#
# Image de production du Vault Heimdall (#119).
# - Build multi-étapes : aucun compilateur ni outil de développement dans l'image finale.
# - Dépendances runtime installées depuis requirements-runtime.lock (hashes SHA-256).
# - Utilisateur non root, système de fichiers racine en lecture seule côté compose.
# - Aucun secret n'est copié dans l'image : ils arrivent par .env / secrets Docker.

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Dépendances runtime verrouillées et vérifiées par hash.
COPY requirements-runtime.lock ./
RUN python -m pip install --require-hashes --no-cache-dir --no-compile \
        -r requirements-runtime.lock

# Paquet Heimdall (Vault + CLI), sans dépendances supplémentaires.
COPY pyproject.toml README.md ./
COPY heimdall ./heimdall
RUN python -m pip install --no-deps --no-build-isolation --no-cache-dir --no-compile . \
    && python -m pip uninstall -y setuptools


FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEIMDALL_ENV=production \
    HEIMDALL_VAULT_HOST=127.0.0.1 \
    HEIMDALL_VAULT_PORT=8443 \
    HEIMDALL_VAULT_STORAGE_BACKEND=sqlite \
    HEIMDALL_VAULT_DB_PATH=/data/vault.db

# Utilisateur système non root, sans home ni shell de connexion.
RUN groupadd --gid 10001 heimdall \
    && useradd --uid 10001 --gid heimdall \
        --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin heimdall \
    && mkdir -p /data /app \
    && chown heimdall:heimdall /data /app \
    && chmod 0700 /data

# Uniquement le runtime Python et l'entrée CLI : pas d'outils de développement dans le PATH.
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/heimdall /usr/local/bin/heimdall
COPY --chown=heimdall:heimdall docker/healthcheck.py /app/healthcheck.py
COPY --chown=heimdall:heimdall docker/entrypoint.py /app/entrypoint.py

WORKDIR /app
USER 10001:10001

VOLUME ["/data"]
EXPOSE 8443
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "/app/healthcheck.py"]

ENTRYPOINT ["python", "/app/entrypoint.py"]
