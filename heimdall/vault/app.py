"""Application FastAPI du serveur Vault Heimdall — squelette (ticket #25).

Ce module initialise l'application FastAPI pour le serveur Vault, sa configuration
lue dans les variables d'environnement (via pydantic-settings) et la route de santé.

Lancement du serveur :
    python -m heimdall.vault.app
    (Point d'entrée unique supporté et documenté : garantit la validation de l'hôte
    et le durcissement du transport uvicorn).

RÈGLES DE SÉCURITÉ ET CONFORMITÉ (DoD, STRIDE, pentest) :
- Allowlist boucle locale : écoute EXCLUSIVEMENT sur la boucle locale (127.0.0.1, ::1, localhost),
  strictement alignée sur `heimdall.vault.client._ALLOWED_LOOPBACK_HOSTS`.
  Toute adresse LAN, WAN, broadcast, 0.0.0.0 ou adresse loopback hors allowlist (ex: 127.0.0.2)
  est rejetée (mitigation Network exposure / Spoofing).
- Garde middleware fail-closed : applique la même allowlist stricte `_ALLOWED_LOOPBACK_HOSTS`
  (avec support pour la forme IPv4-mappée ::ffff:127.0.0.1) et rejette (HTTP 403) toute
  requête sans client identifié ou provenant d'une adresse hors allowlist. Les en-têtes
  X-Forwarded-For sont ignorés et uvicorn est configuré avec proxy_headers=False,
  forwarded_allow_ips="", server_header=False et date_header=False
  (anti-spoofing et anti-fingerprinting).
- Documentation désactivée par défaut : docs_url, redoc_url et openapi_url sont désactivés
  pour interdire la reconnaissance d'empreinte (fingerprinting) et l'exposition de version/schéma.
- Schéma OpenAPI conforme : /api/v1/health déclare fidèlement les réponses du contrat openapi.yaml
  (200, 405, 429, 500, 503, default) avec header Retry-After obligatoire sur 429 et 503. Le rejet
  fail-closed HTTP 403 du middleware loopback est une défense en profondeur au niveau transport
  (socket/peer), volontairement maintenue hors du contrat OpenAPI applicatif (route publique). Seul
  /api/v1/health est exposé (aucun alias racine non contractuel).
- Allowlist sur les en-têtes d'exception : seuls Allow et Retry-After (1-3600) sont retransmis.
- Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography ou
  argon2 (réservés exclusivement à heimdall/vault/crypto.py).
- Gestion d'erreurs normalisée :
  - RequestValidationError -> 400 contractuel {"code": "bad_request", "message": "Requête invalide"}
    sans écho du corps ni enveloppe 422 de FastAPI.
  - StarletteHTTPException -> format contractuel préservant le status_code (400, 401, 403, 404,
    405, 409, 429, 503) sans fuite d'enveloppe framework {"detail": ...}.
  - Exception non gérée -> 500 {"code": "internal_error", "message": "Erreur interne"}.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

import uvicorn
from fastapi import Depends, FastAPI, Response
from fastapi import Path as FastApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from heimdall.vault.database import (
    DEFAULT_DB_PATH,
    db_session,
    resolve_db_path,
    validate_db_path,
)

_ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})
_MAX_BODY_SIZE: int = 1_048_576  # 1 Mio (1 048 576 octets)

logger = logging.getLogger("heimdall.vault.app")

# Seuil ASCII en dessous duquel un caractère est un caractère de contrôle.
_CONTROL_CHAR_THRESHOLD: int = 0x20

_ERROR_PAYLOADS: dict[int, dict[str, str]] = {
    400: {"code": "bad_request", "message": "Requête invalide"},
    401: {"code": "unauthorized", "message": "Authentification requise"},
    403: {"code": "forbidden", "message": "Accès interdit"},
    404: {"code": "not_found", "message": "Ressource introuvable"},
    405: {"code": "method_not_allowed", "message": "Méthode non autorisée"},
    409: {"code": "conflict", "message": "Secret déjà existant"},
    429: {"code": "rate_limited", "message": "Trop de requêtes"},
    500: {"code": "internal_error", "message": "Erreur interne"},
    503: {"code": "unavailable", "message": "Service indisponible"},
}


class BadRequestError(BaseModel):
    """Erreur 400 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["bad_request"] = "bad_request"
    message: Literal["Requête invalide"] = "Requête invalide"


class UnauthorizedError(BaseModel):
    """Erreur 401 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["unauthorized"] = "unauthorized"
    message: Literal["Authentification requise"] = "Authentification requise"


class ForbiddenError(BaseModel):
    """Erreur 403 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["forbidden"] = "forbidden"
    message: Literal["Accès interdit"] = "Accès interdit"


class NotFoundError(BaseModel):
    """Erreur 404 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["not_found"] = "not_found"
    message: Literal["Ressource introuvable"] = "Ressource introuvable"


class MethodNotAllowedError(BaseModel):
    """Erreur 405 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["method_not_allowed"] = "method_not_allowed"
    message: Literal["Méthode non autorisée"] = "Méthode non autorisée"


class ConflictError(BaseModel):
    """Erreur 409 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["conflict"] = "conflict"
    message: Literal["Secret déjà existant"] = "Secret déjà existant"


class RateLimitedError(BaseModel):
    """Erreur 429 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["rate_limited"] = "rate_limited"
    message: Literal["Trop de requêtes"] = "Trop de requêtes"


class UnavailableError(BaseModel):
    """Erreur 503 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["unavailable"] = "unavailable"
    message: Literal["Service indisponible"] = "Service indisponible"


class InternalError(BaseModel):
    """Erreur 500 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["internal_error"] = "internal_error"
    message: Literal["Erreur interne"] = "Erreur interne"


project_api_key_header = APIKeyHeader(
    name="X-Heimdall-API-Key",
    scheme_name="ProjectApiKey",
    auto_error=False,
    description=(
        "Clé d'authentification projet (ticket #64). "
        "Générée à >= 256 bits via secrets.token_urlsafe(32)."
    ),
)


def generate_api_key() -> str:
    """Génère une clé API aléatoire avec au moins 256 bits d'entropie (ticket #64)."""
    return secrets.token_urlsafe(32)


_DUMMY_HASH: str = "0" * 64
_HASH_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{64}$")


def hash_api_key(key: str, pepper: str | bytes | None = None) -> str:
    """Hachage HMAC-SHA256 de vérification d'une clé API avec pepper serveur (ticket #64).

    Conformité openapi.yaml:197-200 :
    Le serveur DOIT stocker uniquement un haché salé de vérification de la clé
    (sel unique par clé, ou HMAC avec un pepper serveur distinct de la KEK de
    chiffrement), jamais sa valeur brute ; la fonction de hachage et la gestion
    du sel/pepper sont documentées pour #25.
    """
    if pepper is None:
        pepper = os.environ.get(
            "HEIMDALL_VAULT_API_KEY_PEPPER",
            "heimdall_default_vault_pepper_dev_only",
        )
    pepper_bytes = pepper.encode("utf-8") if isinstance(pepper, str) else bytes(pepper)
    return hmac.new(pepper_bytes, key.encode("utf-8"), hashlib.sha256).hexdigest()


PROJECT_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_-]{0,63}(?![\s\S])")
ENV_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_-]{0,31}(?![\s\S])")
NAME_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]{1,63}(?![\s\S])")

ProjectId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=PROJECT_PATTERN,
    ),
]
EnvironmentId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=ENV_PATTERN,
    ),
]
SecretName = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=64,
        pattern=NAME_PATTERN,
    ),
]
# NOTE DE SÉCURITÉ : Ne jamais journaliser SecretValue (valeur sensible brute pouvant
# contenir des caractères de contrôle ou retours chariot multilignes : risque de log
# injection et de fuite en clair).
SecretValue = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=65536,
    ),
]
SecretStatus = Literal["vaulte", "rote"]


class SecretCreate(BaseModel):
    """Corps de requête pour la création d'un secret (POST /api/v1/secrets)."""

    model_config = ConfigDict(extra="forbid", regex_engine="python-re")
    project: ProjectId
    env: EnvironmentId
    name: SecretName
    value: SecretValue

    @field_validator("value")
    @classmethod
    def validate_value_no_null(cls, v: str) -> str:
        """Refuse les octets NUL dans la valeur du secret (défense en profondeur).

        Ne jamais journaliser cette valeur en cas d'erreur (anti-fuite de secret).
        """
        if "\x00" in v:
            raise ValueError("Le caractère NUL est interdit dans la valeur du secret.")
        return v


class SecretMetadata(BaseModel):
    """Métadonnées d'un secret retournées lors de sa création (201 Created)."""

    model_config = ConfigDict(extra="forbid", regex_engine="python-re")
    project: ProjectId
    env: EnvironmentId
    name: SecretName
    status: SecretStatus


class SecretRead(SecretMetadata):
    """Représentation complète d'un secret retournée lors de sa lecture (200 OK)."""

    value: SecretValue


_DEFAULT_MAX_SECRETS: int = 10_000
_DEFAULT_MAX_SECRETS_PER_PROJECT: int = 1_000


class QuotaExceededError(Exception):
    """Exception levée en cas de dépassement de quota (global ou par projet)."""


class InMemorySecretStore:
    """Stockage mémoire des secrets pour le squelette fonctionnel (ticket #63).

    NOTE DE SÉCURITÉ :
    Squelette mémoire temporaire non chiffré, strictement réservé aux tests et
    au développement. Ne jamais déployer en production.
    TODO(#26, #62) : Remplacer par le chiffrement au repos (AES-256-GCM / DEK) et
    la persistance SQLite avec contrainte d'unicité UNIQUE(project_id, env, name)
    et PRAGMA foreign_keys=ON.
    TODO(#62) : Poursuivre le quota par projet et la pagination lors du branchement
    SQLite pour borner la croissance disque et mémoire (protection anti-DoS), en
    distinguant quota de stockage et débit (retry inutile tant que la capacité est pleine).
    Ce stockage en mémoire est strictement mono-processus (workers=1). Avec plusieurs
    workers (workers > 1), chaque worker détiendrait une instance mémoire indépendante
    et divergente sans garantie d'unicité inter-processus.
    """

    def __init__(
        self,
        max_secrets: int = _DEFAULT_MAX_SECRETS,
        max_secrets_per_project: int = _DEFAULT_MAX_SECRETS_PER_PROJECT,
    ) -> None:
        self._secrets: dict[tuple[str, str, str], dict[str, str]] = {}
        self._project_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._max_secrets = max_secrets
        self._max_secrets_per_project = max_secrets_per_project

    async def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        async with self._lock:
            record = self._secrets.get((project, env, name))
            if record is None:
                return None
            return dict(record)

    async def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        key = (project, env, name)
        async with self._lock:
            if key in self._secrets:
                raise KeyError("Secret déjà existant")
            if len(self._secrets) >= self._max_secrets:
                raise QuotaExceededError("Capacité maximale globale du store atteinte")
            project_count = self._project_counts.get(project, 0)
            if project_count >= self._max_secrets_per_project:
                raise QuotaExceededError(
                    f"Quota maximal de secrets atteint pour le projet '{project}'"
                )
            record = {
                "project": project,
                "env": env,
                "name": name,
                "status": "vaulte",
                "value": value,
            }
            self._secrets[key] = record
            self._project_counts[project] = project_count + 1
            return dict(record)

    async def clear(self) -> None:
        async with self._lock:
            self._secrets.clear()
            self._project_counts.clear()


_MAX_RETRY_AFTER_SECONDS: int = 3600

_RETRY_AFTER_HEADER = {
    "Retry-After": {
        "required": True,
        "description": "Délai en secondes avant nouvelle tentative.",
        "schema": {"type": "integer", "minimum": 1, "maximum": _MAX_RETRY_AFTER_SECONDS},
    }
}

_HEALTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    405: {"model": MethodNotAllowedError, "description": "Méthode non autorisée"},
    429: {
        "model": RateLimitedError,
        "description": "Trop de requêtes",
        "headers": _RETRY_AFTER_HEADER,
    },
    500: {"model": InternalError, "description": "Erreur interne"},
    503: {
        "model": UnavailableError,
        "description": "Service indisponible",
        "headers": _RETRY_AFTER_HEADER,
    },
    "default": {"model": InternalError, "description": "Erreur inattendue"},
}

_NO_STORE_HEADER = {
    "Cache-Control": {
        "required": True,
        "description": "Réponse interdite de mise en cache.",
        "schema": {"type": "string", "const": "no-store"},
    }
}

_SECRETS_POST_RESPONSES: dict[int | str, dict[str, Any]] = {
    201: {
        "model": SecretMetadata,
        "description": "Secret créé (squelette mémoire non chiffré, persistance chiffrée #26/#62).",
        "headers": _NO_STORE_HEADER,
    },
    400: {"model": BadRequestError, "description": "Requête invalide"},
    401: {"model": UnauthorizedError, "description": "Authentification requise (ticket #64)"},
    403: {"model": ForbiddenError, "description": "Accès interdit (ticket #64)"},
    405: {"model": MethodNotAllowedError, "description": "Méthode non autorisée"},
    409: {"model": ConflictError, "description": "Secret déjà existant"},
    429: {
        "model": RateLimitedError,
        "description": (
            "Trop de requêtes — quota de stockage par projet (ticket #63, #62) ; "
            "rate-limiting réseau/clé à implémenter (ticket #65, TODO(#65))."
        ),
        "headers": _RETRY_AFTER_HEADER,
    },
    500: {"model": InternalError, "description": "Erreur interne"},
    "default": {"model": InternalError, "description": "Erreur inattendue"},
}

_SECRETS_GET_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "model": SecretRead,
        "description": "Valeur courante, à ne jamais journaliser ni mettre en cache.",
        "headers": _NO_STORE_HEADER,
    },
    400: {"model": BadRequestError, "description": "Paramètre de chemin invalide"},
    401: {"model": UnauthorizedError, "description": "Authentification requise (ticket #64)"},
    403: {"model": ForbiddenError, "description": "Accès interdit (ticket #64)"},
    404: {"model": NotFoundError, "description": "Ressource introuvable"},
    405: {"model": MethodNotAllowedError, "description": "Méthode non autorisée"},
    429: {
        "model": RateLimitedError,
        "description": (
            "Trop de requêtes — quota de stockage par projet (ticket #63, #62) ; "
            "rate-limiting réseau/clé à implémenter (ticket #65, TODO(#65))."
        ),
        "headers": _RETRY_AFTER_HEADER,
    },
    500: {"model": InternalError, "description": "Erreur interne"},
    "default": {"model": InternalError, "description": "Erreur inattendue"},
}


class VaultSettings(BaseSettings):
    """Configuration du serveur Vault via variables d'environnement."""

    model_config = SettingsConfigDict(
        env_prefix="HEIMDALL_VAULT_",
        case_sensitive=False,
        extra="ignore",
    )

    host: str = Field(
        default="127.0.0.1",
        description="Adresse d'écoute du serveur Vault (boucle locale uniquement).",
    )
    port: int = Field(
        default=8443,
        ge=1,
        le=65535,
        description="Port d'écoute du serveur Vault (1-65535, défaut: 8443).",
    )
    enable_docs: bool = Field(
        default=False,
        description="Activer la documentation OpenAPI/Swagger (/docs). Faux par défaut.",
    )
    require_auth: bool = Field(
        default=True,
        description=(
            "Exiger l'en-tête X-Heimdall-API-Key pour toute requête sur les routes de secrets. "
            "Vrai par défaut (fail-closed, openapi.yaml:19-20). "
            "Désactivation explicite réservée aux tests unitaires isolés."
        ),
    )
    api_key_pepper: str = Field(
        default="heimdall_default_vault_pepper_dev_only",
        description=(
            "Pepper serveur distinct de la KEK pour hachage HMAC-SHA256 (ticket #64). "
            "Jamais consigné dans les journaux d'audit ni retourné au client."
        ),
    )
    db_path: str = Field(
        default=str(DEFAULT_DB_PATH),
        description="Chemin du fichier de base de données SQLite.",
    )

    @field_validator("db_path")
    @classmethod
    def validate_db_path(cls, value: str) -> str:
        """Refuse les chemins invalides en réutilisant le validateur factorisé."""
        try:
            return validate_db_path(value)
        except IsADirectoryError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        """Valide que l'hôte appartient à l'allowlist loopback alignée sur VaultClient."""
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("L'adresse d'hôte ne peut pas être vide ou blanche.")
        if cleaned not in _ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                "Adresse d'hôte non autorisée. "
                "Le Vault doit écouter sur la boucle locale (127.0.0.1, ::1, localhost)."
            )
        return cleaned


# Alias pour usage ergonomique
Settings = VaultSettings


@lru_cache
def get_settings() -> VaultSettings:
    """Retourne l'instance singleton des paramètres du Vault."""
    return VaultSettings()


class HealthResponse(BaseModel):
    """Réponse minimale du endpoint de santé sans information sensible."""

    model_config = ConfigDict(extra="forbid")
    status: Literal["ok"] = "ok"


def _pin_db_path(settings: VaultSettings) -> Path:
    """Résout le chemin SQLite, exige un chemin absolu et le fige normalisé.

    Source de vérité du chemin serveur : résolu UNE fois, à la création de
    l'application, pour que les futures routes injectent `app.state.db_path`
    dans `get_connection()`.

    Refus fail-closed du chemin relatif (revue v5, double source) : un chemin
    relatif dépend du répertoire courant du processus. Le serveur et la CLI
    `init_db` pourraient alors ouvrir deux bases différentes sans erreur. Le
    défaut XDG / `~/.local/share` étant absolu, seul un chemin explicitement
    relatif est refusé.

    `os.path.normpath` normalise lexicalement les segments `..` sans jamais suivre
    les symlinks : les gardes `lstat` de la couche DB (`_assert_not_symlink`)
    continuent de refuser tout ancêtre lié à l'ouverture.

    Refus fail-closed du mode ':memory:' (remarque 2 de la revue v4) : une base
    éphémère ferait échouer silencieusement chaque route (`no such table`) et
    perdrait toute écriture au redémarrage — un serveur Vault exige un fichier
    persistant. Le refus couvre aussi `HEIMDALL_VAULT_DB_PATH=:memory:` (mappé
    sur `settings.db_path` par pydantic-settings).
    """
    resolved = resolve_db_path(settings.db_path)
    if resolved == ":memory:":
        raise ValueError(
            "Le mode ':memory:' est interdit pour le serveur Vault : base éphémère "
            "silencieuse (fail-closed). Configurer un fichier SQLite persistant."
        )
    if not Path(resolved).is_absolute():
        raise ValueError(
            "Chemin de base de données relatif interdit pour le serveur Vault : "
            "fournir un chemin absolu (un chemin relatif dépend du répertoire courant)."
        )
    return Path(os.path.normpath(str(resolved)))


class _PayloadTooLargeError(Exception):
    """Exception interne levée dès que le flux reçu dépasse la limite de 1 Mio."""


class BodySizeLimitMiddleware:
    """Interrompt immédiatement la lecture du flux dès que la taille dépasse 1 Mio.

    Conforme à openapi.yaml:33-37 : compte le flux effectivement reçu, même sans
    Content-Length ou en transfert segmenté, et interrompt la lecture dès dépassement
    sans accumulation en mémoire (protection anti-OOM).
    """

    def __init__(self, app: Any, max_body_size: int = _MAX_BODY_SIZE) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        has_transfer_encoding = any(k.lower() == b"transfer-encoding" for k, _ in raw_headers)
        content_lengths = [
            val for key, val in raw_headers if key.lower() == b"content-length"
        ]

        # Rejet HTTP smuggling : coexistence de Transfer-Encoding et Content-Length
        # interdite (RFC 9112 §4.2)
        if has_transfer_encoding and content_lengths:
            response = JSONResponse(
                status_code=400,
                content=_ERROR_PAYLOADS[400],
            )
            await response(scope, receive, send)
            return

        if len(content_lengths) > 1:
            response = JSONResponse(
                status_code=400,
                content=_ERROR_PAYLOADS[400],
            )
            await response(scope, receive, send)
            return

        if content_lengths:
            val = content_lengths[0]
            try:
                # Format strict RFC 9110 §8.6 (chiffres uniquement, rejet d'espaces ou signes)
                val_str = val.decode("ascii")
                if not val_str.isdigit():
                    raise ValueError("Content-Length non décimal ou contenant des espaces")
                parsed_len = int(val_str)
                if parsed_len < 0 or parsed_len > self.max_body_size:
                    response = JSONResponse(
                        status_code=400,
                        content=_ERROR_PAYLOADS[400],
                    )
                    await response(scope, receive, send)
                    return
            except (ValueError, UnicodeDecodeError, TypeError):
                response = JSONResponse(
                    status_code=400,
                    content=_ERROR_PAYLOADS[400],
                )
                await response(scope, receive, send)
                return

        total_bytes = 0

        async def limited_receive() -> Any:
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                total_bytes += len(body)
                if total_bytes > self.max_body_size:
                    raise _PayloadTooLargeError()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _PayloadTooLargeError:
            response = JSONResponse(
                status_code=400,
                content=_ERROR_PAYLOADS[400],
            )
            await response(scope, receive, send)


def _register_middleware(app: FastAPI) -> None:
    """Enregistre les middlewares du serveur Vault."""
    app.add_middleware(BodySizeLimitMiddleware, max_body_size=_MAX_BODY_SIZE)

    @app.middleware("http")
    async def loopback_enforcement_middleware(request: Request, call_next: Any) -> Any:
        """Défense en profondeur fail-closed : bloque toute requête hors de l'allowlist loopback."""
        client = request.client
        if not client or not client.host:
            return JSONResponse(
                status_code=403,
                content=_ERROR_PAYLOADS[403],
            )
        host = client.host
        is_allowed = host in _ALLOWED_LOOPBACK_HOSTS
        if not is_allowed:
            try:
                addr = ipaddress.ip_address(host)
                mapped = getattr(addr, "ipv4_mapped", None)
                effective_ip = str(mapped or addr)
                if effective_ip in _ALLOWED_LOOPBACK_HOSTS:
                    is_allowed = True
            except ValueError:
                pass
        if not is_allowed:
            return JSONResponse(
                status_code=403,
                content=_ERROR_PAYLOADS[403],
            )
        return await call_next(request)


def _register_exception_handlers(app: FastAPI) -> None:
    """Enregistre les gestionnaires d'exceptions normalisés du Vault."""

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Remplace l'enveloppe 422 par défaut par un 400 contractuel sans reflet d'entrée."""
        return JSONResponse(
            status_code=400,
            content=_ERROR_PAYLOADS[400],
        )

    @app.exception_handler(StarletteHTTPException)
    async def router_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Garde-fou : préserve le code contractuel sans fuite d'enveloppe framework."""
        status_code = exc.status_code if exc.status_code in _ERROR_PAYLOADS else 500
        content = _ERROR_PAYLOADS.get(
            exc.status_code,
            _ERROR_PAYLOADS[500],
        )
        # Allowlist stricte des en-têtes autorisés pour éviter toute injection ou fuite
        filtered_headers: dict[str, str] = {}
        if exc.headers:
            for key, val in exc.headers.items():
                lower_key = key.lower()
                if lower_key == "allow":
                    filtered_headers["Allow"] = str(val)
                elif lower_key == "retry-after":
                    try:
                        retry_sec = int(val)
                        if 1 <= retry_sec <= _MAX_RETRY_AFTER_SECONDS:
                            filtered_headers["Retry-After"] = str(retry_sec)
                    except (ValueError, TypeError):
                        pass
        headers = filtered_headers or None
        return JSONResponse(
            status_code=status_code,
            content=content,
            headers=headers,
        )

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        """Masque toute exception non gérée pour éviter toute fuite de trace."""
        return JSONResponse(
            status_code=500,
            content=_ERROR_PAYLOADS[500],
        )


def _lookup_db_api_key(db_path: Any, provided_hash: str) -> tuple[str | None, int]:
    """Recherche la clé API en base SQLite à coût comparable et sans oracle temporel."""
    if not (isinstance(db_path, Path) and db_path.is_file()):
        return None, 0
    matching_project: str | None = None
    evaluated = 0
    try:
        with db_session(db_path) as conn:
            cursor = conn.execute(
                "SELECT project_id, key_hash, revoked_at FROM api_keys"
            )
            for row in cursor.fetchall():
                evaluated += 1
                if hmac.compare_digest(provided_hash, row["key_hash"]):
                    if not row["revoked_at"]:
                        matching_project = row["project_id"]
    except Exception as exc:
        logger.debug("Échec consultation clé API SQLite : %s", exc.__class__.__name__)
    return matching_project, evaluated


def verify_api_key(
    request: Request,
    api_key: Annotated[str | None, Depends(project_api_key_header)] = None,
) -> str | None:
    """Vérifie l'en-tête X-Heimdall-API-Key en temps constant (ticket #64).

    Conformité openapi.yaml:19-20, 197-204 :
    - fail-closed : authentification active par défaut (`require_auth=True`).
    - rejet en 401 sans normalisation si la clé comporte des espaces de début/fin.
    - hachage HMAC-SHA256 avec pepper serveur distinct de la KEK.
    - comparaison constante via `hmac.compare_digest` sur empreintes de même longueur.
    - chemin de vérification de coût comparable (aucun break précoce, comparaison factice).
    - si `settings.require_auth=False` et aucune clé fournie, retourne None (test mode).
    """
    settings: VaultSettings = getattr(
        request.app.state,
        "settings",
        VaultSettings(require_auth=True),
    )
    if api_key is None:
        if settings.require_auth:
            raise StarletteHTTPException(
                status_code=401,
                detail="Authentification requise",
            )
        return None

    if api_key != api_key.strip() or not api_key:
        raise StarletteHTTPException(
            status_code=401,
            detail="Authentification requise",
        )

    pepper = getattr(settings, "api_key_pepper", None)
    provided_hash = hash_api_key(api_key, pepper=pepper)
    registered_keys: dict[str, str] = getattr(request.app.state, "api_keys", {})
    matching_project: str | None = None
    evaluated_count = 0

    # Parcours complet sans break précoce pour éviter tout oracle d'index
    for reg_hash, proj_id in registered_keys.items():
        evaluated_count += 1
        if hmac.compare_digest(provided_hash, reg_hash):
            matching_project = proj_id

    # Consultation base de données SQLite si configurée, à coût comparable
    if hasattr(request.app.state, "db_path"):
        db_match, db_eval = _lookup_db_api_key(request.app.state.db_path, provided_hash)
        evaluated_count += db_eval
        if db_match is not None:
            matching_project = db_match

    # Coût comparable : comparaison factice si aucune clé n'a été évaluée
    if evaluated_count == 0:
        hmac.compare_digest(provided_hash, _DUMMY_HASH)

    if matching_project is None:
        raise StarletteHTTPException(
            status_code=401,
            detail="Authentification requise",
        )

    return matching_project


def _register_routes(app: FastAPI) -> None:
    """Enregistre les routes de l'API Vault."""

    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        responses=_HEALTH_RESPONSES,
        tags=["Health"],
        summary="Vérifier la santé minimale",
        operation_id="getHealth",
    )
    async def health() -> dict[str, str]:
        """Santé minimale : répond 200 {'status': 'ok'} sans métadonnées sensibles."""
        return {"status": "ok"}

    @app.post(
        "/api/v1/secrets",
        response_model=SecretMetadata,
        status_code=201,
        responses=_SECRETS_POST_RESPONSES,
        tags=["Secrets"],
        summary="Créer un secret",
        operation_id="createSecret",
    )
    async def create_secret(
        secret_in: SecretCreate,
        response: Response,
        authenticated_project: Annotated[str | None, Depends(verify_api_key)] = None,
    ) -> SecretMetadata:
        """Créer un secret vaulté (ticket #63)."""
        settings: VaultSettings = getattr(
            app.state, "settings", VaultSettings(require_auth=True)
        )
        if settings.require_auth and authenticated_project is None:
            raise StarletteHTTPException(
                status_code=401,
                detail="Authentification requise",
            )
        if (
            authenticated_project is not None
            and authenticated_project != secret_in.project
        ):
            raise StarletteHTTPException(
                status_code=403,
                detail="Accès interdit",
            )
        response.headers["Cache-Control"] = "no-store"
        store: InMemorySecretStore = app.state.secret_store
        try:
            record = await store.create(
                project=secret_in.project,
                env=secret_in.env,
                name=secret_in.name,
                value=secret_in.value,
            )
        except KeyError:
            raise StarletteHTTPException(
                status_code=409,
                detail="Secret déjà existant",
            ) from None
        except QuotaExceededError:
            raise StarletteHTTPException(
                status_code=429,
                detail="Trop de requêtes",
                headers={"Retry-After": "60"},
            ) from None
        return SecretMetadata(
            project=record["project"],
            env=record["env"],
            name=record["name"],
            status=record["status"],  # type: ignore[arg-type]
        )

    @app.get(
        "/api/v1/secrets/{project}/{env}/{name}",
        response_model=SecretRead,
        status_code=200,
        responses=_SECRETS_GET_RESPONSES,
        tags=["Secrets"],
        summary="Lire la valeur courante d'un secret",
        operation_id="getSecret",
    )
    async def get_secret(
        project: Annotated[
            ProjectId,
            FastApiPath(description="Identifiant public du projet ; aucune valeur secrète."),
        ],
        env: Annotated[
            EnvironmentId,
            FastApiPath(description="Environnement autorisé ; aucune valeur secrète."),
        ],
        name: Annotated[
            SecretName,
            FastApiPath(description="Nom de variable ; aucune valeur secrète."),
        ],
        response: Response,
        authenticated_project: Annotated[str | None, Depends(verify_api_key)] = None,
    ) -> SecretRead:
        """Lire la valeur courante d'un secret (ticket #63)."""
        settings: VaultSettings = getattr(
            app.state, "settings", VaultSettings(require_auth=True)
        )
        if settings.require_auth and authenticated_project is None:
            raise StarletteHTTPException(
                status_code=401,
                detail="Authentification requise",
            )
        if (
            authenticated_project is not None
            and authenticated_project != project
        ):
            raise StarletteHTTPException(
                status_code=403,
                detail="Accès interdit",
            )
        response.headers["Cache-Control"] = "no-store"
        store: InMemorySecretStore = app.state.secret_store
        record = await store.get(project=project, env=env, name=name)
        if record is None:
            raise StarletteHTTPException(
                status_code=404,
                detail="Ressource introuvable",
            )
        return SecretRead(
            project=record["project"],
            env=record["env"],
            name=record["name"],
            status=record["status"],  # type: ignore[arg-type]
            value=record["value"],
        )


def create_app(
    settings: VaultSettings | None = None,
    secret_store: InMemorySecretStore | None = None,
    api_key_hashes: dict[str, str] | None = None,
    api_keys: dict[str, str] | None = None,
) -> FastAPI:
    """Fabrique et configure l'application FastAPI pour le serveur Vault.

    Paramètres :
    - `settings` : Configuration VaultSettings (défaut : get_settings()).
    - `secret_store` : Magasin de secrets mémoire ou chiffré (défaut : InMemorySecretStore()).
    - `api_key_hashes` : Dictionnaire {hash_hmac_hex: project_id} de clés pré-hachées.
      Chaque clé DOIT être une chaîne hexadécimale de 64 caractères (^[0-9a-f]{64}$).
      Les clés brutes sont expressément refusées pour éviter toute confusion de format.
    - `api_keys` : Alias de `api_key_hashes` pour compatibilité descendante.
    """
    effective_settings = settings if settings is not None else get_settings()

    docs_url = "/docs" if effective_settings.enable_docs else None
    openapi_url = "/openapi.json" if effective_settings.enable_docs else None

    app = FastAPI(
        title="Heimdall Vault API",
        version="1.0.0",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    app.state.settings = effective_settings
    resolved_db = _pin_db_path(effective_settings)
    app.state.db_path = resolved_db
    logger.debug("Base de données SQLite configurée : %s", resolved_db.name)
    app.state.secret_store = (
        secret_store if secret_store is not None else InMemorySecretStore()
    )

    raw_hashes = api_key_hashes if api_key_hashes is not None else api_keys
    validated_hashes: dict[str, str] = {}
    if raw_hashes is not None:
        for key_candidate, project_id in raw_hashes.items():
            if not isinstance(key_candidate, str) or not _HASH_PATTERN.match(key_candidate):
                raise ValueError(
                    f"Format d'empreinte de clé API invalide : '{key_candidate}'. "
                    "api_key_hashes attend uniquement des empreintes hexadécimales de 64 "
                    "caractères (^[0-9a-f]{64}$). Pour enregistrer une clé brute, utilisez "
                    "app.state.register_api_key(raw_key, project_id)."
                )
            validated_hashes[key_candidate] = project_id
    app.state.api_keys = validated_hashes

    def register_api_key(raw_key: str, project_id: str) -> None:
        """Enregistre une clé API brute en calculant son HMAC-SHA256 avec le pepper serveur."""
        if not raw_key or raw_key != raw_key.strip():
            raise ValueError("La clé API brute ne peut pas être vide ou comporter d'espaces.")
        key_hash = hash_api_key(raw_key, pepper=effective_settings.api_key_pepper)
        app.state.api_keys[key_hash] = project_id

    app.state.register_api_key = register_api_key

    _register_middleware(app)
    _register_exception_handlers(app)
    _register_routes(app)

    return app


app = create_app()


def run_server() -> None:
    """Démarre le serveur Vault avec les paramètres validés (localhost uniquement).

    NOTE DE SÉCURITÉ (ticket #25) :
    Ce montage HTTP en clair est strictement réservé au squelette minimal et à la
    route /api/v1/health sur la boucle locale. Ne jamais réutiliser ce montage HTTP
    au-delà du squelette : les tickets #64 et #65 implémentent le TLS obligatoire avec
    SAN-IP (https://127.0.0.1:8443) et l'authentification X-Heimdall-API-Key.

    NOTE CONCURRENCE : Le serveur tourne avec un seul worker (workers=1 par défaut).
    Ne pas augmenter le nombre de workers tant que le stockage persistant partagé
    SQLite (#26, #62) n'est pas branché.
    """
    server_settings = get_settings()
    uvicorn.run(
        "heimdall.vault.app:app",
        host=server_settings.host,
        port=server_settings.port,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
        date_header=False,
    )


__all__ = [
    "BadRequestError",
    "BodySizeLimitMiddleware",
    "ConflictError",
    "ForbiddenError",
    "HealthResponse",
    "InMemorySecretStore",
    "InternalError",
    "MethodNotAllowedError",
    "NotFoundError",
    "QuotaExceededError",
    "RateLimitedError",
    "SecretCreate",
    "SecretMetadata",
    "SecretRead",
    "Settings",
    "UnauthorizedError",
    "UnavailableError",
    "VaultSettings",
    "app",
    "create_app",
    "generate_api_key",
    "get_settings",
    "hash_api_key",
    "project_api_key_header",
    "run_server",
    "verify_api_key",
]

if __name__ == "__main__":
    run_server()
