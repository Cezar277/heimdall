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

import ipaddress
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

import uvicorn
from fastapi import FastAPI, Path as FastApiPath, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
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

from heimdall.vault.database import DEFAULT_DB_PATH, resolve_db_path, validate_db_path

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


ProjectId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
    ),
]
EnvironmentId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[a-z][a-z0-9_-]{0,31}$",
    ),
]
SecretName = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=64,
        pattern=r"^[A-Z][A-Z0-9_]{1,63}$",
    ),
]
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


class InMemorySecretStore:
    """Stockage mémoire des secrets pour le squelette fonctionnel (ticket #63).

    Les secrets sont indexés par le tuple (project, env, name).
    Le chiffrement au repos et la persistance SQLite (#62 / #26) se brancheront
    sur cette même interface.
    """

    def __init__(self) -> None:
        self._secrets: dict[tuple[str, str, str], dict[str, str]] = {}

    def get(self, project: str, env: str, name: str) -> dict[str, str] | None:
        return self._secrets.get((project, env, name))

    def create(self, project: str, env: str, name: str, value: str) -> dict[str, str]:
        key = (project, env, name)
        if key in self._secrets:
            raise KeyError("Secret déjà existant")
        record = {
            "project": project,
            "env": env,
            "name": name,
            "status": "vaulte",
            "value": value,
        }
        self._secrets[key] = record
        return record

    def clear(self) -> None:
        self._secrets.clear()


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
        "description": "Secret créé et persisté sous forme chiffrée.",
        "headers": _NO_STORE_HEADER,
    },
    400: {"model": BadRequestError, "description": "Requête invalide"},
    401: {"model": UnauthorizedError, "description": "Authentification requise"},
    403: {"model": ForbiddenError, "description": "Accès interdit"},
    405: {"model": MethodNotAllowedError, "description": "Méthode non autorisée"},
    409: {"model": ConflictError, "description": "Secret déjà existant"},
    429: {
        "model": RateLimitedError,
        "description": "Trop de requêtes",
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
    401: {"model": UnauthorizedError, "description": "Authentification requise"},
    403: {"model": ForbiddenError, "description": "Accès interdit"},
    404: {"model": NotFoundError, "description": "Ressource introuvable"},
    405: {"model": MethodNotAllowedError, "description": "Méthode non autorisée"},
    429: {
        "model": RateLimitedError,
        "description": "Trop de requêtes",
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


def _register_middleware(app: FastAPI) -> None:
    """Enregistre les middlewares du serveur Vault."""

    @app.middleware("http")
    async def body_size_limit_middleware(request: Request, call_next: Any) -> Any:
        """Rejette HTTP 400 bad_request tout corps supérieur à 1 Mio (1 048 576 octets)."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > _MAX_BODY_SIZE:
                    return JSONResponse(
                        status_code=400,
                        content=_ERROR_PAYLOADS[400],
                    )
            except (ValueError, TypeError):
                return JSONResponse(
                    status_code=400,
                    content=_ERROR_PAYLOADS[400],
                )

        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > _MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=400,
                    content=_ERROR_PAYLOADS[400],
                )

        return await call_next(request)

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
    ) -> SecretMetadata:
        """Créer un secret vaulté (ticket #63)."""
        response.headers["Cache-Control"] = "no-store"
        store: InMemorySecretStore = app.state.secret_store
        try:
            record = store.create(
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
            str,
            FastApiPath(
                min_length=1,
                max_length=64,
                pattern=r"^[a-z][a-z0-9_-]{0,63}$",
                description="Identifiant public du projet ; aucune valeur secrète.",
            ),
        ],
        env: Annotated[
            str,
            FastApiPath(
                min_length=1,
                max_length=32,
                pattern=r"^[a-z][a-z0-9_-]{0,31}$",
                description="Environnement autorisé ; aucune valeur secrète.",
            ),
        ],
        name: Annotated[
            str,
            FastApiPath(
                min_length=2,
                max_length=64,
                pattern=r"^[A-Z][A-Z0-9_]{1,63}$",
                description="Nom de variable ; aucune valeur secrète.",
            ),
        ],
        response: Response,
    ) -> SecretRead:
        """Lire la valeur courante d'un secret (ticket #63)."""
        response.headers["Cache-Control"] = "no-store"
        store: InMemorySecretStore = app.state.secret_store
        record = store.get(project=project, env=env, name=name)
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
) -> FastAPI:
    """Fabrique et configure l'application FastAPI pour le serveur Vault."""
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
    "ConflictError",
    "ForbiddenError",
    "HealthResponse",
    "InMemorySecretStore",
    "InternalError",
    "MethodNotAllowedError",
    "NotFoundError",
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
    "get_settings",
    "run_server",
]

if __name__ == "__main__":
    run_server()
