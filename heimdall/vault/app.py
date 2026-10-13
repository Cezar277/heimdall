"""Application FastAPI du serveur Vault Heimdall — squelette (ticket #25).

Ce module initialise l'application FastAPI pour le serveur Vault, sa configuration
lue dans les variables d'environnement (via pydantic-settings) et la route de santé.

Lancement du serveur :
    uvicorn heimdall.vault.app:app --host 127.0.0.1 --port 8443

RÈGLES DE SÉCURITÉ ET CONFORMITÉ (DoD, STRIDE, pentest) :
- Allowlist boucle locale : écoute EXCLUSIVEMENT sur la boucle locale (127.0.0.1, ::1, localhost),
  strictement alignée sur `heimdall.vault.client._ALLOWED_LOOPBACK_HOSTS`.
  Toute adresse LAN, WAN, broadcast ou 0.0.0.0 est rejetée (mitigation Network exposure / Spoofing).
- Garde de défense en profondeur : middleware HTTP bloquant avec 403 toute requête provenant d'une
  IP non-loopback même si le serveur était lancé par mégarde sur toutes les interfaces.
- Documentation désactivée par défaut : docs_url, redoc_url et openapi_url sont désactivés
  pour interdire la reconnaissance d'empreinte (fingerprinting) et l'exposition de version/schéma.
- Schéma OpenAPI conforme : /api/v1/health déclare l'ensemble des réponses contractuelles (200, 405,
  429, 500, 503, default) avec header Retry-After obligatoire sur 429 et 503.
- La route /api/v1/health (et son alias /health) ne divulgue JAMAIS de version, de détails
  de configuration, de chemins ou de données internes (mitigation Information Disclosure).
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
from functools import lru_cache
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

_ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

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


class MethodNotAllowedError(BaseModel):
    """Erreur 405 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["method_not_allowed"] = "method_not_allowed"
    message: Literal["Méthode non autorisée"] = "Méthode non autorisée"


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


_RETRY_AFTER_HEADER = {
    "Retry-After": {
        "required": True,
        "description": "Délai en secondes avant nouvelle tentative.",
        "schema": {"type": "integer", "minimum": 1, "maximum": 3600},
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

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        """Valide que l'hôte appartient à l'allowlist loopback alignée sur VaultClient."""
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("L'adresse d'hôte ne peut pas être vide ou blanche.")
        if cleaned not in _ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"Adresse d'hôte non autorisée : {value!r}. "
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


def create_app(settings: VaultSettings | None = None) -> FastAPI:
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

    @app.middleware("http")
    async def loopback_enforcement_middleware(request: Request, call_next: Any) -> Any:
        """Défense en profondeur : bloque toute connexion ne provenant pas de localhost."""
        client = request.client
        if client and client.host:
            host = client.host
            if host != "testclient":
                try:
                    addr = ipaddress.ip_address(host)
                    if not addr.is_loopback:
                        return JSONResponse(
                            status_code=403,
                            content=_ERROR_PAYLOADS[403],
                        )
                except ValueError:
                    if host not in _ALLOWED_LOOPBACK_HOSTS:
                        return JSONResponse(
                            status_code=403,
                            content=_ERROR_PAYLOADS[403],
                        )
        return await call_next(request)

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
    async def router_error_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Garde-fou : préserve le code contractuel sans fuite d'enveloppe framework."""
        status_code = (
            exc.status_code if exc.status_code in _ERROR_PAYLOADS else 500
        )
        content = _ERROR_PAYLOADS.get(
            exc.status_code,
            _ERROR_PAYLOADS[500],
        )
        headers = dict(exc.headers) if exc.headers else None
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

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["Health"],
        summary="Vérifier la santé minimale (alias)",
        include_in_schema=False,
    )
    async def health_alias() -> dict[str, str]:
        """Alias de confort pour /health, exclu du schéma OpenAPI."""
        return {"status": "ok"}

    return app


app = create_app()


def run_server() -> None:
    """Démarre le serveur Vault avec les paramètres validés (localhost uniquement)."""
    server_settings = get_settings()
    uvicorn.run(
        "heimdall.vault.app:app",
        host=server_settings.host,
        port=server_settings.port,
    )


__all__ = [
    "HealthResponse",
    "InternalError",
    "MethodNotAllowedError",
    "RateLimitedError",
    "Settings",
    "UnavailableError",
    "VaultSettings",
    "app",
    "create_app",
    "get_settings",
    "run_server",
]

if __name__ == "__main__":
    run_server()
