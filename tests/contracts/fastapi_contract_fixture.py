"""Fixture indépendante de génération OpenAPI ; aucun serveur Vault réel.

Ne charge jamais openapi.yaml. À remplacer par l'application réelle dans #25.
"""
import re

from typing import Annotated, Any, Literal, NoReturn

from fastapi import Depends, FastAPI, Path
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from pydantic import BaseModel, ConfigDict, StringConstraints

Project = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=re.compile(r"^[a-z][a-z0-9_-]{0,63}(?![\s\S])"))]
Environment = Annotated[str, StringConstraints(min_length=1, max_length=32, pattern=re.compile(r"^[a-z][a-z0-9_-]{0,31}(?![\s\S])"))]
Name = Annotated[str, StringConstraints(min_length=2, max_length=64, pattern=re.compile(r"^[A-Z][A-Z0-9_]{1,63}(?![\s\S])"))]
Value = Annotated[str, StringConstraints(min_length=1, max_length=65536)]
Status = Literal["vaulte", "rote"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", regex_engine="python-re")


class SecretCreate(StrictModel):
    project: Project
    env: Environment
    name: Name
    value: Value


class SecretMetadata(StrictModel):
    project: Project
    env: Environment
    name: Name
    status: Status


class SecretRead(SecretMetadata):
    value: Value


class BadRequestError(StrictModel):
    code: Literal["bad_request"]
    message: Literal["Requête invalide"]


class UnauthorizedError(StrictModel):
    code: Literal["unauthorized"]
    message: Literal["Authentification requise"]


class ForbiddenError(StrictModel):
    code: Literal["forbidden"]
    message: Literal["Accès interdit"]


class NotFoundError(StrictModel):
    code: Literal["not_found"]
    message: Literal["Ressource introuvable"]


class MethodNotAllowedError(StrictModel):
    code: Literal["method_not_allowed"]
    message: Literal["Méthode non autorisée"]


class ConflictError(StrictModel):
    code: Literal["conflict"]
    message: Literal["Secret déjà existant"]


class RateLimitedError(StrictModel):
    code: Literal["rate_limited"]
    message: Literal["Trop de requêtes"]


class UnavailableError(StrictModel):
    code: Literal["unavailable"]
    message: Literal["Service indisponible"]


class Health(StrictModel):
    status: Literal["ok"]


class InternalError(StrictModel):
    code: Literal["internal_error"]
    message: Literal["Erreur interne"]


ERROR_MODELS = {
    400: BadRequestError, 401: UnauthorizedError, 403: ForbiddenError,
    404: NotFoundError, 405: MethodNotAllowedError, 409: ConflictError,
    429: RateLimitedError, 500: InternalError, 503: UnavailableError,
}
project_api_key = APIKeyHeader(
    name="X-Heimdall-API-Key", scheme_name="ProjectApiKey", auto_error=False
)


class AuthenticationRequired(Exception):
    pass


def require_api_key(key: Annotated[str | None, Depends(project_api_key)]) -> NoReturn:
    # Fixture sans registre de clés : toute clé est refusée, sans bypass.
    # #25 doit remplacer ce garde par sa vérification hachée/constante.
    # Ne pas utiliser les erreurs automatiques FastAPI 403/422 ni HTTPException
    # avec une enveloppe {detail: ...} qui ne respecte pas notre contrat.
    raise AuthenticationRequired()


def build_app() -> FastAPI:
    app = FastAPI(title="Heimdall Vault API", version="1.0.0")
    @app.exception_handler(AuthenticationRequired)
    async def authentication_required_handler(request: Request, exc: AuthenticationRequired) -> JSONResponse:
        return JSONResponse(status_code=401, content={
            "code": "unauthorized", "message": "Authentification requise"
        })

    @app.exception_handler(StarletteHTTPException)
    async def router_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # LOW-1 : le routeur ne doit jamais fuir l'enveloppe {detail: ...}
        # du framework (fingerprint). Route inconnue -> 404 contractuel,
        # méthode non déclarée -> 405 contractuel, le reste -> 500 générique.
        if exc.status_code == 404:
            return JSONResponse(status_code=404, content={
                "code": "not_found", "message": "Ressource introuvable"})
        if exc.status_code == 405:
            return JSONResponse(status_code=405, content={
                "code": "method_not_allowed", "message": "Méthode non autorisée"})
        return JSONResponse(status_code=500, content={
            "code": "internal_error", "message": "Erreur interne"})

    responses: dict[int | str, dict[str, Any]] = {code: {"model": ERROR_MODELS[code]} for code in (400, 401, 403, 404, 405, 429)}
    responses["default"] = {"model": InternalError}
    responses[500] = {"model": InternalError}
    no_store = {"Cache-Control": {"required": True, "schema": {"type": "string", "const": "no-store"}}}
    retry_after = {
        "Retry-After": {"required": True, "schema": {"type": "integer", "minimum": 1, "maximum": 3600}}
    }
    responses[429]["headers"] = retry_after
    responses[503] = {"model": UnavailableError, "headers": retry_after}

    @app.post("/api/v1/secrets", response_model=SecretMetadata, status_code=201,
              operation_id="createSecret", responses={**{k: v for k, v in responses.items() if k != 404}, 409: {"model": ConflictError},
                                                       201: {"headers": no_store}},
              dependencies=[Depends(require_api_key)])
    def create_secret(body: SecretCreate) -> NoReturn:
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}", response_model=SecretRead,
             operation_id="getSecret", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(require_api_key)])
    def get_secret(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]) -> NoReturn:
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}/state", response_model=SecretMetadata,
             operation_id="getSecretState", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(require_api_key)])
    def get_state(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]) -> NoReturn:
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/health", response_model=Health, operation_id="getHealth",
             responses={429: responses[429], 405: responses[405], 500: responses[500],
                        503: {"model": UnavailableError, "headers": retry_after},
                        "default": {"model": InternalError}})
    def health() -> NoReturn:
        raise NotImplementedError("Fixture de contrat uniquement")

    return app
