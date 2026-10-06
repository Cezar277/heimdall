"""Fixture indépendante de génération OpenAPI ; aucun serveur Vault réel.

Ne charge jamais openapi.yaml. À remplacer par l'application réelle dans #25.
"""
import re

from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Path
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
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
    404: NotFoundError, 409: ConflictError, 429: RateLimitedError,
    500: InternalError, 503: UnavailableError,
}
project_api_key = APIKeyHeader(
    name="X-Heimdall-API-Key", scheme_name="ProjectApiKey", auto_error=False
)


class AuthenticationRequired(Exception):
    pass


def require_api_key(key: Annotated[str | None, Depends(project_api_key)]):
    # Fixture sans registre de clés : toute clé est refusée, sans bypass.
    # #25 doit remplacer ce garde par sa vérification hachée/constante.
    # Ne pas utiliser les erreurs automatiques FastAPI 403/422 ni HTTPException
    # avec une enveloppe {detail: ...} qui ne respecte pas notre contrat.
    raise AuthenticationRequired()


def build_app():
    app = FastAPI(title="Heimdall Vault API", version="1.0.0")
    @app.exception_handler(AuthenticationRequired)
    async def authentication_required_handler(request, exc):
        return JSONResponse(status_code=401, content={
            "code": "unauthorized", "message": "Authentification requise"
        })

    responses = {code: {"model": ERROR_MODELS[code]} for code in (400, 401, 403, 404, 429)}
    responses["default"] = {"model": InternalError}
    responses[500] = {"model": InternalError}
    no_store = {"Cache-Control": {"required": True, "schema": {"type": "string", "const": "no-store"}}}
    responses[429]["headers"] = {
        "Retry-After": {"required": True, "schema": {"type": "integer", "minimum": 1, "maximum": 3600}}
    }

    @app.post("/api/v1/secrets", response_model=SecretMetadata, status_code=201,
              operation_id="createSecret", responses={**{k: v for k, v in responses.items() if k != 404}, 409: {"model": ConflictError},
                                                       201: {"headers": no_store}},
              dependencies=[Depends(require_api_key)])
    def create_secret(body: SecretCreate):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}", response_model=SecretRead,
             operation_id="getSecret", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(require_api_key)])
    def get_secret(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}/state", response_model=SecretMetadata,
             operation_id="getSecretState", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(require_api_key)])
    def get_state(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/health", response_model=Health, operation_id="getHealth",
             responses={429: responses[429], 500: responses[500], 503: {"model": UnavailableError}, "default": {"model": InternalError}})
    def health():
        raise NotImplementedError("Fixture de contrat uniquement")

    return app
