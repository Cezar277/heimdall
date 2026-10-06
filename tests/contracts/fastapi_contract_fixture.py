"""Fixture indépendante de génération OpenAPI ; aucun serveur Vault réel.

Ne charge jamais openapi.yaml. À remplacer par l'application réelle dans #25.
"""
import re

from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Path
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

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


ERROR_MESSAGES = {
    "bad_request": "Requête invalide",
    "unauthorized": "Authentification requise",
    "forbidden": "Accès interdit",
    "not_found": "Ressource introuvable",
    "conflict": "Secret déjà existant",
    "rate_limited": "Trop de requêtes",
    "unavailable": "Service indisponible",
    "internal_error": "Erreur interne",
}


class Error(StrictModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={
        "allOf": [
            {"if": {"properties": {"code": {"const": code}}, "required": ["code"]},
             "then": {"properties": {"message": {"const": message}}}}
            for code, message in ERROR_MESSAGES.items()
        ]
    })
    code: Literal["bad_request", "unauthorized", "forbidden", "not_found", "conflict", "rate_limited", "unavailable", "internal_error"]
    message: Literal["Requête invalide", "Authentification requise", "Accès interdit",
                     "Ressource introuvable", "Secret déjà existant", "Trop de requêtes",
                     "Service indisponible", "Erreur interne"]

    @model_validator(mode="after")
    def check_message_matches_code(self):
        if self.message != ERROR_MESSAGES[self.code]:
            raise ValueError("Message incohérent avec le code")
        return self


class Health(StrictModel):
    status: Literal["ok"]


def build_app():
    app = FastAPI(title="Heimdall Vault API", version="1.0.0")
    key = APIKeyHeader(name="X-Heimdall-API-Key", scheme_name="ProjectApiKey")
    responses = {code: {"model": Error} for code in (400, 401, 403, 404, 429)}
    responses["default"] = {"model": Error}
    no_store = {"Cache-Control": {"schema": {"type": "string", "const": "no-store"}}}
    responses[429]["headers"] = {
        "Retry-After": {"schema": {"type": "integer", "minimum": 1}}
    }

    @app.post("/api/v1/secrets", response_model=SecretMetadata, status_code=201,
              operation_id="createSecret", responses={**{k: v for k, v in responses.items() if k != 404}, 409: {"model": Error},
                                                       201: {"headers": no_store}},
              dependencies=[Depends(key)])
    def create_secret(body: SecretCreate):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}", response_model=SecretRead,
             operation_id="getSecret", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(key)])
    def get_secret(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/secrets/{project}/{env}/{name}/state", response_model=SecretMetadata,
             operation_id="getSecretState", responses={**responses, 200: {"headers": no_store}}, dependencies=[Depends(key)])
    def get_state(project: Annotated[Project, Path()], env: Annotated[Environment, Path()], name: Annotated[Name, Path()]):
        raise NotImplementedError("Fixture de contrat uniquement")

    @app.get("/api/v1/health", response_model=Health, operation_id="getHealth",
             responses={429: responses[429], 503: {"model": Error}, "default": {"model": Error}})
    def health():
        raise NotImplementedError("Fixture de contrat uniquement")

    return app
