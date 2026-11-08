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
- Allowlist sur les en-têtes d'exception : seuls Allow, Retry-After (1-3600) et
  Connection: close sont retransmis (fermeture anti-smuggling des rejets 400).
- Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography ou
  argon2 (réservés exclusivement à heimdall/vault/crypto.py) et délègue la
  génération/hachage des clés API à `heimdall.vault.crypto`.
- Pepper clés API (ticket #64) : `hash_api_key` exige un pepper explicite d'au
  moins 32 octets (aucun défaut public, aucun repli silencieux). `VaultSettings`
  refuse la constante publique commitée hors `HEIMDALL_ENV=test`, exige
  `HEIMDALL_VAULT_API_KEY_PEPPER` en production et génère hors production un
  pepper aléatoire éphémère au démarrage avec avertissement (documenté #25).
  Les clés opérateur trop peu diverses (`"a" * 43`, `"abcdefghijkl" * 4`),
  répétitives, séquentielles (`abcdefgh…`) ou de clavier (`qwertyuiop…`)
  sont refusées à l'enregistrement : alphabet base64url strict, 43 caractères
  minimum, 16 caractères distincts minimum, aucune période répétitive,
  aucune suite monotone de 8+, aucune ligne de clavier connue. La valeur
  d'un secret est canonisée en NFC avant stockage et le NUL y est interdit ;
  elle n'est jamais journalisée (décision #62).
- Dérivation de la KEK (ticket #262) : `HEIMDALL_VAULT_MASTER_KEY` +
  `HEIMDALL_VAULT_KEK_SALT` dérivent la KEK avec Argon2id **une seule fois à
  la construction de l'application** (64 Mio / 3 itérations / 4 lanes, sel
  public de 16 octets) ; la KEK reste en mémoire et n'est jamais écrite dans
  SQLite. Le mode historique `HEIMDALL_VAULT_KEK` (KEK directe) reste accepté
  pour les données existantes ; les deux modes sont mutuellement exclusifs et
  toute paire incomplète est refusée au démarrage (fail-closed).
- Gestion d'erreurs normalisée :
  - RequestValidationError -> 400 contractuel {"code": "bad_request", "message": "Requête invalide"}
    sans écho du corps ni enveloppe 422 de FastAPI.
  - StarletteHTTPException -> format contractuel préservant le status_code (400, 401, 403, 404,
    405, 409, 429, 503) sans fuite d'enveloppe framework {"detail": ...}.
  - Exception non gérée -> 500 {"code": "internal_error", "message": "Erreur interne"}.
- Schéma OpenAPI publié aligné sur le contrat (openapi.yaml:412-508) : les modèles
  d'erreur et `HealthResponse` déclarent `code`, `message` et `status` SANS valeur
  par défaut. Un champ à valeur par défaut est omis de `required` par Pydantic :
  le schéma publié n'exposerait alors plus `required: [code, message]` exigé par
  le contrat (drift de contrat). Les champs restent donc OBLIGATOIRES dans le
  modèle : les gestionnaires d'exceptions construisent les charges utiles
  explicitement, et le schéma publié expose exactement les contraintes du
  contrat (vérifié par `tests/test_vault_integration_testclient.py`).
"""

import asyncio
import base64
import ipaddress
import logging
import os
import re
import unicodedata
from functools import lru_cache
from http import HTTPStatus
from pathlib import Path
from threading import Lock
from typing import Annotated, Any, Literal

import uvicorn
from fastapi import Depends, FastAPI, Query, Response
from fastapi import Path as FastApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from heimdall.vault import auth as vault_auth
from heimdall.vault.crypto import (
    MIN_MASTER_KEY_BYTES,
    VaultCipher,
    constant_time_equal,
    decode_kek_salt,
    derive_kek_from_master_key,
    generate_api_key,
    generate_api_key_pepper,
    kek_matches_pepper,
)
from heimdall.vault.database import (
    _MAX_SECRET_PAGE_OFFSET,
    DEFAULT_DB_PATH,
    DatabaseUnavailableError,
    _assert_not_symlink,
    resolve_db_path,
    validate_db_path,
)
from heimdall.vault.ratelimit import RateLimiter, SqliteRateLimiter
from heimdall.vault.store import (
    InMemorySecretStore,
    QuotaExceededError,
    SqliteSecretStore,
)

_ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

# Alias de compatibilité ascendante : la primitive de hachage du pepper, la
# dépendance FastAPI et le type d'identifiant de projet restent importables
# depuis `heimdall.vault.app` (documentation et tests historiques).
hash_api_key = vault_auth.hash_project_api_key
project_api_key_header = vault_auth.project_api_key_header
verify_api_key = vault_auth.verify_api_key
ProjectId = vault_auth.ProjectId
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
    code: Literal["bad_request"]
    message: Literal["Requête invalide"]


class UnauthorizedError(BaseModel):
    """Erreur 401 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["unauthorized"]
    message: Literal["Authentification requise"]


class ForbiddenError(BaseModel):
    """Erreur 403 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["forbidden"]
    message: Literal["Accès interdit"]


class NotFoundError(BaseModel):
    """Erreur 404 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["not_found"]
    message: Literal["Ressource introuvable"]


class MethodNotAllowedError(BaseModel):
    """Erreur 405 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["method_not_allowed"]
    message: Literal["Méthode non autorisée"]


class ConflictError(BaseModel):
    """Erreur 409 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["conflict"]
    message: Literal["Secret déjà existant"]


class RateLimitedError(BaseModel):
    """Erreur 429 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["rate_limited"]
    message: Literal["Trop de requêtes"]


class UnavailableError(BaseModel):
    """Erreur 503 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["unavailable"]
    message: Literal["Service indisponible"]


class InternalError(BaseModel):
    """Erreur 500 contractuelle."""

    model_config = ConfigDict(extra="forbid")
    code: Literal["internal_error"]
    message: Literal["Erreur interne"]


# La dépendance FastAPI qui lit l'en-tête `X-Heimdall-API-Key`, la politique de
# pepper, les constantes de validation des clés et le registre des clés API de
# projet vivent dans `heimdall.vault.auth` (ticket #64) : ce module reste
# centré sur le serveur (configuration, middlewares, routes).

# Mode d'environnement normalisé (`HEIMDALL_ENV`) : partagé avec le module
# d'authentification, qui porte la politique du pepper.
_heimdall_env_mode = vault_auth.heimdall_env_mode

_PRODUCTION_ENV_MODES: frozenset[str] = frozenset({"production", "prod"})


@lru_cache(maxsize=1)
def _warn_generated_pepper_once() -> None:
    """Avertit une seule fois par processus qu'un pepper éphémère a été généré."""
    logger.warning(
        "HEIMDALL_VAULT_API_KEY_PEPPER absent : pepper aléatoire éphémère généré "
        "pour cet environnement hors production. Les empreintes de clés ne "
        "survivent pas au redémarrage ; fournir un pepper persisté distinct de "
        "la KEK en production (ticket #25)."
    )


def _resolve_storage_backend(settings: "VaultSettings") -> Literal["memory", "sqlite"]:
    """Résout le backend : SQLite en production, mémoire hors production par défaut.

    Le backend mémoire est interdit en production même s'il est demandé
    explicitement : il ne partage pas l'état entre workers et ne doit jamais
    servir un déploiement réel.
    """
    in_production = _heimdall_env_mode() in _PRODUCTION_ENV_MODES
    if settings.storage_backend is not None:
        if in_production and settings.storage_backend == "memory":
            raise ValueError(
                "Le backend de stockage 'memory' est interdit en production "
                "(HEIMDALL_ENV=production/prod) : utiliser 'sqlite' avec une KEK."
            )
        return settings.storage_backend
    return "sqlite" if in_production else "memory"


def _reject_kek_equal_to_pepper(derived_kek: bytes, pepper: str) -> None:
    """Refuse une KEK qui réutilise l'entropie du pepper (invariant 5).

    Couvre la KEK brute, ses représentations base64 URL-safe et standard, et
    l'encodage hexadécimal : deux encodages de la même entropie ne doivent
    jamais servir au chiffrement et à l'authentification, même si un outil
    opérateur a produit un autre format. Le message reste générique (aucun écho
    de secret).
    """
    pepper_bytes = pepper.encode("utf-8")
    derived_b64 = base64.urlsafe_b64encode(derived_kek).decode("ascii")
    if constant_time_equal(derived_kek, pepper_bytes) or kek_matches_pepper(
        derived_b64, pepper
    ):
        raise ValueError(
            "La KEK dérivée de la clé maîtresse et le pepper d'authentification "
            "doivent être distincts (invariant 5)."
        )


def _resolve_vault_cipher(
    settings: "VaultSettings",
    backend: Literal["memory", "sqlite"],
) -> VaultCipher:
    """Construit le chiffreur une seule fois au démarrage (tickets #25/#262).

    Trois cas, exclusifs par validation de ``VaultSettings`` :

    1. ``HEIMDALL_VAULT_KEK`` fournie directement : mode historique, aucune
       dérivation. Conservé pour que les blobs existants restent déchiffrables.
    2. ``HEIMDALL_VAULT_MASTER_KEY`` + ``HEIMDALL_VAULT_KEK_SALT`` : la KEK est
       dérivée par Argon2id **ici, une seule fois**, puis seule la KEK dérivée
       reste en mémoire dans ``VaultCipher``.
    3. Aucune clé : KEK éphémère uniquement pour le backend mémoire (jamais
       pour SQLite, dont les données doivent survivre au redémarrage).

    La KEK dérivée est comparée au pepper d'authentification (invariant 5) :
    même si les deux secrets sont fournis séparément, une collision fortuite
    ou une configuration volontairement fautive est refusée fail-closed.

    La clé maîtresse reste portée par ``VaultSettings`` et l'environnement pour
    la durée du processus ; la dérivation ne prétend pas l'effacer. Seule la KEK
    dérivée est conservée par ``VaultCipher`` et utilisée par les routes.
    """
    if settings.kek is not None:
        return VaultCipher.from_encoded_key(settings.kek)
    if settings.master_key is not None:
        salt = settings.kek_salt
        if salt is None:
            # VaultSettings garantit la paire ; garde de défense en profondeur.
            raise ValueError(
                "HEIMDALL_VAULT_KEK_SALT est obligatoire avec HEIMDALL_VAULT_MASTER_KEY."
            )
        pepper = settings.api_key_pepper
        # Contrôle bon marché AVANT la KDF coûteuse (défense en profondeur).
        if pepper is not None and constant_time_equal(
            settings.master_key.encode("utf-8"), pepper.encode("utf-8")
        ):
            raise ValueError(
                "La clé maîtresse et le pepper d'authentification doivent être "
                "distincts (invariant 5)."
            )
        derived_kek = derive_kek_from_master_key(settings.master_key, salt)
        if pepper is not None:
            _reject_kek_equal_to_pepper(derived_kek, pepper)
        return VaultCipher(derived_kek)
    if backend == "sqlite":
        raise ValueError(
            "HEIMDALL_VAULT_KEK (mode historique) ou le couple "
            "HEIMDALL_VAULT_MASTER_KEY + HEIMDALL_VAULT_KEK_SALT est obligatoire "
            "pour le backend SQLite : fournir une KEK 256 bits, distincte du pepper "
            "d'authentification. Aucune KEK éphémère n'est générée pour des données "
            "persistées."
        )
    return VaultCipher.generate()


def _validate_explicit_secret_store_configuration(
    settings: "VaultSettings",
    secret_store: "InMemorySecretStore | SqliteSecretStore",
) -> None:
    """Refuse la réutilisation du pepper par la KEK **réelle** du store explicite.

    Avec un store explicite, ``_resolve_vault_cipher`` n'est pas appelé : la KEK
    qui chiffre réellement les secrets est celle portée par le chiffreur du
    store, pas celle que ``settings`` dériverait (les deux peuvent diverger —
    revue LOW). Ce contrôle compare donc la KEK du store au pepper (brut +
    base64), une fois au démarrage, **sans dérivation supplémentaire**. Le
    chemin reste réservé aux tests ; la production HTTP passe toujours par
    ``_resolve_vault_cipher``. Les contrôles bon marché restent dans
    ``VaultSettings`` (paire maître/sel, ``master_key != pepper``).
    """
    if settings.api_key_pepper is None:
        return
    cipher = getattr(secret_store, "_cipher", None)
    if not isinstance(cipher, VaultCipher):
        # Fail-closed générique : un store ou mock sans chiffreur ne doit pas
        # produire un AttributeError technique (revue LOW).
        raise ValueError(
            "Store explicite invalide : un chiffreur VaultCipher est requis "
            "pour vérifier l'invariant 5."
        )
    if cipher.key_reuses_pepper(settings.api_key_pepper):
        raise ValueError(
            "La KEK du store et le pepper d'authentification doivent être "
            "distincts (invariant 5)."
        )


# Motifs d'identifiants du contrat (#15) : `project` vient du module
# d'authentification (#64), qui valide aussi les clés API.
PROJECT_PATTERN: re.Pattern[str] = vault_auth.PROJECT_ID_PATTERN
ENV_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_-]{0,31}(?![\s\S])")
NAME_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]{1,63}(?![\s\S])")


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
# injection et de fuite en clair). Décision #62 : la valeur est canonisée en NFC
# (forme Unicode canonique unique) et l'octet NUL reste interdit ; les retours à
# la ligne restent autorisés (valeur multiligne contractuelle).
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
    def validate_value(cls, v: str) -> str:
        """Canonise la valeur en NFC et refuse l'octet NUL (défense en profondeur).

        Décision #62 (tranchée) : « refus du seul ``\\x00`` » OU « normalisation
        NFC ». Les DEUX sont appliquées : la normalisation NFC donne une forme
        canonique unique (deux écritures visuellement identiques d'un même
        secret ne peuvent plus diverger en base, ni produire deux empreintes
        d'intégrité différentes) et le NUL reste interdit car il tronque les
        valeurs dans les.outils texte.

        La valeur reste multiligne (retours à la ligne autorisés par le
        contrat) : c'est précisément pourquoi elle ne doit JAMAIS être
        journalisée (log injection / fuite en clair).
        Ne jamais journaliser cette valeur en cas d'erreur (anti-fuite).
        """
        if "\x00" in v:
            raise ValueError("Le caractère NUL est interdit dans la valeur du secret.")
        return unicodedata.normalize("NFC", v)


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


_MAX_SECRET_OFFSET = _MAX_SECRET_PAGE_OFFSET


class SecretPage(BaseModel):
    """Page de métadonnées publiques, sans valeur ni empreinte de secret."""

    model_config = ConfigDict(extra="forbid")
    items: list[SecretMetadata] = Field(max_length=100)
    next_offset: int | None = Field(ge=0, le=_MAX_SECRET_OFFSET)


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
        "description": "Secret créé et persisté chiffré (AES-256-GCM, tickets #26/#62).",
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
            "Trop de requêtes — quota de stockage atteint (#62/#63) ou débit "
            "clé/pair/global dépassé (#63, lot d'intégration)."
        ),
        "headers": _RETRY_AFTER_HEADER,
    },
    500: {"model": InternalError, "description": "Erreur interne"},
    503: {
        "model": UnavailableError,
        "description": "Stockage temporairement indisponible",
        "headers": _RETRY_AFTER_HEADER,
    },
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
            "Trop de requêtes — quota de stockage atteint (#62/#63) ou débit "
            "clé/pair/global dépassé (#63, lot d'intégration)."
        ),
        "headers": _RETRY_AFTER_HEADER,
    },
    500: {"model": InternalError, "description": "Erreur interne"},
    503: {
        "model": UnavailableError,
        "description": "Stockage temporairement indisponible",
        "headers": _RETRY_AFTER_HEADER,
    },
    "default": {"model": InternalError, "description": "Erreur inattendue"},
}

_SECRETS_STATE_RESPONSES: dict[int | str, dict[str, Any]] = {
    **_SECRETS_GET_RESPONSES,
    200: {
        "model": SecretMetadata,
        "description": "Métadonnées courantes, sans la valeur (état seul).",
        "headers": _NO_STORE_HEADER,
    },
}


_SECRETS_LIST_RESPONSES: dict[int | str, dict[str, Any]] = {
    **{key: value for key, value in _SECRETS_GET_RESPONSES.items() if key != HTTPStatus.NOT_FOUND},
    200: {"model": SecretPage, "headers": _NO_STORE_HEADER, "description": "Page de métadonnées"},
}

_SECRETS_DELETE_RESPONSES: dict[int | str, dict[str, Any]] = {
    **{key: value for key, value in _SECRETS_GET_RESPONSES.items() if key != HTTPStatus.OK},
    204: {"headers": _NO_STORE_HEADER, "description": "Secret supprimé, capacité libérée"},
}


class VaultSettings(BaseSettings):
    """Configuration du serveur Vault via variables d'environnement."""

    model_config = SettingsConfigDict(
        env_prefix="HEIMDALL_VAULT_",
        case_sensitive=False,
        extra="ignore",
        # Aucune valeur reçue (KEK, clé maîtresse, pepper) ne doit apparaître
        # dans un message de ValidationError : le démarrage peut journaliser
        # l'erreur. Les validateurs ci-dessous produisent déjà des messages
        # génériques ; ce réglage supprime l'écho ``input_value`` de pydantic.
        hide_input_in_errors=True,
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
    api_key_pepper: str | None = Field(
        default=None,
        repr=False, exclude=True,  # jamais dans model_dump()/model_dump_json()
        description=(
            "Pepper serveur distinct de la KEK pour hachage HMAC-SHA256 (ticket #64). "
            "Doit comporter au moins 32 octets (256 bits). "
            "Obligatoire en production via HEIMDALL_VAULT_API_KEY_PEPPER. "
            "Hors production, absent = pepper aléatoire éphémère généré au démarrage "
            "avec avertissement (aucune valeur publique par défaut, aucune portabilité "
            "des empreintes entre déploiements). "
            "Jamais consigné dans les journaux d'audit ni retourné au client."
        ),
    )
    storage_backend: Literal["memory", "sqlite"] | None = Field(
        default=None,
        description=(
            "Backend de stockage des secrets. Défaut : 'sqlite' en production "
            "(persistant, multi-workers), 'memory' hors production (tests/dev). "
            "Le backend 'sqlite' exige toujours une KEK via HEIMDALL_VAULT_KEK "
            "ou le couple HEIMDALL_VAULT_MASTER_KEY + HEIMDALL_VAULT_KEK_SALT."
        ),
    )
    kek: str | None = Field(
        default=None,
        repr=False, exclude=True,  # jamais dans model_dump()/model_dump_json()
        description=(
            "MODE HISTORIQUE : KEK AES-256 encodée base64 (32 octets), utilisée "
            "directement sans dérivation, distincte du pepper d'authentification. "
            "Conservée pour ne pas rendre illisibles les blobs existants ; les "
            "nouveaux déploiements utilisent HEIMDALL_VAULT_MASTER_KEY + "
            "HEIMDALL_VAULT_KEK_SALT (ticket #262). Mutuellement exclusive avec "
            "HEIMDALL_VAULT_MASTER_KEY. Jamais stockée en base ; le backend "
            "'memory' génère une KEK éphémère si aucune clé n'est fournie."
        ),
    )
    master_key: str | None = Field(
        default=None,
        repr=False, exclude=True,  # jamais dans model_dump()/model_dump_json()
        description=(
            "Clé maîtresse du serveur (phrase de passe UTF-8 d'au moins 16 octets), "
            "matière première de la KEK dérivée par Argon2id (ticket #262). "
            "Exige HEIMDALL_VAULT_KEK_SALT et exclut HEIMDALL_VAULT_KEK. "
            "La dérivation a lieu une seule fois au démarrage ; la clé maîtresse "
            "n'est jamais stockée en base, journalisée ni retournée au client."
        ),
    )
    kek_salt: str | None = Field(
        default=None,
        repr=False, exclude=True,  # public mais jamais sérialisé par défense
        description=(
            "Sel public Argon2id de 16 octets encodé base64 URL-safe (ticket #262), "
            "persisté à côté de HEIMDALL_VAULT_MASTER_KEY et stable entre les "
            "démarrages. Non secret, mais indispensable : un sel perdu ou modifié "
            "change la KEK dérivée et rend les secrets existants illisibles."
        ),
    )
    rate_limit_per_key: int = Field(
        default=600,
        ge=1,
        le=1_000_000,
        description="Requêtes autorisées par fenêtre pour une clé API validée.",
    )
    rate_limit_per_peer: int = Field(
        default=1_200,
        ge=1,
        le=1_000_000,
        description="Requêtes autorisées par fenêtre pour une adresse de pair réseau.",
    )
    rate_limit_global: int = Field(
        default=6_000,
        ge=1,
        le=10_000_000,
        description="Requêtes autorisées par fenêtre toutes sources confondues.",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3_600,
        description="Taille de la fenêtre de rate-limiting en secondes (Retry-After borné).",
    )
    db_path: str = Field(
        default=str(DEFAULT_DB_PATH),
        description="Chemin du fichier de base de données SQLite.",
    )
    ssl_certfile: str | None = Field(
        default=None,
        repr=False,
        description=(
            "Certificat TLS PEM (chaîne complète) pour le lanceur uvicorn. "
            "Doit contenir le SAN IP 127.0.0.1 en développement. "
            "Obligatoire en production avec ssl_keyfile (fail-closed)."
        ),
    )
    ssl_keyfile: str | None = Field(
        default=None,
        repr=False,
        description=(
            "Clé privée TLS PEM associée à ssl_certfile. "
            "Obligatoire en production avec ssl_certfile (fail-closed)."
        ),
    )

    @field_validator("api_key_pepper")
    @classmethod
    def validate_api_key_pepper(cls, value: str | None) -> str | None:
        """Valide le pepper : jamais vide, jamais court, jamais le défaut public.

        La politique (longueur minimale, refus de la constante publique
        committée hors ``HEIMDALL_ENV=test``) est appliquée par le module
        d'authentification `heimdall.vault.auth` (ticket #64), seul propriétaire
        du pepper et de la stratégie d'empreinte.
        """
        return vault_auth.validate_api_key_pepper(value)

    @model_validator(mode="after")
    def resolve_api_key_pepper(self) -> "VaultSettings":
        """Résout le pepper absent : obligatoire en production, éphémère sinon.

        Hors production, un pepper aléatoire de 256 bits est généré au démarrage
        avec un avertissement (les empreintes ne survivent pas au redémarrage).
        En production, l'absence lève une erreur explicite : fail-closed, jamais
        de repli sur un pepper public.
        """
        if self.api_key_pepper is not None:
            return self
        if _heimdall_env_mode() in _PRODUCTION_ENV_MODES:
            raise ValueError(
                "HEIMDALL_VAULT_API_KEY_PEPPER est obligatoire en production "
                "(HEIMDALL_ENV=production/prod) : aucun pepper public par défaut "
                "n'est accepté. Fournir un secret unique et persisté, distinct de la KEK."
            )
        self.api_key_pepper = generate_api_key_pepper()
        _warn_generated_pepper_once()
        return self

    @model_validator(mode="after")
    def validate_require_auth_in_production(self) -> "VaultSettings":
        """Refuse la désactivation de l'authentification en production (fail-closed).

        ``require_auth=False`` n'existe que pour des tests isolés : associé à
        ``HEIMDALL_ENV=production/prod``, il démarrerait un vault ouvert (lecture
        et création sur tout projet, oracle 200/404). Comme le backend ``memory``
        interdit en production et le pepper obligatoire, cette misconfiguration
        est refusée au démarrage plutôt que tolérée silencieusement.
        """
        if not self.require_auth and _heimdall_env_mode() in _PRODUCTION_ENV_MODES:
            raise ValueError(
                "HEIMDALL_VAULT_REQUIRE_AUTH=false est interdit en production "
                "(HEIMDALL_ENV=production/prod) : le serveur Vault doit rester "
                "fail-closed. La désactivation est réservée aux tests isolés."
            )
        return self

    @model_validator(mode="after")
    def validate_docs_disabled_in_production(self) -> "VaultSettings":
        """Refuse la documentation OpenAPI en production (anti-fingerprinting).

        ``enable_docs=True`` expose `/docs` et `/openapi.json` (schéma, version)
        sans authentification : comme `require_auth=False` et le backend
        `memory`, cette exposition est refusée en production
        (`HEIMDALL_ENV=production/prod`), réservée au développement local.
        """
        if self.enable_docs and _heimdall_env_mode() in _PRODUCTION_ENV_MODES:
            raise ValueError(
                "HEIMDALL_VAULT_ENABLE_DOCS=true est interdit en production "
                "(HEIMDALL_ENV=production/prod) : /docs et /openapi.json "
                "exposeraient le schéma sans authentification (fingerprinting). "
                "La documentation est réservée au développement local."
            )
        return self

    @property
    def effective_api_key_pepper(self) -> str:
        """Pepper résolu et non vide (garanti par ``resolve_api_key_pepper``)."""
        pepper = self.api_key_pepper
        if pepper is None:
            raise RuntimeError(
                "Pepper serveur non résolu : VaultSettings a contourné sa validation."
            )
        return pepper

    @field_validator("kek")
    @classmethod
    def validate_kek(cls, value: str | None) -> str | None:
        """Valide la KEK : non vide, sans espaces de bord, base64 de 32 octets."""
        if value is None:
            return None
        if not value or value != value.strip():
            raise ValueError(
                "La KEK ne doit pas être vide ni comporter d'espaces de début ou de fin."
            )
        try:
            VaultCipher.from_encoded_key(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("master_key")
    @classmethod
    def validate_master_key(cls, value: str | None) -> str | None:
        """Valide la clé maîtresse : phrase de passe UTF-8 d'au moins 128 bits.

        Le seuil de 16 octets est une défense en profondeur : Argon2id ralentit
        une attaque hors ligne mais ne rend pas une phrase de passe triviale
        résistante. La valeur n'est jamais écho dans un message d'erreur. La
        valeur retournée est canonisée NFC (ticket #262) : deux formes Unicode
        équivalentes (précomposée vs combinée) produisent la même KEK.
        """
        if value is None:
            return None
        if not value or not value.strip():
            raise ValueError("La clé maîtresse ne doit pas être vide ou blanche.")
        if value != value.strip():
            raise ValueError("La clé maîtresse ne doit pas comporter d'espaces de début ou de fin.")
        try:
            # Forme canonique NFC (ticket #262) : cohérente avec la canonisation
            # NFC des valeurs de secrets (décision #62) et avec la normalisation
            # appliquée par `_normalize_master_key` (ADR-005).
            normalized = unicodedata.normalize("NFC", value)
            raw = normalized.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("La clé maîtresse doit être encodable en UTF-8.") from None
        if len(raw) < MIN_MASTER_KEY_BYTES:
            raise ValueError(
                f"La clé maîtresse doit comporter au moins {MIN_MASTER_KEY_BYTES} "
                "octets (128 bits)."
            )
        return normalized

    @field_validator("kek_salt")
    @classmethod
    def validate_kek_salt(cls, value: str | None) -> str | None:
        """Valide le sel Argon2id : base64 de 16 octets exactement (ticket #262)."""
        if value is None:
            return None
        try:
            decode_kek_salt(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @model_validator(mode="after")
    def validate_master_key_configuration(self) -> "VaultSettings":
        """Impose la paire maître/sel et l'exclusivité avec la KEK historique.

        - ``master_key`` sans ``kek_salt`` (ou l'inverse) est refusé : sans sel
          stable, la KEK dériverait différemment à chaque démarrage.
        - ``kek`` et ``master_key`` ensemble sont refusés : deux sources de KEK
          concurrentes rendraient le choix implicite et le débogage dangereux.
        """
        if (self.master_key is None) != (self.kek_salt is None):
            raise ValueError(
                "HEIMDALL_VAULT_MASTER_KEY et HEIMDALL_VAULT_KEK_SALT doivent être "
                "fournis ensemble (ticket #262)."
            )
        if self.master_key is not None and self.kek is not None:
            raise ValueError(
                "HEIMDALL_VAULT_KEK (mode historique) et HEIMDALL_VAULT_MASTER_KEY "
                "sont mutuellement exclusifs : choisir un seul mode de dérivation."
            )
        return self

    @model_validator(mode="after")
    def validate_kek_distinct_from_pepper(self) -> "VaultSettings":
        """La KEK de chiffrement et le pepper d'authentification doivent être distincts.

        La comparaison porte sur l'entropie décodée (KEK brute vs pepper UTF-8),
        pas seulement sur les chaînes encodées : deux représentations d'une même
        entropie (ex. pepper UTF-8 dont le base64 32 octets est la KEK) sont
        refusées, conformément à l'invariant 5 (jamais la même clé pour le
        chiffrement et le HMAC de vérification).

        Le contrôle de la clé maîtresse est également fait ici, et pas seulement
        dans ``_resolve_vault_cipher`` : un ``secret_store`` explicite court-
        circuite la dérivation et ne doit pas laisser passer cette collision.
        """
        pepper = self.api_key_pepper
        if pepper is None:
            return self
        if self.master_key is not None and constant_time_equal(
            self.master_key.encode("utf-8"), pepper.encode("utf-8")
        ):
            raise ValueError(
                "La clé maîtresse et le pepper d'authentification doivent être "
                "distincts (invariant 5)."
            )
        if self.kek is not None and kek_matches_pepper(self.kek, pepper):
            raise ValueError(
                "La KEK de chiffrement et le pepper d'authentification doivent "
                "être distincts, y compris sous des encodages différents."
            )
        return self

    @field_validator("db_path")
    @classmethod
    def validate_db_path(cls, value: str) -> str:
        """Refuse les chemins invalides en réutilisant le validateur factorisé."""
        try:
            return validate_db_path(value)
        except IsADirectoryError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("ssl_certfile", "ssl_keyfile")
    @classmethod
    def validate_tls_file(cls, value: str | None) -> str | None:
        """Valide un fichier TLS : absolu, existant, régulier, sans symlink, sans espace de bord.

        Les liens symboliques sont refusés via le même garde que la couche DB
        (`_assert_not_symlink`, invariant n°3) : uvicorn suivrait sinon la cible
        à l'ouverture, hors du chemin validé (TOCTOU).
        """
        if value is None:
            return None
        if not value or value != value.strip():
            raise ValueError("Le chemin TLS ne doit pas être vide ni comporter d'espaces de bord.")
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("Le chemin TLS doit être absolu.")
        if not path.is_file():
            raise ValueError("Le fichier TLS est introuvable ou n'est pas un fichier régulier.")
        try:
            _assert_not_symlink(path)
        except PermissionError as exc:
            raise ValueError(
                "Le chemin TLS ne doit pas être un lien symbolique ni en traverser un."
            ) from exc
        return str(path)

    @model_validator(mode="after")
    def validate_tls_pair(self) -> "VaultSettings":
        """Certificat et clé TLS vont toujours ensemble (fail-closed)."""
        if (self.ssl_certfile is None) != (self.ssl_keyfile is None):
            raise ValueError(
                "Les options TLS ssl_certfile et ssl_keyfile doivent être fournies ensemble."
            )
        return self

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
    status: Literal["ok"]


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


class _PayloadTooLargeError(StarletteHTTPException):
    """Flux reçu dépassant la limite : rejet 400 fermant la connexion.

    Sous-classe de ``StarletteHTTPException`` car FastAPI convertit toute
    exception non-HTTP levée pendant la lecture du corps en
    ``HTTPException(400, "There was an error parsing the body")`` : ce type
    traverse cette conversion sans être ré-emballé, et le handler contractuel
    (``router_error_handler``) conserve alors l'en-tête ``Connection: close``
    (allowlist). Le middleware ``BodySizeLimitMiddleware`` intercepte aussi ce
    type pour les applications internes qui ne passent pas par FastAPI.
    """

    def __init__(self) -> None:
        super().__init__(
            status_code=400,
            detail="Requête invalide",
            headers={"Connection": "close"},
        )


class BodySizeLimitMiddleware:
    """Interrompt immédiatement la lecture du flux dès que la taille dépasse 1 Mio.

    Conforme à openapi.yaml:33-37 : compte le flux effectivement reçu, même sans
    Content-Length ou en transfert segmenté, et interrompt la lecture dès dépassement
    sans accumulation en mémoire (protection anti-OOM).

    Chaque rejet 400 porte ``Connection: close`` : les octets non consommés du
    corps resteraient sinon dans le tampon d'une connexion keep-alive et
    pourraient désynchroniser la requête suivante (anti-smuggling, RFC 9112).
    """

    def __init__(self, app: Any, max_body_size: int = _MAX_BODY_SIZE) -> None:
        self.app = app
        self.max_body_size = max_body_size

    @staticmethod
    def _reject() -> JSONResponse:
        """Réponse 400 contractuelle fermant la connexion (octets non drainés)."""
        return JSONResponse(
            status_code=400,
            content=_ERROR_PAYLOADS[400],
            headers={"Connection": "close"},
        )

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
            await self._reject()(scope, receive, send)
            return

        if len(content_lengths) > 1:
            await self._reject()(scope, receive, send)
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
                    await self._reject()(scope, receive, send)
                    return
            except (ValueError, UnicodeDecodeError, TypeError):
                await self._reject()(scope, receive, send)
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
            await self._reject()(scope, receive, send)


class DatabaseAvailabilityMiddleware:
    """Transforme les pannes DB des middlewares ET routes en 503 contractuel."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracked_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except DatabaseUnavailableError:
            # Aucun détail SQL, chemin, empreinte ou secret dans les logs/réponses.
            logger.warning("Stockage Vault indisponible.")
            if started:
                raise
            response = JSONResponse(
                status_code=503,
                content=_ERROR_PAYLOADS[503],
                headers={"Retry-After": "1", "Connection": "close", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)


async def _limiter_peek(limiter: RateLimiter | SqliteRateLimiter, peer: str) -> tuple[bool, int]:
    """Lecture seule pair/global, sans verrou d'écriture (rejet précoce)."""
    if isinstance(limiter, SqliteRateLimiter):
        return await asyncio.to_thread(limiter.peek, peer)
    return limiter.peek(peer)


async def _limiter_consume_peer(
    limiter: RateLimiter | SqliteRateLimiter, peer: str
) -> tuple[bool, int]:
    """Consomme pair/global pour les requêtes sans bucket clé (401/400/santé)."""
    if isinstance(limiter, SqliteRateLimiter):
        return await asyncio.to_thread(limiter.check, peer)
    return limiter.check(peer)


async def _limiter_consume_authenticated(
    limiter: RateLimiter | SqliteRateLimiter, peer: str, key_hash: str
) -> tuple[bool, int]:
    """Consomme pair/global + clé en une seule transaction (requête authentifiée)."""
    if isinstance(limiter, SqliteRateLimiter):
        return await asyncio.to_thread(limiter.check_authenticated, peer, key_hash)
    return limiter.check_authenticated(peer, key_hash)


def _register_no_store_middleware(app: FastAPI) -> None:
    """Force ``Cache-Control: no-store`` sur toutes les réponses de secrets.

    Les handlers de succès posent déjà l'en-tête ; ce middleware couvre les
    chemins d'erreur (400/401/403/404/429) sans dupliquer la logique dans
    chaque route. Les 503 de ``DatabaseAvailabilityMiddleware``, plus externe,
    portent déjà l'en-tête.
    """

    @app.middleware("http")
    async def secrets_no_store_middleware(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        path = request.url.path
        if path == "/api/v1/secrets" or path.startswith("/api/v1/secrets/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def _register_middleware(app: FastAPI) -> None:
    """Enregistre les middlewares du serveur Vault."""
    app.add_middleware(BodySizeLimitMiddleware, max_body_size=_MAX_BODY_SIZE)

    # Le rate-limiting est enregistré avant le middleware loopback : ce dernier,
    # ajouté en dernier, reste le plus externe et rejette les pairs non loopback
    # avant toute consommation de budget ou tout accès à la base.
    limiter_kwargs = {
        "per_key": app.state.settings.rate_limit_per_key,
        "per_peer": app.state.settings.rate_limit_per_peer,
        "global_limit": app.state.settings.rate_limit_global,
        "window_seconds": app.state.settings.rate_limit_window_seconds,
    }
    if app.state.storage_backend == "sqlite":
        # Backend persistant : les buckets sont partagés entre workers, donc
        # une limite unique (jamais N × la limite avec workers > 1).
        app.state.rate_limiter = SqliteRateLimiter(app.state.db_path, **limiter_kwargs)
    else:
        # Mode mémoire : strictement mono-processus (workers=1 documenté).
        app.state.rate_limiter = RateLimiter(**limiter_kwargs)

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
        """Borne le débit par clé validée, pair réseau et global (lot #63).

        Rejet précoce sans coût CPU : ``peek`` pair/global (lecture seule,
        sans consommation) précède tout hachage ou lookup. Les 400/401 sont
        comptés par le bucket pair/global puisque le middleware s'exécute
        avant le routage et les dépendances. Une clé invalide ne crée aucun
        bucket arbitraire : seuls pair et global s'appliquent. Le choix du
        bucket par clé emprunte le même parcours à coût comparable que
        ``verify_api_key`` (``find_api_key_project_cached``) : le résultat est
        mémoïsé dans la requête et réutilisé par l'authentification (un seul
        full-scan par requête, lot #63) ; l'existence d'une clé n'est pas
        observable par le temps de réponse du middleware. La phase consommatrice
        est ensuite UNIQUE : ``check_authenticated`` consomme pair/global + clé
        en une seule transaction (mémoire : une seule section critique ;
        SQLite : un seul ``BEGIN IMMEDIATE``), au lieu de deux transactions
        successives (plus de fenêtre inter-transactions ni double verrou
        d'écriture). Sémantique préservée : pair/global restent consommés même
        quand le bucket clé est plein. Avec le backend SQLite,
        ``SqliteRateLimiter`` partage les buckets entre workers : la limite
        n'est jamais multipliée par le nombre de processus. Le mode mémoire
        reste mono-processus (dev/test).
        """
        peer = request.client.host if request.client and request.client.host else "unknown"
        limiter: RateLimiter | SqliteRateLimiter = request.app.state.rate_limiter

        allowed, retry_after = await _limiter_peek(limiter, peer)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content=_ERROR_PAYLOADS[429],
                headers={"Retry-After": str(retry_after), "Connection": "close"},
            )
        key_hash: str | None = None
        raw_key = request.headers.get("X-Heimdall-API-Key")
        if raw_key is not None and len(raw_key) > vault_auth.MAX_API_KEY_LENGTH:
            allowed, retry_after = await _limiter_consume_peer(limiter, peer)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content=_ERROR_PAYLOADS[429],
                    headers={"Retry-After": str(retry_after), "Connection": "close"},
                )
            return JSONResponse(
                status_code=401,
                content=_ERROR_PAYLOADS[401],
                headers={"Connection": "close"},
            )
        if raw_key and raw_key == raw_key.strip() and request.url.path != "/api/v1/health":
            try:
                candidate_hash = vault_auth.hash_project_api_key(
                    raw_key,
                    pepper=request.app.state.settings.effective_api_key_pepper,
                )
            except ValueError:
                candidate_hash = None
            if candidate_hash is not None:
                registered_project, _ = await vault_auth.find_api_key_project_cached(
                    request, candidate_hash
                )
                if registered_project is not None:
                    key_hash = candidate_hash

        if key_hash is not None:
            allowed, retry_after = await _limiter_consume_authenticated(limiter, peer, key_hash)
        else:
            allowed, retry_after = await _limiter_consume_peer(limiter, peer)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content=_ERROR_PAYLOADS[429],
                headers={"Retry-After": str(retry_after), "Connection": "close"},
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
                headers={"Connection": "close"},
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
                headers={"Connection": "close"},
            )
        return await call_next(request)

    _register_no_store_middleware(app)


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
                elif lower_key == "connection":
                    # Seule la fermeture de connexion est admise (anti-smuggling,
                    # rejets du middleware de taille) ; jamais d'autre directive.
                    if str(val).strip().lower() == "close":
                        filtered_headers["Connection"] = "close"
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

    @app.get(
        "/api/v1/secrets",
        response_model=SecretPage,
        responses=_SECRETS_LIST_RESPONSES,
        tags=["Secrets"],
        summary="Lister les métadonnées des secrets d'un projet",
        operation_id="listSecrets",
    )
    async def list_secrets(
        project: Annotated[ProjectId, Query()],
        response: Response,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=_MAX_SECRET_OFFSET)] = 0,
        authenticated_project: Annotated[str | None, Depends(verify_api_key)] = None,
    ) -> SecretPage:
        vault_auth.ensure_project_access(
            authenticated_project, project, require_auth=app.state.settings.require_auth
        )
        response.headers["Cache-Control"] = "no-store"
        store: InMemorySecretStore | SqliteSecretStore = app.state.secret_store
        records = await store.list_page(project, limit + 1, offset)
        return SecretPage(
            items=[SecretMetadata.model_validate(record) for record in records[:limit]],
            next_offset=(
                offset + limit
                if len(records) > limit and offset + limit <= _MAX_SECRET_OFFSET
                else None
            ),
        )

    @app.delete(
        "/api/v1/secrets/{project}/{env}/{name}",
        status_code=204,
        response_class=Response,
        responses=_SECRETS_DELETE_RESPONSES,
        tags=["Secrets"],
        summary="Supprimer un secret et libérer sa capacité",
        operation_id="deleteSecret",
        dependencies=[Depends(vault_auth.require_project_access())],
    )
    async def delete_secret(
        project: Annotated[ProjectId, FastApiPath()],
        env: Annotated[EnvironmentId, FastApiPath()],
        name: Annotated[SecretName, FastApiPath()],
    ) -> Response:
        store: InMemorySecretStore | SqliteSecretStore = app.state.secret_store
        if not await store.delete(project, env, name):
            raise StarletteHTTPException(status_code=404, detail="Ressource introuvable")
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

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
        settings: VaultSettings | None = getattr(app.state, "settings", None)
        require_auth = True if settings is None else settings.require_auth
        # Autorisation AVANT toute écriture : une clé d'un autre projet est
        # refusée en 403 sans que l'existence d'un secret ne soit révélée.
        vault_auth.ensure_project_access(
            authenticated_project,
            secret_in.project,
            require_auth=require_auth,
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
            # 429 de CAPACITÉ (quota de stockage, #62) : distinct du 429 de
            # DÉBIT (rate-limit, lot #63), lui transitoire.
            # Le contrat OpenAPI impose `Retry-After` sur TOUT 429, donc
            # l'en-tête est présent même ici ; en revanche ce 429 n'est PAS
            # transitoire : un retry sera refusé tant que la capacité reste
            # pleine. Libérer un emplacement via DELETE (#158) avant de recréer.
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
        # Ticket #64 : la dépendance lit l'en-tête X-Heimdall-API-Key, retrouve
        # la clé et vérifie qu'elle appartient AU projet demandé. Le contrôle est
        # fait avant toute recherche de ressource (401 clé absente/inconnue/
        # révoquée, 403 clé d'un autre projet).
        dependencies=[Depends(vault_auth.require_project_access())],
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
    ) -> SecretRead:
        """Lire la valeur courante d'un secret (ticket #63)."""
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

    @app.get(
        "/api/v1/secrets/{project}/{env}/{name}/state",
        response_model=SecretMetadata,
        status_code=200,
        responses=_SECRETS_STATE_RESPONSES,
        tags=["Secrets"],
        summary="Lire l'état courant d'un secret sans la valeur",
        operation_id="getSecretState",
    )
    async def get_secret_state(
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
    ) -> SecretMetadata:
        """Lire l'état courant d'un secret sans exposer la valeur (contrat openapi.yaml).

        Même contrôle d'accès que la lecture : authentification requise,
        isolement par projet (403), 404 si inexistant, `Cache-Control: no-store`.
        Seules les métadonnées sont retournées, jamais la valeur.
        """
        settings: VaultSettings | None = getattr(app.state, "settings", None)
        if settings is None:
            settings = VaultSettings(require_auth=True)
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
        return SecretMetadata(
            project=record["project"],
            env=record["env"],
            name=record["name"],
            status=record["status"],  # type: ignore[arg-type]
        )


def _configure_secret_store(
    app: FastAPI,
    settings: VaultSettings,
    resolved_db: Path,
    secret_store: InMemorySecretStore | SqliteSecretStore | None,
) -> Literal["memory", "sqlite"]:
    """Résout et attache le store, sans jamais laisser fuiter le backend mémoire en prod."""
    resolved_backend = _resolve_storage_backend(settings)
    if secret_store is None:
        cipher = _resolve_vault_cipher(settings, resolved_backend)
        if resolved_backend == "sqlite":
            app.state.secret_store = SqliteSecretStore(resolved_db, cipher)
        else:
            app.state.secret_store = InMemorySecretStore(cipher=cipher)
        logger.debug("Backend de stockage des secrets : %s", resolved_backend)
        return resolved_backend

    if _heimdall_env_mode() in _PRODUCTION_ENV_MODES and isinstance(
        secret_store, InMemorySecretStore
    ):
        # Défense en profondeur : même un store explicite ne doit jamais
        # contourner l'interdiction du backend mémoire en production.
        raise ValueError(
            "Un InMemorySecretStore explicite est interdit en production "
            "(HEIMDALL_ENV=production/prod) : utiliser SqliteSecretStore "
            "avec une KEK persistante."
        )
    _validate_explicit_secret_store_configuration(settings, secret_store)
    app.state.secret_store = secret_store
    if isinstance(secret_store, SqliteSecretStore):
        # Aligner l'authentification sur la même base que le store explicite.
        # Le chemin est normalisé en ``Path`` : la lecture d'empreintes
        # (``lookup_db_api_key``) et l'écriture (``_persist_hash``) doivent
        # viser exactement le même fichier, quel que soit le type fourni.
        app.state.db_path = Path(secret_store.db_path)
        return "sqlite"
    return "memory"


def create_app(
    settings: VaultSettings | None = None,
    secret_store: InMemorySecretStore | SqliteSecretStore | None = None,
    api_key_hashes: dict[str, str] | None = None,
    api_keys: dict[str, str] | None = None,
) -> FastAPI:
    """Fabrique et configure l'application FastAPI pour le serveur Vault.

    Paramètres :
    - `settings` : Configuration VaultSettings (défaut : get_settings()).
    - `secret_store` : Magasin de secrets explicite (défaut : résolu par
      `settings.storage_backend` — SQLite chiffré en production, mémoire chiffré
      hors production). **Réservé aux tests** : la production passe toujours par
      `_resolve_vault_cipher`. Par défense en profondeur (invariant 5), la KEK
      du chiffreur du store explicite est comparée au pepper (brut + base64)
      une fois au démarrage, sans dérivation supplémentaire. Ne jamais appeler
      `create_app` avec un store explicite en production.
    - `api_key_hashes` : Dictionnaire {hash_hmac_hex: project_id} de clés pré-hachées.
      Chaque clé DOIT être une chaîne hexadécimale de 64 caractères (^[0-9a-f]{64}$).
      Les clés brutes sont expressément refusées pour éviter toute confusion de format.
      Chaque `project_id` DOIT satisfaire `PROJECT_PATTERN` (^[a-z][a-z0-9_-]{0,63}$) :
      un identifiant hors contrat est refusé à l'enregistrement (fail-fast, sans écho).
      Les empreintes étant opaques (HMAC irréversible), les contrôles de robustesse
      de `_validate_raw_api_key` ne s'y appliquent pas : elles DOIVENT provenir de
      clés générées par `generate_api_key()` (confiance placée dans le détenteur
      du pepper, qui peut hacher n'importe quoi).
    - `api_keys` : Alias de `api_key_hashes` pour compatibilité descendante.

    Le pepper utilisé pour les empreintes de `register_api_key` est celui de
    `effective_settings.effective_api_key_pepper` : obligatoire en production,
    aléatoire éphémère hors production (jamais de défaut public).
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
    # Ne jamais journaliser ni sérialiser ``app.state.settings`` : il porte la
    # clé maîtresse (durée de vie du processus) et le pepper d'authentification.
    app.state.settings = effective_settings
    resolved_db = _pin_db_path(effective_settings)
    app.state.db_path = resolved_db
    logger.debug("Base de données SQLite configurée : %s", resolved_db.name)

    app.state.storage_backend = _configure_secret_store(
        app, effective_settings, resolved_db, secret_store
    )

    if api_key_hashes is not None and api_keys is not None:
        raise ValueError(
            "Spécifiez 'api_key_hashes' ou 'api_keys', pas les deux simultanément."
        )

    raw_hashes = api_key_hashes if api_key_hashes is not None else api_keys
    validated_hashes: dict[str, str] = {}
    if raw_hashes is not None:
        for key_candidate, project_id in raw_hashes.items():
            validated_hashes[key_candidate] = project_id

    # Ticket #64 : le registre des clés API de projet est l'unique source de
    # vérité des empreintes (mémoire en mode `memory`, base SQLite en mode
    # `sqlite`). Il porte le pepper serveur, les verrous et la persistance.
    registry = vault_auth.ApiKeyRegistry(
        pepper=effective_settings.effective_api_key_pepper,
        storage_backend=app.state.storage_backend,
        # Le store explicite peut avoir aligné ``app.state.db_path`` sur un
        # autre fichier : le registre doit lire ET écrire cette même base.
        # Utiliser ``resolved_db`` ici désynchroniserait l'écriture
        # (``_persist_hash``) de la lecture d'authentification
        # (``find_api_key_project``), soit un 401 permanent fail-closed.
        db_path=app.state.db_path if app.state.storage_backend == "sqlite" else None,
    )
    for preregistered_hash, preregistered_project in validated_hashes.items():
        registry.register_hash(preregistered_hash, preregistered_project)
    app.state.api_key_registry = registry
    # Verrou de persistance distinct du verrou de snapshot : l'écriture SQLite
    # de l'enregistrement ne bloque jamais la copie en mémoire lue par le
    # chemin de requête (remarque de revue « api_keys_lock tenu pendant l'I/O DB »).
    app.state.api_keys_lock = registry.lock
    app.state.api_keys_persist_lock = registry.persist_lock
    app.state.api_keys = registry.active_hashes

    def register_api_key(raw_key: str, project_id: str) -> str:
        """Enregistre une clé API brute et retourne son identifiant (ticket #64).

        Les clés DOIVENT être générées par ``generate_api_key()`` (256 bits) :
        tout contournement manuel est une faute opérationnelle (en cas de fuite
        des empreintes et du pepper, seul un token aléatoire résiste au
        brute-force hors ligne). Les motifs triviaux (``"a" * 43``,
        ``"abcdefghijkl" * 4``, suites monotones 8+ comme ``abcdefgh…``/
        ``0123456789…``, lignes de clavier comme ``qwertyuiop…``/``azerty…``)
        sont refusés fail-fast, sans écho.
        L'identifiant de projet est validé contre ``PROJECT_PATTERN`` : une clé
        liée à un identifiant hors contrat ne pourrait jamais matcher une
        requête et provoquerait un 403 silencieux à chaque appel.

        ENREGISTREMENT AU DÉMARRAGE UNIQUEMENT (phase d'amorçage) : la fonction
        est synchrone et performs une E/S SQLite. Deux verrous distincts la
        protègent sans coupler le chemin de lecture des requêtes à l'E/S base :

        - ``api_keys_persist_lock`` sérialise les écritures (pas de double
          persistance de la même empreinte, pas de conflit de projet) ;
        - ``api_keys_lock`` protège la copie en mémoire ; il n'est jamais tenu
          pendant l'E/S base, donc la lecture concurrente des empreintes
          (parcours exhaustif du chemin d'authentification) ne bloque pas.

        Aucun ``asyncio.Lock`` n'est introduit ici : la fonction est synchrone et
        appelée hors de la boucle asyncio (amorçage, CLI, tests).

        La clé brute n'est jamais conservée : seule son empreinte l'est.
        """
        return registry.register(raw_key, project_id)

    app.state.register_api_key = register_api_key

    _register_middleware(app)
    app.add_middleware(DatabaseAvailabilityMiddleware)
    _register_exception_handlers(app)
    _register_routes(app)

    return app


_APP_HOLDER: dict[str, FastAPI] = {}
_app_lock = Lock()


def get_app() -> FastAPI:
    """Fabrique explicite du serveur (appelée par `run_server`, jamais à l'import).

    Garantie sans effet disque à l'import : ``import heimdall.vault.app`` ne
    résout aucun backend, ne génère ni cipher ni pepper et n'appelle jamais
    ``init_db``. Il n'existe volontairement AUCUNE variable module ``app`` :
    `from heimdall.vault.app import app` lève `ImportError` (aucune création
    accidentelle de `vault.db` par un import). La construction (backend SQLite,
    ``vault.db`` 600, pepper éphémère) n'a lieu qu'à l'appel explicite de
    cette factory, donc au démarrage du serveur via `run_server`.
    """
    if "app" not in _APP_HOLDER:
        with _app_lock:
            if "app" not in _APP_HOLDER:
                _APP_HOLDER["app"] = create_app()
    return _APP_HOLDER["app"]


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


def run_server() -> None:
    """Démarre le serveur Vault avec les paramètres validés (localhost uniquement).

    NOTE TLS (ticket #25) :
    En production (``HEIMDALL_ENV=production/prod``), le lanceur refuse de
    démarrer sans ``HEIMDALL_VAULT_SSL_CERTFILE`` et
    ``HEIMDALL_VAULT_SSL_KEYFILE`` : le HTTP en clair reste réservé au
    développement local. Le certificat doit porter le SAN IP ``127.0.0.1``
    pour ``https://127.0.0.1:8443``. La révocation de clés reste suivie dans
    son ticket dédié.

    NOTE CONCURRENCE : Le stockage SQLite chiffré (#26, #62), les empreintes de
    clés API et, avec ce même backend, les buckets de rate-limiting (lot #63)
    sont partagés entre workers. Le serveur épingle toutefois workers=1 (le lanceur
    ignore WEB_CONCURRENCY) : le mode mémoire reste strictement mono-processus
    et cette contrainte évite tout écart de configuration. Le backend SQLite
    peut être répliqué sans multiplier la limite de débit.
    """
    server_settings = get_settings()
    if _heimdall_env_mode() in _PRODUCTION_ENV_MODES and (
        server_settings.ssl_certfile is None or server_settings.ssl_keyfile is None
    ):
        raise ValueError(
            "TLS obligatoire en production (HEIMDALL_ENV=production/prod) : fournir "
            "HEIMDALL_VAULT_SSL_CERTFILE et HEIMDALL_VAULT_SSL_KEYFILE. "
            "Le HTTP en clair reste réservé au développement local."
        )
    uvicorn.run(
        get_app(),
        host=server_settings.host,
        port=server_settings.port,
        # Épinglé par défaut : le backend mémoire est strictement mono-processus.
        # Le backend SQLite partage ses buckets (lot #63), mais workers>1 reste une
        # décision d'exploitation explicite hors de ce lanceur minimal.
        workers=1,
        ssl_certfile=server_settings.ssl_certfile,
        ssl_keyfile=server_settings.ssl_keyfile,
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
    "SecretPage",
    "SecretRead",
    "Settings",
    "UnauthorizedError",
    "UnavailableError",
    "VaultSettings",
    "create_app",
    "generate_api_key",
    "get_app",
    "get_settings",
    "hash_api_key",
    "project_api_key_header",
    "run_server",
    "verify_api_key",
]

if __name__ == "__main__":
    run_server()
