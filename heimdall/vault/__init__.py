"""Vault Heimdall — persistance chiffrée et client TLS.

Implémentation serveur : ticket #25 (contrat OpenAPI #15 : ``openapi.yaml``).

RÈGLE D'ARCHITECTURE (ticket #17, piège à éviter) : **toute** la crypto
(chiffrement au repos, dérivation Argon2, génération et hachage des clés API)
vit dans ``heimdall.vault.crypto``. Aucun autre module du dépôt ne doit
importer ``cryptography`` ou ``argon2`` — vérifié par
``tests/test_crypto_confinement.py``.
"""

from heimdall.vault.client import VaultClient
from heimdall.vault.database import db_session, get_connection, init_db
from heimdall.vault.transitions import (
    ALLOWED_TRANSITIONS,
    FORBIDDEN_TRANSITION_REASONS,
    INITIAL_STATE,
    LIFECYCLE_STATES,
    TERMINAL_STATES,
    InvalidTransitionError,
    LifecycleTransitionError,
    SecretLifecycleState,
    UnknownStateError,
    canonicalize_state,
    is_transition_allowed,
    is_valid_state,
    validate_transition,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "FORBIDDEN_TRANSITION_REASONS",
    "INITIAL_STATE",
    "InvalidTransitionError",
    "LIFECYCLE_STATES",
    "LifecycleTransitionError",
    "SecretLifecycleState",
    "TERMINAL_STATES",
    "UnknownStateError",
    "VaultClient",
    "canonicalize_state",
    "db_session",
    "get_connection",
    "init_db",
    "is_transition_allowed",
    "is_valid_state",
    "validate_transition",
]
