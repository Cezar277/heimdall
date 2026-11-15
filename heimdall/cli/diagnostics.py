"""Diagnostics lisibles des erreurs d'outillage, sans jamais refléter d'entrée.

Par défaut, une erreur d'outillage garde **un seul libellé statique** par
commande (invariant 8 : une panne anticipée et une panne inattendue ne sont pas
distinguables sur stderr). Ce libellé invite à relancer avec ``--debug``.

En mode debug (``--debug`` ou ``HEIMDALL_DEBUG=1``), deux lignes de plus :

- ``cause :`` le message **statique** de l'exception Heimdall (``ScanError``,
  ``EnvRemediationError``…). Ces messages sont des constantes du code : aucun
  chemin, aucune valeur, aucune entrée utilisateur n'y est interpolé ;
- ``action :`` la correction à faire, quand la cause est connue.

Une exception étrangère (panne inattendue) n'est décrite que par son **type** :
son message pourrait contenir une valeur.
"""

from __future__ import annotations

import os
from typing import Final

import typer

from heimdall.mcp.errors import ToolFailure
from heimdall.remediation.apply import ApplyError
from heimdall.remediation.env import EnvRemediationError
from heimdall.remediation.templates import TemplateError
from heimdall.scanner.errors import ScanError

DEBUG_ENV: Final[str] = "HEIMDALL_DEBUG"
DEBUG_HINT: Final[str] = "Relancez avec --debug pour afficher la cause."

#: Exceptions Heimdall dont le message est une constante du code (vérifié :
#: aucune interpolation d'entrée utilisateur ni de valeur).
_STATIC_MESSAGE_ERRORS: Final[tuple[type[BaseException], ...]] = (
    ScanError,
    EnvRemediationError,
    ApplyError,
    TemplateError,
)

#: Préfixe de message statique → action proposée à l'utilisateur.
_ACTIONS: Final[tuple[tuple[str, str], ...]] = (
    (
        "auto-attestation refusée : en mode --ci, l'allowlist du dépôt exige",
        "en --ci, passez --config <fichier hors du dépôt> ou --no-allowlist.",
    ),
    (
        "auto-attestation refusée : en mode --ci, la configuration ne peut pas",
        "placez le fichier --config hors du dépôt scanné.",
    ),
    (
        "auto-attestation refusée : configuration stagée",
        "committez heimdall.toml dans un commit séparé, puis relancez.",
    ),
    (
        "auto-attestation refusée : configuration du worktree",
        "committez ou annulez les modifications de heimdall.toml, puis relancez.",
    ),
    (
        "configuration allowlist invalide",
        "heimdall.toml est invalide ou introuvable : vérifiez sa syntaxe "
        "(docs/t230-scanner-allowlist.md).",
    ),
    (
        "ligne invalide dans le fichier .env existant",
        "chaque ligne de .env doit être NOM=valeur (lignes vides et # autorisées).",
    ),
    (
        "clé existante invalide ou dangereuse dans .env",
        "retirez le préfixe « export » des lignes de .env et vérifiez les noms "
        "(lettres, chiffres, _).",
    ),
    (
        "valeur existante invalide dans .env",
        "une valeur de .env contient un saut de ligne ou un octet nul : corrigez-la.",
    ),
    (
        "écriture refusée : .env est un lien symbolique",
        "remplacez le lien symbolique .env par un fichier réel.",
    ),
    (
        "accès refusé :",
        "remplacez le lien symbolique signalé par un fichier réel.",
    ),
    (
        "volume total des secrets",
        "le fichier .env dépasse 1 Mio : déplacez une partie des valeurs.",
    ),
    (
        "racine modifiée depuis le scan",
        "le dépôt a changé pendant l'opération : relancez la commande.",
    ),
    (
        "contenu modifié depuis le scan",
        "un fichier a changé pendant l'opération : relancez la commande.",
    ),
    (
        "historique incomplet : clone superficiel",
        "récupérez l'historique complet (git fetch --unshallow) puis relancez.",
    ),
    (
        "le mode diff exige --ci",
        "ajoutez --ci à la commande.",
    ),
    (
        "trop de candidats pour la qualification locale",
        "relancez avec --no-llm, ou traitez d'abord les secrets déjà signalés.",
    ),
    (
        "limite de temps de qualification dépassée",
        "relancez avec --no-llm, ou vérifiez que le LLM local (Ollama) répond.",
    ),
    (
        "racine symlinkée refusée",
        "passez le chemin réel du dépôt, pas un lien symbolique.",
    ),
    (
        "racine inaccessible",
        "vérifiez que le chemin existe et que vous avez le droit de le lire.",
    ),
    (
        "scan impossible : entrée non analysable",
        "vérifiez que le chemin est un dépôt Git lisible ; un fichier trop gros "
        "ou un délai dépassé produit aussi cette erreur.",
    ),
)

_debug_flag = False
_remembered: BaseException | None = None


def begin_invocation(debug: bool) -> None:
    """Réinitialise l'état au début d'une invocation (callback racine uniquement).

    Sans cela, un ``--debug`` d'une invocation précédente dans le même
    processus (tests, CliRunner, usage en bibliothèque) resterait actif, et une
    cause mémorisée non consommée serait attribuée à la commande suivante.
    """
    global _debug_flag, _remembered  # noqa: PLW0603 - état d'invocation CLI
    _debug_flag = bool(debug)
    _remembered = None


def set_debug(enabled: bool) -> None:
    """Active le mode debug pour l'invocation courante (option ``--debug``).

    Ne fait que l'activer : ``heimdall --debug scan`` reste en debug même si la
    sous-commande transmet son propre ``--debug`` à ``False``. La remise à zéro
    se fait dans :func:`begin_invocation`.
    """
    global _debug_flag  # noqa: PLW0603 - état d'invocation CLI, un seul processus
    _debug_flag = _debug_flag or bool(enabled)


def debug_enabled() -> bool:
    """Vrai si ``--debug`` a été passé ou si ``HEIMDALL_DEBUG`` vaut 1/true/yes."""
    raw = os.environ.get(DEBUG_ENV, "").strip().lower()
    return _debug_flag or raw in {"1", "true", "yes", "on"}


def remember(exc: BaseException) -> None:
    """Mémorise la cause réelle d'un échec qu'une couche supérieure va masquer.

    La revue (``review_proposals``) remplace toute erreur d'application par une
    ``ReviewError`` statique : la cause d'origine serait perdue pour ``--debug``.
    """
    global _remembered  # noqa: PLW0603 - état d'invocation CLI, un seul processus
    _remembered = exc


def _forget() -> BaseException | None:
    global _remembered  # noqa: PLW0603 - état d'invocation CLI, un seul processus
    exc, _remembered = _remembered, None
    return exc


def describe(exc: BaseException | None) -> tuple[str, str | None]:
    """Rend ``(cause, action)`` pour ``exc`` sans jamais refléter une valeur."""
    if exc is None:
        return "cause inconnue", None
    if isinstance(exc, ToolFailure):
        return f"échec d'outil ({exc.code})", None
    if isinstance(exc, _STATIC_MESSAGE_ERRORS):
        message = str(exc)
        for prefix, action in _ACTIONS:
            if message.startswith(prefix):
                return message, action
        return message, None
    return f"panne inattendue ({type(exc).__name__})", (
        "signalez-la avec la commande lancée (sans secret) : "
        "https://github.com/Cezar277/heimdall/issues"
    )


def failure_message(generic: str) -> str:
    """Libellé unique d'erreur d'outillage, avec l'invitation à ``--debug``."""
    return f"{generic} {DEBUG_HINT}"


def report_failure(generic: str, exc: BaseException | None) -> None:
    """Écrit l'erreur d'outillage sur stderr (best-effort, ne lève jamais).

    Hors debug : une seule ligne statique, identique pour toutes les pannes.
    En debug : la cause statique (ou le type d'une panne inattendue), puis
    l'action connue. Une cause mémorisée par :func:`remember` est préférée à
    l'exception d'enveloppe (``ReviewError``) qui l'a masquée.
    """
    remembered = _forget()
    if not debug_enabled():
        lines = [failure_message(generic)]
    else:
        lines = [generic]
        cause, action = describe(remembered if remembered is not None else exc)
        lines.append(f"cause : {cause}")
        if action is not None:
            lines.append(f"action : {action}")
    try:
        typer.echo("\n".join(lines), err=True)
    except Exception:  # noqa: S110 # nosec B110 - stderr fermé en CI : best-effort
        pass
