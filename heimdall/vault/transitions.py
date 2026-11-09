"""Machine d'états et table des transitions du cycle de vie d'un secret (#40, #115).

Ce module formalise le cycle de vie complet d'un secret dans Heimdall :
`detecte -> confirme -> vaulte -> rote`, avec gestion de l'état `faux_positif`
(écarté) et contrôle strict des transitions interdites.

Aligné sur le contrat Finding v1 (ticket #14, ``docs/contracts/finding.md``,
``docs/adr/001-finding-et-etats.md``) et le journal des rejets LLM (ticket #33,
``docs/llm-rejections.md``). Décisions d'architecture : ADR-006.

Règles de sécurité :
1. Aucun champ ne porte la valeur du secret (invariant 8).
2. Fail-closed : toute transition non explicitement autorisée est interdite.
3. Messages d'erreur statiques : aucune donnée sensible ou entrée brute n'est
   reflétée dans les exceptions ou messages d'erreur.
4. Aucun faux positif n'est stocké dans le Vault.
5. L'état terminal `rote` interdit toute transition sortante.
6. Tout mutateur d'état (future API #117, store DB, CLI) DOIT obligatoirement
   appeler ``validate_transition()`` et ne persister que la forme canonique
   issue de ``canonicalize_state()`` (les alias ne sont jamais persistés).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Literal, get_args

#: Longueur maximale autorisée pour un identifiant d'état (défense DoS / bornage mémoire).
MAX_STATE_CHARS: Final[int] = 64

#: États formels du cycle de vie d'un secret (alignés sur le contrat #14).
SecretLifecycleState = Literal[
    "detecte",
    "confirme",
    "vaulte",
    "rote",
    "faux_positif",
]

#: Tuple des états du cycle de vie dans l'ordre canonique.
LIFECYCLE_STATES: Final[tuple[SecretLifecycleState, ...]] = (
    "detecte",
    "confirme",
    "vaulte",
    "rote",
    "faux_positif",
)

#: Ensemble immuable des états reconnus.
LIFECYCLE_STATES_SET: Final[frozenset[SecretLifecycleState]] = frozenset(
    get_args(SecretLifecycleState)
)

#: Alias acceptés pour la compatibilité métier (notamment « écarté »).
#: Ces alias ne doivent être acceptés qu'aux frontières (CLI / HTTP) et
#: NE DOIVENT JAMAIS être persistés directement (utiliser canonicalize_state()).
STATE_ALIASES: Final[MappingProxyType[str, SecretLifecycleState]] = MappingProxyType(
    {
        "ecarte": "faux_positif",
        "ecarté": "faux_positif",
        "discarded": "faux_positif",
    }
)

#: État initial obligatoire lors de la création d'un Finding par le scanner.
INITIAL_STATE: Final[SecretLifecycleState] = "detecte"

#: États terminaux : aucune transition sortante permise.
TERMINAL_STATES: Final[frozenset[SecretLifecycleState]] = frozenset({"rote"})


def _make_allowed_transitions() -> MappingProxyType[
    SecretLifecycleState, frozenset[SecretLifecycleState]
]:
    return MappingProxyType(
        {
            # 1. Détecté par le scanner déterministe
            "detecte": frozenset({"confirme", "faux_positif"}),
            # 2. Confirmé par validation humaine explicite (dialogue Y/N/E #32)
            "confirme": frozenset({"vaulte"}),
            # 3. Vaulté après persistance chiffrée et remédiation vérifiée
            "vaulte": frozenset({"rote"}),
            # 4. Roté : fin de cycle pour cette version du secret (état terminal)
            "rote": frozenset(),
            # 5. Faux positif (écarté) : réexamen explicite uniquement
            "faux_positif": frozenset({"detecte"}),
        }
    )


#: Table immuable des transitions autorisées (source -> cibles autorisées).
#: Protégée par MappingProxyType sans dictionnaire sous-jacent exposé au module.
ALLOWED_TRANSITIONS: Final[
    MappingProxyType[SecretLifecycleState, frozenset[SecretLifecycleState]]
] = _make_allowed_transitions()


def _make_forbidden_reasons() -> MappingProxyType[tuple[str, str], str]:
    return MappingProxyType(
        {
            # Depuis 'detecte'
            ("detecte", "detecte"): "Transition réflexive interdite : l'état reste inchangé.",
            ("detecte", "vaulte"): (
                "Passage direct interdit : un secret détecté doit d'abord être confirmé "
                "par un humain avant tout stockage chiffré dans le Vault."
            ),
            ("detecte", "rote"): (
                "Passage direct interdit : un secret détecté ne peut pas être roté sans "
                "avoir été préalablement confirmé et vaulté."
            ),
            # Depuis 'confirme'
            ("confirme", "detecte"): (
                "Régression arrière interdite : un secret confirmé ne peut pas redevenir "
                "un simple candidat non qualifié."
            ),
            ("confirme", "confirme"): "Transition réflexive interdite : l'état reste inchangé.",
            ("confirme", "faux_positif"): (
                "Contradiction de qualification : un secret confirmé ne peut pas être "
                "écarté comme faux positif sans réexamen complet à la source."
            ),
            ("confirme", "rote"): (
                "Passage direct interdit : un secret confirmé doit d'abord être persisté "
                "dans le Vault avant de pouvoir être roté."
            ),
            # Depuis 'vaulte'
            ("vaulte", "detecte"): (
                "Régression arrière interdite : un secret vaulté est compromis et "
                "ne peut pas revenir à l'état de détection."
            ),
            ("vaulte", "confirme"): (
                "Régression arrière interdite : un secret vaulté a déjà dépassé "
                "l'étape de confirmation."
            ),
            ("vaulte", "vaulte"): "Transition réflexive interdite : l'état reste inchangé.",
            ("vaulte", "faux_positif"): (
                "Interdiction formelle : un secret vaulté a été reconnu sensible et stocké ; "
                "il ne peut pas être déclassé en faux positif."
            ),
            # Depuis 'rote' (état terminal)
            ("rote", "detecte"): (
                "État terminal : la version du secret est révoquée ; une nouvelle valeur "
                "doit entamer un nouveau cycle indépendant."
            ),
            (
                "rote",
                "confirme",
            ): "État terminal : aucune transition sortante permise depuis 'rote'.",
            ("rote", "vaulte"): (
                "État terminal : impossible de re-vaulter un secret révoqué ; la rotation "
                "génère une nouvelle version du secret."
            ),
            ("rote", "rote"): "Transition réflexive interdite : l'état terminal reste inchangé.",
            ("rote", "faux_positif"): (
                "État terminal : un secret roté a été avéré et révoqué ; il ne peut pas "
                "être classé en faux positif."
            ),
            # Depuis 'faux_positif' (écarté)
            ("faux_positif", "confirme"): (
                "Passage direct interdit : un faux positif écarté doit obligatoirement "
                "repasser par l'état 'detecte' lors d'un réexamen avant toute confirmation."
            ),
            ("faux_positif", "vaulte"): (
                "Interdiction absolue : un faux positif ne doit JAMAIS être persisté dans "
                "le Vault (protection contre la pollution et l'épuisement des quotas)."
            ),
            ("faux_positif", "rote"): (
                "Non-sens fonctionnel : un faux positif n'est pas un secret réel et "
                "ne peut faire l'objet d'aucune rotation."
            ),
            (
                "faux_positif",
                "faux_positif",
            ): "Transition réflexive interdite : l'état reste inchangé.",
        }
    )


#: Justifications fermées immuables pour chaque transition interdite (5x5 - 5 autorisées).
FORBIDDEN_TRANSITION_REASONS: Final[MappingProxyType[tuple[str, str], str]] = (
    _make_forbidden_reasons()
)


class LifecycleTransitionError(ValueError):
    """Erreur de base liée au cycle de vie du secret."""


class UnknownStateError(LifecycleTransitionError):
    """État non reconnu dans le cycle de vie du secret.

    Invariant 8 : message d'erreur statique sans aucun paramètre
    pour éliminer tout risque de reflet d'entrée ou de secret.
    """

    def __init__(self) -> None:
        super().__init__("État de cycle de vie inconnu.")


class InvalidTransitionError(LifecycleTransitionError):
    """Transition d'état interdite ou non conforme."""

    def __init__(self, source: str, target: str, reason: str) -> None:
        message = f"Transition interdite de '{source}' vers '{target}' : {reason}"
        super().__init__(message)
        self.source = source
        self.target = target
        self.reason = reason


def canonicalize_state(state: object) -> SecretLifecycleState:
    """Normalise et valide un état du cycle de vie.

    Invariant 8 : message statique sans reflet en cas d'erreur.
    Gère les alias transparents (ex. ``ecarte`` -> ``faux_positif``).
    L'état retourné appartient toujours à ``LIFECYCLE_STATES_SET``.
    Lève ``UnknownStateError`` si l'état n'est pas une chaîne valide ou
    si sa longueur dépasse ``MAX_STATE_CHARS`` (défense DoS).
    """
    if not isinstance(state, str) or len(state) > MAX_STATE_CHARS:
        raise UnknownStateError()

    normalized = str.strip(state).lower()
    if normalized in LIFECYCLE_STATES_SET:
        return normalized

    if normalized in STATE_ALIASES:
        return STATE_ALIASES[normalized]

    raise UnknownStateError()


def is_valid_state(state: object) -> bool:
    """Vérifie si une chaîne correspond à un état valide ou un alias."""
    try:
        canonicalize_state(state)
        return True
    except UnknownStateError:
        return False


def is_transition_allowed(source: object, target: object) -> bool:
    """Détermine si la transition source -> target est autorisée.

    Retourne ``False`` en cas d'état inconnu ou de transition non autorisée
    (fail-closed).
    """
    try:
        src = canonicalize_state(source)
        dst = canonicalize_state(target)
    except UnknownStateError:
        return False

    return dst in ALLOWED_TRANSITIONS.get(src, frozenset())


def validate_transition(source: object, target: object) -> None:
    """Valide strictement une transition d'état.

    Lève ``UnknownStateError`` si un état est inconnu (sans reflet).
    Lève ``InvalidTransitionError`` si la transition est interdite, avec
    la justification formelle associée.
    """
    src = canonicalize_state(source)
    dst = canonicalize_state(target)

    if dst in ALLOWED_TRANSITIONS.get(src, frozenset()):
        return

    reason = FORBIDDEN_TRANSITION_REASONS.get(
        (src, dst),
        "Transition non définie dans la matrice autorisée (fail-closed).",
    )
    raise InvalidTransitionError(src, dst, reason)


def get_allowed_transitions(source: object) -> frozenset[SecretLifecycleState]:
    """Retourne l'ensemble des états cibles autorisés depuis l'état source."""
    src = canonicalize_state(source)
    return ALLOWED_TRANSITIONS.get(src, frozenset())


def get_forbidden_transitions(source: object) -> frozenset[SecretLifecycleState]:
    """Retourne l'ensemble des états cibles interdits depuis l'état source.

    Comprend les états distincts non autorisés ainsi que la transition réflexive.
    """
    src = canonicalize_state(source)
    allowed = ALLOWED_TRANSITIONS.get(src, frozenset())
    return frozenset(state for state in LIFECYCLE_STATES if state not in allowed)


def get_transition_matrix() -> dict[SecretLifecycleState, dict[SecretLifecycleState, bool]]:
    """Génère la matrice d'adjacence complète 5x5 des transitions autorisées."""
    return {
        src: {dst: (dst in ALLOWED_TRANSITIONS[src]) for dst in LIFECYCLE_STATES}
        for src in LIFECYCLE_STATES
    }
