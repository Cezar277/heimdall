"""Authentification par clé API de projet — ticket #64.

Ce module concentre la brique d'authentification du Vault Heimdall : cycle de vie
des clés API de projet (émission, stockage de l'empreinte, vérification,
révocation) et dépendance FastAPI qui lit l'en-tête `X-Heimdall-API-Key`.

Il est autonome : il ne connaît pas `heimdall.vault.app` (la configuration est
lue via `app.state`), ce qui évite toute dépendance circulaire. `app.py` l'importe
et lui délègue l'authentification ; la CLI `heimdall vault key` l'utilise
directement pour émettre et révoquer des clés.

RÈGLES DE SÉCURITÉ ET CONFORMITÉ (DoD, STRIDE, pentest) :
- Clé brute JAMAIS stockée, journalisée ni renvoyée après l'émission : seul le
  haché de vérification (HMAC-SHA256 + pepper serveur) est persisté
  (openapi.yaml:186-207, mitigation « Information disclosure »).
- Génération à ≥ 256 bits via `secrets.token_urlsafe(32)` : jamais dérivée de
  données prédictibles (identifiant, horodatage, compteur).
- Pepper serveur explicite, ≥ 32 octets, distinct de la KEK de chiffrement :
  aucune valeur publique par défaut (invariant 5), jamais journalisé.
- Réponses 401 génériques : clé absente, inconnue, révoquée ou invalide rendent
  la MÊME réponse, sans écho de la valeur reçue (ni corps, ni logs, ni trace).
- 403 quand la clé est valide mais liée à un autre projet : l'autorisation est
  vérifiée AVANT toute recherche de ressource (openapi.yaml:83-85).
- Coût de vérification comparable : parcours exhaustif des empreintes, comparaison
  en temps constant (`hmac.compare_digest`), empreinte factice quand aucune clé
  n'est évaluée — l'existence d'une clé n'est pas observable par le temps de
  réponse (anti-oracle temporel).
- Confinement crypto (ticket #17) : ce module n'importe JAMAIS `cryptography`
  ni `argon2` (réservés à `heimdall/vault/crypto.py`) ; il délègue à `crypto.py`.
"""

import asyncio
import logging
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends
from fastapi import Path as PathParam
from fastapi.security import APIKeyHeader
from pydantic import StringConstraints
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from heimdall.vault.crypto import (
    constant_time_equal,
    generate_api_key,
    hash_api_key,
)
from heimdall.vault.database import (
    DatabaseUnavailableError,
    ensure_project,
    get_iso_timestamp,
    revoke_api_key,
)
from heimdall.vault.database import runtime_db_session as db_session

logger = logging.getLogger("heimdall.vault.auth")

# Nom de l'en-tête d'authentification (openapi.yaml:186-190).
API_KEY_HEADER_NAME: str = "X-Heimdall-API-Key"

project_api_key_header = APIKeyHeader(
    name=API_KEY_HEADER_NAME,
    scheme_name="ProjectApiKey",
    auto_error=False,
    description=(
        "Clé d'authentification projet (ticket #64). "
        "Générée à >= 256 bits via secrets.token_urlsafe(32)."
    ),
)

# Longueur maximale acceptée pour l'en-tête : au-delà, la requête est rejetée
# sans hachage (garde de taille, coût de vérification borné).
MAX_API_KEY_LENGTH: int = 512

# Empreinte factice : comparée quand aucune clé n'est évaluée, pour que le coût
# du chemin « clé inconnue » reste comparable à celui du chemin « clé connue ».
DUMMY_HASH: str = "0" * 64

# Format attendu des empreintes persistées (HMAC-SHA256 hexadécimal).
HASH_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{64}$")

# Politique #64 : une clé opérateur doit offrir une entropie comparable aux clés
# émises par `generate_api_key` (``secrets.token_urlsafe(32)`` → 43 caractères,
# 256 bits). Le contrôle est fail-closed sur les MOTIFS TRIVIAUX, en six temps :
# - alphabet base64url strict (A-Z, a-z, 0-9, « _ », « - ») via `fullmatch` :
#   ni espaces, ni contrôles, ni ambiguïté de fin de ligne ;
# - longueur minimale 43 caractères (matériau ≥ 256 bits si canonique) ;
# - au moins 16 caractères distincts (refuse « a » * 43, « abcdefghijkl » * 4) ;
# - aucune période répétitive (« abab… », « 0123456789… », blocs répétés) ;
# - aucune suite monotone de 8+ (« abcdefgh… », « 0123456789… », « ZYXW… ») ;
# - aucune ligne de clavier connue QWERTY/AZERTY/QWERTZ (deux sens, casse) ;
# Ce contrôle ne mesure PAS l'entropie : il n'exclut que les motifs triviaux.
# EXIGENCE OPÉRATEUR : toute clé DOIT provenir de `generate_api_key()`.
# Un contournement manuel reste une faute opérationnelle, même sans motif trivial.
MIN_API_KEY_LENGTH: int = 43
MIN_API_KEY_DISTINCT_CHARS: int = 16
API_KEY_ALPHABET_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]+$")

# Format des identifiants de clé interne (jamais un secret, mais validé avant
# tout affichage ou mise à jour : un identifiant refusé n'est jamais réfléchi).
KEY_ID_PATTERN: re.Pattern[str] = re.compile(r"^key_[0-9a-f]{32}$")

# Identifiant de projet : même motif que le `ProjectId` du contrat (#15).
PROJECT_ID_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_-]{0,63}(?![\s\S])")

# Type contraint de l'identifiant de projet : source unique du motif, partagée
# par les routes du Vault et par la dépendance d'accès au projet (#64). Un
# identifiant hors contrat est refusé en 400 (bad_request) AVANT toute
# décision d'autorisation.
ProjectId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=PROJECT_ID_PATTERN,
    ),
]

# Aligné sur `crypto._MIN_PEPPER_BYTES` : défense en profondeur si les
# empreintes stockées et le pepper fuient (résistance hors ligne).
MIN_API_KEY_PEPPER_BYTES: int = 32

# Valeur publique de développement héritée : refusée hors tests explicites pour
# empêcher tout déploiement partagé avec un pepper commité dans le dépôt.
INSECURE_DEFAULT_PEPPER: str = "heimdall_default_vault_pepper_dev_only"
TEST_ENV_MODES: frozenset[str] = frozenset({"test"})
PRODUCTION_ENV_MODES: frozenset[str] = frozenset({"production", "prod"})


def heimdall_env_mode() -> str:
    """Retourne le mode d'environnement Heimdall normalisé (``HEIMDALL_ENV``)."""
    return os.environ.get("HEIMDALL_ENV", "").strip().lower()


def _unauthorized() -> StarletteHTTPException:
    """Construit le refus 401 générique (jamais d'écho de la clé reçue)."""
    return StarletteHTTPException(status_code=401, detail="Authentification requise")


def _forbidden() -> StarletteHTTPException:
    """Construit le refus 403 générique (clé valide, projet non autorisé)."""
    return StarletteHTTPException(status_code=403, detail="Accès interdit")


# ---------------------------------------------------------------------------
# Génération, hachage et validation
# ---------------------------------------------------------------------------


def generate_project_api_key() -> str:
    """Génère une clé API de projet à au moins 256 bits d'entropie (#64).

    Conformité openapi.yaml:190-193 : ``secrets.token_urlsafe(32)``, jamais
    dérivée de données prédictibles (identifiant, horodatage, compteur). La clé
    retournée n'est jamais stockée ni journalisée : seul son haché l'est.
    """
    return generate_api_key()


def hash_project_api_key(raw_key: str, pepper: str | bytes) -> str:
    """Hachage HMAC-SHA256 de vérification d'une clé API avec pepper serveur (#64).

    Conformité openapi.yaml:197-200 : le serveur DOIT stocker uniquement un
    haché salé de vérification (sel unique par clé, ou HMAC avec un pepper
    serveur distinct de la KEK de chiffrement), jamais sa valeur brute.

    Le pepper est obligatoire, doit comporter au moins 32 octets et n'a aucune
    valeur par défaut : un appel sans pepper lève ``ValueError`` au lieu de
    produire une empreinte portable et corrélable entre déploiements. Une clé
    non encodable en UTF-8 (surrogate isolé) est refusée par une erreur
    générique, sans écho de la valeur reçue.
    """
    return hash_api_key(raw_key, pepper)


def validate_api_key_pepper(value: str | None) -> str | None:
    """Valide le pepper serveur : jamais vide, jamais trop court, jamais public.

    La valeur ``heimdall_default_vault_pepper_dev_only`` est une constante
    publique du dépôt : l'accepter reviendrait à un simple hash salé public,
    corrélable entre déploiements. Elle n'est tolérée que sous
    ``HEIMDALL_ENV=test`` explicite (fixtures déterministes).

    Le refus est fail-closed : toute anomalie lève ``ValueError`` sans jamais
    reproduire la valeur reçue dans le message.
    """
    if value is None:
        return None
    if value != value.strip():
        raise ValueError(
            "Le pepper serveur ne doit pas comporter d'espaces de début ou de fin."
        )
    if not value:
        raise ValueError("Le pepper serveur ne peut pas être vide ou blanc.")
    try:
        pepper_bytes = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Le pepper serveur doit être encodable en UTF-8.") from None
    if len(pepper_bytes) < MIN_API_KEY_PEPPER_BYTES:
        raise ValueError(
            "Le pepper serveur doit comporter au moins "
            f"{MIN_API_KEY_PEPPER_BYTES} octets (256 bits) : un secret court "
            "réduit la résistance hors ligne des empreintes de clés API."
        )
    if value == INSECURE_DEFAULT_PEPPER and heimdall_env_mode() not in TEST_ENV_MODES:
        raise ValueError(
            "Le pepper public de développement 'heimdall_default_vault_pepper_dev_only' "
            "est refusé (valeur commitée partagée). Définissez "
            "HEIMDALL_VAULT_API_KEY_PEPPER avec un secret unique et aléatoire ; "
            "seul HEIMDALL_ENV=test explicite l'autorise pour des fixtures déterministes."
        )
    return value


def require_explicit_pepper(value: str | None) -> str:
    """Exige un pepper serveur explicite et persistant (CLI d'émission).

    Un pepper éphémère (généré au démarrage hors production) rendrait la clé
    inutilisable : le serveur redémarré ne retrouverait plus l'empreinte. La CLI
    refuse donc explicitement l'absence de pepper au lieu d'émettre une clé
    morte (fail-closed).
    """
    if value is None or not value.strip():
        raise ValueError(
            "HEIMDALL_VAULT_API_KEY_PEPPER est obligatoire pour émettre une clé "
            "API : un pepper éphémère ne survivrait pas au redémarrage du serveur."
        )
    validated = validate_api_key_pepper(value)
    if validated is None:  # pragma: no cover - garde de type, `value` n'est pas None
        raise ValueError("Le pepper serveur est obligatoire.")
    return validated


def _minimal_pattern_period(value: str) -> int:
    """Retourne la plus courte période répétée d'une chaîne (sa longueur si aucune).

    Exemple : « abcdefghijkl » * 4 → 12, « ababab… » → 2, une chaîne sans
    motif répété → sa longueur. Complexité O(n²) bornée par la longueur
    maximale de clé (512) : l'appel est réservé à l'enregistrement.
    """
    length = len(value)
    for period in range(1, length // 2 + 1):
        if all(value[index] == value[index % period] for index in range(length)):
            return period
    return length


_MIN_MONOTONIC_RUN_LENGTH: int = 8

# Séquences de clavier connues (lignes complètes QWERTY/AZERTY/QWERTZ dans
# les deux sens + préfixes célèbres) : devinables même avec 16+ distincts,
# sans période répétitive ni suite monotone (ex. « qwertyuiop » n'est pas
# ordinalement monotone). Comparaison insensible à la casse, fenêtre 8
# (ligne entière si la ligne est plus courte) : un token aléatoire 256 bits
# contient une telle sous-séquence avec une probabilité négligeable, un motif
# humain l'y place systématiquement. Chiffres et alphabet séquentiels sont
# déjà couverts par le contrôle monotone ; ici seules les lignes de clavier.
_KEYBOARD_SEQUENCES: tuple[str, ...] = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn",
    "qwertzuiop",
    "yxcvbnm",
    "qwerty",
    "azerty",
    "qwertz",
)
_KEYBOARD_SEQUENCES += tuple(seq[::-1] for seq in _KEYBOARD_SEQUENCES)
_MIN_KEYBOARD_RUN_LENGTH: int = 8


def _has_known_keyboard_run(value: str) -> bool:
    """Détecte une ligne de clavier connue (insensible à la casse).

    Fenêtre 8 (ou ligne entière si plus courte) : toute sous-séquence de
    8 d'une ligne connue — ou une ligne courte entière — présente dans la
    clé en minuscules déclenche le refus. O(n·m) borné (512 caractères,
    ~22 séquences) : appel réservé à l'enregistrement.
    """
    lowered = value.lower()
    for seq in _KEYBOARD_SEQUENCES:
        window = min(len(seq), _MIN_KEYBOARD_RUN_LENGTH)
        for start in range(len(seq) - window + 1):
            if seq[start : start + window] in lowered:
                return True
    return False


def _has_long_monotonic_run(value: str, min_run: int = _MIN_MONOTONIC_RUN_LENGTH) -> bool:
    """Détecte une suite monotone (croissante/décroissante, pas de ±1) de ``min_run``+.

    Cible les motifs séquentiels prévisibles (``abcdefgh…``, ``0123456789…``,
    ``ZYXW…``) qu'aucun des quatre contrôles précédents ne voit : alphabet
    valide, longueur et diversité suffisantes, aucune période répétitive.
    Seuil 8 : une suite de 8 sur token aléatoire 256 bits est négligeable
    (≈ 43 × 64⁻⁷), un motif humain séquentiel l'atteint systématiquement.
    Complexité O(n) bornée par 512 (appel réservé à l'enregistrement).
    """
    run = 1
    last_step = 0
    for prev, cur in zip(value, value[1:], strict=False):
        step = ord(cur) - ord(prev)
        if step in (1, -1) and step == last_step:
            run += 1
        elif step in (1, -1):
            run = 2
        else:
            run = 1
        last_step = step if step in (1, -1) else 0
        if run >= min_run:
            return True
    return False


def validate_raw_api_key(raw_key: str) -> str:
    """Valide une clé opérateur brute avant hachage (fail-fast, sans écho).

    Les clés DOIVENT être générées par ``generate_project_api_key()``
    (``secrets.token_urlsafe(32)``, 256 bits, 43 caractères) ou offrir une
    diversité équivalente. La longueur seule ne suffit pas : ``"a" * 43``
    serait brute-forçable hors ligne si la base d'empreintes et le pepper
    fuyaient. Six contrôles cumulatifs refusent les motifs triviaux :
    alphabet base64url strict, longueur ≥ 43, ≥ 16 caractères distincts,
    absence de période répétitive (la clé ne peut pas être la répétition d'un
    bloc plus court : « abcdefghijkl » * 4 et « abcdefghijklmnop » * 3 sont
    désormais refusés), absence de suite monotone de 8+ caractères
    (``abcdefgh…``, ``0123456789…`` : devinables même avec 16+ distincts,
    sans période répétitive) et absence de ligne de clavier connue
    (``qwertyuiop…``, ``azerty…`` : ni monotone ni répétitive, mais
    devinable). Le message reste générique et ne reflète jamais
    la clé. Ce contrôle reste un filtre de motifs triviaux, PAS une mesure
    d'entropie. EXIGENCE OPÉRATEUR (#64) : toute clé DOIT provenir de
    ``generate_api_key()`` (256 bits aléatoires) ; un contournement manuel —
    même passant les six contrôles — est une faute opérationnelle, car en cas
    de fuite des empreintes et du pepper, seul un token aléatoire résiste au
    brute-force hors ligne.
    """
    if (
        not isinstance(raw_key, str)
        or not MIN_API_KEY_LENGTH <= len(raw_key) <= MAX_API_KEY_LENGTH
        or raw_key != raw_key.strip()
    ):
        raise ValueError(
            "La clé API brute doit comporter entre "
            f"{MIN_API_KEY_LENGTH} et {MAX_API_KEY_LENGTH} caractères, "
            "sans espaces de début ou de fin."
        )
    if API_KEY_ALPHABET_PATTERN.fullmatch(raw_key) is None:
        raise ValueError(
            "La clé API brute doit être un token base64url (A-Z, a-z, 0-9, "
            "« _ » et « - ») : ni espaces ni caractères de contrôle."
        )
    if len(set(raw_key)) < MIN_API_KEY_DISTINCT_CHARS:
        raise ValueError(
            "La clé API brute est trop peu diverse : utiliser generate_api_key() "
            "ou une clé aléatoire d'au moins 256 bits (motif trivial refusé)."
        )
    if _minimal_pattern_period(raw_key) != len(raw_key):
        raise ValueError(
            "La clé API brute repose sur un motif répétitif : utiliser "
            "generate_api_key() ou une clé aléatoire d'au moins 256 bits "
            "(motif trivial refusé)."
        )
    if _has_long_monotonic_run(raw_key):
        raise ValueError(
            "La clé API brute repose sur une suite prévisible : utiliser "
            "generate_api_key() ou une clé aléatoire d'au moins 256 bits "
            "(motif trivial refusé)."
        )
    if _has_known_keyboard_run(raw_key):
        raise ValueError(
            "La clé API brute repose sur une séquence de clavier prévisible : "
            "utiliser generate_api_key() ou une clé aléatoire d'au moins "
            "256 bits (motif trivial refusé)."
        )
    return raw_key


def validate_key_id(key_id: str) -> str:
    """Valide un identifiant interne de clé API (format strict, sans écho).

    L'identifiant n'est pas un secret, mais il est affiché par la CLI et
    utilisé dans des requêtes : un format hors contrat est refusé avant tout
    usage, pour ne jamais réfléchir une entrée arbitraire dans la sortie.
    ``fullmatch`` est obligatoire : avec ``match`` et un motif ancré par ``$``,
    ``key_<32hex>\\n`` passerait avant l'écho CLI (injection de retour ligne).
    """
    if not isinstance(key_id, str) or KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise ValueError(
            "Identifiant de clé API invalide : attendu key_<32 caractères hexadécimaux>."
        )
    return key_id


def validate_project_id(project_id: str) -> str:
    """Valide l'identifiant de projet lié à une clé API (fail-fast sans écho).

    Un identifiant hors ``PROJECT_ID_PATTERN`` (ex. ``"../.."``, casse invalide,
    typo) ne matcherait jamais un ``ProjectId`` de requête : la clé serait
    acceptée puis refusée silencieusement en 403 à chaque appel. On refuse donc
    à l'enregistrement. Le message est générique et ne reflète jamais la valeur
    fournie.
    """
    if not isinstance(project_id, str) or PROJECT_ID_PATTERN.match(project_id) is None:
        raise ValueError(
            "Identifiant de projet invalide : attendu ^[a-z][a-z0-9_-]{0,63}$. "
            "La clé API doit être liée à un identifiant de projet conforme au contrat."
        )
    return project_id


# ---------------------------------------------------------------------------
# Registre des clés API de projet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IssuedApiKey:
    """Clé API émise : la valeur brute est renvoyée UNE SEULE fois à l'appelant.

    ``repr`` est expurgé : l'objet ne doit jamais laisser la clé fuiter dans un
    journal, une trace ou un rapport d'erreur.
    """

    key_id: str
    project_id: str
    raw_key: str
    created_at: str

    def __repr__(self) -> str:
        return (
            f"IssuedApiKey(key_id={self.key_id!r}, project_id={self.project_id!r}, "
            "raw_key=<REDACTED>)"
        )


@dataclass
class ApiKeyEntry:
    """Métadonnées d'une clé API enregistrée (jamais la clé brute)."""

    key_id: str
    project_id: str
    key_hash: str
    created_at: str
    revoked_at: str | None = None


class ApiKeyRegistry:
    """Registre des clés API de projet : empreintes, persistance, révocation.

    Le registre est la source de vérité du cycle de vie des clés :

    - ``register`` / ``register_hash`` : enregistre une clé (brute ou déjà
      hachée) et n persiste QUE son empreinte ;
    - ``issue`` : émet une clé neuve (≥ 256 bits) et la rend une seule fois ;
    - ``revoke`` : révoque une clé (elle cesse d'authentifier immédiatement) ;
    - ``active_hashes`` : instantané ``{empreinte: projet}`` des clés actives,
      lu par le chemin de requête (mode mémoire).

    Verrous : ``lock`` protège l'instantané lu par les requêtes, ``persist_lock``
    sérialise les écritures. L'E/S SQLite n'est jamais tenue sous le verrou
    d'instantané : le parcours exhaustif d'authentification reste servi pendant
    un enregistrement.
    """

    def __init__(
        self,
        *,
        pepper: str,
        storage_backend: str = "memory",
        db_path: Path | None = None,
    ) -> None:
        self._pepper = pepper
        self._storage_backend = storage_backend
        self._db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._lock = Lock()
        self._persist_lock = Lock()
        self._entries: dict[str, ApiKeyEntry] = {}
        self._active: dict[str, str] = {}

    def __repr__(self) -> str:
        """Représentation expurgée : le pepper n'apparaît jamais dans un log."""
        return (
            f"ApiKeyRegistry(storage_backend={self._storage_backend!r}, "
            "pepper=<REDACTED>)"
        )

    # -- Introspection (aucune clé brute n'est exposée) --------------------

    @property
    def pepper(self) -> str:
        """Pepper serveur utilisé pour les empreintes (jamais journalisé)."""
        return self._pepper

    @property
    def storage_backend(self) -> str:
        """Backend de stockage du registre (``memory`` ou ``sqlite``)."""
        return self._storage_backend

    @property
    def db_path(self) -> Path | None:
        """Chemin de la base SQLite du registre (``None`` en mode mémoire)."""
        return self._db_path

    @property
    def lock(self) -> Lock:
        """Verrou de l'instantané lu par le chemin de requête."""
        return self._lock

    @property
    def persist_lock(self) -> Lock:
        """Verrou sérialisant les écritures du registre."""
        return self._persist_lock

    @property
    def active_hashes(self) -> dict[str, str]:
        """Instantané ``{empreinte: projet}`` des clés actives (mode mémoire)."""
        return self._active

    # -- Enregistrement ----------------------------------------------------

    def register(self, raw_key: str, project_id: str) -> str:
        """Enregistre une clé API brute et retourne son identifiant.

        La clé brute n'est ni conservée ni journalisée : seule son empreinte
        (HMAC-SHA256 + pepper) est mémorisée. Les motifs triviaux sont refusés
        fail-closed (voir ``validate_raw_api_key``) et l'identifiant de projet
        est validé contre le motif du contrat.
        """
        raw_key = validate_raw_api_key(raw_key)
        key_hash = hash_project_api_key(raw_key, pepper=self._require_pepper())
        return self.register_hash(key_hash, project_id)

    def register_hash(self, key_hash: str, project_id: str) -> str:
        """Enregistre une empreinte déjà calculée (amorçage opérateur).

        L'empreinte doit être un HMAC-SHA256 hexadécimal de 64 caractères : une
        clé brute y est refusée, avec un message qui ne la reflète jamais.
        Réenregistrer la même clé pour le même projet est idempotent et ne
        réactive PAS une clé révoquée ; la lier à un autre projet échoue.
        """
        if not isinstance(key_hash, str) or not HASH_PATTERN.fullmatch(key_hash):
            raise ValueError(
                "Format d'empreinte de clé API invalide : attendu ^[0-9a-f]{64}$. "
                "api_key_hashes attend des empreintes hexadécimales de 64 caractères. "
                "Pour enregistrer une clé brute, utilisez "
                "app.state.register_api_key(raw_key, project_id)."
            )
        self._require_pepper()
        project_id = validate_project_id(project_id)
        with self._persist_lock:
            with self._lock:
                existing_id = self._entry_id_for_hash(key_hash)
                if existing_id is not None:
                    entry = self._entries[existing_id]
                    if entry.project_id != project_id:
                        raise ValueError("Cette clé API est déjà associée à un autre projet.")
                    # Idempotence : ne pas réactiver une clé révoquée.
                    return existing_id
            key_id = f"key_{uuid4().hex}"
            created_at = get_iso_timestamp()
            effective_id, revoked = self._persist_hash(key_id, key_hash, project_id, created_at)
            with self._lock:
                self._entries[effective_id] = ApiKeyEntry(
                    key_id=effective_id,
                    project_id=project_id,
                    key_hash=key_hash,
                    created_at=created_at,
                    revoked_at=created_at if revoked else None,
                )
                if not revoked:
                    self._active[key_hash] = project_id
            logger.debug("Clé API enregistrée pour le projet %s.", project_id)
            return effective_id

    def issue(self, project_id: str) -> IssuedApiKey:
        """Émet une clé API neuve pour un projet et la rend UNE SEULE FOIS.

        La clé brute est retournée à l'appelant (affichage unique à la
        création) et n'est jamais conservée : le registre ne connaît que son
        empreinte.
        """
        project_id = validate_project_id(project_id)
        self._require_pepper()
        raw_key = generate_project_api_key()
        key_id = self.register(raw_key, project_id)
        with self._lock:
            entry = self._entries.get(key_id)
        created_at = entry.created_at if entry is not None else get_iso_timestamp()
        return IssuedApiKey(
            key_id=key_id,
            project_id=project_id,
            raw_key=raw_key,
            created_at=created_at,
        )

    def revoke(self, key_id: str) -> bool:
        """Révoque une clé API : elle cesse d'authentifier immédiatement.

        En backend SQLite la base est la source de vérité : la révocation y est
        persistée avant d'être répercutée sur l'instantané mémoire. Une clé
        déjà révoquée ou inconnue renvoie ``False`` (idempotence).
        """
        with self._persist_lock:
            if self._storage_backend == "sqlite" and self._db_path is not None:
                with db_session(self._db_path) as conn:
                    if not revoke_api_key(conn, key_id):
                        return False
            else:
                with self._lock:
                    entry = self._entries.get(key_id)
                    if entry is None or entry.revoked_at is not None:
                        return False
            with self._lock:
                entry = self._entries.get(key_id)
                if entry is not None and entry.revoked_at is None:
                    entry.revoked_at = get_iso_timestamp()
                    self._active.pop(entry.key_hash, None)
            logger.debug("Clé API révoquée (%s).", key_id)
            return True

    def list_entries(self, project_id: str | None = None) -> list[ApiKeyEntry]:
        """Retourne les métadonnées des clés enregistrées (jamais la clé brute)."""
        with self._lock:
            entries = [
                entry
                for entry in self._entries.values()
                if project_id is None or entry.project_id == project_id
            ]
        return sorted(entries, key=lambda entry: entry.created_at)

    # -- Internes ----------------------------------------------------------

    def _require_pepper(self) -> str:
        """Exige un pepper serveur non vide pour toute écriture (fail-closed).

        Un registre construit avec un pepper vide (par erreur, ou pour une
        simple révocation) ne doit jamais pouvoir enregistrer ni émettre une
        clé : l'empreinte serait calculée sans sel serveur, donc corrélable
        entre déploiements.
        """
        if not isinstance(self._pepper, str) or not self._pepper.strip():
            raise ValueError(
                "Pepper serveur obligatoire pour enregistrer ou émettre une clé API."
            )
        return self._pepper

    def _entry_id_for_hash(self, key_hash: str) -> str | None:
        """Retourne l'identifiant de la clé correspondant à une empreinte."""
        for entry_id, entry in self._entries.items():
            if entry.key_hash == key_hash:
                return entry_id
        return None

    def _persist_hash(
        self,
        key_id: str,
        key_hash: str,
        project_id: str,
        created_at: str,
    ) -> tuple[str, bool]:
        """Persiste l'empreinte dans SQLite et retourne ``(identifiant, révoquée)``.

        L'insertion est idempotente (``ON CONFLICT(key_hash) DO NOTHING``) puis
        le projet lié est relu : une clé déjà enregistrée pour un autre projet
        est refusée sans rien modifier. Une clé déjà RÉVOQUÉE conserve son
        état : la ré-enregistrer ne la réactive pas (openapi.yaml:203-204).
        """
        if self._storage_backend != "sqlite" or self._db_path is None:
            return key_id, False
        with db_session(self._db_path) as conn:
            ensure_project(conn, project_id)
            conn.execute(
                "INSERT INTO api_keys (id, project_id, key_hash, created_at, revoked_at) "
                "VALUES (?, ?, ?, ?, NULL) ON CONFLICT(key_hash) DO NOTHING",
                (key_id, project_id, key_hash, created_at),
            )
            row = conn.execute(
                "SELECT id, project_id, revoked_at FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
        if row is None or row["project_id"] != project_id:
            raise ValueError("Cette clé API est déjà associée à un autre projet.")
        return str(row["id"]), bool(row["revoked_at"])


# ---------------------------------------------------------------------------
# Recherche des empreintes (coût comparable, sans oracle temporel)
# ---------------------------------------------------------------------------


def lookup_db_api_key(db_path: Any, provided_hash: str) -> tuple[str | None, int]:
    """Recherche la clé API en base SQLite à coût comparable et sans oracle temporel.

    Le parcours est exhaustif (pas de sortie précoce) et chaque empreinte est
    comparée en temps constant : le coût est le même que la clé soit connue,
    inconnue ou révoquée. Une clé révoquée n'est jamais retenue.
    """
    if not (isinstance(db_path, Path) and db_path.is_file()):
        raise DatabaseUnavailableError("Stockage temporairement indisponible.")
    matching_project: str | None = None
    evaluated = 0
    with db_session(db_path) as conn:
        cursor = conn.execute("SELECT project_id, key_hash, revoked_at FROM api_keys")
        for row in cursor.fetchall():
            evaluated += 1
            if constant_time_equal(provided_hash, row["key_hash"]):
                if not row["revoked_at"]:
                    matching_project = row["project_id"]
    return matching_project, evaluated


def find_api_key_project(app: Any, provided_hash: str) -> tuple[str | None, int]:
    """Recherche le projet d'une empreinte de clé API à coût comparable.

    Parcours complet des empreintes de la source autoritaire (mémoire en mode
    ``memory``, base seule en mode ``sqlite``), sans ``break`` précoce et avec
    ``constant_time_equal`` pour chaque candidat : le coût est le même que
    l'empreinte soit connue, inconnue ou révoquée. Ce parcours est partagé par
    l'authentification (``verify_api_key``) et par le choix du bucket de débit
    (lot #63) : l'existence d'une clé n'est pas observable par le temps de
    réponse du middleware.

    Retourne ``(project_id ou None, nombre d'empreintes évaluées)``.
    """
    registry = getattr(getattr(app, "state", None), "api_key_registry", None)
    if registry is None:
        return None, 0
    if registry.storage_backend == "sqlite":
        # SQLite est l'unique autorité : révocation, suppression ou erreur DB
        # ne doivent jamais retomber sur une ancienne entrée en mémoire.
        # La lecture passe par la MÊME référence que l'écriture
        # (``registry.db_path``, utilisé par ``_persist_hash`` et ``revoke``) :
        # lire ``app.state.db_path`` pouvait viser un autre fichier que celui
        # où la clé est enregistrée (store explicite sur un autre chemin).
        return lookup_db_api_key(registry.db_path, provided_hash)
    matching_project: str | None = None
    evaluated = 0
    with registry.lock:
        registered_keys = tuple(registry.active_hashes.items())
    for reg_hash, proj_id in registered_keys:
        evaluated += 1
        if constant_time_equal(provided_hash, reg_hash):
            matching_project = proj_id
    return matching_project, evaluated


async def find_api_key_project_cached(
    request: Request, provided_hash: str
) -> tuple[str | None, int]:
    """Parcours complet d'empreintes mémoïsé dans la requête (anti-amplification CPU).

    Le middleware de débit effectue déjà le parcours complet du backend actif
    (sans ``break``) pour choisir le bucket ; l'authentification réutilise ce
    résultat au lieu de refaire le même full-scan + ``compare_digest`` par
    candidat (2 parcours -> 1 par requête, lot #63). La mémoïsation vit dans
    l'état de la requête (``request.state``) : jamais partagée entre requêtes,
    aucune empreinte persistée hors du scope courant. Le coût reste identique
    entre clé connue/inconnue/révoquée : le premier parcours est exhaustif et
    seul l'appel redondant est évité.
    """
    cached_hash: str | None = getattr(request.state, "api_key_lookup_hash", None)
    if cached_hash is not None and constant_time_equal(cached_hash, provided_hash):
        return (
            getattr(request.state, "api_key_lookup_project", None),
            getattr(request.state, "api_key_lookup_evaluated", 0),
        )
    matching_project, evaluated_count = await asyncio.to_thread(
        find_api_key_project, request.app, provided_hash
    )
    request.state.api_key_lookup_hash = provided_hash
    request.state.api_key_lookup_project = matching_project
    request.state.api_key_lookup_evaluated = evaluated_count
    return matching_project, evaluated_count


# ---------------------------------------------------------------------------
# Dépendances FastAPI
# ---------------------------------------------------------------------------


def _registry(request: Request) -> ApiKeyRegistry | None:
    """Retourne le registre de l'application (``None`` si absent)."""
    state = getattr(request.app, "state", None)
    registry = getattr(state, "api_key_registry", None)
    return registry if isinstance(registry, ApiKeyRegistry) else None


def _require_auth(request: Request) -> bool:
    """Indique si l'authentification est exigée (fail-closed par défaut)."""
    state = getattr(request.app, "state", None)
    settings = getattr(state, "settings", None)
    if settings is None:
        return True
    return bool(getattr(settings, "require_auth", True))


async def verify_api_key(
    request: Request,
    api_key: Annotated[str | None, Depends(project_api_key_header)] = None,
) -> str | None:
    """Vérifie l'en-tête X-Heimdall-API-Key et retourne le projet lié à la clé.

    Conformité openapi.yaml:19-20, 197-204 :
    - fail-closed : authentification active par défaut (``require_auth=True``).
    - rejet en 401 sans normalisation si la clé comporte des espaces de début/fin.
    - hachage HMAC-SHA256 avec pepper serveur distinct de la KEK.
    - comparaison constante via ``constant_time_equal`` sur empreintes de même
      longueur.
    - chemin de vérification de coût comparable (aucun break précoce, comparaison
      factice), mémoïsé par requête : le parcours complet du middleware de débit
      est réutilisé (``find_api_key_project_cached``), un seul full-scan par
      requête (lot #63).
    - si ``settings.require_auth=False`` et aucune clé fournie, retourne None
      (mode test isolé).

    La clé reçue n'est jamais journalisée ni répétée dans le message d'erreur :
    le refus est un 401 générique, identique pour une clé absente, inconnue,
    révoquée ou invalide.
    """
    if api_key is None:
        if _require_auth(request):
            raise _unauthorized()
        return None

    if len(api_key) > MAX_API_KEY_LENGTH or api_key != api_key.strip() or not api_key:
        raise _unauthorized()

    registry = _registry(request)
    if registry is None:
        # Fail-closed : sans registre, aucune authentification n'est possible.
        raise _unauthorized()

    try:
        provided_hash = hash_project_api_key(api_key, pepper=registry.pepper)
    except ValueError:
        # Encodage impossible (ex. surrogate isolé) : 401 générique, jamais 500
        # ni écho de la valeur fournie.
        raise _unauthorized() from None

    matching_project, evaluated_count = await find_api_key_project_cached(request, provided_hash)

    # Coût comparable : comparaison factice si aucune clé n'a été évaluée
    if evaluated_count == 0:
        constant_time_equal(provided_hash, DUMMY_HASH)

    if matching_project is None:
        raise _unauthorized()

    return matching_project


def ensure_project_access(
    authenticated_project: str | None,
    requested_project: str,
    *,
    require_auth: bool = True,
) -> None:
    """Vérifie qu'une clé authentifiée appartient bien au projet demandé.

    401 si l'authentification est exigée mais absente, 403 si la clé est valide
    pour un AUTRE projet : l'autorisation est tranchée avant toute recherche de
    ressource, donc l'existence d'un secret n'est jamais révélée à une clé
    étrangère.
    """
    if require_auth and authenticated_project is None:
        raise _unauthorized()
    if authenticated_project is not None and authenticated_project != requested_project:
        raise _forbidden()


def require_project_access() -> Callable[..., Awaitable[str | None]]:
    """Fabrique la dépendance FastAPI qui contrôle l'accès au projet demandé.

    La dépendance lit l'en-tête ``X-Heimdall-API-Key``, retrouve la clé, puis
    vérifie qu'elle appartient AU projet demandé par la route (paramètre de
    chemin ``project``) :

    - clé absente, inconnue, révoquée ou invalide -> 401 générique ;
    - clé valide d'un autre projet -> 403.

    Elle s'utilise sur les routes paramétrées par un projet :
    ``dependencies=[Depends(require_project_access())]``.
    """

    async def dependency(
        project: Annotated[
            ProjectId,
            PathParam(description="Identifiant public du projet ; aucune valeur secrète."),
        ],
        request: Request,
        authenticated_project: Annotated[str | None, Depends(verify_api_key)] = None,
    ) -> str | None:
        ensure_project_access(
            authenticated_project,
            project,
            require_auth=_require_auth(request),
        )
        return authenticated_project

    return dependency


# ---------------------------------------------------------------------------
# Opérations d'administration (CLI `heimdall vault key`)
# ---------------------------------------------------------------------------


def issue_api_key(db_path: Path, project_id: str, pepper: str) -> IssuedApiKey:
    """Émet une clé API de projet et ne persiste que son empreinte (#64).

    Utilisé par la CLI `heimdall vault key create` : la clé brute est retournée
    à l'appelant qui l'affiche UNE SEULE FOIS, jamais journalisée ni stockée.
    """
    registry = ApiKeyRegistry(pepper=pepper, storage_backend="sqlite", db_path=db_path)
    return registry.issue(project_id)


def list_registered_keys(db_path: Path, project_id: str | None = None) -> list[dict[str, Any]]:
    """Retourne les métadonnées des clés API enregistrées.

    Ni la clé brute ni son empreinte ne sont retournées : seules l'identifiant,
    le projet, la date de création et l'éventuelle révocation sont exposées.

    Un filtre de projet hors contrat est refusé (fail-fast) : un simple
    « aucune clé » masquerait une coquille de configuration opérateur.
    """
    if project_id is not None:
        project_id = validate_project_id(project_id)
    with db_session(db_path) as conn:
        rows = conn.execute(
            "SELECT id, project_id, created_at, revoked_at FROM api_keys ORDER BY created_at ASC"
        ).fetchall()
    return [
        dict(row)
        for row in rows
        if project_id is None or row["project_id"] == project_id
    ]


def revoke_registered_key(db_path: Path, key_id: str) -> bool:
    """Révoque une clé API enregistrée (identifiant connu de l'opérateur).

    L'identifiant est validé avant usage ; la révocation est persistée dans la
    base, qui reste la source de vérité : la clé cesse d'authentifier
    immédiatement, y compris pour un serveur déjà démarré.

    Cette opération ne construit pas d'``ApiKeyRegistry`` : elle n'émet ni ne
    vérifie aucune empreinte, donc n'a pas besoin de pepper. Un registre
    « révocation seule » avec un pepper vide serait réutilisable par erreur
    pour ``register``/``issue`` et produirait des empreintes faibles ; l'accès
    direct à la base supprime cette surface.
    """
    validate_key_id(key_id)
    with db_session(db_path) as conn:
        return revoke_api_key(conn, key_id)


__all__ = [
    "API_KEY_HEADER_NAME",
    "ProjectId",
    "validate_key_id",
    "ApiKeyEntry",
    "ApiKeyRegistry",
    "IssuedApiKey",
    "ensure_project_access",
    "find_api_key_project",
    "find_api_key_project_cached",
    "generate_project_api_key",
    "hash_project_api_key",
    "heimdall_env_mode",
    "issue_api_key",
    "list_registered_keys",
    "lookup_db_api_key",
    "project_api_key_header",
    "require_explicit_pepper",
    "require_project_access",
    "revoke_registered_key",
    "validate_api_key_pepper",
    "validate_project_id",
    "validate_raw_api_key",
    "verify_api_key",
]
