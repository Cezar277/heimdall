"""Client Ollama de qualification — T28.2 (#80).

Envoie au modèle local (``gemma3:270m``, ADR-004) un candidat **déjà
masqué** (``<REDACTED:type:len=N>``, produit par le serveur MCP #27) et
force une réponse vérifiable automatiquement :

- prompt système versionné, chargé depuis
  ``heimdall/mcp/prompts/qualify_v1.md`` (jamais de code scanné dedans ; le
  candidat n'apparaît que dans le message utilisateur, entre délimiteurs
  aléatoires par requête — REQ-SEC-01) ;
- le paramètre ``format`` d'``ollama.chat`` reçoit le schéma JSON
  (``QUALIFY_FORMAT_V1``) : la sortie est structurée par le serveur Ollama,
  pas seulement décrite au modèle ; ``temperature`` vaut 0 ;
- la version du prompt (nom + SHA-256 de la chaîne exacte envoyée comme
  prompt système, lecture unique sans relecture fichier) est journalisée à
  chaque appel, et le verdict retenu à chaque succès : une décision reste
  corrélable à l'instruction qui l'a produite, sans secret ni prompt brut —
  un verdict hors enum n'est jamais recopié, seul ``invalide`` est tracé ;
- tout échec local est fermé : prompt de qualification illisible (fichier
  absent, encodage invalide) et candidat au-delà du plafond lèvent une
  ``QualifyError`` à code dédié, jamais une exception brute (un chemin
  dans un message d'erreur) ni un envoi tronquable ;
- la réponse du modèle est bornée (``MAX_RESPONSE_CHARS``) avant parsing :
  un serveur Ollama compromis ne peut pas faire exploser la CLI avec des
  Mo de JSON — refus ``QualifyError("invalid")`` fail-closed.

Client épinglé boucle locale : hôte figé ``http://127.0.0.1:11434``
(``OLLAMA_HOST`` ignoré), ``trust_env=False`` (aucun proxy de
l'environnement), redirections refusées — l'aller-retour Ollama ne peut pas
sortir de la machine (invariant 12).

Périmètre : « verdict validé » (``qualify``) puis « candidat fail-closed »
(``qualify_candidate``, T28.3 #81) : une sortie cassée laisse le candidat
détecté, avec son code de raison. L'affichage Y/N/E et la journalisation
du rejet par la CLI restent à #32 et #33. Le LLM reste consultatif : ce
module ne modifie aucun Finding et ne décide jamais seul (REQ-SEC-01).
"""

import copy
import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal

import ollama
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, ValidationError

from heimdall.mcp.prompts import (
    MAX_CANDIDATE_CHARS,
    PROMPT_NAME,
    QUALIFY_FORMAT_V1,
    CandidateTooLargeError,
    build_messages,
)

# Modèle par défaut : ADR-004 (292 Mo, seul panel à 10/10 secrets et 4/4
# injections bloquées, 0,72 s/requête CPU). Le nom reste validé avant appel.
DEFAULT_MODEL: Final[str] = "gemma3:270m"

# Boucle locale uniquement (invariant 12) : l'hôte est figé ici, jamais lu
# dans l'environnement (cf. _loopback_client).
OLLAMA_HOST: Final[str] = "http://127.0.0.1:11434"

# Délai borné : une panne Ollama devient une erreur explicite, jamais une
# attente infinie. Généreux pour le premier appel (chargement du modèle).
REQUEST_TIMEOUT: Final[float] = 60.0

# Nom de modèle accepté (même grammaire que le bench T28.1) : refus
# fail-closed avant tout appel pour un nom hors contrat.
_MODEL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9._:/-]{1,64}$")

# Options du protocole mesuré en ADR-004 : température nulle
# (reproductibilité), contexte et génération bornés. ``think`` désactivé et
# ``format`` contraint sont passés séparément dans l'appel.
_CHAT_OPTIONS: Final[dict[str, int]] = {"temperature": 0, "num_ctx": 1024, "num_predict": 120}

# Plafond de la réponse du modèle avant parsing : ``num_predict`` 120 ne
# borne qu'un serveur honnête — un serveur compromis (seul interlocuteur,
# mais non fiable selon l'invariant 2) renverrait des Mo de JSON et ferait
# exploser la CLI en mémoire/CPU. 8192 caractères couvrent ~60× une réponse
# réelle (objet ``{"verdict", "confidence"}`` < 150 caractères) : au-delà,
# refus ``invalid`` fail-closed, jamais de ``json.loads`` sans borne.
MAX_RESPONSE_CHARS: Final[int] = 8192

# Fonction de chat injectable (tests hors ligne) : signature de
# ``ollama.Client.chat``, seul canal vers le modèle.
ChatFn = Callable[..., Any]

ErrorCode = Literal["empty", "model", "unavailable", "invalid", "prompt", "too_large"]

Verdict = Literal["secret", "faux_positif", "incertain"]

# Messages statiques, un par code : aucune donnée reflétée (ni extrait, ni
# réponse du modèle, ni entrée) — un texte d'exception peut être relu et
# recopié, il ne doit jamais transporter de contenu non fiable.
ERROR_MESSAGES: Final[dict[ErrorCode, str]] = {
    "empty": "candidat vide : rien a qualifier",
    "model": "nom de modele hors contrat",
    "unavailable": "LLM local indisponible : verifier Ollama sur la boucle locale",
    "invalid": "reponse du LLM invalide : JSON objet attendu",
    "prompt": "prompt de qualification illisible : installation incomplete",
    "too_large": "candidat trop long : plafond du contrat de qualification depasse",
}

logger = logging.getLogger(__name__)


class QualifyVerdict(BaseModel):
    """Verdict strict du trieur — le seul objet que ``qualify()`` renvoie.

    Validation stricte du retour (T28.3, #81) : la grammaire ``format``
    d'Ollama ne contraint qu'un serveur honnête — ici, ``extra="forbid"``
    rejette tout champ bonus (``reason``, ``__proto__``… porteurs de
    consignes), ``verdict`` est l'enum exact (miroir de ``VERDICTS``,
    sensible à la casse) et ``confidence`` un nombre 0..1
    (``StrictFloat | StrictInt`` : l'entier ``1`` du modèle passe, le
    booléen ``True`` ne passe pas). Tout écart → ``ValidationError`` →
    ``QualifyError("invalid")``, jamais réparé ni complété. Un changement
    de verdicts ou de bornes = qualify_v2 (comme le schéma
    ``QUALIFY_FORMAT_V1``).
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: Annotated[StrictFloat | StrictInt, Field(ge=0, le=1)]


class QualifyError(Exception):
    """Échec fail-closed de la qualification, à message statique.

    Porte un code du registre fermé ``ERROR_MESSAGES``, et RIEN d'autre :
    ni contenu, ni réponse du modèle, ni entrée reflétée.
    """

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(ERROR_MESSAGES[code])
        self.code: ErrorCode = code
        self.message: str = ERROR_MESSAGES[code]


@dataclass(frozen=True)
class Qualification:
    """Avis du LLM sur un candidat : un signal, jamais une décision.

    ``status`` vaut toujours ``detecte`` : le LLM ne fait transiter aucun
    Finding (contrat #14, ADR-001). ``verdict`` est l'avis validé ;
    ``reason`` est le code fermé du refus, renseigné si et seulement si la
    sortie n'est pas retenue (``verdict`` vaut alors ``None``).
    """

    status: Literal["detecte"]
    verdict: Verdict | None
    reason: ErrorCode | None

    def __post_init__(self) -> None:
        # Corrélation imposée par le type, pas seulement promise par le
        # docstring : soit un avis retenu (verdict seul), soit un refus
        # motivé (raison seule). Un état ambigu (les deux ou aucun)
        # lèverait chez l'appelant une interprétation « retirer le finding ».
        if (self.verdict is None) == (self.reason is None):
            raise ValueError("etat incoherent : verdict xor reason")


def _loopback_client() -> ollama.Client:
    """Client Ollama verrouillé sur la boucle locale.

    Trois verrous, pour que rien dans l'environnement ne puisse rediriger
    l'appel hors machine :

    - hôte **figé** : ``OLLAMA_HOST`` de l'environnement est ignoré ;
    - ``trust_env=False`` : ni proxy ni ``.netrc`` de l'environnement ;
    - ``follow_redirects=False`` : une redirection échoue (fail-closed) au
      lieu d'être suivie.

    Le délai est borné : une panne devient une ``QualifyError`` explicite.
    """
    return ollama.Client(
        host=OLLAMA_HOST,
        trust_env=False,
        follow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )


def _reject_non_json_constant(value: str) -> Any:
    """Refuse ``NaN``/``Infinity`` (extension Python, hors JSON strict).

    ``json.loads`` les accepte par défaut (``allow_nan``) : un ``nan``
    passerait tout ``isinstance(x, float)`` futur tout en rendant fausse
    toute comparaison de confiance — tri indéfini chez l'appelant. Levée
    en ``ValueError`` pour retomber dans le refus fermé ``invalid``.
    """
    raise ValueError(f"constante non-JSON refusee : {value}")


def qualify(
    candidate: str,
    *,
    model: str = DEFAULT_MODEL,
    chat: ChatFn | None = None,
) -> dict[str, Any]:
    """Qualifie un candidat masqué ; renvoie le verdict strictement validé.

    Le dict renvoyé n'est jamais l'objet brut du modèle : il a passé
    ``QualifyVerdict`` (enum exact, confiance 0..1, aucun champ bonus) —
    un retour non conforme lève ``QualifyError("invalid")``.

    ``chat`` s'injecte en test (aucun appel réel) ; par défaut, l'appel
    part vers le client Ollama épinglé boucle locale. Toute panne du
    transport ou du modèle devient ``QualifyError("unavailable")`` à
    message statique (jamais l'exception d'origine, qui peut recopier la
    requête). Une réponse non-JSON, vide, surdimensionnée, à constante
    non-JSON (``NaN``/``Infinity``) ou qui n'est pas un objet JSON est
    refusée en ``QualifyError("invalid")`` — jamais réparée ni complétée,
    y compris une réponse entourée de balises Markdown. Un prompt de
    qualification illisible devient
    ``QualifyError("prompt")`` et un candidat au-delà du plafond du contrat
    ``QualifyError("too_large")`` : jamais d'exception brute (chemin
    compris) ni d'envoi tronquable. Une entrée non-``str`` est un vide par
    erreur de programmation : ``QualifyError("empty")``.
    """
    if not isinstance(model, str) or not _MODEL_PATTERN.fullmatch(model):
        # Garde de type d'abord : fullmatch(None/bytes/objet) lèverait une
        # TypeError brute — même code fermé "model", jamais d'exception
        # avec traceback (symétrique du candidat non-str → "empty").
        raise QualifyError("model")
    if isinstance(candidate, str) and len(candidate) > MAX_CANDIDATE_CHARS:
        raise QualifyError("too_large")
    try:
        messages = build_messages(candidate)
        # Lecture unique : le digest est calculé sur la chaîne exacte
        # envoyée comme prompt système — jamais une seconde lecture
        # fichier qui pourrait diverger (remplacement entre deux lectures).
        digest = hashlib.sha256(messages[0]["content"].encode("utf-8")).hexdigest()
    except UnicodeDecodeError:
        # Prompt produit non décodable : installation cassée, même code
        # fermé que fichier absent (jamais d'exception brute avec chemin).
        raise QualifyError("prompt") from None
    except OSError:
        raise QualifyError("prompt") from None
    except CandidateTooLargeError:
        # Type distinct du vide (cf. prompts) : le pré-contrôle ci-dessus
        # couvre déjà ce cas, ce rattrapage ferme la voie aux appelants
        # directs de ``build_messages`` sans ambiguïté de code.
        raise QualifyError("too_large") from None
    except ValueError:
        raise QualifyError("empty") from None
    logger.info(
        "qualification: prompt=%s sha256=%s modele=%s",
        PROMPT_NAME,
        digest,
        model,
    )
    try:
        # Construction dans le bloc fail-closed : si _loopback_client()
        # levait (API ollama changée, config httpx invalide, .chat absent),
        # l'erreur devient "unavailable", jamais une exception brute.
        sender = chat if chat is not None else _loopback_client().chat
        response = sender(
            model=model,
            # Copies défensives : le schéma et les messages sont des objets
            # globaux/mutables — une mutation côté SDK (bug ou version
            # compromise) ne doit pas corrompre le contrat des appels
            # suivants dans le même processus.
            messages=[dict(message) for message in messages],
            format=copy.deepcopy(QUALIFY_FORMAT_V1),
            think=False,
            stream=False,
            options=dict(_CHAT_OPTIONS),
        )
    except Exception:
        # Frontière fail-closed : ni pile d'appels ni texte d'origine ne
        # traversent (une exception de transport peut recopier la requête ;
        # `from None` coupe la chaîne de contexte).
        logger.warning("qualification: LLM local indisponible (prompt=%s)", PROMPT_NAME)
        raise QualifyError("unavailable") from None
    content = getattr(getattr(response, "message", None), "content", None)
    if not isinstance(content, str):
        logger.warning("qualification: reponse sans contenu (prompt=%s)", PROMPT_NAME)
        raise QualifyError("invalid")
    if len(content) > MAX_RESPONSE_CHARS:
        # Borne anti-DoS avant parsing : ``num_predict`` ne contraint qu'un
        # serveur honnête ; un contenu surdimensionné est refusé sans être
        # ni parsé ni reflété (même code fermé qu'un JSON invalide).
        logger.warning("qualification: reponse surdimensionnee (prompt=%s)", PROMPT_NAME)
        raise QualifyError("invalid")
    try:
        result = json.loads(content, parse_constant=_reject_non_json_constant)
    except (ValueError, RecursionError):
        # Imbrication profonde (borne de récursion : le scanneur C ne
        # récursionne plus par niveau, mais le repli pur-Python si) : même
        # refus fermé que JSON invalide — jamais d'exception brute.
        result = None
    if not isinstance(result, dict):
        logger.warning("qualification: reponse non conforme (prompt=%s)", PROMPT_NAME)
        raise QualifyError("invalid")
    try:
        validated = QualifyVerdict.model_validate(result)
    except ValidationError:
        # Verdict hors enum, confiance hors bornes / mauvais type, champ
        # bonus : refusé sans effet — jamais réparé (invariant 1/2).
        logger.warning("qualification: verdict non conforme (prompt=%s)", PROMPT_NAME)
        raise QualifyError("invalid") from None
    logger.info(
        "qualification: verdict=%s (prompt=%s)",
        validated.verdict,
        PROMPT_NAME,
    )
    return validated.model_dump()


def qualify_candidate(
    candidate: str,
    *,
    model: str = DEFAULT_MODEL,
    chat: ChatFn | None = None,
) -> Qualification:
    """Avis du LLM sur un candidat, sans qu'une sortie cassée le fasse disparaître.

    Fail-closed (REQ-SEC-01, invariant 2) : toute ``QualifyError`` de
    ``qualify()`` (réponse vide, invalide ou hors schéma, LLM indisponible,
    entrée refusée) renvoie ``Qualification("detecte", None, code)`` et le
    code est journalisé : le candidat reste un finding, avec sa raison. Un
    verdict valide, même ``faux_positif``, ne change pas ``status`` non plus :
    le LLM propose, le développeur décide (#32). Aucun texte du modèle
    n'est renvoyé ni journalisé. Un filet final convertit toute exception
    inattendue (évolution du SDK, propriété hostile) en refus ``invalid`` —
    jamais de traversée vers l'appelant. ``BaseException``
    (``KeyboardInterrupt``/``SystemExit``) n'est pas capturée.
    """
    try:
        verdict = qualify(candidate, model=model, chat=chat)
    except QualifyError as error:
        logger.warning(
            "qualification: candidat conserve (raison=%s, prompt=%s)",
            error.code,
            PROMPT_NAME,
        )
        return Qualification(status="detecte", verdict=None, reason=error.code)
    except Exception:
        logger.warning(
            "qualification: candidat conserve (raison=invalid, prompt=%s)",
            PROMPT_NAME,
        )
        return Qualification(status="detecte", verdict=None, reason="invalid")
    return Qualification(status="detecte", verdict=verdict["verdict"], reason=None)
