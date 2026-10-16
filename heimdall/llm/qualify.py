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
- la version du prompt (nom + SHA-256 du fichier) est journalisée à chaque
  appel, et le verdict retenu à chaque succès : une décision reste
  corrélable à l'instruction qui l'a produite, sans secret ni prompt brut —
  un verdict hors enum n'est jamais recopié, seul ``invalide`` est tracé ;
- tout échec local est fermé : prompt de qualification illisible (fichier
  absent, encodage invalide) et candidat au-delà du plafond lèvent une
  ``QualifyError`` à code dédié, jamais une exception brute (un chemin
  dans un message d'erreur) ni un envoi tronquable.

Client épinglé boucle locale : hôte figé ``http://127.0.0.1:11434``
(``OLLAMA_HOST`` ignoré), ``trust_env=False`` (aucun proxy de
l'environnement), redirections refusées — l'aller-retour Ollama ne peut pas
sortir de la machine (invariant 12).

Périmètre : « JSON objet exploitable ». La validation stricte du verdict
(pydantic ``extra="forbid"``, rejet sans effet) appartient à T28.3 (#81) ;
l'affichage et la journalisation du rejet par la CLI à #32. Le LLM reste
consultatif : ce module ne modifie aucun Finding et ne décide jamais seul
(REQ-SEC-01).
"""

import json
import logging
import re
from collections.abc import Callable
from typing import Any, Final, Literal

import ollama

from heimdall.mcp.prompts import (
    MAX_CANDIDATE_CHARS,
    PROMPT_NAME,
    QUALIFY_FORMAT_V1,
    VERDICTS,
    build_messages,
    prompt_digest,
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

# Fonction de chat injectable (tests hors ligne) : signature de
# ``ollama.Client.chat``, seul canal vers le modèle.
ChatFn = Callable[..., Any]

ErrorCode = Literal["empty", "model", "unavailable", "invalid", "prompt", "too_large"]

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


class QualifyError(Exception):
    """Échec fail-closed de la qualification, à message statique.

    Porte un code du registre fermé ``ERROR_MESSAGES``, et RIEN d'autre :
    ni contenu, ni réponse du modèle, ni entrée reflétée.
    """

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(ERROR_MESSAGES[code])
        self.code: ErrorCode = code
        self.message: str = ERROR_MESSAGES[code]


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


def qualify(
    candidate: str,
    *,
    model: str = DEFAULT_MODEL,
    chat: ChatFn | None = None,
) -> dict[str, Any]:
    """Qualifie un candidat masqué ; renvoie l'objet JSON du modèle.

    ``chat`` s'injecte en test (aucun appel réel) ; par défaut, l'appel
    part vers le client Ollama épinglé boucle locale. Toute panne du
    transport ou du modèle devient ``QualifyError("unavailable")`` à
    message statique (jamais l'exception d'origine, qui peut recopier la
    requête). Une réponse non-JSON, vide ou qui n'est pas un objet JSON est
    refusée en ``QualifyError("invalid")`` — jamais réparée ni complétée,
    y compris une réponse entourée de balises Markdown. Un prompt de
    qualification illisible devient ``QualifyError("prompt")`` et un
    candidat au-delà du plafond du contrat ``QualifyError("too_large")`` :
    jamais d'exception brute (chemin compris) ni d'envoi tronquable.
    """
    if not _MODEL_PATTERN.fullmatch(model):
        raise QualifyError("model")
    if isinstance(candidate, str) and len(candidate) > MAX_CANDIDATE_CHARS:
        raise QualifyError("too_large")
    try:
        messages = build_messages(candidate)
        digest = prompt_digest()
    except UnicodeDecodeError:
        # Prompt produit non décodable : installation cassée, même code
        # fermé que fichier absent (jamais d'exception brute avec chemin).
        raise QualifyError("prompt") from None
    except OSError:
        raise QualifyError("prompt") from None
    except ValueError:
        raise QualifyError("empty") from None
    logger.info(
        "qualification: prompt=%s sha256=%s modele=%s",
        PROMPT_NAME,
        digest,
        model,
    )
    sender = chat if chat is not None else _loopback_client().chat
    try:
        response = sender(
            model=model,
            messages=messages,
            format=QUALIFY_FORMAT_V1,
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
    try:
        result = json.loads(content)
    except ValueError:
        result = None
    if not isinstance(result, dict):
        logger.warning("qualification: reponse non conforme (prompt=%s)", PROMPT_NAME)
        raise QualifyError("invalid")
    verdict = result.get("verdict")
    logger.info(
        "qualification: verdict=%s (prompt=%s)",
        verdict if verdict in VERDICTS else "invalide",
        PROMPT_NAME,
    )
    return result
