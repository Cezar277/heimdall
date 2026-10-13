"""Serveur MCP stdio — ticket #27, sous-ticket #73 (squelette + ``ping``).

Exposera les outils du contrat #16 (``read_diff``, ``sanitize_file``,
puis ``list_candidates`` et ``propose_patch``) en stdio, sans outil
d'écriture, d'exécution ou réseau. Le SDK officiel épinglé est ``mcp``
2.3.0 (ADR-002) : dans cette version, ``FastMCP`` a été renommé
``MCPServer`` (guide de migration du SDK v2), d'où l'import ci-dessous.

Trois règles structurantes, reprises à chaque outil :

1. **Racine fixée au démarrage.** Elle est résolue une fois dans
   ``build_server`` et capturée par les outils. Aucun outil ne prend de
   paramètre ``root`` : le LLM ne peut pas la choisir ni la changer
   (contrat #16, invariant 2).
2. **Erreurs dans l'enveloppe, jamais en exception.** ``tool_handler``
   convertit tout échec en ``{"error": {…}}`` ; rien ne remonte au
   protocole (donc pas de pile d'appels ni de chemin absolu reflété,
   invariant 8).
3. **Aucune écriture sur stdout** hormis le protocole lui-même : les
   outils ne font aucun ``print`` et renvoient du JSON ; les diagnostics
   vont sur stderr (``logging``), sinon le canal stdio casse.
"""

import functools
import inspect
import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final, TypeVar, cast

from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer

from heimdall.mcp import errors
from heimdall.mcp.errors import ToolFailure

# Nom du serveur annoncé au client (tools/list → serverInfo).
SERVER_NAME: Final[str] = "heimdall"

# Outils du contrat #16 (schemas/mcp-tools.schema.json, bloc x-tools) :
# référence figée, y compris pour les outils pas encore livrés.
MCP_TOOLS: Final[tuple[str, ...]] = (
    "read_diff",
    "sanitize_file",
    "list_candidates",
    "propose_patch",
)

# Outils effectivement exposés par ce livrable, dans l'ordre de livraison
# (#73, puis #74, puis #75). ``ping`` est la sonde de vie du ticket #73 :
# elle ne renvoie aucune donnée du dépôt (juste ``pong``) et sera intégrée
# au contrat ou retirée par une PR dédiée — écart documenté dans docs/mcp-server.md.
SERVER_TOOLS: Final[tuple[str, ...]] = ("ping",)

logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., str])


# ---------------------------------------------------------------------------
# Garde d'entrée : « additionalProperties: false » appliqué pour de vrai
# ---------------------------------------------------------------------------


def _expected_types(fn: Callable[..., str]) -> dict[str, type]:
    """Types déclarés d'un outil, déduits de sa signature (source unique).

    Le SDK MCP 2.3.0 écarte silencieusement les clés qu'aucun paramètre
    ne déclare (et se contente de les journaliser) : sans cette déduction,
    ``{"path": "../../etc/passwd", "racine": "/"}`` serait ignoré au lieu
    d'être refusé. Les types sont lus sur la signature réelle, donc un
    paramètre ajouté à un outil devient automatiquement acceptable — pas
    de table à maintenir en parallèle.
    """
    declared: dict[str, type] = {}
    for name, parameter in inspect.signature(fn).parameters.items():
        if parameter.annotation in (int, str):
            declared[name] = parameter.annotation
    return declared


class _StrictArgumentGate:
    """Refuse les entrées hors du contrat AVANT l'exécution de l'outil.

    Deux motifs, tous deux issus du contrat #16 :

    - invariant 11 (``additionalProperties: false``) : une clé inconnue
      est refusée au lieu d'être ignorée, donc aucune consigne ne peut
      être glissée dans un champ « bonus » ;
    - invariant 8 (aucune entrée reflétée) : le SDK, lui, répond par une
      exception pydantic qui recopie la valeur reçue
      (``input_value=…``) dans le texte renvoyé au LLM. La garde valide
      donc les types elle-même et renvoie notre enveloppe statique, de
      sorte que la validation du SDK n'ait jamais lieu.
    """

    def __init__(self, tools: Mapping[str, Callable[..., str]]) -> None:
        self._expected: Final[dict[str, dict[str, type]]] = {
            name: _expected_types(fn) for name, fn in tools.items()
        }

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: Callable[[ServerRequestContext[Any, Any]], Any],
    ) -> Any:
        if ctx.method != "tools/call" or not isinstance(ctx.params, dict):
            return await call_next(ctx)
        name = ctx.params.get("name")
        if not isinstance(name, str) or name not in self._expected:
            # Outil inconnu : le SDK répond « Unknown tool » (registre fermé).
            return await call_next(ctx)
        arguments = ctx.params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _error_result(errors.failure("INVALID_INPUT"))
        for key, value in arguments.items():
            if key == "_meta":
                continue  # métadonnée de protocole MCP, pas un champ d'outil.
            wanted = self._expected[name].get(key)
            # Type exact : un booléan n'est pas un entier (isinstance(True, int)
            # est vrai en Python), une sous-classe serait une valeur forgée.
            if wanted is None or type(value) is not wanted:
                logger.info("outil %s : argument hors contrat refusé", name)
                return _error_result(errors.failure("INVALID_INPUT"))
        return await call_next(ctx)


def _error_result(payload: str) -> dict[str, Any]:
    """Résultat MCP d'échec : notre enveloppe JSON, marquée ``isError``."""
    return {"content": [{"type": "text", "text": payload}], "isError": True}


# ---------------------------------------------------------------------------
# Enveloppe des outils : tout échec devient une réponse, jamais une exception
# ---------------------------------------------------------------------------


def tool_handler(fn: _F) -> _F:
    """Transforme toute exception d'un outil en enveloppe d'erreur.

    ``ToolFailure`` porte déjà son code du contrat ; toute autre exception
    (I/O, git absent, décodage) est un échec ``INTERNAL`` au message
    statique. C'est le comportement fail-closed du contrat : jamais de
    résultat partiel silencieux, jamais de trace qui s'échappe.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return fn(*args, **kwargs)
        except ToolFailure as failure:
            return errors.failure(failure.code, failure.message)
        except Exception:
            logger.exception("échec interne d'un outil MCP")
            return errors.failure("INTERNAL")

    return cast("_F", wrapper)


# ---------------------------------------------------------------------------
# Outils
# ---------------------------------------------------------------------------


def _tools(root: Path) -> dict[str, Callable[..., str]]:
    """Construit les outils, chacun fermé sur la racine résolue.

    Les outils sont des closures et non des méthodes : la racine n'apparaît
    dans aucune signature, donc elle est invisible pour le LLM comme pour
    la garde d'entrée.
    """

    @tool_handler
    def ping() -> str:
        """Sonde de vie du canal stdio : répond ``pong``, rien d'autre.

        Aucune donnée du dépôt, aucun chemin : l'outil sert à vérifier que
        la chaîne client → serveur → réponse fonctionne (#73) avant
        d'exposer les outils du contrat.
        """
        return errors.dumps({"pong": True})

    return {"ping": ping}


# ---------------------------------------------------------------------------
# Assemblage
# ---------------------------------------------------------------------------


def _resolve_root(root: str) -> Path:
    """Résout la racine du dépôt, fixée au démarrage (contrat, invariant 2).

    Messages statiques : une racine inexistante ou mal typée est refusée
    sans refléter la valeur reçue (invariant 8).
    """
    if not isinstance(root, str) or not root:
        raise ValueError("racine du depot requise (chaine non vide)")
    resolved = Path(root).resolve()
    if not resolved.is_dir():
        raise ValueError("racine du depot introuvable")
    return resolved


def build_server(root: str) -> MCPServer:
    """Construit le serveur MCP confiné à ``root`` sans le démarrer."""
    repo_root = _resolve_root(root)
    tools = _tools(repo_root)
    server = MCPServer(name=SERVER_NAME, middleware=[_StrictArgumentGate(tools)])
    for name, tool in tools.items():
        # structured_output=False : un seul canal de sortie (le texte JSON),
        # pour que la réponse vue par le LLM soit exactement celle que le
        # contrat décrit — pas un doublon structuré à masquer aussi.
        server.tool(name=name, structured_output=False)(tool)
    return server


def run_stdio(root: str) -> None:
    """Démarre le serveur MCP sur stdio, confiné à ``root``.

    Bloquant : le serveur vit en sous-processus de la CLI (contrat,
    invariant 7) et n'ouvre aucun port.
    """
    server = build_server(root)
    server.run(transport="stdio")
