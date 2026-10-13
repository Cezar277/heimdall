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

import errno
import functools
import inspect
import json
import logging
import os
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final, TypeVar, cast

from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer

from heimdall.mcp import errors, gitdiff, masking, paths
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
SERVER_TOOLS: Final[tuple[str, ...]] = ("ping", "read_diff", "sanitize_file")

# Budget de réponse par défaut de read_diff et bornes du contrat
# (ReadDiffInput.max_bytes : 1024..65536, défaut 32768).
DEFAULT_MAX_BYTES: Final[int] = 32768
MIN_MAX_BYTES: Final[int] = 1024
MAX_MAX_BYTES: Final[int] = 65536

# Bornes de sanitize_file (contrat 4.2) : 200 lignes par défaut, 400 au
# maximum, fichier de 1 Mo au plus, extrait de 100 000 caractères au plus.
DEFAULT_MAX_LINES: Final[int] = 200
MAX_SANITIZE_LINES: Final[int] = 400
MAX_FILE_BYTES: Final[int] = 1024 * 1024
MAX_CONTENT_CHARS: Final[int] = 100_000

# Nombre d'octets examinés pour décider qu'un fichier est binaire : la
# présence d'un octet nul dans l'en-tête est le test usuel (git fait de
# même). Évite de décoder un exécutable comme du texte.
_BINARY_SNIFF_BYTES: Final[int] = 8192

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


class _ToolBoundary:
    """Frontière des appels d'outils : entrée refusée, échec signalé.

    Deux moitiés, toutes deux issues du contrat #16 :

    **Avant l'exécution** — refuser ce que le contrat interdit :

    - invariant 11 (``additionalProperties: false``) : une clé inconnue est
      refusée au lieu d'être ignorée, donc aucune consigne ne peut être
      glissée dans un champ « bonus ». Le SDK 2.3.0, lui, écarte en silence
      les clés qu'aucun paramètre ne déclare et se contente de les
      journaliser ;
    - invariant 8 (aucune entrée reflétée) : sur un type invalide, le SDK
      répond par une exception pydantic qui recopie la valeur reçue
      (``input_value=…``) dans le texte renvoyé au LLM. La frontière valide
      donc les types elle-même et renvoie notre enveloppe statique, de sorte
      que la validation du SDK n'ait jamais lieu.

    **Après l'exécution** — marquer ``isError`` :

    une réponse portant une enveloppe d'échec ``{"error": {…}}`` est marquée
    ``isError: true``, quel que soit l'outil. Les deux formes du contrat
    étant exclusives (3.1), un succès ne peut jamais être pris pour un
    échec. Centralisé ici, le marquage ne peut pas être oublié par un outil
    de plus.
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
            # Type exact : un booléen n'est pas un entier (isinstance(True, int)
            # est vrai en Python), une sous-classe serait une valeur forgée.
            if wanted is None or type(value) is not wanted:
                logger.info("outil %s : argument hors contrat refusé", name)
                return _error_result(errors.failure("INVALID_INPUT"))
        return _mark_failure(await call_next(ctx))


def _error_result(payload: str) -> dict[str, Any]:
    """Résultat MCP d'échec : notre enveloppe JSON, marquée ``isError``."""
    return {"content": [{"type": "text", "text": payload}], "isError": True}


def _mark_failure(result: Any) -> Any:
    """Pose ``isError`` sur les résultats portant une enveloppe d'échec."""
    if not isinstance(result, dict):
        return result
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return result
    block = content[0]
    if not isinstance(block, dict) or block.get("type") != "text":
        return result
    text = block.get("text")
    if not isinstance(text, str):
        return result
    try:
        payload = json.loads(text)
    except ValueError:
        return result
    # Exclusivité des deux formes du contrat (3.1) : « exactement la clé
    # error » ne peut être qu'un échec, jamais un succès.
    if isinstance(payload, dict) and set(payload) == {"error"}:
        result["isError"] = True
    return result


# ---------------------------------------------------------------------------
# Enveloppe des outils : tout échec devient une réponse, jamais une exception
# ---------------------------------------------------------------------------


def tool_handler(fn: _F) -> _F:
    """Transforme toute exception d'un outil en enveloppe d'erreur.

    ``ToolFailure`` porte déjà son code du contrat, ``PathEscape`` le code
    ``PATH_ESCAPE`` ; toute autre exception (I/O, git absent, décodage) est
    un échec ``INTERNAL`` au message statique. C'est le comportement
    fail-closed du contrat : jamais de résultat partiel silencieux, jamais
    de trace ni de valeur reflétée.

    Seules les exceptions **inattendues** sont journalisées avec leur trace :
    un refus de chemin est un fonctionnement normal, pas une panne, et
    l'inonderait la sortie d'erreur du sous-processus.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return fn(*args, **kwargs)
        except ToolFailure as failure:
            return errors.failure(failure.code, failure.message)
        except paths.PathEscape:
            return errors.failure("PATH_ESCAPE")
        except Exception:
            logger.exception("échec inattendu d'un outil MCP")
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

    @tool_handler
    def read_diff(max_bytes: int = DEFAULT_MAX_BYTES) -> str:
        """Lignes ajoutées du diff indexé, valeurs masquées (contrat 4.1).

        Aucun paramètre de chemin ni de racine : le LLM voit ce qui va être
        commité, il ne choisit pas le périmètre. La commande git est figée,
        sans ``shell=True`` et avec ``--no-ext-diff --no-textconv`` pour que
        la configuration du dépôt ne puisse pas déclencher une commande.
        """
        if not MIN_MAX_BYTES <= max_bytes <= MAX_MAX_BYTES:
            raise errors.ToolFailure("INVALID_INPUT")
        access = gitdiff.GitAccess(root)
        if not access.is_repository():
            raise errors.ToolFailure("NOT_A_GIT_REPO")
        raw, truncated = access.staged_diff(max_bytes)
        entries, parse_truncated = gitdiff.parse_diff(raw.decode("utf-8", errors="replace"))
        files, mask_truncated = _masked_files(entries)
        if _fit_budget(files, max_bytes):
            truncated = True
        return errors.dumps(
            {"files": files, "truncated": truncated or parse_truncated or mask_truncated}
        )

    @tool_handler
    def sanitize_file(path: str, start_line: int = 1, max_lines: int = DEFAULT_MAX_LINES) -> str:
        """Extrait d'un fichier du dépôt, valeurs masquées (contrat 4.2).

        Le chemin vient du LLM : c'est une **donnée non fiable**. Il passe
        par la garde unique (``paths.confine``) avant tout accès au système
        de fichiers, et la garde est le seul endroit qui décide du
        confinement — un outil qui l'oublierait ne serait pas relu, il
        n'aurait pas de garde.

        Aucune écriture : l'outil lit, masque et renvoie. La remédiation
        réutilisera la même garde et la CLI appliquera le patch après la
        validation humaine Y/N/E (#32).
        """
        if start_line < 1 or not 1 <= max_lines <= MAX_SANITIZE_LINES:
            raise errors.ToolFailure("INVALID_INPUT")
        access = gitdiff.GitAccess(root)
        if not access.is_repository():
            raise errors.ToolFailure("NOT_A_GIT_REPO")
        confined = paths.confine(root, path)
        relative = confined.relative
        if is_forbidden_path(relative) or access.is_ignored(relative):
            raise errors.ToolFailure("FORBIDDEN_PATH")
        content, total_lines, truncated = _read_extract(confined.absolute, start_line, max_lines)
        redactions = 0
        pieces: list[str] = []
        for line in content:
            text, count = masking.mask_text(line)
            pieces.append(text)
            redactions += count
        # Borne de contenu du contrat (100 000 caractères) : elle s'applique
        # APRÈS masquage, pour les mêmes raisons que read_diff.
        joined = "\n".join(pieces)
        if len(joined) > MAX_CONTENT_CHARS:
            joined = joined[:MAX_CONTENT_CHARS]
            truncated = True
        if not content:
            end_line = 0
        else:
            end_line = start_line + len(content) - 1
        return errors.dumps(
            {
                "path": relative,
                "start_line": start_line,
                "end_line": end_line,
                "total_lines": total_lines,
                "content": joined,
                "redactions": redactions,
                "truncated": truncated,
            }
        )

    return {"ping": ping, "read_diff": read_diff, "sanitize_file": sanitize_file}


def is_forbidden_path(relative: str) -> bool:
    """Segments que le contrat interdit de lire : ``.git/`` et ``.env*``.

    Décidé sur le chemin **canonique** renvoyé par la garde, pas sur
    l'entrée : ``./.git`` ou ``sous/.././.git`` arrivent ici déjà
    normalisés, donc aucune évasion par chemin tordu n'est possible.
    """
    for segment in relative.split("/"):
        if segment == ".git":
            return True
        if segment == ".env" or segment.startswith(".env."):
            return True
    return False


def _read_extract(absolute: Path, start_line: int, max_lines: int) -> tuple[list[str], int, bool]:
    """Lit les lignes demandées, ou lève le code d'erreur du contrat.

    Ouverture en ``O_NOFOLLOW`` et vérification dev/ino : voir la limite
    TOCTOU documentée dans le module (et à consigner dans l'ADR du #27).
    """
    try:
        before = os.lstat(absolute)
    except OSError:
        raise errors.ToolFailure("NOT_FOUND") from None
    if stat.S_ISDIR(before.st_mode):
        raise errors.ToolFailure("NOT_FOUND")
    if before.st_size > MAX_FILE_BYTES:
        raise errors.ToolFailure("TOO_LARGE")
    try:
        handle = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        # ELOOP : le fichier est devenu un lien symbolique entre la garde et
        # l'ouverture. On refuse (fail-closed) plutôt que de suivre.
        if error.errno == errno.ELOOP:
            raise errors.ToolFailure("INTERNAL") from None
        raise errors.ToolFailure("NOT_FOUND") from None
    try:
        after = os.fstat(handle)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            # Le fichier a été remplacé (ou recréé) entre les deux appels :
            # le contenu lu ne serait pas celui qui a été validé.
            raise errors.ToolFailure("INTERNAL")
        data = _read_bounded(handle)
        if len(data) > MAX_FILE_BYTES:
            raise errors.ToolFailure("TOO_LARGE")
        if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
            raise errors.ToolFailure("BINARY_FILE")
    finally:
        os.close(handle)
    lines = _split_lines(data.decode("utf-8", errors="replace"))
    total_lines = len(lines)
    if start_line > total_lines:
        return [], total_lines, False
    selected = lines[start_line - 1 : start_line - 1 + max_lines]
    truncated = start_line + len(selected) - 1 < total_lines
    return selected, total_lines, truncated


def _read_bounded(handle: int) -> bytes:
    """Lit au plus ``MAX_FILE_BYTES + 1`` octets (le +1 détecte le dépassement)."""
    chunks: list[bytes] = []
    remaining = MAX_FILE_BYTES + 1
    while remaining > 0:
        chunk = os.read(handle, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _split_lines(text: str) -> list[str]:
    """Lignes du fichier, sans ligne vide finale (convention ``wc -l``)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _masked_files(entries: list[gitdiff.DiffEntry]) -> tuple[list[dict[str, object]], bool]:
    """Construit les ``DiffFile`` du contrat, masquage puis bornes.

    Ordre volontaire : on masque **avant** de tronquer une ligne à 2000
    caractères. Tronquer d'abord couperait une valeur en deux et le masquage
    ne la reconnaîtrait plus ; masquer d'abord la raccourcit, donc la borne
    reste respectée.
    """
    files: list[dict[str, object]] = []
    truncated = False
    for entry in entries:
        redactions = 0
        added: list[dict[str, object]] = []
        for number, text in entry.lines:
            masked, count = masking.mask_text(text)
            if len(masked) > gitdiff.MAX_LINE_CHARS:
                masked = masked[: gitdiff.MAX_LINE_CHARS]
                truncated = True
            redactions += count
            added.append({"line": number, "text": masked})
        if entry.line_overflow:
            truncated = True
        files.append(
            {
                "file": entry.path,
                "binary": entry.binary,
                "redactions": redactions,
                "added_lines": added,
            }
        )
    return files, truncated


def _fit_budget(files: list[dict[str, object]], max_bytes: int) -> bool:
    """Garantit que la réponse tient dans le budget ``max_bytes``.

    Le coût du JSON n'est pas négligeable (clés, marqueurs de masquage) : on
    retire des fichiers entiers, les derniers d'abord, jusqu'à ce que la
    réponse sérialisée tienne. La boucle s'arrête toujours : une réponse
    vide est minuscule, donc elle passe sous n'importe quel budget. Un
    fichier retiré est signalé par ``truncated: true`` — la réponse dit
    « information incomplète », jamais « diff vide ».
    """
    truncated = False
    while files and _encoded_size(files) > max_bytes:
        files.pop()
        truncated = True
    return truncated


def _encoded_size(files: list[dict[str, object]]) -> int:
    """Taille de la réponse sérialisée, en octets UTF-8."""
    return len(errors.dumps({"files": files, "truncated": True}).encode("utf-8"))


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
    server = MCPServer(name=SERVER_NAME, middleware=[_ToolBoundary(tools)])
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
