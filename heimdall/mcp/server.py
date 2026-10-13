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

# `O_NONBLOCK` n'existe pas sur Windows : repli à 0 (aucun effet) pour
# rester importable partout. Sur POSIX il est indispensable : sans lui,
# un FIFO substitué entre `lstat` et `open` bloquerait AVANT le contrôle
# post-ouverture. Sans effet sur les réguliers (lecture normale).
_NONBLOCK: Final[int] = getattr(os, "O_NONBLOCK", 0)

# Métadonnée de protocole MCP tolérée (_meta) : bornée, jamais un champ.
# Un client modifié pourrait y glisser un volume arbitraire ; nos outils
# ne la lisent ni ne la renvoient (le SDK l'ignore), mais on refuse
# au-delà d'un Kio plutôt que de laisser passer sans regard.
_META_MAX_BYTES: Final[int] = 1024

logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., str])


# ---------------------------------------------------------------------------
# Garde d'entrée : « additionalProperties: false » appliqué pour de vrai
# ---------------------------------------------------------------------------


def _expected_types(fn: Callable[..., str]) -> tuple[dict[str, type], frozenset[str]]:
    """Types et paramètres requis d'un outil, déduits de sa signature.

    Source unique : la signature réelle. Un paramètre ajouté à un outil
    devient automatiquement acceptable — et, s'il est sans défaut,
    automatiquement requis. Seules les annotations ``int``/``str`` du
    contrat sont reconnues (un futur paramètre d'un autre type serait
    refusé plutôt qu'accepté en douce : fail-closed).
    """
    declared: dict[str, type] = {}
    required: set[str] = set()
    for name, parameter in inspect.signature(fn).parameters.items():
        if parameter.annotation in (int, str):
            declared[name] = parameter.annotation
            if parameter.default is inspect.Parameter.empty:
                required.add(name)
    return declared, frozenset(required)


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
      que la validation du SDK n'ait jamais lieu. Même motif pour les
      paramètres **requis** : sans ``path``, le SDK répond « Field
      required », un texte hors de notre enveloppe ``{"error": …}`` donc
      non conforme au contrat 3.1.
    - `_meta` (protocole) toléré mais borné à 1 Kio : un volume arbitraire
      via un client modifié est refusé, jamais propagé sans regard.

    **Après l'exécution** — marquer ``isError`` :

    une réponse portant une enveloppe d'échec ``{"error": {…}}`` est marquée
    ``isError: true``, quel que soit l'outil. Les deux formes du contrat
    étant exclusives (3.1), un succès ne peut jamais être pris pour un
    échec. Centralisé ici, le marquage ne peut pas être oublié par un outil
    de plus.
    """

    def __init__(self, tools: Mapping[str, Callable[..., str]]) -> None:
        self._expected: Final[dict[str, dict[str, type]]] = {}
        self._required: Final[dict[str, frozenset[str]]] = {}
        for tool_name, fn in tools.items():
            declared, required = _expected_types(fn)
            self._expected[tool_name] = declared
            self._required[tool_name] = required

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
        if not isinstance(arguments, dict) or not self._arguments_valid(name, arguments):
            return _error_result(errors.failure("INVALID_INPUT"))
        return _mark_failure(await call_next(ctx))

    def _arguments_valid(self, name: str, arguments: dict[str, Any]) -> bool:
        """Entrée conforme au contrat de l'outil (types, requis, `_meta`)."""
        for key, value in arguments.items():
            if key == "_meta":
                continue  # métadonnée de protocole MCP, pas un champ d'outil.
            wanted = self._expected[name].get(key)
            # Type exact : un booléen n'est pas un entier (isinstance(True, int)
            # est vrai en Python), une sous-classe serait une valeur forgée.
            if wanted is None or type(value) is not wanted:
                logger.info("outil %s : argument hors contrat refusé", name)
                return False
        if "_meta" in arguments and not self._meta_bounded(arguments["_meta"]):
            logger.info("outil %s : métadonnée hors borne refusée", name)
            return False
        provided = {key for key in arguments if key != "_meta"}
        if not self._required[name] <= provided:
            # Paramètre requis absent : le SDK répondrait « Field required »,
            # hors enveloppe. On refuse nous-mêmes, avec notre enveloppe.
            logger.info("outil %s : paramètre requis absent", name)
            return False
        return True

    @staticmethod
    def _meta_bounded(meta: Any) -> bool:
        """`_meta` tolérée sous 1 Kio, jamais propagée sans regard."""
        try:
            size = len(json.dumps(meta, ensure_ascii=True).encode("utf-8"))
        except (ValueError, TypeError, RecursionError, MemoryError):
            # Imbrication hostile (~10⁵ niveaux), type non sérialisable ou volume inallouable :
            # refusé, jamais remonté hors enveloppe (fail-closed).
            return False
        return size <= _META_MAX_BYTES


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

    Seules les exceptions inattendues sont journalisées avec un message
    statique : un refus de chemin est un fonctionnement normal, pas une
    panne. Jamais de ``str(exc)`` ni de trace brute dans les logs (invariant 8 :
    un message d'exception pourrait embarquer un chemin absolu ou un secret).
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return fn(*args, **kwargs)
        except ToolFailure as failure:
            return errors.failure(failure.code)
        except paths.PathEscape:
            return errors.failure("PATH_ESCAPE")
        except Exception:
            logger.error("échec inattendu d'un outil MCP")
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
        pieces: list[str] = []
        for line in content:
            text, _ = masking.mask_text(line)
            pieces.append(text)
        # Borne de contenu du contrat (100 000 caractères) : elle s'applique
        # APRÈS masquage, pour les mêmes raisons que read_diff.
        joined = "\n".join(pieces)
        if len(joined) > MAX_CONTENT_CHARS:
            joined = joined[:MAX_CONTENT_CHARS]
            truncated = True
        # Même invariant que read_diff : le compteur est recompté sur le
        # contenu final, pour qu'une coupe ne laisse jamais un compteur
        # sans marqueur (forme exigée par le schéma).
        redactions = joined.count(masking.REDACTION_MARKER)
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

    Comparaison en minuscules : sur un système de fichiers insensible à
    la casse (Windows, macOS), ``.GIT/config`` ouvre le même fichier que
    ``.git/config``. Refuser ``.Git`` en trop est un faux positif bénin
    (fail-closed) ; laisser passer ``.GIT`` serait une évasion.

    Préfixe large (`.env`, `.env-backup`, `.env_old`, `.env~`…) comme
    l'exige le contrat (`.env*`, §4.2) : sur-bloquer `.envelope` est un
    faux positif bénin assumé, laisser passer `.env-backup` serait un
    contournement de l'interdit (sauvegardes !).
    """
    for segment in relative.split("/"):
        lowered = segment.lower()
        if lowered == ".git":
            return True
        if lowered.startswith(".env"):
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
    if not stat.S_ISREG(before.st_mode):
        # FIFO, socket, périphérique : aucun texte à renvoyer — et surtout,
        # ouvrir un FIFO en lecture bloquerait pour toujours (DoS du canal
        # stdio, sans timeout possible). Refus avant ouverture.
        raise errors.ToolFailure("BINARY_FILE")
    if before.st_size > MAX_FILE_BYTES:
        raise errors.ToolFailure("TOO_LARGE")
    try:
        handle = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | _NONBLOCK)
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
        if not stat.S_ISREG(after.st_mode):
            # Remplacé par un FIFO/socket entre lstat et open : l'ouverture
            # non bloquante a laissé passer, le contenu reste illisible.
            # Anomalie d'intégrité (comme dev/ino), donc INTERNAL.
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

    Le compteur ``redactions`` est **recompté sur les lignes finales** (les
    marqueurs qui survivent à la coupe), pas sur le masquage brut : une
    coupe qui emporterait le seul marqueur d'un fichier violerait sinon
    l'invariant structurel du contrat (``redactions >= 1`` ⇒ un marqueur
    présent). Le compte décrit donc la réponse, jamais une promesse.
    (Si le source contenait déjà le littéral ``<REDACTED:``, il est compté
    comme un marqueur de la réponse : indiscernable, et l'invariant tient
    dans tous les cas.)
    """
    files: list[dict[str, object]] = []
    truncated = False
    for entry in entries:
        added: list[dict[str, object]] = []
        finals: list[str] = []
        for number, text in entry.lines:
            masked, _ = masking.mask_text(text)
            if len(masked) > gitdiff.MAX_LINE_CHARS:
                masked = masked[: gitdiff.MAX_LINE_CHARS]
                truncated = True
            added.append({"line": number, "text": masked})
            finals.append(masked)
        if entry.line_overflow:
            truncated = True
        redactions = sum(line.count(masking.REDACTION_MARKER) for line in finals)
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
    invariant 7) et n'ouvre aucun port. Testé en sous-processus par tous
    les tests client (`tests/test_mcp_*.py`), jamais ici.
    """
    server = build_server(root)
    server.run(transport="stdio")
