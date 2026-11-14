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
import re
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

# Fichiers de credentials refusés par `sanitize_file` (audit F-09), en plus de
# `.git/` et `.env*` : un faux positif de lecture coûte un fichier de contexte,
# une lecture de `.netrc`/clé privée coûte un secret envoyé au LLM.
_FORBIDDEN_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        ".netrc",
        "netrc",
        "_netrc",
        ".pgpass",
        "pgpass",
        ".npmrc",
        "npmrc",
        ".pypirc",
        "pypirc",
        "credentials",
        "credential",
    }
)

# Suffixes qu'un éditeur ou une rotation ajoute à une copie de fichier.
# Retirés en boucle avant comparaison : `server.pem.bak` → `server.pem`,
# `.netrc.backup` → `.netrc`, `credentials-backup` → `credentials`. Les
# extensions de documentation (`.md`, `.txt`) n'en font pas partie :
# `credentials.md` et `server.pem.txt` restent lisibles.
_BACKUP_SUFFIXES: Final[tuple[str, ...]] = (
    "~",
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".swp",
    "-bak",
    "-backup",
    "-old",
    "_bak",
    "_backup",
    "_old",
)

# Même vocabulaire en position d'INFIXE, devant l'extension finale :
# `credentials.bak.json` → `credentials.json`. Le lookahead exige une
# extension finale, sinon `.bak` serait déjà traité comme suffixe.
_BACKUP_INFIX: Final[re.Pattern[str]] = re.compile(
    "(?:"
    + "|".join(re.escape(suffix) for suffix in sorted(_BACKUP_SUFFIXES, key=len, reverse=True))
    + r")(?=\.[^.]+$)"
)

# `credentials` / `credential` sont des noms nus trop généraux pour un
# préfixe large : `credentials.md` / `credential.md` est de la documentation.
# On énumère les extensions qui, elles, contiennent des credentials (configs,
# mais aussi coffres locaux `.env`, `.db`, `.sqlite*`, `.store`) ; les
# suffixes de sauvegarde sont retirés avant comparaison par
# `_strip_backup_suffixes`.
_CREDENTIALS_VARIANTS: Final[tuple[str, ...]] = tuple(
    f"{stem}{suffix}"
    for stem in ("credentials", "credential")
    for suffix in (
        ".json",
        ".yaml",
        ".yml",
        ".txt",
        ".ini",
        ".toml",
        ".cfg",
        ".conf",
        ".xml",
        ".env",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".store",
    )
)

# Clés privées et trousseaux : le suffixe suffit, quelle que soit la casse.
_FORBIDDEN_SUFFIXES: Final[tuple[str, ...]] = (".pem", ".key")

# Préfixes de clés SSH : `id_rsa.pub` est public, mais le sur-blocage est
# bénin et une clé privée sans suffixe ne doit pas passer par variante.
_FORBIDDEN_PREFIXES: Final[tuple[str, ...]] = ("id_rsa", "id_ed25519")

# Configurations qui contiennent des identifiants de registre / cluster.
# Comparaison par préfixe du nom : `.docker/config.json.bak` et
# `.kube/config.old` sont des copies de la même configuration, pas des
# homonymes inoffensifs.
_FORBIDDEN_CONFIG_PATHS: Final[tuple[tuple[str, str], ...]] = (
    (".docker", "config.json"),
    (".kube", "config"),
)


# `O_NONBLOCK` n'existe pas sur Windows : repli à 0 (aucun effet) pour
# rester importable partout. Sur POSIX il est indispensable : sans lui,
# un FIFO substitué entre `lstat` et `open` bloquerait AVANT le contrôle
# post-ouverture. Sans effet sur les réguliers (lecture normale).
_NONBLOCK: Final[int] = getattr(os, "O_NONBLOCK", 0)

# Partie constante de la réponse sérialisée (`{"files":[],"truncated":true}`
# moins la liste vide), calculée une fois à l'import : `_fit_budget` décide
# ainsi de ses retraits par arithmétique entière, sans jamais resérialiser
# la réponse (le coût était O(n²) sérialisations, cf. ADR-003 §8).
_ENVELOPE_BYTES: Final[int] = len(errors.dumps({"files": [], "truncated": True}).encode("utf-8"))

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
      non conforme au contrat 3.1. Même motif pour un **outil inconnu** :
      le SDK répondrait « Unknown tool », un texte brut hors enveloppe —
      la frontière refuse elle-même en ``INVALID_INPUT`` (registre fermé,
      invariant 1 : une seule enveloppe d'échec).
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
            # Outil inconnu : le SDK répondrait « Unknown tool », un texte
            # brut hors de notre enveloppe `{"error": …}` (contrat 3.1).
            # La frontière refuse elle-même en `INVALID_INPUT`, sans refléter
            # le nom reçu (invariant 8 : il est non fiable). `INVALID_INPUT`
            # appartient au sous-ensemble d'erreur de chaque outil du contrat.
            logger.info("outil inconnu refuse")
            return _error_result(errors.failure("INVALID_INPUT"))
        arguments = ctx.params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict) or not self._arguments_valid(name, arguments):
            return _error_result(errors.failure("INVALID_INPUT"))
        return _mark_failure(await call_next(ctx))

    def _arguments_valid(self, name: str, arguments: dict[str, Any]) -> bool:
        """Entrée conforme au contrat de l'outil (types, requis, `_meta`)."""
        for key, value in arguments.items():
            if not isinstance(key, str):
                logger.info("outil %s : clé non textuelle refusée", name)
                return False
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


def _clean_trailing_marker(text: str) -> str:
    """Évite qu'une coupe à MAX_LINE_CHARS ne laisse un marqueur incomplet sans '>' fermant."""
    last_marker = text.rfind(masking.REDACTION_MARKER)
    if last_marker != -1 and ">" not in text[last_marker:]:
        return text[:last_marker]
    return text


def _bound_line(masked: str) -> tuple[str, bool]:
    """Borne une ligne déjà masquée à ``MAX_LINE_CHARS`` sans couper de marqueur."""
    if len(masked) <= gitdiff.MAX_LINE_CHARS:
        return masked, False
    return _clean_trailing_marker(masked[: gitdiff.MAX_LINE_CHARS]), True


def _masked_line(raw_text: str) -> tuple[str, bool]:
    """Masque une ligne ENTIÈRE, puis la borne à ``MAX_LINE_CHARS``."""
    masked, _ = masking.mask_text(raw_text)
    return _bound_line(masked)


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
        for masked_line in masking.mask_lines(content):
            bounded, cut = _bound_line(masked_line)
            truncated = truncated or cut
            pieces.append(bounded)
        # Borne de contenu du contrat (100 000 caractères) : elle s'applique
        # APRÈS masquage, pour les mêmes raisons que read_diff — et la coupe
        # est nettoyée comme les lignes : sans cela, un marqueur à cheval
        # sur la borne partirait tronqué (`<REDACTED:` sans `>` fermant)
        # tout en étant compté, violant `redactions >= 1 ⇒ marqueur présent`.
        joined = "\n".join(pieces)
        if len(joined) > MAX_CONTENT_CHARS:
            joined = _clean_trailing_marker(joined[:MAX_CONTENT_CHARS])
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


def _strip_backup_suffixes(segment: str) -> str:
    """Retire les suffixes et infixes de sauvegarde, en boucle.

    `.netrc.backup.old` doit redevenir `.netrc` et `credentials.bak.json`
    doit redevenir `credentials.json` ; une seule passe laisserait
    `.netrc.backup` (pas égal à `.netrc`) ou le `.bak` en position d'infixe.
    La borne de longueur évite de réduire un nom à la chaîne vide.
    """
    while True:
        without_infix = _BACKUP_INFIX.sub("", segment)
        if without_infix != segment:
            segment = without_infix
            continue
        for suffix in _BACKUP_SUFFIXES:
            if segment.endswith(suffix) and len(segment) > len(suffix):
                segment = segment[: -len(suffix)]
                break
        else:
            return segment


def _is_forbidden_segment(segment: str) -> bool:
    """Un segment (déjà en minuscules) désigne-t-il un fichier interdit ?"""
    normalized = _strip_backup_suffixes(segment)
    return (
        normalized == ".git"
        or normalized.startswith(".env")
        or normalized in _FORBIDDEN_FILENAMES
        or normalized in _CREDENTIALS_VARIANTS
        or normalized.endswith(_FORBIDDEN_SUFFIXES)
        or normalized.startswith(_FORBIDDEN_PREFIXES)
    )


def is_forbidden_path(relative: str) -> bool:
    """Segments que le contrat interdit de lire, élargis par l'audit F-09.

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

    F-09 : la liste couvre aussi les fichiers de credentials usuels
    (`.netrc`/`netrc`/`_netrc`, `.pgpass`/`pgpass`, `id_rsa`, `*.pem`, `*.key`,
    `.npmrc`/`npmrc`, `.pypirc`/`pypirc`, `.docker/config.json`, `.kube/config`,
    `credentials`/`credential`) **et leurs variantes de sauvegarde**
    (`.netrc.backup`, `credentials.json`, `credential.json`, `server.pem.bak`,
    `private.key.old`, `.docker/config.json.bak`…). Le masquage de E-03 reste
    une seconde barrière, pas une autorisation de lecture.
    """
    segments = relative.split("/")
    lowered = [segment.lower() for segment in segments]
    forbidden_segment = any(_is_forbidden_segment(segment) for segment in lowered)
    forbidden_config = any(
        _strip_backup_suffixes(segment) == directory
        and _strip_backup_suffixes(lowered[index + 1]).startswith(basename)
        for index, segment in enumerate(lowered[:-1])
        for directory, basename in _FORBIDDEN_CONFIG_PATHS
    )
    return forbidden_segment or forbidden_config


def _absent_or_internal(error: OSError) -> ToolFailure:
    """`NOT_FOUND` réservé à l'absence, tout le reste `INTERNAL`.

    `ELOOP` (lien substitué entre la garde et l'ouverture), `EACCES`/`EPERM`
    (droits refusés), quota ou nom trop long : anomalie d'intégrité, pas une
    absence — sinon un fichier illisible serait annoncé « introuvable » et le
    tri confondrait une panne avec une absence. Les deux restent fail-closed.
    """
    if error.errno in (errno.ENOENT, errno.ENOTDIR):
        return errors.ToolFailure("NOT_FOUND")
    return errors.ToolFailure("INTERNAL")


def _read_extract(absolute: Path, start_line: int, max_lines: int) -> tuple[list[str], int, bool]:
    """Lit les lignes demandées, ou lève le code d'erreur du contrat.

    Ouverture en ``O_NOFOLLOW`` et vérification dev/ino : voir la limite
    TOCTOU documentée dans le module (et à consigner dans l'ADR du #27).
    """
    try:
        before = os.lstat(absolute)
    except OSError as error:
        raise _absent_or_internal(error) from None
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
        # Supprimé entre `lstat` et `open` → `NOT_FOUND` ; le reste (lien
        # substitué, droits, panne) → `INTERNAL` (voir `_absent_or_internal`).
        # On refuse (fail-closed) plutôt que de suivre ou d'inventer une absence.
        raise _absent_or_internal(error) from None
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
        if b"\x00" in data:
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

    Ordre delegates à ``_masked_line`` : on masque **avant** de tronquer
    une ligne à 2000 caractères (masquer d'abord la raccourcit, donc la
    borne reste respectée ; l'inverse couperait une valeur en deux et le
    masquage ne la reconnaîtrait plus).

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
        masked_lines = masking.mask_lines([raw_text for _, raw_text in entry.lines])
        for (number, _), masked_raw in zip(entry.lines, masked_lines, strict=True):
            masked, cut = _bound_line(masked_raw)
            truncated = truncated or cut
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
    « information incomplète », jamais « diff vide ». La liste ``files``
    est raccourcie sur place : c'est elle qui est sérialisée ensuite.

    Coût borné : chaque fichier est sérialisé **une seule fois** par
    ``_file_sizes``, puis la boucle ne manipule que des tailles entières.
    L'ancienne version resérialisait toute la liste à chaque ``pop`` —
    jusqu'à 200 ``dumps`` complets, sur le canal stdio synchrone, avec un
    contenu pilotable par le dépôt scanné. L'additivité des tailles
    (``errors.dumps`` compact, un objet = un élément de liste) permet de
    décider du retrait par sommes cumulées, à coût constant par retrait.
    ``_encoded_size`` reste la mesure de référence exacte ; un test vérifie
    que la somme cumulative lui est identique.
    """
    truncated = False
    sizes = _file_sizes(files)
    while sizes and _prefix_size(sizes) > max_bytes:
        sizes.pop()
        truncated = True
    del files[len(sizes) :]
    return truncated


def _file_sizes(files: list[dict[str, object]]) -> list[int]:
    """Taille sérialisée de chaque fichier, calculée une seule fois."""
    return [len(errors.dumps(item).encode("utf-8")) for item in files]


def _encoded_size(files: list[dict[str, object]]) -> int:
    """Taille EXACTE de la réponse sérialisée, en octets UTF-8.

    Référence de contrôle : ``_fit_budget`` passe par les tailles cumulées
    pour ne pas resérialiser, cette fonction sert à prouver (en test) que
    la somme cumulative ne dérape pas de la réalité.
    """
    return len(errors.dumps({"files": files, "truncated": True}).encode("utf-8"))


def _prefix_size(sizes: list[int]) -> int:
    """Taille de la réponse sérialisée pour ce préfixe de fichiers.

    Additivité vérifiée en test : enveloppe à liste vide + somme des
    éléments + une virgule par élément au-delà du premier (``errors.dumps``
    compact, donc un objet = un élément de liste).
    """
    return _ENVELOPE_BYTES + sum(sizes) + max(len(sizes) - 1, 0)


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
