"""Diff indexé confiné — outil ``read_diff`` (contrat #16, section 4.1).

Le LLM ne voit le commit en cours **que** par ce module. Tout y est donc
verrouillé :

- **argv figé**, jamais construit depuis une entrée. ``shell=True`` est
  proscrit (bandit + invariant 5 : aucune commande arbitraire) ;
- **environnement reconstruit de zéro**. ``GIT_DIR``, ``GIT_INDEX_FILE``,
  ``GIT_WORK_TREE``… hérités permettraient de rediriger le dépôt analysé
  sans toucher au code ; ils sont simplement absents de l'environnement
  passé au sous-processus. Idem ``HOME`` et les configurations
  système/global ;
- **découverte plafonnée à la racine**. ``GIT_CEILING_DIRECTORIES`` vaut le
  parent de la racine : git n'y entre jamais, donc aucun dépôt au-dessus de
  la racine n'est découvert — le refus vient de git, pas seulement de
  ``is_repository()`` (invariant 3) ;
- **aucun fetch différé**. ``GIT_NO_LAZY_FETCH`` vaut ``1`` : dans un clone
  partiel, ``git cat-file`` irait chercher l'objet manquant **sur le
  réseau** — interdit ici (invariant « 100 % local »). L'objet manquant est
  alors une erreur, jamais un download ;
- **stdin fermé**. ``stdin=subprocess.DEVNULL`` sur chaque appel : le fils
  n'hérite pas du pipe JSON-RPC du serveur, donc aucune sous-commande
  future ne peut en consommer les octets ni s'y bloquer ;
- **configuration locale neutralisée**. Le `.git/config` du dépôt scanné
  est toujours lu par git : `core.fsmonitor` y exécute une commande à
  chaque `diff`/`check-ignore` (prouvé par exécution). Chaque appel est
  donc préfixé de `-c core.fsmonitor=false` (désactivation réelle,
  vérifiée avec PATH hostile). Le pager hostile est prouvé inopérant
  (sorties toujours pipées) : aucun override, aucune surface ajoutée ;
- **binaire résolu hors PATH hérité**. `shutil.which("git",
  path=os.defpath)` : un PATH compromis ne détourne pas l'exécutable.
  Absent du défaut système → panne d'outillage, jamais de repli ;
- **options du contrat imposées** : ``--no-ext-diff`` et ``--no-textconv``
  empêchent git d'exécuter ``diff.external`` ou les filtres ``textconv``
  configurés dans le dépôt — de l'exécution de commande pilotée par le
  contenu scanné, donc l'interdit I5 contournable par configuration ;
- **limites dures** (200 fichiers, 5000 lignes par fichier, 2000
  caractères par ligne) : au-delà, la sortie est tronquée et le drapeau
  ``truncated`` est posé, jamais un résultat partiel présenté comme
  complet.

Depuis #29, ce module expose aussi la lecture **des blobs de l'index**
(``staged_changes``/``blob_size``/``blob_bytes``) : c'est ce que la CLI
``heimdall scan --staged`` analyse, sans aucune exclusion de chemin. Les
mêmes garanties s'appliquent : argv figé (seul le SHA, validé hexadécimal,
varie), environnement confiné, stdin fermé, aucun fetch.
"""

import os
import re
import shutil
import subprocess  # nosec B404
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.paths import is_rel_path
from heimdall.scanner.finding import validate_relative_path

# Options NON négociables (contrat 4.1) — voir le tableau du contrat pour la
# justification de chacune. `-C` place git dans la racine sans dépendre du
# cwd du processus appelant.
DIFF_ARGUMENTS: Final[tuple[str, ...]] = (
    "diff",
    "--cached",
    "--unified=0",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
)

# Neutralise la configuration LOCALE du dépôt scanné, lue par chaque appel
# git : `core.fsmonitor` y exécute une commande du dépôt à chaque `diff`
# ou `check-ignore` (prouvé par exécution avec hook planté : canari écrit
# sans l'override, absent avec). `-c` gagne sur tous les fichiers de
# config ; `false` désactive vraiment (vérifié avec un PATH hostile
# contenant un binaire `false` piégé : jamais exécuté). Le pager hostile
# est lui prouvé inopérant (sorties toujours pipées : test dédié), donc
# aucun override pager — pas de surface ajoutée.
GIT_CONFIG_OVERRIDES: Final[tuple[str, ...]] = ("-c", "core.fsmonitor=false")

#: Options de l'énumération de l'index (#29) : la liste des fichiers **ajoutés
#: ou modifiés** dans l'index, avec le SHA du blob indexé. `--raw -z` : un
#: en-tête et un chemin, tous deux NUL-terminés. `--no-abbrev` impose le SHA
#: **complet** (40 caractères en SHA-1, 64 en SHA-256) : un SHA abrégé ne
#: désigne pas un objet de façon univoque et ne peut donc pas être relu.
#: `--no-renames` rend la sortie déterministe (un renommage devient une
#: suppression + un ajout : pas de score de similarité, donc pas de cas
#: ambigu à parser).
#: Plafond de la sortie brute de l'énumération de l'index (#29). Le pire cas
#: légitime tient large : ``MAX_STAGED_FILES`` entrées de ~128 octets
#: d'en-tête + chemin (4096 au plus, contrat Finding v1), soit de l'ordre de
#: 4 Mio. Au-delà, le flux est coupé et l'index est refusé — un index adverse
#: de 100 000 entrées ne fait jamais bufferiser des dizaines de Mo avant le
#: contrôle du nombre de fichiers.
MAX_STAGED_RAW_BYTES: Final[int] = 8 * 1024 * 1024

STAGED_RAW_ARGUMENTS: Final[tuple[str, ...]] = (
    "diff",
    "--cached",
    "--raw",
    "-z",
    "--no-abbrev",
    "--no-renames",
    "--no-ext-diff",
    "--no-textconv",
)


# Environnement minimal du sous-processus git. Aucune variable de
# redirection de dépôt (GIT_DIR, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY…),
# aucune variable de configuration (GIT_CONFIG_*), aucun PATH : git est
# appelé par chemin absolu, donc rien ne peut être trouvé par recherche de
# binaire, et GIT_TERMINAL_PROMPT coupe toute invite interactive.
def confined_environment(root: Path) -> dict[str, str]:
    return {
        "PATH": "",
        "HOME": str(root),  # jamais le ~ du développeur (git y lit .gitconfig)
        "LC_ALL": "C",  # messages et chemins stables, indépendants de la locale
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",  # aucun verrou optionnel pris dans .git/
        # Clone partiel : sans cette variable, `git cat-file` irait chercher
        # l'objet manquant SUR LE RÉSEAU. Heimdall est 100 % local : l'objet
        # manquant doit être une erreur, jamais un download.
        "GIT_NO_LAZY_FETCH": "1",
        # Plafond de découverte = le PREMIER dossier que git ascendererait,
        # c'est-à-dire le PARENT de la racine : git refuse d'y entrer, donc
        # aucun dépôt au-dessus de la racine n'est découvert (invariant 3).
        #
        # Ne pas « corriger » en mettant la racine elle-même : git n'exclut
        # que l'entrée dans un dossier plafond, et il est DÉJÀ dans la
        # racine — le plafond ne bloquerait alors rien. Matrice prouvée par
        # exécution (racine = `repo/sous`, dépôt en `repo`) :
        #
        #   plafond = parent : `rev-parse --show-toplevel` → rc=128,
        #                       « not a git repository » : le dépôt parent
        #                       est INATTEIGNABLE, et ce refus vient de git,
        #                       pas de notre test d'égalité — donc un outil
        #                       futur qui oublierait `is_repository()`
        #                       n'hériterait de rien non plus.
        #   plafond = racine : rc=0, toplevel = le dépôt PARENT : la
        #                       garantie retomberait sur chaque appelant.
        #
        # Prouvé aussi qu'un worktree lié répond sa propre racine (le `.git`
        # y est un fichier), donc un dépôt à la racine reste découvert.
        "GIT_CEILING_DIRECTORIES": str(root.resolve().parent),
    }


# Délai maximal d'une commande git : un diff qui ne répond pas est une panne
# d'outillage (INTERNAL), pas une attente sans fin.
GIT_TIMEOUT_SECONDS: Final[float] = 30.0

# Plafonds d'affichage du contrat 4.1.
MAX_FILES: Final[int] = 200
MAX_LINES_PER_FILE: Final[int] = 5000
MAX_LINE_CHARS: Final[int] = 2000

# `@@ -12,0 +1,3 @@ fonction` : seule la position côté nouveau compte, et
# c'est elle que le groupe nommé `new` porte.
_HUNK_HEADER: Final[re.Pattern[str]] = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")

# Hunk **combiné** d'un diff de fusion : `@@@ -1,2 -1,2 +1,3 @@@`. Un couple
# de plages par parent (`parents`), puis la position côté nouveau. Reconnu —
# bien que l'argv figé `diff --cached` n'en émette pas sur les versions
# actuelles de git — plutôt qu'ignoré : un format d'hunk non reconnu faisait
# relire les lignes `+` comme des en-têtes et les jeter **en silence**, à
# l'inverse du fail-closed (invariant 1).
_COMBINED_HUNK_HEADER: Final[re.Pattern[str]] = re.compile(
    r"^@@@ (?P<parents>(?:-\d+(?:,\d+)? )+)\+(?P<new>\d+)(?:,\d+)? @@@"
)

# Préfixe de hunk simple : `@` seul ne l'ouvre pas, mais toute ligne `@...`
# qui n'est pas un en-tête d'hunk lisible signale une sortie qu'on ne comprend
# pas — donc une information perdue.
_HUNK_PREFIX: Final[str] = "@@"

# Longueur maximale d'un en-tête de hunk combiné AVANT toute regex : un vrai
# en-tête tient en ~100 caractères (positions + `@@@`). Au-delà, `truncated`
# sans faire passer la regex dessus. Le motif est mesuré linéaire (la
# partition est déterministe, ~6 ms pour 100 Ko) : cette borne n'est pas la
# preuve, c'en est le garde-fou structurel — le temps d'analyse ne dépend
# plus du contenu, même si le motif est un jour remanié. Coût nul en
# production : notre argv figé n'émet jamais de hunk combiné, et au pire un
# en-tête valide à longue remorque serait signalé incomplet (fail-closed).
# Les en-têtes simples (`@@ `) sont linéaires sans imbrication : pas de borne.
_MAX_HUNK_HEADER_CHARS: Final[int] = 512

# `* Unmerged path x` : résumé que `git diff --cached` produit pour un chemin
# de l'index non résolu (merge en cours). Aucune ligne n'est montrée pour ce
# chemin, donc le parseur doit signaler l'incomplétude.
_UNMERGED_PATH: Final[str] = "* Unmerged path "

# Nombre de morceaux quand la ligne `Binary files` ne contient qu'un seul
# ` and ` : le découpage ancien/nouveau est alors non ambigu.
_BINARY_UNAMBIGUOUS_PARTS: Final[int] = 2


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    """Interrompt un sous-processus et attend sa fin sans bloquer ni lever."""
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait()
    except (subprocess.TimeoutExpired, OSError):
        pass


def _refuse_symlinked_root(root: Path) -> None:
    """Refuse une racine contenant un lien symbolique, comme `_resolve_root` (#22).

    La racine elle-même et chacun de ses ancêtres sont vérifiés par `lstat`
    (`is_symlink` ne suit pas les liens) : un lien dans ce chemin lève
    `ToolFailure` au lieu de faire lire la cible. Parité avec le mode arbre
    (`Scanner`), qui refuse ces mêmes racines : `scan` et `scan --staged`
    disent la même chose sur la même entrée.

    Ni `resolve()` ni existence exigées ici : une racine absente reste un
    diagnostic (`NOT_A_GIT_REPO` côté MCP, code 2 côté CLI), pas une panne
    de construction — seul le lien symbolique est refusé. Limite assumée :
    le contrôle vaut à la construction ; un lien échangé ensuite (TOCTOU)
    serait relu par git lui-même, et `is_repository()` compare des chemins
    résolus.
    """
    absolute = root.absolute()
    candidates: tuple[Path, ...] = (absolute, *absolute.parents)
    for candidate in candidates:
        if candidate.is_symlink():
            raise ToolFailure("INTERNAL")


@dataclass(frozen=True)
class StagedChange:
    """Un fichier ajouté ou modifié dans l'index, et le blob qui le porte.

    ``blob`` est le SHA de l'objet **indexé** (40 caractères en SHA-1, 64 en
    SHA-256) : c'est lui que la CLI scanne (#29). Le contenu n'est jamais
    rangé ici : il vit dans le dépôt d'objets, et l'appelant n'en tire
    qu'une empreinte.
    """

    path: str
    blob: str


class GitAccess:
    """Accès git en lecture seule, confiné à une racine de dépôt."""

    __slots__ = ("_git", "_root")

    def __init__(self, root: Path) -> None:
        _refuse_symlinked_root(root)
        self._root = root
        # Jamais le PATH hérité : un PATH compromis (poste, CI, direnv)
        # détournerait le binaire exécuté à chaque outil. `os.defpath`
        # (`/bin:/usr/bin` sur POSIX) est le défaut système sûr, pas une
        # liste codée en dur (portable : Nix, macOS...). Absent → panne
        # d'outillage, jamais de repli vers un PATH non fiable.
        binary = shutil.which("git", path=os.defpath)
        if binary is None:
            # Panne d'outillage : message statique, jamais de chemin ni de
            # contenu reflété (invariant 8).
            raise ToolFailure("INTERNAL")
        resolved = Path(binary).resolve()
        # Jamais un binaire sous la racine ni sous le répertoire courant :
        # sur win32, `shutil.which` préfixe le répertoire courant d'office
        # (`path.insert(0, curdir)` dans la stdlib, même avec un `path`
        # explicite) — lancé depuis la racine, un `git.exe`/`git.bat` piégé
        # dans le dépôt scanné serait exécuté à chaque outil (RCE). Sur POSIX
        # `os.defpath` est absolu donc ce refus est un filet dormant, mais il
        # couvre aussi un `defpath` vide ou relatif. Refus fail-closed,
        # avant tout usage du binaire : il n'est jamais exécuté.
        if resolved.is_relative_to(root.resolve()) or resolved.parent == Path.cwd().resolve():
            raise ToolFailure("INTERNAL")
        self._git = binary

    def execute(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        """Exécute une commande git figée (argv, jamais de shell).

        Les deux suppressions (`noqa`/`nosec`) sont justifiées : la liste
        d'arguments est entièrement construite par le programme — binaire
        git résolu hors PATH hérité, overrides `-c` puis constantes de ce
        module, et `arguments` qui vient du même module. Aucune valeur issue
        du LLM ou du contenu du dépôt n'entre dans la commande (ni dans sa
        configuration d'exécution), et ``shell=True`` n'est jamais utilisé.

        ``stdin=DEVNULL`` : sans lui le fils hérite du **canal stdio MCP**,
        c'est-à-dire du pipe JSON-RPC du serveur. Aucune sous-commande
        actuelle ne le lit (`GIT_TERMINAL_PROMPT=0` coupe aussi toute
        invite), mais un appel futur qui lirait stdin — ou un filtre qui
        lui parlerait — consommerait des octets du protocole ou bloquerait
        dessus : l'interférence serait pilotable par le dépôt scanné, donc
        on ne laisse pas l'héritage en place. Le garde-fou est statique
        (`tests/security/test_prompt_injection.py` refuse tout appel git
        sans `stdin=subprocess.DEVNULL`), pas seulement la ligne ci-dessous.
        """
        try:
            return subprocess.run(  # noqa: S603 # nosec B603
                [self._git, *GIT_CONFIG_OVERRIDES, "-C", str(self._root), *arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
                env=confined_environment(self._root),
            )
        except (OSError, subprocess.TimeoutExpired):
            # Panne d'outillage (binaire absent, délai dépassé) : message
            # statique, jamais de chemin ni de sortie git reflétés.
            raise ToolFailure("INTERNAL") from None

    def is_repository(self) -> bool:
        """True si la racine est un dépôt Git avec arbre de travail à cette racine exacte.

        Un code de retour non nul (« not a git repository ») ou une racine
        qui pointe vers un dépôt parent n'est PAS une panne : c'est le diagnostic
        attendu, traduit en ``NOT_A_GIT_REPO`` par l'appelant.
        """
        completed = self.execute(("rev-parse", "--show-toplevel"))
        if completed.returncode != 0:
            return False
        top = completed.stdout.strip().decode("utf-8", errors="replace")
        return Path(top).resolve() == self._root.resolve()

    def is_ignored(self, relative_path: str) -> bool:
        """True si le chemin est ignoré par les .gitignore du dépôt.

        `check-ignore` ne lit aucune configuration du dépôt et n'écrit rien.
        Il répond dès qu'une règle de `.gitignore` couvre le chemin, **même si
        le fichier est déjà suivi** : c'est la lecture stricte du contrat 4.2
        (« fichiers ignorés »), et la plus prudente. En cas de doute (code de
        retour inattendu), on refuse (fail-closed).
        """
        completed = self.execute(("check-ignore", "-q", "--", relative_path))
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        raise ToolFailure("INTERNAL")

    def staged_diff(self, max_bytes: int) -> tuple[bytes, bool]:
        """Sortie brute de ``git diff --cached``, lue en flux borné à ``max_bytes``.

        Pour éviter tout déni de service mémoire (OOM sur un dépôt piégé par
        un blob géant stagé), la sortie n'est JAMAIS bufferisée intégralement
        avant coupe : le flux stdout est lu jusqu'à au plus ``max_bytes + 1``
        octets. Si ce plafond est dépassé, le sous-processus est immédiatement
        interrompu (kill) et ``truncated: True`` est posé.

        La coupe tombe sur la dernière ligne COMPLÈTE : couper à l'octet
        près laisserait une ligne tronquée dont le masquage échouerait
        (guillemet fermant manquant → préfixe de secret en clair, plaçable
        à cheval par remplissage + `max_bytes` choisi). Le reste est
        signalé `truncated`, jamais présenté comme complet. Sans `\n`
        dans la coupe (en-tête géant : impossible avec un vrai git, dont
        la première ligne est courte), la coupe part telle quelle — une
        en-tête sans `\n` ne porte aucune ligne ajoutée à fuir.

        ``stdin=DEVNULL`` : le pipe JSON-RPC du serveur ne doit jamais être
        hérité par le fils (même raison que dans ``execute``).
        """
        try:
            proc = subprocess.Popen(  # noqa: S603 # nosec B603
                [self._git, *GIT_CONFIG_OVERRIDES, "-C", str(self._root), *DIFF_ARGUMENTS],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=confined_environment(self._root),
            )
        except OSError:
            raise ToolFailure("INTERNAL") from None

        timer = threading.Timer(GIT_TIMEOUT_SECONDS, proc.kill)
        timer.daemon = True
        timer.start()
        try:
            raw = b""
            if proc.stdout is not None:
                raw = proc.stdout.read(max_bytes + 1)
        except OSError:
            _terminate_process(proc)
            raise ToolFailure("INTERNAL") from None
        finally:
            timer.cancel()
            if proc.stdout is not None:
                proc.stdout.close()

        if len(raw) > max_bytes:
            _terminate_process(proc)
            return raw[:max_bytes].rsplit(b"\n", 1)[0], True

        try:
            ret = proc.wait(timeout=GIT_TIMEOUT_SECONDS)
        except (subprocess.TimeoutExpired, OSError):
            _terminate_process(proc)
            raise ToolFailure("INTERNAL") from None

        if ret != 0:
            raise ToolFailure("INTERNAL")

        return raw, False

    def staged_changes(self) -> list[StagedChange]:
        """Fichiers **ajoutés ou modifiés** dans l'index, et leur blob.

        Utilisé par la CLI ``heimdall scan --staged`` (#29) : l'index est la
        source de vérité de « ce que le commit va contenir », et le contenu
        indexé est lu **blob par blob**, sans aucune exclusion de chemin.
        Les suppressions et les gitlinks (sous-modules : leur SHA désigne
        un commit, pas un blob) sont ignorés — aucun texte à scanner.

        La sortie est lue en **flux borné** (:data:`MAX_STAGED_RAW_BYTES`),
        comme ``staged_diff`` : un index adverse de 100 000 entrées est
        coupé avant d'être bufferisé, puis refusé. Pas de coupe « propre »
        ici (contrairement au diff paginé du MCP) : une énumération
        incomplète ne vaut pas verdict, donc c'est ``ToolFailure``.

        L'index est non résolu (conflit de fusion) ou la sortie est illisible
        → ``ToolFailure`` : le scan ne peut alors pas prétendre avoir tout vu.
        """
        raw = self._read_capped(STAGED_RAW_ARGUMENTS, MAX_STAGED_RAW_BYTES)
        return parse_staged_raw(raw)

    def _read_capped(self, arguments: Sequence[str], max_bytes: int) -> bytes:
        """Sortie d'une commande git figée, lue en flux borné à ``max_bytes``.

        Même motif que ``staged_diff`` (argv figé, ``stdin=DEVNULL``,
        environnement confiné, délai) : le flux stdout est lu jusqu'à au
        plus ``max_bytes + 1`` octets. Au-delà, le sous-processus est tué et
        c'est ``ToolFailure`` — ici aucune coupe partielle n'est rendue :
        l'appelant ne sait exploiter qu'une énumération **complète**.
        """
        try:
            proc = subprocess.Popen(  # noqa: S603 # nosec B603
                [self._git, *GIT_CONFIG_OVERRIDES, "-C", str(self._root), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=confined_environment(self._root),
            )
        except OSError:
            raise ToolFailure("INTERNAL") from None

        timer = threading.Timer(GIT_TIMEOUT_SECONDS, proc.kill)
        timer.daemon = True
        timer.start()
        try:
            raw = b""
            if proc.stdout is not None:
                raw = proc.stdout.read(max_bytes + 1)
        except OSError:
            _terminate_process(proc)
            raise ToolFailure("INTERNAL") from None
        finally:
            timer.cancel()
            if proc.stdout is not None:
                proc.stdout.close()

        if len(raw) > max_bytes:
            _terminate_process(proc)
            raise ToolFailure("INTERNAL")

        try:
            ret = proc.wait(timeout=GIT_TIMEOUT_SECONDS)
        except (subprocess.TimeoutExpired, OSError):
            _terminate_process(proc)
            raise ToolFailure("INTERNAL") from None

        if ret != 0:
            raise ToolFailure("INTERNAL")

        return raw

    def blob_size(self, blob: str) -> int:
        """Taille en octets d'un objet git, **sans** le lire.

        L'appelant borne ainsi la lecture : un blob géant ne doit jamais
        être chargé en mémoire (déni de service).
        """
        completed = self.execute(("cat-file", "-s", _checked_object(blob)))
        if completed.returncode != 0:
            raise ToolFailure("INTERNAL")
        try:
            return int(completed.stdout.strip())
        except ValueError:
            raise ToolFailure("INTERNAL") from None

    def blob_bytes(self, blob: str) -> bytes:
        """Contenu **brut** d'un blob (celui de l'index, pas de la copie de
        travail).

        Aucun filtre ``textconv``, aucune conversion ``CRLF`` : c'est le
        contenu que git a indexé, octet pour octet. Le secret y figure —
        l'appelant ne le **montre** jamais (il n'en garde qu'une empreinte).
        """
        completed = self.execute(("cat-file", "blob", _checked_object(blob)))
        if completed.returncode != 0:
            raise ToolFailure("INTERNAL")
        return completed.stdout


@dataclass(frozen=True)
class DiffEntry:
    """Un fichier du diff : chemin validé et lignes ajoutées brutes.

    ``line_overflow`` signale que le fichier avait plus de
    ``MAX_LINES_PER_FILE`` lignes ajoutées : la liste est alors incomplète
    et l'appelant doit poser ``truncated``.
    """

    path: str
    binary: bool
    lines: tuple[tuple[int, str], ...]
    line_overflow: bool = False


#: En-tête du format « raw » de git : ``:mode mode sha sha statut``.
_RAW_HEADER_FIELDS: Final[int] = 5
#: Un nom d'objet git : 40 caractères (dépôt SHA-1) ou 64 (dépôt SHA-256).
#: Les deux formats sont acceptés : un dépôt `--object-format=sha256` est
#: parfaitement valide, et le refuser rendrait `--staged` inutilisable (#29).
_OBJECT_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
#: Statuts de `--raw` dont le blob indexé doit être scanné : ajout,
#: modification, changement de type (le nouveau contenu est scanné).
_SCAN_STATUSES: Final[frozenset[str]] = frozenset({"A", "M", "T"})


def _is_null_object(blob: str) -> bool:
    """True pour le SHA « nul » de git (40 ou 64 zéros) : l'objet n'existe pas."""
    return bool(blob) and set(blob) == {"0"}


def _checked_object(blob: str) -> str:
    """Valide un nom d'objet git avant de le mettre dans l'argv.

    Un SHA est hexadécimal : cette garde interdit qu'une chaîne venue d'une
    sortie git (ou d'un appelant) soit interprétée comme une option par git
    (``--upload-pack=…``), et qu'une valeur inattendue parte en argument.
    """
    if _OBJECT_PATTERN.fullmatch(blob) is None:
        raise ToolFailure("INTERNAL")
    return blob


def parse_staged_raw(raw: bytes) -> list[StagedChange]:
    """Analyse la sortie de ``git diff --cached --raw -z``.

    Rend la liste des fichiers **ajoutés ou modifiés** dans l'index (les
    suppressions sont ignorées : il n'y a plus de blob à scanner), avec le
    SHA du blob indexé. Les entrées gitlink (sous-modules, mode ``160000``)
    sont ignorées de la même façon : leur SHA désigne un commit, pas un
    blob, donc aucun texte à scanner.

    Sortie illisible, statut inconnu ou index non résolu (conflit de fusion,
    statut ``U``) → ``ToolFailure`` : mieux vaut une panne qu'un verdict
    « propre » sur un index qu'on n'a pas su lire (invariant 1).
    """
    text = raw[:-1] if raw.endswith(b"\0") else raw
    if not text:
        return []
    parts = text.split(b"\0")
    if len(parts) % 2 != 0:
        # En-tête et chemin doivent s'alterner : une sortie tronquée est
        # illisible, et une liste partielle ne vaut pas verdict propre.
        raise ToolFailure("INTERNAL")
    changes: list[StagedChange] = []
    for position in range(0, len(parts), 2):
        change = _staged_change(parts[position], parts[position + 1])
        if change is not None:
            changes.append(change)
    return changes


def _staged_change(header: bytes, path_bytes: bytes) -> StagedChange | None:
    """Un changement de l'index, ou ``None`` pour un fichier supprimé."""
    fields = header.split(b" ")
    if len(fields) != _RAW_HEADER_FIELDS or not fields[0].startswith(b":"):
        raise ToolFailure("INTERNAL")
    try:
        status = fields[4].decode("ascii")
    except UnicodeDecodeError:
        raise ToolFailure("INTERNAL") from None
    if not status:
        raise ToolFailure("INTERNAL")
    code = status[0]
    if code == "U":
        # Index non résolu (conflit de fusion) : git n'en montre aucun
        # contenu, et l'index ne correspond à aucun commit. Refus.
        raise ToolFailure("INTERNAL")
    if code == "D":
        return None
    if code not in _SCAN_STATUSES:
        raise ToolFailure("INTERNAL")
    if fields[1] == b"160000":
        # Entrée gitlink (sous-module) : le SHA indexé désigne un **commit**,
        # pas un blob — il n'y a aucun texte à scanner (`cat-file blob`
        # échouerait avec `bad file`). Ignoré comme les suppressions, pas une
        # erreur : un sous-module stagé ne doit pas faire échouer tout le
        # scan (#29). Seul le mode **indexé** compte : un passage gitlink →
        # fichier (`T` vers 100644) porte un vrai blob et reste scanné.
        return None
    try:
        blob = fields[3].decode("ascii")
    except UnicodeDecodeError:
        raise ToolFailure("INTERNAL") from None
    if _is_null_object(blob) or _OBJECT_PATTERN.fullmatch(blob) is None:
        raise ToolFailure("INTERNAL")
    try:
        path = path_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ToolFailure("INTERNAL") from None
    try:
        # Contrat Finding v1 (#14) : 4096 caractères, segments non vides,
        # sans `.`/`..`, sans `\`, `:` ni caractère de contrôle. C'est la
        # **seule** limite de chemin de la CLI : `FileTarget` revalide avec
        # exactement la même fonction, donc aucune divergence 1024/4096.
        validate_relative_path(path)
    except ValueError:
        # Un nom de fichier que le contrat ne sait pas représenter ne peut
        # pas être montré ni rejoué : la sortie est refusée, pas tronquée.
        raise ToolFailure("INTERNAL") from None
    return StagedChange(path=path, blob=blob)


@dataclass
class _EntryBuilder:
    """Fichier en cours de lecture dans la sortie git."""

    path: str | None = None
    binary: bool = False
    lines: list[tuple[int, str]] = field(default_factory=list)
    line_overflow: bool = False

    def entry(self) -> DiffEntry | None:
        """Matérialise l'entrée, ou None si le fichier n'a rien à montrer."""
        if self.path is None or not (self.binary or self.lines):
            # Pas de `+++` ni de `rename to` : aucune ligne ajoutée possible
            # (les hunks suivent toujours l'en-tête `+++`). Rien à montrer.
            return None
        return DiffEntry(self.path, self.binary, tuple(self.lines), self.line_overflow)


# Un chemin cité par git fait au moins deux caractères (``"x"``) ; en dessous,
# ce n'est pas une citation C à décoder.
_QUOTED_MIN_LENGTH: Final[int] = 2


# Bornes du décodeur C-quote : `\xHH` fait exactement 2 chiffres hexa, un
# octet tient sur 3 chiffres octaux au plus et vaut 0..255.
_HEX_ESCAPE_LENGTH: Final[int] = 2
_MAX_OCTAL_DIGITS: Final[int] = 3
_MAX_SINGLE_BYTE: Final[int] = 0xFF


def _unquote_path(value: str) -> str:
    """Décode le guillemetage C de git (``"caf\\303\\251.py"`` → ``café.py``).

    Les échappements sont décodés en **octets** puis l'ensemble est décodé
    en UTF-8 : décoder chaque échappement en caractère produirait du
    mojibake (``\\303`` → `Ã` au lieu de l'octet 0xC3 de ``é``), donc un
    faux nom de fichier — avec un aller-retour `read_diff` →
    `sanitize_file` cassé (404 sur le vrai nom).
    Tout le jeu d'échappements de git est couvert (`\\a\\b\\f\\n\\r\\t\\v`,
    octal, `\\xHH`) ; tout le reste après un antislash, ou des octets qui
    ne sont pas de l'UTF-8 valide, est une panne (`INTERNAL`, fail-closed :
    un nom de fichier non représentable ne doit pas renvoyer un résultat
    partiel présenté comme complet).
    """
    if len(value) < _QUOTED_MIN_LENGTH or not value.startswith('"') or not value.endswith('"'):
        return value
    body = value[1:-1]
    raw = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            raw.extend(char.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise ToolFailure("INTERNAL")
        esc = body[index]
        if esc in _SIMPLE_ESCAPES:
            raw.append(_SIMPLE_ESCAPES[esc])
            index += 1
        elif esc == "x":
            digits = body[index + 1 : index + 1 + _HEX_ESCAPE_LENGTH]
            if len(digits) != _HEX_ESCAPE_LENGTH or any(
                c not in "0123456789abcdefABCDEF" for c in digits
            ):
                raise ToolFailure("INTERNAL")
            raw.append(int(digits, 16))
            index += 1 + _HEX_ESCAPE_LENGTH
        elif esc in "01234567":
            end = index
            while end < len(body) and end < index + _MAX_OCTAL_DIGITS and body[end] in "01234567":
                end += 1
            code = int(body[index:end], 8)
            if code > _MAX_SINGLE_BYTE:
                raise ToolFailure("INTERNAL")
            raw.append(code)
            index = end
        else:
            raise ToolFailure("INTERNAL")
    try:
        return bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise ToolFailure("INTERNAL") from None


# Échappements simples du guillemetage C de git → octet.
_SIMPLE_ESCAPES: Final[dict[str, int]] = {
    "a": 0x07,
    "b": 0x08,
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": 0x5C,
    '"': 0x22,
}


def _path_from_header(value: str) -> str | None:
    """Chemin depuis un en-tête ``--- a/x`` / ``+++ b/x``.

    Renvoie ``None`` quand l'en-tête ne nomme aucun côté « nouveau »
    (``/dev/null`` : fichier supprimé) et lève ``ToolFailure`` quand le
    chemin existe mais n'est pas représentable dans le contrat. Les deux
    pièges traités ici, sinon le parseur renverrait ``INVALID_INPUT`` sur
    une sortie qu'il a lui-même fabriquée (contrat 4.1) :

    1. git annonce ``/dev/null`` pour un fichier ajouté ou supprimé. C'est
       un chemin absolu, refusé par ``RelPath`` : il ne nomme rien ;
    2. git suffixe d'une tabulation les chemins contenant une espace (place
       réservée à l'horodatage) ; on ne garde que le premier champ.

    Un chemin cité mais irreprésentable (caractère de contrôle, ``..``,
    préfixe de lecteur…) est une **panne** et non un fichier ignoré : le
    diff porterait alors des lignes que le LLM ne verrait pas, sans le
    savoir. Mieux vaut refuser de répondre (``INTERNAL``) que renvoyer un
    résultat partiel présenté comme complet.
    """
    if "\t" in value:
        value = value.split("\t", 1)[0]
    if value == "/dev/null":
        return None
    value = _unquote_path(value)
    # git préfixe les deux côtés (`a/`, `b/`, ou `i/`/`w/` avec
    # diff.mnemonicPrefix). On ne retire que deux caractères, et seulement
    # si le reste reste un chemin relatif valide : un dépôt peut légitimement
    # s'appeler `a/truc`.
    for prefix in ("a/", "b/", "i/", "w/", "o/", "c/"):
        if value.startswith(prefix) and is_rel_path(value[2:]):
            return value[2:]
    if not is_rel_path(value):
        raise ToolFailure("INTERNAL")
    return value


class _DiffParser:
    """Machine à états sur la sortie de ``git diff --cached --unified=0``.

    Distinction indispensable : tant qu'aucun ``@@`` n'a ouvert un hunk,
    les lignes sont des en-têtes de fichier ; dès qu'un hunk est ouvert, une
    ligne qui ne commence pas par ``+``, ``-``, `` `` ou ``\\`` le referme et
    doit être relue comme un en-tête. Sans cette règle, une ligne ajoutée
    telle que ``+++ b/x`` serait prise pour un en-tête, et inversement.

    Principe commun aux formats non reconnus (en-tête de hunk illisible,
    chemin non fusionné) : on pose ``truncated`` au lieu de laisser croire à
    une réponse complète. Invariant 1 : mieux vaut une information incomplète
    annoncée qu'un contenu absent en silence.
    """

    def __init__(self) -> None:
        self.entries: list[DiffEntry] = []
        self.truncated: bool = False
        self._builder: _EntryBuilder | None = None
        self._in_hunk: bool = False
        self._new_line: int = 0
        # Nombre de parents d'un hunk combiné (= 1 hors fusion) : le corps
        # porte un caractère de préfixe PAR PARENT (`+` ajouté, `-` absent,
        # espace contexte), donc le découpage des lignes en dépend.
        self._parents: int = 1

    def feed(self, text: str) -> tuple[list[DiffEntry], bool]:
        for raw in text.split("\n"):
            self._feed(raw)
        self._flush()
        return self.entries, self.truncated

    def _flush(self) -> None:
        builder, self._builder = self._builder, None
        self._in_hunk = False
        self._new_line = 0
        self._parents = 1
        if builder is None:
            return
        if builder.binary and builder.path is None:
            # Binaire innommable : un binaire ne porte aucune ligne à
            # montrer, mais son absence doit être signalée (information
            # incomplète), jamais escamotée en silence — et sans tuer
            # toute la réponse pour un nom (disponibilité).
            self.truncated = True
            return
        entry = builder.entry()
        if entry is None:
            return
        if len(self.entries) < MAX_FILES:
            self.entries.append(entry)
        else:
            self.truncated = True

    def _feed(self, raw: str) -> None:
        if raw.startswith("diff --git ") or raw.startswith("diff --cc "):
            self._flush()
            self._builder = _EntryBuilder()
            return
        if raw.startswith("diff "):
            # Directive inconnue (`diff --combined`, futur format git…) : le
            # fichier courant est clos, un nouveau est ouvert, et l'incomplet
            # est signalé — jamais de silence avec `truncated=False`
            # (invariant 1). Inatteignable avec l'argv figé actuel, qui
            # n'émet que `diff --git ` : garde défensive, pas du code mort.
            self._flush()
            self._builder = _EntryBuilder()
            self.truncated = True
            return
        if raw.startswith(_UNMERGED_PATH):
            # `* Unmerged path x` : l'index porte un chemin non résolu (merge
            # en cours), et git n'en montre alors aucune ligne.
            self.truncated = True
            return
        builder = self._builder
        if builder is None:
            return  # rien avant le premier fichier
        if self._in_hunk and raw[:1] not in ("+", "-", " ", "\\"):
            self._in_hunk = False
        if not self._in_hunk:
            try:
                self._header(builder, raw)
            except ToolFailure:
                # Nom irreprésentable (contrôle, `..`, absolu…) : le FICHIER
                # est abandonné, pas la réponse — `truncated` signale
                # l'incomplet, comme pour tout plafond (`MAX_FILES`, budget,
                # binaire innommable). Cohérence délibérée : tous les plafonds
                # cachent du contenu derrière le même drapeau, et un seul nom
                # piégé n'aveugle plus le tri des autres fichiers. Les lignes
                # déjà lues pour ce fichier partent avec lui ; les suivantes
                # sont ignorées jusqu'au prochain `diff --git`.
                self._builder = None
                self._in_hunk = False
                self._new_line = 0
                self._parents = 1
                self.truncated = True
            return
        self._hunk_line(builder, raw)

    def _header(self, builder: _EntryBuilder, raw: str) -> None:
        if raw.startswith("+++ "):
            path = _path_from_header(raw[4:])
            if path is not None:
                builder.path = path
            return
        if raw.startswith("rename to "):
            path = _path_from_header(raw[len("rename to "):].strip())
            if path is not None:
                builder.path = path
            return
        if raw.startswith("copy to "):
            path = _path_from_header(raw[len("copy to "):].strip())
            if path is not None:
                builder.path = path
            return
        if raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            builder.binary = True
            # ``Binary files /dev/null and b/x differ`` : sans `+++`, c'est la
            # seule ligne qui porte le côté nouveau du chemin. `GIT binary
            # patch` (jamais émis sans `--binary`, que nous ne passons pas)
            # ne nomme rien : on ne lui applique pas le découpage prévu
            # pour l'autre forme (offset faux → nom fantôme).
            if builder.path is None and raw.startswith("Binary files "):
                path = _binary_path(raw)
                if path is not None:
                    builder.path = path
            return
        if raw.startswith(_HUNK_PREFIX):
            self._hunk_header(raw)

    def _hunk_header(self, raw: str) -> None:
        """Ouvre un hunk, ou signale la sortie qu'on n'a pas comprise.

        Deux grammaires, une seule règle : ce qui n'est pas reconnu pose
        ``truncated``. Sans elle, les lignes ``+`` suivantes seraient
        relues comme des en-têtes et jetées sans rien dire — un silence,
        pas un fail-closed (invariant 1).
        """
        match: re.Match[str] | None = None
        parents = 0
        if raw.startswith("@@ "):
            match = _HUNK_HEADER.match(raw)
            parents = 1
        elif raw.startswith("@@@ "):
            if len(raw) > _MAX_HUNK_HEADER_CHARS:
                # Trop long pour un en-tête : pas de regex dessus
                # (fail-closed, comme un en-tête illisible).
                self.truncated = True
                return
            match = _COMBINED_HUNK_HEADER.match(raw)
            # Un couple de plages par parent, chacune `-début[,nb] ` : compter
            # les tirets du préfixe donne donc le nombre de parents, celui
            # qui décide du nombre de caractères de préfixe par ligne.
            if match is not None:
                parents = match.group("parents").count("-")
        if match is None:
            self.truncated = True
            return
        self._parents = parents
        self._in_hunk = True
        self._new_line = int(match.group("new"))

    def _hunk_line(self, builder: _EntryBuilder, raw: str) -> None:
        if self._parents == 1:
            # Ligne retirée, contexte (absent avec --unified=0) ou
            # « \ No newline at end of file » : rien à compter.
            if raw.startswith("+"):
                self._append(builder, raw[1:])
            return
        # Hunk combiné : un caractère de préfixe par parent (`+` ajouté à
        # ce parent, `-` absent, espace contexte). La ligne appartient au
        # résultat si AUCUN préfixe n'est `-` ; elle n'est « ajoutée » que si
        # elle l'est côté TOUS les parents (sinon c'est un contexte chez
        # l'un d'eux, pas une ligne que le commit ajoute au fichier).
        prefixes = raw[: self._parents]
        if len(prefixes) < self._parents:
            # Corps plus court que le nombre de parents : grammaire incomprise
            # (fail-closed, comme un en-tête d'hunk illisible).
            self.truncated = True
            return
        if "-" in prefixes:
            return  # absente du fichier côté nouveau
        if prefixes == "+" * self._parents:
            self._append(builder, raw[self._parents :])
            return
        self._new_line += 1  # contexte : occupe une ligne, sans en être ajoutée

    def _append(self, builder: _EntryBuilder, text: str) -> None:
        """Enregistre une ligne ajoutée, numérotée côté nouveau."""
        if len(builder.lines) >= MAX_LINES_PER_FILE:
            self.truncated = True
            builder.line_overflow = True
            return
        builder.lines.append((self._new_line, text))
        self._new_line += 1


def parse_diff(text: str) -> tuple[list[DiffEntry], bool]:
    """Analyse la sortie de ``git diff --cached --unified=0``.

    Renvoie les fichiers avec leurs lignes ajoutées (brutes : le masquage est
    appliqué plus haut, avant sérialisation) et un drapeau signalant qu'une
    limite du contrat a été atteinte. Un chemin que la grammaire ``RelPath``
    refuse fait abandonner le FICHIER (`truncated=True`), jamais la réponse :
    comme pour tout plafond, l'incomplet est signalé, la réponse survit. Un nom
    irreprésentable ne peut pas être montré (ni ses lignes cachées en
    silence), et `INTERNAL` pour un seul nom piégé aveuglerait le tri des
    autres fichiers.
    """
    return _DiffParser().feed(text)


def _strip_binary_side(raw: str) -> str:
    """Côté d'une ligne ``Binary files`` sans validation ni préfixe git.

    Miroir de ``_path_from_header`` sans le contrôle ``RelPath`` (qui lève)
    : pour CHERCHER le bon découpage, pas pour décider. Seul le préfixe est
    retiré (pas de découpe sur tabulation : les deux côtés nommant le même
    fichier, elle ne changerait aucune égalité). Le côté retenu est toujours
    validé ensuite par ``_path_from_header`` (qui lève `INTERNAL` sur un nom
    irreprésentable, comme avant).
    """
    for prefix in ("a/", "b/", "i/", "w/", "o/", "c/"):
        if raw.startswith(prefix):
            return raw[2:]
    return raw


def _binary_path(line: str) -> str | None:
    """Chemin côté nouveau depuis ``Binary files a/x and b/y differ``.

    Les cas ajout/suppression sont traités en priorité : ``/dev/null``
    est un marqueur git, jamais un nom de fichier, donc le découpage y
    est exact même si le vrai nom contient ``" and "``. Pour un binaire
    **modifié**, l'ancien et le nouveau côté nomment le MÊME fichier :
    on essaie chaque découpe sur ``" and "`` et on retient celle où les
    deux côtés désignent le même chemin (ex. ``a/f and g.bin and b/f and
    g.bin`` → ``f and g.bin`` ; l'ancien ``rpartition`` rendait ``g.bin``,
    cassant l'aller-retour `read_diff` → `sanitize_file`). Découpe unique
    sans égalité (renommage sans en-têtes) : repli sur le côté nouveau,
    comme avant. Plusieurs découpes sans égalité : vraiment ambigu (git ne
    cite pas les espaces) → `None`, signalé `truncated` par l'appelant,
    jamais un nom tronqué. Pas de fuite dans tous les cas (un binaire ne
    porte aucune ligne, seul son nom est affiché).
    """
    body = line[len("Binary files ") :]
    separator = " and "
    if not body.endswith(" differ") or separator not in body:
        return None
    body = body[: -len(" differ")]
    if body.startswith("/dev/null" + separator):
        return _path_from_header(body[len("/dev/null" + separator) :])
    if body.endswith(separator + "/dev/null"):
        return None  # binaire supprimé : aucun côté nouveau à nommer.
    parts = body.split(separator)
    matches: list[str] = []
    for index in range(1, len(parts)):
        old_raw = separator.join(parts[:index])
        new_raw = separator.join(parts[index:])
        if not new_raw:
            continue
        if _strip_binary_side(old_raw) == _strip_binary_side(new_raw):
            matches.append(new_raw)
    # Pas de cas "plusieurs concordances" : deux découpes concordantes
    # distinctes sont impossibles (le séparateur fait 5 caractères, le
    # préfixe retiré 0 ou 2 — les deux égalités exigeraient une longueur
    # négative pour le segment médian, vérifié par recherche exhaustive).
    # Une seule concordance suffit donc, sans ambiguïté ; sinon, repli ou
    # `None` (incomplet signalé, jamais un nom tronqué).
    if len(matches) == 1:
        new_side: str | None = matches[0]
    elif len(parts) == _BINARY_UNAMBIGUOUS_PARTS and parts[1]:
        # Découpe unique sans concordance (renommage sans en-têtes) : repli
        # sur le côté nouveau, comme avant.
        new_side = parts[1]
    else:
        new_side = None
    if new_side is None:
        return None
    return _path_from_header(new_side)
