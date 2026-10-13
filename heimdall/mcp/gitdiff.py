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
- **options du contrat imposées** : ``--no-ext-diff`` et ``--no-textconv``
  empêchent git d'exécuter ``diff.external`` ou les filtres ``textconv``
  configurés dans le dépôt — de l'exécution de commande pilotée par le
  contenu scanné, donc l'interdit I5 contournable par configuration ;
- **limites dures** (200 fichiers, 5000 lignes par fichier, 2000
  caractères par ligne) : au-delà, la sortie est tronquée et le drapeau
  ``truncated`` est posé, jamais un résultat partiel présenté comme
  complet.
"""

import os
import re
import shutil
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.paths import is_rel_path

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
    }


# Délai maximal d'une commande git : un diff qui ne répond pas est une panne
# d'outillage (INTERNAL), pas une attente sans fin.
GIT_TIMEOUT_SECONDS: Final[float] = 30.0

# Plafonds d'affichage du contrat 4.1.
MAX_FILES: Final[int] = 200
MAX_LINES_PER_FILE: Final[int] = 5000
MAX_LINE_CHARS: Final[int] = 2000

# `@@ -12,0 +1,3 @@ fonction; seule la position côté nouveau compte.
_HUNK_HEADER: Final[re.Pattern[str]] = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitAccess:
    """Accès git en lecture seule, confiné à une racine de dépôt."""

    __slots__ = ("_git", "_root")

    def __init__(self, root: Path) -> None:
        self._root = root
        binary = shutil.which("git")
        if binary is None:
            # Panne d'outillage : message statique, jamais de chemin ni de
            # contenu reflété (invariant 8).
            raise ToolFailure("INTERNAL")
        self._git = binary

    def execute(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        """Exécute une commande git figée (argv, jamais de shell).

        Les deux suppressions (`noqa`/`nosec`) sont justifiées : la liste
        d'arguments est entièrement construite par le programme — binaire
        git résolu par ``shutil.which`` puis des constantes de ce module, et
        ``arguments`` qui vient du même module. Aucune valeur issue du LLM
        ou du contenu du dépôt n'entre dans la commande, et ``shell=True``
        n'est jamais utilisé.
        """
        try:
            return subprocess.run(  # noqa: S603 # nosec B603
                [self._git, "-C", str(self._root), *arguments],
                capture_output=True,
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
                env=confined_environment(self._root),
            )
        except (OSError, subprocess.TimeoutExpired):
            # Panne d'outillage (binaire absent, délai dépassé) : message
            # statique, jamais de chemin ni de sortie git reflétés.
            raise ToolFailure("INTERNAL") from None

    def run(self, arguments: Sequence[str]) -> bytes:
        """Exécute une commande git figée et renvoie sa sortie standard."""
        completed = self.execute(arguments)
        if completed.returncode != 0:
            raise ToolFailure("INTERNAL")
        return completed.stdout

    def is_repository(self) -> bool:
        """True si la racine est un dépôt Git avec arbre de travail.

        Un code de retour non nul (« not a git repository ») n'est PAS une
        panne : c'est le diagnostic attendu, traduit en ``NOT_A_GIT_REPO``
        par l'appelant.
        """
        completed = self.execute(("rev-parse", "--is-inside-work-tree"))
        return completed.returncode == 0 and completed.stdout.strip() == b"true"

    def is_ignored(self, relative_path: str) -> bool:
        """True si le chemin est ignoré par les .gitignore du dépôt.

        `check-ignore` ne lit aucune configuration du dépôt et n'écrit rien.
        En cas de doute (code de retour inattendu), on refuse (fail-closed).
        """
        completed = self.execute(("check-ignore", "-q", "--", relative_path))
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        raise ToolFailure("INTERNAL")

    def staged_diff(self, max_bytes: int) -> tuple[bytes, bool]:
        """Sortie brute de ``git diff --cached``, plafonnée à ``max_bytes``."""
        raw = self.run(DIFF_ARGUMENTS)
        if len(raw) <= max_bytes:
            return raw, False
        return raw[:max_bytes], True


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


def _unquote_path(value: str) -> str:
    """Retire le guillemaget C de git (``"a/ta\\tb"`` → ``a/ta<TAB>b``)."""
    if len(value) < _QUOTED_MIN_LENGTH or not value.startswith('"') or not value.endswith('"'):
        return value
    body = value[1:-1]

    def replace(match: re.Match[str]) -> str:
        escape = match.group(0)
        if escape.startswith("\\x"):
            return chr(int(escape[2:], 16))
        if escape.startswith("\\"):
            digits = escape[1:]
            if digits and all("0" <= c <= "7" for c in digits):
                return chr(int(digits, 8))
            return {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(digits, escape)
        return escape

    return _C_ESCAPE.sub(replace, body)


_C_ESCAPE: Final[re.Pattern[str]] = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrt\\\"]")


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
    """

    def __init__(self) -> None:
        self.entries: list[DiffEntry] = []
        self.truncated: bool = False
        self._builder: _EntryBuilder | None = None
        self._in_hunk: bool = False
        self._new_line: int = 0

    def feed(self, text: str) -> tuple[list[DiffEntry], bool]:
        for raw in text.split("\n"):
            self._feed(raw)
        self._flush()
        return self.entries, self.truncated

    def _flush(self) -> None:
        builder, self._builder = self._builder, None
        self._in_hunk = False
        self._new_line = 0
        if builder is None:
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
        builder = self._builder
        if builder is None:
            return  # rien avant le premier fichier
        if self._in_hunk and raw[:1] not in ("+", "-", " ", "\\"):
            self._in_hunk = False
        if not self._in_hunk:
            self._header(builder, raw)
            return
        self._hunk_line(builder, raw)

    def _header(self, builder: _EntryBuilder, raw: str) -> None:
        if raw.startswith("+++ "):
            path = _path_from_header(raw[4:])
            if path is not None:
                builder.path = path
            return
        if raw.startswith("rename to ") or raw.startswith("copy to "):
            path = _path_from_header(raw[10:].strip())
            if path is not None:
                builder.path = path
            return
        if raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            builder.binary = True
            # ``Binary files /dev/null and b/x differ`` : sans `+++`, c'est la
            # seule ligne qui porte le côté nouveau du chemin.
            if builder.path is None:
                path = _binary_path(raw)
                if path is not None:
                    builder.path = path
            return
        if raw.startswith("@@ "):
            match = _HUNK_HEADER.match(raw)
            if match is None:
                return
            self._in_hunk = True
            self._new_line = int(match.group(1))

    def _hunk_line(self, builder: _EntryBuilder, raw: str) -> None:
        if raw.startswith("+"):
            if len(builder.lines) >= MAX_LINES_PER_FILE:
                self.truncated = True
                builder.line_overflow = True
                return
            builder.lines.append((self._new_line, raw[1:]))
            self._new_line += 1
            return
        # Ligne retirée, contexte (absent avec --unified=0) ou
        # « \ No newline at end of file » : rien à compter.


def parse_diff(text: str) -> tuple[list[DiffEntry], bool]:
    """Analyse la sortie de ``git diff --cached --unified=0``.

    Renvoie les fichiers avec leurs lignes ajoutées (brutes : le masquage est
    appliqué plus haut, avant sérialisation) et un drapeau signalant qu'une
    limite du contrat a été atteinte. Un chemin que la grammaire ``RelPath``
    refuse est une panne (``INTERNAL``) : mieux vaut refuser de répondre que
    renvoyer une réponse non conforme au contrat.
    """
    return _DiffParser().feed(text)


def _binary_path(line: str) -> str | None:
    """Chemin côté nouveau depuis ``Binary files a/x and b/y differ``."""
    body = line[len("Binary files ") :]
    separator = " and "
    if not body.endswith(" differ") or separator not in body:
        return None
    body = body[: -len(" differ")]
    _old, _, new = body.rpartition(separator)
    if not new:
        return None
    return _path_from_header(new)
