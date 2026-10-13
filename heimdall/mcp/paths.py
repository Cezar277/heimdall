"""Chemins : grammaire du contrat #16 et **garde de chemin unique** (#76).

Une seule fonction décide de ce qui est lisible : ``confine``. Tous les
outils qui reçoivent un chemin l'appellent, et rien d'autre ne touche au
système de fichiers. La remédiation (#30) la réutilisera telle quelle.

La garde fait trois choses, dans cet ordre :

1. **Refus de forme** — chaîne non vide, sans caractère de contrôle, sans
   segment vide, ``.`` ou ``..``, et surtout **jamais absolue** ;
2. **Résolution réelle** — ``resolve()`` suit les liens symboliques : un
   lien du dépôt qui pointe vers `/etc` se résout hors de la racine ;
3. **Vérification de confinement** — ``is_relative_to(racine)`` sur des
   ``Path`` **résolus**, jamais une comparaison de chaînes : ``/repo-evil``
   commence par ``/repo``, et une garde bâtie sur ``startswith`` laisserait
   passer la traversée.

Pourquoi recopier le motif ``RelPath`` plutôt que valider avec
``jsonschema`` : le serveur ne doit pas dépendre d'une bibliothèque de
validation à l'exécution, et une sortie non conforme doit être refusée au
moment où elle est fabriquée, pas relue après coup. La recopie est protégée
par un test de dérive (``test_rel_path_grammar_matches_the_contract``) qui
rejoue le motif du schéma sur un corpus de chemins.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# Équivalent Python exact du champ ``pattern`` de ``$defs.RelPath`` dans
# schemas/mcp-tools.schema.json. Points porteurs :
#   - ``(?!.*(?:^|/)\.{1,2}(?:/|(?![\s\S])))`` interdit tout segment ``.``
#     ou ``..`` (chemin relatif seulement) ;
#   - les classes de caractères refusent ``/`` (séparateur), ``\\``
#     (Windows), ``:`` (lecteur, URI) et les caractères de contrôle ;
#   - ``(?![\\s\\S])`` termine la chaîne : ``$`` ancrerait la fin AVANT un
#     saut de ligne final, donc ``KEY=\\n`` passerait le contrôle.
REL_PATH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?!.*(?:^|/)\.{1,2}(?:/|(?![\s\S])))"
    r"[^/\\:\x00-\x1f\x7f\u2028\u2029]+"
    r"(?:/[^/\\:\x00-\x1f\x7f\u2028\u2029]+)*"
    r"(?![\s\S])"
)

# Longueur maximale du contrat (RelPath.maxLength). Un chemin plus long
# qu'un kilo-octet dans un dépôt est un signal d'attaque, pas un cas
# d'usage (cf. écart assumé avec le contrat Finding #14).
REL_PATH_MAX_LENGTH: Final[int] = 1024

# Caractères de contrôle déjà refusés par le motif : rappelés ici car la
# garde les rejette explicitement, avec un message dédié, avant même la
# grammaire. Un octet nul dans un chemin est une tentative d'injection
# classique (troncature côté système).
_FORBIDDEN_CHARACTERS: Final[frozenset[str]] = frozenset(
    chr(code) for code in [0x00, *range(0x01, 0x20), 0x7F, 0x2028, 0x2029]
)

# Formes absolues : POSIX, disque Windows, partage UNC. Refusées AVANT la
# résolution, car ``Path("/etc/passwd")`` construit déjà le chemin absolu.
_ABSOLUTE_PREFIXES: Final[tuple[str, ...]] = ("/", "\\")

# Longueur d'une désignation de disque (`C:`), forme Windows.
_DRIVE_LENGTH: Final[int] = 2


class PathEscape(Exception):
    """Le chemin fourni sort de la racine du dépôt (contrat #16, PATH_ESCAPE).

    Exception interne : elle ne quitte jamais le serveur, ``tool_handler``
    la traduit en enveloppe ``{"error": {"code": "PATH_ESCAPE"}}``.
    """


@dataclass(frozen=True)
class ConfinedPath:
    """Résultat de la garde : un chemin absolu résolu + sa forme relative.

    ``relative`` est **canonique** : il est reconstruit depuis le chemin
    résolu, pas recopié depuis l'entrée. Le LLM ne peut donc ni faire
    apparaître un ``..`` dans la réponse, ni reconnaître sa propre entrée
    invariante 8 — aucune entrée reflétée.
    """

    absolute: Path
    relative: str


def is_rel_path(value: object) -> bool:
    """True si ``value`` respecte la grammaire ``RelPath`` du contrat."""
    if not isinstance(value, str):
        return False
    if not 1 <= len(value) <= REL_PATH_MAX_LENGTH:
        return False
    if any(character in _FORBIDDEN_CHARACTERS for character in value):
        return False
    return REL_PATH_PATTERN.match(value) is not None


def _is_absolute(value: str) -> bool:
    """Refus explicite des chemins absolus, toutes formes confondues."""
    if value.startswith(_ABSOLUTE_PREFIXES):
        return True
    # `C:/…`, `C:\…` : refusés même si le processus tourne sous Windows,
    # car le contrat interdit les `:` dans RelPath.
    return len(value) >= _DRIVE_LENGTH and value[1] == ":" and value[0].isalpha()


def _segments(value: str) -> tuple[str, ...]:
    """Segments du chemin, séparés par ``/`` uniquement (jamais ``\\``)."""
    return tuple(value.split("/"))


def confine(root: Path, untrusted_path: object) -> ConfinedPath:
    """Résout ``untrusted_path`` dans ``root``, ou lève ``PathEscape``.

    ``untrusted_path`` est une **donnée non fiable** (elle vient du LLM) :
    elle est traitée comme telle, sans jamais être utilisée pour autre
    chose qu'un nom de fichier relatif. ``root`` est la racine du dépôt,
    fixée au démarrage du serveur et déjà résolue.
    """
    if not isinstance(untrusted_path, str) or not untrusted_path:
        raise PathEscape
    if any(character in _FORBIDDEN_CHARACTERS for character in untrusted_path):
        raise PathEscape
    if _is_absolute(untrusted_path):
        raise PathEscape
    if not is_rel_path(untrusted_path):
        # `..`, `.`, segment vide, `\`, `:`, chaîne trop longue : refusés
        # ici plutôt que dans la résolution, avec un message unique.
        raise PathEscape
    segments = _segments(untrusted_path)
    if any(segment in ("", ".", "..") for segment in segments):
        raise PathEscape

    resolved_root = root.resolve()
    # `joinpath` sur des segments déjà validés : pas de valeur recyclée
    # depuis l'entrée, donc pas de trajectoire empilée.
    candidate = resolved_root.joinpath(*segments).resolve()
    if not candidate.is_relative_to(resolved_root):
        # Lien symbolique sortant, `..` résolu, racine différente.
        raise PathEscape

    relative = candidate.relative_to(resolved_root).as_posix()
    if not is_rel_path(relative):
        # Fichier réel dont le nom contient un caractère interdit par le
        # contrat (tabulation, newline) : il ne peut pas être représenté
        # dans une réponse, donc il n'est pas lisible.
        raise PathEscape
    return ConfinedPath(absolute=candidate, relative=relative)
