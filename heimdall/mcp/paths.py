"""Chemins relatifs : grammaire du contrat #16 (``$defs.RelPath``).

Ce module ne fait que refléter la grammaire gelée du contrat. La **garde de
chemin** proprement dite — résolution réelle, refus des chemins absolus et
des liens symboliques sortants — arrive avec le sous-ticket #76
(``resolve_within_root``) et sera la seule fonction à appeler côté outils.

Pourquoi recopier le motif plutôt que valider les sorties avec
``jsonschema`` : le serveur ne doit pas dépendre d'une bibliothèque de
validation à l'exécution, et une sortie non conforme doit être refusée
au moment où elle est fabriquée, pas relue après coup. La recopie est
protégée par un test de dérive (``test_rel_path_grammar_matches_the_contract``)
qui rejoue le motif du schéma sur un corpus de chemins.
"""

import re
from typing import Final

# Équivalent Python exact du champ ``pattern`` de ``$defs.RelPath`` dans
# schemas/mcp-tools.schema.json. Points porteurs :
#   - ``(?!.*(?:^|/)\.{1,2}(?:/|(?![\s\S])))`` interdit tout segment ``.``
#     ou ``..`` (chemin relatif seulement) ;
#   - les classes de caractères refusent ``/`` (séparateur), ``\\``
#     ( Windows), ``:`` (lecteur, URI) et les caractères de contrôle ;
#   - ``(?![\\s\\S])`` termine la chaîne : ``$`` ancrerait la fin AVANT un
#     saut de ligne final, donc ``KEY=\\n`` passerait le contrôle.
# Le motif n'est pas ancré au début par ``re.match`` implicite : il commence
# par ``^``.
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


def is_rel_path(value: object) -> bool:
    """True si ``value`` respecte la grammaire ``RelPath`` du contrat."""
    if not isinstance(value, str):
        return False
    if not 1 <= len(value) <= REL_PATH_MAX_LENGTH:
        return False
    return REL_PATH_PATTERN.match(value) is not None
