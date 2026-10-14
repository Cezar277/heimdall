"""Canal d'échec unique des outils MCP — contrat #16, sections 3.1 et 6.

Un outil renvoie **exactement une** des deux formes du contrat : un
résultat de succès, ou ``{"error": {"code", "message"}}``. Aucune
exception ne traverse la frontière du serveur : une pile d'appels, un
message d'exécution ou un chemin absolu refileraient au LLM du contenu du
dépôt et une consigne possible à relire. Les messages sont donc **figés**
ici : sans chemin absolu, sans contenu de fichier, sans valeur de secret
et sans caractère de contrôle (``ErrorMessage`` dans
``schemas/mcp-tools.schema.json``).

La sérialisation est centralisée dans ce module pour que le masquage
précède toujours ``json.dumps`` (obligation
``masking_before_serialization`` du contrat) et pour que la réponse
n'emporte jamais de caractère de contrôle sur le fil : ``json.dumps``
échappe systématiquement ``\\u0000``-``\\u001f``.
"""

import json
from typing import Final, Literal

# Vocabulaire global des échecs ($defs.ErrorCode). Chaque outil ne renvoie
# qu'un sous-ensemble (enveloppes ReadDiff*, SanitizeFile*, ...) : un code
# hors du sous-ensemble de l'outil est une erreur du serveur, pas une
# réponse. Ce module ne choisit pas le sous-ensemble : l'appelant le fait.
ErrorCode = Literal[
    "INVALID_INPUT",
    "PATH_ESCAPE",
    "NOT_FOUND",
    "FORBIDDEN_PATH",
    "BINARY_FILE",
    "TOO_LARGE",
    "UNKNOWN_CANDIDATE",
    "STALE_CANDIDATE",
    "NOT_A_GIT_REPO",
    "INTERNAL",
]

# Messages statiques, un par code. Aucune interpolation d'entrée : le LLM
# relit ces chaînes (invariant 8 — aucune entrée reflétée).
ERROR_MESSAGES: Final[dict[ErrorCode, str]] = {
    "INVALID_INPUT": "entree refusee : parametres hors contrat",
    "PATH_ESCAPE": "chemin refuse : il sort de la racine du depot",
    "NOT_FOUND": "chemin introuvable dans le depot",
    "FORBIDDEN_PATH": "chemin interdit : .git, .env ou fichier ignore",
    "BINARY_FILE": "fichier binaire : aucun texte a renvoyer",
    "TOO_LARGE": "fichier ou diff au-dela des limites du contrat",
    "UNKNOWN_CANDIDATE": "candidat inconnu du serveur",
    "STALE_CANDIDATE": "perimetre modifie depuis la liste des candidats",
    "NOT_A_GIT_REPO": "la racine du serveur n'est pas un depot Git",
    "INTERNAL": "erreur interne : la lecture a ete refusee",
}


class ToolFailure(Exception):
    """Échec d'outil, converti en enveloppe d'erreur par ``tool_handler``.

    Porte un code du contrat, et RIEN d'autre : le message est toujours le
    statique d'`ERROR_MESSAGES`. Le paramètre libre a été supprimé
    volontairement — un `raise ToolFailure("INTERNAL", valeur)` futur
    refléterait un secret ou un chemin absolu au LLM (invariant 8). Ce qui
    ne peut pas s'écrire ne peut pas fuir.
    """

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(ERROR_MESSAGES[code])
        self.code: ErrorCode = code
        self.message: str = ERROR_MESSAGES[code]


def dumps(payload: object) -> str:
    """Sérialise une réponse MCP (masquage déjà appliqué par l'appelant).

    ``ensure_ascii`` garantit qu'aucun octet de contrôle ni caractère
    exotique ne part sur le fil, ``separators`` compacte la réponse pour
    respecter le budget ``max_bytes``, et ``allow_nan=False`` refuse une
    valeur non finie (NaN) au lieu d'écrire un JSON que le client ne sait
    pas relire : un résultat non sérialisable est un échec, pas un succès.
    """
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def failure(code: ErrorCode) -> str:
    """Enveloppe d'échec ``{"error": {"code", "message"}}`` (contrat 3.1)."""
    return dumps({"error": {"code": code, "message": ERROR_MESSAGES[code]}})
