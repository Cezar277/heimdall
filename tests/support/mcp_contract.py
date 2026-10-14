"""Accès au contrat #16 depuis les tests (source unique : le schéma).

Le contrat est un fichier figé : les tests le lisent, jamais ne le
recopient. Un test qui dupliquerait une borne ou un motif serait moot le
jour où le contrat bouge.

Technique de validation reprise de ``tests/contracts/`` (fichier gelé) :
le schéma et ses ``$defs`` sont autonomes, donc un validateur ancré sur
``#/$defs/<nom>`` suffit, sans résolution externe ni réseau.
"""

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "mcp-tools.schema.json"


def contract() -> dict[str, Any]:
    """Contrat des outils MCP (#16), tel qu'il est figé."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    """Validateur d'une réponse contre le ``oneOf`` de l'outil ``name``.

    ``name`` est le nom d'un ``$defs`` de résultat (``ReadDiffResult``,
    ``SanitizeFileResult``…) : le validateur accepte donc **soit** la forme
    succès, **soit** l'enveloppe d'échec propre à l'outil.
    """
    schema = contract()
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]})


def errors(name: str, payload: object) -> list[str]:
    """Messages des erreurs de validation (vide = conforme)."""
    return [error.message for error in validator(name).iter_errors(payload)]


def is_valid(name: str, payload: object) -> bool:
    """True si la réponse satisfait exactement le ``oneOf`` de l'outil."""
    return not errors(name, payload)


def defined(name: str) -> dict[str, Any]:
    """Un ``$defs`` du contrat, pour les tests de grammaire."""
    return contract()["$defs"][name]  # type: ignore[no-any-return]


def pattern_of(name: str) -> re.Pattern[str]:
    """Le motif ``pattern`` d'un ``$defs`` de type chaîne."""
    pattern = defined(name)["pattern"]
    return re.compile(pattern)  # type: ignore[no-any-return]
