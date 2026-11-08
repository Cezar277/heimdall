"""Remédiation locale des secrets (ticket parent #30).

Ce paquet ne fait **aucune I/O** : il transforme un texte source en mémoire.
L'application atomique du patch (#85) et la garde de chemin runtime (#86)
restent des tickets séparés. Le présent livrable est le sous-ticket #83
(T30.1), templates de remplacement par langage.
"""

from heimdall.remediation.templates import (
    EXTENSION_LANGUAGE,
    JAVASCRIPT_EXTENSIONS,
    PYTHON_EXTENSIONS,
    TEMPLATES,
    Language,
    ManualReason,
    ReplacementPlan,
    TemplateError,
    build_replacement,
    detect_language,
    plan_for_finding,
    replacement_expression,
)

__all__ = [
    "EXTENSION_LANGUAGE",
    "JAVASCRIPT_EXTENSIONS",
    "PYTHON_EXTENSIONS",
    "TEMPLATES",
    "Language",
    "ManualReason",
    "ReplacementPlan",
    "TemplateError",
    "build_replacement",
    "detect_language",
    "plan_for_finding",
    "replacement_expression",
]
