"""Remédiation locale des secrets (ticket parent #30).

``templates.py`` et ``naming.py`` ne font **aucune I/O** : ils transforment
et valident en mémoire. Seul ``apply.py`` écrit sur disque, de façon
atomique et confinée à la racine (tickets #85/#86).
"""

from heimdall.remediation.apply import AppliedPatch, ApplyError, apply_replacement, undo_apply
from heimdall.remediation.naming import (
    deduplicate_variable_name,
    is_dangerous_env_var,
    validate_variable_name,
)
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
    "AppliedPatch",
    "ApplyError",
    "EXTENSION_LANGUAGE",
    "JAVASCRIPT_EXTENSIONS",
    "PYTHON_EXTENSIONS",
    "TEMPLATES",
    "Language",
    "ManualReason",
    "ReplacementPlan",
    "TemplateError",
    "apply_replacement",
    "build_replacement",
    "deduplicate_variable_name",
    "detect_language",
    "is_dangerous_env_var",
    "plan_for_finding",
    "replacement_expression",
    "undo_apply",
    "validate_variable_name",
]
