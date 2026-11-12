"""Remédiation locale des secrets (tickets parents #30, #31).

``templates.py`` et ``naming.py`` ne font **aucune I/O** : ils transforment
et valident en mémoire. ``apply.py`` et ``env.py`` écrivent sur disque, de façon
atomique et confinée à la racine (tickets #85/#86 et #31).
"""

from heimdall.remediation.apply import AppliedPatch, ApplyError, apply_replacement, undo_apply
from heimdall.remediation.env import (
    EnvRemediationError,
    EnvRemediationReceipt,
    check_env_git_status,
    ensure_gitignore_ignores_env,
    plan_env_example_change,
    plan_gitignore_change,
    remediate_environment,
    update_env_example,
    update_env_file,
)
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
    "EnvRemediationError",
    "EnvRemediationReceipt",
    "JAVASCRIPT_EXTENSIONS",
    "PYTHON_EXTENSIONS",
    "TEMPLATES",
    "Language",
    "ManualReason",
    "ReplacementPlan",
    "TemplateError",
    "apply_replacement",
    "build_replacement",
    "check_env_git_status",
    "deduplicate_variable_name",
    "detect_language",
    "ensure_gitignore_ignores_env",
    "is_dangerous_env_var",
    "plan_env_example_change",
    "plan_for_finding",
    "plan_gitignore_change",
    "remediate_environment",
    "replacement_expression",
    "undo_apply",
    "update_env_example",
    "update_env_file",
    "validate_variable_name",
]
