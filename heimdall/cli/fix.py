"""Commande ``heimdall fix`` : branche la revue Y/N/E (#32) et la remédiation (#30/#31).

Lit les résultats du scan déterministe, prépare les plans de remplacement en
mémoire via :mod:`heimdall.remediation`, puis délègue la validation humaine et
la journalisation à :func:`heimdall.cli.review.review_proposals`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

import typer

from heimdall.cli.review import (
    Proposal,
    ReviewError,
    ReviewReport,
    TextChange,
    review_proposals,
)
from heimdall.cli.scan import EXIT_CLEAN, EXIT_FINDINGS, ToolFailure, collect
from heimdall.mcp.paths import PathEscape, confine
from heimdall.remediation.apply import ApplyError, apply_replacement
from heimdall.remediation.env import EnvRemediationError, remediate_environment
from heimdall.remediation.naming import deduplicate_variable_name, validate_variable_name
from heimdall.remediation.templates import ReplacementPlan, TemplateError, plan_for_finding
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding
from heimdall.vault.atomic import parse_env_file, parse_example_names, read_file_secure_no_follow

_FIX_ERROR_MESSAGE: Final[str] = "heimdall fix : remédiation impossible (erreur d'outillage)."
_QUOTED_LITERAL_RE: Final[re.Pattern[str]] = re.compile(r"""(['"])((?:\\.|(?!\1).)+)\1""")
_ASSIGNMENT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")


def _default_variable_name(line_text: str, finding: Finding) -> str:
    """Dérive un nom de variable valide pour un Finding sans jamais refléter le secret."""
    match = _ASSIGNMENT_NAME_RE.match(line_text)
    if match:
        candidate = match.group(1).upper()
        try:
            return validate_variable_name(candidate)
        except TemplateError:
            pass
    fallback = f"SECRET_{finding.type.upper()}"
    fallback = re.sub(r"[^A-Z0-9_]", "_", fallback)[:64]
    try:
        return validate_variable_name(fallback)
    except TemplateError:
        return "APP_SECRET"


def _extract_secret_for_finding(
    source: str,
    finding: Finding,
    variable: str,
) -> tuple[str, ReplacementPlan] | None:
    """Extrait le littéral secret sur ``finding.line`` et construit un plan valide."""
    lines = source.splitlines()
    if not 1 <= finding.line <= len(lines):
        return None
    line_text = lines[finding.line - 1]
    for _quote, raw_literal in _QUOTED_LITERAL_RE.findall(line_text):
        try:
            plan = plan_for_finding(finding, source, raw_literal, variable)
        except TemplateError:
            continue
        if not plan.manual_remediation and plan.before != plan.after:
            return raw_literal, plan
    return None


def _existing_env_names(root: Path) -> set[str]:
    """Collecte de façon bornée les noms déjà présents dans ``.env`` et ``.env.example``."""
    taken: set[str] = set()
    env_data = parse_env_file(root / ".env")
    if env_data:
        taken.update(env_data.keys())
    example_names = parse_example_names(root / ".env.example")
    if example_names:
        taken.update(example_names)
    return taken


def run_fix(  # noqa: PLR0913
    root: Path,
    *,
    config_path: Path | None = None,
    no_allowlist: bool = False,
    no_gitignore: bool = False,
    ci: bool = False,
    interactive: bool | None = None,
) -> tuple[ReviewReport, int]:
    """Exécute le flux complet scan -> plans -> revue Y/N/E -> écriture atomique."""
    scan_report = collect(
        root,
        staged=False,
        config=config_path,
        allowlist=Allowlist() if no_allowlist else None,
        ci=ci,
        respect_gitignore=not no_gitignore,
    )
    if not scan_report.findings:
        return ReviewReport((), False), 0

    resolved_root = root.resolve()
    used_names = _existing_env_names(resolved_root)
    plans_by_finding: dict[Finding, tuple[ReplacementPlan, str]] = {}
    proposals: list[Proposal] = []
    unfixable = 0

    for finding in scan_report.findings:
        try:
            confined = confine(resolved_root, finding.file)
        except PathEscape:
            unfixable += 1
            continue
        source = read_file_secure_no_follow(confined.absolute)
        if source is None:
            unfixable += 1
            continue
        lines = source.splitlines()
        line_text = lines[finding.line - 1] if 1 <= finding.line <= len(lines) else ""
        base_var = _default_variable_name(line_text, finding)
        variable = deduplicate_variable_name(base_var, used_names)
        extracted = _extract_secret_for_finding(source, finding, variable)
        if extracted is None:
            unfixable += 1
            continue
        secret_value, plan = extracted
        used_names.add(variable)
        plans_by_finding[finding] = (plan, secret_value)
        proposals.append(
            Proposal(
                finding=finding,
                variable=variable,
                changes=(TextChange(file=plan.file, before=plan.before, after=plan.after),),
                secrets=(secret_value,),
            )
        )

    def _apply(proposal: Proposal) -> None:
        entry = plans_by_finding.get(proposal.finding)
        if entry is None:
            raise ApplyError
        plan, secret_value = entry
        apply_replacement(resolved_root, plan, cleanup_backup=True)
        remediate_environment(resolved_root, {plan.variable: secret_value})

    report = review_proposals(
        proposals,
        ci=ci,
        interactive=interactive,
        apply=_apply,
    )
    remaining = unfixable + sum(1 for outcome in report.outcomes if not outcome.applied)
    return report, remaining


def render_fix_summary(report: ReviewReport, remaining: int, *, json_output: bool = False) -> str:
    """Formate le bilan de ``heimdall fix`` sans jamais exposer de secret."""
    applied_count = sum(1 for outcome in report.outcomes if outcome.applied)
    payload = {
        "applied": applied_count,
        "remaining": remaining,
        "interactive": report.interactive,
    }
    if json_output:
        return json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return (
        f"heimdall fix : {applied_count} remédiation(s) appliquée(s), "
        f"{remaining} secret(s) restant(s)."
    )


def fix_command(  # noqa: PLR0913, PLR0917
    path: str = typer.Argument(".", help="Chemin du dépôt à corriger."),
    config: str | None = typer.Option(
        None,
        "--config",
        help="Chemin explicite du fichier de configuration (heimdall.toml par défaut).",
    ),
    no_allowlist: bool = typer.Option(
        False,
        "--no-allowlist",
        help="Désactive l'allowlist déterministe.",
    ),
    no_gitignore: bool = typer.Option(
        False,
        "--no-gitignore",
        help="Scanne aussi les fichiers non suivis ignorés par .gitignore.",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="Mode CI non interactif : rapport seul, aucune écriture.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Sortie JSON sur stdout sans secret.",
    ),
) -> None:
    """Propose et applique la remédiation interactive des secrets détectés (#233)."""
    try:
        report, remaining = run_fix(
            Path(path),
            config_path=Path(config) if config is not None else None,
            no_allowlist=no_allowlist,
            no_gitignore=no_gitignore,
            ci=ci,
        )
        typer.echo(render_fix_summary(report, remaining, json_output=json_output))
    except (
        ScanError,
        ToolFailure,
        ReviewError,
        ApplyError,
        EnvRemediationError,
        TemplateError,
    ):
        typer.echo(_FIX_ERROR_MESSAGE, err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        typer.echo(_FIX_ERROR_MESSAGE, err=True)
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=EXIT_FINDINGS if remaining > 0 else EXIT_CLEAN)
