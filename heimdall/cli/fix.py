"""Commande ``heimdall fix`` : branche la revue Y/N (#32) et la remédiation (#30/#31).

Lit les résultats du scan déterministe, prépare les plans de remplacement en
mémoire via :mod:`heimdall.remediation`, puis délègue la validation humaine et
la journalisation à :func:`heimdall.cli.review.review_proposals`.
"""

from __future__ import annotations

import itertools
import json
import os
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
from heimdall.remediation.apply import ApplyError, apply_replacement, cleanup_backup_file
from heimdall.remediation.env import EnvRemediationError, remediate_environment
from heimdall.remediation.naming import (
    _MAX_TAKEN,
    deduplicate_variable_name,
    validate_variable_name,
)
from heimdall.remediation.templates import ReplacementPlan, TemplateError, plan_for_finding
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding
from heimdall.vault.atomic import parse_env_file, parse_example_names, read_file_secure_no_follow

_FIX_ERROR_MESSAGE: Final[str] = "heimdall fix : remédiation impossible (erreur d'outillage)."
_MAX_LINE_CHARS: Final[int] = 4096
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


def _find_single_quoted_literal(line_text: str) -> str | None:
    """Extrait l'unique littéral quoté d'une ligne en temps linéaire borné (O(n))."""
    if len(line_text) > _MAX_LINE_CHARS:
        return None
    found: str | None = None
    index = 0
    length = len(line_text)
    while index < length:
        char = line_text[index]
        if char in ('"', "'"):
            quote = char
            start = index + 1
            cursor = start
            closed = False
            while cursor < length:
                cur = line_text[cursor]
                if cur == "\\" and cursor + 1 < length:
                    cursor += 2
                    continue
                if cur == quote:
                    closed = True
                    break
                cursor += 1
            if not closed:
                return None
            literal = line_text[start:cursor]
            if not literal or found is not None:
                return None
            found = literal
            index = cursor + 1
            continue
        index += 1
    return found


def _extract_secret_for_finding(
    source: str,
    finding: Finding,
    variable: str,
) -> tuple[str, ReplacementPlan] | None:
    """Extrait le littéral secret unique sur ``finding.line`` (fail-closed si ambigu)."""
    lines = source.splitlines()
    if not 1 <= finding.line <= len(lines):
        return None
    raw_literal = _find_single_quoted_literal(lines[finding.line - 1])
    if raw_literal is None:
        return None
    try:
        plan = plan_for_finding(finding, source, raw_literal, variable)
    except TemplateError:
        return None
    if not plan.manual_remediation and plan.before != plan.after:
        return raw_literal, plan
    return None


def _existing_env_names(root: Path) -> set[str]:
    """Collecte de façon bornée (<= _MAX_TAKEN + 1) les noms dans ``.env`` et ``.env.example``."""
    taken: set[str] = set()
    limit = _MAX_TAKEN + 1
    env_data = parse_env_file(root / ".env")
    if env_data:
        taken.update(itertools.islice(env_data.keys(), limit))
    if len(taken) < limit:
        example_names = parse_example_names(root / ".env.example")
        if example_names:
            taken.update(itertools.islice(example_names, limit - len(taken)))
    return taken


def run_fix(  # noqa: PLR0913, PLR0915
    root: Path,
    *,
    config_path: Path | None = None,
    no_allowlist: bool = False,
    no_gitignore: bool = False,
    ci: bool = False,
    interactive: bool | None = None,
) -> tuple[ReviewReport, int]:
    """Exécute le flux complet scan -> plans -> revue Y/N -> écriture atomique."""
    if root.is_symlink():
        raise ScanError("racine symlinkée refusée")
    resolved_root = root.resolve()
    try:
        root_stat = os.stat(resolved_root)
    except OSError:
        raise ScanError("racine inaccessible") from None
    root_id = (root_stat.st_dev, root_stat.st_ino, root_stat.st_ctime_ns)
    scan_report = collect(
        resolved_root,
        staged=False,
        config=config_path,
        allowlist=Allowlist() if no_allowlist else None,
        ci=ci,
        respect_gitignore=not no_gitignore,
    )
    if not scan_report.findings:
        return ReviewReport((), False), 0

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
        try:
            variable = deduplicate_variable_name(base_var, used_names)
            extracted = _extract_secret_for_finding(source, finding, variable)
        except TemplateError:
            unfixable += 1
            continue
        if extracted is None:
            unfixable += 1
            continue
        secret_value, plan = extracted
        try:
            proposal = Proposal(
                finding=finding,
                variable=variable,
                changes=(TextChange(file=plan.file, before=plan.before, after=plan.after),),
                secrets=(secret_value,),
            )
        except ReviewError:
            # Fichier trop volumineux pour le rendu de revue (ou secret hors
            # bornes) : ce finding reste non remédiable, sans avorter le lot.
            unfixable += 1
            continue
        used_names.add(variable)
        plans_by_finding[finding] = (plan, secret_value)
        proposals.append(proposal)

    def _apply(proposal: Proposal) -> None:
        if root.is_symlink() or root.resolve() != resolved_root:
            raise ApplyError
        try:
            current_stat = os.stat(resolved_root)
        except OSError:
            raise ApplyError from None
        if (current_stat.st_dev, current_stat.st_ino, current_stat.st_ctime_ns) != root_id:
            raise ApplyError
        entry = plans_by_finding.get(proposal.finding)
        if entry is None:
            raise ApplyError
        plan, secret_value = entry
        receipt = apply_replacement(resolved_root, plan, cleanup_backup=False)
        remediate_environment(resolved_root, {plan.variable: secret_value})
        cleanup_backup_file(resolved_root, receipt)

    report = review_proposals(
        proposals,
        ci=ci,
        interactive=interactive,
        # `fix` ne fournit pas de handler d'édition : E est refusé sans
        # écriture et le prompt ne l'annonce pas (fail-closed explicite).
        allow_edit=False,
        apply=_apply,
    )
    if any(outcome.applied for outcome in report.outcomes):
        post_scan = collect(
            resolved_root,
            staged=False,
            config=config_path,
            allowlist=Allowlist() if no_allowlist else None,
            ci=ci,
            respect_gitignore=not no_gitignore,
        )
        remaining = len(post_scan.findings)
    else:
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
