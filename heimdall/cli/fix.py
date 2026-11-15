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
from collections.abc import Iterable
from pathlib import Path
from typing import Final

import typer

from heimdall.cli import diagnostics
from heimdall.cli.review import (
    Proposal,
    ReviewError,
    ReviewReport,
    TextChange,
    review_proposals,
)
from heimdall.cli.scan import EXIT_CLEAN, EXIT_FINDINGS, ToolFailure, collect
from heimdall.mcp.paths import ConfinedPath, PathEscape, confine
from heimdall.remediation.apply import (
    AppliedPatch,
    ApplyError,
    apply_replacement,
    cleanup_backup_file,
    undo_apply,
)
from heimdall.remediation.env import EnvRemediationError, remediate_environment
from heimdall.remediation.naming import (
    _MAX_TAKEN,
    deduplicate_variable_name,
    validate_variable_name,
)
from heimdall.remediation.templates import (
    Language,
    ReplacementPlan,
    TemplateError,
    detect_language,
    plan_for_finding,
)
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding
from heimdall.vault.atomic import parse_env_file, parse_example_names, read_file_secure_no_follow

_FIX_ERROR_MESSAGE: Final[str] = "heimdall fix : remédiation impossible (erreur d'outillage)."
_INCOMPATIBLE_OPTIONS_MESSAGE: Final[str] = "options incompatibles : --config et --no-allowlist"
_NON_INTERACTIVE_HINT: Final[str] = (
    "Aucun terminal interactif détecté : aucune modification n'a été faite. "
    "Lancez `heimdall fix` dans un terminal pour valider chaque correction (Y/N), "
    "ou utilisez `--ci` pour un simple rapport."
)
_MAX_LINE_CHARS: Final[int] = 4096
_ASSIGNMENT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")


def _default_variable_name(line_text: str, finding: Finding) -> str:
    """Dérive un nom de variable valide pour un Finding sans jamais refléter le secret."""
    line_text = line_text.lstrip()
    if line_text.startswith(("export ", "export\t")):
        line_text = line_text[len("export"):].strip()
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


#: Échappements décodés à l'identique en Python et en JavaScript. Tout autre
#: échappement (``\\n``, ``\\x41``, ``\\u…``) rend le littéral ambigu entre
#: langages : refus fail-closed plutôt qu'une valeur fausse dans ``.env``.
_SIMPLE_ESCAPES: Final[frozenset[str]] = frozenset({"\\", '"', "'"})
#: Marqueur de commentaire de ligne par langage pris en charge par ``fix``.
_LINE_COMMENT_MARKERS: Final[dict[Language, str]] = {
    Language.PYTHON: "#",
    Language.JAVASCRIPT: "//",
}


def _scan_quoted(line_text: str, quote_index: int) -> tuple[str, int] | None:
    """Décode le littéral ouvert en ``quote_index`` ; ``(valeur, fin)`` ou ``None``."""
    quote = line_text[quote_index]
    length = len(line_text)
    cursor = quote_index + 1
    decoded: list[str] = []
    escaped = False
    while cursor < length:
        cur = line_text[cursor]
        if cur == "\\":
            if cursor + 1 >= length or line_text[cursor + 1] not in _SIMPLE_ESCAPES:
                return None
            decoded.append(line_text[cursor + 1])
            escaped = True
            cursor += 2
            continue
        if cur == quote:
            # Préfixe Python (r"", b"", f"") : les échappements n'y ont pas le
            # même sens, donc aucun décodage n'est sûr.
            if escaped and quote_index > 0 and line_text[quote_index - 1].isalnum():
                return None
            return "".join(decoded), cursor
        decoded.append(cur)
        cursor += 1
    return None


def _find_single_quoted_literal(line_text: str, comment_marker: str | None = None) -> str | None:
    """Extrait l'unique littéral quoté d'une ligne en temps linéaire borné (O(n)).

    La valeur rendue est **décodée** (``\\"`` → ``"``) comme le font l'AST
    Python et le parseur JS des templates. Hors littéral, ``comment_marker``
    termine l'analyse : une apostrophe dans un commentaire (« clé d'API ») ne
    rend plus la ligne ambiguë.
    """
    if len(line_text) > _MAX_LINE_CHARS:
        return None
    found: str | None = None
    index = 0
    length = len(line_text)
    while index < length:
        if comment_marker is not None and line_text.startswith(comment_marker, index):
            break
        if line_text[index] in ('"', "'"):
            scanned = _scan_quoted(line_text, index)
            if scanned is None:
                return None
            literal, cursor = scanned
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
    language = detect_language(finding.file)
    marker = _LINE_COMMENT_MARKERS.get(language) if language is not None else None
    raw_literal = _find_single_quoted_literal(lines[finding.line - 1], marker)
    if raw_literal is None:
        return None
    try:
        plan = plan_for_finding(finding, source, raw_literal, variable)
    except TemplateError:
        return None
    if not plan.manual_remediation and plan.before != plan.after:
        return raw_literal, plan
    return None


def _confine_fixable(root: Path, file: str, planned: set[str]) -> ConfinedPath | None:
    """Confine le fichier du finding ; ``None`` s'il ne peut pas être remédié.

    - Un ``<fichier>.bak`` déjà présent (sauvegarde de l'utilisateur, parfois
      suivie par Git) serait écrasé par la sauvegarde de ``fix`` puis supprimé
      au nettoyage : le finding reste non remédiable.
    - Un fichier qui porte déjà une proposition dans ce passage est différé :
      chaque plan est calculé sur le contenu d'origine, donc un second plan
      sur le même fichier serait périmé dès l'application du premier (et le
      diff validé par l'humain ne serait plus celui écrit). Le finding est
      compté comme restant ; relancer ``fix`` le propose sur le contenu à jour.
    """
    try:
        confined = confine(root, file)
    except PathEscape:
        return None
    if confined.relative in planned:
        return None
    if os.path.lexists(confined.absolute.with_name(f"{confined.absolute.name}.bak")):
        return None
    return confined


def _rollback_apply(root: Path, receipt: AppliedPatch) -> None:
    """Annule une application dont la mise à jour de ``.env`` a échoué."""
    try:
        undo_apply(root, receipt)
    except ApplyError:
        return
    try:
        cleanup_backup_file(root, receipt)
    except ApplyError:
        return


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


def _checked_root_identity(root: Path, resolved_root: Path) -> tuple[int, int, int]:
    """Relit l'identité sans accepter une redirection ou une racine disparue."""
    try:
        if root.is_symlink() or root.resolve() != resolved_root:
            raise ScanError("racine modifiée depuis le scan")
        current = os.stat(resolved_root, follow_symlinks=False)
    except (OSError, RuntimeError):
        raise ScanError("racine modifiée depuis le scan") from None
    return current.st_dev, current.st_ino, current.st_ctime_ns


def _verify_root_identity(root: Path, resolved_root: Path, expected: tuple[int, int, int]) -> None:
    if _checked_root_identity(root, resolved_root) != expected:
        raise ScanError("racine modifiée depuis le scan")


def _physical_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Un patch par emplacement/empreinte, après filtrage typé du scan."""
    unique: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.file, finding.line, finding.snippet_hash), finding)
    return list(unique.values())


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
    if config_path is not None and no_allowlist:
        raise ScanError(_INCOMPATIBLE_OPTIONS_MESSAGE)
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
    planned_files: set[str] = set()
    unfixable = 0

    for finding in _physical_findings(scan_report.findings):
        confined = _confine_fixable(resolved_root, finding.file, planned_files)
        if confined is None:
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
        planned_files.add(confined.relative)
        plans_by_finding[finding] = (plan, secret_value)
        proposals.append(proposal)

    def _apply(proposal: Proposal) -> None:
        nonlocal root_id
        try:
            current_id = _checked_root_identity(root, resolved_root)
        except ScanError:
            raise ApplyError from None
        if current_id != root_id:
            raise ApplyError
        entry = plans_by_finding.get(proposal.finding)
        if entry is None:
            raise ApplyError
        plan, secret_value = entry
        try:
            receipt = apply_replacement(resolved_root, plan, cleanup_backup=False)
        except BaseException as exc:
            diagnostics.remember(exc)
            raise
        try:
            remediate_environment(resolved_root, {plan.variable: secret_value})
        except BaseException as exc:
            diagnostics.remember(exc)
            # Le source ne référence plus le secret mais `.env` ne le contient
            # pas : sans retour arrière, l'application casse et la seule copie
            # du secret reste dans un `.bak` non ignoré. Restauration du source
            # puis suppression du `.bak` (best-effort : en cas d'échec, le
            # `.bak` est conservé, c'est la dernière copie de la valeur).
            _rollback_apply(resolved_root, receipt)
            raise
        cleanup_backup_file(resolved_root, receipt)
        try:
            current_id = _checked_root_identity(root, resolved_root)
        except ScanError:
            raise ApplyError from None
        if current_id[:2] != root_id[:2]:
            raise ApplyError
        # Nos écritures atomiques changent le ctime du dossier. Rafraîchir
        # seulement après contrôle dev/ino ; ne jamais adopter un autre dossier.
        root_id = current_id

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
        _verify_root_identity(root, resolved_root, root_id)
        post_scan = collect(
            resolved_root,
            staged=False,
            config=config_path,
            allowlist=Allowlist() if no_allowlist else None,
            ci=ci,
            respect_gitignore=not no_gitignore,
        )
        _verify_root_identity(root, resolved_root, root_id)
        remaining = len(_physical_findings(post_scan.findings))
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
    debug: bool = typer.Option(
        False,
        "--debug",
        help="En cas d'erreur, affiche la cause et l'action à faire (jamais de valeur).",
    ),
) -> None:
    """Propose et applique la remédiation interactive des secrets détectés."""
    diagnostics.set_debug(debug)
    if config is not None and no_allowlist:
        typer.echo(_INCOMPATIBLE_OPTIONS_MESSAGE, err=True)
        raise typer.Exit(code=2)
    try:
        report, remaining = run_fix(
            Path(path),
            config_path=Path(config) if config is not None else None,
            no_allowlist=no_allowlist,
            no_gitignore=no_gitignore,
            ci=ci,
        )
        typer.echo(render_fix_summary(report, remaining, json_output=json_output))
        if not ci and not json_output and not report.interactive and remaining > 0:
            # Sans terminal, la revue Y/N est impossible : rien n'est écrit.
            # Le dire évite de croire à un bug (« 0 remédiation appliquée »).
            typer.echo(_NON_INTERACTIVE_HINT, err=True)
    except (
        ScanError,
        ToolFailure,
        ReviewError,
        ApplyError,
        EnvRemediationError,
        TemplateError,
    ) as exc:
        diagnostics.report_failure(_FIX_ERROR_MESSAGE, exc)
        raise typer.Exit(code=2) from None
    except Exception as exc:
        diagnostics.report_failure(_FIX_ERROR_MESSAGE, exc)
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=EXIT_FINDINGS if remaining > 0 else EXIT_CLEAN)
