"""``heimdall init`` : protéger un dépôt en une commande.

Trois étapes, chacune idempotente et sans écrasement :

1. installe le hook ``pre-commit`` (un hook existant est chaîné, jamais écrasé) ;
2. garantit que ``.env`` est ignoré par Git (ajout idempotent à ``.gitignore``) ;
3. fait un premier scan de l'arbre de travail et indique quoi faire ensuite.

Aucune configuration n'est créée : sans ``heimdall.toml``, l'allowlist est vide
(rien n'est masqué), et ``scan --ci`` fonctionne sans option.
"""

from __future__ import annotations

from pathlib import Path

import typer

from heimdall.cli import diagnostics
from heimdall.cli.hook import (
    _INSTALL_MESSAGES,
    HookError,
    OutsideRepositoryError,
    install_hook,
)
from heimdall.cli.scan import collect
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess
from heimdall.remediation.env import EnvRemediationError, ensure_gitignore_ignores_env
from heimdall.scanner.errors import ScanError

_MAX_LISTED_FINDINGS = 10
_SCAN_FAILURE = "premier scan impossible (erreur d'outillage)."


def _report_step_failure(label: str, exc: BaseException) -> None:
    """Échec d'une étape : libellé statique, cause/action seulement en --debug."""
    typer.echo(f"✗ {diagnostics.failure_message(label)}")
    if diagnostics.debug_enabled():
        cause, action = diagnostics.describe(exc)
        typer.echo(f"  cause : {cause}")
        if action is not None:
            typer.echo(f"  action : {action}")


def _is_git_repository(root: Path) -> bool:
    try:
        return GitAccess(root.resolve()).is_repository()
    except Exception:
        return False


def _step_hook(root: Path) -> bool:
    try:
        outcome = install_hook(root)
    except OutsideRepositoryError:
        typer.echo(
            "✗ hook : core.hooksPath pointe hors du dépôt — "
            "lancez `heimdall hook install --force` si c'est voulu."
        )
        return False
    except HookError:
        typer.echo("✗ hook : installation impossible (hook illisible ou dépôt inhabituel).")
        return False
    except Exception as exc:
        _report_step_failure("hook : installation impossible (erreur d'outillage).", exc)
        return False
    typer.echo(f"✓ {_INSTALL_MESSAGES[outcome]} : chaque commit est vérifié.")
    return True


def _step_gitignore(root: Path) -> bool:
    try:
        changed = ensure_gitignore_ignores_env(root)
    except EnvRemediationError:
        typer.echo("✗ .gitignore : mise à jour impossible (lien symbolique ou fichier invalide).")
        return False
    except Exception as exc:
        _report_step_failure(".gitignore : mise à jour impossible (erreur d'outillage).", exc)
        return False
    if changed:
        typer.echo("✓ .env ajouté à .gitignore.")
    else:
        typer.echo("✓ .env déjà ignoré par Git.")
    return True


def _step_scan(root: Path) -> bool:
    try:
        report = collect(root, staged=False)
    except (ScanError, ToolFailure) as exc:
        _report_step_failure(_SCAN_FAILURE, exc)
        return False
    except Exception as exc:
        # Panne inattendue : même libellé, jamais de traceback ni de message
        # brut (invariant 8) ; en --debug, le type seul.
        _report_step_failure(_SCAN_FAILURE, exc)
        return False
    findings = report.findings
    if not findings:
        typer.echo("✓ premier scan : aucun secret détecté.")
        return True
    typer.echo(
        f"! premier scan : {len(findings)} secret(s) détecté(s) (valeurs jamais affichées) :"
    )
    for finding in findings[:_MAX_LISTED_FINDINGS]:
        typer.echo(f"    {finding.file}:{finding.line}  {finding.type}")
    if len(findings) > _MAX_LISTED_FINDINGS:
        typer.echo(f"    … et {len(findings) - _MAX_LISTED_FINDINGS} autre(s) : `heimdall scan`.")
    typer.echo("  → lancez `heimdall fix` pour les déplacer vers .env (validation Y/N).")
    return True


def init_command(
    path: str = typer.Argument(".", help="Racine du dépôt Git à protéger."),
    hook: bool = typer.Option(True, "--hook/--no-hook", help="Installe le hook pre-commit."),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Fait un premier scan."),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="En cas d'erreur, affiche la cause et l'action à faire (jamais de valeur).",
    ),
) -> None:
    """Protège ce dépôt en une commande : hook pre-commit, .env ignoré, premier scan."""
    diagnostics.set_debug(debug)
    # Mêmes refus que `scan`, `fix` ou `hook install` : ni argument vide (que
    # Path() changerait en « . »), ni racine qui est un lien symbolique (on
    # modifierait le .gitignore de sa cible).
    if not path.strip():
        typer.echo("Erreur : chemin du dépôt vide.", err=True)
        raise typer.Exit(code=2)
    root = Path(path)
    if root.is_symlink():
        typer.echo(
            "Erreur : la racine du dépôt est un lien symbolique ; passez le chemin réel.",
            err=True,
        )
        raise typer.Exit(code=2)
    if not _is_git_repository(root):
        typer.echo(
            "Erreur : ce dossier n'est pas un dépôt Git. Lancez `git init` "
            "(ou placez-vous dans votre dépôt), puis `heimdall init`.",
            err=True,
        )
        raise typer.Exit(code=2)
    results = []
    if hook:
        results.append(_step_hook(root))
    results.append(_step_gitignore(root))
    if scan:
        results.append(_step_scan(root))
    typer.echo("")
    typer.echo("Pour aller plus loin :")
    typer.echo("  heimdall scan --ci            dans votre CI (code 1 si un secret est trouvé)")
    typer.echo("  heimdall vault init           coffre chiffré local pour vos secrets (optionnel)")
    raise typer.Exit(code=0 if all(results) else 2)


__all__ = ["init_command"]
