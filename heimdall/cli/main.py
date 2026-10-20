"""Point d'entrée ``heimdall`` — squelette du ticket #17.

Les sous-commandes réelles arrivent avec leurs tickets :
``scan`` (#29 branche le scanner #22 et #32 la validation Y/N/E),
``vault`` (#25/#26), ``mcp`` (#27). En attendant, comportement fail-closed :
``scan`` bloque avec un message explicite au lieu d'inventer un verdict.

Codes de sortie (invariant 11) : 0 propre, 1 secrets détectés, 2 erreur
d'outillage. Une commande non branchée est une panne d'outillage, donc 2 —
jamais 1, réservé aux secrets avérés.
"""

import typer

import heimdall
from heimdall.mcp.server import run_stdio

app = typer.Typer(
    name="heimdall",
    help="Sentinelle DevSecOps 100 % locale : empêche les secrets de finir dans Git.",
    no_args_is_help=True,
    invoke_without_command=True,  # `--version` seul ne doit pas exiger de sous-commande.
)


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", help="Affiche la version et sort."),
) -> None:
    if version:
        typer.echo(f"heimdall {heimdall.__version__}")
        raise typer.Exit(0)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Chemin du dépôt à analyser."),
    ci: bool = typer.Option(False, "--ci", help="Mode CI : échoue si un secret reste en clair."),
) -> None:
    """Scanne le diff (ou le dépôt) à la recherche de secrets."""
    del path, ci  # #29 branchera le scanner réel ici.
    typer.echo("heimdall scan: commande non branchée (voir #29) — refus par défaut.", err=True)
    raise typer.Exit(code=2)


@app.command()
def mcp(
    root: str = typer.Option(".", "--root", help="Racine du dépôt exposée au LLM."),
) -> None:
    """Démarre le serveur MCP sur stdio (outils en lecture seule, contrat #16).

    Le serveur vit en sous-processus et n'ouvre aucun port. La racine est
    fixée ici, au démarrage : le LLM ne la fournit jamais (contrat #16,
    invariant 2). stdout ne porte que le protocole — tout le reste va sur
    stderr, sous peine de casser le canal.
    """
    try:
        run_stdio(root)
    except BrokenPipeError:
        raise typer.Exit(code=0) from None
    except ValueError as exc:
        # Message statique : aucune entrée reflétée (invariant 8).
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        # Échec inattendu au démarrage : message statique seul (invariant 8).
        typer.echo("erreur au démarrage du serveur MCP", err=True)
        raise typer.Exit(code=2) from None


def main() -> None:
    """Entrée console ``heimdall`` (voir ``[project.scripts]``)."""
    app()
