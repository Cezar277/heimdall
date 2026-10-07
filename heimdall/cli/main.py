"""Point d'entrée ``heimdall`` — squelette du ticket #17.

Les sous-commandes réelles arrivent avec leurs tickets :
``scan`` (#22 scanner + #32 validation Y/N/E), ``vault`` (#25/#26),
``mcp`` (#27). En attendant, comportement fail-closed : ``scan`` bloque
avec un message explicite au lieu d'inventer un verdict.

Codes de sortie (invariant 11) : 0 propre, 1 secrets détectés, 2 erreur
d'outillage. Un scanner non implémenté est une panne d'outillage, donc 2 —
jamais 1, réservé aux secrets avérés.
"""

import typer

import heimdall

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
    del path, ci  # #22 branchera le scanner réel ici.
    typer.echo("heimdall scan: scanner non implémenté (voir #22) — refus par défaut.", err=True)
    raise typer.Exit(code=2)


def main() -> None:
    """Entrée console ``heimdall`` (voir ``[project.scripts]``)."""
    app()
