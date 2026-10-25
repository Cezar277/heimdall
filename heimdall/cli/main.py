"""Point d'entrée ``heimdall`` — squelette du ticket #17.

Les sous-commandes réelles arrivent avec leurs tickets :
``scan`` (#29 branche le scanner #22),
``vault`` (#25/#26/#64), ``mcp`` (#27). La validation Y/N/E (#32) et le
remplacement du secret arrivent plus tard : ``scan`` est aujourd'hui une
lecture seule, sans dialogue.

Codes de sortie (invariant 11) : 0 propre, 1 secrets détectés, 2 erreur
d'outillage. Une commande non branchée est une panne d'outillage, donc 2 —
jamais 1, réservé aux secrets avérés. Et **jamais 0 après une erreur** : un
scan raté ne doit pas laisser passer un pipeline (c'est le piège du ticket
#29, et l'exigence REQ-SEC-07).

Invariant 8 : aucun message d'erreur ne reflète une entrée (chemin, contenu,
candidat). Les messages sont statiques.
"""

from pathlib import Path
from typing import Final

import typer

import heimdall
from heimdall.cli.scan import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    ToolFailure,
    collect,
    render_json,
    render_text,
)
from heimdall.cli.vault_client import RUN_CONTEXT_SETTINGS, vault_run
from heimdall.cli.vault_keys import vault_app
from heimdall.mcp.server import run_stdio
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.errors import ScanError

#: Libellé **unique** du code 2 : une panne anticipée (`ScanError`,
#: `ToolFailure`) et une panne inattendue ne doivent pas être distinguables
#: par un observateur du canal stderr (invariant 8, oracle minimal).
_SCAN_ERROR_MESSAGE: Final[str] = "heimdall scan : scan impossible (erreur d'outillage)."

app = typer.Typer(
    name="heimdall",
    help="Sentinelle DevSecOps 100 % locale : empêche les secrets de finir dans Git.",
    no_args_is_help=True,
    invoke_without_command=True,  # `--version` seul ne doit pas exiger de sous-commande.
)
# Administration du Vault (clés API de projet, ticket #64) et client (ticket #35).
app.add_typer(vault_app, name="vault")

# Exécution avec injection en mémoire (ticket #101). Voie canonique :
# `heimdall run`. L'alias `heimdall vault run` (vault_keys.py) partage le
# même callback et les mêmes réglages (RUN_CONTEXT_SETTINGS) — voir
# docs/t35-samm.md §5.
app.command(
    "run",
    help=(
        "Lance une commande avec les secrets injectés en mémoire (ticket #101).\n\n"
        "Limite de sécurité : sous Linux, les variables d'environnement d'un processus sont "
        "visibles par les processus du même utilisateur via /proc/<pid>/environ."
    ),
    context_settings=RUN_CONTEXT_SETTINGS,
)(vault_run)


def _echo_stderr_best_effort(message: str) -> None:
    """Écrit un message sur stderr sans jamais lever.

    En CI, stderr peut être fermé : un ``typer.echo(..., err=True)`` qui lève
    (``BrokenPipeError``, ``OSError``) dans un handler d'erreur ferait sortir
    une traceback Typer en exit 1 — réservé aux secrets avérés (invariant
    11). L'écriture de secours est donc best-effort : en cas d'échec, elle
    est abandonnée en silence, et l'appelant sort en 2.
    """
    try:
        typer.echo(message, err=True)
    # Best-effort volontaire (voir la docstring) : l'échec est abandonné.
    except Exception:  # noqa: S110 # nosec B110
        pass


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", help="Affiche la version et sort."),
) -> None:
    if version:
        typer.echo(f"heimdall {heimdall.__version__}")
        raise typer.Exit(0)


@app.command()
def scan(  # noqa: PLR0913, PLR0917
    path: str = typer.Argument(".", help="Chemin du dépôt à analyser."),
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
    ci: bool = typer.Option(
        False,
        "--ci",
        help="Mode CI headless : verdict déterministe porté par le code de sortie.",
    ),
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Analyse les blobs de l'index (ajoutés ou modifiés) au lieu de l'arbre de travail.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Sortie JSON sur stdout (contrat machine heimdall.scan.v1).",
    ),
) -> None:
    """Scanne le dépôt à la recherche de secrets (#29 et #24).

    Par défaut, l'arbre de travail est analysé en **mode strict** : seule la
    base VCS est écartée, tout le reste est lu par contenu (``vendor/``,
    ``node_modules/``, lockfiles compris). Un rapport incomplet (binaire,
    lien, illisible) refuse le verdict propre. Avec ``--staged``, ce sont les
    blobs **ajoutés ou modifiés** dans l'index git qui sont analysés, sans
    aucune exclusion de chemin.

    L'allowlist déterministe (#24) écarte les cas évidents sans passer par
    le LLM et émet une trace pour chaque rejet (règle, fichier, ligne).

    ``--ci`` active le mode headless : aucun dialogue, aucun LLM, aucun
    réseau — le verdict est le code de sortie, et un résumé déterministe est
    écrit sur stderr. ``--json`` remplace le rapport humain par le document
    JSON du contrat ``heimdall.scan.v1``.

    En cas de doute, **refus par défaut** : une entrée non analysable (racine
    absente, index en conflit, fichier illisible) sort en 2, jamais en 0.
    """
    if config is not None and no_allowlist:
        _echo_stderr_best_effort("options incompatibles : --config et --no-allowlist")
        raise typer.Exit(code=2)

    try:
        custom_allowlist = Allowlist.empty() if no_allowlist else None
        report = collect(
            Path(path),
            staged=staged,
            config=config,
            allowlist=custom_allowlist,
            ci=ci,
        )
        # Le **rendu** et le résumé --ci sont dans le même try que la
        # collecte : un échec de rendu (bug futur, panne mémoire, écriture
        # refusée) est une erreur d'outillage, jamais l'exit 1 réservé aux
        # secrets avérés (invariant 11). Un try qui ne couvrirait que
        # `collect()` laisserait une traceback Typer sortir en 1.
        if json_output:
            typer.echo(render_json(report))
        else:
            typer.echo(render_text(report))
        if ci:
            # Résumé déterministe sur stderr : le journal CI montre toujours
            # le verdict, les findings ignorés, l'empreinte sha256 de config
            # et les bases VCS élaguées (jamais présentées comme analysées).
            hash_info = (
                f" (config sha256:{report.config_hash})"
                if report.config_hash
                else ""
            )
            typer.echo(
                f"heimdall scan : périmètre {report.scope}, "
                f"{len(report.findings)} secret(s) détecté(s), "
                f"{report.ignored_count} ignoré(s) par l'allowlist{hash_info}, "
                f"{report.vcs_ignored} base(s) VCS élaguée(s).",
                err=True,
            )
    except (ScanError, ToolFailure):
        # Erreur d'outillage : le périmètre n'a pas été analysé en entier.
        # Jamais 0, jamais 1 : c'est 2 (REQ-SEC-07). L'écriture est
        # best-effort (stderr fermé en CI) : elle ne doit pas lever à son
        # tour, sinon la traceback sortirait en 1.
        _echo_stderr_best_effort(_SCAN_ERROR_MESSAGE)
        raise typer.Exit(code=2) from None
    except Exception:
        # Panne inattendue (collecte, rendu ou résumé --ci) : même contrat,
        # **même libellé** que ci-dessus (un observateur ne doit pas
        # distinguer une panne anticipée d'une panne inattendue), écriture
        # best-effort (invariant 8).
        _echo_stderr_best_effort(_SCAN_ERROR_MESSAGE)
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=EXIT_FINDINGS if report.findings else EXIT_CLEAN)


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
