"""CLI d'administration des clés API de projet du Vault Heimdall (ticket #64).

Commandes :

    heimdall vault key create --project demo   # émet une clé (affichée UNE fois)
    heimdall vault key list  [--project demo]  # métadonnées des clés (jamais la clé)
    heimdall vault key revoke --key-id key_...  # révoque une clé

RÈGLES DE SÉCURITÉ (invariant 8, fail-closed) :
- La clé brute n'est écrite QUE sur la sortie standard, UNE seule fois, à la
  création. Elle n'est jamais journalisée, jamais stockée en clair et jamais
  répétée dans un message d'erreur.
- Seul le haché de vérification (HMAC-SHA256 + pepper serveur) est persisté.
- Le pepper (`HEIMDALL_VAULT_API_KEY_PEPPER`) est EXPLICITE et obligatoire : un
  pepper éphémère rendrait la clé inutilisable au redémarrage du serveur.
- Les messages d'erreur sont génériques : aucune valeur reçue (clé, chemin
  absolu, identifiant) n'est réfléchie dans la sortie.
- Chemins de base : ABSOLUS uniquement (un chemin relatif dépend du répertoire
  courant) ; le mode `:memory:` est interdit en CLI.

Codes de sortie (convention de la CLI) : 0 (succès), 1 (échec opérationnel),
2 (usage ou configuration invalide).
"""

import os
from pathlib import Path

import typer

from heimdall.vault import auth as vault_auth
from heimdall.vault.database import init_db, resolve_db_path

key_app = typer.Typer(
    name="key",
    help="Cycle de vie des clés API de projet (ticket #64).",
    no_args_is_help=True,
)

vault_app = typer.Typer(
    name="vault",
    help="Administration du Vault Heimdall (clés API de projet).",
    no_args_is_help=True,
)
vault_app.add_typer(key_app, name="key")

_DB_PATH_OPTION = typer.Option(
    None,
    "--db-path",
    help=(
        "Chemin ABSOLU du fichier SQLite "
        "(défaut : $HEIMDALL_VAULT_DB_PATH ou $XDG_DATA_HOME/heimdall/vault.db)."
    ),
)


def _resolve_db_path(db_path: Path | None) -> Path:
    """Résout le chemin SQLite ABSOLU de la base (fail-closed).

    Le mode ``:memory:`` est refusé (argument ou variable d'environnement) :
    une base éphémère ferait perdre les clés à chaque invocation.
    """
    raw = db_path if db_path is not None else os.environ.get("HEIMDALL_VAULT_DB_PATH")
    if raw is not None and str(raw).strip() == ":memory:":
        raise ValueError(
            "Le mode ':memory:' est réservé aux tests et est interdit en CLI."
        )
    resolved = resolve_db_path(db_path)
    if not isinstance(resolved, Path) or not resolved.is_absolute():
        raise ValueError(
            "Chemin absolu requis (un chemin relatif dépend du répertoire courant)."
        )
    return resolved


def _explicit_pepper() -> str:
    """Retourne le pepper serveur explicite, ou échoue (fail-closed)."""
    return vault_auth.require_explicit_pepper(os.environ.get("HEIMDALL_VAULT_API_KEY_PEPPER"))


@key_app.command("create")
def create_key(
    project: str = typer.Option(
        ...,
        "--project",
        "-p",
        help="Identifiant du projet (^[a-z][a-z0-9_-]{0,63}$).",
    ),
    db_path: Path | None = _DB_PATH_OPTION,
) -> None:
    """Émet une clé API de projet et l'affiche UNE SEULE FOIS."""
    try:
        resolved = _resolve_db_path(db_path)
        pepper = _explicit_pepper()
        vault_auth.validate_project_id(project)
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    try:
        init_db(resolved)
        issued = vault_auth.issue_api_key(resolved, project, pepper)
    except Exception:
        # Aucun détail interne (chemin, SQL, clé) dans la sortie : le message
        # reste générique, comme le contrat d'erreurs du serveur.
        typer.echo("Erreur : échec de l'émission de la clé API.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(
        "Clé API de projet émise — affichée UNE SEULE FOIS, à copier maintenant :"
    )
    typer.echo(issued.raw_key)
    typer.echo(f"Identifiant : {issued.key_id}")
    typer.echo(f"Projet      : {issued.project_id}")


@key_app.command("list")
def list_keys(
    project: str | None = typer.Option(
        None,
        "--project",
        "-p",
        help="Filtrer sur un projet (défaut : tous les projets).",
    ),
    db_path: Path | None = _DB_PATH_OPTION,
) -> None:
    """Liste les clés API enregistrées (métadonnées seules, jamais la clé)."""
    try:
        resolved = _resolve_db_path(db_path)
        if project is not None:
            # Une coquille de filtre doit échouer franchement, pas afficher
            # « Aucune clé » et masquer une mauvaise configuration opérateur.
            vault_auth.validate_project_id(project)
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    try:
        rows = vault_auth.list_registered_keys(resolved, project)
    except Exception:
        typer.echo("Erreur : échec de la lecture du registre des clés API.", err=True)
        raise typer.Exit(code=1) from None
    if not rows:
        typer.echo("Aucune clé API enregistrée.")
        return
    for row in rows:
        state = "révoquée" if row["revoked_at"] else "active"
        typer.echo(
            f"{row['id']}  projet={row['project_id']}  "
            f"créée={row['created_at']}  état={state}"
        )


@key_app.command("revoke")
def revoke_key(
    key_id: str = typer.Argument(
        ...,
        help="Identifiant de la clé à révoquer (key_...).",
    ),
    db_path: Path | None = _DB_PATH_OPTION,
) -> None:
    """Révoque une clé API : elle cesse d'authentifier immédiatement."""
    try:
        resolved = _resolve_db_path(db_path)
        vault_auth.validate_key_id(key_id)
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    try:
        revoked = vault_auth.revoke_registered_key(resolved, key_id)
    except Exception:
        typer.echo("Erreur : échec de la révocation de la clé API.", err=True)
        raise typer.Exit(code=1) from None
    if not revoked:
        typer.echo("Erreur : clé API introuvable ou déjà révoquée.", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Clé API {key_id} révoquée : elle n'authentifie plus aucune requête.")


__all__ = ["key_app", "vault_app"]
