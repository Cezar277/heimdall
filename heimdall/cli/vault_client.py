"""Commandes CLI du client Vault Heimdall (tickets #35, #98, #99, #100, #101).

Commandes :
    heimdall vault push               # pousse les secrets locaux vers le Vault
    heimdall vault pull --env dev     # récupère les secrets et écrit .env en 0600
    heimdall run -- <commande>        # exécute une commande avec secrets injectés en mémoire

RÈGLES DE SÉCURITÉ :
- La clé API n'est JAMAIS passée en argument de ligne de commande (invariant DoD #98).
- Les valeurs secrètes ne sont JAMAIS affichées dans la sortie terminal ou les erreurs.
- Aucune écriture sur disque lors de `run` (secrets en mémoire uniquement).
- Droits 0600 obligatoires sur le .env écrit par `pull`, avec sauvegarde préalable.
- Avertissement si le .env est suivi par Git.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Final

import typer

from heimdall.vault.atomic import (
    backup_file,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    parse_example_names,
    write_file_atomic,
)
from heimdall.vault.client import (
    VaultAuthError,
    VaultClient,
    VaultClientError,
    VaultConflictError,
    VaultForbiddenError,
    VaultNotFoundError,
    VaultRateLimitError,
    detect_project,
    resolve_api_key,
    resolve_vault_url,
)

_PROJECT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENV_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SECRET_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")

# Options CLI déclarées au niveau module pour conformité B008
_PROJECT_OPTION = typer.Option(
    None,
    "--project",
    "-p",
    help="Identifiant du projet (défaut : détecté ou $HEIMDALL_PROJECT).",
)
_ENV_OPTION = typer.Option(
    "dev",
    "--env",
    "-e",
    help="Environnement cible (défaut : dev).",
)
_FILE_OPTION = typer.Option(
    Path(".env"),
    "--file",
    "-f",
    help="Fichier de secrets source (défaut : .env).",
)
_VAULT_URL_OPTION = typer.Option(
    None,
    "--vault-url",
    help="URL HTTPS du Vault (défaut : $HEIMDALL_VAULT_URL ou https://127.0.0.1:8443).",
)
_CA_CERT_OPTION = typer.Option(
    None,
    "--ca-cert",
    help="Chemin vers le certificat CA racine pour la vérification TLS.",
)
_NAMES_OPTION = typer.Option(
    None,
    "--name",
    "-n",
    help="Noms des secrets à récupérer (répétable).",
)
_OUTPUT_OPTION = typer.Option(
    Path(".env"),
    "--output",
    "-o",
    help="Fichier de destination (défaut : .env).",
)
_EXAMPLE_FILE_OPTION = typer.Option(
    Path(".env.example"),
    "--example-file",
    help="Fichier .env.example pour découvrir les noms des secrets.",
)
_BACKUP_OPTION = typer.Option(
    True,
    "--backup/--no-backup",
    help="Sauvegarder le fichier de destination existant en .bak (défaut : oui).",
)


def _init_client(
    vault_url: str | None,
    ca_cert: Path | None,
) -> VaultClient:
    """Résout la clé API et initialise le client Vault (fail-closed)."""
    try:
        api_key = resolve_api_key()
    except VaultClientError as exc:
        typer.echo(f"Erreur de configuration : {exc}", err=True)
        raise typer.Exit(code=2) from None

    target_url = resolve_vault_url(vault_url)
    try:
        return VaultClient(target_url, api_key, ca_cert=ca_cert)
    except ValueError as exc:
        typer.echo(f"Erreur de configuration : {exc}", err=True)
        raise typer.Exit(code=2) from None


def _validate_project_and_env(project: str | None, env: str) -> str:
    """Valide les identifiants de projet et d'environnement."""
    proj = project or detect_project()
    if not _PROJECT_ID_PATTERN.match(proj):
        typer.echo(
            f"Erreur : identifiant de projet invalide {proj!r} "
            "(attendu : ^[a-z][a-z0-9_-]{0,63}$).",
            err=True,
        )
        raise typer.Exit(code=2)

    if not _ENV_ID_PATTERN.match(env):
        typer.echo(
            f"Erreur : identifiant d'environnement invalide {env!r} "
            "(attendu : ^[a-z][a-z0-9_-]{0,31}$).",
            err=True,
        )
        raise typer.Exit(code=2)

    return proj


def _push_single_secret(
    client: VaultClient,
    proj: str,
    env: str,
    name: str,
    value: str,
) -> bool:
    """Envoie un secret unique et gère les statuts retournés."""
    if not _SECRET_NAME_PATTERN.match(name):
        typer.echo(
            f"Avertissement : nom de secret ignoré (format invalide) : {name}",
            err=True,
        )
        return False
    try:
        client.create_secret(proj, env, name, value)
        typer.echo(f"Secret '{name}' envoyé au Vault (état: vaulte).")
        return True
    except VaultConflictError:
        typer.echo(f"Secret '{name}' déjà existant dans le Vault (conflit 409).")
        return False
    except VaultAuthError:
        typer.echo(
            "Erreur 401 : Authentification requise ou clé API invalide.",
            err=True,
        )
        raise typer.Exit(code=1) from None
    except VaultForbiddenError:
        typer.echo(
            f"Erreur 403 : Accès interdit pour le projet '{proj}'.",
            err=True,
        )
        raise typer.Exit(code=1) from None
    except VaultRateLimitError as exc:
        msg = "Erreur 429 : Trop de requêtes."
        if exc.retry_after is not None:
            msg += f" Veuillez attendre {exc.retry_after} secondes (Retry-After)."
        typer.echo(msg, err=True)
        raise typer.Exit(code=1) from None
    except VaultClientError as exc:
        typer.echo(f"Erreur lors de l'envoi de '{name}' : {exc}", err=True)
        raise typer.Exit(code=1) from None


def vault_push(  # noqa: PLR0913
    project: str | None = _PROJECT_OPTION,
    env: str = _ENV_OPTION,
    file: Path = _FILE_OPTION,
    vault_url: str | None = _VAULT_URL_OPTION,
    ca_cert: Path | None = _CA_CERT_OPTION,
) -> None:
    """Pousse les secrets d'un fichier local vers le Vault (ticket #99)."""
    proj = _validate_project_and_env(project, env)

    if not file.is_file():
        typer.echo(f"Erreur : fichier de secrets introuvable : {file}", err=True)
        raise typer.Exit(code=2)

    secrets = parse_env_file(file)
    if not secrets:
        typer.echo(f"Aucun secret trouvé dans {file}.")
        raise typer.Exit(code=0)

    client = _init_client(vault_url, ca_cert)
    pushed_count = 0
    conflict_count = 0

    with client:
        for name, value in secrets.items():
            if _push_single_secret(client, proj, env, name, value):
                pushed_count += 1
            else:
                conflict_count += 1

    typer.echo(
        f"Push terminé : {pushed_count} secret(s) envoyé(s), "
        f"{conflict_count} déjà présent(s)."
    )


def _resolve_pull_names(
    names: list[str] | None,
    example_file: Path,
    output: Path,
) -> list[str]:
    """Détermine la liste des noms de secrets à récupérer."""
    if names:
        return list(names)
    if example_file.is_file():
        from_example = parse_example_names(example_file)
        if from_example:
            return from_example
    if output.is_file():
        from_output = list(parse_env_file(output).keys())
        if from_output:
            return from_output
    typer.echo(
        "Erreur : Aucun secret à récupérer. "
        "Spécifiez des noms via --name ou fournissez un fichier .env.example.",
        err=True,
    )
    raise typer.Exit(code=2)


def _pull_secrets_from_vault(
    client: VaultClient,
    proj: str,
    env: str,
    target_names: list[str],
) -> dict[str, str]:
    """Récupère les secrets depuis le Vault et gère les erreurs."""
    retrieved: dict[str, str] = {}
    for name in target_names:
        if not _SECRET_NAME_PATTERN.match(name):
            typer.echo(
                f"Avertissement : nom de secret ignoré (format invalide) : {name}",
                err=True,
            )
            continue
        try:
            record = client.get_secret(proj, env, name)
            retrieved[name] = str(record["value"])
        except VaultNotFoundError:
            typer.echo(
                f"Avertissement : secret '{name}' introuvable dans le Vault ({proj}/{env}).",
                err=True,
            )
        except VaultAuthError:
            typer.echo(
                "Erreur 401 : Authentification requise ou clé API invalide.",
                err=True,
            )
            raise typer.Exit(code=1) from None
        except VaultForbiddenError:
            typer.echo(
                f"Erreur 403 : Accès interdit pour le projet '{proj}'.",
                err=True,
            )
            raise typer.Exit(code=1) from None
        except VaultRateLimitError as exc:
            msg = "Erreur 429 : Trop de requêtes."
            if exc.retry_after is not None:
                msg += f" Veuillez attendre {exc.retry_after} secondes (Retry-After)."
            typer.echo(msg, err=True)
            raise typer.Exit(code=1) from None
        except VaultClientError as exc:
            typer.echo(f"Erreur lors de la récupération de '{name}' : {exc}", err=True)
            raise typer.Exit(code=1) from None
    return retrieved


def vault_pull(  # noqa: PLR0913, PLR0917
    project: str | None = _PROJECT_OPTION,
    env: str = _ENV_OPTION,
    names: list[str] | None = _NAMES_OPTION,
    output: Path = _OUTPUT_OPTION,
    example_file: Path = _EXAMPLE_FILE_OPTION,
    backup: bool = _BACKUP_OPTION,
    vault_url: str | None = _VAULT_URL_OPTION,
    ca_cert: Path | None = _CA_CERT_OPTION,
) -> None:
    """Récupère les secrets du Vault et écrit le fichier .env en droits 0600 (ticket #100)."""
    proj = _validate_project_and_env(project, env)
    target_names = _resolve_pull_names(names, example_file, output)

    client = _init_client(vault_url, ca_cert)
    with client:
        retrieved = _pull_secrets_from_vault(client, proj, env, target_names)

    if not retrieved:
        typer.echo("Aucun secret récupéré depuis le Vault.", err=True)
        raise typer.Exit(code=1)

    if output.exists() and backup:
        bak_file = backup_file(output)
        if bak_file:
            typer.echo(f"Sauvegarde du fichier existant vers {bak_file.name} (droits 0600).")

    lines = [f"{key}={value}" for key, value in retrieved.items()]
    content = "\n".join(lines) + "\n"
    write_file_atomic(output, content, mode=0o600)
    typer.echo(f"Fichier {output} mis à jour avec {len(retrieved)} secret(s) (droits 0600).")

    if is_git_tracked(output):
        typer.echo(
            f"ATTENTION : Le fichier {output} est suivi par Git ! "
            f"Exécutez 'git rm --cached {output}' et ajoutez-le à .gitignore "
            "pour éviter toute fuite.",
            err=True,
        )
    elif not is_git_ignored(output):
        typer.echo(
            f"Avertissement : Le fichier {output} n'est pas ignoré par Git. "
            f"Pensez à ajouter '{output}' dans .gitignore.",
            err=True,
        )


def _resolve_run_names(
    names: list[str] | None,
    example_file: Path,
) -> list[str]:
    """Détermine la liste des noms de secrets à injecter en mémoire."""
    if names:
        return list(names)
    if example_file.is_file():
        from_example = parse_example_names(example_file)
        if from_example:
            return from_example
    dot_env = Path(".env")
    if dot_env.is_file():
        from_env = list(parse_env_file(dot_env).keys())
        if from_env:
            return from_env
    return []


def vault_run(  # noqa: PLR0913, PLR0917
    ctx: typer.Context,
    project: str | None = _PROJECT_OPTION,
    env: str = _ENV_OPTION,
    names: list[str] | None = _NAMES_OPTION,
    example_file: Path = _EXAMPLE_FILE_OPTION,
    vault_url: str | None = _VAULT_URL_OPTION,
    ca_cert: Path | None = _CA_CERT_OPTION,
) -> None:
    """Lance une commande avec les secrets injectés en mémoire (ticket #101).

    Limite de sécurité : les secrets sont injectés dans l'environnement du sous-processus
    sans écriture sur disque. Néanmoins, sous Linux, les variables d'un processus sont
    visibles pour le même UID via /proc/<pid>/environ.
    """
    cmd = list(ctx.args)
    if not cmd:
        typer.echo(
            "Erreur : Aucune commande spécifiée. Usage : heimdall run -- <commande>",
            err=True,
        )
        raise typer.Exit(code=2)

    proj = _validate_project_and_env(project, env)
    target_names = _resolve_run_names(names, example_file)

    injected_secrets: dict[str, str] = {}
    if target_names:
        client = _init_client(vault_url, ca_cert)
        with client:
            injected_secrets = _pull_secrets_from_vault(client, proj, env, target_names)

    child_env = {**os.environ, **injected_secrets}

    try:
        proc = subprocess.run(cmd, env=child_env, check=False)  # noqa: S603
        raise typer.Exit(code=proc.returncode)
    except FileNotFoundError:
        typer.echo(f"Erreur : commande introuvable : {cmd[0]}", err=True)
        raise typer.Exit(code=2) from None
    except PermissionError:
        typer.echo(f"Erreur : permission refusée pour exécuter : {cmd[0]}", err=True)
        raise typer.Exit(code=2) from None


__all__ = ["vault_pull", "vault_push", "vault_run"]
