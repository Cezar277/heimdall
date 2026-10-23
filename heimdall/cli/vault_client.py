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
import shutil
import subprocess
from pathlib import Path
from typing import Final

import typer

from heimdall.vault.atomic import (
    backup_file,
    format_env_value,
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

_DANGEROUS_ENV_PREFIXES: Final[tuple[str, ...]] = (
    "LD_",
    "DYLD_",
    "PYTHON",
    "NODE_",
    "NPM_",
    "YARN_",
    "PNPM_",
    "RUBY",
    "PERL",
    "GIT_",
    "BASH_",
    "PROMPT_",
    "SYSTEMD_",
    "JAVA_",
    "JDK_",
    "_JAVA_",
    "MAVEN_",
    "GRADLE_",
    "DOTNET_",
    "COMPOSE_",
    "DOCKER_",
    "AWS_",
    "TF_",
    "KUBE_",
    "HELM_",
    "XDG_",
    "CARGO_",
    "RUSTUP_",
    "RUSTC_",
    "OPENSSL_",
    "MALLOC_",
)
_DANGEROUS_ENV_EXACT: Final[frozenset[str]] = frozenset({
    "PATH",
    "SHELL",
    "IFS",
    "BASH_ENV",
    "BASHOPTS",
    "SHELLOPTS",
    "ENV",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PROMPT_COMMAND",
    "ZDOTDIR",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    "CORE_PAGER",
    "PAGER",
    "MANPAGER",
    "LESSOPEN",
    "LESSCLOSE",
    "EDITOR",
    "VISUAL",
    "SUDO_ASKPASS",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "SSH_AUTH_SOCK",
    "SSH_ORIGINAL_COMMAND",
    "KUBECONFIG",
    "GOBIN",
    "GOCACHE",
    "GOFLAGS",
    "GOMODCACHE",
    "GOPATH",
    "GOROOT",
    "GOTOOLCHAIN",
    "CC",
    "CXX",
    "CPP",
    "CFLAGS",
    "CPPFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "MAKEFLAGS",
    "MFLAGS",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
})

_MAX_ERROR_MSG_LEN: Final[int] = 150
_TRUNCATE_MSG_LEN: Final[int] = 147


def is_dangerous_env_var(name: str) -> bool:
    """Vérifie si un nom de variable est dangereux pour l'exécution d'un processus."""
    upper = name.upper()
    if upper in _DANGEROUS_ENV_EXACT:
        return True
    return any(upper.startswith(prefix) for prefix in _DANGEROUS_ENV_PREFIXES)


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
    help="Environnement cible (dev, staging, prod...).",
)
_FILE_OPTION = typer.Option(
    Path(".env"),
    "--file",
    "-f",
    help="Fichier de secrets source (.env par défaut).",
)
_OUTPUT_OPTION = typer.Option(
    Path(".env"),
    "--output",
    "-o",
    help="Fichier de destination (.env par défaut).",
)
_EXAMPLE_FILE_OPTION = typer.Option(
    Path(".env.example"),
    "--example-file",
    help="Fichier .env.example pour découvrir les noms des secrets.",
)
_NAMES_OPTION = typer.Option(
    None,
    "--name",
    "-n",
    help="Noms spécifiques de secrets à traiter (répétable).",
)
_BACKUP_OPTION = typer.Option(
    True,
    "--backup/--no-backup",
    help="Crée une sauvegarde .bak si le fichier cible existe déjà.",
)
_VAULT_URL_OPTION = typer.Option(
    None,
    "--vault-url",
    help="URL du Vault (défaut : $HEIMDALL_VAULT_URL ou https://127.0.0.1:8443).",
)
_CA_CERT_OPTION = typer.Option(
    None,
    "--ca-cert",
    help="Chemin vers un certificat CA interne pour vérifier le Vault TLS.",
)


def _init_client(vault_url: str | None, ca_cert: Path | None) -> VaultClient:
    """Initialise le client Vault avec URL, clé et TLS vérifié."""
    url = resolve_vault_url(vault_url)
    try:
        api_key = resolve_api_key()
    except VaultClientError as exc:
        typer.echo(f"Erreur de configuration : {exc}", err=True)
        raise typer.Exit(code=2) from None

    try:
        return VaultClient(base_url=url, api_key=api_key, ca_cert=ca_cert)
    except ValueError as exc:
        typer.echo(f"Configuration du client invalide : {exc}", err=True)
        raise typer.Exit(code=2) from None


def _validate_project_and_env(project: str | None, env: str) -> str:
    """Valide et résout le nom de projet et d'environnement."""
    proj = project or detect_project()
    if not _PROJECT_ID_PATTERN.match(proj):
        typer.echo(f"Identifiant de projet invalide : {proj[:32]!r}", err=True)
        raise typer.Exit(code=2)
    if not _ENV_ID_PATTERN.match(env):
        typer.echo(f"Identifiant d'environnement invalide : {env[:32]!r}", err=True)
        raise typer.Exit(code=2)
    return proj


def _read_input_secrets(input_file: Path) -> dict[str, str]:
    """Lit les secrets locaux depuis un fichier d'entrée.

    Retourne un dictionnaire vide si le fichier est lisible mais ne contient
    aucune paire ``clé=valeur``. Le code de sortie est décidé par l'appelant :
    un fichier vide sans filtre est un succès documenté (0), un filtre
    explicite sans correspondance est une erreur d'usage (2).
    """
    if os.path.islink(input_file):
        typer.echo(
            f"Erreur de sécurité : le fichier source '{input_file}' est un lien symbolique.",
            err=True,
        )
        raise typer.Exit(code=2)
    if not input_file.is_file():
        typer.echo(f"Fichier d'entrée introuvable : {input_file}", err=True)
        raise typer.Exit(code=2)
    secrets = parse_env_file(input_file)
    if secrets is None:
        typer.echo(
            f"Erreur lors de la lecture du fichier '{input_file}' : "
            "fichier illisible ou non sécurisé.",
            err=True,
        )
        raise typer.Exit(code=2)
    return secrets


def _filter_secrets(
    secrets: dict[str, str],
    names: list[str] | None,
) -> dict[str, str]:
    """Filtre les secrets par nom et valide leur forme contractuelle."""
    target_names = set(names) if names else set(secrets.keys())
    filtered: dict[str, str] = {}
    for key, value in secrets.items():
        if key not in target_names:
            continue
        if not _SECRET_NAME_PATTERN.match(key):
            typer.echo(
                f"Avertissement : nom de secret ignoré (format invalide) : {key[:32]!r}",
                err=True,
            )
            continue
        filtered[key] = value
    return filtered


def _push_single_secret(  # noqa: PLR0913, PLR0917
    client: VaultClient,
    proj: str,
    env: str,
    name: str,
    value: str,
    force: bool,
) -> None:
    """Envoie un secret unique au Vault et gère les erreurs contractuelles."""
    try:
        client.create_secret(proj, env, name, value)
        typer.echo(f"Secret '{name}' poussé vers le Vault ({proj}/{env}) [statut: vaulte].")
    except VaultConflictError:
        typer.echo(
            f"Avertissement : le secret '{name}' existe déjà dans le Vault ({proj}/{env}) "
            "(409 Conflict).",
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
    except ValueError:
        # Validation locale du client (valeur vide ou > 65536 caractères).
        # Le message est statique : la valeur n'est jamais reflétée.
        typer.echo(
            f"Erreur : valeur invalide pour le secret '{name}' "
            "(1-65536 caractères requis).",
            err=True,
        )
        raise typer.Exit(code=2) from None
    except VaultClientError as exc:
        typer.echo(f"Erreur lors de l'envoi de '{name}' : {exc}", err=True)
        raise typer.Exit(code=1) from None


def vault_push(  # noqa: PLR0913, PLR0917
    project: str | None = _PROJECT_OPTION,
    env: str = _ENV_OPTION,
    file: Path = _FILE_OPTION,
    names: list[str] | None = _NAMES_OPTION,
    vault_url: str | None = _VAULT_URL_OPTION,
    ca_cert: Path | None = _CA_CERT_OPTION,
) -> None:
    """Pousse les secrets d'un fichier local vers le Vault (ticket #99).

    Ne divulgue JAMAIS les valeurs secrètes dans la sortie terminal ou les erreurs.

    Codes de sortie : 0 si le fichier est vide sans filtre explicite, 2 si un
    ``--name`` fourni ne correspond à aucun secret (aucun envoi silencieux).
    """
    proj = _validate_project_and_env(project, env)
    all_secrets = _read_input_secrets(file)

    if not all_secrets:
        typer.echo(f"Aucun secret trouvé dans le fichier {file}.", err=True)
        raise typer.Exit(code=2 if names else 0)

    to_push = _filter_secrets(all_secrets, names)
    if not to_push:
        if names:
            typer.echo(
                "Aucun secret ne correspond aux noms demandés : rien n'a été poussé.",
                err=True,
            )
            raise typer.Exit(code=2)
        typer.echo("Aucun secret valide à pousser.", err=True)
        raise typer.Exit(code=2)

    client = _init_client(vault_url, ca_cert)
    with client:
        for name, value in to_push.items():
            _push_single_secret(client, proj, env, name, value, False)

    typer.echo(f"{len(to_push)} secret(s) traités pour le projet '{proj}' ({env}).")


def _resolve_pull_names(
    names: list[str] | None,
    example_file: Path,
    output: Path,
) -> list[str]:
    """Détermine la liste des noms de secrets à récupérer."""
    if names:
        return list(names)
    if os.path.islink(example_file):
        typer.echo(
            f"Erreur de sécurité : le fichier d'exemple '{example_file}' est un lien symbolique.",
            err=True,
        )
        raise typer.Exit(code=2)
    if example_file.is_file():
        from_example = parse_example_names(example_file)
        if from_example is None:
            typer.echo(
                f"Erreur lors de la lecture du fichier '{example_file}' : "
                "fichier illisible ou non sécurisé.",
                err=True,
            )
            raise typer.Exit(code=2)
        if from_example:
            return from_example
    if os.path.islink(output):
        typer.echo(
            f"Erreur de sécurité : le fichier de sortie '{output}' est un lien symbolique.",
            err=True,
        )
        raise typer.Exit(code=2)
    if output.is_file():
        parsed = parse_env_file(output)
        if parsed is None:
            typer.echo(
                f"Erreur lors de la lecture du fichier '{output}' : "
                "fichier illisible ou non sécurisé.",
                err=True,
            )
            raise typer.Exit(code=2)
        from_existing = list(parsed.keys())
        if from_existing:
            return from_existing
    typer.echo(
        "Aucun nom de secret spécifié. "
        "Utilisez --name, fournissez un .env.example ou pointez vers un .env existant.",
        err=True,
    )
    raise typer.Exit(code=2)


def _pull_secrets_from_vault(
    client: VaultClient,
    proj: str,
    env: str,
    target_names: list[str],
) -> dict[str, str]:
    """Récupère les valeurs de chaque secret depuis le Vault."""
    retrieved: dict[str, str] = {}
    for name in target_names:
        if not _SECRET_NAME_PATTERN.match(name):
            typer.echo(
                f"Avertissement : nom de secret ignoré (format invalide) : {name[:32]!r}",
                err=True,
            )
            continue
        if is_dangerous_env_var(name):
            typer.echo(
                f"Erreur de sécurité : le secret '{name}' est une variable système interdite.",
                err=True,
            )
            raise typer.Exit(code=1)
        try:
            record = client.get_secret(proj, env, name)
            val = record.get("value")
            if not isinstance(val, str):
                typer.echo(
                    f"Erreur : valeur de type inattendu pour '{name}' dans le Vault.",
                    err=True,
                )
                raise typer.Exit(code=1)
            if "\x00" in val:
                typer.echo(
                    f"Erreur de sécurité : le secret '{name}' contient un octet nul interdit.",
                    err=True,
                )
                raise typer.Exit(code=1)
            retrieved[name] = val
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
            msg = str(exc)
            if len(msg) > _MAX_ERROR_MSG_LEN:
                msg = msg[:_TRUNCATE_MSG_LEN] + "..."
            typer.echo(f"Erreur lors de la récupération de '{name}' : {msg}", err=True)
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

    # Vérification anti-injection : aucune valeur ne doit contenir de retour chariot ou de saut
    for key, value in retrieved.items():
        if "\n" in value or "\r" in value:
            typer.echo(
                f"Erreur : Le secret '{key}' contient un saut de ligne interdit dans le fichier "
                ".env (risque d'injection).",
                err=True,
            )
            raise typer.Exit(code=1)

    if output.exists() and backup:
        try:
            bak_file = backup_file(output)
        except ValueError as exc:
            typer.echo(f"Erreur de sécurité lors de la sauvegarde : {exc}", err=True)
            raise typer.Exit(code=1) from None
        if bak_file:
            typer.echo(f"Sauvegarde du fichier existant vers {bak_file.name} (droits 0600).")

    lines = [f"{key}={format_env_value(value)}" for key, value in retrieved.items()]
    content = "\n".join(lines) + "\n"
    try:
        write_file_atomic(output, content, mode=0o600)
    except (ValueError, OSError) as exc:
        typer.echo(f"Erreur de sécurité lors de l'écriture : {exc}", err=True)
        raise typer.Exit(code=1) from None

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
    if os.path.islink(example_file):
        typer.echo(
            f"Erreur de sécurité : le fichier d'exemple '{example_file}' est un lien symbolique.",
            err=True,
        )
        raise typer.Exit(code=2)
    if example_file.is_file():
        from_example = parse_example_names(example_file)
        if from_example is None:
            typer.echo(
                f"Erreur lors de la lecture du fichier '{example_file}' : "
                "fichier illisible ou non sécurisé.",
                err=True,
            )
            raise typer.Exit(code=2)
        if from_example:
            return from_example
    dot_env = Path(".env")
    if os.path.islink(dot_env):
        typer.echo(
            f"Erreur de sécurité : le fichier '{dot_env}' est un lien symbolique.",
            err=True,
        )
        raise typer.Exit(code=2)
    if dot_env.is_file():
        parsed = parse_env_file(dot_env)
        if parsed is None:
            typer.echo(
                f"Erreur lors de la lecture du fichier '{dot_env}' : "
                "fichier illisible ou non sécurisé.",
                err=True,
            )
            raise typer.Exit(code=2)
        from_env = list(parsed.keys())
        if from_env:
            return from_env
    typer.echo(
        "Erreur : Aucun secret spécifié ou découvert. "
        "Utilisez --name, fournissez un .env.example ou pointez vers un .env existant.",
        err=True,
    )
    raise typer.Exit(code=2)


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

    Allowlist locale : seuls les noms explicitement fournis par ``--name``, le
    ``.env.example`` ou le ``.env`` local sont demandés au Vault. Le nom renvoyé
    par la réponse du Vault n'est jamais utilisé comme nom de variable ; un
    Vault compromis ne peut donc pas introduire une variable arbitraire, il ne
    peut que fournir la valeur d'un nom déjà autorisé localement. Une denylist
    de variables d'exécution système (PATH, LD_*, BASH_*, prompt, runtimes,
    outils de build, etc.) reste appliquée en défense en profondeur.

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

    # Résolution préalable de l'exécutable dans le PATH actuel sans influence de variables injectées
    executable = shutil.which(cmd[0])
    if executable is None and not Path(cmd[0]).is_file():
        typer.echo(f"Erreur : commande introuvable : '{cmd[0]}'", err=True)
        raise typer.Exit(code=127)

    proj = _validate_project_and_env(project, env)
    target_names = _resolve_run_names(names, example_file)

    client = _init_client(vault_url, ca_cert)
    with client:
        injected_secrets = _pull_secrets_from_vault(client, proj, env, target_names)

    if not injected_secrets:
        typer.echo("Erreur : Aucun secret récupéré depuis le Vault pour injection.", err=True)
        raise typer.Exit(code=1)

    # Allowlist locale : `injected_secrets` est indexé par les noms demandés
    # localement (jamais par `record["name"]` renvoyé par le Vault).
    # Garde anti-détournement : interdiction d'injecter des variables système sensibles.
    for secret_name in injected_secrets:
        if is_dangerous_env_var(secret_name):
            typer.echo(
                f"Erreur de sécurité : injection refusée pour la variable système '{secret_name}'.",
                err=True,
            )
            raise typer.Exit(code=1)

    target_cmd = [executable if executable is not None else cmd[0], *cmd[1:]]
    child_env = {**os.environ, **injected_secrets}

    try:
        proc = subprocess.run(target_cmd, env=child_env, check=False)  # noqa: S603
        raise typer.Exit(code=proc.returncode)
    except FileNotFoundError:
        typer.echo(f"Erreur : commande introuvable : {cmd[0]}", err=True)
        raise typer.Exit(code=127) from None
    except PermissionError:
        typer.echo(f"Erreur : permission refusée pour exécuter : {cmd[0]}", err=True)
        raise typer.Exit(code=126) from None
    except (ValueError, OSError) as exc:
        typer.echo(f"Erreur lors de l'exécution de la commande : {exc}", err=True)
        raise typer.Exit(code=1) from None


__all__ = ["is_dangerous_env_var", "vault_pull", "vault_push", "vault_run"]
