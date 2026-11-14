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
import stat
import subprocess  # nosec B404
from pathlib import Path
from typing import Final, NoReturn

import typer

from heimdall.remediation.naming import is_dangerous_env_var, is_dangerous_exec_env_var
from heimdall.vault.atomic import (
    _bounded_error_message,
    _get_git_toplevel,
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


def preview_name(name: object) -> str:
    """Reflet borné et sûr d'un nom de secret (jamais de reflet pour un non-str)."""
    return name[:32] if isinstance(name, str) else type(name).__name__


# Denylist robuste : source unique = heimdall.remediation.naming
# (importée ci-dessus ; mêmes objets, pas de copie qui divergerait).
_MAX_SECRETS_PER_PULL: Final[int] = 1024
_MAX_TOTAL_SECRET_CHARS: Final[int] = 1_048_576

#: Réglages Typer partagés par les deux voies `run` (canonique `heimdall run`
#: + alias `heimdall vault run`) : source unique anti-divergence.
RUN_CONTEXT_SETTINGS: Final[dict[str, bool]] = {
    "allow_extra_args": True,
    "ignore_unknown_options": True,
}


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
        msg = _bounded_error_message(str(exc))
        typer.echo(f"Erreur de configuration : {msg}", err=True)
        raise typer.Exit(code=2) from None

    try:
        return VaultClient(base_url=url, api_key=api_key, ca_cert=ca_cert)
    except ValueError as exc:
        typer.echo(f"Configuration du client invalide : {exc}", err=True)
        raise typer.Exit(code=2) from None


def _validate_project_and_env(project: str | None, env: str) -> str:
    """Valide et résout le nom de projet et d'environnement."""
    try:
        proj = project or detect_project()
    except VaultClientError as exc:
        typer.echo(f"Erreur de configuration : {exc}", err=True)
        raise typer.Exit(code=2) from None
    if not _PROJECT_ID_PATTERN.fullmatch(proj):
        typer.echo(f"Identifiant de projet invalide : {preview_name(proj)!r}", err=True)
        raise typer.Exit(code=2)
    if not _ENV_ID_PATTERN.fullmatch(env):
        typer.echo(f"Identifiant d'environnement invalide : {preview_name(env)!r}", err=True)
        raise typer.Exit(code=2)
    return proj


def _validate_requested_names(names: list[str] | None) -> None:
    """Refus franc des noms ``--name`` de format invalide (même sévérité que 404).

    Un nom explicitement demandé qui ne respecte pas
    ``^[A-Z][A-Z0-9_]{1,63}$`` sort en ``Exit(1)`` avant toute E/S : jamais
    de succès partiel où l'utilisateur croirait l'ensemble demandé traité.
    Les noms découverts via fichiers restent tolérés avec avertissement
    (voir ``_filter_secrets`` et ``_pull_secrets_from_vault``).
    """
    if not names:
        return
    for name in names:
        if not isinstance(name, str) or not _SECRET_NAME_PATTERN.fullmatch(name):
            typer.echo(
                f"Erreur : nom de secret invalide demandé : {preview_name(name)!r} "
                "(format requis : ^[A-Z][A-Z0-9_]{1,63}$).",
                err=True,
            )
            raise typer.Exit(code=1)


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
    names: list[str] | None = None,
) -> dict[str, str]:
    """Filtre les secrets par nom et valide leur forme contractuelle.

    Les noms ``--name`` invalides sont déjà refusés en ``Exit(1)`` par
    ``_validate_requested_names`` ; l'avertissement + saut ci-dessous ne
    couvre que les clés découvertes via fichier (tolérance documentée).
    """
    target_names = set(names) if names else set(secrets.keys())
    filtered: dict[str, str] = {}
    for key, value in secrets.items():
        if key not in target_names:
            continue
        if is_dangerous_exec_env_var(key):
            # Même refus que pull/run : un nom interdit à l'injection ne doit
            # jamais être stocké (secret empoisonné, rotation crue mais
            # inexploitable). Code 2 = validation locale avant tout réseau ;
            # pull/run sortent en 1 car le refus y intervient dans le pipeline
            # de récupération (voir docs/t35-samm.md §6).
            typer.echo(
                f"Erreur de sécurité : le secret {preview_name(key)!r} "
                "est une variable système interdite.",
                err=True,
            )
            raise typer.Exit(code=2)
        if not isinstance(key, str) or not _SECRET_NAME_PATTERN.fullmatch(key):
            typer.echo(
                f"Avertissement : nom de secret ignoré (format invalide) : {preview_name(key)!r}",
                err=True,
            )
            continue
        filtered[key] = value
    return filtered


def _push_single_secret(
    client: VaultClient,
    proj: str,
    env: str,
    name: str,
    value: str,
) -> bool:
    """Envoie un secret unique au Vault et gère les erreurs contractuelles.

    Retourne ``True`` si le secret a été créé, ``False`` s'il existait déjà
    (409 : avertissement, non écrasé). Les autres erreurs sortent en `Exit`.
    """
    if is_dangerous_exec_env_var(name):
        # Reflet borné et échappé : `_push_single_secret` peut être appelée
        # directement (défense en profondeur) avant tout contrôle de format.
        # Un nom non-str n'est jamais reflété : seul son type est affiché.
        typer.echo(
            f"Erreur de sécurité : le secret {preview_name(name)!r} "
            "est une variable système interdite.",
            err=True,
        )
        raise typer.Exit(code=2)
    name_preview = f"{preview_name(name)!r}"
    try:
        client.create_secret(proj, env, name, value)
        typer.echo(f"Secret {name_preview} poussé vers le Vault ({proj}/{env}) [statut: vaulte].")
        return True
    except VaultConflictError:
        typer.echo(
            f"Avertissement : le secret {name_preview} existe déjà dans le Vault ({proj}/{env}) "
            "(409 Conflict).",
            err=True,
        )
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
    except ValueError:
        # Validation locale du client : distinguer identifiant et valeur.
        # L'identifiant a déjà été validé en amont (patterns CLI) : cette
        # branche est de la défense en profondeur. La valeur n'est jamais
        # reflétée (message statique, invariant 8).
        if not isinstance(name, str) or not _SECRET_NAME_PATTERN.fullmatch(name):
            typer.echo(
                f"Erreur : nom de secret invalide : {preview_name(name)!r} "
                "(format requis : ^[A-Z][A-Z0-9_]{1,63}$).",
                err=True,
            )
        else:
            typer.echo(
                f"Erreur : valeur invalide pour le secret {name_preview} "
                "(1-65536 caractères requis).",
                err=True,
            )
        raise typer.Exit(code=2) from None
    except VaultClientError as exc:
        msg = _bounded_error_message(str(exc))
        typer.echo(f"Erreur lors de l'envoi de {name_preview} : {msg}", err=True)
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
    ``--name`` fourni ne correspond à aucun secret (aucun envoi silencieux),
    1 si un ``--name`` fourni est de format invalide (refus franc, même
    sévérité que 404), 1 si aucun secret créé (tous déjà existants, 409 —
    jamais de succès affiché sans création).
    """
    proj = _validate_project_and_env(project, env)
    _validate_requested_names(names)
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

    total_chars = 0
    for name, value in to_push.items():
        if not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value:
            # Refus franc avant tout envoi : un octet nul ou un saut de ligne
            # rendrait le secret inexploitable (pull/run le rejettent).
            # Message statique : la valeur n'est jamais reflétée.
            typer.echo(
                f"Erreur : valeur invalide pour le secret {name[:32]!r} "
                "(octets nuls et sauts de ligne interdits).",
                err=True,
            )
            raise typer.Exit(code=2)
        total_chars += len(value)

    # Mêmes bornes anti-DoS que pull/run, AVANT toute initialisation client
    # et donc avant le premier POST : jamais d'envoi partiel.
    _enforce_secret_count(len(to_push))
    _enforce_total_secret_chars(total_chars)

    client = _init_client(vault_url, ca_cert)
    created = 0
    skipped = 0
    with client:
        for name, value in to_push.items():
            if _push_single_secret(client, proj, env, name, value):
                created += 1
            else:
                skipped += 1

    if created == 0:
        typer.echo(
            f"Aucun secret créé : {skipped} déjà existant(s) dans le Vault "
            f"({proj}/{env}), non écrasé(s) (409 Conflict).",
            err=True,
        )
        raise typer.Exit(code=1)
    if skipped:
        typer.echo(
            f"{created} secret(s) créé(s), {skipped} déjà existant(s) "
            f"(409, non écrasé(s)) pour le projet '{proj}' ({env})."
        )
    else:
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


def _enforce_secret_count(count: int) -> None:
    """Refuse un nombre de secrets au-delà du plafond anti-DoS local."""
    if count > _MAX_SECRETS_PER_PULL:
        typer.echo(
            f"Erreur de sécurité : trop de secrets ({count}, max {_MAX_SECRETS_PER_PULL}).",
            err=True,
        )
        raise typer.Exit(code=1)


def _enforce_total_secret_chars(total_chars: int) -> None:
    """Refuse un volume cumulé de valeurs au-delà du plafond anti-OOM local."""
    if total_chars > _MAX_TOTAL_SECRET_CHARS:
        typer.echo(
            "Erreur de sécurité : volume cumulé des secrets trop important "
            f"(max {_MAX_TOTAL_SECRET_CHARS} caractères).",
            err=True,
        )
        raise typer.Exit(code=1)


def _pull_secrets_from_vault(  # noqa: PLR0912, PLR0915
    client: VaultClient,
    proj: str,
    env: str,
    target_names: list[str],
) -> dict[str, str]:
    """Récupère les valeurs de chaque secret depuis le Vault.

    Échec franc (``Exit(1)``) dès qu'un secret demandé est introuvable
    (404) : jamais de ``.env`` partiel ni d'injection partielle. Un nom
    manquant (faute de frappe, secret révoqué) sort en erreur au lieu de
    laisser croire à une configuration complète (invariant 11). Les noms
    ``--name`` de format invalide sont déjà refusés par
    ``_validate_requested_names`` ; l'avertissement + saut sur format
    invalide ci-dessous ne couvre que les noms découverts via fichiers.

    Deux bornes anti-OOM s'appliquent AVANT toute écriture/injection (et avant
    même la première requête pour le nombre) : au plus
    ``_MAX_SECRETS_PER_PULL`` noms, et au plus ``_MAX_TOTAL_SECRET_CHARS``
    caractères cumulés. Un Vault compromis ne peut donc pas faire croître le
    dict/``.env``/environnement enfant à plusieurs Go.
    """
    _enforce_secret_count(len(target_names))

    retrieved: dict[str, str] = {}
    total_chars = 0
    for name in target_names:
        if is_dangerous_exec_env_var(name):
            typer.echo(
                f"Erreur de sécurité : le secret {preview_name(name)!r} "
                "est une variable système interdite.",
                err=True,
            )
            raise typer.Exit(code=1)
        if not isinstance(name, str) or not _SECRET_NAME_PATTERN.fullmatch(name):
            typer.echo(
                f"Avertissement : nom de secret ignoré (format invalide) : {preview_name(name)!r}",
                err=True,
            )
            continue
        try:
            record = client.get_secret(proj, env, name)
            if record.get("status") != "vaulte":
                typer.echo(
                    f"Erreur de sécurité : le secret {preview_name(name)!r} "
                    "n'est pas au statut 'vaulte'.",
                    err=True,
                )
                raise typer.Exit(code=1)
            val = record.get("value")
            if not isinstance(val, str):
                typer.echo(
                    f"Erreur : valeur de type inattendu pour {preview_name(name)!r} dans le Vault.",
                    err=True,
                )
                raise typer.Exit(code=1)
            if "\x00" in val:
                typer.echo(
                    f"Erreur de sécurité : le secret {preview_name(name)!r} "
                    "contient un octet nul interdit.",
                    err=True,
                )
                raise typer.Exit(code=1)
            total_chars += len(val)
            _enforce_total_secret_chars(total_chars)
            retrieved[name] = val
        except VaultNotFoundError:
            typer.echo(
                f"Erreur : secret {preview_name(name)!r} introuvable dans le Vault ({proj}/{env}).",
                err=True,
            )
            raise typer.Exit(code=1) from None
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
            msg = _bounded_error_message(str(exc))
            typer.echo(
                f"Erreur lors de la récupération de {preview_name(name)!r} : {msg}",
                err=True,
            )
            raise typer.Exit(code=1) from None
        except ValueError:
            # Défense en profondeur : les patterns CLI et client sont
            # dupliqués aujourd'hui. Une divergence future ne doit jamais
            # produire un traceback (invariant 11) ni refléter la valeur.
            typer.echo(
                f"Erreur : identifiant invalide pour le secret {preview_name(name)!r}.",
                err=True,
            )
            raise typer.Exit(code=1) from None
    return retrieved


def vault_pull(  # noqa: PLR0912, PLR0913, PLR0917
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
    _validate_requested_names(names)
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
                f"Erreur : Le secret {preview_name(key)!r} contient un saut de ligne interdit "
                "dans le fichier .env (risque d'injection).",
                err=True,
            )
            raise typer.Exit(code=1)

    bak_file: Path | None = None
    if output.exists() and backup:
        try:
            bak_file = backup_file(output)
        except ValueError as exc:
            msg = _bounded_error_message(str(exc))
            typer.echo(f"Erreur de sécurité lors de la sauvegarde : {msg}", err=True)
            raise typer.Exit(code=1) from None
        if bak_file:
            typer.echo(f"Sauvegarde du fichier existant vers {bak_file.name} (droits 0600).")

    lines = [f"{key}={format_env_value(value)}" for key, value in retrieved.items()]
    content = "\n".join(lines) + "\n"
    try:
        write_file_atomic(output, content, mode=0o600)
    except (ValueError, OSError) as exc:
        msg = _bounded_error_message(str(exc))
        typer.echo(f"Erreur de sécurité lors de l'écriture : {msg}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"Fichier {output} mis à jour avec {len(retrieved)} secret(s) (droits 0600).")

    # Garde-fou Git (invariant 10) : le .env ET sa sauvegarde .bak contiennent
    # des secrets — le contrôle porte sur les deux, jamais sur output seul.
    for guarded_path in [output] + ([bak_file] if bak_file else []):
        if is_git_tracked(guarded_path):
            typer.echo(
                f"ATTENTION : Le fichier {guarded_path} est suivi par Git ! "
                f"Exécutez 'git rm --cached {guarded_path}' et ajoutez-le à .gitignore "
                "pour éviter toute fuite.",
                err=True,
            )
        elif is_git_ignored(guarded_path):
            pass  # Ignoré avéré : rien à signaler.
        elif _get_git_toplevel(guarded_path) is None:
            typer.echo(
                f"Avertissement : statut Git indéterminé pour '{guarded_path}' "
                "(hors dépôt ou git indisponible) : impossible de vérifier "
                "qu'il ne sera pas committé. Ajoutez-le à .gitignore et "
                "vérifiez avec 'git status'.",
                err=True,
            )
        else:
            typer.echo(
                f"Avertissement : Le fichier {guarded_path} n'est pas ignoré par Git. "
                f"Pensez à ajouter '{guarded_path}' dans .gitignore.",
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


def _regular_file_identity(path: str) -> tuple[int, int, int, int, int] | None:
    """Empreinte d'un fichier régulier, sinon ``None``.

    Retourne ``(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)`` : au-delà
    du simple chemin, un rename (nouvel inode), une réécriture en place
    (taille/mtime/ctime changés) ou un type non régulier (FIFO, répertoire...)
    est détecté fail-closed. Les liens symboliques du PATH
    (``/usr/bin/python3``...) sont suivis volontairement : l'empreinte est
    celle de la cible réellement exécutée. Limite documentée : une réécriture
    préservant inode ET taille/mtime/ctime (horloge ou FS à granularité
    grossière) n'est pas détectable sans ``fexecve``.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _refuse_modified_command() -> NoReturn:
    """Refuse une commande dont l'empreinte a changé pendant le fetch Vault."""
    typer.echo(
        "Erreur de sécurité : commande modifiée ou remplacée entre résolution et exécution.",
        err=True,
    )
    raise typer.Exit(code=1)


def vault_run(  # noqa: PLR0912, PLR0913, PLR0915, PLR0917
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
    outils de build, HEIMDALL_*, CDPATH/GLOBIGNORE/HISTFILE/MAILCAPS,
    TERMINFO/TERMPATH/VIRTUAL_ENV, INPUTRC/TERM/TZ/TERMCAP/LUA_*,
    runtimes (BUN_/DENO_/UV_/PIP_/BUNDLE_/GEM_/CONDA_), etc.)
    reste appliquée en défense en profondeur. Tout nom listé localement est
    une entrée de confiance : ne jamais y inscrire de variable de comportement
    shell (dont INPUTRC/TERM/TZ — readline, terminal, fuseau — ni LUA_*
    — chargement de modules) dans ``--name``/``.env.example``/``.env``.

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

    # Résolution préalable de l'exécutable dans le PATH actuel sans influence
    # de variables injectées. L'empreinte du fichier est figée avant le
    # round-trip Vault : le chemin seul ne suffit pas, un remplacement à même
    # chemin exécuterait sinon le binaire substitué avec les secrets.
    executable = shutil.which(cmd[0])
    # Voie `which` comme voie slash : figer l'empreinte du fichier réellement
    # visé AVANT le round-trip Vault (les deux voies sont soumises au même
    # remplacement à même chemin pendant le fetch). Pour la voie slash,
    # l'empreinte sert aussi de contrôle d'existence/type (fichier régulier).
    executable_identity = _regular_file_identity(executable if executable is not None else cmd[0])
    if executable is None and executable_identity is None:
        typer.echo(f"Erreur : commande introuvable : '{cmd[0]}'", err=True)
        raise typer.Exit(code=127)

    proj = _validate_project_and_env(project, env)
    _validate_requested_names(names)
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
        if is_dangerous_exec_env_var(secret_name):
            typer.echo(
                "Erreur de sécurité : injection refusée pour la variable système "
                f"{preview_name(secret_name)!r}.",
                err=True,
            )
            raise typer.Exit(code=1)

    target_cmd = [executable if executable is not None else cmd[0], *cmd[1:]]
    child_env = {
        env_key: env_val
        for env_key, env_val in os.environ.items()
        if env_key.upper() not in {"HEIMDALL_API_KEY", "HEIMDALL_API_KEY_FILE"}
        and not env_key.upper().startswith("HEIMDALL_VAULT_")
    }
    child_env.update(injected_secrets)

    # Anti-TOCTOU juste avant l'exécution : si la commande était un chemin,
    # le fichier a pu être substitué pendant le round-trip réseau — refuser
    # s'il a disparu ou n'est plus un fichier régulier (lien, FIFO...).
    if executable is None:
        try:
            path_still_ok = stat.S_ISREG(os.lstat(cmd[0]).st_mode)
        except OSError:
            path_still_ok = False
        if not path_still_ok:
            typer.echo(f"Erreur : commande introuvable : '{cmd[0]}'", err=True)
            raise typer.Exit(code=127)
    elif shutil.which(cmd[0]) != executable:
        _refuse_modified_command()

    # Voie `which` ET voie slash : l'empreinte figée avant le fetch doit être
    # identique juste avant `exec` (même chemin mais inode/taille/mtime/ctime
    # différents → refus). Une réécriture préservant toute l'empreinte reste
    # une limite documentée (pas de `fexecve` portable).
    current_identity = _regular_file_identity(executable if executable is not None else cmd[0])
    if (
        executable_identity is None
        or current_identity is None
        or current_identity != executable_identity
    ):
        _refuse_modified_command()

    try:
        proc = subprocess.run(target_cmd, env=child_env, check=False)  # noqa: S603  # nosec B603
        raise typer.Exit(code=proc.returncode)
    except FileNotFoundError:
        typer.echo(f"Erreur : commande introuvable : {cmd[0]}", err=True)
        raise typer.Exit(code=127) from None
    except PermissionError:
        typer.echo(f"Erreur : permission refusée pour exécuter : {cmd[0]}", err=True)
        raise typer.Exit(code=126) from None
    except (ValueError, OSError) as exc:
        msg = _bounded_error_message(str(exc))
        typer.echo(f"Erreur lors de l'exécution de la commande : {msg}", err=True)
        raise typer.Exit(code=1) from None


__all__ = [
    "RUN_CONTEXT_SETTINGS",
    "is_dangerous_env_var",
    "preview_name",
    "vault_pull",
    "vault_push",
    "vault_run",
]
