"""Mise en route du Vault en une commande : ``init``, ``serve``, ``login``.

Avant : générer à la main 3 à 4 secrets (``openssl rand``), un certificat TLS
avec le bon SAN, des variables d'environnement, puis passer ``--ca-cert`` à
chaque commande client. Après :

- ``heimdall vault init`` génère tout, avec des permissions privées
  (répertoire ``0700``, fichiers ``0600``), et refuse d'écraser quoi que ce soit ;
- ``heimdall vault serve`` démarre le serveur avec cette configuration ;
- ``heimdall vault key create --project X --save`` émet la clé et l'enregistre
  là où le client la cherche (``heimdall vault login`` pour une clé existante) ;
- ``push``/``pull``/``run`` trouvent alors seuls la clé et le certificat.

La configuration serveur (``server.env``) n'est chargée **que** par les
commandes serveur et d'administration (``serve``, ``key``, ``audit``), jamais
par les commandes client : ``heimdall run`` ne doit pas transmettre la clé
maîtresse au processus qu'il lance.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Final

import typer

from heimdall.vault.atomic import format_env_value, parse_env_file, write_file_atomic
from heimdall.vault.client import (
    DEFAULT_CA_FILENAME,
    DEFAULT_KEY_FILENAME,
    heimdall_config_dir,
)
from heimdall.vault.crypto import (
    generate_api_key_pepper,
    generate_kek_salt,
    generate_loopback_tls_pair,
    generate_master_key,
    generate_server_hmac_key,
)
from heimdall.vault.database import default_db_path

SERVER_DIRNAME: Final[str] = "server"
SERVER_ENV_FILENAME: Final[str] = "server.env"
TLS_CERT_FILENAME: Final[str] = "tls-cert.pem"
TLS_KEY_FILENAME: Final[str] = "tls-key.pem"
#: Noms attendus par ``docker-compose.yml`` (montage ``./secrets``).
DOCKER_CERT_FILENAME: Final[str] = "vault_tls_cert.pem"
DOCKER_KEY_FILENAME: Final[str] = "vault_tls_key.pem"
#: UID/GID figés du conteneur (``docker-compose.yml``).
_CONTAINER_UID: Final[int] = 10001
_PRIVATE_DIR_MODE: Final[int] = 0o700
_PRIVATE_FILE_MODE: Final[int] = 0o600
_MAX_API_KEY_CHARS: Final[int] = 512
_SERVER_ENV_HEADER: Final[str] = (
    "# Configuration du Vault Heimdall, générée par `heimdall vault init`.\n"
    "# SECRET : ne jamais committer ni partager. Sauvegardez ce fichier dans un\n"
    "# coffre séparé : sans lui, la base du Vault est définitivement illisible.\n"
)


class SetupError(Exception):
    """Mise en route impossible ; le message est statique et actionnable."""


def server_config_dir() -> Path:
    """Répertoire privé de la configuration serveur locale."""
    return heimdall_config_dir() / SERVER_DIRNAME


def server_env_path() -> Path:
    """Fichier ``server.env`` écrit par ``heimdall vault init``."""
    return server_config_dir() / SERVER_ENV_FILENAME


def client_ca_path() -> Path:
    """Certificat que le client approuve par défaut (voir ``resolve_ca_cert``)."""
    return heimdall_config_dir() / DEFAULT_CA_FILENAME


def client_key_path() -> Path:
    """Fichier de clé API que le client lit par défaut (voir ``resolve_api_key``)."""
    return heimdall_config_dir() / DEFAULT_KEY_FILENAME


def display_path(path: Path) -> str:
    """Chemin affiché avec ``~`` : ce sont nos propres chemins, jamais une entrée."""
    try:
        return "~/" + path.relative_to(Path.home()).as_posix()
    except (ValueError, RuntimeError, OSError):
        return str(path)


def _check_private_file(path: Path) -> None:
    """Refuse un fichier de configuration lien, non régulier, étranger ou lisible par autrui."""
    try:
        info = os.lstat(path)
    except OSError:
        raise SetupError("configuration serveur illisible") from None
    if not stat.S_ISREG(info.st_mode):
        raise SetupError("configuration serveur refusée : fichier non régulier ou lien")
    if os.name == "posix" and (
        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SetupError(
            "configuration serveur refusée : elle doit vous appartenir et être en "
            "droits 0600 (chmod 600 ~/.config/heimdall/server/server.env)"
        )


def load_server_env() -> bool:
    """Charge ``server.env`` dans l'environnement, sans écraser une variable définie.

    Retourne ``False`` si le fichier n'existe pas (configuration par variables
    d'environnement ou Docker). Seules les clés ``HEIMDALL_*`` sont reprises.
    Une variable déjà définie garde sa valeur : l'opérateur peut toujours
    surcharger un réglage ponctuellement.
    """
    path = server_env_path()
    try:
        exists = os.path.lexists(path)
    except (OSError, ValueError):
        return False
    if not exists:
        return False
    _check_private_file(path)
    values = parse_env_file(path)
    if values is None:
        raise SetupError("configuration serveur illisible")
    for key, value in values.items():
        if key.startswith("HEIMDALL_"):
            os.environ.setdefault(key, value)
    return True


def load_server_env_or_exit() -> bool:
    """Variante CLI de :func:`load_server_env` : erreur lisible et code 2."""
    try:
        return load_server_env()
    except SetupError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None


def _env_file_content(values: dict[str, str]) -> str:
    lines = [f"{key}={format_env_value(value)}" for key, value in values.items()]
    return _SERVER_ENV_HEADER + "\n".join(lines) + "\n"


def _generated_secrets() -> dict[str, str]:
    """Clés indépendantes de 256 bits.

    - la clé HMAC serveur active la détection de fuite par empreinte ;
    - la clé HMAC d'audit est **dédiée** dès le départ : sinon la chaîne
      d'audit serait signée par une sous-clé de la KEK, et ``rotate-kek``
      (qui exige une clé d'audit explicite vérifiant l'historique) serait
      impossible sans migration ``audit rekey``.
    """
    return {
        "HEIMDALL_VAULT_MASTER_KEY": generate_master_key(),
        "HEIMDALL_VAULT_KEK_SALT": generate_kek_salt(),
        "HEIMDALL_VAULT_API_KEY_PEPPER": generate_api_key_pepper(),
        "HEIMDALL_VAULT_SERVER_HMAC_KEY": generate_server_hmac_key(),
        "HEIMDALL_VAULT_AUDIT_HMAC_KEY": generate_server_hmac_key(),
    }


def _refuse_existing(paths: list[Path]) -> None:
    existing = [path for path in paths if os.path.lexists(path)]
    if existing:
        listed = ", ".join(display_path(path) for path in existing)
        raise SetupError(
            f"déjà initialisé ({listed}) : rien n'a été modifié. Écraser ces "
            "fichiers rendrait la base existante illisible ; déplacez-les "
            "d'abord (après sauvegarde) pour repartir de zéro."
        )


def _make_private_dir(path: Path, created: list[Path] | None = None) -> None:
    """Crée ``path`` et chacun de ses parents manquants en ``0700``.

    ``Path.mkdir(parents=True)`` n'applique ``mode`` qu'à la feuille : sous
    ``umask 0002``, un parent créé au passage serait ``0775`` et refusé ensuite
    par ``write_file_atomic`` (parent accessible en écriture au groupe). Chaque
    répertoire **créé ici** est donc fixé à ``0700`` ; un répertoire préexistant
    (``~/.config``) n'est jamais modifié, sauf ``path`` lui-même, qui nous
    appartient. ``created`` reçoit les répertoires créés, pour un retour arrière.
    """
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in [current, *missing]:
        if os.path.islink(directory):
            raise SetupError(
                f"répertoire refusé : {display_path(directory)} est un lien symbolique"
            )
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=_PRIVATE_DIR_MODE)
        except OSError:
            raise SetupError(f"création impossible : {display_path(directory)}") from None
        if created is not None:
            created.append(directory)
        if os.name == "posix":
            os.chmod(directory, _PRIVATE_DIR_MODE)
    if os.name == "posix" and path not in missing:
        try:
            os.chmod(path, _PRIVATE_DIR_MODE)
        except OSError:
            raise SetupError(f"droits impossibles à fixer : {display_path(path)}") from None


class _Transaction:
    """Retour arrière d'une initialisation interrompue.

    Les fichiers écrits contiennent des clés **neuves, jamais utilisées** : les
    supprimer est sans perte. Sans cela, une erreur à mi-chemin laisserait un
    état partiel qui bloque toute relance (« déjà initialisé »).
    """

    def __init__(self) -> None:
        self.files: list[Path] = []
        self.dirs: list[Path] = []

    def write(self, path: Path, content: str | bytes) -> None:
        _write_private(path, content)
        self.files.append(path)

    def rollback(self) -> None:
        for path in reversed(self.files):
            try:
                os.unlink(path)
            except OSError:  # noqa: PERF203 - best-effort, fichier par fichier
                pass
        for directory in reversed(self.dirs):
            try:
                os.rmdir(directory)
            except OSError:  # noqa: PERF203 - non vide ou déjà absent : conservé
                pass


def _write_private(path: Path, content: str | bytes) -> None:
    try:
        write_file_atomic(path, content, mode=_PRIVATE_FILE_MODE)
    except ValueError as exc:
        if "permissions trop permissives" in str(exc):
            raise SetupError(
                f"écriture refusée : un répertoire parent de {display_path(path)} est "
                "accessible en écriture à d'autres utilisateurs ; corrigez-le "
                "(chmod go-w <répertoire>) puis relancez"
            ) from None
        raise SetupError(f"écriture impossible : {display_path(path)}") from None
    except OSError:
        raise SetupError(f"écriture impossible : {display_path(path)}") from None


def init_local() -> dict[str, Path]:
    """Configuration d'un Vault local (sans Docker) ; rend les chemins écrits."""
    config_dir = server_config_dir()
    env_path = config_dir / SERVER_ENV_FILENAME
    cert_path = config_dir / TLS_CERT_FILENAME
    key_path = config_dir / TLS_KEY_FILENAME
    ca_path = client_ca_path()
    db_path = default_db_path()
    # La base existante est la donnée à protéger : de nouvelles clés la
    # rendraient illisible. Son existence suffit à refuser.
    _refuse_existing([env_path, cert_path, key_path, ca_path, db_path])
    cert_pem, key_pem, _expires = generate_loopback_tls_pair()
    values = {
        "HEIMDALL_ENV": "production",
        **_generated_secrets(),
        "HEIMDALL_VAULT_STORAGE_BACKEND": "sqlite",
        "HEIMDALL_VAULT_DB_PATH": str(db_path),
        "HEIMDALL_VAULT_SSL_CERTFILE": str(cert_path),
        "HEIMDALL_VAULT_SSL_KEYFILE": str(key_path),
    }
    tx = _Transaction()
    try:
        # Le répertoire client (vault.key, vault-ca.pem) est privé lui aussi.
        _make_private_dir(ca_path.parent, tx.dirs)
        _make_private_dir(config_dir, tx.dirs)
        tx.write(key_path, key_pem)
        tx.write(cert_path, cert_pem)
        tx.write(env_path, _env_file_content(values))
        tx.write(ca_path, cert_pem)
    except BaseException:
        tx.rollback()
        raise
    return {"config": env_path, "ca": ca_path, "db": db_path}


def init_docker(directory: Path) -> dict[str, Path]:
    """Fichiers attendus par ``docker-compose.yml`` dans ``directory``."""
    root = directory.resolve()
    if not (root / "docker-compose.yml").is_file():
        raise SetupError(
            "aucun docker-compose.yml dans ce répertoire : passez le dossier du "
            "dépôt Heimdall (celui qui contient docker-compose.yml)"
        )
    env_path = root / ".env"
    secrets_dir = root / "secrets"
    data_dir = root / "data"
    ca_path = client_ca_path()
    _refuse_existing([env_path, secrets_dir, data_dir, ca_path])
    cert_pem, key_pem, _expires = generate_loopback_tls_pair()
    tx = _Transaction()
    try:
        _make_private_dir(ca_path.parent, tx.dirs)
        _make_private_dir(secrets_dir, tx.dirs)
        _make_private_dir(data_dir, tx.dirs)
        tx.write(secrets_dir / DOCKER_KEY_FILENAME, key_pem)
        tx.write(secrets_dir / DOCKER_CERT_FILENAME, cert_pem)
    # Compose fixe HEIMDALL_ENV, l'hôte, le port, la base et les chemins TLS :
    # `.env` ne porte que les secrets.
        tx.write(env_path, _env_file_content(_generated_secrets()))
        tx.write(ca_path, cert_pem)
    except BaseException:
        tx.rollback()
        raise
    return {"config": env_path, "ca": ca_path, "secrets": secrets_dir, "data": data_dir}


def save_client_key(raw_key: str, *, force: bool = False) -> Path:
    """Enregistre la clé API client en ``0600`` à l'emplacement lu par défaut."""
    key = raw_key.strip()
    if (
        not key
        or len(key) > _MAX_API_KEY_CHARS
        or any(c.isspace() or not c.isprintable() for c in key)
    ):
        raise SetupError("clé API invalide : une seule ligne, sans espace")
    path = client_key_path()
    if os.path.lexists(path) and not force:
        raise SetupError(
            f"une clé est déjà enregistrée ({display_path(path)}) : relancez avec --force "
            "pour la remplacer"
        )
    _make_private_dir(path.parent)
    _write_private(path, key + "\n")
    return path


def _docker_next_steps(paths: dict[str, Path]) -> str:
    root = paths["config"].parent
    return (
        "Étapes suivantes (Docker) :\n"
        f"  cd {root}\n"
        "  # le conteneur tourne en 10001:10001 : lui donner les répertoires (une fois)\n"
        f'  sudo chown -R --no-dereference {_CONTAINER_UID}:"$(id -g)" data secrets\n'
        "  sudo chmod 750 data secrets && sudo chmod 640 secrets/vault_tls_cert.pem\n"
        "  docker compose up -d --build\n"
        "  docker compose exec -T vault heimdall vault key create --project <projet>\n"
        "  heimdall vault login        # colle la clé affichée\n"
    )


_INIT_LOCAL_DONE: Final[str] = (
    "Étapes suivantes :\n"
    "  heimdall vault serve                                # démarre le Vault\n"
    "  heimdall vault key create --project <projet> --save  # dans un autre terminal\n"
    "  heimdall vault push --project <projet>              # envoie votre .env\n"
)


_DOCKER_OPTION = typer.Option(
    None,
    "--docker",
    help=(
        "Prépare un déploiement Docker dans ce répertoire (celui de "
        "docker-compose.yml) au lieu d'un Vault local."
    ),
)


def vault_init_command(docker: Path | None = _DOCKER_OPTION) -> None:
    """Génère toute la configuration du Vault en une commande (clés, certificat TLS).

    Par défaut : Vault local, configuration dans ~/.config/heimdall/server
    (droits privés), base dans ~/.local/share/heimdall. Avec --docker DIR :
    `.env`, `secrets/` et `data/` attendus par docker-compose.yml. Le client
    est configuré dans les deux cas (certificat approuvé automatiquement).
    Rien n'est jamais écrasé.
    """
    try:
        if docker is None:
            paths = init_local()
        else:
            paths = init_docker(docker)
    except SetupError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Configuration du Vault écrite dans {display_path(paths['config'])} (droits 0600).")
    typer.echo(f"Certificat approuvé par le client : {display_path(paths['ca'])}.")
    typer.echo(
        "IMPORTANT : sauvegardez ce fichier de configuration dans un coffre séparé ; "
        "sans lui, les secrets du Vault sont définitivement perdus."
    )
    typer.echo("")
    typer.echo(_INIT_LOCAL_DONE if docker is None else _docker_next_steps(paths), nl=False)


def vault_serve_command() -> None:
    """Démarre le Vault local configuré par `heimdall vault init` (Ctrl+C pour arrêter)."""
    load_server_env_or_exit()
    if not (
        os.environ.get("HEIMDALL_VAULT_MASTER_KEY") or os.environ.get("HEIMDALL_VAULT_KEK")
    ):
        typer.echo(
            "Erreur : Vault non configuré. Lancez d'abord `heimdall vault init`.",
            err=True,
        )
        raise typer.Exit(code=2)
    # Import différé : uvicorn/FastAPI ne sont chargés que pour servir.
    from heimdall.vault.app import get_settings, run_server  # noqa: PLC0415

    try:
        # Validation AVANT l'annonce : jamais « Vault sur … » pour un
        # démarrage qui échoue, et l'adresse affichée est la vraie.
        settings = get_settings()
        typer.echo(
            f"Vault Heimdall sur https://{settings.host}:{settings.port} (Ctrl+C pour arrêter).",
            err=True,
        )
        run_server()
    except ValueError as exc:
        # Messages de configuration statiques (aucun secret n'y est interpolé).
        typer.echo(f"Erreur de configuration : {exc}", err=True)
        raise typer.Exit(code=2) from None


def vault_login_command(
    force: bool = typer.Option(False, "--force", help="Remplace la clé déjà enregistrée."),
) -> None:
    """Enregistre votre clé API (0600) : push, pull et run la trouvent ensuite seuls."""
    if sys.stdin.isatty():
        raw = typer.prompt("Clé API", hide_input=True)
    else:
        raw = sys.stdin.readline(_MAX_API_KEY_CHARS + 2)
    try:
        path = save_client_key(raw, force=force)
    except SetupError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Clé API enregistrée dans {display_path(path)} (droits 0600).")


__all__ = [
    "SetupError",
    "client_ca_path",
    "client_key_path",
    "display_path",
    "init_docker",
    "init_local",
    "load_server_env",
    "load_server_env_or_exit",
    "save_client_key",
    "server_env_path",
    "vault_init_command",
    "vault_login_command",
    "vault_serve_command",
]
