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

import asyncio
import json
import os
import sqlite3
import stat
from pathlib import Path

import typer

from heimdall.cli.vault_client import (
    RUN_CONTEXT_SETTINGS,
    vault_pull,
    vault_push,
    vault_run,
)
from heimdall.vault import auth as vault_auth
from heimdall.vault.audit import DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, SqliteAuditLog
from heimdall.vault.crypto import (
    KekHmacContinuityError,
    VaultCipher,
    VaultCipherError,
    validate_server_hmac_key,
)
from heimdall.vault.database import (
    KekConcurrencyError,
    KekVersionError,
    db_session,
    init_db,
    resolve_db_path,
    rotate_secrets_kek,
    validate_kek_version,
)

key_app = typer.Typer(
    name="key",
    help="Cycle de vie des clés API de projet (ticket #64).",
    no_args_is_help=True,
)

vault_app = typer.Typer(
    name="vault",
    help="Administration et client du Vault Heimdall (tickets #35, #64).",
    no_args_is_help=True,
)
vault_app.add_typer(key_app, name="key")

audit_app = typer.Typer(
    name="audit",
    help="Consultation du journal d'audit chaîné (ticket #113).",
    no_args_is_help=True,
)
vault_app.add_typer(audit_app, name="audit")

# Client Vault CLI (tickets #35, #99, #100, #101).
# `vault run` est un alias de la voie canonique `heimdall run` (main.py) :
# même callback `vault_run`, mêmes gardes, mêmes réglages partagés
# (RUN_CONTEXT_SETTINGS) — voir docs/t35-samm.md §5.
vault_app.command("push")(vault_push)
vault_app.command("pull")(vault_pull)
vault_app.command(
    "run",
    help="Lance une commande avec les secrets injectés en mémoire (ticket #101).",
    context_settings=RUN_CONTEXT_SETTINGS,
)(vault_run)

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


def _assert_regular_non_empty_db_file(path: Path) -> None:
    """Refuse une base absente, vide, non régulière ou un lien symbolique.

    Le test s'appuie sur ``lstat`` (jamais ``stat``) : un lien symbolique est
    refusé sans être suivi, avant même la garde d'ouverture sécurisée de
    ``db_session``. Le message reste générique et ne reflète jamais le chemin
    (invariant 8).
    """
    try:
        file_stat = os.lstat(path)
    except OSError:
        raise ValueError(
            "la base de données Vault est introuvable ou vide. Vérifiez --db-path."
        ) from None
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size == 0:
        raise ValueError(
            "la base de données Vault est introuvable ou vide. Vérifiez --db-path."
        )


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


def _resolve_audit_hmac_key() -> bytes:
    """Résout la clé HMAC du journal d'audit (env dédiée ou chiffreur configuré).

    Jamais de repli silencieux sur SHA-256 nu : sans clé résolvable, lève
    ``ValueError`` (code 2) au lieu d'annoncer à tort une chaîne invalide.
    """
    raw = os.environ.get("HEIMDALL_VAULT_AUDIT_HMAC_KEY")
    if raw is not None:
        # Une variable exportée vide est une erreur explicite (code 2), jamais
        # un repli silencieux sur la sous-clé dérivée.
        if not raw:
            raise ValueError(
                "clé HMAC d'audit indisponible : HEIMDALL_VAULT_AUDIT_HMAC_KEY est vide."
            )
        return validate_server_hmac_key(raw)
    try:
        cipher = _resolve_cli_cipher(
            env_direct="HEIMDALL_VAULT_KEK",
            env_fallback=None,
            env_master="HEIMDALL_VAULT_MASTER_KEY",
            env_salt="HEIMDALL_VAULT_KEK_SALT",
            label="la KEK du Vault",
            server_hmac_key=os.environ.get("HEIMDALL_VAULT_SERVER_HMAC_KEY"),
        )
    except ValueError:
        raise ValueError(
            "clé HMAC d'audit indisponible : définir HEIMDALL_VAULT_AUDIT_HMAC_KEY "
            "ou la KEK du Vault."
        ) from None
    return cipher.audit_hmac_key()


_SCHEMA_MIGRATION_MESSAGE = (
    "Erreur : journal d'audit antérieur à M-03, migration requise : démarrer une "
    "fois le serveur Vault (migration du schéma) puis relancer la commande."
)


def _exit_if_audit_schema_outdated(audit_log: SqliteAuditLog) -> None:
    """Base pré-M-03 : message « migration requise » explicite (code 1)."""
    if audit_log.needs_schema_migration():
        typer.echo(_SCHEMA_MIGRATION_MESSAGE, err=True)
        raise typer.Exit(code=1)


@audit_app.command("list")
def list_audit_events(
    db_path: Path | None = _DB_PATH_OPTION,
    limit: int = typer.Option(
        DEFAULT_LIST_LIMIT,
        "--limit",
        min=1,
        max=MAX_LIST_LIMIT,
        help="Nombre maximum d'événements récents à afficher.",
    ),
    project: str | None = typer.Option(
        None,
        "--project",
        "-p",
        help="Filtrer sur un projet (défaut : tous les projets).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Sortie JSON (aucune valeur de secret).",
    ),
) -> None:
    """Liste les derniers événements d'audit (jamais de secret ni de clé)."""
    try:
        resolved = _resolve_db_path(db_path)
        if project is not None:
            vault_auth.validate_project_id(project)
        if not resolved.is_file():
            raise FileNotFoundError
        audit_log = SqliteAuditLog(
            resolved, create=False, hmac_key=_resolve_audit_hmac_key()
        )
        _exit_if_audit_schema_outdated(audit_log)
        events = audit_log.list_events(limit=limit, project=project)
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    except FileNotFoundError:
        typer.echo("Erreur : base du journal d'audit introuvable.", err=True)
        raise typer.Exit(code=1) from None
    except typer.Exit:
        raise
    except Exception:
        typer.echo("Erreur : échec de la lecture du journal d'audit.", err=True)
        raise typer.Exit(code=1) from None
    if not events:
        typer.echo("Aucun événement d'audit.")
        return
    if json_output:
        typer.echo(json.dumps(events, sort_keys=True, ensure_ascii=True))
        return
    for event in events:
        typer.echo(
            f"{event['id']}  {event['occurred_at']}  {event['outcome']}  "
            f"status={event['status_code']}  peer={event['peer']}  "
            f"projet={event['project'] or '-'}  "
            f"cle_id={event['key_id'] or '-'}  "
            f"cle={event['key_fingerprint'] or '-'}  "
            f"action={event['action']}  cible={event['target'] or '-'}"
        )


@audit_app.command("verify")
def verify_audit_chain(
    db_path: Path | None = _DB_PATH_OPTION,
) -> None:
    """Vérifie le chaînage par hash du journal d'audit."""
    try:
        resolved = _resolve_db_path(db_path)
        if not resolved.is_file():
            raise FileNotFoundError
        audit_log = SqliteAuditLog(
            resolved, create=False, hmac_key=_resolve_audit_hmac_key()
        )
        _exit_if_audit_schema_outdated(audit_log)
        valid, invalid_id = audit_log.verify_chain()
        legacy = not valid and audit_log.is_legacy_sha256_chain()
        total = audit_log.count()
        pruned = audit_log.pruned_count()
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    except FileNotFoundError:
        typer.echo("Erreur : base du journal d'audit introuvable.", err=True)
        raise typer.Exit(code=1) from None
    except typer.Exit:
        raise
    except Exception:
        typer.echo("Erreur : échec de la vérification du journal d'audit.", err=True)
        raise typer.Exit(code=1) from None
    if legacy:
        typer.echo(
            "Erreur : journal d'audit historique SHA-256 (pré-F-16), migration "
            "requise : archiver la base puis réinitialiser le journal d'audit.",
            err=True,
        )
        raise typer.Exit(code=1)
    if not valid:
        typer.echo(
            f"Erreur : chaîne d'audit invalide à l'événement {invalid_id}.",
            err=True,
        )
        raise typer.Exit(code=1)
    typer.echo(
        f"Chaîne d'audit valide ({total} événements retenus, {pruned} purgés)."
    )


def _read_env_secret(var_name: str, label: str) -> str | None:
    val = os.environ.get(var_name)
    if val is not None and not val:
        raise ValueError(
            f"{label} manquante ou vide dans l'environnement ({var_name} ne peut pas être vide)."
        )
    return val


def _resolve_cli_cipher(  # noqa: PLR0913 - paramètres nommés explicites
    *,
    env_direct: str,
    env_fallback: str | None,
    env_master: str,
    env_salt: str,
    label: str,
    server_hmac_key: str | None = None,
) -> VaultCipher:
    """Résout un chiffreur VaultCipher depuis une clé directe ou une dérivation Argon2id."""
    resolved_direct = _read_env_secret(env_direct, label)
    if resolved_direct is None and env_fallback and env_fallback in os.environ:
        resolved_direct = _read_env_secret(env_fallback, label)

    raw_master = os.environ.get(env_master)
    if raw_master is not None and not raw_master:
        raise ValueError(f"La clé maîtresse pour {label} dans {env_master} ne peut pas être vide.")
    resolved_master = raw_master

    raw_salt = os.environ.get(env_salt)
    if raw_salt is not None and not raw_salt:
        raise ValueError(f"Le sel pour {label} dans {env_salt} ne peut pas être vide.")
    resolved_salt = raw_salt

    if resolved_direct and (resolved_master or resolved_salt):
        raise ValueError(
            f"Fournir une KEK directe OU une clé maîtresse avec sel pour {label}, pas les deux."
        )
    if resolved_direct:
        try:
            return VaultCipher.from_encoded_key(
                resolved_direct, server_hmac_key=server_hmac_key
            )
        except Exception:
            raise ValueError(f"{label} directe invalide (base64 attendu).") from None
    if resolved_master and resolved_salt:
        try:
            return VaultCipher.from_master_key(
                resolved_master, resolved_salt, server_hmac_key=server_hmac_key
            )
        except Exception:
            raise ValueError(f"{label} dérivée invalide.") from None
    if resolved_master or resolved_salt:
        raise ValueError(f"Clé maîtresse ET sel obligatoires pour dériver {label}.")
    raise ValueError(
        f"{label} manquante dans l'environnement ({env_direct} ou {env_master}+{env_salt} requis)."
    )


_MAX_TCP_PORT: int = 65535


def _vault_server_is_listening() -> bool:
    """True si un serveur Vault répond sur le port configuré (rotation à chaud)."""
    import socket  # noqa: PLC0415

    raw_port = os.environ.get("HEIMDALL_VAULT_PORT", "8443")
    try:
        port = int(raw_port)
    except ValueError:
        return False
    if not 1 <= port <= _MAX_TCP_PORT:
        return False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _require_rotation_audit_key(resolved: Path) -> bytes:
    """Clé d'audit explicite, déjà valide pour l'historique existant (F-16).

    Lève ``ValueError`` (code 2) avant toute écriture si la clé manque ou ne
    vérifie pas la chaîne existante.
    """
    # Fail-closed (F-16) : sans clé d'audit explicite, la sous-clé dérivée
    # de la KEK change à la rotation et casse la vérification de la chaîne.
    raw_audit_key = os.environ.get("HEIMDALL_VAULT_AUDIT_HMAC_KEY")
    if not raw_audit_key:
        raise ValueError(
            "HEIMDALL_VAULT_AUDIT_HMAC_KEY est obligatoire pour la rotation de la "
            "KEK : sans clé d'audit explicite, la chaîne d'audit deviendrait "
            "invérifiable après la rotation."
        )
    audit_key = validate_server_hmac_key(raw_audit_key)
    # La clé fournie doit déjà vérifier l'historique existant : sinon le
    # serveur tournait avec une autre clé (dérivée, par exemple) et
    # l'événement de rotation produirait une chaîne mixte invérifiable.
    existing_audit = SqliteAuditLog(resolved, create=False, hmac_key=audit_key)
    try:
        unverifiable = existing_audit.needs_schema_migration() or (
            existing_audit.count() > 0 and existing_audit.verify_chain() != (True, None)
        )
    except sqlite3.Error:
        raise ValueError(
            "journal d'audit illisible, migration requise : démarrer une fois le "
            "serveur Vault (migration du schéma) avant la rotation."
        ) from None
    if unverifiable:
        raise ValueError(
            "le journal d'audit existant n'est pas vérifiable avec "
            "HEIMDALL_VAULT_AUDIT_HMAC_KEY : configurer le serveur avec cette clé "
            "(ou migrer le journal) avant la rotation."
        )
    return audit_key


@vault_app.command(
    "rotate-kek",
    help=(
        "Effectue la rotation transactionnelle de la KEK sur tous les secrets (ticket #71).\n\n"
        "RÈGLES DE SÉCURITÉ (invariant 9) :\n"
        "Pour éviter toute fuite dans les arguments de processus ('ps') et l'historique shell,\n"
        "les clés et phrases de passe sont lues EXCLUSIVEMENT depuis l'environnement :\n"
        "- KEK directe : $HEIMDALL_VAULT_OLD_KEK (ou $HEIMDALL_VAULT_KEK) et\n"
        "  $HEIMDALL_VAULT_NEW_KEK\n"
        "- Dérivation Argon2id : $HEIMDALL_VAULT_OLD_MASTER_KEY + $HEIMDALL_VAULT_OLD_KEK_SALT et\n"
        "  $HEIMDALL_VAULT_NEW_MASTER_KEY + $HEIMDALL_VAULT_NEW_KEK_SALT\n\n"
        "La clé HMAC serveur ($HEIMDALL_VAULT_SERVER_HMAC_KEY) est requise si la base\n"
        "porte un canari HMAC. La rotation ne renouvelle pas les DEK : après une\n"
        "compromission de la KEK, un rechiffrement complet des valeurs est nécessaire.\n"
        "Le serveur doit être arrêté (ou --force explicite) pour éviter une rotation\n"
        "à chaud avec une KEK encore en mémoire dans le processus serveur (garde\n"
        "best-effort : sonde TCP sur $HEIMDALL_VAULT_PORT, pas un verrou ; préférer un\n"
        "arrêt supervisé). $HEIMDALL_VAULT_AUDIT_HMAC_KEY est obligatoire et doit être\n"
        "la même avant et après la rotation, sinon la chaîne d'audit est invérifiable.\n"
        "L'événement VAULT KEK ROTATE est écrit après le commit de la rotation\n"
        "(best-effort) : en cas d'échec, code 1 explicite ; lancer ensuite\n"
        "'heimdall vault audit verify'."
    ),
)
def rotate_kek_command(
    db_path: Path | None = _DB_PATH_OPTION,
    target_version: int | None = typer.Option(
        None,
        "--target-version",
        help="Version de KEK cible explicite (kek_version).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Autorise la rotation même si un serveur Vault semble écouter sur le port.",
    ),
) -> None:
    """Effectue la rotation transactionnelle de la KEK sur tous les secrets (ticket #71)."""
    try:
        resolved = _resolve_db_path(db_path)
        # Pré-contrôle sans suivi de lien symbolique (lstat), avant la garde
        # d'ouverture sécurisée de db_session (invariant 8, fail-closed).
        _assert_regular_non_empty_db_file(resolved)
        if not force and _vault_server_is_listening():
            raise ValueError(
                "Un serveur Vault semble écouter sur le port configuré : arrêter le "
                "serveur avant la rotation (ou utiliser --force)."
            )
        server_hmac_key = _read_env_secret(
            "HEIMDALL_VAULT_SERVER_HMAC_KEY", "la clé HMAC serveur"
        )
        old_cipher = _resolve_cli_cipher(
            env_direct="HEIMDALL_VAULT_OLD_KEK",
            env_fallback="HEIMDALL_VAULT_KEK",
            env_master="HEIMDALL_VAULT_OLD_MASTER_KEY",
            env_salt="HEIMDALL_VAULT_OLD_KEK_SALT",
            label="l'ancienne KEK",
            server_hmac_key=server_hmac_key,
        )
        new_cipher = _resolve_cli_cipher(
            env_direct="HEIMDALL_VAULT_NEW_KEK",
            env_fallback=None,
            env_master="HEIMDALL_VAULT_NEW_MASTER_KEY",
            env_salt="HEIMDALL_VAULT_NEW_KEK_SALT",
            label="la nouvelle KEK",
            server_hmac_key=server_hmac_key,
        )
        if old_cipher.has_same_key_as(new_cipher):
            raise ValueError("L'ancienne et la nouvelle KEK doivent être distinctes.")
        if target_version is not None:
            validate_kek_version(target_version, label="Le numéro de version cible")
        audit_key = _require_rotation_audit_key(resolved)
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None

    try:
        with db_session(resolved) as conn:
            count, new_version = rotate_secrets_kek(
                conn,
                old_cipher,
                new_cipher,
                target_kek_version=target_version,
            )
    except KekHmacContinuityError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=1) from None
    except VaultCipherError:
        typer.echo("Erreur : échec du déchiffrement avec l'ancienne KEK.", err=True)
        raise typer.Exit(code=1) from None
    except (KekVersionError, KekConcurrencyError):
        typer.echo("Erreur : base de données corrompue ou invalide.", err=True)
        raise typer.Exit(code=1) from None
    except ValueError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        typer.echo("Erreur : échec de la rotation de la KEK.", err=True)
        raise typer.Exit(code=1) from None

    if count == 0:
        typer.echo(
            "Erreur : aucun secret trouvé dans la base — vérifiez --db-path.",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        audit_log = SqliteAuditLog(resolved, hmac_key=audit_key)
        asyncio.run(
            audit_log.record(
                peer="cli",
                action="VAULT KEK ROTATE",
                target=f"kek_version={new_version}",
                status_code=200,
            )
        )
    except Exception:
        typer.echo(
            "Erreur : rotation effectuée mais journal d'audit indisponible "
            "(événement VAULT KEK ROTATE non écrit) : lancer 'heimdall vault audit "
            "verify' et consigner la rotation hors bande.",
            err=True,
        )
        raise typer.Exit(code=1) from None

    typer.echo(f"Rotation de la KEK réussie : {count} secret(s) réenveloppé(s).")


vault_app.command("kek-rotate", hidden=True)(rotate_kek_command)


__all__ = ["audit_app", "key_app", "rotate_kek_command", "vault_app"]
