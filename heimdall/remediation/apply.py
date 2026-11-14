"""Application atomique des correctifs validés (T30.3, #85).

Seule l'écriture sur disque du paquet ``remediation`` — tout le reste
(``templates.py``, ``naming.py``) reste purement en mémoire :

- le chemin vient d'un plan déjà validé puis est **reconfiné**
  (``mcp.paths.confine`` : ``resolve()`` + ``is_relative_to`` + refus des
  absolus et des liens sortants — la garde unique du ticket #27.3.1, réutilisée
  ici, jamais recopiée) ;
- le contenu actuel est relu de façon sécurisée (``O_NOFOLLOW``, fichier
  régulier, borne 1 Mio, UTF-8 strict) puis comparé au snapshot du plan
  (``STALE_CANDIDATE`` : un fichier modifié depuis le plan n'est jamais
  écrasé) ;
- une sauvegarde est écrite avant toute modification
  (``vault.atomic.backup_file``, mode ``0600`` — elle contient le secret) ;
- le nouveau contenu est écrit via ``vault.atomic.write_file_atomic``
  (temporaire + ``fsync`` + ``os.replace`` atomique, permissions du fichier
  d'origine conservées) : **aucun fichier à moitié écrit en cas d'erreur** ;
- ``undo_apply`` restaure la sauvegarde après revérification du snapshot.

Toute erreur (y compris inattendue) devient ``ApplyError`` statique : aucun
secret, aucun chemin reconstruit depuis l'entrée ne fuit dans l'exception.
"""

from __future__ import annotations

import os
import stat
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from heimdall.mcp.paths import PathEscape, confine
from heimdall.remediation.templates import ReplacementPlan
from heimdall.vault.atomic import (
    _get_git_toplevel,
    _open_file_read_fd,
    backup_file,
    is_git_ignored,
    is_git_tracked,
    write_file_atomic,
)

#: Lecture bornée : même plafond que le scanner et les plans (1 Mio).
_MAX_READ_BYTES: Final[int] = 1_048_576

#: Mode POSIX valide d'un fichier (bits rwx utilisateur/groupe/autres).
_MAX_MODE: Final[int] = 0o777


class ApplyError(Exception):
    """Échec d'application : entrée invalide, fichier modifié ou écriture impossible."""

    def __init__(self) -> None:
        super().__init__("application du correctif impossible : entrée invalide")


@dataclass(frozen=True)
class AppliedPatch:
    """Reçu d'une application réussie ; sans le secret (ni ``before``)."""

    file: str
    #: Chemin de la sauvegarde, relatif à la racine (jamais absolu).
    backup: str
    mode: int
    after: str = field(repr=False)


def _read_current_secure(path: Path) -> tuple[str, int]:
    """Lit un fichier régulier sans suivre aucun lien (mode + contenu).

    Garde unique ``vault.atomic._open_file_read_fd`` : parents ouverts
    composant par composant (``openat`` + ``O_NOFOLLOW``), cible en
    ``O_NONBLOCK`` (pas de blocage sur FIFO). Le mode est lu par ``fstat``
    pour le conserver à l'écriture. Toute anomalie vaut ``ApplyError`` statique.
    """
    try:
        descriptor = _open_file_read_fd(path)
    except (ValueError, OSError):
        raise ApplyError from None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ApplyError
        if status.st_size > _MAX_READ_BYTES:
            raise ApplyError
        raw = os.read(descriptor, _MAX_READ_BYTES + 1)
    except OSError:
        raise ApplyError from None
    finally:
        try:
            os.close(descriptor)
        except OSError:  # noqa: S110 - fermeture best-effort, l'erreur est déjà gérée
            pass
    if len(raw) > _MAX_READ_BYTES:
        raise ApplyError
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ApplyError from None
    return text, stat.S_IMODE(status.st_mode)


def _check_backup_git_status(backup: Path, relative_name: str) -> None:
    """Avertit si la sauvegarde .bak contenant un secret risque d'être committée.

    Le message n'affiche que le chemin relatif (aligné sur AppliedPatch.backup,
    sans divulgation de layout FS local absolu).
    Aligné sur la politique de sécurité de ``heimdall vault pull --backup`` :
    - Fichier suivi par Git : avertissement fort pour éviter la fuite de secrets.
    - Fichier ignoré (.gitignore) : rien à signaler.
    - Statut indéterminé (hors dépôt ou git indisponible) : avertissement explicite.
    - Présent dans un dépôt mais non ignoré : avertissement invitant à l'ignorer.
    Aucune règle .gitignore n'est écrite silencieusement.
    """
    if is_git_tracked(backup):
        msg = (
            f"ATTENTION : Le fichier {relative_name} est suivi par Git ! "
            f"Exécutez 'git rm --cached {relative_name}' et ajoutez-le à .gitignore "
            "pour éviter toute fuite."
        )
        sys.stderr.write(msg + "\n")
        warnings.warn(msg, UserWarning, stacklevel=3)
    elif is_git_ignored(backup):
        pass
    elif _get_git_toplevel(backup) is None:
        msg = (
            f"Avertissement : statut Git indéterminé pour '{relative_name}' "
            "(hors dépôt ou git indisponible) : impossible de vérifier "
            "qu'il ne sera pas committé. Ajoutez-le à .gitignore et "
            "vérifiez avec 'git status'."
        )
        sys.stderr.write(msg + "\n")
        warnings.warn(msg, UserWarning, stacklevel=3)
    else:
        msg = (
            f"Avertissement : Le fichier {relative_name} n'est pas ignoré par Git. "
            f"Pensez à ajouter '{relative_name}' dans .gitignore."
        )
        sys.stderr.write(msg + "\n")
        warnings.warn(msg, UserWarning, stacklevel=3)


def cleanup_backup_file(root: Path, receipt: AppliedPatch) -> None:
    """Supprime le fichier ``.bak`` créé lors d'un remplacement validé (F-10)."""
    if not isinstance(receipt, AppliedPatch):
        raise ApplyError
    if receipt.backup != f"{receipt.file}.bak":
        raise ApplyError
    try:
        confined = confine(root, receipt.backup)
    except PathEscape:
        raise ApplyError from None
    # Un seul chemin fait foi : celui déjà résolu et confiné par `confine`.
    # `relative` est canonique ; s'il diffère du reçu, un lien symbolique a
    # redirigé la cible (même à l'intérieur de la racine) : refus fail-closed.
    if confined.relative != receipt.backup:
        raise ApplyError
    try:
        os.unlink(confined.absolute)
    except FileNotFoundError:
        pass
    except OSError:
        raise ApplyError from None


def apply_replacement(  # noqa: PLR0912
    root: Path,
    plan: ReplacementPlan,
    *,
    cleanup_backup: bool = False,
) -> AppliedPatch:
    """Applique un plan validé sous ``root`` ; lève ``ApplyError`` sinon.

    Fail-closed : plan manuel, fichier absent/illisible/modifié depuis le plan
    (``plan.before``), chemin hors dépôt, ou écriture impossible — dans tous
    les cas le fichier d'origine est intact (aucune écriture partielle).
    Si ``cleanup_backup=True``, supprime ``<fichier>.bak`` après validation
    de l'écriture atomique (F-10).
    """
    if not isinstance(root, Path):
        raise ApplyError
    if not isinstance(plan, ReplacementPlan):
        raise ApplyError
    if plan.manual_remediation:
        raise ApplyError
    try:
        try:
            confined = confine(root, plan.file)
        except PathEscape:
            raise ApplyError from None
        current, mode = _read_current_secure(confined.absolute)
        if current != plan.before:
            raise ApplyError
        try:
            backup = backup_file(confined.absolute)
        except ValueError:
            raise ApplyError from None
        if backup is None:
            raise ApplyError
        backup_rel = f"{confined.relative}.bak"
        _check_backup_git_status(backup, backup_rel)
        try:
            write_file_atomic(confined.absolute, plan.after, mode=mode)
        except ValueError:
            raise ApplyError from None
    except ApplyError:
        raise
    except Exception:
        raise ApplyError from None
    receipt = AppliedPatch(
        file=confined.relative,
        backup=backup_rel,
        mode=mode,
        after=plan.after,
    )
    if cleanup_backup:
        cleanup_backup_file(root, receipt)
    return receipt


def undo_apply(root: Path, receipt: AppliedPatch) -> None:
    """Restaure la sauvegarde d'un :class:`AppliedPatch` ; lève ``ApplyError`` sinon.

    La restauration est refusée si le fichier a changé depuis l'application
    (``current != receipt.after``) : on ne doit jamais écraser un contenu
    inconnu. La sauvegarde est conservée (un second ``undo`` échoue donc sur
    le contrôle snapshot).
    """
    if not isinstance(root, Path):
        raise ApplyError
    if not isinstance(receipt, AppliedPatch):
        raise ApplyError
    try:
        try:
            confined = confine(root, receipt.file)
        except PathEscape:
            raise ApplyError from None
        if receipt.backup != f"{confined.relative}.bak":
            raise ApplyError
        if type(receipt.mode) is not int or not 0 <= receipt.mode <= _MAX_MODE:
            raise ApplyError
        backup_path = confined.absolute.with_name(f"{confined.absolute.name}.bak")
        current, _ = _read_current_secure(confined.absolute)
        if current != receipt.after:
            raise ApplyError
        content, _ = _read_current_secure(backup_path)
        try:
            write_file_atomic(confined.absolute, content, mode=receipt.mode)
        except ValueError:
            raise ApplyError from None
    except ApplyError:
        raise
    except Exception:
        raise ApplyError from None
