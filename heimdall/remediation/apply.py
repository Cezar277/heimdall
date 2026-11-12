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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from heimdall.mcp.paths import PathEscape, confine
from heimdall.remediation.templates import ReplacementPlan
from heimdall.vault.atomic import backup_file, write_file_atomic

#: Lecture bornée : même plafond que le scanner et les plans (1 Mio).
_MAX_READ_BYTES: Final[int] = 1_048_576


class ApplyError(Exception):
    """Échec d'application : entrée invalide, fichier modifié ou écriture impossible."""

    def __init__(self) -> None:
        super().__init__("application du correctif impossible : entrée invalide")


@dataclass(frozen=True)
class AppliedPatch:
    """Reçu d'une application réussie ; sans le secret (ni ``before``)."""

    file: str
    backup: str
    mode: int
    after: str = field(repr=False)


def _read_current_secure(path: Path) -> tuple[str, int]:
    """Lit un fichier régulier sans suivre les liens (mode + contenu).

    Copie locale de la stratégie de ``vault.atomic.read_file_secure_no_follow``
    (``O_NOFOLLOW``, régulier, borne, UTF-8 strict), qui retourne en plus le
    mode du fichier pour le conserver à l'écriture. Toute anomalie vaut
    ``ApplyError`` statique.
    """
    try:
        if os.path.islink(path):
            raise ApplyError
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(path, flags)
    except OSError:
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


def apply_replacement(root: Path, plan: ReplacementPlan) -> AppliedPatch:
    """Applique un plan validé sous ``root`` ; lève ``ApplyError`` sinon.

    Fail-closed : plan manuel, fichier absent/illisible/modifié depuis le plan
    (``plan.before``), chemin hors dépôt, ou écriture impossible — dans tous
    les cas le fichier d'origine est intact (aucune écriture partielle).
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
        try:
            write_file_atomic(confined.absolute, plan.after, mode=mode)
        except ValueError:
            raise ApplyError from None
    except ApplyError:
        raise
    except Exception:
        raise ApplyError from None
    return AppliedPatch(
        file=confined.relative,
        backup=backup.as_posix(),
        mode=mode,
        after=plan.after,
    )


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
        backup_path = Path(receipt.backup)
        if backup_path.parent != confined.absolute.parent:
            raise ApplyError
        if backup_path.name != confined.absolute.name + ".bak":
            raise ApplyError
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
