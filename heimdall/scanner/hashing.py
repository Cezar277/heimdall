"""Empreinte HMAC-SHA-256 d'un candidat, sans conserver sa valeur (ADR-001).

La clé locale fait 32 octets et vit **hors du dépôt** :
``$HEIMDALL_SNIPPET_HMAC_KEY`` (hexadécimal, 64 caractères) ou, à défaut, un
fichier sous ``$XDG_DATA_HOME/heimdall/snippet-hmac.key`` (défaut
``~/.local/share/heimdall/snippet-hmac.key``), créé en ``0600``. Le fichier
doit appartenir à l'utilisateur courant et son répertoire parent est durci en
``0700``. Aucun composant du chemin ne peut être un lien symbolique : le
chemin résolu doit être **exactement** le chemin demandé, sinon la clé serait
créée hors du répertoire prévu. Toute lecture ou création impossible lève
``ScanError`` : aucune clé éphémère ne masque une panne, et les empreintes
restent stables entre deux exécutions.

Dérogation assumée à l'invariant 3 (garde de chemin unique du MCP) : ce
chemin est un **état local** fourni par l'opérateur (``XDG_DATA_HOME`` ou
``HEIMDALL_SNIPPET_HMAC_KEY_FILE``), jamais un chemin issu du dépôt ou du LLM.
La garde reste fail-closed (absolu, sans ``..``, sans lien symbolique,
propriétaire et permissions vérifiés).

La primitive ``hmac``/``hashlib`` de la bibliothèque standard n'est pas la
crypto du Vault : l'invariant 5 (``cryptography``/``argon2`` confinés à
``vault/crypto.py``) reste intact.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path
from typing import Final

from heimdall.scanner.errors import ScanError

KEY_ENV: Final[str] = "HEIMDALL_SNIPPET_HMAC_KEY"
KEY_FILE_ENV: Final[str] = "HEIMDALL_SNIPPET_HMAC_KEY_FILE"
KEY_BYTES: Final[int] = 32
_KEY_ERROR: Final[str] = "clé d'empreinte locale invalide"


def _key_path() -> Path:
    override = os.environ.get(KEY_FILE_ENV)
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute() or any(part == ".." for part in path.parts):
            raise ScanError(_KEY_ERROR)
        return path
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    if not base.is_absolute() or any(part == ".." for part in base.parts):
        raise ScanError(_KEY_ERROR)
    return base / "heimdall" / "snippet-hmac.key"


def _open_flags(base: int) -> int:
    return (
        base
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _current_uid() -> int | None:
    getuid = getattr(os, "getuid", None)
    return None if getuid is None else int(getuid())


def _check_owner_and_mode(metadata: os.stat_result) -> None:
    """Refuse une clé lisible par un autre utilisateur (POSIX)."""
    if os.name != "posix":
        return
    uid = _current_uid()
    owner = getattr(metadata, "st_uid", None)
    if uid is not None and owner is not None and owner != uid:
        raise ScanError(_KEY_ERROR)
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ScanError(_KEY_ERROR)


def _harden_parent(parent: Path) -> Path:
    """Crée ou durcit le répertoire de la clé et retourne son chemin résolu.

    ``parent`` est absolu et sans ``..`` (voir ``_key_path``). Après
    ``mkdir``, la résolution doit rendre **exactement** le chemin demandé :
    un lien symbolique sur le dernier composant *ou sur un composant
    intermédiaire* est refusé, car il déporterait la clé hors du répertoire
    prévu. ``O_NOFOLLOW`` protège ensuite l'ouverture du fichier lui-même.
    """
    try:
        if parent.is_symlink():
            raise ScanError(_KEY_ERROR)
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = parent.resolve(strict=True)
        # Sans lien symbolique, `resolve` est idempotent : toute différence
        # signifie qu'un composant a été redirigé (attaque ou configuration
        # inattendue), donc refus fail-closed.
        if resolved != parent:
            raise ScanError(_KEY_ERROR)
        metadata = resolved.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ScanError(_KEY_ERROR)
        if os.name == "posix":
            uid = _current_uid()
            owner = getattr(metadata, "st_uid", None)
            if uid is not None and owner is not None and owner != uid:
                raise ScanError(_KEY_ERROR)
            mode = stat.S_IMODE(metadata.st_mode)
            # Un répertoire accessible en écriture au monde (ex. /tmp, 01777)
            # n'est jamais chmodé : cela détruirait les permissions d'un
            # répertoire partagé, voire bloquerait le système si le scanner
            # tourne en root. On refuse fail-closed avant tout changement.
            if mode & 0o002:
                raise ScanError(_KEY_ERROR)
            if mode & 0o077:
                os.chmod(resolved, 0o700)
                if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
                    raise ScanError(_KEY_ERROR)
        return resolved
    except (OSError, RuntimeError):
        raise ScanError(_KEY_ERROR) from None


def _key_location(path: Path) -> Path:
    return _harden_parent(path.parent) / path.name


def _read_key(path: Path) -> bytes:
    try:
        descriptor = os.open(path, _open_flags(os.O_RDONLY))
    except OSError:
        raise ScanError(_KEY_ERROR) from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != KEY_BYTES:
            raise ScanError(_KEY_ERROR)
        _check_owner_and_mode(metadata)
        key = os.read(descriptor, KEY_BYTES + 1)
    except OSError:
        raise ScanError(_KEY_ERROR) from None
    finally:
        os.close(descriptor)
    if len(key) != KEY_BYTES:
        raise ScanError(_KEY_ERROR)
    return key


def _create_key(path: Path) -> bytes | None:
    key = secrets.token_bytes(KEY_BYTES)
    try:
        descriptor = os.open(
            path,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
        )
    except FileExistsError:
        return None
    except OSError:
        raise ScanError(_KEY_ERROR) from None
    try:
        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            fchmod(descriptor, 0o600)
        pending = key
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:
                raise OSError("écriture partielle")
            pending = pending[written:]
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != KEY_BYTES:
            raise OSError("taille inattendue")
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        raise ScanError(_KEY_ERROR) from None
    finally:
        os.close(descriptor)
    return key


def _environment_key() -> bytes | None:
    encoded = os.environ.get(KEY_ENV)
    if encoded is None:
        return None
    try:
        key = bytes.fromhex(encoded)
    except ValueError:
        raise ScanError(_KEY_ERROR) from None
    if len(key) != KEY_BYTES:
        raise ScanError(_KEY_ERROR)
    return key


def load_local_key() -> bytes:
    """Charge ou crée la clé HMAC locale, hors dépôt."""
    environment_key = _environment_key()
    if environment_key is not None:
        return environment_key
    path = _key_location(_key_path())
    try:
        return _read_key(path)
    except ScanError:
        pass
    created = _create_key(path)
    if created is not None:
        return created
    return _read_key(path)


class SnippetHasher:
    """Calcule l'empreinte d'un candidat sans jamais exposer sa valeur."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes | None = None) -> None:
        self._key = load_local_key() if key is None else key
        if len(self._key) != KEY_BYTES:
            raise ScanError(_KEY_ERROR)

    def hash(self, candidate: str) -> str:
        """HMAC-SHA-256 hexadécimal minuscule du candidat UTF-8."""
        return hmac.new(self._key, candidate.encode("utf-8"), hashlib.sha256).hexdigest()
