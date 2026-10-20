"""Empreinte HMAC-SHA-256 des candidats, sans valeur brute (ADR-001).

La clé locale fait 32 octets et vit hors du dépôt :
``$HEIMDALL_SNIPPET_HMAC_KEY`` (hexadécimal, 64 caractères) ou, à défaut,
``$XDG_DATA_HOME/heimdall/snippet-hmac.key`` (défaut
``~/.local/share/heimdall/snippet-hmac.key``), créé en ``0600``. Si le stockage
local est indisponible, une clé de processus est utilisée : l'empreinte reste
non réversible, mais n'est plus stable entre deux exécutions.
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
        if not path.is_absolute():
            raise ScanError(_KEY_ERROR)
        return path
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    if not base.is_absolute():
        raise ScanError(_KEY_ERROR)
    return base / "heimdall" / "snippet-hmac.key"


def _open_flags(base: int) -> int:
    return (
        base
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _read_key(path: Path) -> bytes:
    try:
        descriptor = os.open(path, _open_flags(os.O_RDONLY))
    except OSError:
        raise ScanError(_KEY_ERROR) from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != KEY_BYTES:
            raise ScanError(_KEY_ERROR)
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
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            path,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
        )
    except FileExistsError:
        return None
    except OSError:
        # Stockage local indisponible : clé de processus, jamais de blocage
        # du scan pour un simple problème de cache d'empreinte.
        return key
    try:
        pending = key
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:
                raise OSError("écriture partielle")
            pending = pending[written:]
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        return key
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
    path = _key_path()
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
