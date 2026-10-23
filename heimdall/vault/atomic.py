"""Opérations de fichiers sécurisées et atomiques pour Heimdall (tickets #85, #100).

Fournit l'écriture atomique avec fsync, les permissions strictes 0600 (POSIX),
la gestion des sauvegardes et le contrôle de suivi Git.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import errno
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Final

_DEFAULT_SECURE_MODE: Final[int] = 0o600
_MAX_BACKUP_BYTES: Final[int] = 1_048_576
_MIN_QUOTED_LEN: Final[int] = 2


def _write_file_atomic_dir_fd(
    parent_fd: int,
    target_name: str,
    data: bytes,
    mode: int,
) -> None:
    """Écrit et remplace un fichier exclusivement via le descripteur du parent.

    Aucun chemin n'est ré-résolu après l'ouverture du répertoire : la création
    du temporaire et le remplacement utilisent ``dir_fd`` (équivalent
    ``openat``/``renameat``). Un échange du répertoire parent contre un lien
    symbolique après l'ouverture ne peut donc pas détourner l'écriture.
    """
    temp_name = f".{target_name}.tmp.{secrets.token_hex(16)}"
    temp_fd = -1
    replaced = False
    try:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC

        temp_fd = os.open(temp_name, create_flags, mode, dir_fd=parent_fd)
        if os.name == "posix":
            os.fchmod(temp_fd, mode)
        with os.fdopen(temp_fd, "wb") as f:
            temp_fd = -1  # Géré désormais par f
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        # Vérification de la cible sans suivre un éventuel lien symbolique,
        # relativement au répertoire déjà ouvert.
        try:
            target_stat = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(target_stat.st_mode):
                raise ValueError(
                    f"Écriture refusée : la cible '{target_name}' est un lien symbolique."
                )

        os.replace(
            temp_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True

        try:
            os.fsync(parent_fd)
        except OSError:
            pass
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:  # noqa: S110
                pass
        if not replaced:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:  # noqa: S110
                pass


def _write_file_atomic_fallback(
    parent: Path,
    path: Path,
    data: bytes,
    mode: int,
) -> None:
    """Repli portable pour les plateformes sans ``dir_fd`` (Windows).

    Garantie POSIX-only : l'anti-symlink fort (marcheur ``openat`` +
    ``O_NOFOLLOW`` + ``dir_fd``) n'existe que sur POSIX. Ce repli reste en
    check-then-use par construction (pas de ``dir_fd``) : il refuse tout
    symlink avant ``replace`` et revérifie par ``lstat`` après ``replace``
    (fail-closed), sans prétendre à la même résistance aux courses que la
    voie POSIX.
    """
    prefix = f".{path.name}.tmp."
    temp_fd, temp_path_str = tempfile.mkstemp(prefix=prefix, dir=parent)
    temp_path = Path(temp_path_str)
    try:
        if os.name == "posix":
            os.fchmod(temp_fd, mode)
        with os.fdopen(temp_fd, "wb") as f:
            temp_fd = -1  # Géré désormais par f
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        if os.path.islink(path):
            raise ValueError(f"Écriture refusée : la cible '{path}' est un lien symbolique.")
        os.replace(temp_path, path)
        # Revérification post-replace sans suivre le lien (défense en
        # profondeur du repli check-then-use) : un symlink replanté après
        # le contrôle pré-replace fait échouer l'appel au lieu de passer
        # sous silence.
        try:
            final_st = os.lstat(path)
        except OSError as exc:
            raise ValueError(f"Impossible de vérifier le fichier : {exc}") from exc
        if stat.S_ISLNK(final_st.st_mode):
            raise ValueError(
                f"Écriture refusée : la cible '{path}' est un lien symbolique."
            )
        if not stat.S_ISREG(final_st.st_mode):
            raise ValueError(
                f"Écriture refusée : la cible '{path}' n'est pas un fichier régulier."
            )
        if os.name == "posix":
            os.chmod(path, mode)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:  # noqa: S110
                pass
        raise
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:  # noqa: S110
                pass


def _open_parent_dir_secure(parent: Path) -> int:  # noqa: PLR0912, PLR0915
    """Ouvre le répertoire parent sans jamais suivre de lien symbolique.

    Marche composant par composant depuis ``/`` avec ``openat`` +
    ``O_NOFOLLOW`` (``dir_fd``) : chaque composant existant est ouvert avec
    ``O_DIRECTORY | O_NOFOLLOW`` (un symlink lève ``ELOOP`` — ou ``ENOTDIR``
    quand combiné à ``O_DIRECTORY`` sur Linux — → refus), chaque
    composant manquant est créé par ``mkdirat`` (``0o700``) puis ré-ouvert
    avec ``O_NOFOLLOW``. Contrairement à ``Path.mkdir(parents=True)`` qui
    suit les liens intermédiaires, un échange d'un composant intermédiaire
    (``out/sub`` → symlink) est donc détecté au lieu d'être traversé.

    Retourne un descripteur ouvert sur le répertoire parent (à fermer par
    l'appelant). Lève ``ValueError`` fail-closed en cas de symlink, de
    composant non-répertoire ou de divergence ``fstat`` vs ``stat``.
    """
    abs_str = os.path.abspath(str(parent))
    if "\x00" in abs_str:
        raise ValueError("Écriture refusée : octet nul dans le chemin parent.")
    abs_path = Path(abs_str)
    if not abs_path.is_absolute():
        raise ValueError(f"Écriture refusée : chemin parent non absolu : '{parent}'.")
    parts = abs_path.parts
    if not parts or parts[0] != "/":
        raise ValueError(f"Écriture refusée : racine inattendue pour '{parent}'.")

    open_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        open_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        open_flags |= os.O_CLOEXEC

    try:
        cur_fd = os.open("/", open_flags)
    except OSError as exc:
        raise ValueError(f"Impossible d'ouvrir le répertoire parent : {exc}") from exc

    try:
        for comp in parts[1:]:
            if comp in ("", ".", ".."):
                raise ValueError(
                    f"Écriture refusée : composant parent invalide '{comp}'."
                )
            if "/" in comp or "\x00" in comp:
                raise ValueError(
                    f"Écriture refusée : composant parent invalide '{comp}'."
                )
            try:
                child_fd = os.open(comp, open_flags, dir_fd=cur_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(comp, 0o700, dir_fd=cur_fd)
                except FileExistsError:
                    pass  # Course bénigne : un tiers l'a créé, on ré-ouvre.
                except OSError as exc:
                    raise ValueError(
                        f"Impossible de créer le répertoire parent '{comp}' : {exc}"
                    ) from exc
                try:
                    child_fd = os.open(comp, open_flags, dir_fd=cur_fd)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ValueError(
                            f"Écriture refusée : le composant parent '{comp}' "
                            "est un lien symbolique."
                        ) from exc
                    if exc.errno == errno.ENOTDIR:
                        # O_DIRECTORY|O_NOFOLLOW sur un symlink vers un
                        # répertoire donne ENOTDIR sur Linux (pas ELOOP) :
                        # distinguer via lstat sans suivre le lien.
                        try:
                            link_st = os.stat(
                                comp, dir_fd=cur_fd, follow_symlinks=False
                            )
                            is_link = stat.S_ISLNK(link_st.st_mode)
                        except OSError:
                            is_link = False
                        if is_link:
                            raise ValueError(
                                f"Écriture refusée : le composant parent '{comp}' "
                                "est un lien symbolique."
                            ) from exc
                        raise ValueError(
                            f"Écriture refusée : le composant parent '{comp}' "
                            "n'est pas un répertoire."
                        ) from exc
                    raise ValueError(
                        f"Écriture refusée : composant parent '{comp}' "
                        f"non sécurisé ({exc})."
                    ) from exc
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError(
                        f"Écriture refusée : le composant parent '{comp}' "
                        "est un lien symbolique."
                    ) from exc
                if exc.errno == errno.ENOTDIR:
                    try:
                        link_st = os.stat(comp, dir_fd=cur_fd, follow_symlinks=False)
                        is_link = stat.S_ISLNK(link_st.st_mode)
                    except OSError:
                        is_link = False
                    if is_link:
                        raise ValueError(
                            f"Écriture refusée : le composant parent '{comp}' "
                            "est un lien symbolique."
                        ) from exc
                    raise ValueError(
                        f"Écriture refusée : le composant parent '{comp}' "
                        "n'est pas un répertoire."
                    ) from exc
                raise ValueError(
                    f"Écriture refusée : composant parent '{comp}' "
                    f"non sécurisé ({exc})."
                ) from exc
            try:
                st = os.fstat(child_fd)
            except OSError as exc:
                try:
                    os.close(child_fd)
                except OSError:  # noqa: S110
                    pass
                raise ValueError(
                    f"Écriture refusée : impossible de vérifier '{comp}' : {exc}"
                ) from exc
            if not stat.S_ISDIR(st.st_mode):
                try:
                    os.close(child_fd)
                except OSError:  # noqa: S110
                    pass
                raise ValueError(
                    f"Écriture refusée : le composant parent '{comp}' "
                    "n'est pas un répertoire."
                )
            try:
                os.close(cur_fd)
            except OSError:  # noqa: S110
                pass
            cur_fd = child_fd

        # Défense en profondeur : le fd obtenu doit désigner le même inode
        # que le chemin nominal. Un swap post-ouverture diverge ici.
        try:
            fd_stat = os.fstat(cur_fd)
            path_stat = os.stat(abs_str)
        except OSError as exc:
            raise ValueError(
                f"Impossible de vérifier le répertoire parent : {exc}"
            ) from exc
        if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise ValueError(
                "Écriture refusée : le répertoire parent a été modifié "
                "entre l'ouverture et la vérification (symlink TOCTOU)."
            )
        owned_fd = cur_fd
        cur_fd = -1
        return owned_fd
    finally:
        if cur_fd >= 0:
            try:
                os.close(cur_fd)
            except OSError:  # noqa: S110
                pass


def write_file_atomic(  # noqa: PLR0912, PLR0915
    path: Path,
    content: str | bytes,
    mode: int = _DEFAULT_SECURE_MODE,
) -> None:
    """Écrit un fichier de manière atomique avec fsync et permissions strictes.

    Refuse strictement les liens symboliques (cible ou répertoire parent)
    afin de prévenir tout écrasement ou détournement de cible. Sur POSIX,
    les répertoires parents sont créés et ouverts composant par composant
    avec ``openat`` + ``O_NOFOLLOW`` (voir ``_open_parent_dir_secure``) puis
    toutes les opérations passent par le descripteur du parent (``dir_fd``),
    ce qui neutralise un échange d'un composant intermédiaire contre un
    symlink avant ou pendant l'ouverture.
    """
    target_name = path.name
    if not target_name or target_name in (".", ".."):
        raise ValueError(f"Écriture refusée : nom de fichier invalide '{path}'.")
    if "/" in target_name or "\x00" in target_name:
        raise ValueError(f"Écriture refusée : nom de fichier invalide '{path}'.")
    if os.sep in target_name and os.sep != "/":
        raise ValueError(f"Écriture refusée : nom de fichier invalide '{path}'.")
    # Vérification anti-symlink précoce (message clair, défense en profondeur ;
    # la garantie réelle vient de l'ouverture O_NOFOLLOW ci-dessous).
    if os.path.islink(path):
        raise ValueError(f"Écriture refusée : la cible '{path}' est un lien symbolique.")
    for parent_part in path.parents:
        if os.path.islink(parent_part):
            raise ValueError(
                f"Écriture refusée : le répertoire parent '{parent_part}' est un lien symbolique."
            )

    parent = path.parent

    if os.name != "posix":  # pragma: no cover - dépend de la plateforme
        parent.mkdir(parents=True, exist_ok=True)
        for parent_part in path.parents:
            if os.path.islink(parent_part):
                raise ValueError(
                    "Écriture refusée : le répertoire parent "
                    f"'{parent_part}' est un lien symbolique."
                )
        data = content.encode("utf-8") if isinstance(content, str) else content
        try:
            _write_file_atomic_fallback(parent, path, data, mode)
        except OSError as exc:
            raise ValueError(f"Impossible d'écrire le fichier : {exc}") from exc
        return

    try:
        parent_fd = _open_parent_dir_secure(parent)
    except OSError as exc:
        raise ValueError(f"Impossible d'écrire le fichier : {exc}") from exc

    try:
        data = content.encode("utf-8") if isinstance(content, str) else content

        _write_file_atomic_dir_fd(parent_fd, target_name, data, mode)
    except OSError as exc:
        raise ValueError(f"Impossible d'écrire le fichier : {exc}") from exc
    finally:
        try:
            os.close(parent_fd)
        except OSError:  # noqa: S110
            pass


def format_env_value(value: str) -> str:
    """Encode une valeur ``.env`` entre guillemets doubles, sans expansion shell.

    Les caractères significatifs pour le shell (``\\``, ``"``, ``$`` et
    backtick) sont échappés. ``parse_env_file`` applique l'encodage inverse,
    ce qui garantit un aller-retour fidèle sans exécution si le fichier est
    sourcé.
    """
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
    return f'"{escaped}"'


def _decode_env_value(raw_value: str) -> str:
    """Décode une valeur ``.env`` produite par ``format_env_value``."""
    value = raw_value.strip()
    if len(value) >= _MIN_QUOTED_LEN and value.startswith('"') and value.endswith('"'):
        inner = value[1:-1]
        decoded: list[str] = []
        index = 0
        while index < len(inner):
            char = inner[index]
            if (
                char == "\\"
                and index + 1 < len(inner)
                and inner[index + 1] in ('\\', '"', "$", "`")
            ):
                decoded.append(inner[index + 1])
                index += 2
                continue
            decoded.append(char)
            index += 1
        return "".join(decoded)
    if len(value) >= _MIN_QUOTED_LEN and value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    return value


def backup_file(path: Path) -> Path | None:  # noqa: PLR0912
    """Crée une copie de sauvegarde d'un fichier existant avec droits 0600."""
    if os.path.islink(path):
        raise ValueError(f"Sauvegarde refusée : '{path}' est un lien symbolique.")
    if not path.is_file():
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Impossible d'ouvrir le fichier à sauvegarder : {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Sauvegarde refusée : '{path}' n'est pas un fichier régulier.")
        if st.st_size > _MAX_BACKUP_BYTES:
            raise ValueError(
                f"Sauvegarde refusée : '{path}' dépasse la taille maximale "
                f"({_MAX_BACKUP_BYTES} octets)."
            )
        # Lecture bornée : le fichier peut grossir entre fstat() et read().
        content = os.read(fd, _MAX_BACKUP_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Impossible de lire le fichier à sauvegarder : {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError:  # noqa: S110
            pass

    if len(content) > _MAX_BACKUP_BYTES:
        raise ValueError(
            f"Sauvegarde refusée : '{path}' dépasse la taille maximale "
            f"({_MAX_BACKUP_BYTES} octets)."
        )

    backup_path = path.with_suffix(path.suffix + ".bak")
    if os.path.islink(backup_path):
        raise ValueError(
            f"Sauvegarde refusée : la cible backup '{backup_path}' est un lien symbolique."
        )

    write_file_atomic(backup_path, content, mode=_DEFAULT_SECURE_MODE)
    return backup_path


def read_file_secure_no_follow(  # noqa: PLR0911, PLR0912
    path: Path,
    max_bytes: int = 1_048_576,
) -> str | None:
    """Lit un fichier de manière sécurisée sans suivre les liens symboliques (anti-TOCTOU).

    Retourne None si le fichier n'existe pas ou ne peut pas être lu
    (symlink, non-régulier, trop gros).
    """
    if os.path.islink(path):
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

    fd = -1
    try:
        fd = os.open(path, flags)
    except OSError:
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > max_bytes:
            return None
        # Lecture bornée : le fichier peut grossir entre fstat() et read().
        raw = os.read(fd, max_bytes + 1)
    except Exception:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:  # noqa: S110
                pass

    if len(raw) > max_bytes:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_env_file(path: Path) -> dict[str, str] | None:
    """Parse un fichier .env en extrayant les paires clé=valeur.

    Ignore les commentaires (#...) et les lignes vides.
    Refuse de suivre les liens symboliques (anti-exfiltration).
    Retourne None si le fichier ne peut pas être lu (symlink, permission, non-régulier).
    Retourne un dictionnaire (éventuellement vide) si le fichier a été lu avec succès.
    """
    content = read_file_secure_no_follow(path)
    if content is None:
        return None
    secrets: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = _decode_env_value(val)
        if key:
            secrets[key] = val
    return secrets


def parse_example_names(path: Path) -> list[str] | None:
    """Extrait les noms de variables déclarés dans un .env.example.

    Refuse de suivre les liens symboliques.
    Retourne None si le fichier ne peut pas être lu (symlink, permission, non-régulier).
    Retourne une liste (éventuellement vide) si le fichier a été lu avec succès.
    """
    if os.path.islink(path):
        return None
    try:
        content = read_file_secure_no_follow(path)
    except Exception:
        return None
    if content is None:
        return None
    names: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.partition("=")[0].strip()
        if key and key not in names:
            names.append(key)
    return names


def _get_git_toplevel(path: Path) -> Path | None:
    """Trouve la racine du dépôt Git contenant le chemin."""
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    parent_dir = path if path.is_dir() else path.parent
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=parent_dir,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            top = res.stdout.strip()
            if top:
                return Path(top)
    except Exception:  # noqa: S110
        pass
    return None


def is_git_tracked(path: Path) -> bool:
    """Vérifie si un fichier est actuellement suivi dans Git."""
    git_bin = shutil.which("git")
    if not git_bin:
        return False
    top = _get_git_toplevel(path)
    if top is None:
        return False
    try:
        rel = path.resolve().relative_to(top.resolve())
    except (ValueError, RuntimeError, OSError):
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "ls-files", "--error-unmatch", str(rel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=top,
            check=False,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def is_git_ignored(path: Path) -> bool:
    """Vérifie si un chemin est ignoré par les règles .gitignore."""
    git_bin = shutil.which("git")
    if not git_bin:
        return False
    top = _get_git_toplevel(path)
    if top is None:
        return False
    try:
        rel = path.resolve().relative_to(top.resolve())
    except (ValueError, RuntimeError, OSError):
        return False
    try:
        res = subprocess.run(  # noqa: S603
            [git_bin, "check-ignore", "-q", str(rel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=top,
            check=False,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def check_file_mode_600(path: Path) -> bool:
    """Vérifie si un fichier a les permissions 0600 (POSIX)."""
    if os.name != "posix":
        return True
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        return (mode & 0o077) == 0
    except OSError:
        return False


__all__ = [
    "backup_file",
    "check_file_mode_600",
    "format_env_value",
    "is_git_ignored",
    "is_git_tracked",
    "parse_env_file",
    "parse_example_names",
    "read_file_secure_no_follow",
    "write_file_atomic",
]
