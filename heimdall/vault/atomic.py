"""Opérations de fichiers sécurisées et atomiques pour Heimdall (tickets #85, #100).

Fournit l'écriture atomique avec fsync, les permissions strictes 0600 (POSIX),
la gestion des sauvegardes et le contrôle de suivi Git.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import errno
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Final

from heimdall.mcp.gitdiff import GitAccess

_DEFAULT_SECURE_MODE: Final[int] = 0o600
_MAX_BACKUP_BYTES: Final[int] = 1_048_576
#: Extrait borné d'un chemin dans un message (invariant 8 : pas de chemin
#: opérateur de 5000 caractères recopié dans les logs).
_PATH_PREVIEW_LEN: Final[int] = 32
_MAX_ERROR_MSG_LEN: Final[int] = 150
_MIN_QUOTED_LEN: Final[int] = 2


def _bounded_error_message(message: str, max_len: int = _MAX_ERROR_MSG_LEN) -> str:
    """Borne et échappe un message d'erreur non fiable (invariant 8).

    Les caractères non imprimables (``\\n``, ``\\r``, ESC/ANSI, NUL, tabulation,
    C1...) sont rendus sous forme ``\\n``/``\\x1b`` : aucun saut de ligne brut
    ni séquence de terminal ne peut être injecté dans stderr/logs. Les
    caractères imprimables (accents compris) sont conservés. La transformation
    est idempotente et la longueur finale est plafonnée à ``max_len``.
    """
    safe = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in message
    )
    if len(safe) > max_len:
        safe = safe[: max_len - len("...")] + "..."
    return safe


#: Plafond d'attente des sondes `git` (gardes informatives) : un binaire
#: bloqué ne doit jamais pendre la CLI. `git` vient du PATH de confiance de
#: l'opérateur (jamais du Vault) ; tout échec/timeout vaut statut inconnu.
_GIT_TIMEOUT_SECONDS: Final[int] = 5


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
    voie POSIX. Il n'est JAMAIS appelé sur POSIX : ``write_file_atomic``
    emprunte toujours la voie forte ``dir_fd`` (verrouillé par test). Cible
    de confinement : Linux/POSIX uniquement (CI self-hosted Linux) ; Windows
    n'est couvert qu'en best-effort, sans garantie anti-TOCTOU native.
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


def _open_parent_dir_secure(parent: Path, *, create_missing: bool = True) -> int:  # noqa: PLR0912, PLR0915
    """Ouvre le répertoire parent sans jamais suivre de lien symbolique.

    Marche composant par composant depuis ``/`` avec ``openat`` +
    ``O_NOFOLLOW`` (``dir_fd``) : chaque composant existant est ouvert avec
    ``O_DIRECTORY | O_NOFOLLOW`` (un symlink lève ``ELOOP`` — ou ``ENOTDIR``
    quand combiné à ``O_DIRECTORY`` sur Linux — → refus), chaque
    composant manquant est créé par ``mkdirat`` (``0o700``) puis ré-ouvert
    avec ``O_NOFOLLOW`` (sauf ``create_missing=False`` : l'absence lève
    au lieu de créer, pour les lectures). Contrairement à
    ``Path.mkdir(parents=True)`` qui suit les liens intermédiaires, un
    échange d'un composant intermédiaire (``out/sub`` → symlink) est donc
    détecté au lieu d'être traversé.

    Retourne un descripteur ouvert sur le répertoire parent (à fermer par
    l'appelant). Lève ``ValueError`` fail-closed en cas de symlink, de
    composant non-répertoire, de répertoire accessible en écriture à
    d'autres utilisateurs sans sticky bit (``0o022``), ou de divergence
    ``fstat`` vs ``stat``.
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
        root_st = os.fstat(cur_fd)
    except OSError as exc:
        raise ValueError(f"Impossible de vérifier le répertoire parent : {exc}") from exc
    if (root_st.st_mode & 0o022) and not (root_st.st_mode & stat.S_ISVTX):
        raise ValueError(
            "Écriture refusée : permissions trop permissives sur le "
            "répertoire parent '/' (accessible en écriture à d'autres utilisateurs)."
        )

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
                if not create_missing:
                    raise ValueError(
                        f"Accès refusé : le répertoire parent '{comp}' n'existe pas."
                    ) from None
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
            if (st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX):
                try:
                    os.close(child_fd)
                except OSError:  # noqa: S110
                    pass
                raise ValueError(
                    "Écriture refusée : permissions trop permissives sur le "
                    f"répertoire parent '{comp}' (accessible en écriture à "
                    "d'autres utilisateurs)."
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


def _open_file_read_fd(path: Path) -> int:  # noqa: PLR0912
    """Ouvre un fichier en lecture sans suivre aucun symlink (cible + parents).

    Sur POSIX, le parent est ouvert par ``_open_parent_dir_secure`` (marcheur
    ``openat`` + ``O_NOFOLLOW``, ``create_missing=False`` : aucune création,
    insensible à l'échange d'un composant intermédiaire contre un symlink),
    puis la cible est ouverte par ``openat`` avec ``O_NOFOLLOW`` (refus si la
    cible finale est un lien) et ``O_NONBLOCK`` (pas de blocage sur FIFO,
    rejetée ensuite par le contrôle fichier régulier). Hors POSIX, repli
    direct best-effort (pas de ``dir_fd``, voir ``_write_file_atomic_fallback``).

    Retourne un descripteur ouvert (à fermer par l'appelant).
    Lève ``ValueError`` fail-closed en cas de symlink ou de parent non sûr.
    """
    target_name = path.name
    path_preview = str(path)[:_PATH_PREVIEW_LEN]
    if (
        not target_name
        or target_name in (".", "..")
        or "/" in target_name
        or "\x00" in target_name
        or (os.sep != "/" and os.sep in target_name)
    ):
        raise ValueError(f"Lecture refusée : nom de fichier invalide {path_preview!r}.")
    if os.path.islink(path):
        raise ValueError(f"Lecture refusée : {path_preview!r} est un lien symbolique.")

    if os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
        parent_fd = _open_parent_dir_secure(path.parent, create_missing=False)
        try:
            read_flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                read_flags |= os.O_NONBLOCK
            if hasattr(os, "O_CLOEXEC"):
                read_flags |= os.O_CLOEXEC
            return os.open(target_name, read_flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(
                    f"Lecture refusée : {path_preview!r} est un lien symbolique."
                ) from exc
            raise ValueError(
                f"Impossible d'ouvrir le fichier : {_bounded_error_message(str(exc))}"
            ) from exc
        finally:
            try:
                os.close(parent_fd)
            except OSError:  # noqa: S110
                pass

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise ValueError(
            f"Impossible d'ouvrir le fichier : {_bounded_error_message(str(exc))}"
        ) from exc


def write_file_atomic(  # noqa: PLR0912, PLR0915
    path: Path,
    content: str | bytes,
    mode: int = _DEFAULT_SECURE_MODE,
) -> None:
    """Écrit un fichier de manière atomique avec fsync et permissions strictes.

    Refuse strictement les liens symboliques (cible ou répertoire parent)
    et les parents accessibles en écriture à d'autres utilisateurs (sans
    sticky bit) afin de prévenir tout écrasement ou détournement de cible. Sur POSIX,
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

    Un saut de ligne (``\\n`` ou ``\\r``) est refusé (``ValueError``) : il
    injecterait une ligne ``NOM=…`` que ``parse_env_file`` ne relirait pas à
    l'identique. Les appelants filtrent déjà en amont ; ce refus est la
    défense en profondeur pour tout appel direct.
    """
    if "\n" in value or "\r" in value:
        raise ValueError("Saut de ligne interdit dans une valeur .env.")
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

    # Ouverture via le parent sécurisé (marcheur anti-symlink intermédiaire).
    try:
        fd = _open_file_read_fd(path)
    except (ValueError, OSError) as exc:
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

    Ni la cible ni aucun composant parent intermédiaire n'est suivi (marcheur
    ``_open_parent_dir_secure`` + ``openat`` ``O_NOFOLLOW`` sur POSIX).

    Retourne None si le fichier n'existe pas ou ne peut pas être lu
    (symlink, non-régulier, trop gros).
    """
    if os.path.islink(path):
        return None

    fd = -1
    try:
        fd = _open_file_read_fd(path)
    except (ValueError, OSError):
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


def _strip_env_inline_comment(raw_value: str) -> str:
    """Supprime un éventuel commentaire de fin de ligne hors chaînes quotées."""
    value = raw_value.strip()
    if not value or value.startswith("#"):
        return ""
    quote = value[0]
    if quote in ('"', "'"):
        index = 1
        while index < len(value):
            char = value[index]
            if quote == '"' and char == "\\" and index + 1 < len(value):
                index += 2
                continue
            if char == quote:
                trailing = value[index + 1 :]
                if not trailing or trailing.lstrip().startswith("#"):
                    return value[: index + 1]
                return value
            index += 1
        return value
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def parse_env_file(path: Path) -> dict[str, str] | None:
    """Parse un fichier .env en extrayant les paires clé=valeur.

    Gère le préfixe optionnel ``export `` et les commentaires de fin de ligne.
    Ignore les commentaires (#...) et les lignes vides.
    Refuse de suivre les liens symboliques (anti-exfiltration).
    Retourne None si le fichier ne peut pas être lu (symlink, permission, non-régulier).
    Retourne un dictionnaire (éventuellement vide) si le fichier a été lu avec succès.
    """
    content = read_file_secure_no_follow(path)
    if content is None:
        return None
    secrets_map: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith(("export ", "export\t")):
            key = key[len("export") :].strip()
        cleaned_val = _strip_env_inline_comment(val)
        decoded_val = _decode_env_value(cleaned_val)
        if key:
            secrets_map[key] = decoded_val
    return secrets_map


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
    seen: set[str] = set()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.partition("=")[0].strip()
        if key.startswith(("export ", "export\t")):
            key = key[len("export") :].strip()
        # Dédoublonnage O(1) : un .env.example d'1 Mio peut contenir ~200k
        # noms ; `key not in names` (liste) était O(n²), DoS CPU local.
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _find_repo_dir_without_symlinks(start: Path) -> Path | None:
    """Premier ancêtre portant ``.git``, par ``lstat`` seulement.

    Retourne ``None`` si un ancêtre ou ``.git`` lui-même est un lien
    symbolique (fail-closed), ou si aucun dépôt n'est trouvé.
    """
    for candidate in (start, *start.parents):
        try:
            if stat.S_ISLNK(os.lstat(candidate).st_mode):
                return None
            git_entry = os.lstat(candidate / ".git")
        except FileNotFoundError:
            continue
        except OSError:
            return None
        # ``.git`` symlinké vers l'extérieur : statut Git indéterminé.
        return None if stat.S_ISLNK(git_entry.st_mode) else candidate
    return None


def _get_git_toplevel(path: Path) -> Path | None:
    """Trouve la racine du dépôt Git contenant le chemin via ``GitAccess``.

    Sans jamais suivre les liens symboliques (``lstat``) : un répertoire
    ou un parent échangé contre un symlink ne doit pas fausser le cwd
    de ``git rev-parse`` (oracle Git trompeur, invariant 10).
    """
    try:
        path_stat = os.lstat(path)
        if stat.S_ISLNK(path_stat.st_mode):
            return None
        is_plain_dir = stat.S_ISDIR(path_stat.st_mode) and not stat.S_ISLNK(path_stat.st_mode)
    except OSError:
        is_plain_dir = False
    parent_dir = path if is_plain_dir else path.parent
    # ``GitAccess`` plafonne la découverte à son répertoire de travail
    # (``GIT_CEILING_DIRECTORIES``) : on localise donc la racine nous-mêmes,
    # par ``lstat`` seulement (aucun processus git par ancêtre). Un ancêtre
    # symlinké arrête la recherche (fail-closed : jamais de repli sur un dépôt
    # ancêtre sans rapport avec le fichier), puis un seul ``rev-parse``.
    repo_dir = _find_repo_dir_without_symlinks(parent_dir)
    if repo_dir is None:
        return None
    try:
        access = GitAccess(repo_dir)
        res = access.execute(("rev-parse", "--show-toplevel"), timeout=_GIT_TIMEOUT_SECONDS)
        if res.returncode != 0:
            return None
        top = res.stdout.decode("utf-8", errors="strict").strip()
        # Le toplevel annoncé par Git doit être exactement le dépôt localisé
        # par lstat, jamais un ancêtre ou une cible de lien.
        if top and Path(top) == access.root:
            return access.root
    except Exception:  # noqa: BLE001  # nosec B110
        return None
    return None


def _git_relative_path(path: Path, top: Path) -> Path | None:
    """Calcule le chemin relatif au dépôt sans suivre la cible finale.

    ``os.lstat`` refuse tout lien symbolique final (fail-closed, cohérent
    avec ``check_file_mode_600``) : un output échangé contre un symlink ne
    doit pas être résolu vers sa cible, ce qui fausserait le verdict
    « suivi / ignoré » et pourrait taire l'avertissement CLI. Seuls les
    composants parents sont résolus, jamais ``path`` lui-même. Toute erreur
    ou sortie du dépôt vaut ``None`` (statut Git indéterminé).
    """
    try:
        if not path.name or stat.S_ISLNK(os.lstat(path).st_mode):
            return None
    except OSError:
        return None
    try:
        resolved_parent = path.parent.resolve()
        resolved_top = top.resolve()
        return (resolved_parent / path.name).relative_to(resolved_top)
    except (ValueError, RuntimeError, OSError):
        return None


def is_git_tracked(path: Path) -> bool:
    """Vérifie si un fichier est actuellement suivi dans Git via ``GitAccess``."""
    top = _get_git_toplevel(path)
    if top is None:
        return False
    rel = _git_relative_path(path, top)
    if rel is None:
        return False
    try:
        access = GitAccess(top)
        res = access.execute(
            ("ls-files", "--error-unmatch", str(rel)),
            timeout=_GIT_TIMEOUT_SECONDS,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def is_git_ignored(path: Path) -> bool:
    """Vérifie si un chemin est ignoré par les règles .gitignore via ``GitAccess``."""
    top = _get_git_toplevel(path)
    if top is None:
        return False
    rel = _git_relative_path(path, top)
    if rel is None:
        return False
    try:
        access = GitAccess(top)
        res = access.execute(
            ("check-ignore", "-q", str(rel)),
            timeout=_GIT_TIMEOUT_SECONDS,
        )
        return res.returncode == 0
    except Exception:  # noqa: S110
        return False


def check_file_mode_600(path: Path) -> bool:
    """Vérifie si un fichier a les permissions 0600 (POSIX).

    Ne suit jamais les liens symboliques : un symlink retourne ``False``
    (oracle fail-closed, comme le reste du module qui utilise
    ``lstat``/``O_NOFOLLOW``/``fstat``).
    """
    if os.name != "posix":
        return True
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return False
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
