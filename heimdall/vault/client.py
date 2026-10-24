"""Client du Vault — tickets #25, #35 (#98, #99, #100, #101).

Parle au Vault EXCLUSIVEMENT en HTTPS vers une adresse de boucle locale
(invariant 12 ; allowlist : ``127.0.0.1``, ``::1``, ``localhost``), avec
vérification TLS obligatoire (chaîne + SAN, CA interne explicitement
approuvée). ``localhost`` est épinglé vers l'IP de boucle locale résolue à
la construction : le client ne résout plus aucun nom à la connexion, aucune
fenêtre de rebinding DNS. Interdit : ``verify=False``, ``-k``, contexte SSL non vérifié,
repli non vérifié, credentials dans l'URL, espaces ou caractères de contrôle
dans l'URL, formes encodées ``%XX`` (``%3F``/``%23`` contourneraient le rejet
de query/fragment), ports hors 1-65535 (concaténation ``f"{base_url}/..."``
dangereuse en #25).

La clé API doit être une chaîne non vide et non blanche (refus local précoce
plutôt qu'un 401 générique en #25) et l'URL une chaîne non vide, stockée sous
forme canonique reconstruite depuis hôte+port (sans `/` final, casse
normalisée) pour une concaténation sûre. Le client conserve son credential
dans un stockage local protégé (#26 : mode 600), jamais dans l'URL ni les
logs — ``repr()`` est redacté et la clé ne doit jamais être journalisée.

Confinement crypto (ticket #17) : ce module n'importe JAMAIS cryptography
ni argon2.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NoReturn
from urllib.parse import urlparse

from heimdall.vault.atomic import _open_file_read_fd, read_file_secure_no_follow

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

if TYPE_CHECKING:
    import httpx
    from pydantic import BaseModel, ConfigDict, Field, ValidationError
else:
    try:
        import httpx
    except ImportError:  # pragma: no cover
        httpx = None

    try:
        from pydantic import BaseModel, ConfigDict, Field, ValidationError
    except ImportError:  # pragma: no cover
        BaseModel = None
        ConfigDict = None
        Field = None
        ValidationError = None

_ALLOWED_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost"})
_MAX_PORT: Final[int] = 65535
_MAX_TIMEOUT_SECONDS: Final[float] = 300.0
_MAX_SECRET_VALUE_LEN: Final[int] = 65536
_MAX_RESPONSE_BYTES: Final[int] = 1_048_576
_MAX_API_KEY_FILE_BYTES: Final[int] = 4096
_MAX_CA_CERT_BYTES: Final[int] = 1_048_576
_MAX_STATUS_LEN: Final[int] = 64
_GROUP_OTHER_PERMS_MASK: Final[int] = 0o077
#: Taille des morceaux de lecture HTTP : aucun chunk alloué au-delà avant le
#: contrôle du compteur (miroir de ``os.read(fd, MAX + 1)`` côté fichiers).
_STREAM_CHUNK_SIZE: Final[int] = 64 * 1024
#: Plafonds des en-têtes HTTP avant lecture du corps. httpx 0.28.1 /
#: httpcore / h11 n'exposent aucun plafond configurable sur les en-têtes
#: (vérifié dans le venv : h11 bufferise jusqu'à fin des en-têtes sans
#: limite) : ce contrôle pré-corps est le point d'application, le buffering
#: pair restant la borne ultime (best-effort, boucle locale uniquement).
_MAX_RESPONSE_HEADERS_BYTES: Final[int] = 64 * 1024
_MAX_RESPONSE_HEADER_COUNT: Final[int] = 256
#: Longueur maximale d'un extrait d'entrée recopié dans un message d'erreur
#: (invariant 8 : messages bornés, jamais de valeur recopiée en entier).
_PREVIEW_LEN: Final[int] = 32
#: Plafond d'attente des sondes `git` (détection projet informative) : un
#: binaire bloqué ne doit jamais pendre la CLI. `git` vient du PATH de
#: confiance de l'opérateur ; tout échec/timeout vaut absence de détection.
_GIT_TIMEOUT_SECONDS: Final[int] = 5

_PROJECT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENV_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SECRET_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class VaultClientError(Exception):
    """Erreur générique du client Vault."""


class VaultAuthError(VaultClientError):
    """Erreur 401 : Authentification requise ou clé API invalide."""


class VaultForbiddenError(VaultClientError):
    """Erreur 403 : Accès interdit pour le projet demandé."""


class VaultNotFoundError(VaultClientError):
    """Erreur 404 : Ressource introuvable dans le Vault."""


class VaultConflictError(VaultClientError):
    """Erreur 409 : Secret déjà existant dans le Vault."""


class VaultRateLimitError(VaultClientError):
    """Erreur 429 : Trop de requêtes adressées au Vault."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class VaultUnavailableError(VaultClientError):
    """Erreur 500/503 ou indisponibilité réseau du Vault."""


if BaseModel is not None:

    class _HealthResponseModel(BaseModel):
        model_config = ConfigDict(extra="forbid")
        status: str = Field(min_length=1, max_length=_MAX_STATUS_LEN)
        version: str | None = Field(default=None, max_length=_MAX_STATUS_LEN)

    class _SecretResponseModel(BaseModel):
        model_config = ConfigDict(extra="forbid")
        project: str = Field(min_length=1, max_length=64, pattern=_PROJECT_ID_PATTERN.pattern)
        env: str = Field(min_length=1, max_length=64, pattern=_ENV_ID_PATTERN.pattern)
        name: str = Field(min_length=2, max_length=64, pattern=_SECRET_NAME_PATTERN.pattern)
        status: str = Field(min_length=1, max_length=_MAX_STATUS_LEN, pattern=r"^[a-z0-9_-]+$")
        value: str = Field(min_length=1, max_length=_MAX_SECRET_VALUE_LEN)

    class _SecretMetadataResponseModel(BaseModel):
        model_config = ConfigDict(extra="forbid")
        project: str = Field(min_length=1, max_length=64, pattern=_PROJECT_ID_PATTERN.pattern)
        env: str = Field(min_length=1, max_length=64, pattern=_ENV_ID_PATTERN.pattern)
        name: str = Field(min_length=2, max_length=64, pattern=_SECRET_NAME_PATTERN.pattern)
        status: str = Field(min_length=1, max_length=_MAX_STATUS_LEN, pattern=r"^[a-z0-9_-]+$")


def _validate_identifier(value: str, label: str, pattern: re.Pattern[str]) -> None:
    """Valide la forme d'un identifiant contractuel (projet, environnement, nom).

    Le message d'erreur est borné : une réponse Vault ou un argument CLI
    volumineux ne doit pas être recopié en entier dans les logs (invariant 8).
    """
    if not isinstance(value, str) or not pattern.match(value):
        preview = value[:_PREVIEW_LEN] if isinstance(value, str) else f"<{type(value).__name__}>"
        raise ValueError(f"Identifiant de {label} invalide : {preview!r}")


def _key_from_env() -> str | None:
    """Tente de lire la clé depuis la variable d'environnement HEIMDALL_API_KEY."""
    env_key = os.environ.get("HEIMDALL_API_KEY")
    if env_key is not None and env_key.strip():
        return env_key.strip()
    return None


def _find_key_file(key_file: Path | None) -> Path | None:
    """Détermine le chemin du fichier de clé API.

    ``HOME`` indéterminé → ``None`` (l'appelant lève l'erreur standard
    « clé requise », qui devient ``Exit(2)`` en CLI — jamais de traceback).
    """
    if key_file is not None:
        return key_file
    env_file = os.environ.get("HEIMDALL_API_KEY_FILE")
    if env_file is not None and env_file.strip():
        return Path(env_file.strip())
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    try:
        config_dir = Path(xdg_config) if xdg_config else Path.home() / ".config"
    except (OSError, RuntimeError):
        return None
    default_file = config_dir / "heimdall" / "vault.key"
    if default_file.exists():
        return default_file
    return None


def _read_and_check_key_file(path: Path) -> str:  # noqa: PLR0912
    """Valide les permissions et lit le fichier de clé de façon atomique sans TOCTOU.

    Ni la cible ni aucun composant parent intermédiaire n'est suivi (parent
    ouvert par le marcheur ``_open_parent_dir_secure`` + ``openat``
    ``O_NOFOLLOW``, voir ``heimdall.vault.atomic``).
    """
    try:
        fd = _open_file_read_fd(path)
    except (ValueError, OSError) as exc:
        raise VaultClientError(f"Impossible d'ouvrir le fichier de clé API : {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise VaultClientError("Le chemin de clé API doit être un fichier régulier.")
        if st.st_size > _MAX_API_KEY_FILE_BYTES:
            raise VaultClientError(
                f"Fichier de clé API trop volumineux (max {_MAX_API_KEY_FILE_BYTES} octets)."
            )

        if os.name == "posix":
            if st.st_uid != os.getuid():
                raise VaultClientError(
                    "Le fichier de clé API doit appartenir à l'utilisateur courant."
                )
            mode = stat.S_IMODE(st.st_mode)
            if mode & _GROUP_OTHER_PERMS_MASK:
                raise VaultClientError(
                    f"Permissions trop permissives sur le fichier de clé API ({oct(mode)}) : "
                    "droits 0600 requis (chmod 600)."
                )

        # Lecture bornée : le fichier peut grossir entre fstat() et read().
        raw = os.read(fd, _MAX_API_KEY_FILE_BYTES + 1)
        if len(raw) > _MAX_API_KEY_FILE_BYTES:
            raise VaultClientError(
                f"Fichier de clé API trop volumineux (max {_MAX_API_KEY_FILE_BYTES} octets)."
            )
        try:
            content = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise VaultClientError(
                "Le fichier de clé API n'est pas un texte UTF-8 valide."
            ) from None
    except OSError as exc:
        raise VaultClientError(f"Impossible de lire le fichier de clé API : {exc}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    if not content:
        raise VaultClientError("Le fichier de clé API est vide.")

    return content


def resolve_api_key(key_file: Path | None = None) -> str:
    """Résout la clé API depuis HEIMDALL_API_KEY ou un fichier en droits 0600.

    JAMAIS depuis un argument de commande (invariant DoD ticket #98).
    """
    env_key = _key_from_env()
    if env_key is not None:
        # Symétrique au fichier (4096 o.) : une variable d'opérateur n'a
        # aucune raison de dépasser le plafond, et la clé part en en-tête
        # vers le Vault. Message statique : la clé n'est jamais reflétée.
        if len(env_key) > _MAX_API_KEY_FILE_BYTES:
            raise VaultClientError(
                "Clé API du Vault trop volumineuse "
                f"(max {_MAX_API_KEY_FILE_BYTES} octets)."
            )
        key = env_key
    else:
        candidate_path = _find_key_file(key_file)
        if candidate_path is None or not candidate_path.exists():
            raise VaultClientError(
                "Clé API du Vault requise. "
                "Définir la variable d'environnement HEIMDALL_API_KEY "
                "ou placer la clé dans un fichier en permissions 0600 "
                "(HEIMDALL_API_KEY_FILE ou ~/.config/heimdall/vault.key)."
            )
        key = _read_and_check_key_file(candidate_path)

    if re.search(r"[\r\n\x00]", key):
        raise VaultClientError(
            "Clé API du Vault invalide : sauts de ligne ou octets nuls interdits."
        )

    return key


def resolve_vault_url(url: str | None = None) -> str:
    """Résout l'URL canonique du Vault depuis l'argument, l'environnement ou le défaut.

    Le défaut est ``https://127.0.0.1:8443`` (littéral IP, aucune résolution
    DNS) : ``localhost`` reste accepté par compatibilité mais est épinglé vers
    l'IP de boucle locale à la validation (voir ``_pin_loopback_ip``).
    """
    if url is not None and url.strip():
        return url.strip()
    env_url = os.environ.get("HEIMDALL_VAULT_URL")
    if env_url is not None and env_url.strip():
        return env_url.strip()
    return "https://127.0.0.1:8443"


def _detect_from_git(start_dir: Path) -> str | None:
    """Détecte l'identifiant du projet depuis le dépôt Git racine.

    Sonde informative bornée (``timeout``) : `git` vient du PATH de confiance
    de l'opérateur ; tout échec/timeout vaut absence de détection (None).
    """
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    try:
        git_root = subprocess.check_output(  # noqa: S603
            [git_bin, "rev-parse", "--show-toplevel"],
            cwd=start_dir,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).strip()
        if git_root:
            name = Path(git_root).name.lower()
            sanitized = re.sub(r"[^a-z0-9_-]", "-", name)
            if sanitized and sanitized[0].isalpha() and _PROJECT_ID_PATTERN.match(sanitized):
                return sanitized
    except Exception:  # noqa: S110
        pass
    return None


def _detect_from_pyproject(start_dir: Path) -> str | None:
    """Détecte l'identifiant du projet depuis pyproject.toml de façon bornée et sans symlink."""
    pyproject = start_dir / "pyproject.toml"
    if tomllib is None:
        return None
    try:
        content = read_file_secure_no_follow(pyproject, max_bytes=65536)
        if not content:
            return None
        data = tomllib.loads(content)
        name = data.get("project", {}).get("name")
        if isinstance(name, str):
            candidate = name.lower()
            if candidate and candidate[0].isalpha() and _PROJECT_ID_PATTERN.match(candidate):
                return candidate
    except Exception:  # noqa: S110
        pass
    return None


def detect_project(start_dir: Path | None = None) -> str:
    """Détecte l'identifiant du projet à partir de l'environnement, de Git ou du dossier."""
    env_proj = os.environ.get("HEIMDALL_PROJECT")
    if env_proj is not None and env_proj.strip():
        candidate = env_proj.strip().lower()
        if _PROJECT_ID_PATTERN.match(candidate):
            return candidate

    dir_to_check = (start_dir or Path.cwd()).resolve()
    from_git = _detect_from_git(dir_to_check)
    if from_git is not None:
        return from_git

    from_pyproject = _detect_from_pyproject(dir_to_check)
    if from_pyproject is not None:
        return from_pyproject

    name = dir_to_check.name.lower()
    sanitized = re.sub(r"[^a-z0-9_-]", "-", name)
    if not (sanitized and sanitized[0].isalpha()):
        sanitized = f"p-{sanitized}"
    if _PROJECT_ID_PATTERN.match(sanitized):
        return sanitized[:64]
    return "default"


def _pin_loopback_ip(host: str) -> str:
    """Épingle ``localhost`` vers l'IP de boucle locale résolue (anti-rebinding).

    Résolution unique à la validation : le client stocke un littéral IP et
    ``httpx`` ne résout plus aucun nom à la connexion, ce qui ferme la
    fenêtre d'empoisonnement du résolveur local entre construction et
    requêtes. Choix déterministe : ``127.0.0.1`` si présent, sinon ``::1``.
    Toute adresse hors boucle, toute absence de résolution ou tout échec
    (``gaierror``) lève ``ValueError`` fail-closed. Les littéraux
    ``127.0.0.1``/``::1`` sont retournés inchangés.
    """
    if host in ("127.0.0.1", "::1"):
        return host
    try:
        addr_info = socket.getaddrinfo("localhost", None)
    except socket.gaierror as exc:
        raise ValueError(
            "Sécurité : localhost ne résout vers aucune adresse de boucle locale"
        ) from exc
    ips = {str(entry[4][0]) for entry in addr_info}
    outsiders = sorted(ips - {"127.0.0.1", "::1"})
    if outsiders:
        raise ValueError(
            f"Sécurité : localhost résout vers une IP hors boucle locale ({outsiders[0]})"
        )
    if "127.0.0.1" in ips:
        return "127.0.0.1"
    if "::1" in ips:
        return "::1"
    raise ValueError("Sécurité : localhost ne résout vers aucune adresse de boucle locale")


def _check_localhost_resolution(host: str) -> None:
    """Vérifie que localhost résout strictement vers une boucle locale.

    Contrôle à la construction relayé par ``_pin_loopback_ip`` : `localhost`
    est accepté par compatibilité mais `127.0.0.1` reste le défaut sans
    résolution (aucune fenêtre de rebinding sur le défaut).
    """
    if host != "localhost":
        return
    _pin_loopback_ip(host)


def _validate_loopback_url(base_url: str) -> str:  # noqa: PLR0912
    """Vérifie l'URL du Vault (HTTPS, boucle locale, forme canonique).

    ``localhost`` est accepté en entrée mais stocké épinglé vers l'IP de
    boucle locale (voir ``_pin_loopback_ip``) : la forme canonique stockée ne
    contient plus jamais de nom à résoudre.
    """
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("URL du Vault requise (chaîne non vide)")
    if re.search(r"\s|[\x00-\x09\x0e-\x1f\x7f]", base_url):
        raise ValueError("espaces et contrôles interdits dans l'URL du Vault")
    if "%" in base_url:
        raise ValueError("formes encodées interdites dans l'URL du Vault")
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        raise ValueError("le Vault n'est joignable qu'en HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("aucun credential dans l'URL du Vault")
    if "?" in base_url or "#" in base_url:
        raise ValueError("ni query ni fragment dans l'URL du Vault")
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_LOOPBACK_HOSTS:
        raise ValueError(
            "le Vault n'est joignable que sur boucle locale (127.0.0.1, ::1, localhost)"
        )
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("port invalide dans l'URL du Vault (1-65535)") from None
    if port is not None and not 1 <= port <= _MAX_PORT:
        raise ValueError("port invalide dans l'URL du Vault (1-65535)")
    raw_authority = f"[{host}]" if ":" in host else host
    if port is not None:
        raw_authority = f"{raw_authority}:{port}"
    raw_canonical = f"{parsed.scheme}://{raw_authority}"
    if base_url != raw_canonical:
        raise ValueError("URL du Vault non canonique (attendu : scheme://hôte[:port])")
    pinned = _pin_loopback_ip(host)
    if pinned == host:
        return raw_canonical
    pinned_authority = f"[{pinned}]" if ":" in pinned else pinned
    if port is not None:
        pinned_authority = f"{pinned_authority}:{port}"
    return f"{parsed.scheme}://{pinned_authority}"


def _measure_response_headers(headers: Any) -> tuple[int, int]:
    """Compte les en-têtes et leurs octets (``httpx.Headers`` comme ``dict``).

    Préfère ``.raw`` (octets exacts sur le fil, doublons comptés) quand
    disponible, sinon ``.items()``. Aucune copie transitoire : comptage en
    générateur, jamais de liste dupliquée. En-têtes illisibles →
    ``ValueError`` (l'appelant convertit en ``VaultClientError`` bornée,
    fail-closed).
    """
    raw = getattr(headers, "raw", None)
    if raw is not None:
        total = 0
        for k, v in raw:
            total += len(k) + len(v)
        return len(raw), total
    items = getattr(headers, "items", None)
    if items is None:
        raise ValueError("en-têtes de réponse illisibles")
    entries = list(items())
    return len(entries), sum(len(str(k)) + len(str(v)) for k, v in entries)


def _read_bounded_body(resp: Any, endpoint: str) -> bytes:
    """Lit un corps HTTP en streaming avec une borne stricte de 1 Mio.

    Les en-têtes sont bornés d'abord (nombre + octets, sans copie
    transitoire ; borne ultime = buffering httpx/h11, voir constantes) ;
    ``Content-Length`` est vérifié avant lecture ;
    le compteur d'octets effectivement reçus protège aussi contre un en-tête
    absent, mensonger ou une réponse compressée qui se décompresserait
    au-delà de la limite. La lecture se fait par morceaux de
    ``_STREAM_CHUNK_SIZE`` : aucun chunk géant n'est alloué avant le contrôle
    du compteur.
    """
    header_count, header_bytes = _measure_response_headers(resp.headers)
    if header_count > _MAX_RESPONSE_HEADER_COUNT or header_bytes > _MAX_RESPONSE_HEADERS_BYTES:
        raise VaultClientError(
            f"En-têtes de réponse {endpoint} trop volumineux "
            f"(bornes : {_MAX_RESPONSE_HEADER_COUNT} en-têtes / "
            f"{_MAX_RESPONSE_HEADERS_BYTES} octets max)."
        )

    content_length_header = resp.headers.get("content-length")
    if content_length_header:
        try:
            content_length = int(content_length_header)
        except ValueError:
            content_length = None
        if content_length is not None and content_length > _MAX_RESPONSE_BYTES:
            raise VaultClientError(
                f"Réponse {endpoint} trop volumineuse "
                f"({content_length} octets, max {_MAX_RESPONSE_BYTES})."
            )

    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in resp.iter_bytes(chunk_size=_STREAM_CHUNK_SIZE):
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise VaultClientError(
                    f"Réponse {endpoint} trop volumineuse "
                    f"(>{_MAX_RESPONSE_BYTES} octets, max {_MAX_RESPONSE_BYTES})."
                )
            chunks.append(chunk)
    except VaultClientError:
        raise
    except Exception:
        raise VaultClientError(f"Erreur de lecture de la réponse {endpoint}.") from None
    return b"".join(chunks)


def _parse_and_validate_json_dict(resp: Any, endpoint: str) -> dict[str, Any]:
    """Parse et valide qu'une réponse est un dictionnaire JSON de taille bornée."""
    content = _read_bounded_body(resp, endpoint)
    try:
        data = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise VaultClientError(f"Réponse JSON invalide pour {endpoint}.") from None
    if not isinstance(data, dict):
        raise VaultClientError(f"Format de réponse {endpoint} invalide : attendu un objet JSON.")
    return data


def _validate_health_response(data: Any) -> dict[str, Any]:
    """Valide strictement la réponse health."""
    if not isinstance(data, dict):
        raise VaultClientError("Format de réponse health invalide : attendu un objet JSON.")
    if BaseModel is not None:
        try:
            _HealthResponseModel.model_validate(data)
        except ValidationError as exc:
            rejected = {str(err.get("loc", ("inconnu",))[-1]) for err in exc.errors()}
            rejected_str = ", ".join(sorted(rejected))
            raise VaultClientError(
                f"Réponse health non conforme au schéma (champs rejetés : {rejected_str})"
            ) from None
    else:
        if not set(data.keys()).issubset({"status", "version"}) or "status" not in data:
            raise VaultClientError("Réponse health non conforme : schéma inattendu.")
        if not isinstance(data["status"], str) or not (1 <= len(data["status"]) <= _MAX_STATUS_LEN):
            raise VaultClientError("Réponse health non conforme : statut invalide.")
    return data


def _validate_metadata_response(data: Any, label: str) -> dict[str, Any]:
    """Valide strictement la réponse metadata (create ou state) sans valeur."""
    if not isinstance(data, dict):
        raise VaultClientError(f"Format de réponse {label} invalide : attendu un objet JSON.")
    if BaseModel is not None:
        try:
            _SecretMetadataResponseModel.model_validate(data)
        except ValidationError as exc:
            rejected = {str(err.get("loc", ("inconnu",))[-1]) for err in exc.errors()}
            rejected_str = ", ".join(sorted(rejected))
            raise VaultClientError(
                f"Réponse {label} non conforme au schéma (champs rejetés : {rejected_str})"
            ) from None
    else:
        expected = {"project", "env", "name", "status"}
        if set(data.keys()) != expected:
            raise VaultClientError(
                f"Réponse {label} non conforme : clés inattendues ou manquantes."
            )
        try:
            _validate_identifier(str(data["project"]), "projet", _PROJECT_ID_PATTERN)
            _validate_identifier(str(data["env"]), "environnement", _ENV_ID_PATTERN)
            _validate_identifier(str(data["name"]), "nom de secret", _SECRET_NAME_PATTERN)
        except ValueError as exc:
            raise VaultClientError(
                f"Identifiant non conforme dans {label} (champ rejeté) : {exc}"
            ) from None
        status = data.get("status")
        if not isinstance(status, str) or not (1 <= len(status) <= _MAX_STATUS_LEN):
            status_preview = (
                status[:_PREVIEW_LEN] if isinstance(status, str) else type(status).__name__
            )
            raise VaultClientError(f"Statut non conforme dans {label} : {status_preview!r}")
    return data


def _validate_secret_read_response(data: Any) -> dict[str, Any]:
    """Valide strictement le schéma du secret retourné par le Vault sans fuite de valeur."""
    if not isinstance(data, dict):
        raise VaultClientError("Format de réponse Vault invalide : attendu un objet JSON.")

    if BaseModel is not None:
        try:
            _SecretResponseModel.model_validate(data)
        except ValidationError as exc:
            # Invariant 8 : ne jamais inclure l'input ou str(exc) qui contiendrait la valeur
            rejected = {str(err.get("loc", ("inconnu",))[-1]) for err in exc.errors()}
            rejected_str = ", ".join(sorted(rejected))
            raise VaultClientError(
                f"Réponse du Vault non conforme au schéma (champs rejetés : {rejected_str})"
            ) from None
    else:
        expected = {"project", "env", "name", "status", "value"}
        if set(data.keys()) != expected:
            diff = set(data.keys()) ^ expected
            diff_preview = ", ".join(sorted(str(k)[:32] for k in diff))[:64]
            raise VaultClientError(
                f"Schéma de réponse Vault invalide : champs inattendus/manquants ({diff_preview})"
            )
        val = data.get("value")
        if not isinstance(val, str) or not (1 <= len(val) <= _MAX_SECRET_VALUE_LEN):
            raise VaultClientError(
                "Valeur de secret non conforme au schéma (champ 'value' rejeté)."
            )
        try:
            _validate_identifier(str(data["project"]), "projet", _PROJECT_ID_PATTERN)
            _validate_identifier(str(data["env"]), "environnement", _ENV_ID_PATTERN)
            _validate_identifier(str(data["name"]), "nom de secret", _SECRET_NAME_PATTERN)
        except ValueError as exc:
            raise VaultClientError(
                f"Identifiant non conforme dans le secret (champ rejeté) : {exc}"
            ) from None

    status_val = data.get("status")
    if status_val not in ("actif", "revoque", "vaulte"):
        status_preview = str(status_val)[:_PREVIEW_LEN]
        raise VaultClientError(f"Statut de secret non conforme : {status_preview!r}")

    return data


class VaultClient:
    """Client HTTPS du Vault (boucle locale uniquement). Non héritable.

    Aucun hook ``transport`` n'est exposé en production : le constructeur
    crée toujours un ``httpx.Client`` TLS vérifié vers la boucle locale.
    L'injection d'un transport (``httpx.MockTransport``,
    ``SyncASGITransport``) est strictement réservée aux tests unitaires via
    la fabrique dédiée :meth:`VaultClient.create_for_tests`.
    """

    __slots__ = (
        "_base_url",
        "_api_key",
        "_timeout",
        "_ca_cert",
        "_transport",
        "_client",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("VaultClient non héritable (secret en mémoire)")

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        ca_cert: str | Path | None = None,
    ) -> None:
        self._init_state(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            ca_cert=ca_cert,
            transport=None,
        )

    @classmethod
    def create_for_tests(
        cls,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        ca_cert: str | Path | None = None,
        transport: Any = None,
    ) -> VaultClient:
        """Fabrique test-only : identique au constructeur + transport injecté.

        Ne doit jamais être appelée par le code de production
        (``heimdall/cli/vault_client.py`` ne la référence pas) : elle
        court-circuite le TLS loopback vérifié au profit du transport fourni.
        """
        instance = cls.__new__(cls)
        instance._init_state(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            ca_cert=ca_cert,
            transport=transport,
        )
        return instance

    def _init_state(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float,
        ca_cert: str | Path | None,
        transport: Any,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("clé API requise (chaîne non vide, non blanche)")
        if re.search(r"[\r\n\x00]", api_key):
            raise ValueError("clé API invalide (retours ligne et octets nuls interdits)")

        canonical = _validate_loopback_url(base_url)

        if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > _MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout invalide (nombre positif <= 300 secondes requis)")

        ca_context: ssl.SSLContext | None = None
        if ca_cert is not None:
            if not isinstance(ca_cert, (str, Path)):
                raise ValueError("chemin du certificat CA invalide")
            ca_path = Path(ca_cert)
            ca_content = read_file_secure_no_follow(ca_path, max_bytes=_MAX_CA_CERT_BYTES)
            if ca_content is None:
                raise ValueError(
                    "fichier de certificat CA introuvable ou non sécurisé : "
                    f"{str(ca_cert)[:_PREVIEW_LEN]!r}"
                )
            try:
                ca_context = ssl.create_default_context()
                ca_context.check_hostname = True
                ca_context.verify_mode = ssl.CERT_REQUIRED
                ca_context.load_verify_locations(cadata=ca_content)
            except (ssl.SSLError, ValueError):
                raise ValueError(
                    "certificat CA invalide : "
                    f"{str(ca_cert)[:_PREVIEW_LEN]!r}"
                ) from None

        self._base_url = canonical
        self._api_key = api_key
        self._timeout = float(timeout)
        self._ca_cert = ca_context
        self._transport = transport
        self._client: Any = None

    def __repr__(self) -> str:
        return f"VaultClient({self._base_url!r}, api_key=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    def __reduce__(self) -> NoReturn:
        raise TypeError("VaultClient n'est pas sérialisable (secret en mémoire)")

    def _get_client(self) -> httpx.Client:
        """Initialise ou réutilise le client HTTP sous-jacent."""
        if httpx is None:
            raise RuntimeError(
                "La bibliothèque 'httpx' est requise pour effectuer des requêtes HTTP."
            )
        if self._client is not None and not self._client.is_closed:
            return self._client  # type: ignore[no-any-return]

        verify: bool | ssl.SSLContext = True
        if self._ca_cert is not None:
            verify = self._ca_cert

        self._client = httpx.Client(
            base_url=self._base_url,
            verify=verify,
            timeout=self._timeout,
            transport=self._transport,
            headers={
                "User-Agent": "heimdall-vault-client/0.1.0",
                "Accept": "application/json",
            },
        )
        return self._client  # type: ignore[no-any-return]

    def _handle_error_response(self, resp: Any) -> NoReturn:
        """Convertit une réponse HTTP d'erreur en exception typée."""
        status = resp.status_code
        retry_after: int | None = None
        if "retry-after" in resp.headers:
            try:
                retry_after = int(resp.headers["retry-after"])
            except ValueError:
                pass

        if status == HTTPStatus.BAD_REQUEST:
            raise VaultClientError("Requête invalide auprès du Vault (400)")
        if status == HTTPStatus.UNAUTHORIZED:
            raise VaultAuthError("Authentification requise ou clé API invalide (401)")
        if status == HTTPStatus.FORBIDDEN:
            raise VaultForbiddenError("Accès interdit au projet demandé (403)")
        if status == HTTPStatus.NOT_FOUND:
            raise VaultNotFoundError("Ressource introuvable dans le Vault (404)")
        if status == HTTPStatus.CONFLICT:
            raise VaultConflictError("Secret déjà existant dans le Vault (409)")
        if status == HTTPStatus.TOO_MANY_REQUESTS:
            msg = "Trop de requêtes au Vault (429)"
            if retry_after is not None:
                msg += f" (veuillez attendre {retry_after} secondes)"
            raise VaultRateLimitError(msg, retry_after=retry_after)
        if status in (
            HTTPStatus.INTERNAL_SERVER_ERROR,
            HTTPStatus.BAD_GATEWAY,
            HTTPStatus.SERVICE_UNAVAILABLE,
            HTTPStatus.GATEWAY_TIMEOUT,
        ):
            raise VaultUnavailableError(f"Serveur Vault indisponible ({status})")
        raise VaultClientError(f"Erreur HTTP du Vault ({status})")

    def _request_json(  # noqa: PLR0913, PLR0917
        self,
        method: str,
        url: str,
        *,
        endpoint: str,
        expected_status: int,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Exécute une requête en streaming et parse une réponse JSON bornée."""
        try:
            client = self._get_client()
        except RuntimeError as exc:
            raise VaultUnavailableError(f"Erreur de communication avec le Vault : {exc}") from exc
        try:
            with client.stream(
                method,
                url,
                headers=headers,
                json=json_body,
            ) as resp:
                if resp.status_code == expected_status:
                    return _parse_and_validate_json_dict(resp, endpoint)
                self._handle_error_response(resp)
        except VaultClientError:
            raise
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            raise VaultUnavailableError(f"Erreur de communication avec le Vault : {exc}") from exc

    def health(self) -> dict[str, object]:
        """Vérifie la santé minimale du Vault (/api/v1/health)."""
        data = self._request_json(
            "GET",
            "/api/v1/health",
            endpoint="health",
            expected_status=HTTPStatus.OK,
        )
        return _validate_health_response(data)

    def create_secret(
        self,
        project: str,
        env: str,
        name: str,
        value: str,
    ) -> dict[str, Any]:
        """Crée un secret dans le Vault (/api/v1/secrets)."""
        _validate_identifier(project, "projet", _PROJECT_ID_PATTERN)
        _validate_identifier(env, "environnement", _ENV_ID_PATTERN)
        _validate_identifier(name, "nom de secret", _SECRET_NAME_PATTERN)
        if not isinstance(value, str) or not (1 <= len(value) <= _MAX_SECRET_VALUE_LEN):
            raise ValueError("Valeur de secret invalide (1-65536 caractères requis)")

        payload = {
            "project": project,
            "env": env,
            "name": name,
            "value": value,
        }
        headers = {"X-Heimdall-API-Key": self._api_key}
        data = self._request_json(
            "POST",
            "/api/v1/secrets",
            endpoint="secrets",
            expected_status=HTTPStatus.CREATED,
            headers=headers,
            json_body=payload,
        )
        return _validate_metadata_response(data, "création secret")

    def get_secret(
        self,
        project: str,
        env: str,
        name: str,
    ) -> dict[str, Any]:
        """Lit la valeur courante d'un secret (/api/v1/secrets/{project}/{env}/{name})."""
        _validate_identifier(project, "projet", _PROJECT_ID_PATTERN)
        _validate_identifier(env, "environnement", _ENV_ID_PATTERN)
        _validate_identifier(name, "nom de secret", _SECRET_NAME_PATTERN)

        headers = {"X-Heimdall-API-Key": self._api_key}
        data = self._request_json(
            "GET",
            f"/api/v1/secrets/{project}/{env}/{name}",
            endpoint="secrets",
            expected_status=HTTPStatus.OK,
            headers=headers,
        )
        return _validate_secret_read_response(data)

    def get_secret_state(
        self,
        project: str,
        env: str,
        name: str,
    ) -> dict[str, Any]:
        """Lit l'état d'un secret sans sa valeur (/api/v1/secrets/{project}/{env}/{name}/state)."""
        _validate_identifier(project, "projet", _PROJECT_ID_PATTERN)
        _validate_identifier(env, "environnement", _ENV_ID_PATTERN)
        _validate_identifier(name, "nom de secret", _SECRET_NAME_PATTERN)

        headers = {"X-Heimdall-API-Key": self._api_key}
        data = self._request_json(
            "GET",
            f"/api/v1/secrets/{project}/{env}/{name}/state",
            endpoint="state",
            expected_status=HTTPStatus.OK,
            headers=headers,
        )
        if "value" in data:
            raise VaultClientError("L'endpoint state ne doit jamais renvoyer de valeur.")
        return _validate_metadata_response(data, "état secret")

    def close(self) -> None:
        """Ferme la session HTTP sous-jacente."""
        if self._client is not None:
            try:
                if not getattr(self._client, "is_closed", False):
                    self._client.close()
            except Exception:  # noqa: S110
                pass
            self._client = None

    def __enter__(self) -> VaultClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()


__all__ = [
    "VaultAuthError",
    "VaultClient",
    "VaultClientError",
    "VaultConflictError",
    "VaultForbiddenError",
    "VaultNotFoundError",
    "VaultRateLimitError",
    "VaultUnavailableError",
    "detect_project",
    "resolve_api_key",
    "resolve_vault_url",
]
