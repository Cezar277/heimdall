"""Génération et sécurisation des fichiers d'environnement locaux (ticket #31).

Ne jamais laisser le secret dans l'arbre Git :
- ``.env.example`` : fichier versionnable ne contenant QUE les noms de variables,
  avec des valeurs strictement vides (``NOM=\\n``). Aucun secret n'y est jamais écrit.
- ``.env`` : fichier local contenant les secrets en clair, créé avec des permissions
  strictes 0600 (POSIX : ``os.open(..., 0o600)`` / ``fchmod``).
- ``.gitignore`` : ajout idempotent de ``.env`` s'il n'y figure pas déjà, évitant
  toute duplication de ligne ou committage accidentel.
- Contrôle de suivi Git : si ``.env`` est déjà suivi par Git (index ou historique),
  émission d'un avertissement de sécurité recommandant ``git rm --cached .env``.

Confinement et sécurité :
- Chemins confinés via ``heimdall.mcp.paths.confine`` (anti-traversal, pas de symlink escape).
- Écritures atomiques via ``heimdall.vault.atomic.write_file_atomic``
  (temporaire + fsync + replace atomique).
- Lectures bornées (1 Mio) et sans suivi de liens symboliques.
- Noms de variables validés via ``heimdall.remediation.naming.validate_variable_name``
  (grammaire fermée, denylist système, rejet des sauts de ligne et injections).
- Valeurs de variables formatées via ``heimdall.vault.atomic.format_env_value``
  (échappement des guillemets doubles, dollars, backticks, backslashes).
- Messages d'erreur statiques : aucune fuite de valeur de secret dans les exceptions.
"""

from __future__ import annotations

import os
import stat
import sys
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from heimdall.mcp.paths import PathEscape, confine
from heimdall.remediation.naming import validate_variable_name
from heimdall.remediation.templates import TemplateError
from heimdall.vault.atomic import (
    _get_git_toplevel,
    _open_file_read_fd,
    check_file_mode_600,
    format_env_value,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    write_file_atomic,
)

#: Lecture bornée : même plafond que le scanner et les templates (1 Mio).
_MAX_READ_BYTES: Final[int] = 1_048_576

#: Plafond de volume total cumulé des valeurs secrètes (anti-DoS mémoire).
_MAX_TOTAL_SECRET_CHARS: Final[int] = 1_048_576

#: Nombre maximal de variables traitées en un seul appel (aligné sur vault_client).
_MAX_VARIABLES_COUNT: Final[int] = 1024

#: Mode de permission strict (0600 : lecture/écriture propriétaire uniquement).
_SECURE_ENV_MODE: Final[int] = 0o600

#: Mode par défaut pour .gitignore et .env.example (0644).
_DEFAULT_FILE_MODE: Final[int] = 0o644


class EnvRemediationError(Exception):
    """Échec d'opération d'environnement : entrée invalide ou écriture impossible."""

    def __init__(
        self,
        message: str = "erreur de remédiation d'environnement : opération impossible",
    ) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class EnvRemediationReceipt:
    """Reçu d'une remédiation d'environnement réussie, sans aucun secret.

    Invariant de sécurité (REQ-SEC-01, invariant 8) : aucune valeur de secret
    n'est conservée ni reflétée dans ce reçu ou dans son repr().
    """

    env_file: str
    example_file: str
    gitignore_file: str
    variables: tuple[str, ...]
    example_created_or_updated: bool
    env_created_or_updated: bool
    gitignore_updated: bool
    git_tracked: bool
    git_ignored: bool
    warning: str | None = None
    git_rm_command: str | None = None

    def __repr__(self) -> str:
        return (
            f"EnvRemediationReceipt(env_file={self.env_file!r}, "
            f"example_file={self.example_file!r}, "
            f"gitignore_file={self.gitignore_file!r}, "
            f"variables={self.variables!r}, "
            f"example_updated={self.example_created_or_updated!r}, "
            f"env_updated={self.env_created_or_updated!r}, "
            f"gitignore_updated={self.gitignore_updated!r}, "
            f"git_tracked={self.git_tracked!r}, "
            f"git_ignored={self.git_ignored!r})"
        )


def _read_text_secure(path: Path) -> tuple[str, int]:
    """Lit un fichier texte régulier de façon sécurisée sans suivre de lien symbolique.

    Retourne le contenu texte décodé et le mode POSIX du fichier.
    Lève FileNotFoundError si le fichier n'existe pas.
    Lève EnvRemediationError si le fichier est un symlink, non régulier,
    trop volumineux (> 1 Mio) ou non décodable en UTF-8.
    """
    if os.path.islink(path):
        raise EnvRemediationError("lecture refusée : lien symbolique détecté")

    if not path.exists():
        raise FileNotFoundError(f"{path} introuvable")

    try:
        descriptor = _open_file_read_fd(path)
    except FileNotFoundError:
        raise
    except (ValueError, OSError):
        raise EnvRemediationError from None

    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise EnvRemediationError("lecture refusée : fichier non régulier")
        if status.st_size > _MAX_READ_BYTES:
            raise EnvRemediationError("lecture refusée : fichier trop volumineux")
        raw = os.read(descriptor, _MAX_READ_BYTES + 1)
    except OSError:
        raise EnvRemediationError from None
    finally:
        try:
            os.close(descriptor)
        except OSError:  # noqa: S110
            pass

    if len(raw) > _MAX_READ_BYTES:
        raise EnvRemediationError("lecture refusée : fichier trop volumineux")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EnvRemediationError("lecture refusée : encodage UTF-8 invalide") from None

    return text, stat.S_IMODE(status.st_mode)


def _extract_and_validate_names(  # noqa: PLR0912
    variables: str | Iterable[str] | Mapping[str, str] | Iterable[tuple[str, str]],
) -> list[str]:
    """Valide et extrait une liste de noms de variables dédoublonnés.

    Chaque nom est vérifié par validate_variable_name.
    Lève EnvRemediationError si un nom est invalide ou dépasse le plafond.
    """
    raw_names: list[str] = []
    if isinstance(variables, str):
        raw_names = [variables]
    elif isinstance(variables, Mapping):
        raw_names = list(variables.keys())
    elif isinstance(variables, Iterable):
        for item in variables:
            if isinstance(item, tuple):
                raw_names.append(item[0])
            else:
                raw_names.append(item)
    else:
        raise EnvRemediationError("liste de variables invalide : type non supporté")

    if not raw_names:
        raise EnvRemediationError("liste de variables vide")

    if len(raw_names) > _MAX_VARIABLES_COUNT:
        raise EnvRemediationError(
            f"trop de variables : {len(raw_names)} dépasse le plafond {_MAX_VARIABLES_COUNT}"
        )

    validated: list[str] = []
    seen: set[str] = set()
    for item in raw_names:
        if not isinstance(item, str):
            raise EnvRemediationError("nom de variable invalide : non-str")
        try:
            clean_name = validate_variable_name(item)
        except (TemplateError, ValueError, TypeError):
            raise EnvRemediationError from None
        if clean_name not in seen:
            seen.add(clean_name)
            validated.append(clean_name)

    return validated


def _parse_example_lines(content: str) -> tuple[set[str], list[str]]:
    """Extrait les noms existants et les lignes d'un .env.example."""
    names: set[str] = set()
    lines = content.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.partition("=")[0].strip()
        if key:
            names.add(key)
    return names, lines


def _is_env_covered_in_gitignore(content: str) -> bool:
    """Vérifie si une règle non commentée dans .gitignore couvre déjà .env."""
    lines = content.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # Motifs standards couvrant .env
        if line in (".env", "/.env", "*.env", ".env*", "/.env*"):
            return True
    return False


def ensure_gitignore_ignores_env(  # noqa: PLR0912
    root: Path,
    gitignore_path: str = ".gitignore",
    pattern: str = ".env",
) -> bool:
    """Ajoute de façon idempotente la règle d'exclusion de .env dans .gitignore.

    - Confine gitignore_path sous root.
    - Si .gitignore existe, vérifie si une règle non commentée exclut déjà le motif.
    - Si déjà présent : retourne False sans modifier le fichier (idempotence stricte).
    - Si absent : ajoute '.env\\n' (en préservant le contenu existant et les sauts de ligne)
      et écrit atomiquement.
    - Retourne True si le fichier a été modifié ou créé.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    raw_path = root / gitignore_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("écriture refusée : .gitignore est un lien symbolique")
    raw_path = root / gitignore_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("planification refusée : .gitignore est un lien symbolique")
    try:
        confined = confine(root, gitignore_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("planification refusée : .gitignore est un lien symbolique")

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("écriture refusée : .gitignore est un lien symbolique")

    existing_content = ""
    mode = _DEFAULT_FILE_MODE
    try:
        existing_content, mode = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    if _is_env_covered_in_gitignore(existing_content):
        return False

    clean_pattern = pattern.strip()
    if not clean_pattern or "\n" in clean_pattern or "\r" in clean_pattern:
        clean_pattern = ".env"

    if existing_content and not existing_content.endswith("\n"):
        new_content = f"{existing_content}\n{clean_pattern}\n"
    elif existing_content:
        new_content = f"{existing_content}{clean_pattern}\n"
    else:
        new_content = f"{clean_pattern}\n"

    try:
        write_file_atomic(confined.absolute, new_content, mode=mode)
    except (ValueError, OSError):
        raise EnvRemediationError from None

    return True


def update_env_example(
    root: Path,
    variables: str | Iterable[str] | Mapping[str, str] | Iterable[tuple[str, str]],
    example_path: str = ".env.example",
) -> list[str]:
    """Met à jour ou crée le fichier .env.example avec les noms de variables et des valeurs vides.

    INVARIANT DE SÉCURITÉ : .env.example ne contient JAMAIS de secret (REQ-SEC-01, invariant 8).
    Même si un dictionnaire {nom: valeur} est passé, les valeurs sont ignorées :
    seuls les noms sont écrits sous la forme 'NOM=\\n'.

    Chaque nom de variable est validé selon la grammaire stricte et la denylist
    système via validate_variable_name (lève EnvRemediationError si invalide).

    L'écriture est idempotente : si une variable est déjà déclarée dans .env.example,
    elle n'est pas dupliquée. L'ordre et les commentaires existants sont préservés.

    Retourne la liste des variables nouvellement ajoutées.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    validated_names = _extract_and_validate_names(variables)

    raw_path = root / example_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("écriture refusée : .env.example est un lien symbolique")
    try:
        confined = confine(root, example_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("écriture refusée : .env.example est un lien symbolique")

    existing_content = ""
    mode = _DEFAULT_FILE_MODE
    try:
        existing_content, mode = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    existing_names, _ = _parse_example_lines(existing_content)
    new_names = [name for name in validated_names if name not in existing_names]

    if not new_names:
        return []

    lines_to_add = [f"{name}=" for name in new_names]
    addition = "\n".join(lines_to_add) + "\n"

    if existing_content and not existing_content.endswith("\n"):
        new_content = f"{existing_content}\n{addition}"
    elif existing_content:
        new_content = f"{existing_content}{addition}"
    else:
        new_content = addition

    try:
        write_file_atomic(confined.absolute, new_content, mode=mode)
    except (ValueError, OSError):
        raise EnvRemediationError from None

    return new_names


def update_env_file(  # noqa: PLR0912, PLR0915
    root: Path,
    secrets: Mapping[str, str] | Iterable[tuple[str, str]],
    env_path: str = ".env",
) -> Path:
    """Met à jour ou crée le fichier .env avec les permissions strictes 0600.

    INVARIANT DE SÉCURITÉ : le fichier .env contient des secrets en clair.
    Il DOIT être créé et conservé avec le mode POSIX 0600 (os.open(..., 0o600)).
    Toute tentative d'accès via un lien symbolique est refusée fail-closed.

    Chaque clé est validée via validate_variable_name.
    Chaque valeur est échappée via format_env_value (prévention d'injection shell).
    Le volume total des secrets est borné à 1 Mio.

    Retourne le chemin absolu confiné du fichier écrit.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")

    if isinstance(secrets, Mapping):
        pairs = list(secrets.items())
    elif isinstance(secrets, Iterable):
        pairs = list(secrets)
    else:
        raise EnvRemediationError("secrets invalides : type non supporté")

    if not pairs:
        raise EnvRemediationError("aucun secret fourni")

    if len(pairs) > _MAX_VARIABLES_COUNT:
        raise EnvRemediationError(f"trop de secrets : {len(pairs)} dépasse {_MAX_VARIABLES_COUNT}")

    validated_dict: dict[str, str] = {}
    total_chars = 0
    for key, val in pairs:
        if not isinstance(key, str) or not isinstance(val, str):
            raise EnvRemediationError("clé ou valeur de secret invalide (non-str)")
        try:
            clean_key = validate_variable_name(key)
        except (TemplateError, ValueError, TypeError):
            raise EnvRemediationError from None

        total_chars += len(val)
        if total_chars > _MAX_TOTAL_SECRET_CHARS:
            raise EnvRemediationError("volume total des secrets supérieur à 1 Mio")

        validated_dict[clean_key] = val

    raw_path = root / env_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("écriture refusée : .env est un lien symbolique")
    try:
        confined = confine(root, env_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("écriture refusée : .env est un lien symbolique")

    # Lecture sécurisée du .env existant si présent pour fusionner
    merged_secrets: dict[str, str] = {}
    if confined.absolute.exists():
        if os.path.islink(confined.absolute):
            raise EnvRemediationError("écriture refusée : .env est un lien symbolique")
        existing_env = parse_env_file(confined.absolute)
        if existing_env is None:
            raise EnvRemediationError("impossible de lire le fichier .env existant")
        merged_secrets.update(existing_env)

    merged_secrets.update(validated_dict)

    lines = [f"{k}={format_env_value(v)}" for k, v in merged_secrets.items()]
    content = "\n".join(lines) + "\n"

    try:
        write_file_atomic(confined.absolute, content, mode=_SECURE_ENV_MODE)
    except (ValueError, OSError):
        raise EnvRemediationError from None

    if not check_file_mode_600(confined.absolute):
        raise EnvRemediationError("permissions invalides : .env n'est pas en mode 0600")

    return confined.absolute


def check_env_git_status(
    root: Path,
    env_path: str = ".env",
) -> tuple[bool, bool, str | None, str | None]:
    """Contrôle si .env est suivi ou ignoré par Git.

    Retourne un quadruplet :
    (is_tracked, is_ignored, warning_message, remediation_command)

    Si .env est suivi par Git (is_tracked == True) :
    - remediation_command = f"git rm --cached {rel_path}"
    - warning_message contient l'avertissement explicite.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    raw_path = root / env_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("écriture refusée : .env est un lien symbolique")
    try:
        confined = confine(root, env_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("écriture refusée : .env est un lien symbolique")

    tracked = is_git_tracked(confined.absolute)
    ignored = is_git_ignored(confined.absolute)

    if tracked:
        cmd = f"git rm --cached {confined.relative}"
        warn = (
            f"ATTENTION : Le fichier {confined.relative} est suivi par Git ! "
            f"Exécutez '{cmd}' et ajoutez-le à .gitignore pour éviter toute fuite."
        )
        return True, ignored, warn, cmd

    if ignored:
        return False, True, None, None

    if _get_git_toplevel(confined.absolute) is None:
        warn = (
            f"Avertissement : statut Git indéterminé pour '{confined.relative}' "
            "(hors dépôt ou git indisponible) : impossible de vérifier "
            "qu'il ne sera pas committé. Ajoutez-le à .gitignore et "
            "vérifiez avec 'git status'."
        )
        return False, False, warn, None

    warn = (
        f"Avertissement : Le fichier {confined.relative} n'est pas ignoré par Git. "
        f"Pensez à ajouter '{confined.relative}' dans .gitignore."
    )
    return False, False, warn, None


def plan_env_example_change(
    root: Path,
    variables: str | Iterable[str] | Mapping[str, str] | Iterable[tuple[str, str]],
    example_path: str = ".env.example",
) -> tuple[str, str, str] | None:
    """Calcule le diff (chemin_relatif, avant, après) pour .env.example sans modifier le disque.

    Utilisable par la CLI review pour construire un TextChange pour affichage diff.
    Retourne None si aucune variable nouvelle n'est à ajouter.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    validated_names = _extract_and_validate_names(variables)

    raw_path = root / example_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("écriture refusée : .env.example est un lien symbolique")
    try:
        confined = confine(root, example_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("écriture refusée : .env.example est un lien symbolique")

    existing_content = ""
    try:
        existing_content, _ = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    existing_names, _ = _parse_example_lines(existing_content)
    new_names = [name for name in validated_names if name not in existing_names]

    if not new_names:
        return None

    lines_to_add = [f"{name}=" for name in new_names]
    addition = "\n".join(lines_to_add) + "\n"

    if existing_content and not existing_content.endswith("\n"):
        after_content = f"{existing_content}\n{addition}"
    elif existing_content:
        after_content = f"{existing_content}{addition}"
    else:
        after_content = addition

    return confined.relative, existing_content, after_content


def plan_gitignore_change(
    root: Path,
    gitignore_path: str = ".gitignore",
    pattern: str = ".env",
) -> tuple[str, str, str] | None:
    """Calcule le diff (chemin_relatif, avant, après) pour .gitignore sans modifier le disque.

    Utilisable par la CLI review pour construire un TextChange pour affichage diff.
    Retourne None si .env est déjà ignoré dans .gitignore.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    raw_path = root / gitignore_path
    if os.path.islink(raw_path):
        raise EnvRemediationError("planification refusée : .gitignore est un lien symbolique")
    try:
        confined = confine(root, gitignore_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError("planification refusée : .gitignore est un lien symbolique")

    existing_content = ""
    try:
        existing_content, _ = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    if _is_env_covered_in_gitignore(existing_content):
        return None

    clean_pattern = pattern.strip()
    if not clean_pattern or "\n" in clean_pattern or "\r" in clean_pattern:
        clean_pattern = ".env"

    if existing_content and not existing_content.endswith("\n"):
        after_content = f"{existing_content}\n{clean_pattern}\n"
    elif existing_content:
        after_content = f"{existing_content}{clean_pattern}\n"
    else:
        after_content = f"{clean_pattern}\n"

    return confined.relative, existing_content, after_content


def remediate_environment(  # noqa: PLR0913
    root: Path,
    secrets: Mapping[str, str] | Iterable[tuple[str, str]],
    *,
    env_path: str = ".env",
    example_path: str = ".env.example",
    gitignore_path: str = ".gitignore",
    warn_stderr: bool = True,
) -> EnvRemediationReceipt:
    """Exécute la remédiation complète d'environnement selon les exigences du ticket #31.

    1. .env.example avec les noms et des valeurs vides (sans secrets).
    2. .env créé avec des droits stricts 600 (os.open(..., 0o600)).
    3. Ajout idempotent de .env au .gitignore s'il n'y figure pas déjà.
    4. Contrôle Git : si .env est déjà suivi par Git, propose 'git rm --cached .env'.

    Toute anomalie (traversal, symlink, nom invalide, entrée non fiable) lève
    EnvRemediationError de façon fail-closed.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")

    # 1. Mise à jour de .env.example (valeurs vides obligatoires)
    added_to_example = update_env_example(root, secrets, example_path=example_path)

    # 2. Mise à jour ou création de .env en mode 0600
    update_env_file(root, secrets, env_path=env_path)

    # 3. Ajout de .env au .gitignore si absent (idempotent)
    confined_env = confine(root, env_path)
    gitignore_updated = ensure_gitignore_ignores_env(
        root, gitignore_path=gitignore_path, pattern=confined_env.relative
    )

    # 4. Contrôle du suivi Git de .env
    tracked, ignored, warn, rm_cmd = check_env_git_status(root, env_path=env_path)
    if warn_stderr and warn:
        sys.stderr.write(warn + "\n")
        warnings.warn(warn, UserWarning, stacklevel=2)

    all_names = _extract_and_validate_names(secrets)
    confined_example = confine(root, example_path)
    confined_gitignore = confine(root, gitignore_path)

    return EnvRemediationReceipt(
        env_file=confined_env.relative,
        example_file=confined_example.relative,
        gitignore_file=confined_gitignore.relative,
        variables=tuple(all_names),
        example_created_or_updated=len(added_to_example) > 0,
        env_created_or_updated=True,
        gitignore_updated=gitignore_updated,
        git_tracked=tracked,
        git_ignored=ignored,
        warning=warn,
        git_rm_command=rm_cmd,
    )


__all__ = [
    "EnvRemediationError",
    "EnvRemediationReceipt",
    "check_env_git_status",
    "ensure_gitignore_ignores_env",
    "plan_env_example_change",
    "plan_gitignore_change",
    "remediate_environment",
    "update_env_example",
    "update_env_file",
]
