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
- Clés existantes relues depuis .env re-validées (rejet fail-closed des variables dangereuses).
- Négation '!' dans .gitignore respectée : le dernier motif gagne (sémantique gitignore).
- Motif .gitignore validé (rejet de négation, métacaractères et sauts de ligne)
  et limité à une cible de forme .env (pas d'ignore arbitraire de source).
- Chemins env/example/gitignore distincts après confinement (rejet des collisions)
  et de forme .env/.gitignore (pas d'écriture dans un fichier arbitraire).
- Lignes non commentées sans '=' rejetées dans .env.example (pas de recopie verbatim).
- Valeurs de variables formatées via ``heimdall.vault.atomic.format_env_value``
  (échappement des guillemets doubles, dollars, backticks, backslashes).
- ``.env.example`` et ``.gitignore`` : mode 0644 par défaut ; les bits d'écriture
  groupe/monde et setuid/setgid/sticky d'un fichier préexistant sont retirés
  (anti-tampering local).
- Diffs ``.env.example`` : valeurs préexistantes masquées (``***``), jamais
  exposées en clair (invariant 8).
- Messages d'erreur statiques : aucune fuite de valeur de secret dans les exceptions.
"""

from __future__ import annotations

import itertools
import os
import re
import shlex
import stat
import sys
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from heimdall.mcp.masking import mask_text, shannon_entropy
from heimdall.mcp.paths import ConfinedPath, PathEscape, confine, is_rel_path
from heimdall.remediation.naming import validate_variable_name
from heimdall.remediation.templates import TemplateError
from heimdall.vault.atomic import (
    _decode_env_value,
    _get_git_toplevel,
    _open_file_read_fd,
    check_file_mode_600,
    format_env_value,
    is_git_ignored,
    is_git_tracked,
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

#: Marqueur constant des valeurs masquées dans les diffs (aucune valeur réelle).
_MASKED_VALUE: Final[str] = "***"

#: Taille exacte attendue pour une paire (clé, valeur).
_SECRET_PAIR_LENGTH: Final[int] = 2

#: Suffixes de fichiers gabarits (.env.example, etc.) interdits comme cible de secrets.
_EXAMPLE_TEMPLATE_SUFFIXES: Final[tuple[str, ...]] = (
    ".example",
    ".template",
    ".sample",
    ".dist",
)

#: Extensions de sauvegarde ou fichiers temporaires rejetés fail-closed.
_REJECTED_ENV_SUFFIXES: Final[tuple[str, ...]] = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    "~",
    ".swp",
    ".tmp",
)

#: Métacaractères et caractères de globbing interdits dans un motif gitignore.
_GITIGNORE_FORBIDDEN_CHARS: Final[tuple[str, ...]] = (
    "*",
    "?",
    "[",
    "]",
    "{",
    "}",
    "\\",
)


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


def _confine_and_check_no_symlink(
    root: Path,
    rel_path: str,
    name_for_msg: str = "fichier",
) -> ConfinedPath:
    """Valide le type du chemin, confine sous root et refuse les liens symboliques."""
    if not isinstance(rel_path, str):
        raise EnvRemediationError(f"chemin {name_for_msg} invalide (non-str)")

    # Validation grammaticale AVANT tout accès disque : un chemin absolu ou
    # traversant ne doit jamais être staté (oracle d'existence hors racine).
    if not is_rel_path(rel_path):
        raise EnvRemediationError(f"chemin {name_for_msg} invalide")

    # ``confine`` résout les liens : le contrôle du chemin brut est conservé
    # pour refuser un symlink final (le chemin résolu, lui, n'est plus un lien).
    raw_path = root / rel_path
    if os.path.islink(raw_path):
        raise EnvRemediationError(f"accès refusé : {name_for_msg} est un lien symbolique")

    try:
        confined = confine(root, rel_path)
    except PathEscape:
        raise EnvRemediationError from None

    if os.path.islink(confined.absolute):
        raise EnvRemediationError(f"accès refusé : {name_for_msg} est un lien symbolique")

    return confined


def _is_env_like_path(rel_path: str) -> bool:
    """Vrai si le nom de fichier ressemble à un fichier d'environnement.

    Accepte :
    - le nom exact ``.env``
    - les préfixes normalisés ``.env.`` (ex. ``.env.example``, ``.env.local``)
    - les préfixes normalisés ``.env_`` (ex. ``.env_test``)
    - les suffixes ``.env`` (ex. ``prod.env``, ``config/a.env``).

    Refuse fail-closed :
    - les extensions de sauvegarde ou temporaires (``.env.bak``, ``.env.old``, etc.)
    - les faux positifs de préfixe (``.environment``, ``.envstuff``)
    - les sources ou fichiers arbitraires (``src/app.py``, ``.gitignore``).
    """
    name = Path(rel_path).name
    if not name or name != name.strip():
        return False
    if any(name.endswith(suffix) for suffix in _REJECTED_ENV_SUFFIXES):
        return False
    return (
        name == ".env"
        or name.startswith(".env.")
        or name.startswith(".env_")
        or name.endswith(".env")
    )


def _is_example_template_path(rel_path: str) -> bool:
    """Vrai si le chemin désigne un gabarit (.env.example, .env.template, etc.)."""
    name = Path(rel_path).name
    return any(name.endswith(suffix) for suffix in _EXAMPLE_TEMPLATE_SUFFIXES)


def _validate_env_like_path(
    rel_path: str,
    name_for_msg: str,
    *,
    expect_template: bool | None = None,
) -> str:
    """Valide qu'un chemin désigne un fichier d'environnement, pas une source.

    Si ``expect_template`` est vrai, exige un nom de gabarit (``.example``,
    ``.template``, ``.sample``, ``.dist``). S'il est faux, refuse un gabarit
    pour empêcher toute inversion de rôle (écriture de secrets dans un gabarit).
    """
    if not isinstance(rel_path, str):
        raise EnvRemediationError(f"chemin {name_for_msg} invalide (non-str)")
    if rel_path != rel_path.strip() or Path(rel_path).name != Path(rel_path).name.strip():
        raise EnvRemediationError(
            f"chemin {name_for_msg} invalide : espaces de tête ou de fin interdits"
        )
    if not is_rel_path(rel_path):
        raise EnvRemediationError(f"chemin {name_for_msg} invalide")
    if not _is_env_like_path(rel_path):
        raise EnvRemediationError(
            f"chemin {name_for_msg} invalide : fichier d'environnement attendu"
        )
    is_template = _is_example_template_path(rel_path)
    if expect_template is True and not is_template:
        raise EnvRemediationError(
            f"chemin {name_for_msg} invalide : nom de gabarit (.example) attendu"
        )
    if expect_template is False and is_template:
        raise EnvRemediationError(
            f"chemin {name_for_msg} invalide : un gabarit (.example) ne peut recevoir de secrets"
        )
    return rel_path


def _validate_gitignore_path(rel_path: str) -> str:
    """Valide qu'un chemin désigne bien un fichier ``.gitignore``."""
    if not isinstance(rel_path, str):
        raise EnvRemediationError("chemin .gitignore invalide (non-str)")
    if rel_path != rel_path.strip() or not is_rel_path(rel_path):
        raise EnvRemediationError("chemin .gitignore invalide")
    if Path(rel_path).name != ".gitignore":
        raise EnvRemediationError("chemin .gitignore invalide : nom .gitignore attendu")
    return rel_path


def _validate_gitignore_pattern(pattern: str) -> str:
    """Valide et assainit le motif destiné à .gitignore.

    Refuse fail-closed toute entrée malveillante ou ambiguë :
    - Non-str -> EnvRemediationError
    - Espaces de tête ou de fin -> EnvRemediationError (aucun strip() silencieux)
    - Négation '!' -> EnvRemediationError
    - Commentaire '#' -> EnvRemediationError
    - Globbing dangereux '*' ou '?' -> EnvRemediationError
    - Sauts de ligne '\\n', '\\r' -> EnvRemediationError
    - Motif vide ou ne respectant pas is_rel_path -> EnvRemediationError
    - Chemin qui ne ressemble pas à un fichier d'environnement -> EnvRemediationError
    """
    if not isinstance(pattern, str):
        raise EnvRemediationError("motif .gitignore invalide : non-str")

    if (
        not pattern
        or pattern != pattern.strip()
        or Path(pattern).name != Path(pattern).name.strip()
        or "\n" in pattern
        or "\r" in pattern
    ):
        raise EnvRemediationError(
            "motif .gitignore invalide : motif vide, espaces de bord ou saut de ligne"
        )

    if (
        pattern.startswith("!")
        or pattern.startswith("#")
        or any(char in pattern for char in _GITIGNORE_FORBIDDEN_CHARS)
    ):
        raise EnvRemediationError(
            "motif .gitignore invalide : négation, commentaire ou métacaractère interdit"
        )

    if not is_rel_path(pattern):
        raise EnvRemediationError("motif .gitignore invalide : chemin relatif invalide")

    if not _is_env_like_path(pattern):
        raise EnvRemediationError("motif .gitignore invalide : fichier d'environnement attendu")

    return pattern


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


def _harden_default_file_mode(mode: int) -> int:
    """Retire les droits d'écriture groupe/monde des fichiers non sensibles.

    Un ``.env.example`` ou ``.gitignore`` préexistant en 0777 resterait
    modifiable par un autre utilisateur local (tampering). Les bits setuid,
    setgid et sticky sont également retirés. Si l'un de ces bits est présent,
    on retombe sur le mode par défaut 0644 ; sinon le mode existant est
    préservé.
    """
    if mode & 0o7022:
        return _DEFAULT_FILE_MODE
    return mode


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
        raw_names = list(itertools.islice(variables.keys(), _MAX_VARIABLES_COUNT + 1))
    elif isinstance(variables, Iterable):
        bounded_items: Iterable[str | tuple[str, str]] = itertools.islice(
            variables, _MAX_VARIABLES_COUNT + 1
        )
        for item in bounded_items:
            if isinstance(item, tuple):
                if len(item) != _SECRET_PAIR_LENGTH:
                    raise EnvRemediationError(
                        "format de tuple de variable invalide : attendu paire (clé, valeur)"
                    )
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


#: Identifiant snake_case documentaire court (ex. npm_install).
_LOWER_SNAKE_DOC_TOKEN: Final[re.Pattern[str]] = re.compile(r"^[a-z]{2,}(?:_[a-z]{2,})+$")

#: Séparateurs de mots alphabétiques documentaires (apostrophe ou tiret).
_PROSE_WORD_SPLIT: Final[re.Pattern[str]] = re.compile(r"['\-]")

#: Ponctuation de bord autorisée autour d'un mot de documentation.
_DOC_EDGE_PUNCTUATION: Final[str] = ".,:;!?()[]{}\"'"

#: Version ou date documentaire (ex. 1.2.3-beta+build.123) : jamais un secret.
_VERSION_LIKE_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"(?i)^v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.+-]+)?$"
)

#: URL complète, retirée avant le filet d'entropie pour ne pas purger la documentation.
_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{1,16}://\S+")

#: Userinfo d'URL (``https://user:pass@hôte`` ou ``https://<jeton>@hôte``).
_URL_USERINFO_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]{1,16}://(?P<userinfo>[^/@\s]+)@"
)

#: Longueur minimale d'un jeton nu pour le contrôle d'entropie.
_MIN_ENTROPY_TOKEN_LEN: Final[int] = 16

#: Seuil d'entropie de Shannon (bits/caractère), aligné sur le masquage central.
_COMMENT_ENTROPY_THRESHOLD: Final[float] = 3.5

#: Nombre minimal de mots pour qu'un commentaire nu soit considéré documentaire.
_MIN_DOC_COMMENT_WORDS: Final[int] = 2

#: Mots-clés évocateurs de secret pouvant précéder une valeur sans ':' ni '='.
_COMMENT_EVOCATIVE_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "secrets",
        "token",
        "tokens",
        "apikey",
        "api_key",
        "access_key",
        "private_key",
        "client_secret",
        "auth_token",
        "bearer",
        "credential",
        "credentials",
        "mdp",
        "mot_de_passe",
    }
)

#: Mots courants de prose documentaire (anglais/français) qui ne sont pas des secrets.
_PROSE_STOPWORDS: Final[frozenset[str]] = frozenset(
    {
        "a",
        "an",
        "the",
        "for",
        "is",
        "are",
        "was",
        "were",
        "be",
        "to",
        "of",
        "in",
        "on",
        "at",
        "by",
        "or",
        "and",
        "with",
        "from",
        "without",
        "not",
        "as",
        "if",
        "this",
        "that",
        "your",
        "our",
        "my",
        "un",
        "une",
        "le",
        "la",
        "les",
        "de",
        "du",
        "des",
        "au",
        "aux",
        "et",
        "ou",
        "pour",
        "est",
        "sont",
        "avec",
        "sans",
        "dans",
        "sur",
        "par",
        "ce",
        "cette",
        "votre",
        "notre",
        "mon",
        "should",
        "must",
        "can",
        "will",
        "needed",
        "required",
        "optional",
        "generated",
        "stored",
        "used",
        "set",
        "here",
        "below",
        "above",
        "doit",
        "requis",
        "requise",
        "optionnel",
        "optionnelle",
        "généré",
        "ici",
        "ci-dessous",
        "ci-dessus",
    }
)


def _is_safe_doc_token(token: str) -> bool:
    """Vrai uniquement si le jeton appartient à la grammaire documentaire allowlistée."""
    cleaned = token.strip(_DOC_EDGE_PUNCTUATION)
    if not cleaned:
        return False
    if _URL_PATTERN.fullmatch(cleaned) is not None:
        return True
    if _VERSION_LIKE_TOKEN.match(cleaned) is not None:
        return True
    if _LOWER_SNAKE_DOC_TOKEN.match(cleaned) is not None and len(cleaned) < _MIN_ENTROPY_TOKEN_LEN:
        return True

    parts = _PROSE_WORD_SPLIT.split(cleaned)
    if not all(part and part.isalpha() for part in parts):
        return False

    return not (
        len(cleaned) >= _MIN_ENTROPY_TOKEN_LEN
        and shannon_entropy(cleaned) >= _COMMENT_ENTROPY_THRESHOLD
    )


def _has_evocative_keyword_secret(without_urls: str) -> bool:
    """Vrai si un mot-clé évocateur de secret précède une valeur non documentaire."""
    words = without_urls.split()
    for idx, word in enumerate(words[:-1]):
        key = word.lower().strip(":=,-_()[]{}\"'")
        if key not in _COMMENT_EVOCATIVE_KEYWORDS:
            continue
        next_word = words[idx + 1].strip(",.;:()[]{}\"'")
        if next_word and "'" not in next_word and next_word.lower() not in _PROSE_STOPWORDS:
            return True
    return False


def _is_allowlisted_doc_comment(raw_line: str) -> bool:
    """Vrai uniquement pour un commentaire nu respectant la liste blanche documentaire.

    Sont purgés en ``# ***`` : les commentaires à un seul mot (ex. ``# hunter2``),
    les jetons alphanumériques/symboliques non documentaires, les jetons >= 16 car.
    à haute entropie, les userinfo d'URL, les motifs du masquage central et les
    mots-clés évocateurs suivis d'une valeur.

    Limite assumée : la prose alphabétique multi-mots courte (< 16 car./mot, sans
    ``=``, userinfo, préfixe connu ni mot-clé évocateur, ex. ``# my hunter``)
    n'est ni détectée, ni purgée, ni signalée dans ``plan_env_example_change``
    (elle est conservée par conception pour préserver la documentation).
    """
    stripped = raw_line.strip()
    if not stripped.startswith("#"):
        return False
    body = stripped.lstrip("#").strip()
    if not body or body == _MASKED_VALUE:
        return True
    if _URL_USERINFO_PATTERN.search(body):
        return False

    without_urls = _URL_PATTERN.sub(" ", body)
    if mask_text(without_urls)[1] > 0 or _has_evocative_keyword_secret(without_urls):
        return False

    words = body.split()
    if len(words) < _MIN_DOC_COMMENT_WORDS:
        return False

    return all(_is_safe_doc_token(word) for word in words)


def _comment_contains_potential_secret(raw_line: str) -> bool:
    """Détecte si un commentaire (# ...) doit être purgé (non allowlisté fail-closed)."""
    return not _is_allowlisted_doc_comment(raw_line)


def _sanitize_example_comment_line(raw_line: str, *, mask_values: bool) -> str:
    """Assainit une ligne de commentaire (# ...) dans .env.example.

    - Si la ligne contient '=', la valeur après '=' est purgée en NOM= (ou
      masquée en NOM=*** si mask_values est vrai).
    - Si la ligne est un commentaire nu sans '=' contenant un secret potentiel ou
      une valeur à haute entropie, elle est systématiquement purgée et masquée par '***'
      sur disque et dans les diffs (before et after) pour garantir l'invariant 8
      (zéro secret dans .env.example versionné ni dans les diffs affichés).
    - Les commentaires ordinaires en prose alphabétique multi-mots courte
      (sans secret détectable ni mot-clé évocateur) sont préservés par conception
      (non détectés et non signalés).
    """
    if "=" in raw_line:
        head, _, val = raw_line.partition("=")
        if not val.strip():
            return f"{head.rstrip()}="
        rendered_val = _MASKED_VALUE if mask_values else ""
        return f"{head.rstrip()}={rendered_val}"

    if _comment_contains_potential_secret(raw_line):
        prefix_len = len(raw_line) - len(raw_line.lstrip())
        indent = raw_line[:prefix_len]
        return f"{indent}# {_MASKED_VALUE}"

    return raw_line


def _build_sanitized_example_content(
    content: str,
    target_names: list[str],
    *,
    mask_values: bool = False,
) -> tuple[str, list[str]]:
    """Génère le contenu assaini de .env.example en purgeant toute valeur préexistante.

    INVARIANT DE SÉCURITÉ : .env.example ne contient JAMAIS de secret (invariant 8).
    Toute valeur préexistante (ex. NOM=secret, NOM="val", NOM=v # com) est purgée
    en NOM= sans valeur.
    Les nouvelles variables sont ajoutées à la suite sous forme NOM=.
    Si ``mask_values`` est vrai, une valeur préexistante non vide est remplacée
    par le marqueur constant ``***`` au lieu d'être supprimée : utilisé pour
    produire un ``before`` de diff qui ne révèle jamais le secret d'origine.
    Retourne le contenu assaini final et la liste des noms ajoutés ou modifiés
    (valeurs purgées), suivis des marqueurs ``#comment:<ligne>`` pour les
    commentaires assainis.
    """
    existing_keys: set[str] = set()
    modified_keys: list[str] = []
    purged_comments: list[str] = []
    new_lines: list[str] = []

    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            new_lines.append(raw_line)
            continue
        if stripped.startswith("#"):
            sanitized_comment = _sanitize_example_comment_line(raw_line, mask_values=mask_values)
            if sanitized_comment != raw_line:
                purged_comments.append(f"#comment:{len(new_lines) + 1}")
            new_lines.append(sanitized_comment)
            continue
        if "=" in stripped:
            key, _, val = stripped.partition("=")
            clean_key = key.strip()
            try:
                valid_key = validate_variable_name(clean_key)
            except (TemplateError, ValueError, TypeError):
                raise EnvRemediationError("clé invalide dans .env.example") from None
            existing_keys.add(valid_key)
            if val.strip():
                modified_keys.append(valid_key)
                rendered_value = _MASKED_VALUE if mask_values else ""
            else:
                rendered_value = ""
            new_lines.append(f"{valid_key}={rendered_value}")
        else:
            raise EnvRemediationError("ligne invalide dans .env.example : '=' attendu")

    added_keys: list[str] = []
    for k in target_names:
        if k not in existing_keys:
            existing_keys.add(k)
            new_lines.append(f"{k}=")
            added_keys.append(k)

    if not new_lines:
        return "", []

    new_content = "\n".join(new_lines) + "\n"
    return new_content, modified_keys + added_keys + purged_comments


def _pattern_matches_target(rule: str, target: str) -> bool:
    """Vérifie si une règle positive simple de gitignore correspond à la cible."""
    # Match exact : target ou /target (ex. config/.env ou /config/.env)
    if rule in (target, f"/{target}"):
        return True

    target_name = Path(target).name
    is_root = "/" not in target.strip("/")
    ends_with_dot_env = target_name == ".env" or target_name.endswith(".env")
    starts_with_dot_env = target_name.startswith(".env")

    # Règle ancrée à la racine (/...) : ne couvre JAMAIS une cible en sous-dossier
    if rule.startswith("/"):
        if not is_root:
            return False
        return (
            rule == f"/{target_name}"
            or (ends_with_dot_env and rule in ("/*.env", "/.env"))
            or (starts_with_dot_env and rule in ("/*.env*", "/.env*"))
        )

    # Règle non-ancrée (sans slash de tête) :
    return (
        rule == target_name
        or (rule == "*.env" and ends_with_dot_env)
        or (rule == ".env*" and starts_with_dot_env)
    )


def _is_env_covered_in_gitignore(content: str, pattern: str = ".env") -> bool:
    """Vérifie si une règle non commentée dans .gitignore couvre déjà le motif.

    Prend en compte l'ordre séquentiel des règles et les négations '!' :
    la dernière règle applicable l'emporte (sémantique gitignore conforme).
    """
    clean_target = pattern.strip() if isinstance(pattern, str) else ".env"
    if not clean_target:
        clean_target = ".env"

    covered = False
    for raw_line in content.splitlines():
        # Git ignore les espaces de fin non échappés, jamais les espaces/tabs de tête :
        # " .env" ou "\t.env" désigne littéralement un fichier nommé " .env" / "\t.env".
        line = raw_line.rstrip("\r\n").rstrip(" ")
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            negated = line[1:]
            if _pattern_matches_target(negated, clean_target):
                covered = False
        elif _pattern_matches_target(line, clean_target):
            covered = True
    return covered


def _write_text_atomic_checked(target: Path, content: str, mode: int) -> None:
    """Écrit atomiquement ``content`` sur ``target`` via EnvRemediationError."""
    try:
        write_file_atomic(target, content, mode=mode)
    except (ValueError, OSError):
        raise EnvRemediationError from None


def _prepare_gitignore_update(gitignore_file: Path, clean_pattern: str) -> tuple[str, int] | None:
    """Prépare en mémoire l'ajout idempotent de ``clean_pattern`` à ``.gitignore``.

    Retourne ``(nouveau_contenu, mode)`` si une mise à jour est nécessaire, ou ``None`` si
    le motif est déjà couvert.
    """
    existing_content = ""
    mode = _DEFAULT_FILE_MODE
    try:
        existing_content, mode = _read_text_secure(gitignore_file)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    mode = _harden_default_file_mode(mode)

    if _is_env_covered_in_gitignore(existing_content, pattern=clean_pattern):
        return None

    if existing_content and not existing_content.endswith("\n"):
        new_content = f"{existing_content}\n{clean_pattern}\n"
    elif existing_content:
        new_content = f"{existing_content}{clean_pattern}\n"
    else:
        new_content = f"{clean_pattern}\n"

    return new_content, mode


def ensure_gitignore_ignores_env(
    root: Path,
    gitignore_path: str = ".gitignore",
    pattern: str = ".env",
) -> bool:
    """Ajoute de façon idempotente la règle d'exclusion de .env dans .gitignore.

    - Confine gitignore_path sous root.
    - Valide strictement le motif pattern (refuse fail-closed '!', '*', etc.).
    - Si .gitignore existe, vérifie si une règle non commentée exclut déjà le motif
      en tenant compte des négations '!' et de l'ordre d'évaluation gitignore.
    - Si déjà couvert : retourne False sans modifier le fichier (idempotence stricte).
    - Si non couvert : ajoute '<pattern>\\n' (en préservant le contenu existant)
      et écrit atomiquement.
    - Retourne True si le fichier a été modifié ou créé.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")

    _validate_gitignore_path(gitignore_path)
    clean_pattern = _validate_gitignore_pattern(pattern)
    confined = _confine_and_check_no_symlink(root, gitignore_path, ".gitignore")

    prepared = _prepare_gitignore_update(confined.absolute, clean_pattern)
    if prepared is None:
        return False

    new_content, mode = prepared
    _write_text_atomic_checked(confined.absolute, new_content, mode)
    return True


def _prepare_env_example_update(
    example_file: Path, validated_names: list[str]
) -> tuple[str | None, int, list[str]]:
    """Prépare en mémoire la mise à jour assainie de ``.env.example``."""
    existing_content = ""
    mode = _DEFAULT_FILE_MODE
    try:
        existing_content, mode = _read_text_secure(example_file)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    mode = _harden_default_file_mode(mode)

    new_content, changed_names = _build_sanitized_example_content(existing_content, validated_names)
    if not changed_names and new_content == existing_content:
        return None, mode, []

    return new_content, mode, changed_names


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
    elle n'est pas dupliquée. L'ordre et les commentaires documentaires allowlistés
    sont préservés.

    Retourne la liste des noms ajoutés ou modifiés (valeurs purgées), suivis le cas
    échéant des marqueurs statiques de purge de commentaires (``#comment:<ligne>``).
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    _validate_env_like_path(example_path, ".env.example", expect_template=True)
    validated_names = _extract_and_validate_names(variables)
    confined = _confine_and_check_no_symlink(root, example_path, ".env.example")

    new_content, mode, changed_names = _prepare_env_example_update(
        confined.absolute, validated_names
    )
    if new_content is None:
        return []

    _write_text_atomic_checked(confined.absolute, new_content, mode)
    return changed_names


def _parse_env_strict(raw_content: str) -> dict[str, str]:
    """Parse le contenu brut d'un .env existant en mémoire avec validation stricte (anti-TOCTOU).

    Contrat fail-closed :
    - Ignore les lignes vides et les commentaires (#...).
    - Lève EnvRemediationError si une ligne non vide/non commentée ne contient pas '='.
    - Lève EnvRemediationError si la clé est vide ou invalide (denylist, syntaxe, export).
    - Décode la valeur via _decode_env_value.
    - Lève EnvRemediationError si la valeur contient un saut de ligne ou octet nul interdit.
    - Aucune seconde lecture disque nécessaire (anti-TOCTOU, I/O unique).
    """
    secrets: dict[str, str] = {}
    for raw_line in raw_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise EnvRemediationError("ligne invalide dans le fichier .env existant : '=' attendu")
        key_part, _, val_part = line.partition("=")
        clean_key = key_part.strip()
        if not clean_key:
            raise EnvRemediationError("ligne invalide dans le fichier .env existant : clé vide")
        try:
            valid_key = validate_variable_name(clean_key)
        except (TemplateError, ValueError, TypeError):
            raise EnvRemediationError("clé existante invalide ou dangereuse dans .env") from None

        decoded_val = _decode_env_value(val_part)
        if "\n" in decoded_val or "\r" in decoded_val or "\0" in decoded_val:
            raise EnvRemediationError(
                "valeur existante invalide dans .env : saut de ligne ou octet nul interdit"
            )
        secrets[valid_key] = decoded_val
    return secrets


parse_env_strict = _parse_env_strict


def _validate_secret_pair(item: object) -> tuple[str, str]:
    """Valide une paire (clé, valeur) de secret et retourne (clé_normalisée, valeur)."""
    if not isinstance(item, tuple) or len(item) != _SECRET_PAIR_LENGTH:
        raise EnvRemediationError("secret invalide : format attendu tuple (clé, valeur)")
    key, val = item
    if not isinstance(key, str) or not isinstance(val, str):
        raise EnvRemediationError("clé ou valeur de secret invalide (non-str)")
    if "\n" in val or "\r" in val or "\0" in val:
        raise EnvRemediationError("valeur de secret invalide : saut de ligne ou octet nul interdit")
    try:
        clean_key = validate_variable_name(key)
    except (TemplateError, ValueError, TypeError):
        raise EnvRemediationError("clé de secret invalide") from None
    return clean_key, val


def _validate_and_materialize_secrets(
    secrets: Mapping[str, str] | Iterable[tuple[str, str]],
) -> dict[str, str]:
    """Valide et matérialise de façon bornée les paires (clé, valeur) en mémoire."""
    if isinstance(secrets, (str, bytes)):
        raise EnvRemediationError(
            "secrets invalides : format attendu dictionnaire ou liste de paires"
        )

    if isinstance(secrets, Mapping):
        pairs = list(itertools.islice(secrets.items(), _MAX_VARIABLES_COUNT + 1))
    elif isinstance(secrets, Iterable):
        pairs = list(itertools.islice(secrets, _MAX_VARIABLES_COUNT + 1))
    else:
        raise EnvRemediationError("secrets invalides : type non supporté")

    if not pairs:
        raise EnvRemediationError("aucun secret fourni")

    if len(pairs) > _MAX_VARIABLES_COUNT:
        raise EnvRemediationError(f"trop de secrets : {len(pairs)} dépasse {_MAX_VARIABLES_COUNT}")

    validated_dict: dict[str, str] = {}
    total_chars = 0
    try:
        for item in pairs:
            clean_key, val = _validate_secret_pair(item)
            total_chars += len(val)
            if total_chars > _MAX_TOTAL_SECRET_CHARS:
                raise EnvRemediationError("volume total des secrets supérieur à 1 Mio")
            validated_dict[clean_key] = val
    except (ValueError, TypeError) as exc:
        raise EnvRemediationError("structure de secrets invalide") from exc

    return validated_dict


def _prepare_env_file_content(
    env_file: Path,
    validated_dict: dict[str, str],
) -> str:
    """Lit .env existant (lecture unique), fusionne et valide le volume final (<= 1 Mio)."""
    merged_secrets: dict[str, str] = {}
    if env_file.exists():
        if os.path.islink(env_file):
            raise EnvRemediationError("écriture refusée : .env est un lien symbolique")

        # Lecture unique : le contenu validé en mémoire est la seule source de
        # vérité. Aucune seconde lecture ne peut fusionner un snapshot divergent.
        raw_existing, _ = _read_text_secure(env_file)
        merged_secrets = _parse_env_strict(raw_existing)

    merged_secrets.update(validated_dict)

    # Vérification stricte du volume cumulé total après fusion (anti-DoS)
    total_merged_chars = sum(len(v) for v in merged_secrets.values())
    if total_merged_chars > _MAX_TOTAL_SECRET_CHARS:
        raise EnvRemediationError("volume total des secrets supérieur à 1 Mio")

    lines = [f"{k}={format_env_value(v)}" for k, v in merged_secrets.items()]
    content = "\n".join(lines) + "\n"

    if len(content.encode("utf-8")) > _MAX_READ_BYTES:
        raise EnvRemediationError("volume total des secrets supérieur à 1 Mio")

    return content


def _write_prepared_env_file(env_file: Path, content: str) -> Path:
    """Écrit atomiquement le contenu .env déjà préparé en mode 0600 et le vérifie."""
    _write_text_atomic_checked(env_file, content, _SECURE_ENV_MODE)

    if not check_file_mode_600(env_file):
        raise EnvRemediationError("permissions invalides : .env n'est pas en mode 0600")

    return env_file


def update_env_file(
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
    Les clés pré-existantes dans .env sont également re-validées (rejet fail-closed).
    Le volume total des secrets est borné à 1 Mio.

    Retourne le chemin absolu confiné du fichier écrit.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    _validate_env_like_path(env_path, ".env", expect_template=False)

    validated_dict = _validate_and_materialize_secrets(secrets)
    confined = _confine_and_check_no_symlink(root, env_path, ".env")
    content = _prepare_env_file_content(confined.absolute, validated_dict)
    return _write_prepared_env_file(confined.absolute, content)


def check_env_git_status(
    root: Path,
    env_path: str = ".env",
) -> tuple[bool, bool, str | None, str | None]:
    """Contrôle si .env est suivi ou ignoré par Git.

    Retourne un quadruplet :
    (is_tracked, is_ignored, warning_message, remediation_command)

    Si .env est suivi par Git (is_tracked == True) :
    - remediation_command = f"git rm --cached {shlex.quote(rel_path)}"
    - warning_message contient l'avertissement explicite.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    _validate_env_like_path(env_path, ".env", expect_template=False)
    confined = _confine_and_check_no_symlink(root, env_path, ".env")

    tracked = is_git_tracked(confined.absolute)
    ignored = is_git_ignored(confined.absolute)

    quoted_rel = shlex.quote(confined.relative)

    if tracked:
        cmd = f"git rm --cached {quoted_rel}"
        warn = (
            f"ATTENTION : Le fichier {quoted_rel} est suivi par Git ! "
            f"Exécutez '{cmd}' et ajoutez-le à .gitignore pour éviter toute fuite."
        )
        return True, ignored, warn, cmd

    if ignored:
        return False, True, None, None

    if _get_git_toplevel(confined.absolute) is None:
        warn = (
            f"Avertissement : statut Git indéterminé pour {quoted_rel} "
            "(hors dépôt ou git indisponible) : impossible de vérifier "
            "qu'il ne sera pas committé. Ajoutez-le à .gitignore et "
            "vérifiez avec 'git status'."
        )
        return False, False, warn, None

    warn = (
        f"Avertissement : Le fichier {quoted_rel} n'est pas ignoré par Git. "
        f"Pensez à ajouter {quoted_rel} dans .gitignore."
    )
    return False, False, warn, None


def plan_env_example_change(
    root: Path,
    variables: str | Iterable[str] | Mapping[str, str] | Iterable[tuple[str, str]],
    example_path: str = ".env.example",
) -> tuple[str, str, str] | None:
    """Calcule le diff (chemin_relatif, avant, après) pour .env.example sans modifier le disque.

    Utilisable par la CLI review pour construire un TextChange pour affichage diff.
    ``avant`` est toujours assaini : toute valeur préexistante est remplacée par
    le marqueur ``***`` (invariant 8), jamais exposée en clair dans le diff.
    Retourne None si aucun ajout ni purge ne modifie le fichier.
    """
    if not isinstance(root, Path):
        raise EnvRemediationError("racine invalide")
    _validate_env_like_path(example_path, ".env.example", expect_template=True)
    validated_names = _extract_and_validate_names(variables)
    confined = _confine_and_check_no_symlink(root, example_path, ".env.example")

    existing_content = ""
    try:
        existing_content, _ = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    after_content, changed_names = _build_sanitized_example_content(
        existing_content, validated_names
    )

    if not changed_names and after_content == existing_content:
        return None

    # Invariant 8 : le diff ne doit jamais exposer une valeur préexistante.
    # ``before`` est donc assaini et les valeurs polluées sont remplacées par
    # un marqueur constant, jamais par leur contenu réel.
    before_content, _ = _build_sanitized_example_content(existing_content, [], mask_values=True)

    return confined.relative, before_content, after_content


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

    _validate_gitignore_path(gitignore_path)
    clean_pattern = _validate_gitignore_pattern(pattern)
    confined = _confine_and_check_no_symlink(root, gitignore_path, ".gitignore")

    existing_content = ""
    try:
        existing_content, _ = _read_text_secure(confined.absolute)
    except FileNotFoundError:
        pass
    except EnvRemediationError:
        raise

    if _is_env_covered_in_gitignore(existing_content, pattern=clean_pattern):
        return None

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
    if not isinstance(env_path, str):
        raise EnvRemediationError("chemin env invalide (non-str)")
    if not isinstance(example_path, str):
        raise EnvRemediationError("chemin exemple invalide (non-str)")
    if not isinstance(gitignore_path, str):
        raise EnvRemediationError("chemin gitignore invalide (non-str)")

    _validate_env_like_path(env_path, ".env", expect_template=False)
    _validate_env_like_path(example_path, ".env.example", expect_template=True)
    _validate_gitignore_path(gitignore_path)

    confined_env = _confine_and_check_no_symlink(root, env_path, ".env")
    confined_example = _confine_and_check_no_symlink(root, example_path, ".env.example")
    confined_gitignore = _confine_and_check_no_symlink(root, gitignore_path, ".gitignore")

    env_paths = (
        confined_env.relative,
        confined_example.relative,
        confined_gitignore.relative,
    )
    if len(set(env_paths)) != len(env_paths):
        raise EnvRemediationError("chemins d'environnement confondus")

    # Validation complète des noms, valeurs (\n/\r/\0), bornes et relecture/fusion
    # des fichiers pré-existants EN MÉMOIRE AVANT toute écriture disque :
    # si .env ou .env.example ou .gitignore échoue (syntaxe invalide, quota > 1 Mio),
    # aucun des trois fichiers n'est créé ni modifié.
    validated_secrets = _validate_and_materialize_secrets(secrets)
    clean_pattern = _validate_gitignore_pattern(confined_env.relative)

    prepared_example_content, example_mode, added_to_example = _prepare_env_example_update(
        confined_example.absolute, list(validated_secrets.keys())
    )
    prepared_env_content = _prepare_env_file_content(confined_env.absolute, validated_secrets)
    prepared_gitignore = _prepare_gitignore_update(confined_gitignore.absolute, clean_pattern)

    # 1. Mise à jour de .env.example (valeurs vides obligatoires)
    if prepared_example_content is not None:
        _write_text_atomic_checked(
            confined_example.absolute, prepared_example_content, example_mode
        )

    # 2. Mise à jour ou création de .env en mode 0600
    _write_prepared_env_file(confined_env.absolute, prepared_env_content)

    # 3. Ajout de .env au .gitignore si absent (idempotent)
    gitignore_updated = False
    if prepared_gitignore is not None:
        gitignore_content, gitignore_mode = prepared_gitignore
        _write_text_atomic_checked(confined_gitignore.absolute, gitignore_content, gitignore_mode)
        gitignore_updated = True

    # 4. Contrôle du suivi Git de .env
    tracked, ignored, warn, rm_cmd = check_env_git_status(root, env_path=env_path)
    if warn_stderr and warn:
        sys.stderr.write(warn + "\n")
        warnings.warn(warn, UserWarning, stacklevel=2)

    all_names = list(validated_secrets.keys())

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
