"""Allowlist déterministe du scanner de secrets (#24).

Permet d'écarter les cas évidents (example, changeme, dummy, fixtures de test)
sans passer par le LLM, de façon 100 % déterministe, traçable et auditable.
Fonctionne aussi bien en mode local qu'en mode CI headless.

Invariants de sécurité :
- Traçabilité totale (critère d'acceptation) : aucun rejet sans règle nommée.
  Chaque rejet émet une trace contenant exactement : règle, fichier, ligne.
- Confidentialité (invariant 8) : aucun secret ou extrait de secret n'est
  jamais reflété dans les traces, les journaux ou les rapports.
- Confinement strict (CWE-22) : le fichier de configuration et les motifs
  de chemins ne peuvent pas traverser hors du dépôt (refus des `..`, des
  liens symboliques et des chemins absolus).
- Anti-DDoS / Anti-ReDoS (CWE-400, CWE-1333) : la taille du fichier TOML
  est plafonnée (64 Kio), le nombre de règles et de motifs est borné,
  et les regex sont vérifiées contre les quantificateurs imbriqués.
- Fail-closed (REQ-SEC-07) : toute configuration invalide, corrompue,
  inconnue ou inaccessible lève ``ScanError`` (code 2), jamais un passage
  silencieux.
- Piège évité : aucun allowlist aveugle de `tests/` ; un vrai secret placé
  dans un fichier de test reste détecté s'il ne correspond pas à une règle
  spécifique de valeurs factices.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import MAX_PATH_LENGTH

logger = logging.getLogger("heimdall.scanner.allowlist")

#: Plafond de taille du fichier de configuration en octets (64 Kio).
MAX_CONFIG_BYTES: Final[int] = 65_536

#: Plafonds de complexité pour prévenir les abus de configuration.
MAX_RULES: Final[int] = 100
MAX_ITEMS_PER_RULE: Final[int] = 50
MAX_PATTERN_LENGTH: Final[int] = 256
MAX_RULE_NAME_LENGTH: Final[int] = 64
MAX_DESCRIPTION_LENGTH: Final[int] = 512

#: Validation stricte de l'identifiant de règle (nom ASCII sécurisé).
_RULE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

#: Détection basique de motifs regex à risque de backtracking catastrophique.
_REDOS_DANGEROUS_RE: Final[re.Pattern[str]] = re.compile(
    r"(\([^)]*[+*]\)[+*]|\.[+*]\.[+*]|\\[wdDsS][+*]\\[wdDsS][+*])"
)

_CONFIG_ERROR: Final[str] = "configuration allowlist invalide"


@dataclass(frozen=True, slots=True)
class AllowlistTrace:
    """Trace déterministe d'un rejet par l'allowlist (#24).

    Ne contient JAMAIS la valeur candidate : seulement la règle qui a décidé
    du rejet, le chemin du fichier et le numéro de ligne.
    """

    rule: str
    file: str
    line: int

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not self.rule:
            raise ValueError("nom de règle invalide pour la trace")
        if not isinstance(self.file, str) or not self.file:
            raise ValueError("chemin de fichier invalide pour la trace")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("numéro de ligne invalide pour la trace")

    def as_dict(self) -> dict[str, object]:
        return {"rule": self.rule, "file": self.file, "line": self.line}


@dataclass(frozen=True, slots=True)
class AllowlistRule:
    """Règle nommée et auditable d'allowlist (#24).

    Une règle est constituée d'un nom unique, d'une description et d'au moins
    un critère de correspondance parmi :
    - `keywords` : sous-chaînes insensibles à la casse (ex. 'example', 'dummy')
    - `patterns` : expressions régulières compilées linéaires
    - `paths` : motifs glob POSIX relatifs (ex. 'tests/**', '*_test.py')
    - `secret_types` : types de secrets restreints (ex. 'aws', 'stripe')
    - `hashes` : empreintes HMAC-SHA-256 exactes autorisées
    """

    name: str
    description: str
    keywords: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    paths: tuple[str, ...] = ()
    secret_types: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _RULE_NAME_RE.fullmatch(self.name):
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.description, str) or not self.description:
            raise ScanError(_CONFIG_ERROR)
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            raise ScanError(_CONFIG_ERROR)

        has_criteria = bool(
            self.keywords or self.patterns or self.paths or self.secret_types or self.hashes
        )
        if not has_criteria:
            raise ScanError(_CONFIG_ERROR)

    def matches(  # noqa: PLR0913
        self,
        *,
        value: str,
        file_path: str,
        line_number: int,
        secret_type: str,
        line_text: str = "",
        snippet_hash: str = "",
    ) -> bool:
        """Détermine si un candidat satisfait tous les critères de la règle."""
        # 1. Filtre par chemin (si spécifié)
        if self.paths:
            path_matched = any(
                fnmatch.fnmatch(file_path, pattern)
                or PurePosixPath(file_path).match(pattern)
                for pattern in self.paths
            )
            if not path_matched:
                return False

        # 2. Filtre par type de secret (si spécifié)
        if self.secret_types and secret_type not in self.secret_types:
            return False

        # 3. Filtre par empreinte HMAC exacte (si spécifiée)
        if self.hashes and snippet_hash not in self.hashes:
            return False

        # 4. Si la règle n'a ni keywords ni patterns, le filtre chemin/type/hash suffit
        if not self.keywords and not self.patterns:
            return True

        # 5. Filtre par keywords et patterns
        val_cf = value.casefold()
        line_cf = line_text.casefold()
        kw_match = bool(
            self.keywords
            and any(
                kw.casefold() in val_cf or (line_cf and kw.casefold() in line_cf)
                for kw in self.keywords
            )
        )
        pat_match = bool(
            self.patterns
            and any(
                pattern.search(value) or (line_text and pattern.search(line_text))
                for pattern in self.patterns
            )
        )
        return kw_match or pat_match


class Allowlist:
    """Moteur d'allowlist déterministe (#24).

    Applique une séquence ordonnée de règles nommées. Émet une trace
    structurée pour chaque candidat rejeté.
    """

    __slots__ = ("_rules", "_rules_by_name")

    def __init__(self, rules: Sequence[AllowlistRule] = ()) -> None:
        names: set[str] = set()
        validated: list[AllowlistRule] = []
        for rule in rules:
            if not isinstance(rule, AllowlistRule):
                raise ScanError(_CONFIG_ERROR)
            if rule.name in names:
                raise ScanError(_CONFIG_ERROR)
            names.add(rule.name)
            validated.append(rule)
        self._rules: tuple[AllowlistRule, ...] = tuple(validated)
        self._rules_by_name: dict[str, AllowlistRule] = {r.name: r for r in self._rules}

    @property
    def rules(self) -> tuple[AllowlistRule, ...]:
        return self._rules

    def is_empty(self) -> bool:
        return len(self._rules) == 0

    def evaluate(  # noqa: PLR0913
        self,
        *,
        value: str,
        file: str,
        line: int,
        secret_type: str,
        line_text: str = "",
        snippet_hash: str = "",
    ) -> str | None:
        """Évalue un candidat et retourne le nom de la règle si rejeté, sinon None."""
        for rule in self._rules:
            if rule.matches(
                value=value,
                file_path=file,
                line_number=line,
                secret_type=secret_type,
                line_text=line_text,
                snippet_hash=snippet_hash,
            ):
                logger.info(
                    "rejet allowlist : règle '%s' sur %s:%d (type=%s)",
                    rule.name,
                    file,
                    line,
                    secret_type,
                )
                return rule.name
        return None

    @classmethod
    def empty(cls) -> Allowlist:
        """Allowlist vide : aucun candidat n'est ignoré."""
        return cls(())

    @classmethod
    def default(cls) -> Allowlist:
        """Allowlist par défaut contenant les 4 règles standard (#24)."""
        return cls(create_default_rules())


def create_default_rules() -> tuple[AllowlistRule, ...]:
    """Crée les règles déterministes par défaut demandées par le ticket #24 :

    - example : mots-clés et jetons d'exemple (example, sample, your_key_here)
    - changeme : mots de passe ou secrets par défaut changeme
    - dummy : valeurs et jetons factices dummy
    - test-fixtures : fixtures et valeurs factices explicites dans tests/
    """
    return (
        AllowlistRule(
            name="example-placeholders",
            description="Mots-clés et jetons d'exemple (example, sample, your_key_here)",
            keywords=("example", "sample", "your_key_here"),
        ),
        AllowlistRule(
            name="changeme-passwords",
            description="Mots de passe ou secrets par défaut changeme",
            keywords=("changeme",),
        ),
        AllowlistRule(
            name="dummy-tokens",
            description="Valeurs et jetons factices dummy",
            keywords=("dummy",),
        ),
        AllowlistRule(
            name="test-fixtures",
            description="Valeurs factices et corpus délimités dans les tests",
            paths=("tests/**", "*_test.py", "test_*.py", "**/fixtures/**", "**/support/**"),
            keywords=(
                "test",
                "fake",
                "mock",
                "dummy",
                "placeholder",
                "synthetic",
                "factice",
                "fixture",
                "expected",
                "invalid",
            ),
        ),
    )


def _validate_path_pattern(pattern: str) -> str:
    """Valide qu'un motif de chemin est relatif et sans traversée."""
    if not isinstance(pattern, str) or not pattern:
        raise ScanError(_CONFIG_ERROR)
    if len(pattern) > MAX_PATH_LENGTH:
        raise ScanError(_CONFIG_ERROR)
    if "\x00" in pattern or "\r" in pattern or "\n" in pattern:
        raise ScanError(_CONFIG_ERROR)
    if pattern.startswith("/") or pattern.startswith("\\"):
        raise ScanError(_CONFIG_ERROR)
    parts = pattern.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        raise ScanError(_CONFIG_ERROR)
    return pattern


def _compile_safe_regex(raw: str) -> re.Pattern[str]:
    """Compile une regex avec vérification anti-ReDoS élémentaire."""
    if not isinstance(raw, str) or not raw:
        raise ScanError(_CONFIG_ERROR)
    if len(raw) > MAX_PATTERN_LENGTH:
        raise ScanError(_CONFIG_ERROR)
    if _REDOS_DANGEROUS_RE.search(raw):
        raise ScanError(_CONFIG_ERROR)
    try:
        return re.compile(raw)
    except re.error:
        raise ScanError(_CONFIG_ERROR) from None


_ALLOWED_RULE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "name",
        "description",
        "keywords",
        "patterns",
        "paths",
        "secret_types",
        "hashes",
    }
)


def _parse_str_list(raw_dict: dict[str, object], field: str) -> tuple[str, ...]:
    items = raw_dict.get(field, [])
    if not isinstance(items, list):
        raise ScanError(_CONFIG_ERROR)
    if len(items) > MAX_ITEMS_PER_RULE:
        raise ScanError(_CONFIG_ERROR)
    res: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item or len(item) > MAX_PATTERN_LENGTH:
            raise ScanError(_CONFIG_ERROR)
        res.append(item)
    return tuple(res)


def _parse_rule_dict(raw_rule: object) -> AllowlistRule:
    if not isinstance(raw_rule, dict):
        raise ScanError(_CONFIG_ERROR)
    if not set(raw_rule.keys()).issubset(_ALLOWED_RULE_KEYS):
        raise ScanError(_CONFIG_ERROR)

    name = raw_rule.get("name")
    description = raw_rule.get("description", "")
    if not isinstance(name, str) or not isinstance(description, str):
        raise ScanError(_CONFIG_ERROR)

    keywords = _parse_str_list(raw_rule, "keywords")
    secret_types = _parse_str_list(raw_rule, "secret_types")
    hashes = _parse_str_list(raw_rule, "hashes")

    raw_paths = raw_rule.get("paths", [])
    if not isinstance(raw_paths, list) or len(raw_paths) > MAX_ITEMS_PER_RULE:
        raise ScanError(_CONFIG_ERROR)
    paths = tuple(_validate_path_pattern(p) for p in raw_paths)

    raw_patterns = raw_rule.get("patterns", [])
    if not isinstance(raw_patterns, list) or len(raw_patterns) > MAX_ITEMS_PER_RULE:
        raise ScanError(_CONFIG_ERROR)
    patterns = tuple(_compile_safe_regex(p) for p in raw_patterns)

    return AllowlistRule(
        name=name,
        description=description,
        keywords=keywords,
        patterns=patterns,
        paths=paths,
        secret_types=secret_types,
        hashes=hashes,
    )


def parse_allowlist_toml(content: str) -> Allowlist:
    """Parse et valide le document TOML d'allowlist."""
    try:
        data = tomllib.loads(content)
    except Exception:
        raise ScanError(_CONFIG_ERROR) from None

    if not isinstance(data, dict):
        raise ScanError(_CONFIG_ERROR)

    allowlist_table = data.get("allowlist")
    if not isinstance(allowlist_table, dict):
        raise ScanError(_CONFIG_ERROR)

    # Vérification des clés de la table [allowlist]
    allowed_allowlist_keys = {"version", "rules"}
    if not set(allowlist_table.keys()).issubset(allowed_allowlist_keys):
        raise ScanError(_CONFIG_ERROR)

    version = allowlist_table.get("version", "1")
    if str(version) != "1":
        raise ScanError(_CONFIG_ERROR)

    raw_rules = allowlist_table.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ScanError(_CONFIG_ERROR)
    if len(raw_rules) > MAX_RULES:
        raise ScanError(_CONFIG_ERROR)

    rules = [_parse_rule_dict(raw) for raw in raw_rules]
    return Allowlist(rules)


def load_allowlist_from_file(config_path: Path, *, repo_root: Path | None = None) -> Allowlist:
    """Charge l'allowlist depuis un fichier TOML en appliquant les contrôles de sécurité.

    - Vérification anti-symlink (sur le fichier ET ses répertoires ancêtres)
    - Confinement sous repo_root si fourni
    - Plafond de taille borné (MAX_CONFIG_BYTES)
    - Décodage strict UTF-8
    """
    try:
        if not config_path.exists():
            raise ScanError(_CONFIG_ERROR)

        # Vérification des liens symboliques
        if config_path.is_symlink():
            raise ScanError(_CONFIG_ERROR)
        for parent in config_path.parents:
            if parent.is_symlink():
                raise ScanError(_CONFIG_ERROR)

        resolved = config_path.resolve(strict=True)
        if repo_root is not None:
            resolved_root = repo_root.resolve(strict=True)
            if not resolved.is_relative_to(resolved_root):
                raise ScanError(_CONFIG_ERROR)

        file_stat = os.stat(config_path, follow_symlinks=False)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ScanError(_CONFIG_ERROR)
        if file_stat.st_size > MAX_CONFIG_BYTES:
            raise ScanError(_CONFIG_ERROR)

        raw_bytes = config_path.read_bytes()
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ScanError(_CONFIG_ERROR) from None

        return parse_allowlist_toml(content)
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, ScanError):
            raise
        raise ScanError(_CONFIG_ERROR) from None


def load_allowlist(root: Path, config_file: str | Path | None = None) -> Allowlist:
    """Charge la configuration d'allowlist pour la racine d'un dépôt.

    Si `config_file` est fourni, ce fichier spécifique est chargé (fail-closed s'il
    est invalide ou manquant).
    Si `config_file` n'est pas fourni, recherche `heimdall.toml` à la racine de `root`.
    Si `heimdall.toml` n'existe pas, retourne une Allowlist vide.
    """
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ScanError(_CONFIG_ERROR) from None

    if config_file is not None:
        target = Path(config_file)
        if not target.is_absolute():
            target = resolved_root / target
        return load_allowlist_from_file(target, repo_root=resolved_root)

    default_config = resolved_root / "heimdall.toml"
    try:
        if not default_config.is_file() or default_config.is_symlink():
            return Allowlist.empty()
    except OSError:
        return Allowlist.empty()

    return load_allowlist_from_file(default_config, repo_root=resolved_root)


__all__ = [
    "MAX_CONFIG_BYTES",
    "Allowlist",
    "AllowlistRule",
    "AllowlistTrace",
    "create_default_rules",
    "load_allowlist",
    "load_allowlist_from_file",
    "parse_allowlist_toml",
]
