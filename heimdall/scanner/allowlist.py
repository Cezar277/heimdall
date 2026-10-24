"""Allowlist déterministe du scanner de secrets (#24).

Permet d'écarter les cas évidents (example, changeme, dummy, fixtures de test)
sans passer par le LLM, de façon 100 % déterministe, traçable et auditable.
Fonctionne aussi bien en mode local qu'en mode CI headless.

Invariants de sécurité :
- Traçabilité totale (critère d'acceptation) : aucun rejet sans règle nommée.
  Chaque rejet émet une trace contenant exactement : règle, fichier, ligne.
- Confidentialité (invariant 8) : aucun secret ou extrait de secret n'est
  jamais reflété dans les traces, les journaux ou les rapports.
- Absence de contournement par commentaire (invariant 1) : les mots-clés et
  motifs ne sont évalués que sur la valeur candidate du secret, JAMAIS sur le
  texte complet de la ligne.
- Confinement strict (CWE-22) : le fichier de configuration et les motifs
  de chemins ne peuvent pas traverser hors du dépôt (refus des `..`, des
  liens symboliques et des chemins absolus via la garde centrale `_resolve_root`).
- Anti-DDoS / Anti-ReDoS (CWE-400, CWE-1333) : la taille du fichier TOML
  est plafonnée (64 Kio), le nombre de règles et de motifs est borné,
  et les regex sont vérifiées contre toute alternance ou répétition imbriquée.
- Fail-closed (REQ-SEC-07) : toute configuration invalide, corrompue,
  inconnue ou inaccessible lève ``ScanError`` (code 2), jamais un passage
  silencieux.
- Anti auto-attestation (CWE-345) : une modification de `heimdall.toml` dans
  les changements scannés en CI/staged est refusée loud (code 2).
- Piège évité (CWE-1188) : aucun allowlist aveugle de `tests/` ; un vrai secret
  placé dans un fichier de test reste détecté s'il ne correspond pas à une règle
  spécifique de valeurs factices.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import validate_relative_path
from heimdall.scanner.interface import _open_flags, _resolve_root

logger = logging.getLogger("heimdall.scanner.allowlist")

#: Plafond de taille du fichier de configuration en octets (64 Kio).
MAX_CONFIG_BYTES: Final[int] = 65_536

#: Plafonds de complexité pour prévenir les abus de configuration.
MAX_RULES: Final[int] = 100
MAX_ITEMS_PER_RULE: Final[int] = 50
MAX_PATTERN_LENGTH: Final[int] = 128
MAX_RULE_NAME_LENGTH: Final[int] = 64
MAX_DESCRIPTION_LENGTH: Final[int] = 512

#: Longueur minimale d'un mot-clé d'allowlist. Un mot-clé d'une ou deux
#: lettres est trop large pour être auditable : avec la frontière `\b`
#: stricte, `keywords = ["a"]` ignorerait toute valeur contenant le mot
#: `a` seul. La validation s'applique aux configurations TOML ; l'API
#: Python reste libre de construire des règles de test explicites.
MIN_KEYWORD_LENGTH: Final[int] = 3

#: Validation stricte de l'identifiant de règle (nom ASCII sécurisé).
_RULE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

#: Détection rigoureuse de constructions regex à risque de backtracking catastrophique (CWE-1333).
#: Interdit :
#: 1. L'alternance sous quantificateur : `(a|b)+`, `(a|aa)+`, `(a|b)?`, `(a|b){2,}`
#: 2. Les wildcards ou classes quantifiées sous quantificateur : `(.*a)+`, `(\w+)+`, `(a?)+`
#: 3. La double quantification imbriquée : `(a+)+`, `(a?)+`
#: 4. Les quantificateurs consécutifs : `a++`, `a**`, `a??`
#: 5. Les quantificateurs lazy : `*?`, `+?`, `??`
#: 6. Les quantificateurs répétés sur le même atome : `a*a*`, `a?a?`, `.*.*`
#: 7. Les classes de caractères quantifiées consécutives : `\d+\d+`, `\w+\w+`, `\s?\s?`
#: 8. Les classes entre crochets quantifiées consécutives : `[0-9]+[0-9]+`
_QUANT: Final[str] = r"(?:[*+?]|\{\d+,?\d*\})\??"
_REDOS_DANGEROUS_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\([^)]*\|[^)]*\)\s*" + _QUANT),
    re.compile(r"\([^)]*" + _QUANT + r"[^)]*\)\s*" + _QUANT),
    re.compile(r"[*+?]\?"),
    re.compile(r"[*+?]{2,}"),
    re.compile(r"(.)" + _QUANT + r"\s*\1" + _QUANT),
    re.compile(r"\\[dDwWsS]" + _QUANT + r"\s*\\[dDwWsS]" + _QUANT),
    re.compile(r"\[[^\]]+\]" + _QUANT + r"\s*\[[^\]]+\]" + _QUANT),
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


def _keyword_matches_value(kw: str, value: str) -> bool:
    """Vérifie si un mot-clé correspond à la valeur du secret (Invariant 1).

    Pour éviter tout faux négatif sur un secret réel de production contenant
    un mot-clé comme sous-chaîne (ex: mot de passe 'dummyP@ssw0rd!' ou
    'prod_fake_token_123', ou 'myexample'), la correspondance exige :
    - Soit l'égalité exacte insensible à la casse (ex: 'changeme', 'your_key_here')
    - Soit une frontière de mot complète '\\b' (ex: '\\bdummy\\b', '\\bfake\\b', 'admin:changeme')

    La frontière est **stricte dans tous les cas**, y compris pour une règle
    restreinte par chemin (`tests/**`). `_` est un caractère de mot pour
    `\\b` : 'fake_slack_token' ou 'my_dummy_key' ne sont donc PAS des fixtures
    et restent signalés. Un séparateur non-mot ('fake-token') ou une valeur
    exacte ('dummy') reste reconnu. Ce choix privilégie l'invariant 1
    (doute → signalé) sur la disponibilité d'une allowlist de tests.
    """
    kw_cf = kw.casefold()
    val_cf = value.casefold()
    return val_cf == kw_cf or re.search(rf"\b{re.escape(kw_cf)}\b", val_cf) is not None


@dataclass(frozen=True, slots=True)
class AllowlistRule:
    """Règle nommée et auditable d'allowlist (#24).

    Une règle est constituée d'un nom unique, d'une description et d'au moins
    un critère sur la valeur du candidat parmi :
    - `keywords` : sous-chaînes/mots entiers sur la valeur du secret (ex. 'example', 'dummy')
    - `patterns` : expressions régulières compilées linéaires sur la valeur

    Les critères de restriction facultatifs (en conjonction avec keywords/patterns) sont :
    - `paths` : motifs glob POSIX relatifs (évalués via `fnmatch`)
    - `secret_types` : types de secrets restreints (ex. 'aws', 'stripe')

    Les mots-clés sont toujours comparés avec une frontière `\\b` stricte :
    `paths` ne transforme jamais `_` en séparateur (voir
    :func:`_keyword_matches_value`).
    """

    name: str
    description: str
    keywords: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    paths: tuple[str, ...] = ()
    secret_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _RULE_NAME_RE.fullmatch(self.name):
            raise ScanError(_CONFIG_ERROR)
        if len(self.name) > MAX_RULE_NAME_LENGTH:
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.description, str) or not self.description:
            raise ScanError(_CONFIG_ERROR)
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            raise ScanError(_CONFIG_ERROR)

        # Invariant 1 / Sécurité : toute règle DOIT obligatoirement définir au moins
        # un critère sur la valeur (keywords ou patterns). Les filtres paths ou
        # secret_types ne peuvent JAMAIS constituer une règle aveugle à eux seuls.
        if not self.keywords and not self.patterns:
            raise ScanError(_CONFIG_ERROR)

    def matches(
        self,
        *,
        value: str,
        file_path: str,
        line_number: int,
        secret_type: str,
    ) -> bool:
        """Détermine si un candidat satisfait tous les critères de la règle.

        Important (sécurité) : les mots-clés et patterns ne sont vérifiés
        QUE sur `value` (le secret candidat).
        """
        # 1. Filtre par chemin (si spécifié) — moteur unique fnmatch documenté
        if self.paths:
            path_matched = any(
                fnmatch.fnmatch(file_path, pattern)
                for pattern in self.paths
            )
            if not path_matched:
                return False

        # 2. Filtre par type de secret (si spécifié)
        if self.secret_types and secret_type not in self.secret_types:
            return False

        # 3. Filtre par keywords et patterns — SUR VALUE UNIQUEMENT avec frontières de mots
        kw_match = bool(
            self.keywords
            and any(_keyword_matches_value(kw, value) for kw in self.keywords)
        )
        pat_match = bool(
            self.patterns and any(pattern.search(value) for pattern in self.patterns)
        )
        return kw_match or pat_match


class Allowlist:
    """Moteur d'allowlist déterministe (#24).

    Applique une séquence ordonnée de règles nommées. Émet une trace
    structurée pour chaque candidat rejeté.
    """

    __slots__ = ("_rules", "_rules_by_name", "_sha256")

    def __init__(
        self,
        rules: Sequence[AllowlistRule] = (),
        *,
        sha256: str | None = None,
    ) -> None:
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
        self._sha256 = sha256

    @property
    def rules(self) -> tuple[AllowlistRule, ...]:
        return self._rules

    @property
    def sha256(self) -> str | None:
        """Empreinte SHA-256 du fichier de configuration ayant produit cette allowlist."""
        return self._sha256

    def is_empty(self) -> bool:
        return len(self._rules) == 0

    def evaluate(
        self,
        *,
        value: str,
        file: str,
        line: int,
        secret_type: str,
    ) -> str | None:
        """Évalue un candidat et retourne le nom de la règle si rejeté, sinon None."""
        for rule in self._rules:
            if rule.matches(
                value=value,
                file_path=file,
                line_number=line,
                secret_type=secret_type,
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
        return cls((), sha256=None)

    @classmethod
    def default(cls) -> Allowlist:
        """Allowlist par défaut contenant les 4 règles standard (#24).

        Cette méthode de fabrique est réservée aux tests et à l'API Python
        programmatique ; en usage CLI / CI, l'allowlist est chargée depuis la
        configuration TOML auditée (`load_allowlist`). Sans `heimdall.toml`,
        `load_allowlist` retourne volontairement `Allowlist.empty()` : aucune
        règle implicite ne s'applique au verdict.
        """
        return cls(create_default_rules(), sha256=None)


#: Fabrique de commodité (tests/API). Elle n'est pas branchée sur le
#: chargement CLI/CI : la configuration versionnée `heimdall.toml` reste la
#: seule source d'allowlist opposable, et l'absence de fichier vaut vide.
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
            description="Mots-clés et jetons d'exemple (AKIAIOSFODNN7EXAMPLE, example, sample)",
            keywords=("AKIAIOSFODNN7EXAMPLE", "example", "sample", "your_key_here"),
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
            description=(
                "Valeurs factices et fixtures délimitées dans les tests "
                "(frontière \\b stricte : 'fake_slack_token' reste signalé)"
            ),
            paths=("tests/**", "fixtures/**", "**/fixtures/**", "support/**", "**/support/**"),
            keywords=(
                "fake",
                "mock",
                "dummy",
                "placeholder",
                "synthetic",
                "factice",
                "fixture",
            ),
        ),
    )


def _validate_path_pattern(pattern: str) -> str:
    """Valide un motif de chemin selon la grammaire du contrat Finding #14.

    Un motif est un chemin relatif POSIX : pas de traversée (`..`), pas
    d'absolu, pas de lecteur Windows (`C:`), pas d'antislash, pas de NUL ou
    de caractère de contrôle, pas de segment vide. Les métacaractères glob
    (`*`, `?`, `[...]`) restent autorisés.
    """
    try:
        validate_relative_path(pattern)
    except ValueError:
        raise ScanError(_CONFIG_ERROR) from None
    return pattern


def _compile_safe_regex(raw: str) -> re.Pattern[str]:
    """Compile une regex avec vérification anti-ReDoS élémentaire (CWE-1333)."""
    if not isinstance(raw, str) or not raw:
        raise ScanError(_CONFIG_ERROR)
    if len(raw) > MAX_PATTERN_LENGTH:
        raise ScanError(_CONFIG_ERROR)
    if "\x00" in raw:
        raise ScanError(_CONFIG_ERROR)
    for dangerous in _REDOS_DANGEROUS_PATTERNS:
        if dangerous.search(raw):
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
    }
)


def _parse_str_list(
    raw_dict: dict[str, object],
    field: str,
    *,
    min_length: int = 1,
) -> tuple[str, ...]:
    items = raw_dict.get(field, [])
    if not isinstance(items, list):
        raise ScanError(_CONFIG_ERROR)
    if len(items) > MAX_ITEMS_PER_RULE:
        raise ScanError(_CONFIG_ERROR)
    res: list[str] = []
    for item in items:
        if (
            not isinstance(item, str)
            or len(item) < min_length
            or len(item) > MAX_PATTERN_LENGTH
        ):
            raise ScanError(_CONFIG_ERROR)
        if "\x00" in item:
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

    keywords = _parse_str_list(
        raw_rule,
        "keywords",
        min_length=MIN_KEYWORD_LENGTH,
    )
    secret_types = _parse_str_list(raw_rule, "secret_types")

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
    )


def parse_allowlist_toml(content: str, *, sha256: str | None = None) -> Allowlist:
    """Parse et valide le document TOML d'allowlist."""
    try:
        data = tomllib.loads(content)
    except Exception:
        raise ScanError(_CONFIG_ERROR) from None

    if not isinstance(data, dict):
        raise ScanError(_CONFIG_ERROR)

    # Contrat fermé au premier niveau : une faute de frappe (`[tool.foo]`,
    # `[allowlistt]`) doit échouer loud, pas être ignorée silencieusement.
    if set(data.keys()) != {"allowlist"}:
        raise ScanError(_CONFIG_ERROR)

    allowlist_table = data["allowlist"]
    if not isinstance(allowlist_table, dict):
        raise ScanError(_CONFIG_ERROR)

    allowed_allowlist_keys = {"version", "rules"}
    if not set(allowlist_table.keys()).issubset(allowed_allowlist_keys):
        raise ScanError(_CONFIG_ERROR)

    version = allowlist_table.get("version", "1")
    # Typage strict : `version = 1` (int) n'est pas `version = "1"`.
    if not isinstance(version, str) or version != "1":
        raise ScanError(_CONFIG_ERROR)

    raw_rules = allowlist_table.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ScanError(_CONFIG_ERROR)
    if len(raw_rules) > MAX_RULES:
        raise ScanError(_CONFIG_ERROR)

    rules = [_parse_rule_dict(raw) for raw in raw_rules]
    return Allowlist(rules, sha256=sha256)


def parse_allowlist_bytes(raw_bytes: bytes) -> Allowlist:
    """Parse une configuration déjà lue et bornée, sans nouvelle I/O.

    Cette fonction est le point de liaison entre la garde anti
    auto-attestation et le parseur : le contenu vérifié contre l'index est
    analysé directement, donc un écrivain concurrent ne peut pas substituer
    un autre fichier entre la vérification et le parsing.
    """
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_CONFIG_BYTES:
        raise ScanError(_CONFIG_ERROR)
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ScanError(_CONFIG_ERROR) from None
    return parse_allowlist_toml(
        content,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def load_allowlist_from_file(config_path: Path, *, repo_root: Path | None = None) -> Allowlist:
    """Charge l'allowlist depuis un fichier TOML en réutilisant la garde unique (`_resolve_root`).

    - Vérification anti-symlink sur le fichier et tous ses parents via `_resolve_root`
    - Confinement sous repo_root si fourni
    - Ouverture par descripteur O_NOFOLLOW / O_CLOEXEC / O_NONBLOCK
    - Plafond de taille borné (MAX_CONFIG_BYTES) vérifié par fstat
    - Décodage strict UTF-8 et parsing depuis les octets lus (une seule lecture)
    - Calcul déterministe de l'empreinte SHA-256
    """
    resolved = _resolve_root(config_path)
    if repo_root is not None:
        resolved_root = _resolve_root(repo_root)
        if not resolved.is_relative_to(resolved_root):
            raise ScanError(_CONFIG_ERROR)

    try:
        # O_NONBLOCK : un FIFO posé à la place du fichier ne bloque pas
        # l'ouverture ; le fstat + S_ISREG ci-dessous le refuse.
        descriptor = os.open(resolved, _open_flags() | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ScanError(_CONFIG_ERROR) from None

    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_CONFIG_BYTES:
            raise ScanError(_CONFIG_ERROR)

        raw_bytes = os.read(descriptor, MAX_CONFIG_BYTES + 1)
        if len(raw_bytes) > MAX_CONFIG_BYTES or len(raw_bytes) != file_stat.st_size:
            # Trop gros, ou fichier modifié pendant la lecture : fail-closed.
            raise ScanError(_CONFIG_ERROR)
    finally:
        os.close(descriptor)

    return parse_allowlist_bytes(raw_bytes)


def load_allowlist(
    root: Path,
    config_file: str | Path | None = None,
    *,
    allow_external: bool = False,
) -> Allowlist:
    """Charge la configuration d'allowlist pour la racine d'un dépôt.

    Si `config_file` est fourni, ce fichier spécifique est chargé (fail-closed s'il
    est invalide ou manquant).
    Si `config_file` n'est pas fourni, recherche `heimdall.toml` à la racine de `root`.
    Si `heimdall.toml` n'existe pas, retourne une Allowlist vide.
    """
    resolved_root = _resolve_root(root)

    if config_file is not None:
        target = Path(config_file)
        if not target.is_absolute():
            target = resolved_root / target
        resolved_target = _resolve_root(target)
        if resolved_target.is_relative_to(resolved_root):
            return load_allowlist_from_file(resolved_target, repo_root=resolved_root)
        if allow_external:
            return load_allowlist_from_file(resolved_target, repo_root=None)
        raise ScanError(_CONFIG_ERROR)

    default_config = resolved_root / "heimdall.toml"
    try:
        if not default_config.exists():
            return Allowlist.empty()
    except OSError:
        return Allowlist.empty()

    return load_allowlist_from_file(default_config, repo_root=resolved_root)


__all__ = [
    "MAX_CONFIG_BYTES",
    "MAX_DESCRIPTION_LENGTH",
    "MAX_PATTERN_LENGTH",
    "MAX_RULES",
    "MAX_RULE_NAME_LENGTH",
    "MIN_KEYWORD_LENGTH",
    "Allowlist",
    "AllowlistRule",
    "AllowlistTrace",
    "create_default_rules",
    "load_allowlist",
    "load_allowlist_from_file",
    "parse_allowlist_bytes",
    "parse_allowlist_toml",
]
