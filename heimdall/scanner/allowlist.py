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
  est plafonnée (64 Kio), le nombre de règles et de motifs est borné, les
  regex subissent une analyse structurelle (imbrication réelle, alternance
  sous quantificateur, quantificateurs consécutifs, références arrière) et
  la valeur candidate soumise à une regex est bornée. Le filtre de chemins
  est borné d'un côté et de l'autre : au plus
  :data:`MAX_PATH_WILDCARDS` jokers `*` par motif via `fnmatch`, et au plus
  :data:`MAX_MATCH_PATH_LENGTH` caractères de chemin soumis au filtre.
- Anti-allowlist aveugle (CWE-1188) : un motif doit porter au moins
  :data:`MIN_PATTERN_LITERALS` caractères littéraux et ne jamais matcher la
  chaîne vide ; les motifs universels (`.`, `.*`, `^`, `^.*$`) sont refusés.
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
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import MAX_TYPE_LENGTH, validate_relative_path
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

#: Nombre minimal de caractères littéraux dans un motif regex. En dessous,
#: le motif est trop large pour être auditable : `.`, `.*`, `^`, `$`,
#: `\w+`, `[a-z]+` ou `[^x]+` ne portent aucun marqueur concret et peuvent
#: ignorer n'importe quel secret. Un motif doit contenir au moins trois
#: caractères littéraux (hors classes, ancres et quantificateurs).
MIN_PATTERN_LITERALS: Final[int] = 3

#: Longueur maximale de la valeur candidate soumise à une regex. Au-delà,
#: l'évaluation regex est **omise** (le candidat reste signalé) : c'est
#: fail-closed, et cela borne l'exposition à un motif pathologique qui
#: aurait échappé à l'analyse structurelle.
MAX_REGEX_VALUE_LENGTH: Final[int] = 256

#: Nombre maximal de jokers `*` par motif de chemin. Chaque `*` devient
#: un quantificateur dans la regex de `fnmatch` ; sous Python < 3.13
#: (translate sans groupes atomiques), une longue chaîne de `*` croisée à
#: un chemin adverse peut explorer un nombre exponentiel de découpages.
#: Un plafond conservateur borne ce coût à des millisecondes mesurées.
MAX_PATH_WILDCARDS: Final[int] = 10

#: Longueur maximale d'un chemin soumis à `fnmatch`. Au-delà, l'évaluation
#: est **omise** (le candidat reste signalé, fail-closed) : même protection
#: que :data:`MAX_REGEX_VALUE_LENGTH` pour le filtre de chemins.
MAX_MATCH_PATH_LENGTH: Final[int] = 1024

#: Catégories Unicode jamais acceptées dans un mot-clé ou un motif
#: (contrôles, formats invisibles, séparateurs de ligne/paragraphe) : les
#: mêmes que `_visible` échappe à l'affichage (`scan.py`). Un `\n` littéral
#: ou un RLO ne matcherait jamais une valeur monoligne (règle morte
#: silencieuse) : refusé en `ScanError`, jamais ignoré. Les échappements
#: regex (`\\n`, `\\t`) restent deux caractères ordinaires et acceptés.
_FORBIDDEN_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _reject_control_characters(value: str) -> None:
    """Refuse tout caractère de contrôle/invisible (fail-closed, invariant 8)."""
    if any(unicodedata.category(char) in _FORBIDDEN_CATEGORIES for char in value):
        raise ScanError(_CONFIG_ERROR)


#: Grammaire des types de secrets acceptés en allowlist : miroir exact de
#: `finding._TYPE_PATTERN` (contrat #14) — `[a-z][a-z0-9_]*`, 64 caractères
#: max (`finding.MAX_TYPE_LENGTH`). Un `secret_types` hors grammaire
#: (`"AWS"`, `"../etc"`, `"foo bar"`) ne matcherait jamais le type réel et
#: rendrait la règle muette : refusé en `ScanError`. Toute divergence entre
#: les deux définitions est une anomalie d'audit (voir fiche SAMM T24).
_SECRET_TYPE_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]*")


def _validate_secret_type(value: str) -> None:
    """Refuse un `secret_types` hors grammaire du contrat #14 (typo = règle morte)."""
    if len(value) > MAX_TYPE_LENGTH or _SECRET_TYPE_RE.fullmatch(value) is None:
        raise ScanError(_CONFIG_ERROR)

#: Validation stricte de l'identifiant de règle (nom ASCII sécurisé).
_RULE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

#: Détection rigoureuse de constructions regex à risque de backtracking catastrophique (CWE-1333).
#: La fonction :func:`_reject_dangerous_regex` effectue une analyse structurelle
#: (groupes, classes, échappements) qui couvre l'imbrication réelle, puis les
#: motifs ci-dessous servent de seconde barrière pour les répétitions d'atomes.
#: Sont interdits :
#: 1. L'alternance sous quantificateur : `(a|b)+`, `((a|aa))+`, `(a|b)?`
#: 2. Les wildcards ou classes quantifiées sous quantificateur : `(.*a)+`, `(\w+)+`
#: 3. La double quantification imbriquée : `(a+)+`, `(a?)+`, `(?:(a|aa))+`
#: 4. Les quantificateurs consécutifs : `a++`, `a**`, `a??`, `a*?`
#: 5. Les quantificateurs répétés sur le même atome : `a*a*`, `a?a?`, `.*.*`
#: 6. Les classes de caractères quantifiées consécutives : `\d+\d+`, `\w+\w+`
#: 7. Les classes entre crochets quantifiées consécutives : `[0-9]+[0-9]+`
#: 8. Les références arrière (`\1`, `(?P=nom)`) et les groupes conditionnels,
#:    dont le coût de backtracking n'est pas borné linéairement.
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

#: Drapeaux inline reconnus par `re` (hors `x`, refusé car il rend l'analyse
#: statique des littéraux non fiable).
_FLAG_CHARS: Final[frozenset[str]] = frozenset("aiLmsux-")


def _skip_char_class(raw: str, start: int) -> int:
    """Retourne l'index juste après une classe ``[...]`` fermée.

    Gère l'échappement, le ``^`` de négation et le ``]`` littéral en première
    position. Une classe non fermée est une configuration invalide.
    """
    i = start + 1
    n = len(raw)
    if i < n and raw[i] == "^":
        i += 1
    if i < n and raw[i] == "]":
        i += 1
    while i < n:
        if raw[i] == "\\":
            i += 2
            continue
        if raw[i] == "]":
            return i + 1
        i += 1
    raise ScanError(_CONFIG_ERROR)


def _group_content_start(  # noqa: PLR0911, PLR0912 - préfixes (?...) exhaustifs
    raw: str,
    open_index: int,
) -> tuple[int, int | None]:
    """Localise le contenu d'un groupe et refuse les constructions non analysables.

    Retourne ``(content_start, skip_to)``. Un ``skip_to`` non nul signifie que
    le groupe entier doit être ignoré (groupe de drapeaux sans contenu) : il ne
    porte aucun motif à analyser.
    """
    if open_index + 1 >= len(raw) or raw[open_index + 1] != "?":
        return open_index + 1, None

    i = open_index + 2
    if i >= len(raw):
        return i, None
    marker = raw[i]

    if marker == "P":
        if i + 1 < len(raw) and raw[i + 1] == "<":
            end = raw.find(">", i + 2)
            if end < 0:
                raise ScanError(_CONFIG_ERROR)
            return end + 1, None
        if i + 1 < len(raw) and raw[i + 1] == "=":
            # Référence arrière nommée : coût de backtracking non borné.
            raise ScanError(_CONFIG_ERROR)
        return i + 1, None

    if marker == "#":
        # Commentaire de motif : refusé, car il complique l'analyse statique.
        raise ScanError(_CONFIG_ERROR)

    if marker == "(":
        # Groupe conditionnel (?(id)oui|non) : non supporté.
        raise ScanError(_CONFIG_ERROR)

    if marker in "=!":
        return i + 1, None

    if marker == "<" and i + 1 < len(raw) and raw[i + 1] in "=!":
        return i + 2, None

    if marker == ">":
        # Groupe atomique : son contenu reste analysable normalement.
        return i + 1, None

    # (?drapeaux) ou (?drapeaux:...)
    j = i
    while j < len(raw) and raw[j] in _FLAG_CHARS:
        if raw[j] in "xX":
            # Mode verbose : espaces et `#` deviennent significatifs, l'analyse
            # statique des littéraux ne serait plus fiable.
            raise ScanError(_CONFIG_ERROR)
        j += 1
    if j < len(raw) and raw[j] == ":":
        return j + 1, None
    if j < len(raw) and raw[j] == ")":
        return j + 1, j + 1
    return i, None


def _skip_quantifier(raw: str, start: int) -> int:
    """Retourne l'index juste après un quantificateur ``*``, ``+``, ``?`` ou ``{m,n}``."""
    if raw[start] in "*+?":
        return start + 1
    end = raw.find("}", start + 1)
    if end < 0:
        return start + 1
    return end + 1


def _body_is_unsafe(body: str) -> bool:
    """Vrai si un corps de groupe contient une imbrication dangereuse.

    Détecte une alternance, un quantificateur ou un groupe imbriqué hors
    échappement et hors classe de caractères. Une imbrication sous
    quantificateur est refusée par prudence : c'est le vecteur ReDoS
    ``((a|aa))+$`` que les regex ``[^)]*`` ne voyaient pas.
    """
    i = 0
    n = len(body)
    while i < n:
        char = body[i]
        if char == "\\":
            i += 2
            continue
        if char == "[":
            i = _skip_char_class(body, i)
            continue
        if char in "(|*+?{":
            return True
        i += 1
    return False


def _reject_dangerous_regex(raw: str) -> None:  # noqa: PLR0912 - automate explicite
    """Analyse structurelle anti-ReDoS (CWE-1333).

    Suit la pile des groupes, ignore échappements et classes, et refuse :
    - un groupe quantifié dont le corps contient ``(``, ``|`` ou un
      quantificateur (imbrication réelle, y compris ``((a|aa))+``) ;
    - les quantificateurs consécutifs ou lazy (``a++``, ``a*?``) ;
    - les références arrière (``\\1``) et constructions non supportées.
    """
    stack: list[int] = []
    i = 0
    n = len(raw)
    while i < n:
        char = raw[i]
        if char == "\\":
            if i + 1 < n and raw[i + 1] in "123456789":
                raise ScanError(_CONFIG_ERROR)
            i += 2
            continue
        if char == "[":
            i = _skip_char_class(raw, i)
            continue
        if char == "(":
            content_start, skip_to = _group_content_start(raw, i)
            if skip_to is not None:
                i = skip_to
                continue
            stack.append(content_start)
            i = content_start
            continue
        if char == ")":
            if not stack:
                raise ScanError(_CONFIG_ERROR)
            content_start = stack.pop()
            next_index = i + 1
            if next_index < n and raw[next_index] in "*+?{":
                if _body_is_unsafe(raw[content_start:i]):
                    raise ScanError(_CONFIG_ERROR)
            i += 1
            continue
        if char in "*+?{":
            next_index = _skip_quantifier(raw, i)
            if next_index < n and raw[next_index] in "*+?{":
                raise ScanError(_CONFIG_ERROR)
            i = next_index
            continue
        i += 1
    if stack:
        raise ScanError(_CONFIG_ERROR)


def _split_alternatives(raw: str) -> tuple[str, ...]:
    """Découpe les alternances au niveau courant, hors groupes/classes."""
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(raw)
    while i < n:
        char = raw[i]
        if char == "\\":
            i += 2
            continue
        if char == "[":
            i = _skip_char_class(raw, i)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(raw[start:i])
            start = i + 1
        i += 1
    parts.append(raw[start:])
    return tuple(parts)


def _group_end(raw: str, start: int) -> int:
    depth = 1
    index = start + 1
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_char_class(raw, index)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ScanError(_CONFIG_ERROR)


def _escaped_literal(segment: str, start: int) -> tuple[int, int]:
    if start < 0 or start + 1 >= len(segment):
        raise ScanError(_CONFIG_ERROR)
    escaped = segment[start + 1]
    if escaped in "dDwWsSbBAZz123456789":
        return 0, start + 2
    widths = {"x": 2, "u": 4, "U": 8}
    if escaped in widths:
        return 1, start + 2 + widths[escaped]
    if escaped == "N":
        try:
            return 1, segment.index("}", start + 2) + 1
        except ValueError:
            raise ScanError(_CONFIG_ERROR) from None
    if escaped == "0":
        end = start + 2
        while end < min(start + 4, len(segment)) and segment[end] in "01234567":
            end += 1
        return 1, end
    return 1, start + 2


def _count_literal_chars(segment: str) -> int:  # noqa: PLR0912 - grammaire bornée explicite
    """Minimum de marqueurs littéraux obligatoires sur chaque branche.

    Les assertions ne consomment pas de texte. Un atome/groupe optionnel
    ne contribue pas ; une répétition ne multiplie jamais les marqueurs.
    La longueur maximale borne aussi la profondeur et le coût du parseur.
    """
    if len(segment) > MAX_PATTERN_LENGTH:
        raise ScanError(_CONFIG_ERROR)
    alternatives = _split_alternatives(segment)
    if len(alternatives) > 1:
        return min(_count_literal_chars(branch) for branch in alternatives)
    count = 0
    atom = 0
    i = 0
    n = len(segment)
    while i < n:
        char = segment[i]
        if char == "\\":
            atom, i = _escaped_literal(segment, i)
            count += atom
            continue
        if char == "[":
            i = _skip_char_class(segment, i)
            atom = 0
            continue
        if char == "(":
            content_start, skip_to = _group_content_start(segment, i)
            if skip_to is not None:
                i = skip_to
                atom = 0
                continue
            end = _group_end(segment, i)
            assertion = segment.startswith(("(?=", "(?!", "(?<=", "(?<!"), i)
            atom = 0 if assertion else _count_literal_chars(segment[content_start:end])
            count += atom
            i = end + 1
            continue
        if char in "*?":
            count -= atom
            atom = 0
        elif char == "{":
            end = segment.find("}", i + 1)
            lower = segment[i + 1:end].split(",", 1)[0] if end >= 0 else ""
            if not lower or (lower.isascii() and lower.isdigit() and int(lower) == 0):
                count -= atom
                atom = 0
            i = end + 1 if end >= 0 else i + 1
            continue
        elif char == "+":
            pass
        elif char in "^$.":
            atom = 0
        else:
            atom = 1
            count += atom
        i += 1
    return count


def _path_matches(file_path: str, pattern: str) -> bool:
    """Glob sensible à la casse : seul un segment ``**`` traverse ``/``."""
    parts = file_path.split("/")
    if "\\" in file_path or any(part in {"", ".", ".."} for part in parts):
        return False
    reachable = {0}
    for segment in pattern.split("/"):
        if not reachable:
            return False
        if segment == "**":
            reachable = set(range(min(reachable), len(parts) + 1))
        else:
            reachable = {
                index + 1 for index in reachable
                if index < len(parts) and fnmatch.fnmatchcase(parts[index], segment)
            }
    return len(parts) in reachable


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
    - `patterns` : expressions régulières compilées, non universelles et
      porteuses d'au moins :data:`MIN_PATTERN_LITERALS` caractères littéraux
    - `exact_keywords` : marqueurs exacts comparés à égalité insensible à la
      casse (ex. 'changeme') — le choix auditable pour les règles globales
      sans `paths` : `my-example-key` reste détecté (invariant 1)

    Les critères de restriction facultatifs (en conjonction avec
    keywords/patterns/exact_keywords) sont :
    - `paths` : globs POSIX relatifs, `*` par segment et `**` récursif
    - `secret_types` : types de secrets restreints (ex. 'aws', 'stripe')

    Les mots-clés sont toujours comparés avec une frontière `\\b` stricte :
    `paths` ne transforme jamais `_` en séparateur (voir
    :func:`_keyword_matches_value`).
    """

    name: str
    description: str
    keywords: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    exact_keywords: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    secret_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:  # noqa: PLR0912 - gauntlet de validation, un bloc par champ du contrat
        if not isinstance(self.name, str) or not _RULE_NAME_RE.fullmatch(self.name):
            raise ScanError(_CONFIG_ERROR)
        if len(self.name) > MAX_RULE_NAME_LENGTH:
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.description, str) or not self.description:
            raise ScanError(_CONFIG_ERROR)
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            raise ScanError(_CONFIG_ERROR)

        # Validation de type des critères. En particulier, une chaîne passée
        # à `patterns` provoquerait un AttributeError dans `matches()` :
        # l'API doit rester dans le contrat ScanError (invariant 11).
        if not isinstance(self.patterns, (tuple, list)) or any(
            not isinstance(pattern, re.Pattern)
            or not isinstance(pattern.pattern, str)
            for pattern in self.patterns
        ):
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.keywords, (tuple, list)) or any(
            not isinstance(keyword, str) for keyword in self.keywords
        ):
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.exact_keywords, (tuple, list)) or any(
            not isinstance(exact, str) for exact in self.exact_keywords
        ):
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.paths, (tuple, list)) or any(
            not isinstance(path, str) for path in self.paths
        ):
            raise ScanError(_CONFIG_ERROR)
        if not isinstance(self.secret_types, (tuple, list)) or any(
            not isinstance(secret_type, str) for secret_type in self.secret_types
        ):
            raise ScanError(_CONFIG_ERROR)
        # Grammaire du contrat #14, comme au parsing TOML : un type hors
        # grammaire rendrait la règle muette sans erreur (typo silencieuse).
        for secret_type in self.secret_types:
            _validate_secret_type(secret_type)
        # Contrôles/invisibles refusés aussi via l'API (même contrat que le
        # parsing TOML) : un mot-clé ou un motif à `\n` littéral ou RLO ne
        # matcherait jamais — faute de frappe, pas règle de test.
        for keyword in self.keywords:
            _reject_control_characters(keyword)
        for exact in self.exact_keywords:
            _reject_control_characters(exact)
        for pattern in self.patterns:
            _reject_control_characters(pattern.pattern)

        # Invariant 1 / Sécurité : toute règle DOIT obligatoirement définir au moins
        # un critère sur la valeur (keywords, patterns ou exact_keywords). Les
        # filtres paths ou secret_types ne peuvent JAMAIS constituer une règle
        # aveugle à eux seuls.
        if not self.keywords and not self.patterns and not self.exact_keywords:
            raise ScanError(_CONFIG_ERROR)
        # Seuls les marqueurs exacts peuvent être globaux : un `keywords`
        # (`\b`) ou un `patterns` sans `paths` ni `secret_types` ignore des
        # valeurs choisies contenant le marqueur (footgun `my-example-key`,
        # invariant 1 : doute → signalé). Les règles globales passent par
        # `exact_keywords` ; les motifs larges se restreignent par `paths`.
        if (self.keywords or self.patterns) and not (self.paths or self.secret_types):
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

        Une valeur plus longue que :data:`MAX_REGEX_VALUE_LENGTH` n'est pas
        soumise aux regex, et un chemin plus long que
        :data:`MAX_MATCH_PATH_LENGTH` n'est pas soumis à `fnmatch` : dans les
        deux cas le candidat reste signalé (fail-closed). Cela borne
        l'exposition à un motif pathologique qui aurait échappé aux
        validations.
        """
        # 1. Globs par segment ; seul ** traverse les répertoires.
        # Un chemin plus long que MAX_MATCH_PATH_LENGTH n'est pas soumis à
        # fnmatch : le candidat reste signalé (fail-closed), même protection
        # anti-backtracking que pour les regex sur la valeur.
        if self.paths:
            path_matched = (
                len(file_path) <= MAX_MATCH_PATH_LENGTH
                and any(
                    _path_matches(file_path, pattern)
                    for pattern in self.paths
                )
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
        # Marqueurs exacts : égalité insensible à la casse sur la valeur
        # entière — aucun coût regex, aucun faux-négatif par frontière.
        val_cf = value.casefold()
        ex_match = bool(
            self.exact_keywords
            and any(exact.casefold() == val_cf for exact in self.exact_keywords)
        )
        if self.patterns and len(value) <= MAX_REGEX_VALUE_LENGTH:
            pat_match = any(pattern.search(value) for pattern in self.patterns)
        else:
            pat_match = False
        return kw_match or ex_match or pat_match


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


def _validate_path_pattern(pattern: str) -> str:
    """Valide un motif de chemin selon la grammaire du contrat Finding #14.

    Un motif est un chemin relatif POSIX : pas de traversée (`..`), pas
    d'absolu, pas de lecteur Windows (`C:`), pas d'antislash, pas de NUL ou
    de caractère de contrôle, pas de segment vide. Les métacaractères glob
    (`*`, `?`, `[...]`) restent autorisés, dans la limite de
    :data:`MAX_PATH_WILDCARDS` jokers `*` par motif (anti-backtracking).
    """
    try:
        validate_relative_path(pattern)
    except ValueError:
        raise ScanError(_CONFIG_ERROR) from None
    if pattern.count("*") > MAX_PATH_WILDCARDS:
        # Chaque `*` devient un quantificateur dans fnmatch ; une chaîne de
        # `*` croisée à un chemin adverse peut ralentir la passe sous les
        # interpréteurs sans groupes atomiques. Refus fail-closed (code 2).
        raise ScanError(_CONFIG_ERROR)
    return pattern


def _compile_safe_regex(raw: str) -> re.Pattern[str]:
    """Compile une regex après analyse structurelle anti-ReDoS (CWE-1333).

    Refuse aussi les motifs universels : une regex qui matche la chaîne vide
    (donc toute valeur par un match de longueur nulle) ou dont une branche
    d'alternance ne porte pas au moins :data:`MIN_PATTERN_LITERALS` caractères
    littéraux est une allowlist aveugle.
    """
    if not isinstance(raw, str) or not raw:
        raise ScanError(_CONFIG_ERROR)
    if len(raw) > MAX_PATTERN_LENGTH:
        raise ScanError(_CONFIG_ERROR)
    if "\x00" in raw:
        raise ScanError(_CONFIG_ERROR)
    # Un contrôle littéral (`\n`, RLO…) ne matcherait jamais une valeur
    # monoligne : faute de frappe refusée (les échappements `\\n` restent
    # deux caractères ordinaires et acceptés).
    _reject_control_characters(raw)

    # 1. Analyse structurelle : imbrication réelle, quantificateurs, backrefs.
    _reject_dangerous_regex(raw)
    # 2. Seconde barrière pour les répétitions d'atomes connues.
    for dangerous in _REDOS_DANGEROUS_PATTERNS:
        if dangerous.search(raw):
            raise ScanError(_CONFIG_ERROR)

    try:
        compiled = re.compile(raw)
    except (re.error, OverflowError, RecursionError):
        raise ScanError(_CONFIG_ERROR) from None

    # 3. Un match de longueur nulle sur "" vaut pour toute valeur en position 0.
    if compiled.search(""):
        raise ScanError(_CONFIG_ERROR)

    # 4. Chaque branche d'alternance doit porter un marqueur littéral suffisant.
    for branch in _split_alternatives(raw):
        if _count_literal_chars(branch) < MIN_PATTERN_LITERALS:
            raise ScanError(_CONFIG_ERROR)

    return compiled


_ALLOWED_RULE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "name",
        "description",
        "keywords",
        "patterns",
        "exact_keywords",
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
        # Contrôles/invisibles (`\n` littéral, RLO…) : faute de frappe
        # refusée — un tel mot-clé ne matcherait jamais (règle morte).
        _reject_control_characters(item)
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
    exact_keywords = _parse_str_list(
        raw_rule,
        "exact_keywords",
        min_length=MIN_KEYWORD_LENGTH,
    )
    secret_types = _parse_str_list(raw_rule, "secret_types")
    # Grammaire du contrat #14 : un type hors grammaire (`"AWS"`, `"../etc"`)
    # ne matcherait jamais et rendrait la règle muette sans erreur.
    for secret_type in secret_types:
        _validate_secret_type(secret_type)

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
        exact_keywords=exact_keywords,
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

    version = allowlist_table.get("version")
    # Contrat fermé : `version` est EXPLICITE et vaut exactement le littéral
    # `"1"` — une version manquante, un entier `1` ou toute autre chaîne
    # est refusée (fail-closed), pour qu'un opérateur sache toujours quelle
    # grammaire il lit.
    if "version" not in allowlist_table:
        raise ScanError(_CONFIG_ERROR)
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
        # `os.close` peut lever `OSError` (EBADF/EINTR sur FS adverse) :
        # convertir pour garder le contrat unique `ScanError` (invariant 11).
        try:
            os.close(descriptor)
        except OSError:
            raise ScanError(_CONFIG_ERROR) from None

    return parse_allowlist_bytes(raw_bytes)


def load_allowlist(
    root: Path,
    config_file: str | Path | None = None,
    *,
    allow_external: bool = False,
) -> Allowlist:
    """Charge la configuration d'allowlist pour la racine d'un dépôt.

    Si `config_file` est fourni, ce fichier spécifique est chargé (fail-closed s'il
    est invalide ou manquant). Un chemin explicite peut vivre **hors** du dépôt :
    c'est un choix opérateur (`--config`), assumé par `allow_external=True` ; la
    garde `_resolve_root` + `O_NOFOLLOW` et le plafond de taille s'appliquent
    toujours, et le contenu reste soumis au contrat fermé.
    Si `config_file` n'est pas fourni, recherche `heimdall.toml` à la racine de `root`.
    Si `heimdall.toml` est absent, retourne une Allowlist vide ; si son accès
    échoue (`OSError` sur `exists()`), lève `ScanError` (code 2, invariant 11).
    """
    resolved_root = _resolve_root(root)

    if config_file is not None:
        # `Path()` lève `ValueError` sur un octet NUL (ou `TypeError` sur un
        # type inattendu) : convertir en `ScanError` pour garder le contrat
        # d'erreur unique (invariant 11), comme `_resolve_root` ci-dessous.
        try:
            target = Path(config_file)
        except (OSError, RuntimeError, ValueError, TypeError):
            raise ScanError(_CONFIG_ERROR) from None
        if not target.is_absolute():
            target = resolved_root / target
        resolved_target = _resolve_root(target)
        if resolved_target.is_relative_to(resolved_root):
            return load_allowlist_from_file(resolved_target, repo_root=resolved_root)
        if allow_external:
            return load_allowlist_from_file(resolved_target, repo_root=None)
        raise ScanError(_CONFIG_ERROR)

    default_config = resolved_root / "heimdall.toml"
    # `exists()` lève `OSError` sur un répertoire illisible (panne
    # d'outillage) : c'est un code 2, pas une allowlist vide silencieuse.
    # Seule l'absence avérée du fichier vaut « pas de config » (le vide
    # reste fail-closed : plus strict, aucun faux-négatif).
    try:
        if not default_config.exists():
            return Allowlist.empty()
    except OSError:
        raise ScanError(_CONFIG_ERROR) from None

    return load_allowlist_from_file(default_config, repo_root=resolved_root)


__all__ = [
    "MAX_CONFIG_BYTES",
    "MAX_DESCRIPTION_LENGTH",
    "MAX_MATCH_PATH_LENGTH",
    "MAX_PATTERN_LENGTH",
    "MAX_PATH_WILDCARDS",
    "MAX_REGEX_VALUE_LENGTH",
    "MAX_RULES",
    "MAX_RULE_NAME_LENGTH",
    "MIN_KEYWORD_LENGTH",
    "MIN_PATTERN_LITERALS",
    "Allowlist",
    "AllowlistRule",
    "AllowlistTrace",
    "load_allowlist",
    "load_allowlist_from_file",
    "parse_allowlist_bytes",
    "parse_allowlist_toml",
]
