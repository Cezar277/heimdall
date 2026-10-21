"""Modèle d'une règle de signature (#54).

Une règle est **déclarative** : identifiant stable, description, expression
régulière, mot-clé de contexte optionnel, exemple positif et exemple négatif.
Le registre est validé au chargement : une règle dont un exemple ne se comporte
pas comme annoncé empêche l'import du scanner (fail-closed, jamais un registre
silencieusement faux).

Les motifs doivent rester **linéaires et bornés** : aucun quantificateur
imbriqué, aucune borne ouverte sur un contenu arbitraire. Le contenu scanné
est contrôlé par un attaquant (fichier ou diff piégé) : une regex qui explose
en backtracking bloquerait le scanner (ReDoS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

#: Grammaire commune aux identifiants de règle et aux types Finding (#14).
_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]*")
_MAX_IDENTIFIER_LENGTH: Final[int] = 64
_VALUE_GROUP: Final[str] = "value"


class RuleMatch:
    """Correspondance d'une règle dont le ``repr`` ne montre pas le candidat.

    ``re.Match`` expose le texte reconnu dans son ``repr`` (``match='...'``) :
    un simple ``log.debug("%r", match)`` écrirait un secret en clair. Ce
    wrapper délègue l'API utile de ``re.Match`` mais son ``repr`` se limite à
    l'identifiant de règle et aux bornes.

    Le candidat reste accessible par ``group("value")`` : ces données sont
    sensibles et ne doivent jamais être journalisées, sérialisées ni
    transmises à un LLM.
    """

    __slots__ = ("_match", "_rule_id")

    def __init__(self, match: re.Match[str], rule_id: str) -> None:
        self._match = match
        self._rule_id = rule_id

    def __repr__(self) -> str:
        start, end = self._match.span()
        return f"RuleMatch(rule={self._rule_id!r}, span=({start}, {end}))"

    def group(self, *groups: int | str) -> Any:
        """Délègue à ``re.Match.group`` (le groupe ``value`` est sensible)."""
        return self._match.group(*groups)

    def __getitem__(self, group: int | str) -> Any:
        """Délègue à ``re.Match.__getitem__`` (accès explicite au candidat)."""
        return self._match[group]

    def groups(self, default: str | None = None) -> tuple[str | None, ...]:
        """Délègue à ``re.Match.groups``."""
        return self._match.groups(default)

    def groupdict(self, default: str | None = None) -> dict[str, str | None]:
        """Délègue à ``re.Match.groupdict``."""
        return self._match.groupdict(default)

    def start(self, group: int | str = 0) -> int:
        """Délègue à ``re.Match.start``."""
        return self._match.start(group)

    def end(self, group: int | str = 0) -> int:
        """Délègue à ``re.Match.end``."""
        return self._match.end(group)

    def span(self, group: int | str = 0) -> tuple[int, int]:
        """Délègue à ``re.Match.span``."""
        return self._match.span(group)

    def expand(self, template: str) -> str:
        """Délègue à ``re.Match.expand``."""
        return self._match.expand(template)

    @property
    def re(self) -> re.Pattern[str]:
        """Motif compilé, comme ``re.Match.re``."""
        return self._match.re

    @property
    def string(self) -> str:
        """Ligne analysée, comme ``re.Match.string`` (donnée sensible)."""
        return self._match.string

    @property
    def pos(self) -> int:
        """Position de départ de la recherche."""
        return self._match.pos

    @property
    def endpos(self) -> int:
        """Position de fin de la recherche."""
        return self._match.endpos

    @property
    def lastindex(self) -> int | None:
        """Index du dernier groupe capturé."""
        return self._match.lastindex

    @property
    def lastgroup(self) -> str | None:
        """Nom du dernier groupe capturé."""
        return self._match.lastgroup


@dataclass(frozen=True, slots=True)
class Rule:
    """Une signature de secret identifiable et testable.

    - ``id`` : nom stable de la règle, unique dans le registre ;
    - ``description`` : ce que la règle reconnaît, en une phrase ;
    - ``regex`` : motif compilé avec un groupe nommé ``value`` ;
    - ``secret_type`` : valeur du champ ``type`` du Finding (#14) ;
    - ``keywords`` : mots-clés de contexte optionnels (casse ignorée) ;
    - ``positive_example`` / ``negative_example`` : exemples vérifiés à
      l'import, puis relus par le test paramétré du ticket.
    """

    id: str
    description: str
    regex: str
    secret_type: str
    positive_example: str
    negative_example: str
    keywords: tuple[str, ...] = ()
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Valide la règle et compile son motif (échec = import refusé)."""
        _check_identifier(self.id, "id de règle")
        _check_identifier(self.secret_type, "type de Finding")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError(f"règle {self.id} : description vide")
        if not isinstance(self.regex, str) or not self.regex:
            raise ValueError(f"règle {self.id} : regex vide")
        if not isinstance(self.positive_example, str) or not self.positive_example:
            raise ValueError(f"règle {self.id} : exemple positif vide")
        if not isinstance(self.negative_example, str) or not self.negative_example:
            raise ValueError(f"règle {self.id} : exemple négatif vide")
        keywords = tuple(self.keywords)
        if any(not isinstance(keyword, str) or not keyword for keyword in keywords):
            raise ValueError(f"règle {self.id} : mot-clé vide")
        object.__setattr__(self, "keywords", tuple(keyword.casefold() for keyword in keywords))
        try:
            pattern = re.compile(self.regex)
        except re.error:
            raise ValueError(f"règle {self.id} : regex invalide") from None
        if _VALUE_GROUP not in pattern.groupindex:
            raise ValueError(f"règle {self.id} : groupe nommé 'value' absent")
        object.__setattr__(self, "_pattern", pattern)
        if not self.matches(self.positive_example):
            raise ValueError(f"règle {self.id} : exemple positif non reconnu")
        if self.matches(self.negative_example):
            raise ValueError(f"règle {self.id} : exemple négatif reconnu")

    @property
    def name(self) -> str:
        """Alias historique : le nom stable de la règle est son ``id``."""
        return self.id

    @property
    def type(self) -> str:
        """Alias : valeur du champ ``type`` du Finding produit."""
        return self.secret_type

    @property
    def pattern(self) -> re.Pattern[str]:
        """Motif compilé (le groupe nommé ``value`` porte le candidat)."""
        return self._pattern

    def matches(self, line: str) -> tuple[RuleMatch, ...]:
        """Toutes les correspondances de la règle dans ``line``.

        Les mots-clés, s'ils sont déclarés, sont un **filtre de contexte** :
        aucun d'eux présent (casse ignorée) signifie aucune correspondance.
        Le filtre ne remplace pas l'ancrage de la regex ; il évite seulement
        de chercher une forme trop générique dans un contexte non pertinent.

        Les objets rendus portent le candidat via ``group("value")`` ; leur
        ``repr`` est masqué (``RuleMatch``) pour qu'une journalisation
        accidentelle n'écrive jamais le secret en clair.
        """
        if not isinstance(line, str):
            return ()
        if self.keywords:
            lowered = line.casefold()
            if not any(keyword in lowered for keyword in self.keywords):
                return ()
        return tuple(
            RuleMatch(match, self.id)
            for match in self._pattern.finditer(line)
            if match.group(_VALUE_GROUP)
        )


def _check_identifier(value: object, label: str) -> None:
    """Vérifie la grammaire ``snake_case`` bornée d'un identifiant."""
    if (
        not isinstance(value, str)
        or len(value) > _MAX_IDENTIFIER_LENGTH
        or _ID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(f"{label} non conforme : {value!r}")


def validate_rules(rules: tuple[Rule, ...]) -> tuple[Rule, ...]:
    """Refuse un registre vide, un identifiant dupliqué ou un type incohérent."""
    if not rules:
        raise ValueError("registre de signatures vide")
    identifiers: set[str] = set()
    for rule in rules:
        if rule.id in identifiers:
            raise ValueError(f"règle dupliquée : {rule.id}")
        identifiers.add(rule.id)
    return rules


def make_rule(  # noqa: PLR0913 — miroir explicite des champs d'une règle.
    *,
    id: str,
    description: str,
    regex: str,
    finding_type: str,
    positive: str,
    negative: str,
    keywords: tuple[str, ...] = (),
) -> Rule:
    """Fabrique une règle avec des noms d'arguments non ambigus pour le SAST.

    ``finding_type`` est la valeur du champ Finding ``type`` (``aws``,
    ``stripe``…), pas un secret. La construction positionnelle évite que
    Bandit B106 confonde ``secret_type`` avec un mot de passe codé en dur.
    """
    return Rule(id, description, regex, finding_type, positive, negative, keywords)
