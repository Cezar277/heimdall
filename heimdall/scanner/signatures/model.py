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
from typing import Final

#: Grammaire commune aux identifiants de règle et aux types Finding (#14).
_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]*")
_MAX_IDENTIFIER_LENGTH: Final[int] = 64
_VALUE_GROUP: Final[str] = "value"


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

    def matches(self, line: str) -> tuple[re.Match[str], ...]:
        """Toutes les correspondances de la règle dans ``line``.

        Les mots-clés, s'ils sont déclarés, sont un **filtre de contexte** :
        aucun d'eux présent (casse ignorée) signifie aucune correspondance.
        Le filtre ne remplace pas l'ancrage de la regex ; il évite seulement
        de chercher une forme trop générique dans un contexte non pertinent.
        """
        if not isinstance(line, str):
            return ()
        if self.keywords:
            lowered = line.casefold()
            if not any(keyword in lowered for keyword in self.keywords):
                return ()
        return tuple(match for match in self._pattern.finditer(line) if match.group(_VALUE_GROUP))


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
