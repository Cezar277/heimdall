"""Registre des signatures de secrets (#54, sous-tickets #55 à #58).

Le registre est la **seule source de vérité** des règles : un fichier par
famille, agrégé et validé ici. Chaque règle porte son identifiant, sa
description, sa regex, ses mots-clés optionnels, un exemple positif et un
exemple négatif ; le test paramétré ``tests/test_scanner_signatures.py`` relit
ces exemples et vérifie qu'ils se comportent comme annoncé.

Ce module ne lit aucun fichier, n'appelle aucun réseau et ne conserve jamais
la valeur d'un candidat au-delà de l'appel : le moteur (#54) produit ensuite
des ``Finding`` avec une empreinte HMAC (voir ``signature_engine``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from heimdall.scanner.signatures.aws_cloud import RULES as AWS_CLOUD_RULES
from heimdall.scanner.signatures.github_jwt import RULES as GITHUB_JWT_RULES
from heimdall.scanner.signatures.model import Rule, validate_rules
from heimdall.scanner.signatures.pem import RULES as PEM_RULES
from heimdall.scanner.signatures.stripe_slack import RULES as STRIPE_SLACK_RULES

#: Les quatre familles du découpage #22.2.1 à #22.2.4, dans un ordre stable.
FAMILIES: Final[tuple[tuple[str, tuple[Rule, ...]], ...]] = (
    ("aws_cloud", AWS_CLOUD_RULES),
    ("stripe_slack", STRIPE_SLACK_RULES),
    ("github_jwt", GITHUB_JWT_RULES),
    ("pem", PEM_RULES),
)

#: Registre complet, validé au chargement (ids uniques, exemples conformes).
RULES: Final[tuple[Rule, ...]] = validate_rules(
    tuple(rule for _family, rules in FAMILIES for rule in rules)
)

#: Alias historique du ticket #22 : une signature est une règle.
SIGNATURES: Final[tuple[Rule, ...]] = RULES

#: Alias de type pour les appelants qui parlent de « signature ».
Signature = Rule


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """Une valeur candidate reconnue et la règle qui l'a produite.

    ``start`` est le début de la correspondance complète (mot-clé éventuel
    compris) ; le moteur s'en sert pour attribuer une correspondance
    multi-ligne à la bonne ligne.

    Usage **interne** : ``value`` n'est jamais sérialisée dans un Finding. Le
    moteur la hache immédiatement (HMAC-SHA-256, ADR-001) et ne la conserve
    pas au-delà de la construction du Finding. Le ``repr`` ne reflète jamais
    ``value`` (invariant 8) : journaliser un match ne doit pas écrire le
    secret en clair.
    """

    secret_type: str
    signature: str
    value: str = field(repr=False)
    start: int = 0

    def __repr__(self) -> str:
        """Résumé sans la valeur candidate (jamais de secret dans un ``repr``)."""
        return (
            f"SignatureMatch(type={self.secret_type!r}, "
            f"signature={self.signature!r}, start={self.start})"
        )

    @property
    def rule_id(self) -> str:
        """Identifiant stable de la règle (alias de ``signature``)."""
        return self.signature

    @property
    def type(self) -> str:
        """Type Finding du candidat (alias de ``secret_type``)."""
        return self.secret_type


def rules_for_family(family: str) -> tuple[Rule, ...]:
    """Renvoie les règles d'une famille nommée, ou refuse un nom inconnu."""
    for name, rules in FAMILIES:
        if name == family:
            return rules
    raise KeyError(f"famille de signatures inconnue : {family!r}")


def find_signature_matches(line: str) -> tuple[SignatureMatch, ...]:
    """Signatures présentes dans une ligne, dédupliquées par (type, valeur).

    Une même valeur identique sur la même ligne n'est signalée qu'une fois ;
    deux valeurs distinctes du même type restent deux candidats (un secret ne
    doit jamais en masquer un autre). L'ordre du registre est conservé, puis
    l'ordre des occurrences dans la ligne.

    .. warning::
       Le retour contient la **valeur brute** du candidat
       (``SignatureMatch.value``). Ces données sont sensibles : ne jamais les
       journaliser, les sérialiser ni les transmettre à un LLM. Le moteur les
       hache immédiatement et ne rend que des ``Finding`` sans valeur.
    """
    matches: list[SignatureMatch] = []
    seen: set[tuple[str, str]] = set()
    for rule in RULES:
        for match in rule.matches(line):
            value = match.group("value")
            key = (rule.secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                SignatureMatch(
                    secret_type=rule.secret_type,
                    signature=rule.id,
                    value=value,
                    start=match.start(),
                )
            )
    return tuple(matches)


# ``find_signature_matches`` reste importable explicitement depuis ce module,
# mais n'est volontairement pas dans ``__all__`` : son retour contient des
# valeurs brutes (surface sensible, réservée au moteur et aux tests). Elle
# n'est **pas** réexportée par ``heimdall.scanner`` : un seul point d'export,
# pas deux politiques contradictoires.
__all__ = [
    "FAMILIES",
    "RULES",
    "SIGNATURES",
    "Rule",
    "Signature",
    "SignatureMatch",
    "rules_for_family",
]
