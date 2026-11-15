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

import re
from dataclasses import dataclass, field
from typing import Final, Literal

from heimdall.scanner.signatures.aws_cloud import RULES as AWS_CLOUD_RULES
from heimdall.scanner.signatures.credentials import RULES as CREDENTIAL_RULES
from heimdall.scanner.signatures.github_jwt import RULES as GITHUB_JWT_RULES
from heimdall.scanner.signatures.model import Rule, RuleMatch, validate_rules
from heimdall.scanner.signatures.pem import RULES as PEM_RULES
from heimdall.scanner.signatures.service_tokens import RULES as SERVICE_TOKEN_RULES
from heimdall.scanner.signatures.stripe_slack import (
    ROTATING_INNER_RULE_IDS,
    ROTATING_PREFIX_LEN,
    ROTATING_RULE_ID,
)
from heimdall.scanner.signatures.stripe_slack import RULES as STRIPE_SLACK_RULES

#: Familles historiques et extensions E-02, dans un ordre stable.
FAMILIES: Final[tuple[tuple[str, tuple[Rule, ...]], ...]] = (
    ("aws_cloud", AWS_CLOUD_RULES),
    ("stripe_slack", STRIPE_SLACK_RULES),
    ("github_jwt", GITHUB_JWT_RULES),
    ("service_tokens", SERVICE_TOKEN_RULES),
    ("credentials", CREDENTIAL_RULES),
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
    source: Literal["regex", "entropy"] = "regex"
    context_end: int = 0  # fin de la clé ; elle ne doit pas traverser une jointure

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


def _matches_rotatifs(line: str) -> tuple[RuleMatch, ...]:
    """Correspondances de la règle rotative, calculées une seule fois.

    Le registre a besoin de leurs bornes **avant** de traiter les règles
    « jeton interne », qui les précèdent dans l'ordre du registre. Les
    recalculer dans la boucle principale doublerait le coût de la regex ; les
    calculer une fois puis n'en garder que les bornes garde la neutralisation
    en O(1) par candidat.
    """
    for rule in RULES:
        if rule.id == ROTATING_RULE_ID:
            return rule.matches(line)
    return ()


#: Ligne qui commence par sa propre affectation (``NOM=``, ``"nom":``,
#: ``nom:``). Borné et linéaire (aucun quantificateur imbriqué).
_OWN_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"[ \t]{0,64}[\"']?[A-Za-z_][A-Za-z0-9_.-]{0,128}[\"']?[ \t]{0,32}[:=]"
)


def crosses_into_own_assignment(match: SignatureMatch, boundary: int, joined: str) -> bool:
    """Vrai si la « valeur » jointe n'est que l'affectation de la ligne suivante.

    La jointure colle deux lignes sans séparateur pour reconstituer un secret
    coupé. Quand la clé se termine exactement à la frontière (``API_KEY=``
    vide) et que la ligne suivante est elle-même une affectation
    (``OTHER_KEY=``), ``API_KEY=OTHER_KEY=`` n'est pas un secret : c'est un
    ``.env.example`` (celui que ``heimdall fix`` génère). Une valeur seule sur
    la ligne suivante (bloc YAML ``api_key:`` puis la valeur) reste détectée.
    """
    if not 0 < match.context_end <= boundary:
        return False
    # Entre la fin de la clé et la frontière : séparateur seul, donc la
    # valeur commence sur la ligne suivante.
    if joined[match.context_end : boundary].strip(" \t\"':=") != "":
        return False
    return _OWN_ASSIGNMENT.match(joined, boundary) is not None


def find_signature_matches(line: str) -> tuple[SignatureMatch, ...]:
    """Signatures présentes dans une ligne, dédupliquées par (type, valeur).

    Une même valeur identique sur la même ligne n'est signalée qu'une fois ;
    deux valeurs distinctes du même type restent deux candidats (un secret ne
    doit jamais en masquer un autre). L'ordre du registre est conservé, puis
    l'ordre des occurrences dans la ligne.

    Le jeton interne d'une forme rotative ``xoxe.`` n'est émis qu'une fois :
    la forme rotative le neutralise **si elle est elle-même reconnue** et que
    le jeton interne occupe exactement sa charge (longueur et frontière avale
    comprises). Un préfixe ``xoxe.`` suivi d'une charge hors bornes ne peut
    donc pas faire disparaître un jeton interne par avance. La déduplication
    par valeur a lieu après cette neutralisation : le filtrage ne modifie
    jamais l'ensemble des valeurs autonomes conservées.

    .. warning::
       Le retour contient la **valeur brute** du candidat
       (``SignatureMatch.value``). Ces données sont sensibles : ne jamais les
       journaliser, les sérialiser ni les transmettre à un LLM. Le moteur les
       hache immédiatement et ne rend que des ``Finding`` sans valeur.
    """
    rotatifs = _matches_rotatifs(line)
    # Bornes des formes rotatives **effectivement reconnues** : la
    # neutralisation ne teste pas le seul préfixe `xoxe.`, elle exige que la
    # charge complète (longueur et frontière avale) ait été reconnue.
    bornes_rotatives = {(match.start("value"), match.end("value")) for match in rotatifs}
    matches: list[SignatureMatch] = []
    seen: set[tuple[str, str]] = set()
    for rule in RULES:
        rule_matches = rotatifs if rule.id == ROTATING_RULE_ID else rule.matches(line)
        for match in rule_matches:
            if rule.id in ROTATING_INNER_RULE_IDS:
                debut = match.start("value")
                fin = match.end("value")
                if (debut - ROTATING_PREFIX_LEN, fin) in bornes_rotatives:
                    continue
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
                    context_end=match.end("key") if "key" in rule.pattern.groupindex else 0,
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
