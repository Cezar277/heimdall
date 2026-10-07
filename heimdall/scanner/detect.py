"""Détection déterministe des candidats secrets — squelette du ticket #22.

Le scanner réel (regex de signatures + entropie de Shannon sur les octets
UTF-8, exclusions, garde de chemin avec résolution des liens symboliques)
sera implémenté dans #22 conformément au contrat Finding (#14).
"""

from typing import Literal

FindingStatus = Literal["detecte", "confirme", "vaulte", "rote", "faux_positif"]


def find_candidates(path: str) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (diff stagé ou dépôt).

    Lève ``NotImplementedError`` tant que #22 n'est pas livré (fail-closed :
    aucun résultat partiel silencieux, jamais de verdict inventé).
    """
    raise NotImplementedError(f"scanner non implémenté (voir #22) : {path!r}")
