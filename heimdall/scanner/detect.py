"""Détection déterministe des candidats secrets — squelette du ticket #22.

Le scanner réel (regex de signatures + entropie de Shannon sur les octets
UTF-8, exclusions, garde de chemin avec résolution des liens symboliques)
sera implémenté dans #22 conformément au contrat Finding (#14).

L'interface est figée par #53 et vit dans deux modules :

- ``heimdall.scanner.interface`` : la cible d'analyse (``DiffTarget`` pour
  les lignes ajoutées du diff indexé, ``FileTarget`` pour un fichier entier)
  et la méthode ``scan(cible) -> list[Finding]`` ;
- ``heimdall.scanner.finding`` : la sortie, conforme au schéma #14 **par
  construction** (aucune valeur de secret, aucun champ surnuméraire).

Ce module ne garde que le point d'entrée historique ``find_candidates``, qui
reste fail-closed tant que #22 n'est pas livré : aucune liste partielle, jamais
de verdict inventé.
"""

from heimdall.scanner.finding import Finding, FindingSource, FindingStatus

__all__ = ["Finding", "FindingSource", "FindingStatus", "find_candidates"]


def find_candidates(path: str) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (diff stagé ou dépôt).

    Lève ``NotImplementedError`` tant que #22 n'est pas livré (fail-closed :
    aucun résultat partiel silencieux, jamais de verdict inventé). Message
    statique : aucune entrée n'est reflétée (invariant 8).

    La forme de retour est celle du contrat #14 : un dictionnaire par
    candidat, exactement les sept champs de ``schemas/finding.schema.json``.
    """
    del path  # #22 utilisera ce paramètre ; en attendant, rien n'est reflété.
    raise NotImplementedError("scanner non implémenté (voir #22)")
