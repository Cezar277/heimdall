"""Entropie de Shannon du contrat Finding (#14).

La mesure porte sur les octets UTF-8 du candidat, en bits par octet (0 à 8).
Ce module fournit la métadonnée ``entropy`` ; il ne déclenche aucun Finding :
la détection par seuil d'entropie appartient au ticket #23.
"""

from __future__ import annotations

import math
from typing import Final

_MAX_ENTROPY: Final[float] = 8.0


def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon de ``data`` en bits par octet.

    Une entrée vide a une entropie nulle. Le résultat est borné à 8 bits par
    octet, y compris face à un arrondi flottant.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return min(_MAX_ENTROPY, max(0.0, entropy))
