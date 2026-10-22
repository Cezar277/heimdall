"""Entropie de Shannon d'un candidat, métadonnée du Finding (#14).

La mesure porte sur les octets UTF-8, en bits par octet (0 à 8). Ce module ne
déclenche aucun Finding : il fournit seulement le champ ``entropy``.
"""

from __future__ import annotations

import math
from typing import Final

_MAX_ENTROPY: Final[float] = 8.0


def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon de ``data``, en bits par octet (0 à 8).

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
