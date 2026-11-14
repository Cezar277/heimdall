"""Bornes communes du scanner (#229) : une seule source pour les 4 Kio.

Les jetons, les lignes et les jointures multilignes partagent la même fenêtre
de 4096 octets. Centraliser la valeur évite qu'une évolution d'une seule
borne rouvre une jointure contournable ou un jeton non borné.
"""

from __future__ import annotations

from typing import Final

#: Fenêtre maximale (4 Kio) d'un jeton, d'une ligne ou d'une jointure.
TEXT_WINDOW_BYTES: Final[int] = 4096

#: Alias historiques : même borne, noms conservés pour les appelants.
MAX_TOKEN_LENGTH: Final[int] = TEXT_WINDOW_BYTES
MULTILINE_WINDOW: Final[int] = TEXT_WINDOW_BYTES
