"""Entrypoint du conteneur Vault (#119/#120).

Le Vault ne doit jamais tourner en root : l'image définit ``USER 10001:10001``
et le compose fige ``user: "10001:10001"``. Ce garde refuse explicitement
``euid == 0`` ou ``egid == 0`` (par exemple en cas de surcharge manuelle
``--user 0``) avant de lancer le serveur. Aucun secret n'est lu ni affiché.
"""

from __future__ import annotations

import os
import sys

_REFUS_ROOT = "refus: le conteneur Vault ne doit pas tourner en root"


def main() -> int:
    if os.geteuid() == 0 or os.getegid() == 0:
        print(_REFUS_ROOT, file=sys.stderr)
        return 1
    os.execvp(sys.executable, [sys.executable, "-m", "heimdall.vault.app"])
    return 1


if __name__ == "__main__":
    sys.exit(main())
