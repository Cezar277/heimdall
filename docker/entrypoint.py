"""Entrypoint du conteneur Vault (#119/#120).

Le Vault ne doit jamais tourner en root : l'image définit ``USER 10001:10001``
et le compose utilise l'UID/GID de l'hôte. Ce garde refuse explicitement
``euid == 0`` (par exemple si ``HEIMDALL_UID=0`` est mis dans ``.env``) avant
de lancer le serveur. Aucun secret n'est lu ni affiché.
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
