"""Healthcheck local du conteneur Vault (#119).

Le Vault n'écoute que sur la boucle locale. Ce script interroge
``/api/v1/health`` en HTTP ou HTTPS selon la configuration TLS, en vérifiant le
certificat local (SAN ``127.0.0.1``) quand TLS est actif. Aucun secret n'est lu
ni affiché : seuls les chemins de certificat fournis par l'environnement sont
utilisés.
"""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request

_PORT_DEFAULT = "8443"
_TIMEOUT_SECONDS = 2


def main() -> int:
    port = os.environ.get("HEIMDALL_VAULT_PORT", _PORT_DEFAULT)
    certfile = os.environ.get("HEIMDALL_VAULT_SSL_CERTFILE")
    scheme = "https" if certfile else "http"
    url = f"{scheme}://127.0.0.1:{port}/api/v1/health"
    context = ssl.create_default_context(cafile=certfile) if certfile else None
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT_SECONDS, context=context) as response:
            return 0 if response.status == 200 else 1
    except Exception:
        # Message générique : jamais de chemin, de certificat ni de secret.
        print("healthcheck: indisponible", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
