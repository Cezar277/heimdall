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


def _validated_port() -> str | None:
    """Retourne un port valide ou ``None`` sans refléter la valeur reçue."""
    raw = os.environ.get("HEIMDALL_VAULT_PORT", _PORT_DEFAULT).strip()
    if not raw.isdigit():
        return None
    port = int(raw)
    if not 1 <= port <= 65535:
        return None
    return str(port)


def main() -> int:
    port = _validated_port()
    if port is None:
        print("healthcheck: configuration invalide", file=sys.stderr)
        return 1
    certfile = os.environ.get("HEIMDALL_VAULT_SSL_CERTFILE")
    scheme = "https" if certfile else "http"
    url = f"{scheme}://127.0.0.1:{port}/api/v1/health"
    handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({})]
    if certfile:
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certfile))
        )
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(url, timeout=_TIMEOUT_SECONDS) as response:
            return 0 if response.status == 200 else 1
    except Exception:
        # Message générique : jamais de chemin, de certificat ni de secret.
        print("healthcheck: indisponible", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
