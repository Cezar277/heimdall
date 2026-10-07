"""Client du Vault — squelette (tickets #25/#26).

Parle au Vault EXCLUSIVEMENT en HTTPS vers une adresse de boucle locale
(invariant 12 ; allowlist : ``127.0.0.1``, ``::1``, ``localhost``), avec
vérification TLS obligatoire (chaîne + SAN, CA interne explicitement
approuvée). Interdit : ``verify=False``, ``-k``, contexte SSL non vérifié,
repli non vérifié, credentials dans l'URL, espaces ou caractères de contrôle
dans l'URL (concaténation ``f"{base_url}/..."`` dangereuse en #25).
Le client conserve son credential dans un stockage local protégé (#26 : mode
600), jamais dans l'URL ni les logs — ``repr()`` est redacté et la clé ne
doit jamais être journalisée.
"""

import re
from urllib.parse import urlparse

_ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class VaultClient:
    """Client HTTPS du Vault (boucle locale uniquement)."""

    def __init__(self, base_url: str, api_key: str) -> None:
        if re.search(r"[\x00-\x20\x7f]", base_url):
            raise ValueError("espaces et contrôles interdits dans l'URL du Vault")
        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            raise ValueError("le Vault n'est joignable qu'en HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("aucun credential dans l'URL du Vault")
        host = (parsed.hostname or "").lower()
        if host not in _ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                "le Vault n'est joignable que sur boucle locale (127.0.0.1, ::1, localhost)"
            )
        self._base_url = base_url
        self._api_key = api_key

    def __repr__(self) -> str:
        return f"VaultClient({self._base_url!r}, api_key=<REDACTED>)"

    def health(self) -> dict[str, object]:
        """Vérifie la santé minimale (ticket #25)."""
        raise NotImplementedError("client Vault non implémenté (voir #25)")
