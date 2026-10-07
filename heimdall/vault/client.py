"""Client du Vault — squelette (tickets #25/#26).

Parle au Vault EXCLUSIVEMENT en HTTPS avec vérification TLS obligatoire
(chaîne + SAN, CA interne explicitement approuvée). Interdit : ``verify=False``,
``-k``, contexte SSL non vérifié, repli non vérifié. Le client conserve son
credential dans un stockage local protégé, jamais dans l'URL ni les logs.
"""


class VaultClient:
    """Client HTTPS du Vault (réseau privé)."""

    def __init__(self, base_url: str, api_key: str) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("le Vault n'est joignable qu'en HTTPS")
        self._base_url = base_url
        self._api_key = api_key

    def health(self) -> dict[str, object]:
        """Vérifie la santé minimale (ticket #25)."""
        raise NotImplementedError("client Vault non implémenté (voir #25)")
