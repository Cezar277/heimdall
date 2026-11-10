"""Abuse cases Vault : rejeu et force brute — REQ-SEC-05 / REQ-SEC-06 (#19).

Le serveur #25 n'existe pas encore : ces tests prouvent que le CONTRAT
(OpenAPI + docs) impose deja l'anti-rejeu et l'anti-brute-force, et que le
client squelette refuse localement les cibles non loopback / non verifiees.
L'implementation devra prouver le comportement runtime avec module + ligne.
"""

from pathlib import Path

from heimdall.vault.client import VaultClient

REPO = Path(__file__).resolve().parents[2]
OPENAPI = REPO / "openapi.yaml"
VAULT_DOC = REPO / "docs" / "contracts" / "vault-api.md"
CLIENT_SRC = REPO / "heimdall" / "vault" / "client.py"


def test_replay_without_overwrite() -> None:
    """REQ-SEC-05 : rejouer une creation n'ecrase jamais, etat cote serveur."""
    contract = OPENAPI.read_text(encoding="utf-8")
    doc = VAULT_DOC.read_text(encoding="utf-8")
    # Creation sans ecrasement : 409 declare sur le POST collection.
    assert "409" in contract
    assert "Secret déjà existant" in contract
    assert "n'écrase jamais" in contract
    # Aucun etat choisi par le client : pas de PUT/PATCH sur les secrets.
    # DELETE (#158) libère la capacité sans permettre de choisir un état.
    for line in contract.splitlines():
        stripped = line.strip()
        if stripped in ("put:", "patch:"):
            raise AssertionError(f"etat client refuse, methode interdite : {stripped}")
    assert "Aucun endpoint" in contract or "hors v1" in contract
    # Autoriser (projet/env/operation) AVANT toute recherche du secret.
    assert "avant toute recherche" in contract
    assert "de chercher une ressource" in doc
    # 403 independant de l'existence, 404 seulement apres autorisation.
    assert "403" in contract and "404" in contract
    assert "jamais utilisée pour révéler un autre projet" in contract
    # Lecture d'une valeur revoquee interdite (rotation hors v1).
    assert "révoquée" in contract
    assert "sans écrasement" in doc
    assert "409" in doc


def test_bruteforce_rate_limit_and_constant_errors() -> None:
    """REQ-SEC-06 : quotas, 401/403 constants, comparaison sure, TLS verifie."""
    contract = OPENAPI.read_text(encoding="utf-8")
    # Rate-limit : bucket par cle validee, 400/401 inclus, XFF ignore par defaut.
    assert "429" in contract
    assert "Trop de requêtes" in contract
    assert "X-Forwarded-For" in contract
    assert "ignoré" in contract
    assert "Retry-After" in contract
    assert "minimum: 1" in contract and "maximum: 3600" in contract
    # Ticket #111 : la fenêtre est glissante, pas fixe.
    assert "Fenêtre glissante" in contract
    # Erreurs constantes : meme 401 generique, meme 403, sans oracle.
    assert "même réponse 401 générique" in contract
    assert "sans oracle temporel exploitable" in contract
    assert "compare_digest" in contract
    assert "token_urlsafe(32)" in contract
    assert "haché salé" in contract
    assert "jamais sa valeur brute" in contract
    # Corps borne a 1 Mio AVANT parsing JSON.
    assert "1 048 576" in contract or "1048576" in contract
    assert "avant parsing JSON" in contract or "avant le parsing" in contract
    # Reponses sensibles non mises en cache.
    assert "no-store" in contract
    doc = VAULT_DOC.read_text(encoding="utf-8")
    assert "compare_digest" in doc
    assert "verify=False" in doc  # cite comme interdit
    assert "interdit de désactiver" in doc
    # Tickets #111/#113/#114 : fenêtre glissante, journal d'audit et rejeu.
    assert "fenêtre glissante" in doc
    assert "Journal d'audit" in doc
    assert "audit_events" in doc
    assert "Rejeu de requête" in doc
    assert "409" in doc and "révocation" in doc
    # Client : loopback canonique uniquement, refus local avant tout envoi.
    good = VaultClient("https://127.0.0.1:8443", "SYNTHETIC_API_KEY_01")
    assert "127.0.0.1" in repr(good)
    assert "SYNTHETIC_API_KEY_01" not in repr(good)  # redaction
    for bad_url in (
        "http://127.0.0.1:8443",
        "https://192.168.0.10:8443",
        "https://example.com:8443",
        "https://127.0.0.1:8443/?q=SYNTHETIC",
        "https://127.0.0.1:8443/#frag",
        "https://user:SYNTHETIC@127.0.0.1:8443",
        "https://127.0.0.1:8443/%2e%2e",
        "https://127.0.0.1:99999",
        "https://127.0.0.1:8443/",
    ):
        try:
            VaultClient(bad_url, "SYNTHETIC_API_KEY_01")
        except ValueError:
            continue
        raise AssertionError(f"URL non loopback/canonical acceptee : {bad_url}")
    try:
        VaultClient("https://127.0.0.1:8443", "   ")
    except ValueError:
        pass
    else:
        raise AssertionError("cle blanche acceptee")
