"""Heimdall — sentinelle DevSecOps 100 % locale.

Empêche les secrets (mots de passe, clés API, clés privées) de finir dans Git :
scanner déterministe, remédiation agentique locale (MCP/Ollama) et Vault chiffré.

Organisation imposée par le ticket #17 (voir docs/adr/002-stack-python.md) :

- ``heimdall.scanner`` : détection déterministe (regex + entropie de Shannon).
- ``heimdall.mcp`` : serveur MCP stdio, 4 outils en lecture seule.
- ``heimdall.vault`` : client/serveur du Vault ; toute la crypto vit dans
  ``heimdall.vault.crypto`` et nulle part ailleurs.
- ``heimdall.cli`` : point d'entrée ``heimdall`` (Typer).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
