"""Client LLM local (Ollama) — orchestration hors du serveur MCP.

Le serveur MCP (``heimdall.mcp``) est un sous-processus stdio sans réseau ;
c'est la CLI qui parle au LLM local (``127.0.0.1`` uniquement, voir
``heimdall.llm.qualify``). Le prompt et le schéma de sortie versionnés
vivent dans ``heimdall.mcp.prompts``.
"""
