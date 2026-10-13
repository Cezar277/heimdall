"""Entrée console du serveur MCP : ``python -m heimdall.mcp --root <dépôt>``.

Le serveur parle le protocole MCP sur stdio : **rien d'autre** ne doit
être écrit sur stdout, sous peine de casser le canal. Tout diagnostic va
donc sur stderr, et la sortie du processus est 0 (arrêt propre), 2 (outil
mal lancé : racine absente ou git introuvable).
"""

import argparse
import sys

from heimdall.mcp.server import run_stdio


def main(argv: list[str] | None = None) -> int:
    """Démarre le serveur MCP confiné à ``--root``."""
    parser = argparse.ArgumentParser(
        prog="heimdall.mcp",
        description="Serveur MCP stdio d'Heimdall (outils en lecture seule, contrat #16).",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Racine du dépôt à exposer. Fixée au démarrage, jamais fournie par le LLM.",
    )
    args = parser.parse_args(argv)
    try:
        run_stdio(args.root)
    except ValueError as exc:
        # Message statique (racine invalide) : aucune entrée reflétée.
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
