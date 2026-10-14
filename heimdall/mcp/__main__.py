"""Entrée console du serveur MCP : ``python -m heimdall.mcp --root <dépôt>``.

Le serveur parle le protocole MCP sur stdio : **rien d'autre** ne doit
être écrit sur stdout, sous peine de casser le canal. Tout diagnostic va
donc sur stderr, et la sortie du processus est 0 (arrêt propre), 2 (outil
mal lancé : racine absente ou git introuvable).
"""

import argparse
import sys

from heimdall.mcp.server import run_stdio


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Options de lancement, séparées du démarrage (testable sans bloquer)."""
    parser = argparse.ArgumentParser(
        prog="heimdall.mcp",
        description="Serveur MCP stdio d'Heimdall (outils en lecture seule, contrat #16).",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Racine du dépôt à exposer. Fixée au démarrage, jamais fournie par le LLM.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Démarre le serveur MCP confiné à ``--root``."""
    args = parse_args(argv)
    try:
        run_stdio(args.root)
    except BrokenPipeError:
        return 0
    except ValueError as exc:
        # Message statique (racine invalide) : aucune entrée reflétée.
        print(str(exc), file=sys.stderr)
        return 2
    except Exception:
        # Échec inattendu au démarrage : message statique seul (invariant 8).
        print("erreur au démarrage du serveur MCP", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - garde d'exécution, couverte en sous-processus.
    sys.exit(main())
