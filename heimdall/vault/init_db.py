"""Initialisation à froid de la base SQLite du Vault Heimdall (ticket #25 / #62).

Ce script crée depuis zéro la structure SQLite (tables `projects`, `api_keys`, `secrets`
et leurs index) requise par le Vault.

Usage :
    python -m heimdall.vault.init_db [--db-path CHEMIN]
"""

import argparse
import sys
from pathlib import Path

from heimdall.vault.database import DEFAULT_DB_PATH, init_db, resolve_db_path


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée CLI pour initialiser à froid la base SQLite."""
    parser = argparse.ArgumentParser(
        description="Initialisation à froid de la base de données SQLite du Vault Heimdall (#62).",
        epilog=(
            "Codes de retour : 0 (succès), 1 (erreur d'initialisation ou permissions), "
            "2 (mode ':memory:' interdit en CLI)."
        ),
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help=f"Chemin du fichier SQLite (défaut : {DEFAULT_DB_PATH} ou $HEIMDALL_VAULT_DB_PATH).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Affiche le détail technique de l'erreur en cas d'échec.",
    )
    args = parser.parse_args(argv)
    try:
        resolved = resolve_db_path(args.db_path)
        if resolved == ":memory:":
            print(
                "Erreur : le mode ':memory:' est réservé aux tests via API et est interdit en CLI.",
                file=sys.stderr,
            )
            return 2
        init_db(resolved)
        print("Base de données SQLite du Vault initialisée avec succès.")
        return 0
    except Exception as exc:
        print("Erreur : échec de l'initialisation de la base de données SQLite.", file=sys.stderr)
        if args.verbose:
            exc_type = exc.__class__.__name__
            msg = str(exc).splitlines()[0] if str(exc) else ""
            if args.db_path:
                msg = msg.replace(str(args.db_path), Path(args.db_path).name)
            print(f"Détail [{exc_type}] : {msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
