"""Initialisation à froid de la base SQLite du Vault Heimdall (ticket #25 / #62).

Ce script crée depuis zéro la structure SQLite (tables `projects`, `api_keys`, `secrets`
et leurs index) requise par le Vault.

Usage :
    python -m heimdall.vault.init_db [--db-path CHEMIN]
"""

import argparse
import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path

from heimdall.vault.database import DEFAULT_DB_PATH, init_db, resolve_db_path

# Chemin absolu (POSIX `/...` ou Windows `C:\...`), guillemets et parenthèses
# exclus : capturé pour être réduit à son basename avant tout affichage verbose
# (anti-fuite d'empreinte de l'environnement, invariant 8).
_ABSOLUTE_PATH_TOKEN_RE: re.Pattern[str] = re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\s'\"(),;]*")


def _basename_token(token: str) -> str:
    """Réduit un jeton de chemin à son dernier composant (gère `/` et `\\`)."""
    trimmed = token.rstrip("/\\")
    return re.split(r"[\\/]", trimmed)[-1] or token


def _sanitize_error_message(
    exc: BaseException,
    candidates: Iterable[str | Path | None],
) -> str:
    """Assainit le détail d'erreur affiché par `--verbose` (aucun chemin FS en sortie).

    - Seule la première ligne du message est conservée.
    - Chaque chemin candidat connu (argument `--db-path`, variable
      `HEIMDALL_VAULT_DB_PATH`, chemin résolu et sa forme absolue) est remplacé
      par son basename, y compris lorsque le chemin contient des espaces.
    - Tout chemin absolu résiduel est réduit à son basename (défense en
      profondeur : couvre le chemin par défaut `vault.db` et les chemins non
      déclarés remontés par une `OSError`/`sqlite3.OperationalError` native).
    """
    raw_message = str(exc)
    message = raw_message.splitlines()[0] if raw_message else ""
    known_paths = sorted(
        (
            str(candidate)
            for candidate in candidates
            if candidate is not None and str(candidate).strip()
        ),
        key=len,
        reverse=True,
    )
    for known in known_paths:
        message = message.replace(known, _basename_token(known))
    return _ABSOLUTE_PATH_TOKEN_RE.sub(
        lambda match: _basename_token(match.group(0)),
        message,
    )


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée CLI pour initialiser à froid la base SQLite."""
    parser = argparse.ArgumentParser(
        description="Initialisation à froid de la base de données SQLite du Vault Heimdall (#62).",
        epilog=(
            "Codes de retour : 0 (succès), 1 (erreur d'initialisation ou permissions), "
            "2 (chemin relatif ou mode ':memory:' interdit en CLI)."
        ),
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help=(
            "Chemin ABSOLU du fichier SQLite "
            f"(défaut : {DEFAULT_DB_PATH} ou $HEIMDALL_VAULT_DB_PATH)."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Affiche le détail technique de l'erreur en cas d'échec.",
    )
    args = parser.parse_args(argv)
    # Refus ':memory:' AVANT résolution : couvre l'argument `--db-path` ET la
    # variable d'environnement (que `resolve_db_path` refuse désormais aussi).
    raw_db_path = (
        args.db_path if args.db_path is not None else os.environ.get("HEIMDALL_VAULT_DB_PATH")
    )
    if raw_db_path is not None and str(raw_db_path).strip() == ":memory:":
        print(
            "Erreur : le mode ':memory:' est réservé aux tests via API et est interdit en CLI.",
            file=sys.stderr,
        )
        return 2
    resolved: Path | str | None = None
    try:
        resolved = resolve_db_path(args.db_path)
        if isinstance(resolved, Path) and not resolved.is_absolute():
            print(
                "Erreur : chemin absolu requis (un chemin relatif dépend du répertoire courant).",
                file=sys.stderr,
            )
            return 2
        init_db(resolved)
        print("Base de données SQLite du Vault initialisée avec succès.")
        return 0
    except Exception as exc:
        print("Erreur : échec de l'initialisation de la base de données SQLite.", file=sys.stderr)
        if args.verbose:
            candidates: list[str | Path | None] = [
                args.db_path,
                os.environ.get("HEIMDALL_VAULT_DB_PATH"),
                resolved,
            ]
            if isinstance(resolved, Path):
                absolute_path = resolved.absolute()
                candidates.append(absolute_path)
                candidates.append(Path(os.path.normpath(str(resolved))))
                candidates.append(Path(os.path.normpath(str(absolute_path))))
            detail = _sanitize_error_message(exc, candidates)
            print(f"Détail [{exc.__class__.__name__}] : {detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
