"""Depuis la racine après installation editable: python tests/measure_trap.py."""

import json
import sys
import tempfile
from pathlib import Path


def main():
    """0: seuils atteints; 1: seuils non atteints; 2: mesure impossible."""
    try:
        # L'import fait partie de la mesure : dépendance absente => code 2.
        from support.trap_corpus import scan_corpus  # noqa: PLC0415

        with tempfile.TemporaryDirectory(prefix="heimdall-t21-") as directory:
            report = scan_corpus(Path(directory))
        result = int(report["core"]["precision"] < 0.9 or report["core"]["recall"] < 0.9)
        print(json.dumps(report, indent=2))
        return result
    except NotImplementedError:
        print("Scanner T22 non livré: précision/rappel indisponibles.")
        return 2
    except Exception:
        # Frontière CLI uniquement : ne jamais refléter l'exception ou un secret.
        print("Mesure impossible : erreur interne, aucun verdict disponible.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
