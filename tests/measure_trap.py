"""Depuis la racine après installation editable: python tests/measure_trap.py."""

import json
import tempfile
from pathlib import Path

from support.trap_corpus import scan_corpus


def main():
    with tempfile.TemporaryDirectory(prefix="heimdall-t21-") as directory:
        try:
            report = scan_corpus(Path(directory))
        except NotImplementedError:
            print("Scanner T22 non livré: précision/rappel indisponibles.")
            return 2
    print(json.dumps(report, indent=2))
    return int(report["core"]["precision"] < 0.9 or report["core"]["recall"] < 0.9)


if __name__ == "__main__":
    raise SystemExit(main())
