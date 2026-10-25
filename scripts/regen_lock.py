#!/usr/bin/env python3
"""Régénère ``requirements.lock`` de façon reproductible.

Deux contraintes ne sont pas exprimables par un seul appel ``pip-compile`` :

1. L'en-tête français du lock est remplacé par pip-compile ; on le restaure.
2. ``filelock`` doit être épinglé deux fois selon l'interpréteur :
   ``4.1.0`` est la dernière version compatible Python 3.10, mais elle porte
   six CVE corrigées dans ``4.2.1`` (qui exige Python >= 3.11). Un lock généré
   sous 3.10 ne peut donc pas sélectionner la version corrigée ; on ajoute un
   pin marqué pour que les environnements 3.11+ installent la version saine.

À lancer avec l'interpréteur 3.10 qui porte pip-tools ::

    python scripts/regen_lock.py

Le script est idempotent et échoue si la forme attendue du bloc filelock
change (nouvelle version compatible 3.10, etc.), pour éviter un lock
silencieusement vulnérable.
"""

from __future__ import annotations

import subprocess  # nosec B404
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCK = REPO_ROOT / "requirements.lock"

HEADER = """# requirements.lock — dépendances et outils vérifiés par hashes SHA-256.
# Ticket #20 : `pip` et `setuptools` sont inclus via `--allow-unsafe` pour
# verrouiller aussi le bootstrap et le backend editable (sans build isolation).
# Installer :
#   python3 -m venv .venv
#   .venv/bin/pip install --require-hashes -r requirements.lock
#   .venv/bin/pip install -e . --no-deps --no-build-isolation
# Régénérer sous Python 3.10 (script : en-tête + pin filelock double) :
#   python scripts/regen_lock.py
"""

FILELOCK_310 = 'filelock==4.1.0 ; python_version < "3.11" \\\n'
FILELOCK_310_PLAIN = "filelock==4.1.0"
FILELOCK_COMPAT = """\
# Compatibilité Python 3.10 : 4.2.1+ exige >= 3.11 (correctifs CVE filelock).
filelock==4.2.4 ; python_version >= "3.11" \\
    --hash=sha256:301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e \\
    --hash=sha256:c6d8663535e1650ee430507b4ffbac7b464dd64b7647ea0112a9f406499d163d
    # via cachecontrol
"""


def _run_pip_compile() -> None:
    # Chemins *relatifs* + cwd=racine : pip-compile les recopie tels quels dans
    # ses commentaires ``# via heimdall (pyproject.toml)``, ce qui garde le lock
    # identique quel que soit le répertoire de travail (worktree, CI, local).
    subprocess.run(  # noqa: S603  # nosec B603 - argv figé, pas de shell
        [
            sys.executable,
            "-m",
            "piptools",
            "compile",
            "--allow-unsafe",
            "--generate-hashes",
            "--extra",
            "dev",
            "-o",
            LOCK.name,
            "pyproject.toml",
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def _restore_header(text: str) -> str:
    lines = text.splitlines(keepends=True)
    if lines and lines[0].strip() == "#":
        lines = lines[1:]
    return HEADER + "".join(lines)


def _pin_filelock(text: str) -> str:
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.startswith("filelock==")), None)
    if start is None:
        raise SystemExit("requirements.lock ne contient aucun bloc filelock")

    end = start + 1
    while end < len(lines) and (lines[end].startswith(("    ", "#")) or not lines[end].strip()):
        end += 1
    block = lines[start:end]

    if any(
        line.startswith("filelock==") and "python_version >= " in line for line in lines
    ):
        return text  # déjà traité

    # pip-compile écrit ``filelock==4.1.0 \`` (continuation de hashes) : on
    # compare le requirement nu, sans le backslash de continuation.
    current = block[0].rstrip("\n").removesuffix(" \\")
    if current not in (FILELOCK_310_PLAIN, FILELOCK_310.rstrip("\n").removesuffix(" \\")):
        raise SystemExit(
            f"forme filelock inattendue : {block[0]!r}. "
            "Mettre à jour FILELOCK_310/FILELOCK_COMPAT dans scripts/regen_lock.py."
        )

    block[0] = FILELOCK_310
    return "".join(lines[:start] + block + [FILELOCK_COMPAT] + lines[end:])


def main() -> int:
    _run_pip_compile()
    text = _restore_header(LOCK.read_text(encoding="utf-8"))
    text = _pin_filelock(text)
    LOCK.write_text(text, encoding="utf-8")
    print(f"{LOCK} régénéré (en-tête restauré, filelock 3.10/3.11+ épinglé).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
