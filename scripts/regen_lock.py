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

RPDS_310 = 'rpds-py==0.30.0 ; python_version < "3.11" \\\n'
RPDS_310_PLAIN = "rpds-py==0.30.0"
RPDS_COMPAT = """\
# Compatibilité Python 3.10 : 2026.x exige >= 3.11 (wheels cp315 pour Docker).
rpds-py==2026.9.1 ; python_version >= "3.11" \\
    --hash=sha256:07deecbfce94c78473018bc7d10b337cc651d12df87a1eb2cb3e4024bc9c33d0 \\
    --hash=sha256:0da298fb372dc192610a4b9ecbc68a0cd8b675bbbd1fc519d01b41cfd658333e \\
    --hash=sha256:136a1c3fe4402b7008bc81cb62ee538481795b61a7e83df88dff3b3f02b726ff \\
    --hash=sha256:1d55198263bb51f557550c6ed2e6d1cb6a6fed6eb5c9120b741c5926bef8a45d \\
    --hash=sha256:2693b2728bbcc48d09a981a356954b0c47c53ff25b545856f28a889ea619f69a \\
    --hash=sha256:270bdcdaac5d5b6f73c5e22e7e135c7f2a50e789f71d9e241d5be8d90026e19a \\
    --hash=sha256:2c16ab111bc27c646ba8aa005d0527754edc538ebb636f0b1bf8e244b48d1945 \\
    --hash=sha256:457866b85daf5034296666168b84a69e0b2e89dc4f1af102b46f6448a60b9063 \\
    --hash=sha256:4793ef7f78268b124b73fa933440f01d258bbae01de9fa53e9080c9ab0425a12 \\
    --hash=sha256:4c0d2cb595a420b34d5086db0add011e26e2c09d6a024afbac4228bf8f863a30 \\
    --hash=sha256:6cdc537c8633d7fd92a82e2e0d2ab74320a3f63d5e59fb9cf08711e08fe151c4 \\
    --hash=sha256:7868b85224291c6cb6759f9b5adb9745f486d226f62b16a614dd5a2a5ab2b35b \\
    --hash=sha256:addeda51556dac7c1a2f14cda62db8b621cd12afba3091d03a96c72932387eab \\
    --hash=sha256:cdeaa99ce822dca76cfb1b993e9120c5ea212f2eb66d48950ad63c349668a018 \\
    --hash=sha256:d1028417bb44037eb3069c1009bd7b7277212876cda22fbe565b0bca9fab6d2c \\
    --hash=sha256:d7fca4eb6df565e2a928f1c7dad92d27db8f9df0f449e76423ed5d7e713ed445 \\
    --hash=sha256:e01b3c878c8641913e688edd1b3f08658c6783d29cf6b826bd3c0d1ae7a1ffaa \\
    --hash=sha256:eac2f5dbafd585dfe31f86a23ebf0d3ba480a9d49ebc87947267b5608d4ea0cd \\
    --hash=sha256:ec450527cbf485e13c8d3602a54f428ab0432fdade0ede75efd74b735421c871
    # via
    #   jsonschema
    #   referencing
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


def _pin_py311_compat(
    text: str,
    package: str,
    plain_310: str,
    marker_310: str,
    compat_block: str,
) -> str:
    """Ajoute un pin conditionnel ``>= 3.11`` pour un paquet bloqué en 3.10."""
    lines = text.splitlines(keepends=True)
    prefix = f"{package}=="
    start = next((i for i, line in enumerate(lines) if line.startswith(prefix)), None)
    if start is None:
        raise SystemExit(f"requirements.lock ne contient aucun bloc {package}")

    end = start + 1
    while end < len(lines) and (lines[end].startswith(("    ", "#")) or not lines[end].strip()):
        end += 1
    block = lines[start:end]

    if any(line.startswith(prefix) and "python_version >= " in line for line in lines):
        return text  # déjà traité

    # pip-compile écrit ``<pkg>==<ver> \`` (continuation de hashes) : on
    # compare le requirement nu, sans le backslash de continuation.
    current = block[0].rstrip("\n").removesuffix(" \\")
    if current not in (plain_310, marker_310.rstrip("\n").removesuffix(" \\")):
        raise SystemExit(
            f"forme {package} inattendue : {block[0]!r}. "
            f"Mettre à jour la constante dans scripts/regen_lock.py."
        )

    block[0] = marker_310
    return "".join(lines[:start] + block + [compat_block] + lines[end:])


def main() -> int:
    _run_pip_compile()
    text = _restore_header(LOCK.read_text(encoding="utf-8"))
    text = _pin_py311_compat(
        text, "filelock", FILELOCK_310_PLAIN, FILELOCK_310, FILELOCK_COMPAT
    )
    text = _pin_py311_compat(
        text, "rpds-py", RPDS_310_PLAIN, RPDS_310, RPDS_COMPAT
    )
    LOCK.write_text(text, encoding="utf-8")
    print(f"{LOCK} régénéré (en-tête restauré, filelock et rpds-py 3.10/3.11+ épinglés).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
