#!/usr/bin/env python3
"""Régénère ``requirements-runtime.lock`` pour l'image Docker du Vault.

Le lock de développement (``requirements.lock``) contient aussi pytest, mypy,
ruff, bandit, pip-audit, etc. L'image de production ne doit embarquer que le
runtime du Vault et de la CLI ``heimdall``. Ce script extrait la fermeture
transitive des dépendances runtime déclarées dans ``pyproject.toml`` à partir
du lock hashé existant, sans réseau ni résolution de versions.

Usage ::

    python scripts/regen_runtime_lock.py

Le fichier produit reste installable avec ``pip install --require-hashes``.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

RACINE = Path(__file__).resolve().parents[1]
LOCK_DEV = RACINE / "requirements.lock"
LOCK_RUNTIME = RACINE / "requirements-runtime.lock"
PYPROJECT = RACINE / "pyproject.toml"

_BLOCK_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s\\]+)")
_VIA_RE = re.compile(r"^    # via(?: (.*))?$")
_VIA_ENTRY_RE = re.compile(r"^    #   (.*)$")


def _normalise(name: str) -> str:
    """Normalise un nom de distribution (minuscules, underscores -> tirets)."""
    return name.strip().lower().replace("_", "-")


def _parse_blocks(text: str) -> list[dict[str, object]]:
    """Découpe le lock en blocs ``name==version`` avec leurs lignes d'origine."""
    blocks: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in text.splitlines():
        match = _BLOCK_RE.match(line)
        if match:
            if current is not None:
                blocks.append(current)
            current = {
                "name": _normalise(match.group(1)),
                "lines": [line],
                "via": [],
            }
            continue
        if current is None:
            continue
        cast_lines = current["lines"]
        assert isinstance(cast_lines, list)
        cast_lines.append(line)
        via = current["via"]
        assert isinstance(via, list)
        via_match = _VIA_RE.match(line)
        if via_match:
            if via_match.group(1):
                via.append(_normalise(via_match.group(1)))
            continue
        entry_match = _VIA_ENTRY_RE.match(line)
        if entry_match:
            via.append(_normalise(entry_match.group(1)))
    if current is not None:
        blocks.append(current)
    return blocks


def _runtime_roots() -> set[str]:
    """Retourne les dépendances runtime déclarées dans ``pyproject.toml``."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    roots = set()
    for requirement in data["project"]["dependencies"]:
        name = re.split(r"[<>=!~;\[ ]", requirement, maxsplit=1)[0]
        roots.add(_normalise(name))
    # Le backend de build est nécessaire pour ``pip install --no-build-isolation``.
    roots.add("setuptools")
    return roots


def _closure(blocks: list[dict[str, object]], roots: set[str]) -> set[str]:
    """Calcule la fermeture transitive via les commentaires ``# via``."""
    by_name = {str(block["name"]): block for block in blocks}
    children: dict[str, set[str]] = {name: set() for name in by_name}
    for name, block in by_name.items():
        via = block["via"]
        assert isinstance(via, list)
        for parent in via:
            if parent in by_name:
                children[parent].add(name)
    selected: set[str] = set()
    stack = list(roots)
    while stack:
        name = stack.pop()
        if name in selected or name not in by_name:
            continue
        selected.add(name)
        stack.extend(children.get(name, ()))
    missing = roots - selected
    if missing:
        raise SystemExit(f"dépendances runtime absentes du lock : {sorted(missing)}")
    return selected


def main() -> int:
    blocks = _parse_blocks(LOCK_DEV.read_text(encoding="utf-8"))
    selected = _closure(blocks, _runtime_roots())
    header = [
        "# requirements-runtime.lock — dépendances runtime du Vault/CLI.",
        "# Généré depuis requirements.lock par scripts/regen_runtime_lock.py.",
        "# Aucun outil de développement (pytest, mypy, ruff, bandit, pip-audit).",
        "# Installer avec : pip install --require-hashes -r requirements-runtime.lock",
        "",
    ]
    output: list[str] = list(header)
    for block in blocks:
        if str(block["name"]) in selected:
            lines = block["lines"]
            assert isinstance(lines, list)
            output.extend(str(line) for line in lines)
            output.append("")
    tmp = LOCK_RUNTIME.with_name(f"{LOCK_RUNTIME.name}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(output) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, LOCK_RUNTIME)
    print(f"{LOCK_RUNTIME.name} régénéré ({len(selected)} paquets runtime).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
