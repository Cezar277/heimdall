"""Confinement crypto : `cryptography`/`argon2` UNIQUEMENT dans vault/crypto.py. (#17)

Invariant 5 : tout import direct, `from`-import ou chargement dynamique
(`__import__`, `importlib.import_module`) d'une lib crypto hors
`heimdall/vault/crypto.py` fait échouer la suite. Détection par AST (pas de
regex contournable) + méta-tests du détecteur sur extraits piégés.
Preuve SAMM : cycle de vie, module + ligne.
"""

import ast
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "heimdall"
CRYPTO_LIBS = frozenset({"cryptography", "argon2"})


def _call_loads_crypto(node: ast.Call) -> bool:
    """Vrai si l'appel charge explicitement une lib crypto par son nom."""
    func = node.func
    if isinstance(func, ast.Name):
        qualified = func.id
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        qualified = f"{func.value.id}.{func.attr}"
    else:
        return False
    if qualified not in {"__import__", "importlib.import_module", "import_module"}:
        return False
    return any(
        isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and arg.value.split(".")[0] in CRYPTO_LIBS
        for arg in node.args[:1]
    )


def imports_crypto_lib(source: str) -> bool:
    """Détecte tout chargement d'une lib crypto dans un source Python."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True  # fail-closed : un fichier illisible est signalé, pas ignoré.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in CRYPTO_LIBS for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in CRYPTO_LIBS:
                return True
        elif isinstance(node, ast.Call) and _call_loads_crypto(node):
            return True
    return False


def find_offenders(package_root: pathlib.Path) -> list[pathlib.Path]:
    """Modules chargeant une lib crypto hors `vault/crypto.py` (vide = OK)."""
    crypto = package_root / "vault" / "crypto.py"
    return sorted(
        path
        for path in package_root.rglob("*.py")
        if path != crypto and imports_crypto_lib(path.read_text(encoding="utf-8"))
    )


class CryptoConfinementTests(unittest.TestCase):
    def test_repo_confinement(self) -> None:
        offenders = [path.relative_to(ROOT).as_posix() for path in find_offenders(PKG)]
        self.assertEqual(offenders, [])

    def test_detector_catches_import_forms(self) -> None:
        cases = {
            "import cryptography": True,
            "from cryptography.hazmat.primitives import hashes": True,
            "import argon2": True,
            "from argon2 import PasswordHasher": True,
            '__import__("cryptography")': True,
            "import importlib\nimportlib.import_module('argon2')": True,
            "from importlib import import_module\nimport_module('cryptography')": True,
            "import os": False,
            "import httpx": False,
            "x = 'cryptography'  # simple chaîne, pas un chargement": False,
            "# import cryptography (commentaire)": False,
            "": False,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(imports_crypto_lib(source), expected)

    def test_detector_catches_dynamic_import_in_vault_client(self) -> None:
        """Si `vault/client.py` chargeait de la crypto (même via importlib),
        le garde le signalerait : preuve sur arborescence synthétique."""
        with tempfile.TemporaryDirectory(prefix="heimdall-crypto-") as tmp:
            package = pathlib.Path(tmp) / "heimdall"
            vault = package / "vault"
            vault.mkdir(parents=True)
            (vault / "crypto.py").write_text('"""Crypto."""\n', encoding="utf-8")
            client = vault / "client.py"
            client.write_text(
                '"""Client."""\nimport importlib\n_lib = importlib.import_module("cryptography")\n',
                encoding="utf-8",
            )
            offenders = find_offenders(package)
            self.assertEqual(offenders, [client])

    def test_crypto_module_exists(self) -> None:
        self.assertTrue((PKG / "vault" / "crypto.py").is_file())


if __name__ == "__main__":
    unittest.main()
