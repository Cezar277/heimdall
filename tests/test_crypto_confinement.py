"""Confinement crypto : `cryptography`/`argon2` uniquement dans heimdall/vault. (#17)

Piège du ticket : « Importer la crypto partout ». Ce test balaie les sources
du paquet (hors `.venv`) et échoue si un module hors `heimdall/vault/`
importe une librairie crypto. Preuve SAMM : cycle de vie, module + ligne.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "heimdall"
VAULT = PKG / "vault"
PATTERN = re.compile(r"^\s*(import|from)\s+(cryptography|argon2)(\.|[\s])", re.MULTILINE)


class CryptoConfinementTests(unittest.TestCase):
    def test_crypto_imports_confined_to_vault(self) -> None:
        offenders = [
            path.relative_to(ROOT).as_posix()
            for path in sorted(PKG.rglob("*.py"))
            if VAULT not in path.parents and PATTERN.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_crypto_module_exists(self) -> None:
        self.assertTrue((VAULT / "crypto.py").is_file())


if __name__ == "__main__":
    unittest.main()
