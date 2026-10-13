"""Tests de la garde de chemin — sous-tickets #76 et #77 (contrat #16, I2).

La garde est la petite fonction dont dépend la sécurité du MCP **et** de la
remédiation (#30) : elle est testée avec les astuces classiques
d'évasion — ``..``, chemins absolus, liens symboliques, caractères
interdits — sur un vrai système de fichiers (``tmp_path``), pas sur des
chemins imaginaires.

Chaque cas rejeté est une ligne du tableau : un cas par ligne, lisible en
revue comme en rapport.
"""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from support import mcp_contract

from heimdall.mcp.paths import PathEscape, confine, is_rel_path

# Cas qui DOIVENT être refusés. Chaque entrée est une astuce distincte,
# pas une variante cosmétique de la précédente.
EVASION_CASES: tuple[Any, ...] = (
    # Traversée de répertoire : la valeur monte puis redescend ailleurs.
    "../secret",
    "../../etc/passwd",
    "sub/../../secret",
    "..",
    ".",
    "./relatif",
    "relatif/.",
    "relatif/..",
    "double//slash",
    "slash/final/",
    # Chemins absolus, toutes familles de systèmes.
    "/etc/passwd",
    "/",
    "C:/Windows/system32",
    "C:\\Windows",
    "\\\\serveur\\partage",
    "file:///etc/passwd",
    # Caractères interdits par la grammaire ou vecteurs d'injection.
    "avec\ttabulation",
    "avec\nsaut",
    "avec\x00nul",
    "retour\rchariot",
    "back\\slash",
    "deux:points",
    # Types non textuels : la garde n'a rien à résoudre.
    None,
    12,
    b"octets",
    ["liste"],
    {"dict": "ionnaire"},
    "",
    # Chemins trop longs : un chemin d'un kilooctet est une attaque.
    "x" * 1025,
)

# Cas qui DOIVENT passer : chemins normaux, y compris dans un sous-dossier.
ACCEPTED_CASES = (
    "ok.py",
    "sous/dossier/ok.py",
    "sous/dossier/tres/profond/ok.py",
    "nom avec espace.py",
    "nom-avec_tiret2024.py",
)

# Sous-dossier voisin dont le nom commence comme la racine : piège classique
# d'une garde bâtie sur `startswith` (``/repo-evil`` commence par ``/repo``).
SIBLING_NAME = "repo-evil"


class GuardTestCase(unittest.TestCase):
    """Arborescence réelle : racine, sous-dossiers, liens sortants, voisin."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-garde-")
        self.addCleanup(self._tmp.cleanup)
        workspace = Path(self._tmp.name).resolve()
        self.root = workspace / "repo"
        (self.root / "sous" / "dossier" / "tres" / "profond").mkdir(parents=True)
        (self.root / "ok.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "sous" / "dossier" / "ok.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "sous" / "dossier" / "tres" / "profond" / "ok.py").write_text(
            "x = 1\n", encoding="utf-8"
        )
        (self.root / "nom avec espace.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "nom-avec_tiret2024.py").write_text("x = 1\n", encoding="utf-8")

        # Voisin au nom préfixe : traverser vers lui doit échouer.
        self.sibling = workspace / SIBLING_NAME
        self.sibling.mkdir()
        (self.sibling / "secret").write_text("x = 1\n", encoding="utf-8")

        # Lien symbolique du dépôt vers l'extérieur : refusé après résolution.
        os.symlink("/etc", self.root / "lien-etc")
        # Lien symbolique du dépôt vers l'intérieur : autorisé, mais le chemin
        # renvoyé est canonique (pas le nom du lien).
        os.symlink(self.root / "sous", self.root / "lien-interne")
        # Fichier réel dont le nom contient un caractère interdit.
        (self.root / "avec\ttabulation.py").write_text("x = 1\n", encoding="utf-8")


class RefusalTests(GuardTestCase):
    def test_evasion_cases_are_refused(self) -> None:
        """Un cas par ligne : chaque astuce est refusée, sans exception."""
        for candidate in EVASION_CASES:
            with self.subTest(path=repr(candidate)[:60]):
                with self.assertRaises(PathEscape):
                    confine(self.root, candidate)

    def test_symlink_out_of_the_repository_is_refused(self) -> None:
        """Cible atteinte via un lien pointant hors du dépôt."""
        for candidate in ("lien-etc/passwd", "lien-etc/hostname"):
            with self.subTest(path=candidate):
                with self.assertRaises(PathEscape):
                    confine(self.root, candidate)

    def test_traversal_to_the_prefixed_sibling_is_refused(self) -> None:
        """``repo-evil`` commence par ``repo`` : `startswith` laisserait passer."""
        for candidate in (f"../{SIBLING_NAME}/secret", f"../{SIBLING_NAME}"):
            with self.subTest(path=candidate):
                with self.assertRaises(PathEscape):
                    confine(self.root, candidate)

    def test_root_itself_is_not_a_readable_path(self) -> None:
        """La racine est le conteneur, pas un fichier lisible."""
        with self.assertRaises(PathEscape):
            confine(self.root, "")


class AcceptanceTests(GuardTestCase):
    def test_regular_paths_are_accepted(self) -> None:
        """Cas qui doit passer, y compris dans un sous-dossier (checklist #77)."""
        for candidate in ACCEPTED_CASES:
            with self.subTest(path=candidate):
                confined = confine(self.root, candidate)
                self.assertTrue(confined.absolute.is_file())
                self.assertEqual(confined.relative, candidate)

    def test_nonexistent_path_inside_the_repository_is_accepted(self) -> None:
        """Un fichier absent est un problème d'existence, pas de sécurité.

        La garde ne dit PAS que le fichier existe : `NOT_FOUND` est décidé
        plus loin, à l'ouverture.
        """
        confined = confine(self.root, "sous/absent.py")
        self.assertTrue(confined.absolute.is_relative_to(self.root))

    def test_internal_symlink_resolves_to_a_canonical_path(self) -> None:
        """Un lien interne est suivi, et le chemin renvoyé est canonique.

        Le LLM ne retrouve jamais sa propre entrée dans la réponse
        (invariant 8) et ne peut pas y glisser de `..`.
        """
        confined = confine(self.root, "lien-interne/dossier/ok.py")
        self.assertEqual(confined.relative, "sous/dossier/ok.py")
        self.assertTrue(confined.absolute.is_file())

    def test_path_with_a_forbidden_character_is_refused_even_if_it_exists(self) -> None:
        """Un vrai fichier au nom interdit ne peut pas être représenté."""
        with self.assertRaises(PathEscape):
            confine(self.root, "avec\ttabulation.py")

    def test_guard_can_be_applied_to_any_root(self) -> None:
        """La garde est paramétrée par la racine : réutilisable par #30."""
        other = self.root / "sous"
        confined = confine(other, "dossier/ok.py")
        self.assertEqual(confined.absolute, other / "dossier" / "ok.py")


class GrammarTests(unittest.TestCase):
    def test_rel_path_grammar_matches_the_contract(self) -> None:
        """Notre grammaire est celle du contrat, sinon elle dérive."""
        contract_regex = mcp_contract.pattern_of("RelPath")
        maximum = int(mcp_contract.defined("RelPath")["maxLength"])
        corpus = [
            "app.py",
            "src/deep/nested/file.py",
            "../secret",
            "/etc/passwd",
            "a//b",
            "a/.",
            "a/..",
            "trailing/",
            "C:/Windows",
            "back\\slash",
            "tab\there",
            "",
            "with space.txt",
            "x" * maximum,
            "x" * (maximum + 1),
        ]
        for candidate in corpus:
            with self.subTest(path=candidate[:40]):
                expected = bool(contract_regex.match(candidate))
                expected = expected and 1 <= len(candidate) <= maximum
                self.assertEqual(is_rel_path(candidate), expected)


if __name__ == "__main__":
    unittest.main()
