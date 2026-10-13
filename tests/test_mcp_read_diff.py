"""Tests de l'outil ``read_diff`` — sous-ticket #74 (contrat #16, 4.1).

Le dépôt d'exemple est créé dans ``tmp_path`` (jamais le dépôt Heimdall
lui-même) : ``GitRepoTestCase`` fabrique un vrai dépôt git, y compris pour
les cas tordus — fichier binaire, renommage, fichier avec une espace dans
son nom, ``diff.external`` configuré.

Les appels passent par le serveur réel en sous-processus, donc par un vrai
client MCP : c'est la réponse réellement sérialisée qui est vérifiée.
"""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from support import mcp_contract
from support.mcp_client import call_tool, tool_payload

from heimdall.mcp.paths import is_rel_path

GIT = shutil.which("git")

# Motif RelPath du contrat #16, relu depuis le schéma figé (jamais recopié).
CONTRACT_REL_PATH = mcp_contract.pattern_of("RelPath")


def _git(repo: Path, *arguments: str) -> None:
    """Commande git d'aide au test (repo jetable, argv figé, sans shell)."""
    if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
        raise unittest.SkipTest("git requis pour les tests du diff")
    completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {arguments} a échoué : {completed.stderr}")


class GitRepoTestCase(unittest.TestCase):
    """Dépôt git jetable, prêt à recevoir des modifications indexées."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-diff-")
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "Heimdall Test")
        self.write("README.md", "# exemple\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "initial")

    def write(self, relative: str, content: str) -> Path:
        """Écrit un fichier dans le dépôt (crée les dossiers manquants)."""
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_bytes(self, relative: str, content: bytes) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def stage(self, *relative: str) -> None:
        _git(self.repo, "add", "--", *relative)

    def call_read_diff(self, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Appelle l'outil sur ce dépôt et renvoie sa charge utile décodée."""
        return tool_payload(call_tool("read_diff", arguments or {}, root=self.repo))


class ReadDiffToolTests(GitRepoTestCase):
    def test_added_lines_are_listed_with_line_numbers(self) -> None:
        """Fait quand (#74) : le diff indexé est lu sur un repo d'exemple."""
        self.write(
            "app.py",
            'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\nprint("bonjour")\n',
        )
        self.stage("app.py")
        payload = self.call_read_diff()
        self.assertFalse(payload["truncated"])
        self.assertEqual([item["file"] for item in payload["files"]], ["app.py"])
        added = payload["files"][0]["added_lines"]
        self.assertEqual([item["line"] for item in added], [1, 2])
        self.assertEqual(added[0]["text"], 'TOKEN = "<REDACTED:github:len=40>"')
        self.assertEqual(added[1]["text"], 'print("bonjour")')

    def test_secret_values_are_masked_before_serialization(self) -> None:
        """Obligation masking_before_serialization : la valeur ne sort jamais."""
        jeton = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        self.write("app.py", f'TOKEN = "{jeton}"\n')
        self.stage("app.py")
        response = json.dumps(self.call_read_diff())
        self.assertNotIn(jeton, response)
        self.assertIn("<REDACTED:github:len=40>", response)

    def test_redactions_counter_matches_the_markers(self) -> None:
        """Filet du contrat : redactions >= 1 implique un marqueur présent."""
        self.write(
            "app.py",
            'A = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\npassword = "hunter2"\n',
        )
        self.stage("app.py")
        entry = self.call_read_diff()["files"][0]
        markers = sum("<REDACTED:" in line["text"] for line in entry["added_lines"])
        self.assertEqual(entry["redactions"], 2)
        self.assertGreaterEqual(markers, 1)

    def test_line_without_secret_is_left_untouched(self) -> None:
        """Une ligne sans secret ne porte aucun marqueur (légitime)."""
        self.write("app.py", "print('bonjour')\n")
        self.stage("app.py")
        entry = self.call_read_diff()["files"][0]
        self.assertEqual(entry["redactions"], 0)
        self.assertEqual(entry["added_lines"][0]["text"], "print('bonjour')")

    def test_binary_file_is_listed_without_any_line(self) -> None:
        """Invariant if/then : binary true implique added_lines vide."""
        self.write_bytes("logo.png", b"\x89PNG\r\n\x1a\n\x00\x01binary")
        self.stage("logo.png")
        entry = self.call_read_diff()["files"][0]
        self.assertTrue(entry["binary"])
        self.assertEqual(entry["added_lines"], [])

    def test_empty_diff_returns_no_files(self) -> None:
        self.assertEqual(self.call_read_diff(), {"files": [], "truncated": False})

    def test_max_bytes_out_of_contract_is_refused(self) -> None:
        for value in (1023, 65537, 0, -1):
            with self.subTest(max_bytes=value):
                payload = self.call_read_diff({"max_bytes": value})
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_response_never_exceeds_max_bytes(self) -> None:
        """Le budget demandé est une borne haute réellement respectée."""
        self.write("big.py", "x = 1\n" * 400)
        self.stage("big.py")
        for budget in (1024, 2048, 4096):
            with self.subTest(max_bytes=budget):
                payload = self.call_read_diff({"max_bytes": budget})
                self.assertLessEqual(len(json.dumps(payload).encode("utf-8")), budget)
                self.assertTrue(payload["truncated"], "un budget serré doit tronquer")

    def test_long_lines_are_capped_and_flagged(self) -> None:
        """2000 caractères par ligne : au-delà, ligne tronquée + truncated."""
        self.write("long.txt", "y" * 5000 + "\n")
        self.stage("long.txt")
        payload = self.call_read_diff()
        entry = payload["files"][0]
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(entry["added_lines"][0]["text"]), 2000)

    def test_many_files_are_capped_and_flagged(self) -> None:
        """200 fichiers : au-delà, la liste est incomplète et le dit."""
        names = [f"f{index}.txt" for index in range(205)]
        for name in names:
            self.write(name, "contenu\n")
        self.stage(*names)
        payload = self.call_read_diff()
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(payload["files"]), 200)

    def test_not_a_git_repository_is_reported(self) -> None:
        """Code d'erreur dédié : la racine doit être un dépôt git."""
        with tempfile.TemporaryDirectory(prefix="heimdall-nogit-") as tmp:
            payload = tool_payload(call_tool("read_diff", {}, root=Path(tmp)))
            self.assertEqual(payload["error"]["code"], "NOT_A_GIT_REPO")

    def test_removed_and_context_lines_are_not_reported(self) -> None:
        """Seules les lignes ajoutées intéressent le LLM (--unified=0)."""
        self.write("app.py", "a\nb\nc\n")
        self.stage("app.py")
        _git(self.repo, "commit", "-qm", "suite")
        self.write("app.py", "a\nB\nc\n")
        self.stage("app.py")
        entry = self.call_read_diff()["files"][0]
        self.assertEqual([line["text"] for line in entry["added_lines"]], ["B"])
        self.assertEqual([line["line"] for line in entry["added_lines"]], [2])

    def test_renamed_file_reports_the_new_path(self) -> None:
        """Piège du contrat : un renommage est nommé par son côté nouveau."""
        self.write("src/old_name.py", "valeur = 1\n")
        self.stage("src/old_name.py")
        _git(self.repo, "commit", "-qm", "ajout")
        _git(self.repo, "mv", "src/old_name.py", "src/new_name.py")
        self.write("src/new_name.py", "valeur = 1\nvaleur = 2\n")
        self.stage("src/new_name.py")
        payload = self.call_read_diff()
        self.assertEqual([item["file"] for item in payload["files"]], ["src/new_name.py"])
        self.assertEqual(
            [line["text"] for line in payload["files"][0]["added_lines"]], ["valeur = 2"]
        )

    def test_added_file_uses_the_new_path_not_dev_null(self) -> None:
        """``/dev/null`` est un chemin absolu : RelPath le refuserait."""
        self.write("brand/new.py", "x = 1\n")
        self.stage("brand/new.py")
        entry = self.call_read_diff()["files"][0]
        self.assertEqual(entry["file"], "brand/new.py")


class ReadDiffConformanceTests(GitRepoTestCase):
    """Critère d'acceptation du #27 : les réponses sont conformes au schéma."""

    def assert_conforms(self, payload: dict[str, Any], name: str) -> None:
        self.assertEqual(mcp_contract.errors(name, payload), [], "réponse hors contrat")

    def test_diff_response_conforms_to_the_contract(self) -> None:
        """Succès validé contre ReadDiffResult (oneOf succès / échec)."""
        self.write("app.py", 'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
        self.stage("app.py")
        payload = self.call_read_diff()
        self.assert_conforms(payload, "ReadDiffResult")
        # La forme succès est aussi rejetée par l'enveloppe d'échec : les
        # deux formes du contrat restent exclusives.
        self.assertTrue(mcp_contract.errors("ReadDiffErrorResponse", payload))

    def test_error_response_conforms_to_the_contract(self) -> None:
        """Échec validé contre ReadDiffResult, et refusé par ReadDiffOutput."""
        payload = self.call_read_diff({"max_bytes": 12})
        self.assert_conforms(payload, "ReadDiffResult")
        self.assertTrue(mcp_contract.errors("ReadDiffOutput", payload))
        self.assertEqual(set(payload), {"error"})

    def test_binary_entry_respects_the_conditional_invariant(self) -> None:
        """``binary: true`` implique ``added_lines`` vide (invariant if/then)."""
        self.write_bytes("logo.png", b"\x89PNG\r\n\x1a\n\x00\x01binary")
        self.stage("logo.png")
        entry = self.call_read_diff()["files"][0]
        self.assert_conforms({"files": [entry], "truncated": False}, "ReadDiffOutput")

    def test_rel_path_grammar_matches_the_contract(self) -> None:
        """Notre grammaire est celle du contrat, sinon elle dérive.

        Le serveur valide les chemins qu'il fabrique avec son propre motif
        (``heimdall/mcp/paths.py``) ; ce test rejoue la définition complète
        du contrat — motif **et** bornes de longueur — sur un corpus, pour
        prouver que les deux coïncident.
        """
        contract = mcp_contract.defined("RelPath")
        maximum = int(contract["maxLength"])
        corpus = [
            "app.py",
            "src/deep/nested/file.py",
            "no-extension",
            "a/b/c/d/e/f",
            "../secret",
            "/etc/passwd",
            "a//b",
            "./a",
            "a/.",
            "a/..",
            "trailing/",
            "C:/Windows/system32",
            "back\\slash",
            "tab\there",
            "new\nline",
            "",
            "with space.txt",
            "sp ace.txt",
            "emoji-\U0001f600.py",
            "x" * maximum,
            "x" * (maximum + 1),
        ]
        for candidate in corpus:
            with self.subTest(path=candidate[:40]):
                expected = bool(CONTRACT_REL_PATH.match(candidate))
                expected = expected and 1 <= len(candidate) <= maximum
                self.assertEqual(is_rel_path(candidate), expected, "dérive du contrat RelPath")
