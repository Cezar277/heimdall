"""Tests de l'outil ``sanitize_file`` — sous-ticket #75 (contrat #16, 4.2).

L'outil lit un fichier du dépôt pour donner du contexte au LLM. Tout ce
qu'il reçoit — le chemin — est traité comme une entrée piégée : les tests
rejouent les attaques attendues (traversée, lien sortant, ``.git``,
``.env``, fichier ignoré) sur un vrai dépôt git jetable, et vérifient
qu'aucune valeur en clair ne sort.
"""

import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from support import mcp_contract
from support.fake_secrets import FAKE_GITHUB_TOKEN
from support.mcp_client import call_tool, tool_payload

from heimdall.mcp.paths import confine

GIT = shutil.which("git")


class FileRepoTestCase(unittest.TestCase):
    """Dépôt git jetable avec des fichiers à lire, interdits et piégés."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-sanitize-")
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Heimdall Test")
        self.write("app.py", f"ligne1\nAPI = '{FAKE_GITHUB_TOKEN}'\nligne3\n")
        self.write("vide.txt", "")
        self.write("sub/profond.py", "a\nb\nc\nd\ne\n")
        self.write("crlf.txt", "un\r\ndeux\r\n")
        self.write_bytes("binaire.bin", b"\x00\x01\x02\x03secret")
        (self.repo / "gros.txt").write_text("x" * 10, encoding="utf-8")
        self.write(".env", "TOKEN=valeur\n")
        self.write(".env.example", "TOKEN=\n")
        (self.repo / "ignore.txt").write_text("secret\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("ignore.txt\n", encoding="utf-8")
        # Lien symbolique sortant, et lien interne.
        os.symlink("/etc", self.repo / "lien-etc")
        os.symlink(self.repo / "sub", self.repo / "lien-interne")

    def write(self, relative: str, content: str) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_bytes(self, relative: str, content: bytes) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def git(self, *arguments: str) -> None:
        if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
            raise unittest.SkipTest("git requis")
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [GIT, "-C", str(self.repo), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"git {arguments} a échoué : {completed.stderr}")

    def read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return tool_payload(call_tool("sanitize_file", arguments, root=self.repo))


class SanitizeFileToolTests(FileRepoTestCase):
    def test_extract_is_returned_masked(self) -> None:
        """Fait quand (#75) : un extrait est lu et masqué."""
        payload = self.read({"path": "app.py"})
        self.assertEqual(payload["path"], "app.py")
        self.assertEqual(payload["start_line"], 1)
        self.assertEqual(payload["end_line"], 3)
        self.assertEqual(payload["total_lines"], 3)
        self.assertIn("ligne1", payload["content"])
        self.assertIn("<REDACTED:github:len=40>", payload["content"])
        self.assertEqual(payload["redactions"], 1)
        self.assertFalse(payload["truncated"])

    def test_no_clear_value_ever_reaches_the_llm(self) -> None:
        """Obligation masking_before_serialization (contrat 4.2)."""
        jeton = FAKE_GITHUB_TOKEN
        for arguments in (
            {"path": "app.py"},
            {"path": "app.py", "start_line": 2, "max_lines": 1},
            {"path": "sub/profond.py"},
        ):
            with self.subTest(**arguments):
                self.assertNotIn(jeton, str(self.read(arguments)))

    def test_json_quoted_password_is_masked_end_to_end(self) -> None:
        """E-03 : une clé JSON entre guillemets ne part plus en clair au LLM."""
        self.write("config.json", '{"password": "hunter2!hunter"}\n')
        payload = self.read({"path": "config.json"})
        self.assertNotIn("hunter2!hunter", payload["content"])
        self.assertIn("<REDACTED:generic_secret:len=14>", payload["content"])
        self.assertEqual(payload["redactions"], 1)

    def test_unclosed_quoted_password_is_masked_end_to_end(self) -> None:
        """Revue (MEDIUM) : guillemet fermant absent, secret quand même masqué."""
        self.write("conf.py", 'password="hunter2!hunter\n')
        payload = self.read({"path": "conf.py"})
        self.assertNotIn("hunter2!hunter", payload["content"])
        self.assertIn("<REDACTED:generic_secret:len=14>", payload["content"])
        self.assertEqual(payload["redactions"], 1)
        self.assertEqual(mcp_contract.errors("SanitizeFileResult", payload), [])

    def test_long_quoted_value_is_masked_not_windowed(self) -> None:
        """Régression de revue : plus de fenêtre AVANT le masquage.

        Une valeur citée dont le guillemet fermant tombait au-delà de la
        fenêtre de 2500 caractères n'était plus reconnue par
        `_QUOTED_ASSIGNMENT`, et son préfixe partait en clair au LLM. Le
        masquage porte désormais sur la ligne entière.
        """
        value = "a" * 5000
        self.write("conf.py", f'SECRET = "{value}"\n')
        payload = self.read({"path": "conf.py"})
        content = payload["content"]
        self.assertNotIn(f'SECRET = "{value[:50]}', content)
        self.assertNotIn(value[:200], content)
        self.assertIn("<REDACTED:generic_secret:len=5000>", content)
        self.assertEqual(payload["redactions"], 1)
        self.assertFalse(payload["truncated"], "une valeur masquée ne doit plus être coupée")
        self.assertEqual(mcp_contract.errors("SanitizeFileResult", payload), [])

    def test_long_line_without_secret_is_still_capped(self) -> None:
        """La borne de 2000 caractères tient toujours (masquage puis coupe)."""
        self.write("remplissage.txt", "y" * 5000 + "\n")
        payload = self.read({"path": "remplissage.txt"})
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(payload["content"]), 2000)

    def test_slice_selects_the_requested_lines(self) -> None:
        """``start_line`` / ``max_lines`` bornent l'extrait."""
        payload = self.read({"path": "sub/profond.py", "start_line": 2, "max_lines": 2})
        self.assertEqual(payload["start_line"], 2)
        self.assertEqual(payload["end_line"], 3)
        self.assertEqual(payload["content"], "b\nc")
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["total_lines"], 5)

    def test_start_beyond_the_end_returns_an_empty_extract(self) -> None:
        payload = self.read({"path": "sub/profond.py", "start_line": 99})
        self.assertEqual(payload["content"], "")
        self.assertEqual(payload["end_line"], 0)
        self.assertFalse(payload["truncated"])

    def test_empty_file_is_readable(self) -> None:
        payload = self.read({"path": "vide.txt"})
        self.assertEqual(payload["total_lines"], 0)
        self.assertEqual(payload["content"], "")
        self.assertEqual(payload["end_line"], 0)

    def test_max_lines_bounds_are_enforced(self) -> None:
        for value in (0, -1, 401, 10_000):
            with self.subTest(max_lines=value):
                payload = self.read({"path": "app.py", "max_lines": value})
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_start_line_bound_is_enforced(self) -> None:
        for value in (0, -3):
            with self.subTest(start_line=value):
                payload = self.read({"path": "app.py", "start_line": value})
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_missing_file_is_reported(self) -> None:
        payload = self.read({"path": "absent.py"})
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

    def test_binary_file_is_refused(self) -> None:
        payload = self.read({"path": "binaire.bin"})
        self.assertEqual(payload["error"]["code"], "BINARY_FILE")

    def test_unreadable_file_is_internal_not_not_found(self) -> None:
        """Fichier `chmod 000` : `INTERNAL`, pas `NOT_FOUND`.

        Un fichier illisible par droits existe peut-être : l'annoncer
        « introuvable » fausse le tri et masque une panne d'intégrité.
        Droits restaurés en `finally` pour ne pas piéger le nettoyage.
        """
        target = self.write("illisible.txt", "x\n")
        target.chmod(0)
        try:
            probe = os.open(target, os.O_RDONLY)
        except OSError:
            probe = None
        else:
            os.close(probe)
        if probe is not None:
            self.skipTest("l'environnement lit malgré chmod 000 (root ?)")
        try:
            payload = self.read({"path": "illisible.txt"})
        finally:
            target.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(payload["error"]["code"], "INTERNAL")

    def test_directory_is_not_a_file(self) -> None:
        payload = self.read({"path": "sub"})
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

    def test_non_regular_files_keep_a_stable_code(self) -> None:
        """Codes stables pour un même objet, dans les deux ordres possibles.

        Un FIFO/socket/périphérique présent **avant** la garde : `BINARY_FILE`
        (« aucun texte à renvoyer », et surtout jamais d'ouverture qui
        bloquerait). Le même objet substitué **après** la garde : `INTERNAL`,
        parce que c'est une anomalie d'intégrité (dev/ino qui ne colle plus),
        pas la nature du fichier. La distinction est voulue et stable : elle
        est épinglée ici pour qu'un refactor ne la rende pas aléatoire.
        """
        os.mkfifo(self.repo / "tuyau")
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(self.repo / "sock"))
            self.assertEqual(self.read({"path": "tuyau"})["error"]["code"], "BINARY_FILE")
            self.assertEqual(self.read({"path": "sock"})["error"]["code"], "BINARY_FILE")

    def test_symlink_targets_decide_the_code(self) -> None:
        """Un lien n'a pas de code propre : c'est sa CIBLE qui est jugée.

        Vérifié parce que la revue supposait un `BINARY_FILE` pour un lien :
        non — `confine` résout le lien avant tout. Sortant de la racine :
        `PATH_ESCAPE`. Vers un FIFO interne : `BINARY_FILE` (la cible est un
        FIFO). Vers un fichier interne : lu, et `path` renvoie la cible
        canonique, jamais le nom du lien.
        """
        os.symlink("/etc/passwd", self.repo / "lien-sortant")
        self.assertEqual(self.read({"path": "lien-sortant"})["error"]["code"], "PATH_ESCAPE")
        os.mkfifo(self.repo / "cible-tuyau")
        os.symlink(self.repo / "cible-tuyau", self.repo / "lien-tuyau")
        self.assertEqual(self.read({"path": "lien-tuyau"})["error"]["code"], "BINARY_FILE")
        os.symlink(self.repo / "sub" / "profond.py", self.repo / "lien-ok")
        payload = self.read({"path": "lien-ok"})
        self.assertEqual(payload["path"], "sub/profond.py")
        self.assertEqual(payload["content"], "a\nb\nc\nd\ne")

    def test_git_directory_is_forbidden(self) -> None:
        payload = self.read({"path": ".git/config"})
        self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_env_files_are_forbidden(self) -> None:
        """Contrat §4.2 (`.env*`) : sauvegardes incluses, pas juste `.env`.

        `.env-backup` / `.env_old` / `.env~` contournaient l'ancien test
        (`startswith(".env.")`) : une sauvegarde lue, même masquée, viole
        l'interdit. Le sur-blocage (`.envelope.py`) est assumé et épinglé.
        """
        for path in (
            ".env",
            ".env.example",
            "sub/.env.local",
            ".env-backup",
            ".env_old",
            ".env~",
            ".env.bak",
            "backups/.env-backup",
        ):
            with self.subTest(path=path):
                self.write(path, "TOKEN=factice\n")
                payload = self.read({"path": path})
                self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_credential_files_are_forbidden(self) -> None:
        """F-09 : les fichiers de credentials ne sont jamais lus, même masqués."""
        for path in (
            ".netrc",
            ".pgpass",
            "id_rsa",
            "id_ed25519",
            "server.pem",
            "private.key",
            ".npmrc",
            ".pypirc",
            "credentials",
            ".docker/config.json",
            ".kube/config",
            ".netrc.backup",
            ".pgpass~",
            ".npmrc-backup",
            "credentials.json",
            "credentials.txt",
            "credentials-backup",
            "credentials_backup",
            "server.pem.bak",
            "private.key.old",
            ".docker/config.json.bak",
            ".kube/config.old",
        ):
            with self.subTest(path=path):
                self.write(path, "mot-de-passe-factice\n")
                payload = self.read({"path": path})
                self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_envelope_lookalike_is_overblocked(self) -> None:
        """`.envelope.py` n'est pas un `.env*` légitime à lire : le contrat
        dit `.env*`, fail-closed l'emporte sur la disponibilité."""
        self.write(".envelope.py", "x = 1\n")
        payload = self.read({"path": ".envelope.py"})
        self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_ignored_file_is_forbidden(self) -> None:
        """``ignore.txt`` est dans le .gitignore du dépôt."""
        payload = self.read({"path": "ignore.txt"})
        self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_tracked_file_matching_gitignore_is_refused_too(self) -> None:
        """Choix fail-closed : « fichier ignoré » vaut aussi pour un suivi.

        `git check-ignore` ne consulte PAS l'index dans ce sens : il répond
        dès qu'une règle de `.gitignore` couvre le chemin, même si le fichier
        est déjà suivi. Refuser est la lecture stricte du contrat 4.2
        (« fichiers ignorés par .gitignore ») et la plus prudente. Le jour où
        la remédiation (#30) devra lire un fichier déjà commité, elle le fera
        par son propre canal, pas par cet outil.
        """
        self.git("add", "-A")
        self.git("commit", "-qm", "tout suivi")
        payload = self.read({"path": "ignore.txt"})
        self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_symlink_out_of_the_repository_is_refused(self) -> None:
        payload = self.read({"path": "lien-etc/passwd"})
        self.assertEqual(payload["error"]["code"], "PATH_ESCAPE")

    def test_traversal_is_refused(self) -> None:
        for path in ("../secret", "../../etc/passwd", "sub/../../secret"):
            with self.subTest(path=path):
                payload = self.read({"path": path})
                self.assertEqual(payload["error"]["code"], "PATH_ESCAPE")

    def test_absolute_path_is_refused(self) -> None:
        payload = self.read({"path": "/etc/passwd"})
        self.assertEqual(payload["error"]["code"], "PATH_ESCAPE")

    def test_internal_symlink_normalises_the_reported_path(self) -> None:
        """Le chemin renvoyé est canonique, pas celui fourni par le LLM."""
        payload = self.read({"path": "lien-interne/profond.py"})
        self.assertEqual(payload["path"], "sub/profond.py")
        self.assertNotIn("lien", str(payload))

    def test_content_is_capped_at_100k_characters(self) -> None:
        """Borne du contrat, appliquée après masquage."""
        (self.repo / "minifie.js").write_text(("x" * 1500 + "\n") * 80, encoding="utf-8")
        payload = self.read({"path": "minifie.js"})
        self.assertLessEqual(len(payload["content"]), 100_000)
        self.assertTrue(payload["truncated"])

    def test_giant_line_is_bounded_to_max_line_chars_without_blocking(self) -> None:
        """Ligne géante (~900 Ko) : bornée à 2 000 caractères en temps borné."""
        (self.repo / "giant.txt").write_text("a" * 900_000, encoding="utf-8")
        start = time.perf_counter()
        payload = self.read({"path": "giant.txt"})
        duration = time.perf_counter() - start
        self.assertLess(duration, 10.0, "Le traitement de la ligne géante ne doit pas bloquer")
        self.assertLessEqual(len(payload["content"]), 2_000)
        self.assertTrue(payload["truncated"])

    def test_hardlink_alias_behavior_is_documented_boundary(self) -> None:
        """Hardlink alias innocent pointant vers .env.

        Lu sous son alias avec contenu masqué : limite documentée ADR-003 §9.
        """
        self.write(".env", f"SECRET_KEY='{FAKE_GITHUB_TOKEN}'\n")
        try:
            os.link(self.repo / ".env", self.repo / "innocent.txt")
        except OSError:
            self.skipTest("hardlinks non supportés sur ce système de fichiers")
        payload = self.read({"path": "innocent.txt"})
        self.assertEqual(payload["path"], "innocent.txt")
        self.assertIn("<REDACTED:", payload["content"])
        self.assertNotIn(FAKE_GITHUB_TOKEN, payload["content"])

    def test_nul_byte_beyond_8k_is_detected_as_binary(self) -> None:
        """Octet NUL au-delà de 8 Ko (offset 9000) : détecté comme BINARY_FILE."""
        self.write_bytes("nul_late.bin", b"a" * 9000 + b"\x00" + b"b" * 100)
        payload = self.read({"path": "nul_late.bin"})
        self.assertEqual(payload["error"]["code"], "BINARY_FILE")

    def test_response_conforms_to_the_contract(self) -> None:
        """Critère d'acceptation du #27 : réponse conforme au schéma."""
        payload = self.read({"path": "app.py"})
        self.assertEqual(
            mcp_contract.errors("SanitizeFileResult", payload), [], "réponse hors contrat"
        )

    def test_error_response_conforms_to_the_contract(self) -> None:
        payload = self.read({"path": "/etc/passwd"})
        self.assertEqual(mcp_contract.errors("SanitizeFileResult", payload), [])
        self.assertNotEqual(mcp_contract.errors("SanitizeFileOutput", payload), [])


class GuardWiringTests(FileRepoTestCase):
    """La garde est bien celle de #76, et elle est appelée avant tout accès."""

    def test_tool_uses_the_single_guard(self) -> None:
        """Le même ``confine`` est utilisé par l'outil et par les tests."""
        for candidate in ("app.py", "sub/profond.py"):
            with self.subTest(path=candidate):
                self.assertEqual(
                    confine(self.repo, candidate).relative,
                    self.read({"path": candidate})["path"],
                )

    def test_read_permissions_are_not_granted_to_the_world(self) -> None:
        """O_NOFOLLOW + lecture seule : rien n'est ouvert en écriture."""
        handle = os.open(self.repo / "app.py", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(handle)
            self.assertTrue(stat.S_ISREG(info.st_mode))
        finally:
            os.close(handle)


if __name__ == "__main__":
    unittest.main()
