"""Tests unitaires in-process du serveur MCP — rapides et déterministes.

Complément des tests de bout en bout (sous-processus, `test_mcp_*.py`) :
ici aucun serveur n'est démarré, aucun git n'est requis sauf mention
explicite. Ces tests donnent la couverture de branche des modules
`heimdall/mcp` sans dépendre du timing des sous-processus — la mesure
subprocess (transmission de `COVERAGE_PROCESS_START`, voir
`tests/support/mcp_client.py`) reste câblée pour la CI du #20.
"""

import asyncio
import errno
import inspect
import json
import os
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path as _Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support.fake_secrets import FAKE_GITHUB_TOKEN, fake_token
from support.git_repo import GitRepo

from heimdall.mcp import __main__ as entry
from heimdall.mcp import errors, gitdiff, masking, server
from heimdall.mcp.__main__ import parse_args
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.paths import PathEscape, confine, is_rel_path


class ErrorsTests(unittest.TestCase):
    def test_every_code_has_a_static_ascii_message(self) -> None:
        """Un message par code, ASCII pur, sans interpolation d'entrée."""
        codes = (
            "INVALID_INPUT",
            "PATH_ESCAPE",
            "NOT_FOUND",
            "FORBIDDEN_PATH",
            "BINARY_FILE",
            "TOO_LARGE",
            "UNKNOWN_CANDIDATE",
            "STALE_CANDIDATE",
            "NOT_A_GIT_REPO",
            "INTERNAL",
        )
        self.assertEqual(set(errors.ERROR_MESSAGES), set(codes))
        for code in codes:
            with self.subTest(code=code):
                message = errors.ERROR_MESSAGES[code]  # type: ignore[literal-required]
                message.encode("ascii")
                self.assertNotIn("\n", message)

    def test_failure_envelope_shape(self) -> None:
        payload = json.loads(errors.failure("PATH_ESCAPE"))
        self.assertEqual(set(payload), {"error"})
        self.assertEqual(payload["error"]["code"], "PATH_ESCAPE")
        self.assertEqual(payload["error"]["message"], errors.ERROR_MESSAGES["PATH_ESCAPE"])

    def test_tool_failure_carries_code_and_static_message(self) -> None:
        failure = ToolFailure("NOT_FOUND")
        self.assertEqual(failure.code, "NOT_FOUND")
        self.assertEqual(failure.message, errors.ERROR_MESSAGES["NOT_FOUND"])
        self.assertEqual(str(failure), errors.ERROR_MESSAGES["NOT_FOUND"])

    def test_tool_failure_has_no_free_message_channel(self) -> None:
        """L'API libre est supprimée : aucun futur appel ne peut refléter
        une valeur (invariant 8 structurel, pas disciplinaire)."""
        with self.assertRaises(TypeError):
            ToolFailure("INTERNAL", "valeur")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            errors.failure("INTERNAL", "valeur")  # type: ignore[call-arg]

    def test_dumps_is_compact_ascii_and_rejects_nan(self) -> None:
        self.assertEqual(errors.dumps({"a": 1}), '{"a":1}')
        out = errors.dumps({"café": "é"})
        self.assertEqual(json.loads(out), {"café": "é"})
        self.assertTrue(out.isascii())
        with self.assertRaises(ValueError):
            errors.dumps({"x": float("nan")})


class ExpectedTypesTests(unittest.TestCase):
    def test_signature_is_the_single_source(self) -> None:
        def tool(path: str, start_line: int = 1, flag: bool = False) -> str:
            return path

        declared, required = server._expected_types(tool)
        self.assertEqual(declared, {"path": str, "start_line": int})
        self.assertEqual(required, frozenset({"path"}))
        # `bool` n'est pas un type du contrat : ignoré (fail-closed).
        self.assertNotIn("flag", declared)


class ToolBoundaryTests(unittest.TestCase):
    """La frontière, sans serveur : faux contexte + appel suivant factice."""

    def setUp(self) -> None:
        def read_diff(max_bytes: int = 32768) -> str:
            return f"ok:{max_bytes}"

        def sanitize_file(path: str, start_line: int = 1) -> str:
            return f"ok:{path}:{start_line}"

        self.gate = server._ToolBoundary({"read_diff": read_diff, "sanitize_file": sanitize_file})

    def run_gate(self, name: str, arguments: Any, result: Any = None) -> Any:
        async def call_next(ctx: Any) -> Any:
            return {"ok": True} if result is None else result

        ctx = SimpleNamespace(method="tools/call", params={"name": name, "arguments": arguments})
        return asyncio.run(self.gate(ctx, call_next))  # type: ignore[arg-type]

    def test_valid_call_passes_through(self) -> None:
        self.assertEqual(self.run_gate("read_diff", {}), {"ok": True})
        self.assertEqual(self.run_gate("sanitize_file", {"path": "a.py"}), {"ok": True})

    def test_meta_is_protocol_not_a_tool_field(self) -> None:
        self.assertEqual(self.run_gate("read_diff", {"_meta": {"x": 1}}), {"ok": True})

    def test_oversized_meta_is_refused_in_process(self) -> None:
        result = self.run_gate("read_diff", {"_meta": "x" * 100_000})
        self.assertTrue(result["isError"])

    def test_deeply_nested_meta_is_refused_not_raised(self) -> None:
        """~10⁵ niveaux : RecursionError rattrapée dans l'enveloppe."""
        nested: Any = "x"
        for _ in range(100_000):
            nested = [nested]
        result = self.run_gate("read_diff", {"_meta": nested})
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"])["error"]["code"], "INVALID_INPUT")

    def test_unserializable_meta_is_refused_not_raised(self) -> None:
        """_meta non sérialisable (ex. bytes) : TypeError rattrapée dans l'enveloppe."""
        result = self.run_gate("read_diff", {"_meta": b"\x00"})
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"])["error"]["code"], "INVALID_INPUT")


    def test_unknown_field_is_refused(self) -> None:
        payload = json.loads(self.run_gate("read_diff", {"root": "/etc"})["content"][0]["text"])
        self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_wrong_type_is_refused(self) -> None:
        for arguments in ({"max_bytes": "1024"}, {"max_bytes": True}, {"max_bytes": 1.5}):
            with self.subTest(arguments=arguments):
                result = self.run_gate("read_diff", arguments)
                self.assertTrue(result["isError"])

    def test_missing_required_param_is_refused(self) -> None:
        result = self.run_gate("sanitize_file", {})
        self.assertTrue(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_absent_arguments_mean_defaults(self) -> None:
        """`arguments: null` = pas d'arguments : les défauts s'appliquent."""
        self.assertEqual(self.run_gate("read_diff", None), {"ok": True})

    def test_non_dict_arguments_are_refused(self) -> None:
        for arguments in ([], "x", 12):
            with self.subTest(arguments=arguments):
                result = self.run_gate("read_diff", arguments)
                self.assertTrue(result["isError"])

    def test_non_string_keys_in_arguments_are_refused_not_raised(self) -> None:
        """Clés non-chaînes (ex. int, tuple) : refusées avec INVALID_INPUT dans l'enveloppe."""
        for bad_args in ({1: "val"}, {("x",): 1}):
            with self.subTest(arguments=bad_args):
                result = self.run_gate("read_diff", bad_args)
                self.assertTrue(result["isError"])
                self.assertEqual(
                    json.loads(result["content"][0]["text"])["error"]["code"],
                    "INVALID_INPUT",
                )

    def test_unknown_tool_is_refused_in_our_envelope(self) -> None:
        """Outil inconnu : notre enveloppe `INVALID_INPUT`, pas le texte du SDK.

        Le SDK répondrait « Unknown tool », un texte brut hors de notre
        enveloppe `{"error": …}` (contrat 3.1) : la frontière refuse
        elle-même, sans appeler la suite ni refléter le nom reçu.
        """
        for name in ("exec", "propose_patch", "ping2", "", 123):
            with self.subTest(name=name):

                def fail_if_called(ctx: Any) -> Any:
                    raise AssertionError("la suite ne doit pas être appelée")

                ctx = SimpleNamespace(method="tools/call", params={"name": name, "arguments": {}})
                result = asyncio.run(self.gate(ctx, fail_if_called))  # type: ignore[arg-type]
                self.assertTrue(result["isError"])
                payload = json.loads(result["content"][0]["text"])
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_non_call_method_passes_through(self) -> None:
        async def call_next(ctx: Any) -> Any:
            return "untouched"

        ctx = SimpleNamespace(method="notifications/initialized", params={})
        self.assertEqual(asyncio.run(self.gate(ctx, call_next)), "untouched")  # type: ignore[arg-type]

    def test_mark_failure_flags_only_error_envelopes(self) -> None:
        error = {"content": [{"type": "text", "text": '{"error":{"code":"X","message":"y"}}'}]}
        self.assertTrue(server._mark_failure(error)["isError"])
        success = {"content": [{"type": "text", "text": '{"files":[]}'}], "isError": False}
        self.assertFalse(server._mark_failure(success)["isError"])
        self.assertEqual(server._mark_failure({"no": "content"}), {"no": "content"})
        self.assertEqual(server._mark_failure([]), [])
        self.assertEqual(server._mark_failure(None), None)


class ToolHandlerTests(unittest.TestCase):
    def test_tool_failure_maps_to_its_code(self) -> None:
        @server.tool_handler
        def tool() -> str:
            raise ToolFailure("NOT_A_GIT_REPO")

        self.assertEqual(json.loads(tool())["error"]["code"], "NOT_A_GIT_REPO")

    def test_path_escape_maps_to_path_escape(self) -> None:
        @server.tool_handler
        def tool() -> str:
            raise PathEscape

        self.assertEqual(json.loads(tool())["error"]["code"], "PATH_ESCAPE")

    def test_unexpected_exception_maps_to_internal(self) -> None:
        @server.tool_handler
        def tool() -> str:
            raise ValueError("panne")

        payload = json.loads(tool())
        self.assertEqual(payload["error"]["code"], "INTERNAL")
        self.assertNotIn("panne", payload["error"]["message"])

    def test_success_passes_through_and_keeps_metadata(self) -> None:
        @server.tool_handler
        def tool() -> str:
            """Doc conservée."""
            return '{"pong":true}'

        self.assertEqual(tool(), '{"pong":true}')
        self.assertEqual(tool.__name__, "tool")
        self.assertIn("Doc", tool.__doc__ or "")


class MaskedFilesTests(unittest.TestCase):
    def test_recount_drops_markers_lost_to_the_cut(self) -> None:
        """Invariant structurel : le compte décrit les lignes finales."""
        token = "ghp_" + "K" * 36
        long_line = "y" * 5000 + f'TOKEN = "{token}"'
        files, truncated = server._masked_files(
            [gitdiff.DiffEntry("e.py", False, ((1, long_line),))]
        )
        self.assertTrue(truncated)
        self.assertEqual(files[0]["redactions"], 0)
        self.assertNotIn(token, files[0]["added_lines"][0]["text"])

    def test_long_quoted_value_is_masked_never_windowed(self) -> None:
        """Régression de revue : la fenêtre précédait le masquage.

        `SECRET="` + 5000 caractères + `"` ne matchait plus
        `_QUOTED_ASSIGNMENT` une fois la ligne tronquée avant masquage : le
        préfixe de 2000 caractères partait en clair. Le guillemet fermant
        étant désormais toujours vu, la valeur entière est remplacée.
        """
        value = "a" * 5000
        files, truncated = server._masked_files(
            [gitdiff.DiffEntry("e.py", False, ((1, f'SECRET="{value}"'),))]
        )
        self.assertFalse(truncated, "une valeur masquée ne doit plus être coupée")
        text = files[0]["added_lines"][0]["text"]
        self.assertEqual(text, 'SECRET="<REDACTED:generic_secret:len=5000>"')
        self.assertEqual(files[0]["redactions"], 1)
        self.assertNotIn(value[:50], text)

    def test_budget_pops_last_files_first(self) -> None:
        entries = [gitdiff.DiffEntry(f"f{i}.py", False, ((1, "x = 1"),)) for i in range(5)]
        files, truncated = server._masked_files(entries)
        self.assertFalse(truncated)
        self.assertTrue(server._fit_budget(files, 200))
        self.assertLessEqual(server._encoded_size(files), 200)
        self.assertEqual([item["file"] for item in files], ["f0.py"])  # les derniers partent

    def test_budget_is_sized_without_reserializing_every_file(self) -> None:
        """Les tailles cumulées valent la taille réelle, à l'octet près.

        C'est ce qui permet à `_fit_budget` de décider du retrait sans
        resérialiser la réponse à chaque `pop` (coût O(n²) avant correctif).
        """
        files = [
            {"file": f"f{i}.py", "binary": False, "redactions": 0, "added_lines": []}
            for i in range(7)
        ]
        for count in range(len(files) + 1):
            with self.subTest(files=count):
                self.assertEqual(
                    server._prefix_size(server._file_sizes(files[:count])),
                    server._encoded_size(files[:count]),
                )

    def test_budget_below_one_file_returns_an_empty_diff(self) -> None:
        """Budget minuscule : on retire jusqu'à passer, `truncated` le dit."""
        files = [{"file": "gros.py", "binary": False, "redactions": 0, "added_lines": []}]
        self.assertTrue(server._fit_budget(files, 1))
        self.assertEqual(files, [])

    def test_empty_budget_is_always_reachable(self) -> None:
        self.assertFalse(server._fit_budget([], 1024))

    def test_split_lines_follows_wc_convention(self) -> None:
        self.assertEqual(server._split_lines("a\nb\n"), ["a", "b"])
        self.assertEqual(server._split_lines(""), [])
        self.assertEqual(server._split_lines("a"), ["a"])


class ForbiddenPathTests(unittest.TestCase):
    def test_git_and_env_segments_are_forbidden(self) -> None:
        for path in (".git/config", "a/.GIT/x", ".env", ".ENV", ".env.local", "s/.Env.X"):
            with self.subTest(path=path):
                self.assertTrue(server.is_forbidden_path(path))

    def test_lookalikes_are_allowed(self) -> None:
        for path in (".gitignore", ".github/a", "git/x", "my.env/file", "a.envb/c"):
            with self.subTest(path=path):
                self.assertFalse(server.is_forbidden_path(path))


class ConfinedEnvironmentTests(unittest.TestCase):
    def test_minimal_and_redirection_free(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-env-") as tmp:
            env = gitdiff.confined_environment(_Path(tmp))
        for forbidden in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY"):
            self.assertNotIn(forbidden, env)
        self.assertEqual(env["PATH"], "")
        self.assertEqual(env["HOME"], tmp)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_discovery_ceiling_is_the_parent_of_the_root(self) -> None:
        """Plafond = le parent, parce que c'est lui que git ascendererait.

        git n'exclut que l'**entrée** dans un dossier plafond. Depuis la
        racine, le premier dossier que git ascendedrait est son PARENT :
        c'est donc le parent qu'il faut plafonner. Mettre la racine
        elle-même ne bloquerait rien (git est déjà dedans) et rouvrirait la
        découverte du dépôt parent — prouvé par `RepositoryCeilingTests`
        ci-dessous, qui échouerait si le plafond redevenait la racine.
        """
        with tempfile.TemporaryDirectory(prefix="heimdall-ceil-") as tmp:
            root = _Path(tmp) / "racine"
            root.mkdir()
            env = gitdiff.confined_environment(root)
            self.assertEqual(env["GIT_CEILING_DIRECTORIES"], str(root.resolve().parent))


class RepositoryCeilingTests(unittest.TestCase):
    """Preuve par exécution : c'est GIT qui refuse de monter au-dessus.

    Indépendant de `is_repository()` : même un appelant qui oublierait le
    test d'égalité n'hériterait d'aucun dépôt parent, parce que git ne le
    découvre pas. C'est la réplique directe au reproche « la garantie
    repose sur chaque appelant qui n'oublie pas le test ».
    """

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-plafond-", self)

    def test_root_is_still_discovered(self) -> None:
        """Plafond au parent, dépôt à la racine : le cas normal fonctionne."""
        access = gitdiff.GitAccess(self.repo.root)
        self.assertTrue(access.is_repository())
        self.repo.write("a.txt", "x\n")
        self.repo.stage("a.txt")
        raw, truncated = access.staged_diff(10**6)
        self.assertFalse(truncated)
        self.assertIn(b"a.txt", raw)

    def test_parent_repository_is_unreachable_from_a_subfolder(self) -> None:
        """Sous-dossier du dépôt : git lui-même refuse (rc≠0), pas nous."""
        sub = self.repo.root / "sous" / "profond"
        sub.mkdir(parents=True)
        for child in (sub, self.repo.root / "sous"):
            with self.subTest(root=child.name):
                access = gitdiff.GitAccess(child)
                self.assertFalse(access.is_repository())
                # Preuve directe : le code de retour de git, sans notre test.
                completed = access.execute(("rev-parse", "--show-toplevel"))
                self.assertNotEqual(completed.returncode, 0, "git a découvert un dépôt parent")

    def test_tools_on_a_subfolder_fail_closed_without_is_repository(self) -> None:
        """Sans `is_repository()`, `staged_diff`/`is_ignored` refusent aussi.

        Preuve que la barrière est réelle pour TOUT appelant futur :
        `staged_diff` lève `INTERNAL` (git sort en erreur, aucune sortie
        n'est lue) et `is_ignored` lève `INTERNAL` (code de retour
        inattendu, jamais un « non » par défaut).
        """
        sub = self.repo.root / "sous"
        sub.mkdir()
        access = gitdiff.GitAccess(sub)
        with self.assertRaises(ToolFailure) as ctx:
            access.staged_diff(1024)
        self.assertEqual(ctx.exception.code, "INTERNAL")
        with self.assertRaises(ToolFailure) as ctx:
            access.is_ignored("nimporte.txt")
        self.assertEqual(ctx.exception.code, "INTERNAL")


class GitAccessDirectTests(unittest.TestCase):
    """`GitAccess` sans serveur : dépôts jetables, dans le processus."""

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-units-", self)

    def test_missing_git_binary_is_an_internal_failure(self) -> None:
        with mock.patch.object(gitdiff.shutil, "which", return_value=None):
            with self.assertRaises(ToolFailure) as ctx:
                gitdiff.GitAccess(self.repo.root)
        self.assertEqual(ctx.exception.code, "INTERNAL")

    def test_hostile_path_cannot_hijack_the_git_binary(self) -> None:
        """Un `git` piégé en tête de PATH n'est jamais exécuté : le binaire
        vient de `os.defpath` (défaut système), pas de l'héritage."""
        if gitdiff.shutil.which("git", path=os.defpath) is None:
            self.skipTest("git introuvable dans le PATH système")
        with tempfile.TemporaryDirectory(prefix="heimdall-evilbin-") as bindir:
            canary = _Path(tempfile.gettempdir()) / "heimdall-git-hijack-canary"
            canary.unlink(missing_ok=True)
            fake = _Path(bindir) / "git"
            fake.write_text(f'#!/bin/sh\necho "PWNED" >> {canary}\n', encoding="utf-8")
            fake.chmod(stat.S_IRWXU)
            previous = os.environ.get("PATH")
            os.environ["PATH"] = f"{bindir}{os.pathsep}{previous or ''}"
            try:
                access = gitdiff.GitAccess(self.repo.root)
                self.assertTrue(access.is_repository())
            finally:
                if previous is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = previous
            self.assertFalse(canary.exists(), "le faux binaire git a été exécuté !")
            self.assertNotEqual(os.path.dirname(access._git), bindir)

    def test_repository_detection(self) -> None:
        self.assertTrue(gitdiff.GitAccess(self.repo.root).is_repository())
        with tempfile.TemporaryDirectory(prefix="heimdall-nogit-") as tmp:
            self.assertFalse(gitdiff.GitAccess(_Path(tmp)).is_repository())

    def test_ignored_detection_and_unexpected_codes(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        self.repo.write(".gitignore", "ign.txt\n")
        self.repo.write("ign.txt", "x\n")
        self.repo.write("keep.txt", "x\n")
        self.assertTrue(access.is_ignored("ign.txt"))
        self.assertFalse(access.is_ignored("keep.txt"))
        with mock.patch.object(gitdiff.GitAccess, "execute") as execute:
            execute.return_value = mock.Mock(returncode=128, stdout=b"", stderr=b"")
            with self.assertRaises(ToolFailure):
                access.is_ignored("keep.txt")

    def test_git_access_has_no_unbounded_run_method(self) -> None:
        """Méthode morte run() supprimée.

        Seul execute() (borné) et staged_diff() (streaming) existent.
        """
        access = gitdiff.GitAccess(self.repo.root)
        self.assertFalse(hasattr(access, "run"))

    def test_execute_failure_is_internal(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        with mock.patch("subprocess.run", side_effect=OSError("echec")):
            with self.assertRaises(ToolFailure):
                access.execute(("rev-parse", "--verify", "objet-inexistant-xyz"))

    def test_staged_diff_truncation_flag(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        self.repo.write("a.txt", "x\n")
        self.repo.stage("a.txt")
        raw, truncated = access.staged_diff(10**9)
        self.assertFalse(truncated)
        self.assertIn(b"a.txt", raw)
        _, truncated = access.staged_diff(10)
        self.assertTrue(truncated)

    def test_no_git_call_inherits_the_server_stdin_pipe(self) -> None:
        """`stdin=DEVNULL` sur TOUS les appels git (le canal JSON-RPC).

        Le serveur parle MCP sur stdin : un sous-processus qui hérite de ce
        pipe pourrait en consommer les octets (protocole corrompu) ou s'y
        bloquer (canal figé, aucun timeout possible côté serveur). Les
        sous-commandes actuelles ne lisent pas stdin, mais un appel futur
        (`apply`, `hash-object --stdin`, un `textconv` si l'option sautait)
        le ferait : on ne laisse donc pas l'héritage en place.
        """
        access = gitdiff.GitAccess(self.repo.root)
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"", stderr=b""
            )
            access.execute(("rev-parse", "--is-inside-work-tree"))
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        proc = mock.MagicMock()
        proc.stdout.read.return_value = b""
        proc.wait.return_value = 0
        with mock.patch("subprocess.Popen", return_value=proc) as popen:
            access.staged_diff(1024)
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        # Les deux autres descripteurs restent capturés/devnull comme avant :
        # stdout est le seul à être lu, et rien n'est écrit sur le canal.
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs["stdout"], subprocess.PIPE)

    def test_staged_diff_popen_failure_is_internal(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        with mock.patch("subprocess.Popen", side_effect=OSError("echec")):
            with self.assertRaises(ToolFailure):
                access.staged_diff(1024)

    def test_staged_diff_stdout_read_error_is_internal(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        proc = mock.MagicMock()
        proc.stdout.read.side_effect = OSError("read error")
        with mock.patch("subprocess.Popen", return_value=proc):
            with self.assertRaises(ToolFailure):
                access.staged_diff(1024)
        proc.kill.assert_called_once()
        proc.wait.assert_called_once()

    def test_staged_diff_without_a_pipe_returns_no_bytes(self) -> None:
        """Branche défensive : sans `stdout`, rien à lire, rien à fermer.

        `subprocess.PIPE` est toujours passé par notre argv figé, donc la
        branche est inatteignable en production ; elle est testée pour que
        la mesure de couverture annoncée (100 % instructions / 100 %
        branches, ADR-003 « Preuve ») reste vraie au lieu d'être recopiée.
        """
        access = gitdiff.GitAccess(self.repo.root)
        proc = mock.MagicMock()
        proc.stdout = None
        proc.wait.return_value = 0
        with mock.patch("subprocess.Popen", return_value=proc):
            self.assertEqual(access.staged_diff(1024), (b"", False))

    def test_staged_diff_process_nonzero_exit_is_internal(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        proc = mock.MagicMock()
        proc.stdout.read.return_value = b"some diff"
        proc.wait.return_value = 1
        with mock.patch("subprocess.Popen", return_value=proc):
            with self.assertRaises(ToolFailure):
                access.staged_diff(1024)

    def test_staged_diff_process_wait_timeout_is_internal(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        proc = mock.MagicMock()
        proc.stdout.read.return_value = b"some diff"
        proc.wait.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=30)
        with mock.patch("subprocess.Popen", return_value=proc):
            with self.assertRaises(ToolFailure):
                access.staged_diff(1024)
        proc.kill.assert_called_once()

    def test_execute_success_returns_completed_process(self) -> None:
        access = gitdiff.GitAccess(self.repo.root)
        completed = access.execute(("rev-parse", "--is-inside-work-tree"))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), b"true")

    def test_terminate_process_ignores_oserror_and_timeout(self) -> None:
        proc = mock.MagicMock()
        proc.kill.side_effect = OSError("already dead")
        proc.wait.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=1)
        gitdiff._terminate_process(proc)


    def test_resolve_root_refuses_garbage(self) -> None:
        for bad in ("", "/definitely/not/here", "\x00"):
            with self.subTest(root=bad):
                with self.assertRaises(ValueError):
                    server._resolve_root(bad)
        self.assertTrue(server._resolve_root(str(self.repo.root)).is_dir())


class InProcessToolTests(unittest.TestCase):
    """Outils appelés dans le processus : même code, sans stdio."""

    def test_ping_read_diff_and_sanitize_in_process(self) -> None:
        repo = GitRepo("heimdall-units-", self)
        repo.write("app.py", "x = 1\n")
        repo.stage("app.py")
        mcp_server = server.build_server(str(repo.root))

        async def body() -> dict[str, Any]:
            out: dict[str, Any] = {}
            for name, arguments in (
                ("ping", {}),
                ("read_diff", {}),
                ("sanitize_file", {"path": "app.py"}),
            ):
                result = await mcp_server.call_tool(name, arguments)
                out[name] = json.loads(result.content[0].text)
            return out

        out = asyncio.run(body())
        self.assertEqual(out["ping"], {"pong": True})
        self.assertEqual([item["file"] for item in out["read_diff"]["files"]], ["app.py"])
        self.assertEqual(out["sanitize_file"]["path"], "app.py")

    def test_server_tools_match_the_closed_registry(self) -> None:
        tools = server._tools(_Path("/"))
        self.assertEqual(sorted(tools), ["ping", "read_diff", "sanitize_file"])
        for name, tool in tools.items():
            with self.subTest(tool=name):
                self.assertNotIn("root", inspect.signature(tool).parameters)


class MaskingRulesTests(unittest.TestCase):
    """Chaque règle de masquage, directement, sans serveur."""

    def test_empty_string_has_zero_entropy(self) -> None:
        self.assertEqual(masking.shannon_entropy(""), 0.0)

    def test_bare_dense_token_low_entropy_is_not_masked(self) -> None:
        masked, count = masking.mask_text(" " + "0" * 40 + " ")
        self.assertEqual(count, 0)
        self.assertNotIn("<REDACTED:", masked)

    def test_secret_type_matrix(self) -> None:
        cases = (
            (None, "ghp_abc", "github"),
            (None, "glpat-abc", "gitlab"),
            (None, "xoxb-abc", "slack"),
            (None, "sk_live_abc", "stripe"),
            (None, "shpat_abc", "webhook_secret"),
            (None, "npm_abc", "package_token"),
            (None, "AIza-abc", "google_api_key"),
            (None, fake_token("AKIA", 36), "aws"),
            (None, "-----BEGIN X", "private_key"),
            ("my_private_key", "abc", "private_key"),
            ("aws_region", "abc", "aws"),
            ("ssh_config", "abc", "ssh_key"),
            ("openai_model", "abc", "openai"),
            (None, "abc", "generic_secret"),
        )
        for key, value, expected in cases:
            with self.subTest(key=key, value=value):
                self.assertEqual(masking._secret_type(key, value), expected)

    def test_prefix_vocabulary_is_fully_mapped(self) -> None:
        """Invariant de `_secret_type` : tout préfixe connu a son type.

        C'est ce test (et lui seul) qui rend la sortie de boucle sans
        retour inatteignable : si un préfixe est ajouté au vocabulaire
        sans sa ligne dans la table, ce test casse au lieu de laisser un
        repli silencieux vers `generic_secret`.
        """
        for prefix in masking._KNOWN_PREFIXES:
            with self.subTest(prefix=prefix):
                token = prefix + "X" * 40
                self.assertNotEqual(masking._secret_type(None, token), "generic_secret")

    def test_bare_and_typing_vocabularies_cannot_diverge(self) -> None:
        """Un préfixe masqué est forcément un préfixe connu (par construction).

        `_KNOWN_PREFIXES` est dérivé de `_BARE_PREFIXES` : l'oubli de
        `pk_test_` (jeton masqué mais typé `generic_secret`, donc tri LLM
        dégradé) ne peut plus se reproduire. Le test verrouille le lien, au
        cas où quelqu'un remplacerait un jour la dérivation par une liste.
        """
        normalised = {prefix.lower().replace("\\", "") for prefix in masking._BARE_PREFIXES}
        self.assertEqual(normalised, set(masking._KNOWN_PREFIXES))

    def test_stripe_test_key_prefixes_are_typed_as_stripe(self) -> None:
        """`pk_test_` / `rk_test_` : masqués ET typés `stripe`.

        Régression de revue : ces préfixes n'étaient que dans le vocabulaire
        de masquage, donc un jeton Stripe en mode test partait en
        `<REDACTED:generic_secret>` — pas de fuite, mais un tri dégradé que
        le LLM ne peut pas rattraper.
        """
        for prefix in ("pk_test_", "rk_test_", "pk_live_", "rk_live_"):
            token = fake_token(prefix, 40)
            with self.subTest(prefix=prefix):
                self.assertEqual(masking._secret_type(None, token), "stripe")
                bare, count = masking.mask_text(token)
                self.assertEqual(count, 1)
                self.assertEqual(bare, f"<REDACTED:stripe:len={len(token)}>")
                assigned, count = masking.mask_text(f'CLE = "{token}"')
                self.assertEqual(count, 1)
                self.assertEqual(assigned, f'CLE = "<REDACTED:stripe:len={len(token)}>"')

    def test_looks_like_secret_matrix(self) -> None:
        self.assertFalse(masking._looks_like_secret(None, ""))
        self.assertFalse(masking._looks_like_secret(None, "$MY_VAR"))
        self.assertTrue(masking._looks_like_secret(None, "ghp_abc"))
        self.assertTrue(masking._looks_like_secret("password", "x"))
        self.assertTrue(masking._looks_like_secret(None, "9f8a7b6c5d4e3f2a1b0c"))

    def test_authorization_header_is_masked(self) -> None:
        masked, count = masking.mask_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        self.assertEqual(count, 1)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", masked)

    def test_url_credentials_are_masked(self) -> None:
        masked, count = masking.mask_text("postgres://admin:sup3rsecret@db.internal/app")
        self.assertEqual(count, 1)
        self.assertNotIn("sup3rsecret", masked)

    def test_url_token_without_password_is_masked(self) -> None:
        """Userinfo SANS mot de passe : `https://<jeton>@hôte` (remote git, CI).

        `_URL_CREDENTIALS` exige `utilisateur:motdepasse@`, donc ce jeton
        n'était vu par AUCUNE règle : court et sans préfixe connu, il
        partait en clair. Les filets `bare` ne rattrapent qu'au-delà de
        32 caractères denses ou d'un préfixe connu.
        """
        for line, secret in (
            ("git clone https://tok1234567890@serveur/repo", "tok1234567890"),
            ("remote: https://ghp_court1@github.com/o/r.git", "ghp_court1"),
            ("curl https://monmotdepasse123@serveur/chemin", "monmotdepasse123"),
        ):
            with self.subTest(line=line):
                masked, count = masking.mask_text(line)
                self.assertEqual(count, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:url_userinfo:", masked)

    def test_url_userinfo_that_is_a_username_stays_readable(self) -> None:
        """Un nom d'utilisateur n'est pas un jeton : le seuil est mesuré.

        Secrets ≥ 3,09 bits par caractère (`monmotdepasse`), identités
        ≤ 2,91 (`utilisateur`), et sous 8 caractères de toute façon
        (`alice`, `deploy`). L'hôte reste lisible dans tous les cas : c'est
        lui qui sert au tri.
        """
        for user, host in (
            ("alice", "git.interne"),
            ("utilisateur", "git.interne"),
        ):
            with self.subTest(user=user):
                masked, _ = masking.mask_text(f"https://{user}@{host}")
                self.assertNotIn("url_userinfo", masked)
                self.assertIn(user, masked)
                self.assertIn(host, masked)

    def test_bare_url_keeps_its_precise_type(self) -> None:
        """Sans affectation qui fait de l'ombre, seul le mot de passe part."""
        masked, _ = masking.mask_text("voir postgres://admin:sup3rsecret@db.internal/app ici")
        self.assertNotIn("sup3rsecret", masked)
        self.assertIn("url_password", masked)
        self.assertIn("db.internal", masked)

    def test_quoted_assignment_is_masked(self) -> None:
        masked, count = masking.mask_text('token = "hunter2-long-value-xyz"')
        self.assertEqual(count, 1)
        self.assertNotIn("hunter2-long-value-xyz", masked)

    def test_generic_key_and_pass_names_are_masked(self) -> None:
        """Noms génériques : `KEY=`, `PASS=`, `AWS_KEY=`, `MYKEY=`.

        `_SECRET_KEY` exigeait un qualificatif (`api_key`, `access_key`…), donc
        `KEY=hunter2` et `PASS=abc12345` passaient en clair vers le LLM et son
        historique — vérifié par exécution avant correctif.
        """
        for line, secret in (
            ("KEY=hunter2", "hunter2"),
            ("PASS=abc12345", "abc12345"),
            ("AWS_KEY=hunter2", "hunter2"),
            ("DB_PASS=hunter2", "hunter2"),
            ("MYKEY=ab12", "ab12"),
            ('KEY="hunter2"', "hunter2"),
            ('AWS_KEY="hunter2"', "hunter2"),
            ("PASSPHRASE=abc12345", "abc12345"),
            # Préfixe connu : masqué même SANS chiffre. Par la règle LONGUE le
            # préfixe est déjà testé en amont de la règle générique ; c'est
            # donc la règle COURTE qui atteint ce chemin (`ghp_` fait 4
            # caractères, avec un chiffre pour passer le filtre court).
            ("MYKEY=ghp_factice", "ghp_factice"),
            ("KEY=ghp_1", "ghp_1"),
            ("PASS=akia_7", "akia_7"),
        ):
            with self.subTest(line=line):
                masked, count = masking.mask_text(line)
                self.assertEqual(count, 1)
                self.assertNotIn(secret, masked)

    def test_generic_names_keep_ordinary_code_readable(self) -> None:
        """`key`/`pass` seuls sont faibles : le second rang exige un credential.

        Ancrage par FIN (`key$`) : `AWS_KEY` et `MYKEY` matchent, `keyboard`,
        `keyword` et `monkey` non. Et la valeur doit encore ressembler à un
        secret (au moins un chiffre), sinon `key: "name"` d'un JSON ordinaire
        serait masqué — mesuré sur 1,29 million de lignes de corpus.
        """
        for line in (
            'key = "production"',
            'key: "name"',
            "KEY = value",
            "keyboard = 1",
            "keyword = 1",
            "monkey = 1",
            "bypass = True",
            "compass = x",
            "passed = 1",
            "cnonce = md5(x)",
            "best_key = max(sizes, key=lambda k: sizes[k])",
            # 2e rang sans chiffre : `KEY`/`AWS_KEY` seuls sont faibles, la
            # valeur doit ressembler à un credential. Un nom QUALIFIÉ
            # (`API_KEY`, `SECRET`) reste masqué sans condition — voir
            # `test_generic_key_and_pass_names_are_masked`.
            'AWS_KEY="aws_secret_value"',
            "KEY=huntervalue",
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_long_unquoted_value_is_masked_whole(self) -> None:
        """`SECRET=` + 5000 caractères : plus de queue en clair.

        La borne `{6,4096}` masquait les 4096 premiers caractères et laissait
        les 904 suivants en clair APRÈS le marqueur — une fuite déguisée en
        masquage, vérifiée par exécution. La borne haute ne protégeait de rien
        (aucun quantificateur imbriqué, rien ne suit le groupe), donc
        supprimée : `{6,}`.
        """
        for length in (5000, 20_000, 100_000):
            value = "b" * length
            with self.subTest(length=length):
                masked, count = masking.mask_text(f"SECRET={value}")
                self.assertEqual(count, 1)
                self.assertEqual(masked, f"SECRET=<REDACTED:generic_secret:len={length}>")
                self.assertNotIn("b" * 60, masked)

    def test_short_evocative_value_is_masked(self) -> None:
        """`SECRET=abc12`, `PASSWORD=1234` : sous 6 caractères, c'était en clair.

        La borne de 6 de `_UNQUOTED_ASSIGNMENT` laissait partir ces lignes
        vers le LLM et son historique alors que le nom dit « secret ».
        """
        for line, secret in (
            ("SECRET=abc12", "abc12"),
            ("PASSWORD=1234", "1234"),
            ("secret=x1", "x1"),
            ("TOKEN=a9", "a9"),
        ):
            with self.subTest(line=line):
                masked, count = masking.mask_text(line)
                self.assertEqual(count, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)

    def test_short_rule_does_not_shadow_the_long_one(self) -> None:
        """Deux fenêtres, pas une : une valeur courte matche tôt dans la ligne.

        Abaisser la borne du motif long avait un effet de bord mesuré :
        `max_bytes: int` matchait d'abord et consommait la suite du texte,
        si bien que `DEFAULT_MAX_BYTES` n'était plus vu du tout. La règle
        courte est donc SÉPARÉE, et ce test verrouille qu'elle n'absorbe
        rien des règles longues.
        """
        line = "def read_diff(max_bytes: int = DEFAULT_MAX_BYTES) -> str:"
        masked, count = masking.mask_text(line)
        self.assertEqual(count, 1)
        # La valeur longue est celle qui est remplacée (17 caractères) ; le
        # type `int` de 3 caractères reste lisible — une seule fenêtre
        # n'aurait vu que lui et laissé `DEFAULT_MAX_BYTES` partir en clair.
        self.assertEqual(
            masked,
            "def read_diff(max_bytes: int = <REDACTED:generic_secret:len=17>) -> str:",
        )

    def test_short_rule_keeps_ordinary_code_readable(self) -> None:
        """Le bruit est mesuré, pas espéré : littéraux, mots, annotations.

        Mesuré sur 1,29 million de lignes de corpus (dépôt + bibliothèques
        tierces) : 36 lignes tierces nouvellement masquées (constantes dont
        le NOM contient `auth`/`cert`/`salt`, comme `UNAUTHORIZED = 401`),
        0 dans le dépôt lui-même, et 0 ligne auparavant masquée devenue
        lisible. Les faux positifs assumés ci-dessous sont épinglés : si le
        bruit augmente, ce test doit être mis à jour consciemment.
        """
        for line in (
            "session = None",
            "auth = None",
            "cert = null",
            "id-token: write",
            "def __init__(self, api_key: str) -> None:",
            "x = 1",
            "port = 8080",
            "token = 0",
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_short_rule_false_positives_are_pinned(self) -> None:
        """Faux positifs CONNUS et assumés de la règle courte (36 en corpus).

        `UNAUTHORIZED = 401` et `salt_len = 16` sont masqués : le nom
        contient `auth`/`salt` et la valeur est alphanumérique courte. Les
        épingler évite deux tentations opposées — les « corriger » en
        doublant le bruit, ou les oublier et croire le filtre parfait.
        """
        for line, length in (
            ("UNAUTHORIZED = 401", 3),
            ("salt_len = 16", 2),
            ("token = undefined", 9),  # règle LONGUE préexistante : non concerné
        ):
            with self.subTest(line=line):
                masked, count = masking.mask_text(line)
                self.assertEqual(count, 1)
                self.assertIn(f"len={length}>", masked)

    def test_mask_text_tail_appends_the_rest(self) -> None:
        masked, count = masking.mask_text('a = "ghp_ hei" b = 1')
        self.assertIn("b = 1", masked)


class DirectToolErrorTests(unittest.TestCase):
    """Branches d'erreur des outils, sans serveur : appels directs."""

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-units-", self)
        self.tools = server._tools(self.repo.root)

    def test_read_diff_rejects_bad_budget(self) -> None:
        for bad in (0, 1023, 65537):
            with self.subTest(bad=bad):
                payload = json.loads(self.tools["read_diff"](max_bytes=bad))
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_read_diff_outside_a_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-nogit-") as tmp:
            tools = server._tools(_Path(tmp))
            payload = json.loads(tools["read_diff"]())
            self.assertEqual(payload["error"]["code"], "NOT_A_GIT_REPO")

    def test_read_diff_tight_budget_truncates_in_process(self) -> None:
        self.repo.write("big.py", "x = 1\n" * 400)
        self.repo.stage("big.py")
        payload = json.loads(self.tools["read_diff"](max_bytes=1024))
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(json.dumps(payload).encode()), 1024)

    def test_internal_failure_does_not_leak_paths_or_secrets_to_stderr(self) -> None:
        """Exceptions inattendues : message statique seul, aucun secret ni chemin dans stderr."""
        with mock.patch.object(gitdiff, "GIT_CONFIG_OVERRIDES", ("-c", "hostile.invalid=1")):
            with mock.patch.object(
                gitdiff.GitAccess,
                "staged_diff",
                side_effect=RuntimeError(
                    "erreur /tmp/secret_dir avec KEY=sk_live_1234567890"  # noqa: S108
                ),
            ):
                with self.assertLogs("heimdall.mcp.server", level="ERROR") as cm:
                    res = self.tools["read_diff"]()
                payload = json.loads(res)
                self.assertEqual(payload["error"]["code"], "INTERNAL")
                logged = "\n".join(cm.output)
                self.assertIn("échec inattendu d'un outil MCP", logged)
                self.assertNotIn("/tmp/", logged)  # noqa: S108
                self.assertNotIn("sk_live", logged)
                self.assertNotIn("KEY=", logged)


    def test_sanitize_rejects_bad_bounds(self) -> None:
        for arguments in ({"start_line": 0}, {"max_lines": 0}, {"max_lines": 401}):
            with self.subTest(arguments=arguments):
                payload = json.loads(self.tools["sanitize_file"](path="x", **arguments))
                self.assertEqual(payload["error"]["code"], "INVALID_INPUT")

    def test_start_beyond_the_end_returns_an_empty_extract(self) -> None:
        self.repo.write("court.txt", "a\nb\n")
        payload = json.loads(self.tools["sanitize_file"](path="court.txt", start_line=99))
        self.assertEqual(payload["content"], "")
        self.assertEqual(payload["end_line"], 0)
        self.assertFalse(payload["truncated"])

    def test_overflow_entry_flags_truncation(self) -> None:
        entry = gitdiff.DiffEntry("x.py", False, (), True)
        _, truncated = server._masked_files([entry])
        self.assertTrue(truncated)

    def test_sanitize_missing_and_directory(self) -> None:
        payload = json.loads(self.tools["sanitize_file"](path="absent.py"))
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")
        (self.repo.root / "dossier").mkdir()
        payload = json.loads(self.tools["sanitize_file"](path="dossier"))
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

    def test_sanitize_outside_a_repo_and_forbidden(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-nogit-") as tmp:
            tools = server._tools(_Path(tmp))
            payload = json.loads(tools["sanitize_file"](path="x.py"))
            self.assertEqual(payload["error"]["code"], "NOT_A_GIT_REPO")
        payload = json.loads(self.tools["sanitize_file"](path=".git/config"))
        self.assertEqual(payload["error"]["code"], "FORBIDDEN_PATH")

    def test_sanitize_huge_content_is_capped_in_process(self) -> None:
        self.repo.write("gros.txt", ("z" * 1500 + "\n") * 80)
        payload = json.loads(self.tools["sanitize_file"](path="gros.txt"))
        self.assertTrue(payload["truncated"])
        self.assertEqual(len(payload["content"]), server.MAX_CONTENT_CHARS)

    def test_sanitize_line_longer_than_2000_is_capped(self) -> None:
        self.repo.write("long_line.txt", "y" * 5000 + "\n")
        payload = json.loads(self.tools["sanitize_file"](path="long_line.txt"))
        self.assertTrue(payload["truncated"])
        self.assertEqual(len(payload["content"]), gitdiff.MAX_LINE_CHARS)

    def test_redaction_marker_straddling_2000_char_boundary_is_cleaned(self) -> None:
        """Secret chevauchant la borne 2000 car : aucun fragment sans '>' fermant."""
        line = "x" * 1980 + f"'{FAKE_GITHUB_TOKEN}'\n"
        self.repo.write("straddle.py", line)
        payload = json.loads(self.tools["sanitize_file"](path="straddle.py"))
        content = payload["content"]
        self.assertNotIn("<REDACTED:", content)
        self.assertEqual(payload["redactions"], 0)

    def test_sanitize_too_large_precheck(self) -> None:
        big = self.repo.root / "gros.bin"
        big.write_bytes(b"x" * (server.MAX_FILE_BYTES + 1))
        payload = json.loads(self.tools["sanitize_file"](path="gros.bin"))
        self.assertEqual(payload["error"]["code"], "TOO_LARGE")

    def test_binary_sniff_bytes_constant_removed(self) -> None:
        """La constante morte _BINARY_SNIFF_BYTES a été supprimée (sniff complet)."""
        self.assertFalse(hasattr(server, "_BINARY_SNIFF_BYTES"))

    def test_sanitize_open_failures(self) -> None:
        """Échec d'ouverture du FICHIER visé : code d'erreur dédié.

        Seul le chemin visé est intercepté. Depuis `stdin=DEVNULL`,
        `subprocess` ouvre aussi `/dev/null` — via `os.open` (le module `io`
        passe par là depuis Python 3.13) — dans le processus parent : un
        mock global ferait échouer l'appel git avant même que la garde
        n'ouvre le fichier, et le code d'erreur testé serait masqué.
        """
        target = self.repo.write("f.txt", "x\n")
        real_open = server.os.open

        def failing(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if os.fspath(path) == str(target):
                raise OSError(errno.ELOOP, "lien")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(server.os, "open", side_effect=failing):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")

        def missing(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if os.fspath(path) == str(target):
                raise OSError(errno.ENOENT, "rien")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(server.os, "open", side_effect=missing):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "NOT_FOUND")

        def denied(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if os.fspath(path) == str(target):
                raise OSError(errno.EACCES, "permission")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(server.os, "open", side_effect=denied):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")

        def no_perm(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if os.fspath(path) == str(target):
                raise OSError(errno.EPERM, "operation")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(server.os, "open", side_effect=no_perm):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")
        self.assertTrue(target.is_file())

    def test_sanitize_lstat_permission_failure_is_internal(self) -> None:
        """`lstat` refusé (droits du dossier parent) : `INTERNAL`, pas `NOT_FOUND`.

        `NOT_FOUND` est réservé à l'absence (`ENOENT`/`ENOTDIR`) : annoncer
        « introuvable » un fichier peut-être présent fausse le tri et masque
        une panne d'intégrité.
        """
        self.repo.write("f.txt", "x\n")
        with mock.patch.object(server.os, "lstat", side_effect=OSError(errno.EACCES, "x")):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")

    def test_sanitize_replaced_between_stat_and_open(self) -> None:
        self.repo.write("f.txt", "x\n")
        real_fstat = server.os.fstat

        def swapped(handle: int) -> Any:
            info = real_fstat(handle)
            return mock.Mock(st_dev=info.st_dev + 1, st_ino=info.st_ino)

        with mock.patch.object(server.os, "fstat", side_effect=swapped):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")

    def test_sanitize_type_swapped_between_stat_and_open(self) -> None:
        """Régulier → FIFO entre les deux appels : l'ouverture non bloquante
        laisse passer, le contrôle post-ouverture refuse (INTERNAL)."""
        self.repo.write("f.txt", "x\n")
        real_fstat = server.os.fstat

        def swapped(handle: int) -> Any:
            info = real_fstat(handle)
            fields = list(tuple(info))
            fields[0] = stat.S_IFIFO | 0o600
            return server.os.stat_result(tuple(fields))

        with mock.patch.object(server.os, "fstat", side_effect=swapped):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")

    def test_sanitize_grown_between_stat_and_read(self) -> None:
        """Le fichier grossit après `lstat` : second garde-fou `TOO_LARGE`."""
        self.repo.write("f.txt", "x\n")
        with mock.patch.object(
            server, "_read_bounded", return_value=b"x" * (server.MAX_FILE_BYTES + 1)
        ):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "TOO_LARGE")

    def test_sanitize_grown_during_read(self) -> None:
        """Le fichier grossit *pendant* la lecture : la boucle s'arrête au
        plafond + 1 et le dépassement est refusé (pas de lecture infinie).

        Testé directement sur `_read_bounded` avec un descripteur factice :
        mocker `os.read` autour de l'outil complet empoisonnerait aussi les
        lectures des sous-processus git (boucle infinie).
        """
        with mock.patch.object(server.os, "read", return_value=b"y" * 65536):
            data = server._read_bounded(12345)
        self.assertGreater(len(data), server.MAX_FILE_BYTES)
        self.assertLessEqual(len(data), server.MAX_FILE_BYTES + 65536)

    def test_sanitize_binary_sniff(self) -> None:
        self.repo.write_bytes("b.bin", b"AB\x00CD")
        payload = json.loads(self.tools["sanitize_file"](path="b.bin"))
        self.assertEqual(payload["error"]["code"], "BINARY_FILE")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO POSIX uniquement")
    def test_fifo_does_not_hang_the_server(self) -> None:
        """Un FIFO piégé : enveloppe, pas de blocage (DoS du canal stdio).

        Appel direct in-process dans un thread avec timeout : sans le
        garde-fou, ce test pendrait au lieu d'échouer (le thread démon
        ne bloque jamais la suite ; une exception inattendue y laisse
        `box` vide et fait échouer l'assertion, en clair).
        """
        os.mkfifo(self.repo.root / "creds.txt")
        box: dict[str, Any] = {}

        def call() -> None:
            box["payload"] = json.loads(self.tools["sanitize_file"](path="creds.txt"))

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=15)
        self.assertFalse(worker.is_alive(), "sanitize_file pendu sur le FIFO !")
        self.assertIn("payload", box)
        self.assertEqual(box["payload"]["error"]["code"], "BINARY_FILE")

    def test_socket_file_is_refused(self) -> None:
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(self.repo.root / "sock"))
        finally:
            sock.close()
        payload = json.loads(self.tools["sanitize_file"](path="sock"))
        self.assertEqual(payload["error"]["code"], "BINARY_FILE")

    def test_mark_failure_remaining_shapes(self) -> None:
        self.assertEqual(server._mark_failure({"content": ["brute"]}), {"content": ["brute"]})
        self.assertEqual(
            server._mark_failure({"content": [{"type": "text"}]}),
            {"content": [{"type": "text"}]},
        )
        self.assertEqual(
            server._mark_failure({"content": [{"type": "text", "text": 12}]}),
            {"content": [{"type": "text", "text": 12}]},
        )
        self.assertEqual(
            server._mark_failure({"content": [{"type": "text", "text": "pas du json"}]}),
            {"content": [{"type": "text", "text": "pas du json"}]},
        )


class ExecuteFailureTests(unittest.TestCase):
    def test_timeout_and_os_error_are_internal(self) -> None:
        repo = GitRepo("heimdall-units-", self)
        access = gitdiff.GitAccess(repo.root)
        with mock.patch.object(
            gitdiff.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 30)
        ):
            with self.assertRaises(ToolFailure):
                access.execute(("diff",))
        with mock.patch.object(gitdiff.subprocess, "run", side_effect=OSError("panne")):
            with self.assertRaises(ToolFailure):
                access.execute(("diff",))


class UnquoteTests(unittest.TestCase):
    """Le décodeur C-quote, en pur : octets d'abord, UTF-8 ensuite."""

    def parse(self, *lines: str) -> Any:
        return gitdiff.parse_diff("\n".join(lines))

    def test_utf8_name_is_decoded_not_mojibake(self) -> None:
        entries, _ = self.parse(
            'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"',
            "new file mode 100644",
            "--- /dev/null",
            '+++ "b/caf\\303\\251.py"',
            "@@ -0,0 +1 @@",
            "+x",
        )
        self.assertEqual([entry.path for entry in entries], ["café.py"])

    def test_bel_escape_is_refused_fail_closed(self) -> None:
        # BEL (0x07) décodé puis interdit par la grammaire : refus, pas de nom faux.
        with self.assertRaises(ToolFailure):
            self.parse(
                'diff --git "a/b\\007c" "b/b\\007c"',
                "--- /dev/null",
                '+++ "b/b\\007c"',
                "@@ -0,0 +1 @@",
                "+x",
            )

    def test_truncated_or_bad_escape_is_internal(self) -> None:
        for quoted in ('"b/abc\\"', '"b/ab\\x4"', '"b/ab\\xZZ"', '"b/a\\777c"', '"b/a\\db"'):
            with self.subTest(quoted=quoted):
                with self.assertRaises(ToolFailure):
                    self.parse(
                        "diff --git a/x b/x",
                        "--- /dev/null",
                        f"+++ {quoted}",
                        "@@ -0,0 +1 @@",
                        "+x",
                    )

    def test_invalid_utf8_bytes_are_internal(self) -> None:
        with self.assertRaises(ToolFailure):
            self.parse(
                "diff --git a/x b/x",
                "--- /dev/null",
                '+++ "b/bad\\xffc"',
                "@@ -0,0 +1 @@",
                "+x",
            )

    def test_tab_suffixed_header_keeps_first_field(self) -> None:
        """Git suffixe d'une tabulation les chemins à espace (horodatage)."""
        entries, _ = self.parse(
            "diff --git a/sp ace.txt b/sp ace.txt",
            "--- a/sp ace.txt",
            "+++ b/sp ace.txt\t2026-10-13",
            "@@ -0,0 +1 @@",
            "+x",
        )
        self.assertEqual([entry.path for entry in entries], ["sp ace.txt"])

    def test_simple_escape_decodes_then_fails_closed(self) -> None:
        """`\\t` décodé en vraie tabulation, refusée par la grammaire."""
        with self.assertRaises(ToolFailure):
            self.parse(
                "diff --git a/x b/x",
                "--- /dev/null",
                '+++ "b/a\\tb"',
                "@@ -0,0 +1 @@",
                "+x",
            )

    def test_line_overflow_flags_truncation(self) -> None:
        """5000 lignes par fichier : au-delà, drapeau, pas de plantage."""
        lines = [
            "diff --git a/gros.py b/gros.py",
            "--- /dev/null",
            "+++ b/gros.py",
            "@@ -0,0 +1 @@",
        ]
        lines.extend("+x" for _ in range(gitdiff.MAX_LINES_PER_FILE + 5))
        entries, truncated = self.parse(*lines)
        self.assertTrue(truncated)
        self.assertEqual(len(entries[0].lines), gitdiff.MAX_LINES_PER_FILE)

    def test_garbage_binary_line_is_ignored_but_flagged(self) -> None:
        entries, truncated = self.parse(
            "diff --git a/x b/x",
            "Binary files nonsense without separator",
            "@@ -0,0 +1 @@",
            "+x",
        )
        self.assertEqual(entries, [])
        self.assertTrue(truncated)

    def test_git_binary_patch_is_flagged_not_smuggled(self) -> None:
        """`GIT binary patch` (jamais émis sans `--binary`) : pas de nom
        fantôme par mauvais offset, fichier signalé incomplet."""
        entries, truncated = self.parse(
            "diff --git a/logo.png b/logo.png",
            "new file mode 100644",
            "index 0000000..8194775",
            "GIT binary patch",
            "literal 3",
            "KcmZQ",
        )
        self.assertEqual(entries, [])
        self.assertTrue(truncated)

    def test_degenerate_binary_separator_is_ignored(self) -> None:
        """Ligne `Binary files` difforme : rien à nommer, incomplet signalé."""
        entries, truncated = self.parse(
            "diff --git a/x b/x",
            "Binary files  and  differ",
            "@@ -0,0 +1 @@",
            "+x",
        )
        self.assertEqual(entries, [])
        self.assertTrue(truncated)

    def test_added_and_deleted_binary_fast_paths(self) -> None:
        added, _ = self.parse(
            "diff --git a/n.bin b/n.bin",
            "Binary files /dev/null and b/n.bin differ",
        )
        self.assertEqual([entry.path for entry in added], ["n.bin"])
        self.assertTrue(added[0].binary)
        deleted, _ = self.parse(
            "diff --git a/o.bin b/o.bin",
            "--- a/o.bin",
            "+++ /dev/null",
            "Binary files a/o.bin and /dev/null differ",
        )
        self.assertEqual(deleted, [])

    def test_modified_binary_with_and_in_its_name_keeps_the_whole_name(self) -> None:
        """Binaire modifié `f and g.bin` : nom entier, pas `g.bin` tronqué.

        L'ancien `rpartition(" and ")` coupait au dernier séparateur et
        cassait l'aller-retour `read_diff` → `sanitize_file` (`NOT_FOUND`
        sur le nom affiché). L'ancien et le nouveau côté nommant le MÊME
        fichier, la découpe retenue est celle où les deux côtés concordent.
        """
        entries, truncated = self.parse(
            "diff --git a/f and g.bin b/f and g.bin",
            "index 1234567..89abcde 100644",
            "Binary files a/f and g.bin and b/f and g.bin differ",
        )
        self.assertFalse(truncated)
        self.assertEqual([entry.path for entry in entries], ["f and g.bin"])
        self.assertTrue(entries[0].binary)

    def test_modified_binary_with_several_and_separators_picks_the_matching_split(self) -> None:
        """`a and b and c.bin` modifié : seule la découpe concordante gagne."""
        entries, truncated = self.parse(
            "diff --git a/a and b and c.bin b/a and b and c.bin",
            "Binary files a/a and b and c.bin and b/a and b and c.bin differ",
        )
        self.assertFalse(truncated)
        self.assertEqual([entry.path for entry in entries], ["a and b and c.bin"])

    def test_truly_ambiguous_binary_name_is_flagged_not_truncated(self) -> None:
        """Plusieurs découpes sans concordance : `truncated`, jamais un nom tronqué.

        Git ne citant pas les espaces, un nom reste théoriquement ambigu ;
        on signale l'incomplet plutôt que d'afficher un nom coupé (qui
        casserait l'aller-retour vers `sanitize_file`). Pas de fuite dans
        tous les cas : un binaire ne porte aucune ligne.
        """
        entries, truncated = self.parse(
            "diff --git a/x b/y",
            "Binary files a/p and q and b/r and s differ",
        )
        self.assertEqual(entries, [])
        self.assertTrue(truncated)

    def test_deleted_text_file_has_no_new_side(self) -> None:
        """`+++ /dev/null` seul : rien à nommer, le fichier sort de la liste."""
        entries, _ = self.parse(
            "diff --git a/vieux.py b/vieux.py",
            "deleted file mode 100644",
            "--- a/vieux.py",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            "-x = 1",
        )
        self.assertEqual(entries, [])

    def test_rename_to_nowhere_keeps_previous_path(self) -> None:
        """`rename to /dev/null` n'existe jamais via git ; s'il apparaissait
        (sortie corrompue), le chemin précédent est conservé, pas écrasé."""
        entries, _ = self.parse(
            "diff --git a/x b/y",
            "--- a/x",
            "+++ b/y",
            "rename to /dev/null",
            "@@ -0,0 +1 @@",
            "+z",
        )
        self.assertEqual([entry.path for entry in entries], ["y"])

    def test_copy_to_header_extracts_exact_path(self) -> None:
        """`copy to neuf.txt` extrait 'neuf.txt', pas 'ef.txt'."""
        entries, _ = self.parse(
            "diff --git a/source.txt b/neuf.txt",
            "copy from source.txt",
            "copy to neuf.txt",
            "--- a/source.txt",
            "+++ b/neuf.txt",
            "@@ -0,0 +1 @@",
            "+z",
        )
        self.assertEqual([entry.path for entry in entries], ["neuf.txt"])

    def test_copy_to_nowhere_keeps_previous_path(self) -> None:
        """`copy to /dev/null` conserve le chemin précédent si aucun nom valide."""
        entries, _ = self.parse(
            "diff --git a/x b/y",
            "--- a/x",
            "+++ b/y",
            "copy to /dev/null",
            "@@ -0,0 +1 @@",
            "+z",
        )
        self.assertEqual([entry.path for entry in entries], ["y"])


class ParserStateTests(unittest.TestCase):
    def test_combined_diff_starts_a_file(self) -> None:
        entries, _ = gitdiff.parse_diff("diff --cc x\n--- a/x\n+++ b/x\n@@ -1,0 +1 @@\n+y\n")
        self.assertEqual([(entry.path, entry.lines) for entry in entries], [("x", ((1, "y"),))])

    def test_noise_before_first_file_is_ignored(self) -> None:
        entries, _ = gitdiff.parse_diff("bruit\nencore du bruit\n")
        self.assertEqual(entries, [])

    def test_malformed_hunk_header_is_skipped(self) -> None:
        entries, _ = gitdiff.parse_diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ garbage\n+y\n")
        self.assertEqual(entries, [])

    def test_unreadable_hunk_header_flags_truncation(self) -> None:
        """Format d'hunk non reconnu : fail-closed, jamais du silence.

        Le hunk ne s'ouvre pas, donc les lignes `+` qui suivent ne sont
        pas montrées — et la réponse doit le dire (`truncated: true`),
        sinon le LLM lit une absence de changement là où git en montre.
        """
        for header in ("@@ garbage", "@@@ nonsense", "@@@@@ @@"):
            with self.subTest(header=header):
                entries, truncated = gitdiff.parse_diff(
                    f"diff --git a/x b/x\n--- a/x\n+++ b/x\n{header}\n+y\n"
                )
                self.assertEqual(entries, [])
                self.assertTrue(truncated)

    def test_combined_hunk_shows_the_lines_added_to_every_parent(self) -> None:
        """Hunk combiné (`@@@ `) : lu, pas jeté en silence.

        L'argv figé (`diff --cached`) n'émet pas de hunk combiné sur les
        versions actuelles de git, mais le parseur le comprend quand même :
        une grammaire non reconnue est un angle mort, pas une garantie.
        Chaque ligne porte un préfixe PAR PARENT (`+` ajouté, `-` absent,
        espace contexte) ; seule une ligne ajoutée côté tous les parents
        est une ligne ajoutée du fichier.
        """
        entries, truncated = gitdiff.parse_diff(
            "diff --cc x\n"
            "index 751cc53,dd63c94..0000000\n"
            "mode 100644\n"
            "--- a/x\n"
            "+++ b/x\n"
            "@@@ -1,4 -1,4 +1,5 @@@\n"
            "  contexte\n"
            "++ajoutee partout\n"
            " +ajoutee chez un seul parent\n"
            " -absente du resultat\n"
        )
        self.assertFalse(truncated)
        self.assertEqual(
            [(entry.path, entry.lines) for entry in entries],
            [("x", ((2, "ajoutee partout"),))],
        )

    def test_combined_hunk_of_three_parents_uses_three_prefixes(self) -> None:
        """Merge octopus : un préfixe par parent, donc 3 caractères."""
        entries, _ = gitdiff.parse_diff(
            "diff --cc x\n"
            "--- a/x\n"
            "+++ b/x\n"
            "@@@ -1,2 -1,2 -1,2 +1,3 @@@\n"
            "+++ajoutee partout\n"
            "  +ajoutee chez un seul parent\n"
        )
        self.assertEqual(entries[0].lines, ((1, "ajoutee partout"),))

    def test_combined_hunk_with_a_truncated_body_flags_truncation(self) -> None:
        """Corps plus court que le nombre de parents : fail-closed aussi."""
        entries, truncated = gitdiff.parse_diff(
            "diff --cc x\n--- a/x\n+++ b/x\n@@@ -1,2 -1,2 +1,3 @@@\n+\n"
        )
        self.assertEqual(entries, [], "aucune ligne lisible, le fichier n'est pas montré")
        self.assertTrue(truncated)

    def test_unmerged_path_is_flagged_never_a_silent_empty_diff(self) -> None:
        """`git diff --cached` sur un index en conflit ne montre AUCUNE ligne.

        Sans drapeau, `read_diff` répondrait « aucun changement indexé »
        alors que le dépôt est en cours de fusion : l'information manquante
        doit être annoncée (`truncated: true`).
        """
        entries, truncated = gitdiff.parse_diff(
            "diff --git a/nouveau.py b/nouveau.py\n"
            "new file mode 100644\n"
            "index 0000000..a1b2c3d\n"
            "--- /dev/null\n"
            "+++ b/nouveau.py\n"
            "@@ -0,0 +1 @@\n"
            "+x = 1\n"
            "* Unmerged path conflictuel.py\n"
        )
        self.assertEqual([entry.path for entry in entries], ["nouveau.py"])
        self.assertTrue(truncated)


class ConfineDirectTests(unittest.TestCase):
    def test_non_string_is_refused(self) -> None:
        self.assertFalse(is_rel_path(None))
        self.assertFalse(is_rel_path(12))
        with tempfile.TemporaryDirectory(prefix="heimdall-garde-") as tmp:
            root = _Path(tmp)
            for bad in (None, 12, b"x", ""):
                with self.subTest(bad=bad):
                    with self.assertRaises(PathEscape):
                        confine(root, bad)

    def test_real_file_with_forbidden_name_is_refused(self) -> None:
        # Atteint la re-validation finale : l'entrée passe la grammaire
        # mais le résolu (via un lien au nom propre) ne la passe pas.
        with tempfile.TemporaryDirectory(prefix="heimdall-garde-") as tmp:
            root = _Path(tmp)
            (root / "avec\ttab.py").write_text("x", encoding="utf-8")
            os.symlink(root / "avec\ttab.py", root / "lien-propre")
            with self.assertRaises(PathEscape):
                confine(root, "lien-propre")


class MainEntryTests(unittest.TestCase):
    def test_parse_args_defaults_and_explicit_root(self) -> None:
        self.assertEqual(parse_args([]).root, ".")
        self.assertEqual(parse_args(["--root", "/srv/depot"]).root, "/srv/depot")

    def test_main_refuses_a_missing_root_statically(self) -> None:
        marker = "SENTINELLE_RACINE"
        with mock.patch.object(entry, "run_stdio", side_effect=ValueError("racine requise")):
            with mock.patch("sys.stderr") as stderr:
                self.assertEqual(entry.main(["--root", marker]), 2)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertNotIn(marker, written)

    def test_main_success_path_returns_zero(self) -> None:
        """Le démarrage bloquant lui-même reste couvert en sous-processus ;
        ici on prouve le câblage (racine transmise, code 0)."""
        with mock.patch.object(entry, "run_stdio") as run:
            self.assertEqual(entry.main(["--root", "/srv/depot"]), 0)
        run.assert_called_once_with("/srv/depot")

    def test_main_handles_unexpected_startup_exception(self) -> None:
        """Échec MCPServer / démarrage : exit 2 + stderr sans chemin absolu ni secret."""
        leak_path = "/tmp/sensitive_installation/path.py"  # noqa: S108
        with mock.patch.object(
            entry, "run_stdio", side_effect=RuntimeError(f"crash at {leak_path}")
        ):
            with mock.patch("sys.stderr") as stderr:
                code = entry.main(["--root", "."])
        self.assertEqual(code, 2)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertNotIn("/tmp/", written)  # noqa: S108
        self.assertNotIn("secret", written)
        self.assertIn("erreur au démarrage du serveur MCP", written)

    def test_main_handles_broken_pipe_silently(self) -> None:
        """BrokenPipeError au démarrage ou à la coupure stdio : sortie silencieuse 0."""
        with mock.patch.object(entry, "run_stdio", side_effect=BrokenPipeError):
            with mock.patch("sys.stderr") as stderr:
                code = entry.main(["--root", "."])
        self.assertEqual(code, 0)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertEqual(written, "")

    def test_run_stdio_builds_then_runs(self) -> None:
        """`run_stdio` assemble puis démarre — `run` mocké, sans bloquer."""
        with mock.patch.object(server, "build_server") as build:
            server.run_stdio(".")
        build.assert_called_once_with(".")
        build.return_value.run.assert_called_once_with(transport="stdio")


if __name__ == "__main__":
    unittest.main()
