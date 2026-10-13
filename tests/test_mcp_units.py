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

    def test_unknown_tool_passes_through_to_the_sdk(self) -> None:
        """Registre fermé = réponse du SDK, pas de la frontière."""
        self.assertEqual(self.run_gate("exec", {}, result="sdk"), "sdk")

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

    def test_budget_pops_last_files_first(self) -> None:
        entries = [gitdiff.DiffEntry(f"f{i}.py", False, ((1, "x = 1"),)) for i in range(5)]
        files, truncated = server._masked_files(entries)
        self.assertFalse(truncated)
        self.assertTrue(server._fit_budget(files, 200))
        self.assertLessEqual(server._encoded_size(files), 200)

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
        target = self.repo.write("f.txt", "x\n")
        with mock.patch.object(server.os, "open", side_effect=OSError(errno.ELOOP, "lien")):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "INTERNAL")
        with mock.patch.object(server.os, "open", side_effect=OSError(errno.ENOENT, "rien")):
            payload = json.loads(self.tools["sanitize_file"](path="f.txt"))
            self.assertEqual(payload["error"]["code"], "NOT_FOUND")
        self.assertTrue(target.is_file())

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
