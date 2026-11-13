"""Tests de l'outil ``read_diff`` — sous-ticket #74 (contrat #16, 4.1).

Le dépôt d'exemple est créé dans ``tmp_path`` (jamais le dépôt Heimdall
lui-même) : ``GitRepoTestCase`` fabrique un vrai dépôt git, y compris pour
les cas tordus — fichier binaire, renommage, fichier avec une espace dans
son nom, ``diff.external`` configuré.

Les appels passent par le serveur réel en sous-processus, donc par un vrai
client MCP : c'est la réponse réellement sérialisée qui est vérifiée.
"""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from support import mcp_contract
from support.fake_secrets import FAKE_GITHUB_TOKEN
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

    def call_read_diff(
        self, arguments: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        """Appelle l'outil sur ce dépôt et renvoie sa charge utile décodée."""
        params = dict(arguments or {})
        params.update(kwargs)
        return tool_payload(call_tool("read_diff", params, root=self.repo))


class ReadDiffToolTests(GitRepoTestCase):
    def test_added_lines_are_listed_with_line_numbers(self) -> None:
        """Fait quand (#74) : le diff indexé est lu sur un repo d'exemple."""
        self.write(
            "app.py",
            f'TOKEN = "{FAKE_GITHUB_TOKEN}"\nprint("bonjour")\n',
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
        jeton = FAKE_GITHUB_TOKEN
        self.write("app.py", f'TOKEN = "{jeton}"\n')
        self.stage("app.py")
        response = json.dumps(self.call_read_diff())
        self.assertNotIn(jeton, response)
        self.assertIn("<REDACTED:github:len=40>", response)

    def test_redactions_counter_matches_the_markers(self) -> None:
        """Filet du contrat : redactions >= 1 implique un marqueur présent."""
        self.write(
            "app.py",
            f'A = "{FAKE_GITHUB_TOKEN}"\npassword = "hunter2"\n',
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

    def test_short_evocative_value_is_masked(self) -> None:
        """`SECRET=abc12`, `PASSWORD=1234` : sous 6 caractères, c'est un secret.

        Ces lignes partaient en clair vers le LLM et son historique : la borne
        de 6 caractères de la règle d'affectation non citée prenait le pas sur
        le nom évocateur. Test de bout en bout (dépôt git réel + vrai client
        MCP), donc la réponse sérialisée est bien celle qui est vérifiée.
        """
        self.write("court.env", "SECRET=abc12\nPASSWORD=1234\nTOKEN=x1\nMODE=read\n")
        self.stage("court.env")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        for secret in ("abc12", "1234", "x1"):
            with self.subTest(secret=secret):
                self.assertNotIn(f'"{secret}"', content)
                self.assertNotIn(f":{secret}", content)
        self.assertIn("MODE=read", content, "une valeur non secrète reste lisible")
        self.assertEqual(payload["files"][0]["redactions"], 3)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_short_quoted_value_is_masked_end_to_end(self) -> None:
        """`TOKEN="x1"`, `SECRET="ab1"` stagés : la forme quotée aussi est masquée.

        Dépôt git réel + vrai client MCP : c'est la réponse sérialisée qui est
        vérifiée. La forme non quotée l'était déjà, la quotée partait en clair.
        """
        self.write("court.env", 'TOKEN="x1"\nSECRET="ab1"\nMODE="read"\n')
        self.stage("court.env")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        for secret in ("x1", "ab1"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, content)
        self.assertIn("MODE=", content)
        self.assertIn("read", content, "une valeur non secrète reste lisible")
        self.assertEqual(payload["files"][0]["redactions"], 2)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_json_quoted_password_is_masked_end_to_end(self) -> None:
        """E-03 : une clé JSON entre guillemets ne fuit plus dans le diff."""
        self.write("config.json", '{"password": "hunter2!hunter"}\n')
        self.stage("config.json")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        self.assertNotIn("hunter2!hunter", content)
        self.assertIn("<REDACTED:generic_secret:len=14>", content)
        self.assertEqual(payload["files"][0]["redactions"], 1)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_generic_key_names_are_masked_end_to_end(self) -> None:
        """`KEY=hunter2`, `AWS_KEY=...`, `MYKEY=ab12` : bout en bout.

        Dépôt git réel + vrai client MCP : c'est la réponse sérialisée qui est
        vérifiée, pas l'appel à `mask_text`. Les formes non citées ET citées
        sont couvertes (elles passaient toutes les deux en clair).

        Les valeurs portent un chiffre, conformément à la règle de second
        rang : sous un nom générique (`KEY`, `AWS_KEY`), la valeur doit
        encore ressembler à un credential. La frontière est épinglée par
        `test_generic_names_keep_ordinary_code_readable`.
        """
        self.write(
            "deploy.env",
            'KEY=hunter2\nAWS_KEY="aws_secret_value1"\nMYKEY=ab12\nMODE=production\n',
        )
        self.stage("deploy.env")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        for secret in ("hunter2", "aws_secret_value1", "ab12"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, content)
        self.assertIn("MODE=production", content, "une valeur ordinaire reste lisible")
        self.assertEqual(payload["files"][0]["redactions"], 3)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_long_unquoted_value_is_masked_whole_end_to_end(self) -> None:
        """`SECRET=` + 5000 caractères : aucune queue en clair après le marqueur.

        La borne haute de la règle non citée coupait le match et laissait la
        queue partir en clair ; la valeur est désormais masquée en entier.
        """
        value = "b" * 5000
        self.write("long.env", f"SECRET={value}\n")
        self.stage("long.env")
        content = json.dumps(self.call_read_diff())
        self.assertNotIn("b" * 60, content)
        self.assertIn("<REDACTED:generic_secret:len=5000>", content)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", json.loads(content)), [])

    def test_url_with_secret_user_is_masked_end_to_end(self) -> None:
        """`https://<jeton>:pwd@h` stagé : aucun fragment du user en clair.

        Dépôt git réel + vrai client MCP : c'est la réponse sérialisée qui est
        vérifiée. Le mot de passe seul était déjà masqué ; le user secret
        partait en clair (règle userinfo seul écartée par fusion).
        """
        self.write("deploy.env", "REMOTE=https://mysecretuser123:longpassword123@host\n")
        self.stage("deploy.env")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        self.assertNotIn("mysecretuser123", content)
        self.assertNotIn("longpassword123", content)
        self.assertIn("<REDACTED:url_userinfo:", content)
        self.assertIn("<REDACTED:url_password:", content)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_long_quoted_value_is_masked_not_windowed(self) -> None:
        """Régression de revue : plus de fenêtre AVANT le masquage.

        Une valeur citée plus longue que la fenêtre (2500 caractères) ne
        matchait plus `_QUOTED_ASSIGNMENT` une fois la ligne tronquée, et
        son préfixe partait en clair au LLM. Le masquage porte désormais sur
        la ligne entière : la borne de 2000 caractères ne peut plus
        sectionner une valeur avant détection.
        """
        value = "a" * 5000
        self.write("conf.py", f'SECRET = "{value}"\n')
        self.stage("conf.py")
        payload = self.call_read_diff()
        text = json.dumps(payload)
        self.assertNotIn(f'SECRET = "{value[:50]}', text)
        self.assertNotIn(value[:200], text)
        self.assertIn("<REDACTED:generic_secret:len=5000>", text)
        self.assertEqual(payload["files"][0]["redactions"], 1)
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_long_quoted_value_stays_masked_whatever_the_budget(self) -> None:
        """Le budget (`max_bytes`, choisi par le LLM) ne réouvre pas la fuite."""
        value = "a" * 5000
        self.write("conf.py", "Z" * 400 + f'\nSECRET = "{value}"\n')
        self.stage("conf.py")
        for budget in (1024, 2048, 4096, 32768):
            with self.subTest(max_bytes=budget):
                text = json.dumps(self.call_read_diff({"max_bytes": budget}))
                self.assertNotIn(f'SECRET = "{value[:50]}', text)
                self.assertEqual(mcp_contract.errors("ReadDiffResult", json.loads(text)), [])

    def test_secret_never_straddles_any_budget(self) -> None:
        """Quel que soit `max_bytes` (contrôlé par le LLM), aucun fragment
        de secret en clair : la ligne incomplète est abandonnée, la ligne
        complète est masquée. Balayage de tous les alignements autour du
        secret (l'index git fait varier les offsets de quelques octets)."""
        token = FAKE_GITHUB_TOKEN
        self.write("f.py", "Z" * 900 + "\n" + f'TOKEN = "{token}"\n')
        self.stage("f.py")
        for budget in range(1000, 1120, 7):
            with self.subTest(max_bytes=budget):
                payload = self.call_read_diff({"max_bytes": budget})
                text = json.dumps(payload)
                self.assertNotIn(token, text)
                if "TOKEN" in text:
                    self.assertIn("<REDACTED:github:", text)
                self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

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
        self.write("app.py", f'TOKEN = "{FAKE_GITHUB_TOKEN}"\n')
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


class GitEnvironmentTests(GitRepoTestCase):
    """Le sous-processus git ne doit rien hériter ni exécuter du dépôt.

    Chaque test piège le dépôt (variable détournée, commande configurée,
    hook) puis prouve par l'absence du canari que le serveur ne l'a pas
    suivi — avec une réponse d'outil correcte par ailleurs.
    """

    def _conflicting_merge(self, name: str = "conflit.py") -> None:
        """Laisse un chemin de l'index NON RÉSOLU (merge en cours).

        Le fichier n'est volontairement pas `git add` après le conflit :
        l'entrée d'index reste aux étapes 1/2/3, et c'est exactement ce que
        `git diff --cached` rencontre en production.
        """
        self.write(name, "tete\ncorps\n")
        self.stage(name)
        _git(self.repo, "commit", "-qm", "base")
        _git(self.repo, "checkout", "-q", "-b", "branche")
        self.write(name, "tete\ncote branche\n")
        self.stage(name)
        _git(self.repo, "commit", "-qm", "branche")
        _git(self.repo, "checkout", "-q", "-")
        self.write(name, "tete\ncote principal\n")
        self.stage(name)
        _git(self.repo, "commit", "-qm", "principal")
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [GIT, "-C", str(self.repo), "merge", "branche"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0, "le merge devait conflicter")
        # Valeur factice laissée dans l'arbre de travail : un chemin non
        # fusionné ne doit jamais la laisser fuir (ni en clair, ni du tout).
        self.write(name, f'tete\nTOKEN = "{FAKE_GITHUB_TOKEN}"\n')

    def _plant_hook(self, name: str) -> Path:
        """Script-canari : son exécution laisse un fichier témoin hors dépôt."""
        canary = Path(self._tmp.name) / f"canary-{name}"
        hook = self.repo / f"faux-{name}.sh"
        hook.write_text(f'#!/bin/sh\necho "PWNED" >> {canary}\n', encoding="utf-8")
        hook.chmod(stat.S_IRWXU)
        return canary

    def test_inherited_git_environment_cannot_redirect_the_repository(self) -> None:
        """`GIT_DIR` / `GIT_INDEX_FILE` hérités ne redirigent pas l'analyse."""
        self.write("app.py", "x = 1\n")
        self.stage("app.py")
        other = Path(self._tmp.name) / "piege-repo"
        other.mkdir()
        _git(other, "init", "-q")
        _git(other, "config", "user.email", "test@example.invalid")
        _git(other, "config", "user.name", "Heimdall Test")
        (other / "piege.py").write_text("TOKEN = 'ghp_factice'\n", encoding="utf-8")
        _git(other, "add", "-A")
        _git(other, "commit", "-qm", "piege")
        names = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")
        previous = {name: os.environ.get(name) for name in names}
        os.environ.update(
            {
                "GIT_DIR": str(other / ".git"),
                "GIT_WORK_TREE": str(other),
                "GIT_INDEX_FILE": str(other / ".git" / "index"),
            }
        )
        try:
            payload = self.call_read_diff()
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual([item["file"] for item in payload["files"]], ["app.py"])
        self.assertNotIn("piege.py", json.dumps(payload))

    def test_no_command_from_the_repository_configuration_is_executed(self) -> None:
        """``diff.external`` configuré dans le dépôt reste inopérant (I5)."""
        self.write("app.py", "x = 1\n")
        self.stage("app.py")
        marker = "SENTINELLE_EXT_DIFF"
        hook = self.repo / "faux-diff"
        hook.write_text(f'#!/bin/sh\necho "{marker}"\ncat\n', encoding="utf-8")
        hook.chmod(stat.S_IRWXU)
        _git(self.repo, "config", "diff.external", str(hook))
        payload = self.call_read_diff()
        self.assertNotIn(marker, json.dumps(payload))
        self.assertEqual([item["file"] for item in payload["files"]], ["app.py"])

    def test_fsmonitor_hook_is_never_executed(self) -> None:
        """`core.fsmonitor` piégé : chaque appel git porte
        `-c core.fsmonitor=false` (désactivation réelle, pas un nom)."""
        canary = self._plant_hook("fsmonitor")
        _git(self.repo, "config", "core.fsmonitor", str(self.repo / "faux-fsmonitor.sh"))
        self.write("app.py", "x = 1\n")
        self.stage("app.py")
        canary.unlink(missing_ok=True)  # le `git add` ci-dessus a déjà déclenché le hook :
        payload = self.call_read_diff()  # seul l'appel outil compte désormais.
        self.assertFalse(canary.exists(), "le hook fsmonitor a été exécuté !")
        self.assertEqual([item["file"] for item in payload["files"]], ["app.py"])

    def test_hostile_pager_is_never_executed(self) -> None:
        """Pager piégé + sorties toujours pipées : jamais exécuté, donc
        aucun override pager (pas de surface ajoutée)."""
        canary = self._plant_hook("pager")
        _git(self.repo, "config", "core.pager", str(self.repo / "faux-pager.sh"))
        self.write("app.py", "x = 1\n")
        self.stage("app.py")
        canary.unlink(missing_ok=True)
        payload = self.call_read_diff()
        self.assertFalse(canary.exists(), "le pager a été exécuté !")
        self.assertEqual([item["file"] for item in payload["files"]], ["app.py"])

    def test_giant_staged_diff_bounded_and_no_oom(self) -> None:
        """Diff géant (~50 Mo) lu avec max_bytes borné : flux en streaming, pas d'OOM."""
        chunk = "a" * 1024 + "\n"
        blob_path = self.repo / "giant.txt"
        with blob_path.open("w", encoding="utf-8") as f:
            for _ in range(50 * 1024):
                f.write(chunk)
        self.stage("giant.txt")
        payload = self.call_read_diff(max_bytes=1024)
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(json.dumps(payload)), 100_000)

    def test_copy_to_roundtrip_with_sanitize_file(self) -> None:
        """Copie git (`copy to`) : nom exact extrait, et sanitize_file trouve le fichier."""
        self.write("src.py", "line\n" * 10)
        self.stage("src.py")
        _git(self.repo, "commit", "-m", "initial commit")
        self.write("neuf.py", "line\n" * 10 + "added\n")
        self.write("src.py", "modified\n")
        self.stage("neuf.py", "src.py")
        _git(self.repo, "config", "diff.renames", "copies")
        payload = self.call_read_diff()
        files = [item["file"] for item in payload["files"]]
        self.assertIn("neuf.py", files)
        self.assertNotIn("uf.py", files)
        sanitize_payload = tool_payload(
            call_tool("sanitize_file", {"path": "neuf.py"}, root=self.repo)
        )
        self.assertNotIn("error", sanitize_payload)
        self.assertEqual(sanitize_payload["path"], "neuf.py")

    def test_subfolder_server_root_does_not_expose_parent_diff(self) -> None:
        """Serveur lancé sur sous-dossier : GIT_CEILING_DIRECTORIES et is_repository refusent."""
        self.write("top.txt", "top secret\n")
        self.stage("top.txt")
        sub = self.repo / "sub"
        sub.mkdir()
        res = call_tool("read_diff", {}, root=sub)
        self.assertTrue(res.is_error)
        payload = tool_payload(res)
        self.assertEqual(payload["error"]["code"], "NOT_A_GIT_REPO")

    def test_unmerged_path_is_never_a_silent_empty_diff(self) -> None:
        """Merge en cours : l'information manquante est ANNONCÉE.

        `git diff --cached` ne montre aucune ligne pour un chemin non
        fusionné (`* Unmerged path x`). Sans drapeau, la réponse aurait
        ressemblé à un diff vide alors que le dépôt est en cours de
        fusion — l'inverse du fail-closed (invariant 1).
        """
        self._conflicting_merge()
        payload = self.call_read_diff()
        self.assertTrue(payload["truncated"], "un chemin non fusionné doit se signaler")
        self.assertNotIn(FAKE_GITHUB_TOKEN, json.dumps(payload))
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_unmerged_path_does_not_hide_the_resolved_files(self) -> None:
        """Un chemin non fusionné n'annule pas le reste : le reste est montré."""
        self._conflicting_merge()
        self.write("autre.py", "x = 1\n")
        self.stage("autre.py")
        payload = self.call_read_diff()
        self.assertIn("autre.py", [item["file"] for item in payload["files"]])
        self.assertTrue(payload["truncated"])
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_unquoted_short_secret_with_evocative_key_is_masked(self) -> None:
        """Secret court non quoté à clé évocatrice (ex. PASSWORD=hunter2) : masqué."""
        self.write("auth.sh", "PASSWORD=hunter2\nSECRET=abc12345\n")
        self.stage("auth.sh")
        payload = self.call_read_diff()
        content = json.dumps(payload)
        self.assertNotIn("hunter2", content)
        self.assertNotIn("abc12345", content)
        self.assertIn("<REDACTED:", content)
