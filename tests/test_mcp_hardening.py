"""Durcissement du serveur MCP — preuves que l'audit adverse échouerait.

Chaque classe part d'une attaque réaliste (ce que l'équipe adverse tentera
à partir du 25/11) et prouve la mitigation par l'exécution, jamais par la
doc. Toutes les valeurs sensibles ci-dessous sont des **factices** (préfixe
réel + charge aléatoire déterministe, jamais une clé fonctionnelle).
"""

import random
import time
import unittest
from typing import Any

from support import mcp_contract
from support.fake_secrets import fake_pem_body, fake_token
from support.git_repo import GitRepo
from support.mcp_client import call_tool, tool_payload

from heimdall.mcp import gitdiff, masking
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.paths import is_rel_path


class RequiredParametersTests(unittest.TestCase):
    """Sans `path`, le SDK répondait « Field required » hors enveloppe."""

    def test_missing_path_returns_our_envelope(self) -> None:
        payload = tool_payload(call_tool("sanitize_file", {}))
        self.assertEqual(payload["error"]["code"], "INVALID_INPUT")
        self.assertEqual(mcp_contract.errors("SanitizeFileResult", payload), [])

    def test_tools_without_required_params_still_answer(self) -> None:
        self.assertEqual(tool_payload(call_tool("ping", {})), {"pong": True})
        payload = tool_payload(call_tool("read_diff", {}))
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])


class TruncationInvariantTests(unittest.TestCase):
    """Une coupe ne doit jamais laisser un compteur sans marqueur."""

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-durcissement-", self)

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return tool_payload(call_tool(name, arguments, root=self.repo.root))

    def test_long_line_with_secret_at_the_end_stays_valid(self) -> None:
        """Le marqueur au-delà de 2000 caractères : compteur recompté."""
        token = fake_token("ghp_")
        self.repo.write("evil.py", "y" * 5000 + f'TOKEN = "{token}"\n')
        self.repo.stage("evil.py")
        payload = self.call("read_diff", {})
        self.assertTrue(payload["truncated"])
        self.assertNotIn(token, str(payload))
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_long_line_with_secret_before_the_cut_keeps_its_marker(self) -> None:
        token = fake_token("ghp_")
        self.repo.write("evil.py", f'TOKEN = "{token}"\n' + "y" * 5000 + "\n")
        self.repo.stage("evil.py")
        payload = self.call("read_diff", {})
        entry = payload["files"][0]
        self.assertIn("<REDACTED:github:", entry["added_lines"][0]["text"])
        self.assertNotIn(token, str(payload))
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_huge_content_with_secret_at_the_end_stays_valid(self) -> None:
        """Même invariant côté sanitize_file (borne 100 000 caractères)."""
        token = fake_token("sk_live_")
        self.repo.write("gros.txt", "z" * 120_000 + f'\nTOKEN = "{token}"\n')
        payload = self.call("sanitize_file", {"path": "gros.txt"})
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(payload["content"]), 100_000)
        self.assertNotIn(token, str(payload))
        self.assertEqual(mcp_contract.errors("SanitizeFileResult", payload), [])


class BareTokenMaskingTests(unittest.TestCase):
    """Un jeton sans `clé =` devant lui sortait en clair."""

    def test_bare_known_tokens_are_masked(self) -> None:
        for prefix, expected in (("ghp_", "github"), ("AKIA", "aws"), ("sk_live_", "stripe")):
            token = fake_token(prefix)
            with self.subTest(prefix=prefix):
                masked, count = masking.mask_text(token)
                self.assertEqual(count, 1)
                self.assertNotIn(token, masked)
                self.assertIn(f"<REDACTED:{expected}:len={len(token)}>", masked)

    def test_token_inside_a_json_array_is_masked(self) -> None:
        token = fake_token("ghp_")
        masked, _ = masking.mask_text(f'    "{token}",')
        self.assertNotIn(token, masked)
        self.assertIn("<REDACTED:github:", masked)

    def test_full_pem_block_is_masked_end_to_end(self) -> None:
        """En-tête, corps ET pied : rien d'une fausse clé ne sort."""
        body = fake_pem_body()
        block = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
        masked, count = masking.mask_text(block)
        self.assertNotIn(body.splitlines()[0], masked)
        self.assertIn("<REDACTED:private_key:", masked)
        self.assertGreaterEqual(count, 3)

    def test_ordinary_code_is_left_untouched(self) -> None:
        """Pas de bruit : le code normal repart inchangé, compteur nul.

        Note : un UUID *entre guillemets après `=`* est masqué par la règle
        d'entropie historique (pré-existant) ; seul l'UUID nu (tirets exclus
        de la classe des jetons denses) reste en clair, prouvé ici.
        """
        for line in (
            "print('bonjour')",
            'version = "1.2.3"',
            "port = 8080",
            'region = "eu-west"',
            "# voir 123e4567-e89b-12d3-a456-426614174000 ci-dessus",
            "def compute_total(items):",
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_short_neutral_value_is_left_visible_by_design(self) -> None:
        """Borne documentée (ADR-003 §7), pas un oubli : sans indice (nom
        neutre, < 16 caractères), le filet ne masque pas — la détection de
        précision appartient au scanner #22 mesuré en #21. Ce test épingle
        la frontière pour que personne ne la déplace en silence."""
        line = 'MY_DATA = "motdepasse12"'
        self.assertEqual(masking.mask_text(line), (line, 0))

    def test_short_lookalikes_are_not_masked(self) -> None:
        """`ghp_abc` isolé : trop court pour être exploitable, on le laisse."""
        self.assertEqual(masking.mask_text("voir ghp_abc ci-dessus"), ("voir ghp_abc ci-dessus", 0))


class AmbiguousBinaryNameTests(unittest.TestCase):
    """`Binary files … and …` : le nom avec `and` dedans était écorché."""

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-durcissement-", self)

    def test_binary_with_and_in_its_name_is_listed_whole(self) -> None:
        self.repo.write_bytes("x and y.bin", b"\x00\x01binaire")
        self.repo.stage("x and y.bin")
        payload = tool_payload(call_tool("read_diff", {}, root=self.repo.root))
        self.assertEqual([item["file"] for item in payload["files"]], ["x and y.bin"])
        self.assertTrue(payload["files"][0]["binary"])
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_quoted_non_ascii_path_is_decoded(self) -> None:
        """Git cite en C (`"caf\\303\\251.py"`) : le parseur décode en `café.py`."""
        self.repo.write("café.py", "q\n")
        self.repo.stage("café.py")
        payload = tool_payload(call_tool("read_diff", {}, root=self.repo.root))
        self.assertEqual([item["file"] for item in payload["files"]], ["café.py"])
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])

    def test_unrepresentable_path_fails_closed(self) -> None:
        """Un nom non représentable dans le contrat refuse la réponse.

        Choix délibéré (fail-closed) : plutôt INTERNAL que des lignes
        cachées au LLM sans le dire. Le développeur voit l'erreur et
        regarde le diff lui-même.
        """
        name = "ta\tb.txt"
        self.repo.write(name, "q\n")
        self.repo.stage(name)
        payload = tool_payload(call_tool("read_diff", {}, root=self.repo.root))
        self.assertEqual(payload["error"]["code"], "INTERNAL")
        self.assertEqual(mcp_contract.errors("ReadDiffResult", payload), [])


class CaseInsensitiveForbiddenTests(unittest.TestCase):
    """`.GIT` ouvre le même dossier que `.git` sur FS insensible à la casse."""

    def setUp(self) -> None:
        self.repo = GitRepo("heimdall-durcissement-", self)
        self.repo.write("ok.py", "x = 1\n")

    def read(self, path: str) -> dict[str, Any]:
        return tool_payload(call_tool("sanitize_file", {"path": path}, root=self.repo.root))

    def test_uppercase_variants_are_forbidden(self) -> None:
        (self.repo.root / ".GIT").mkdir(exist_ok=True)
        (self.repo.root / ".GIT" / "config").write_text("x\n", encoding="utf-8")
        self.repo.write(".ENV", "X=1\n")
        self.repo.write("sub/.Env.local", "X=1\n")
        for path in (".GIT/config", ".ENV", "sub/.Env.local"):
            with self.subTest(path=path):
                self.assertEqual(self.read(path)["error"]["code"], "FORBIDDEN_PATH")

    def test_lookalikes_stay_readable(self) -> None:
        """`.gitignore`, `.github/`, `git/` ne sont pas `.git/`."""
        self.repo.write(".gitignore", "*.log\n")
        self.repo.write(".github/workflows/ci.yml", "x\n")
        self.repo.write("git/notes.txt", "x\n")
        for path in (".gitignore", ".github/workflows/ci.yml", "git/notes.txt"):
            with self.subTest(path=path):
                self.assertIn("content", self.read(path))


class DiffParserFuzzTests(unittest.TestCase):
    """Le parseur ne doit jamais planter sur une entrée difforme.

    Frontière de confiance honnête : le CADRE (`diff --git`, `@@`) vient de
    notre propre appel git ; le CONTENU (noms, lignes) vient du dépôt donc
    est hostile. Le fuzz mélange les deux : aucune exception hors
    `ToolFailure`, et tout chemin renvoyé respecte la grammaire du contrat.
    """

    def test_seeded_corpus_never_crashes_and_stays_in_contract(self) -> None:
        rng = random.Random(0x27)  # noqa: S311 - graine fixe, fuzz déterministe, aucun usage crypto.
        pieces = [
            "+",
            "-",
            " ",
            "\\",
            "@",
            "diff --git a/x b/x",
            "diff --cc x",
            "+++ b/y",
            "--- a/y",
            "rename to z",
            "@@ -1,0 +1 @@",
            "@@ -12,3 +45,6 @@ func",
            "@@ garbage",
            "Binary files a/b and b/c differ",
            "GIT binary patch",
            "/dev/null",
            "..",
            "/etc/passwd",
            "é",
            "\t",
            "\x00",
            "x" * 3000,
            "A" * 40,
            '"b/quoted\\tname"',
        ]
        for iteration in range(500):
            text = "\n".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
            with self.subTest(iteration=iteration):
                try:
                    entries, _ = gitdiff.parse_diff(text)
                except ToolFailure:
                    continue  # refus fail-closed : comportement correct.
                for entry in entries:
                    self.assertTrue(
                        is_rel_path(entry.path), f"chemin hors contrat : {entry.path!r}"
                    )
                    for number, _ in entry.lines:
                        self.assertIsInstance(number, int)


class MaskingPerformanceTests(unittest.TestCase):
    """Garde-fou anti-ReDoS : les motifs sont linéaires, prouvé par le temps."""

    def test_huge_minified_line_completes_in_time(self) -> None:
        """Anti-ReDoS : 120 Ko d'une traite, temps borné, inchangé."""
        line = "a" * 120_000
        started = time.monotonic()
        masked, count = masking.mask_text(line)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, f"masquage trop lent : {elapsed:.1f}s")
        self.assertEqual((masked, count), (line, 0))

    def test_diluted_secret_is_caught_by_its_prefix(self) -> None:
        """Un jeton noyé dans du remplissage : l'entropie locale est diluée,
        seul son préfixe le trahit — d'où les règles nues (faille corrigée).

        Limite honnête : un jeton SANS préfixe connu, noyé dans 100 Ko de
        remplissage, reste indétectable par fenêtre (consigné en ADR-003).
        """
        token = fake_token("ghp_")
        line = 'x = "' + "a" * 1000 + token + "b" * 1000 + '"'
        masked, count = masking.mask_text(line)
        self.assertNotIn(token, masked)
        self.assertIn("<REDACTED:github:", masked)
        self.assertEqual(count, 1)

    def test_many_files_parse_in_time(self) -> None:
        chunks = []
        for index in range(300):
            chunks.append(f"diff --git a/f{index}.txt b/f{index}.txt")
            chunks.append("new file mode 100644")
            chunks.append("--- /dev/null")
            chunks.append(f"+++ b/f{index}.txt")
            chunks.append("@@ -0,0 +1 @@")
            chunks.append("+contenu")
        started = time.monotonic()
        entries, truncated = gitdiff.parse_diff("\n".join(chunks))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, f"parse trop lent : {elapsed:.1f}s")
        self.assertTrue(truncated)
        self.assertLessEqual(len(entries), 200)

    def test_quoted_assignment_above_20k_chars_is_documented_boundary(self) -> None:
        """Borne actée ADR-003 §7 : SECRET='a'*50000 sur une ligne n'est pas masqué."""
        line = 'SECRET = "' + "a" * 50_000 + '"'
        masked, count = masking.mask_text(line)
        self.assertEqual(count, 0)
        self.assertEqual(masked, line)



if __name__ == "__main__":
    unittest.main()
