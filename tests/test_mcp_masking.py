"""Preuves de l'audit E-03 : le masquage avant envoi au LLM.

Les onze lignes de l'audit sont rejouées telles quelles. Elles partaient
toutes **en clair** vers Ollama avant le correctif : clés JSON/YAML entre
guillemets, apostrophe interne, phrase de passe avec espaces, ponctuation
non quotée, balise XML, `define`, `.netrc`, `-u user:pass` et `--password`.
"""

import unittest

from heimdall.mcp import masking


class AuditE03MaskingProofTests(unittest.TestCase):
    """Les 11 cas de preuve de l'audit, plus les variantes de syntaxe."""

    def test_the_eleven_audit_cases_are_masked(self) -> None:
        cases = (
            ('{"password": "hunter2!hunter"}', "hunter2!hunter"),
            ("'api_key': 'abcd1234efgh'", "abcd1234efgh"),
            ('password = "it\'s-secret-123"', "it's-secret-123"),
            ("password = my secret pass phrase 42", "my secret pass phrase 42"),
            ("password=abc,defghijk99", "abc,defghijk99"),
            ("DB_PASSWORD: p@ss;word1234", "p@ss;word1234"),
            ("<password>Sup3rS3cret</password>", "Sup3rS3cret"),
            ("define('DB_PASSWORD', 'S3cr3tValue99');", "S3cr3tValue99"),
            ("machine github.com login bob password S3cretP4ss", "S3cretP4ss"),
            ("curl -u admin:Sup3rS3cret https://x", "Sup3rS3cret"),
            ("--password Sup3rS3cret99", "Sup3rS3cret99"),
        )
        for line, secret in cases:
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertGreaterEqual(redactions, 1)
                self.assertIn("<REDACTED:", masked)
                self.assertNotIn(secret, masked)

    def test_quoted_key_arrow_and_internal_quotes(self) -> None:
        """Guillemets de clé optionnels, `=>`, et quotes internes croisées."""
        cases = (
            ('"password": "hunter2!hunter"', "hunter2!hunter"),
            ("'db_password' => 'S3cr3tValue99'", "S3cr3tValue99"),
            ('password = "it\'s-secret-123"', "it's-secret-123"),
            ("password = 'say \"hi\" now'", 'say "hi" now'),
        )
        for line, secret in cases:
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:generic_secret:", masked)

    def test_passphrase_without_digit_is_masked(self) -> None:
        """Un mot de passe multi-mots sans chiffre reste un secret."""
        for line in (
            "password = correct horse battery staple",
            "PASS=correct horse battery staple",
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn("correct horse battery staple", masked)

    def test_multiword_value_does_not_leave_its_tail(self) -> None:
        """La règle large passe AVANT la règle courte : pas de queue en clair."""
        for line in (
            "PASSWORD=1234 5678",
            "password = abc12 def34",
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn("5678", masked)
                self.assertNotIn("def34", masked)

    def test_trailing_comment_stays_readable(self) -> None:
        """La valeur s'arrête avant ` #`, le commentaire reste utile au tri."""
        masked, redactions = masking.mask_text("password = hunter2-long-value # rotation prévue")
        self.assertEqual(redactions, 1)
        self.assertNotIn("hunter2-long-value", masked)
        self.assertIn("# rotation prévue", masked)

    def test_cli_username_stays_readable(self) -> None:
        masked, _ = masking.mask_text("curl -u admin:Sup3rS3cret https://x")
        self.assertIn("admin", masked)
        self.assertNotIn("Sup3rS3cret", masked)

    def test_ordinary_code_and_json_stay_readable(self) -> None:
        """Pas de bruit : type, littéral et JSON ordinaire inchangés."""
        for line in (
            "api_key: str",
            "session = None",
            "password = None  # pas de secret",
            '{"author": "Martin"}',
            '{"key": "production"}',
            '{"version": "1.2.3"}',
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_json_quoted_key_without_credential_is_not_masked(self) -> None:
        """La clé citée ne suffit pas : le nom et la valeur doivent peser."""
        for line in (
            '{"name": "production"}',
            '{"key": "name"}',
            '{"tokenizer": "bert-base"}',
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_plural_token_keys_are_masked(self) -> None:
        """Régression de revue : `tokens`/`TOKENS` ne sont pas `tokenizer`.

        `token(?![a-z])`, introduit pour épargner `tokenizer`, excluait aussi
        le pluriel : `tokens = "hunter2!hunter"` repartait en clair vers le
        LLM (0 masquage vérifié par exécution). Seul `tokenizer` doit rester
        lisible.
        """
        for line, secret in (
            ('tokens = "hunter2!hunter"', "hunter2!hunter"),
            ("TOKENS = hunter2!hunter", "hunter2!hunter"),
            ("tokens = 'hunter2!hunter'", "hunter2!hunter"),
            ('{"tokens": "hunter2!hunter"}', "hunter2!hunter"),
            ("--tokens=abcd1234efgh", "abcd1234efgh"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)

    def test_author_lookalikes_stay_readable(self) -> None:
        """`author`/`authors`/`authority` ne sont pas des noms de credentials."""
        for line in (
            '{"author": "Martin"}',
            '{"authors": "Martin Dupont"}',
            '{"authority": "example.invalid"}',
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_cli_user_password_edge_lengths_are_pinned(self) -> None:
        """`-u user:a` masque dès 1 caractère ; `-u user:` n'a rien à masquer."""
        masked, redactions = masking.mask_text("curl -u admin:a https://x")
        self.assertEqual(redactions, 1)
        self.assertNotIn("-u admin:a", masked)
        self.assertIn("admin", masked)

        unchanged = "curl -u admin: https://x"
        self.assertEqual(masking.mask_text(unchanged), (unchanged, 0))
