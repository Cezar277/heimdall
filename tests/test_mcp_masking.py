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

    def test_unclosed_quoted_value_is_masked_to_end_of_line(self) -> None:
        """Revue (MEDIUM) : `password="hunter2!hunter` fuyait sans guillemet final.

        Une ligne de diff tronquée, une coquille ou une valeur multiligne
        suffisait : les règles citées exigent le guillemet fermant et la
        règle non quotée refuse les valeurs commençant par un guillemet.
        Le rattrapage masque jusqu'à la fin de ligne (commentaire ` #` exclu).
        """
        for line, secret in (
            ('password="hunter2!hunter', "hunter2!hunter"),
            ("password = 'abc12345", "abc12345"),
            ("api_key = 'abcd1234efgh", "abcd1234efgh"),
            ('password="hunter2!hunter # rotation', "hunter2!hunter"),
            ('DB_PASSWORD="p@ss;word1234', "p@ss;word1234"),
            ('TOKEN="x1', "x1"),
            ('--password "hunter2!hunter', "hunter2!hunter"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)

    def test_unclosed_quoted_ordinary_code_stays_readable(self) -> None:
        """Le rattrapage ne masque pas un type, un littéral ou une valeur vide."""
        for line in (
            "api_key: str",
            "session = None",
            'password=""',
            "password='",
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

    def test_case_insensitive_netrc_and_define_are_masked(self) -> None:
        """Revue (LOW) : `Password` et `DEFINE` sont valides, donc masqués."""
        for line, secret in (
            ("machine x login bob Password S3cretP4ss", "S3cretP4ss"),
            ("machine x login bob PASSWORD S3cretP4ss", "S3cretP4ss"),
            ("DEFINE('DB_PASSWORD', 'S3cr3tValue99');", "S3cr3tValue99"),
            ('Define("DB_PASSWORD", "S3cr3tValue99");', "S3cr3tValue99"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)

    def test_function_call_partial_mask_is_pinned(self) -> None:
        """Comportement préexistant figé (revue), hors périmètre de ce ticket.

        `_UNQUOTED_ASSIGNMENT` masque le nom de la fonction évocatrice
        (`get_password`) mais laisse la parenthèse fermante. L'ADR affirmait
        que les appels de fonction restaient lisibles : c'est faux pour un
        nom évocateur, et ce test évite une régression silencieuse dans un
        sens ou dans l'autre.
        """
        masked, redactions = masking.mask_text("password = get_password()")
        self.assertEqual(redactions, 1)
        self.assertNotIn("get_password", masked)
        self.assertTrue(masked.endswith(")"))

    def test_multiline_xml_sensitive_element_is_masked(self) -> None:
        """Revue (LOW) : un XML indenté laissait la valeur en clair."""
        for line, secret in (
            ("<password>\nS3cretP4ss99\n</password>", "S3cretP4ss99"),
            ("<password>\n  S3cretP4ss99\n</password>", "S3cretP4ss99"),
            ("<api_key>\n  abcd1234efgh\n</api_key>", "abcd1234efgh"),
            ("<password>\n  my secret\n  phrase 42\n</password>", "my secret\n  phrase 42"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)
                self.assertIn("\n", masked, "la mise en forme XML est préservée")

    def test_multiline_xml_ordinary_element_stays_readable(self) -> None:
        line = "<name>\n  Martin\n</name>"
        self.assertEqual(masking.mask_text(line), (line, 0))

    def test_xml_attribute_is_not_taken_for_netrc(self) -> None:
        """Revue (LOW) : `<password lang="en">` ne doit pas masquer `lang=`."""
        line = '<password lang="en">S3cretP4ss99</password>'
        masked, redactions = masking.mask_text(line)
        self.assertEqual(redactions, 1, "seule la valeur est masquée")
        self.assertIn('lang="en"', masked)
        self.assertNotIn("S3cretP4ss99", masked)

    def test_passphrase_with_parens_is_pinned_readable(self) -> None:
        """Arbitrage bruit/fuite assumé (revue), sans mesure de bruit.

        `_evocative_unquoted_looks_secret` refuse `()[]{}` pour épargner le
        code ; `password = my secret (test) 99` reste donc lisible. Le
        premier segment n'est masqué par `_UNQUOTED_ASSIGNMENT` que s'il fait
        au moins 6 caractères, ce qui n'est pas le cas ici. Comportement figé
        pour éviter une régression silencieuse dans un sens ou dans l'autre.
        """
        for line in (
            "password = my secret (test) 99",
            "PASSWORD = my secret [test] 99",
            "password = my secret {test} 99",
        ):
            with self.subTest(line=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

        masked, redactions = masking.mask_text("password = abcdefgh (test) 99")
        self.assertEqual(redactions, 1)
        self.assertNotIn("abcdefgh", masked)

    def test_quoted_netrc_value_is_masked(self) -> None:
        """Revue (LOW) : `password "S3cr****"` (netrc quoté) partait en clair."""
        for line, secret in (
            ('password "S3cretP4ss"', "S3cretP4ss"),
            ("Password 'S3cretP4ss'", "S3cretP4ss"),
            ('machine x login bob password "S3cretP4ss"', "S3cretP4ss"),
            ('machine x login bob password "my secret phrase 42"', "my secret phrase 42"),
            ('password "my secret phrase 42', "my secret phrase 42"),
            ('password "my secret phrase 42 # note', "my secret phrase 42"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)

    def test_quoted_cli_user_password_is_masked(self) -> None:
        """Revue (LOW) : `-u "user:pass"` et `-u user:"pass"` sont usuels."""
        for line, secret in (
            ('curl -u "admin:S3cretP4ss" https://x', "S3cretP4ss"),
            ("curl -u 'admin:S3cretP4ss' https://x", "S3cretP4ss"),
            ('curl -u admin:"S3cretP4ss" https://x', "S3cretP4ss"),
            ("curl -u admin:'S3cretP4ss' https://x", "S3cretP4ss"),
            ('curl -u "admin:my secret phrase 42" https://x', "my secret phrase 42"),
            ('curl -u admin:"my secret phrase 42" https://x', "my secret phrase 42"),
            ('curl -u "admin:S3cretP4ss', "S3cretP4ss"),
            ('curl -u admin:"S3cretP4ss', "S3cretP4ss"),
            ('curl -u "admin:S3cretP4ss # rotation', "S3cretP4ss"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("admin", masked, "le nom d'utilisateur reste lisible")

    def test_define_with_space_before_parenthesis_is_masked(self) -> None:
        """Revue (LOW) : PHP autorise `define (` ; les formatters l'ajoutent."""
        for line, secret in (
            ("define ( 'DB_PASSWORD' , 'S3cr3tValue99' )", "S3cr3tValue99"),
            ('DEFINE ( "DB_PASSWORD" , "S3cr3tValue99" )', "S3cr3tValue99"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)

    def test_define_with_unquoted_arguments_is_masked(self) -> None:
        """`define(DB_PASSWORD, S3cr3tValue99)` : nom et valeur nus sont valides."""
        for line, secret in (
            ("define(DB_PASSWORD, 'S3cr3tValue99');", "S3cr3tValue99"),
            ('define(DB_PASSWORD, "S3cr3tValue99");', "S3cr3tValue99"),
            ("define(DB_PASSWORD, S3cr3tValue99);", "S3cr3tValue99"),
            ("define('DB_PASSWORD', S3cr3tValue99);", "S3cr3tValue99"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)

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
            "define('DB_NAME', 'production');",
            "define ('DB_NAME', 'production');",
            "define('WP_DEBUG', true);",
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

    def test_space_separated_secret_directives_are_masked(self) -> None:
        """Revue (LOW) : formes espace-séparées hors `password` (`api_key`, `secret`, `token`)."""
        for line, secret in (
            ("api_key mysecret123", "mysecret123"),
            ("api-key mysecret123", "mysecret123"),
            ("secret mysecret123", "mysecret123"),
            ("token mysecret123", "mysecret123"),
            ("tokens mysecret123", "mysecret123"),
            ("passwd S3cretP4ss", "S3cretP4ss"),
            ("pwd S3cretP4ss", "S3cretP4ss"),
            ('api_key "my secret 42"', "my secret 42"),
            ('secret "my secret 42', "my secret 42"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)

        for line in (
            "tokenizer bert-base",
            "api_key None",
            "secret null",
            "password $SECRET_ENV",
            "--name bob",
            "curl -u admin:$SECRET_ENV https://x",
        ):
            with self.subTest(readable=line):
                self.assertEqual(masking.mask_text(line), (line, 0))

        # Affectations avec échappement ou virgule : restent couvertes en entier.
        masked, redactions = masking.mask_text('password = "abc\\"def')
        self.assertEqual(redactions, 1)
        self.assertNotIn("abcdef", masked)
        self.assertNotIn("def", masked)

        masked, redactions = masking.mask_text("password=abcdef,ghijkl")
        self.assertEqual(redactions, 1)
        self.assertNotIn("abcdef", masked)
        self.assertNotIn("ghijkl", masked)

    def test_xml_value_with_lt_is_pinned(self) -> None:
        """Revue (LOW) : un `<` brut dans une valeur XML est masqué, pas les balises imbriquées."""
        for line, secret in (
            ("<password>P@ss<wo1234</password>", "P@ss<wo1234"),
            ("<api_key>ab<cd1234ef</api_key>", "ab<cd1234ef"),
        ):
            with self.subTest(line=line):
                masked, redactions = masking.mask_text(line)
                self.assertEqual(redactions, 1)
                self.assertNotIn(secret, masked)
                self.assertIn("<REDACTED:", masked)

        # Une balise sœur ou parente ne doit pas avaler le bloc XML environnant.
        nested = "<auth><user>alice</user><password>S3cretP4ss99</password></auth>"
        masked, redactions = masking.mask_text(nested)
        self.assertEqual(redactions, 1)
        self.assertIn("<user>alice</user>", masked)
        self.assertNotIn("S3cretP4ss99", masked)

        # Vraie balise imbriquée : reste hors périmètre de la règle XML.
        inner_tag = "<password><nested>short</nested></password>"
        self.assertEqual(masking.mask_text(inner_tag), (inner_tag, 0))
