"""Validation hors ligne du contrat Finding ; aucun secret réel."""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schemas/finding.schema.json").read_text(encoding="utf-8"))
EXAMPLES = json.loads(
    (ROOT / "schemas/examples/finding/examples.json").read_text(encoding="utf-8")
)


class FindingSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = Draft202012Validator(SCHEMA)
        cls.base = EXAMPLES["valid"][0]["finding"]

    def test_schema_matches_draft_2020_12(self):
        self.assertEqual(SCHEMA["$schema"], "https://json-schema.org/draft/2020-12/schema")
        Draft202012Validator.check_schema(SCHEMA)

    def test_valid_examples(self):
        for case in EXAMPLES["valid"]:
            with self.subTest(case=case["name"]):
                self.validator.validate(case["finding"])

    def test_invalid_examples_rejected_for_expected_reason(self):
        for case in EXAMPLES["invalid"]:
            with self.subTest(case=case["name"]):
                errors = list(self.validator.iter_errors(case["finding"]))
                self.assertTrue(errors)
                self.assertTrue(any(
                    error.validator == case["validator"]
                    and list(error.path) == case["path"] for error in errors
                ), [error.message for error in errors])

    def test_all_fields_required(self):
        for field in self.base:
            with self.subTest(field=field):
                finding = copy.deepcopy(self.base)
                del finding[field]
                self.assertFalse(self.validator.is_valid(finding))

    def test_status_and_source_values(self):
        for status in ("detecte", "confirme", "vaulte", "rote", "faux_positif"):
            for source in ("regex", "entropy", "llm"):
                with self.subTest(status=status, source=source):
                    self.validator.validate(dict(self.base, status=status, source=source))

    def test_entropy_bounds(self):
        for value in (0, 8, 4.25):
            self.validator.validate(dict(self.base, entropy=value))
        for value in (-0.01, 8.01, "4.25", None, True):
            with self.subTest(value=value):
                self.assertFalse(self.validator.is_valid(dict(self.base, entropy=value)))

    def test_line_and_type(self):
        for value in (0, -1, 1.5, "1", True, None):
            with self.subTest(line=value):
                self.assertFalse(self.validator.is_valid(dict(self.base, line=value)))
        for value in ("", "API_KEY", "api-key", "a" * 65, None):
            with self.subTest(type=value):
                self.assertFalse(self.validator.is_valid(dict(self.base, type=value)))

    def test_path_confinement_lexical(self):
        for value in ("", "/etc/file", "../file", "src/../file", "src/./file",
                      "src/..", "src/.", "C:/file", "src\\file", "src/\nfile"):
            with self.subTest(file=value):
                self.assertFalse(self.validator.is_valid(dict(self.base, file=value)))
        for value in ("config.py", "src/config.py", ".env.example", "src/été.py"):
            self.validator.validate(dict(self.base, file=value))

    def test_hash_encoding(self):
        for value in ("", "0" * 63, "0" * 65, "A" * 64, "g" * 64, None):
            with self.subTest(hash=value):
                self.assertFalse(self.validator.is_valid(dict(self.base, snippet_hash=value)))

    def test_unknown_fields_rejected(self):
        for field in ("secret", "value", "snippet", "unexpected"):
            with self.subTest(field=field):
                self.assertFalse(self.validator.is_valid(dict(self.base, **{field: "PLACEHOLDER"})))

    def test_root_must_be_object(self):
        for value in ([], None, "finding", 42):
            with self.subTest(value=value):
                self.assertFalse(self.validator.is_valid(value))


if __name__ == "__main__":
    unittest.main()
