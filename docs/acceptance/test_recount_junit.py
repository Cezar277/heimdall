"""Replay the offline verifier checks with stdlib only; run under POSIX for symlinks.

From the repository root: python3 docs/acceptance/test_recount_junit.py
All mutations are confined to a TemporaryDirectory; archived evidence is read only.
"""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recount_junit as recount


class RecountChecks(unittest.TestCase):
    def setUp(self):
        archive = Path(__file__).resolve().parent
        self.expected = json.loads((archive / "results.json").read_text(encoding="utf-8"))
        self.xml = (archive / "junit.xml").read_bytes()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "acceptance"
        self.root.mkdir()
        self.fake_script = self.root / "recount_junit.py"
        self.write_fixture(self.expected, self.xml)

    def write_fixture(self, expected, xml=None):
        (self.root / "results.json").write_text(json.dumps(expected), encoding="utf-8")
        if xml is not None:
            (self.root / "junit.xml").write_bytes(xml)

    def run_verifier(self):
        with patch.object(recount, "__file__", str(self.fake_script)):
            recount.main()

    def expect_error(self, message, before_xml_read=False):
        with self.assertRaisesRegex(ValueError, message):
            if before_xml_read:
                with patch.object(Path, "read_bytes", side_effect=AssertionError("XML read")):
                    self.run_verifier()
            else:
                self.run_verifier()

    def test_valid_archive(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.run_verifier()
        self.assertEqual(
            output.getvalue(),
            "OK: 2211 passed, 16 skipped; 46 modules, 19 groups; SHA-256 verified\n",
        )

    def test_24_invalid_metadata_and_paths_before_xml_read(self):
        valid = self.expected
        cases = []
        for value in (None, 12, "", "  "):
            cases.append(({**valid, "junit_path": value}, "junit_path must be"))
        missing = dict(valid)
        missing.pop("junit_path")
        cases.append((missing, "junit_path must be"))
        cases.append(({**valid, "junit_path": "../outside.xml"}, "junit_path outside"))
        for target in (self.base / "outside.xml", self.root / "junit.xml"):
            cases.append(({**valid, "junit_path": str(target)}, "must be a relative path"))
        (self.base / "outside.xml").write_bytes(self.xml)
        (self.root / "link.xml").symlink_to(self.base / "outside.xml")
        cases.append(({**valid, "junit_path": "link.xml"}, "junit_path outside"))
        for value in (None, 42, "", "a" * 63, "G" * 64):
            cases.append(({**valid, "junit_sha256": value}, "junit_sha256 must be"))
        missing = dict(valid)
        missing.pop("junit_sha256")
        cases.append((missing, "junit_sha256 must be"))
        cases.append(([], "must contain an object"))
        for key in ("by_module", "pytest_counts", "subtests_passed", "groups"):
            missing = dict(valid)
            missing.pop(key)
            cases.append((missing, f"field: {key}"))
            cases.append(({**valid, key: None}, f"field: {key}"))
        self.assertEqual(len(cases), 24)
        for index, (payload, message) in enumerate(cases):
            with self.subTest(case=index):
                self.write_fixture(payload)
                self.expect_error(message, before_xml_read=True)

    def test_invalid_group_fields(self):
        for key in ("id", "selectors", "modules", "counts", "status"):
            for value in ("missing", None, 42):
                with self.subTest(field=key, value=value):
                    expected = copy.deepcopy(self.expected)
                    if value == "missing":
                        expected["groups"][0].pop(key)
                    else:
                        expected["groups"][0][key] = value
                    self.write_fixture(expected)
                    self.expect_error(f"group 0 field: {key}", before_xml_read=True)
        for key in ("selectors", "modules"):
            with self.subTest(field=key, value="non-string entry"):
                expected = copy.deepcopy(self.expected)
                expected["groups"][0][key] = [None]
                self.write_fixture(expected)
                self.expect_error(f"group 0 field: {key}", before_xml_read=True)

    def test_invalid_group_object(self):
        expected = copy.deepcopy(self.expected)
        expected["groups"][0] = None
        self.write_fixture(expected)
        self.expect_error("Group 0 must be an object", before_xml_read=True)

    def mutate_xml(self, mutation):
        tree = recount.ET.fromstring(self.xml)
        mutation(tree)
        xml = recount.ET.tostring(tree, encoding="utf-8")
        expected = copy.deepcopy(self.expected)
        expected["junit_sha256"] = hashlib.sha256(xml).hexdigest()
        self.write_fixture(expected, xml)

    def test_invalid_suite_tests(self):
        for value in (None, "", "abc", "-1", "1.5", "²"):
            with self.subTest(tests=value):
                def mutate(tree):
                    suite = next(tree.iter("testsuite"))
                    if value is None:
                        suite.attrib.pop("tests")
                    else:
                        suite.set("tests", value)
                self.mutate_xml(mutate)
                self.expect_error("Missing or invalid testsuite 0 attribute: tests")

    def test_invalid_classname(self):
        for value in (None, "unexpected.module"):
            with self.subTest(classname=value):
                def mutate(tree):
                    case = next(tree.iter("testcase"))
                    if value is None:
                        case.attrib.pop("classname")
                    else:
                        case.set("classname", value)
                self.mutate_xml(mutate)
                self.expect_error("Unexpected classname .* for testcase")

    def test_hash_mismatch_before_xml_parse(self):
        expected = {**self.expected, "junit_sha256": "0" * 64}
        self.write_fixture(expected)
        with patch.object(recount.ET, "parse", side_effect=AssertionError("XML parsed")):
            self.expect_error("JUnit SHA-256 mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
