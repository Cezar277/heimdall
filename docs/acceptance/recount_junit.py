"""Recompute T42 counts from the archived, redacted JUnit report (stdlib only)."""

import collections
import fnmatch
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    root = Path(__file__).resolve().parent
    expected = json.loads((root / "results.json").read_text(encoding="utf-8"))
    if not isinstance(expected, dict):
        raise ValueError("results.json must contain an object")
    junit_path = expected.get("junit_path")
    if not isinstance(junit_path, str) or not junit_path.strip():
        raise ValueError("junit_path must be a non-empty relative path")
    if Path(junit_path).is_absolute():
        raise ValueError("junit_path must be a relative path")
    source = (root / junit_path).resolve()
    if not source.is_relative_to(root):
        raise ValueError("junit_path outside acceptance directory")
    expected_sha = expected.get("junit_sha256", "")
    if (
        not isinstance(expected_sha, str)
        or len(expected_sha) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha)
    ):
        raise ValueError("junit_sha256 must be a lowercase SHA-256 hex digest")
    for key, value_type in (
        ("by_module", dict), ("pytest_counts", dict), ("subtests_passed", int), ("groups", list)
    ):
        if type(expected.get(key)) is not value_type:
            raise ValueError(f"Missing or invalid results.json field: {key}")
    for index, group in enumerate(expected["groups"]):
        if not isinstance(group, dict):
            raise ValueError(f"Group {index} must be an object")
        for key in ("id", "status"):
            if not isinstance(group.get(key), str) or not group.get(key):
                raise ValueError(f"Missing or invalid group {index} field: {key}")
        for key in ("selectors", "modules"):
            values = group.get(key)
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError(f"Missing or invalid group {index} field: {key}")
        if not isinstance(group.get("counts"), dict):
            raise ValueError(f"Missing or invalid group {index} field: counts")
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected_sha:
        raise ValueError("JUnit SHA-256 mismatch")
    by_module = collections.defaultdict(collections.Counter)
    tree = ET.parse(source)
    for case in tree.iter("testcase"):
        classname = case.attrib.get("classname", "")
        parts = classname.split(".")
        index = next((i for i, part in enumerate(parts) if part.startswith("test_")), None)
        if index is None:
            raise ValueError(
                f"Unexpected classname {classname!r} for testcase {case.attrib.get('name', '<unnamed>')!r}"
            )
        module = "/".join(parts[: index + 1]) + ".py"
        status = "passed"
        for tag, verdict in (("failure", "failed"), ("error", "error"), ("skipped", "skipped")):
            if case.find(tag) is not None:
                status = verdict
                break
        by_module[module][status] += 1
    if dict(by_module) != expected["by_module"]:
        raise ValueError("Per-module counts mismatch")
    total = collections.Counter()
    for counts in by_module.values():
        total.update(counts)
    if total != expected["pytest_counts"]:
        raise ValueError("Total counts mismatch")
    suite_tests = 0
    for index, suite in enumerate(tree.iter("testsuite")):
        tests = suite.attrib.get("tests")
        if tests is None or not tests.isascii() or not tests.isdecimal():
            raise ValueError(f"Missing or invalid testsuite {index} attribute: tests ({tests!r})")
        suite_tests += int(tests)
    if suite_tests - sum(total.values()) != expected["subtests_passed"]:
        raise ValueError("Subtest counts mismatch")
    seen = []
    for group in expected["groups"]:
        modules = sorted(
            module
            for module in by_module
            if any(fnmatch.fnmatchcase(module, pattern) for pattern in group["selectors"])
        )
        seen.extend(modules)
        counts = collections.Counter()
        for module in modules:
            counts.update(by_module[module])
        status = (
            "Fail" if counts["failed"] or counts["error"] else
            "Non execute" if not counts["passed"] else
            "Partiel" if counts["skipped"] else "Pass"
        )
        if modules != group["modules"] or counts != group["counts"] or status != group["status"]:
            raise ValueError("Group mismatch: " + group["id"])
    if len(seen) != len(set(seen)) or set(seen) != set(by_module):
        raise ValueError("Missing or duplicate module assignment")
    print(
        f"OK: {total['passed']} passed, {total['skipped']} skipped; "
        f"{len(by_module)} modules, {len(expected['groups'])} groups; SHA-256 verified"
    )


if __name__ == "__main__":
    main()
