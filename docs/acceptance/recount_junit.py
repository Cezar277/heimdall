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
    source = root / expected["junit_path"]
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected["junit_sha256"]:
        raise ValueError("JUnit SHA-256 mismatch")
    by_module = collections.defaultdict(collections.Counter)
    tree = ET.parse(source)
    for case in tree.iter("testcase"):
        parts = case.attrib["classname"].split(".")
        index = next(i for i, part in enumerate(parts) if part.startswith("test_"))
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
    suite_tests = sum(int(suite.attrib["tests"]) for suite in tree.iter("testsuite"))
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
