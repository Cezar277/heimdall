"""T23 : détection générique, seuils, contexte et non-régressions sécurité."""

import base64
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

import heimdall.scanner.entropy_detection as module
import heimdall.scanner.signatures as registry
from heimdall.scanner import DiffTarget, EntropyConfig, FileTarget, Finding, Scanner
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.entropy_detection import (
    check_multiline_overflow,
    find_entropy_matches,
    find_line_matches,
)
from heimdall.scanner.errors import ScanError
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signature_engine import SignatureEngine
from heimdall.scanner.signatures import SignatureMatch
from heimdall.scanner.signatures.model import ALLOWED_SECRET_TYPES


def synthetic_value(alphabet: str) -> str:
    """Aucune valeur émise par un fournisseur, corpus reproductible."""
    digest = hashlib.sha256(b"heimdall-t23-synthetic-only").digest()
    return digest.hex() if alphabet == "hex" else base64.b64encode(digest).decode()


@pytest.mark.parametrize("alphabet", ["hex", "base64"])
def test_unknown_value_reaches_both_scanner_paths(tmp_path: Path, alphabet: str) -> None:
    value = synthetic_value(alphabet)
    text = f'credential = "{value}"\n'
    hasher = SnippetHasher(key=b"T" * 32)
    target = FileTarget("config.py", text)
    (tmp_path / target.path).write_text(text)
    tree = TreeScanner(tmp_path, hasher=hasher).scan()
    engine = Scanner(SignatureEngine(hasher)).scan(target)
    assert tree == engine
    assert len(tree) == 1
    finding = tree[0]
    assert finding.source == "entropy"
    assert finding.type == f"high_entropy_{alphabet}"
    assert finding.entropy == round(shannon_entropy(value.encode()), 4)
    assert finding.snippet_hash == hasher.hash(value)
    assert value not in repr(finding)
    assert Finding.from_dict(finding.as_dict()) == finding


def test_threshold_and_minimum_length_are_configurable(tmp_path: Path) -> None:
    value = synthetic_value("base64")
    target = FileTarget("config.py", value)
    hasher = SnippetHasher(key=b"T" * 32)
    assert SignatureEngine(hasher).analyser(target)
    assert not SignatureEngine(hasher, entropy_config=EntropyConfig(base64_threshold=6)).analyser(
        target
    )
    assert not SignatureEngine(hasher, entropy_config=EntropyConfig(min_length=100)).analyser(
        target
    )
    (tmp_path / target.path).write_text(value)
    assert not TreeScanner(
        tmp_path, hasher=hasher, entropy_config=EntropyConfig(base64_threshold=6)
    ).scan()
    short_hex = "0123456789abcdef"
    assert not tuple(find_entropy_matches(short_hex))
    assert tuple(find_entropy_matches(short_hex, EntropyConfig(min_length=16)))
    assert tuple(find_entropy_matches(short_hex, EntropyConfig(min_length=16, hex_threshold=4)))


@pytest.mark.parametrize("value", [0, -1, True, "4", float("nan"), float("inf"), 8])
@pytest.mark.parametrize("field", ["hex_threshold", "base64_threshold", "min_length"])
def test_invalid_configuration_is_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError, match="configuration d'entropie invalide"):
        EntropyConfig(**{field: value})


def test_low_entropy_is_not_a_candidate() -> None:
    assert not tuple(find_entropy_matches("a" * 100))


def test_distinct_values_same_line_and_limit() -> None:
    text = synthetic_value("hex") + ' "' + synthetic_value("base64") + '"'
    hasher = SnippetHasher(key=b"T" * 32)
    target = FileTarget("config.py", text)
    assert len(Scanner(SignatureEngine(hasher)).scan(target)) == 2
    with pytest.raises(ScanError):
        SignatureEngine(hasher, max_findings=1).analyser(target)


def test_no_entropy_join_of_arbitrary_lines() -> None:
    target = DiffTarget("config.py", ((10, "0123456789abcdef"), (11, "ABCDEF9876543210")))
    assert not SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(target)


@pytest.mark.parametrize("alphabet", ["hex", "base64"])
def test_unquoted_env_assignment_is_detected(alphabet: str) -> None:
    target = FileTarget(".env", "CREDENTIAL=" + synthetic_value(alphabet))
    findings = SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(target)
    assert len(findings) == 1
    assert findings[0].type == f"high_entropy_{alphabet}"


def test_invalid_byte_inside_candidate_is_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_bytes(b"AKIA12345678\xff12345678")
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        TreeScanner(tmp_path, hasher=SnippetHasher(key=b"T" * 32)).scan()


def test_complete_assignment_does_not_hide_an_incomplete_one() -> None:
    text = 'aws_secret_key = "' + "A" * 40 + '"; aws_secret_key = ' + "x" * 5000 + "\nvalue"
    with pytest.raises(ScanError):
        SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(FileTarget("config.py", text))


def test_invalid_config_object_is_refused_by_both_motors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="configuration d'entropie invalide"):
        SignatureEngine(entropy_config=None)
    with pytest.raises(ValueError, match="configuration d'entropie invalide"):
        TreeScanner(tmp_path, hasher=SnippetHasher(key=b"T" * 32), entropy_config=None)


@pytest.mark.parametrize(
    "wrapper",
    [
        "sha256 = '{}'",
        "commit = '{}'",
        "checksum = '{}'",
        "integrity = 'sha512-{}'",
        "data:text/plain;base64,{}",
        "'{}'",
        "sha1-{}",
        "sha256-{}",
        "sha384-{}",
        "sha512-{}",
        "md5-{}",
        "prefix-{}",
        "prefix.{}",
        "x{}",
        "a{}",
        "x-{}",
        "x_{}",
        "x+{}",
        "x/{}",
        "{}-suffix",
        "{}x",
    ],
)
@pytest.mark.parametrize("alphabet", ["hex", "base64"])
def test_labels_cannot_hide_unknown_candidates(tmp_path: Path, wrapper: str, alphabet: str) -> None:
    text = wrapper.format(synthetic_value(alphabet))
    (tmp_path / "config.py").write_text(text)
    hasher = SnippetHasher(key=b"T" * 32)
    tree = TreeScanner(tmp_path, hasher=hasher).scan()
    engine = SignatureEngine(hasher).analyser(FileTarget("config.py", text))
    assert tree == engine
    assert tree and all(f.source == "entropy" for f in tree)
    assert all(f.type in ALLOWED_SECRET_TYPES for f in tree)
    if alphabet == "hex":
        assert all(f.type == "high_entropy_hex" for f in tree)


def test_hex_fragment_offsets_and_hashes_do_not_include_non_hex_affixes(tmp_path: Path) -> None:
    value = synthetic_value("hex")
    text = f'credential = "prefix-{value}-suffix"'
    matches = tuple(find_entropy_matches(text))
    assert len(matches) == 1
    match = matches[0]
    assert match.value == value
    assert match.start == text.index(value)
    assert text[match.start : match.start + len(match.value)] == value
    hasher = SnippetHasher(key=b"T" * 32)
    (tmp_path / "config.py").write_text(text)
    for findings in (
        TreeScanner(tmp_path, hasher=hasher).scan(),
        SignatureEngine(hasher).analyser(FileTarget("config.py", text)),
    ):
        assert len(findings) == 1
        assert findings[0].snippet_hash == hasher.hash(value)
        assert findings[0].entropy == round(shannon_entropy(value.encode()), 4)
        assert value not in json.dumps(asdict(findings[0]))


def test_two_hex_fragments_in_one_token_are_both_detected() -> None:
    first = synthetic_value("hex")
    second = hashlib.sha256(b"heimdall-t23-second-synthetic-only").hexdigest()
    text = f"x{first}x{second}x"
    matches = tuple(find_entropy_matches(text))
    assert [match.value for match in matches] == [first, second]
    assert [match.start for match in matches] == [1, len(first) + 2]


def test_deadline_is_checked_before_scoring_a_hex_fragment(monkeypatch) -> None:
    times = iter([0.0, 0.0, 0.0, 2.0])
    monkeypatch.setattr("heimdall.scanner.entropy_detection.time.monotonic", lambda: next(times))
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(find_entropy_matches("prefix-" + synthetic_value("hex"), deadline=1.0))


def test_known_signature_does_not_hide_a_separate_hex_fragment() -> None:
    value = synthetic_value("hex")
    text = "ghp_" + "A" * 36 + "-" + value
    findings = SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(FileTarget("config.py", text))
    assert {(finding.source, finding.type) for finding in findings} == {
        ("regex", "pat"),
        ("entropy", "high_entropy_hex"),
    }


def test_uuid_shape_is_not_an_exclusion() -> None:
    value = synthetic_value("hex")
    uuid = "-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:32]))
    assert tuple(find_entropy_matches(uuid))


@pytest.mark.parametrize("label", ["stripe", "slack", "pat", "jwt", "unknown", ""])
def test_multiline_overflow_is_not_provider_specific(tmp_path: Path, label: str) -> None:
    value = synthetic_value("base64")
    text = (f"{label} = " if label else "") + " " * 5000 + "\n" + value
    (tmp_path / "config.py").write_text(text)
    hasher = SnippetHasher(key=b"T" * 32)
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        TreeScanner(tmp_path, hasher=hasher).scan()
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        SignatureEngine(hasher).analyser(FileTarget("config.py", text))


@pytest.mark.parametrize(
    "line,config",
    [(None, EntropyConfig()), (b"abc", EntropyConfig()), ("abc", None), ("abc", object())],
)
@pytest.mark.parametrize("detector", [find_entropy_matches, find_line_matches])
def test_direct_function_rejects_invalid_inputs(line: object, config: object, detector) -> None:
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(detector(line, config))


@pytest.mark.parametrize("detector", [find_entropy_matches, find_line_matches])
def test_oversized_token_refuses_before_shannon_or_signature_work(monkeypatch, detector) -> None:
    def forbidden(*args):
        pytest.fail("unbounded token reached signature matching or Shannon")

    monkeypatch.setattr("heimdall.scanner.entropy_detection.shannon_entropy", forbidden)
    monkeypatch.setattr("heimdall.scanner.entropy_detection.find_signature_matches", forbidden)
    with pytest.raises(ScanError):
        tuple(detector("a" * 1_048_576))


def test_deadline_is_checked_inside_a_line(monkeypatch) -> None:
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr("heimdall.scanner.entropy_detection.time.monotonic", lambda: next(times))
    with pytest.raises(ScanError):
        tuple(find_entropy_matches("first second third", deadline=1.0))


def test_megabyte_token_and_expired_deadline_in_both_engines(tmp_path: Path) -> None:
    text = "a" * 1_048_576
    (tmp_path / "config.py").write_text(text)
    hasher = SnippetHasher(key=b"T" * 32)
    for deadline in (None, 0.0):
        with pytest.raises(ScanError):
            TreeScanner(tmp_path, hasher=hasher).scan(deadline=deadline)
        with pytest.raises(ScanError):
            SignatureEngine(hasher, deadline=deadline).analyser(FileTarget("config.py", text))


@pytest.mark.parametrize("size", [4096, 4097])
def test_token_limit_is_inclusive(size: int) -> None:
    if size == 4096:
        assert not tuple(find_entropy_matches("A" * size))
    else:
        with pytest.raises(ScanError):
            tuple(find_entropy_matches("A" * size))


def test_low_entropy_fragment_cannot_hide_behind_overflow() -> None:
    text = "A" * 20 + " " * 5000 + "\n" + "B" * 20
    with pytest.raises(ScanError):
        SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(FileTarget("config.py", text))


def test_overflow_without_candidate_or_assignment_remains_scannable() -> None:
    text = "#" * 5000 + "\nshort"
    assert (
        SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(FileTarget("config.py", text)) == []
    )


def test_signature_id_entropy_does_not_control_source() -> None:
    hasher = SnippetHasher(key=b"T" * 32)
    match = SignatureMatch("aws", "entropy", "A" * 20)
    findings = []
    SignatureEngine(hasher)._append(findings, set(), match, 1, "config.py")
    assert findings[0].source == "regex"


def test_real_registry_rule_named_entropy_stays_regex(tmp_path: Path, monkeypatch) -> None:
    rule = replace(registry.RULES[0], id="entropy")
    monkeypatch.setattr(registry, "RULES", (rule,))
    hasher = SnippetHasher(key=b"T" * 32)
    target = FileTarget("config.py", rule.positive_example)
    (tmp_path / target.path).write_text(target.text)
    for findings in (
        SignatureEngine(hasher).analyser(target),
        TreeScanner(tmp_path, hasher=hasher).scan(),
    ):
        assert findings and all(f.source == "regex" for f in findings)


def test_removed_context_surface_cannot_expose_cleartext() -> None:
    assert not hasattr(module, "ScanContext")
    assert not hasattr(module, "context_lines")
    value = synthetic_value("hex")
    finding = SignatureEngine(SnippetHasher(key=b"T" * 32)).analyser(FileTarget("x", value))[0]
    assert value not in json.dumps(asdict(finding))
    assert value not in str(finding)


@pytest.mark.parametrize("preceding", ["evil", ["x"], ("x",), (object(),), None])
@pytest.mark.parametrize("detector", [find_entropy_matches, find_line_matches])
def test_direct_function_rejects_invalid_preceding_matches(preceding: object, detector) -> None:
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(detector("abc", preceding_matches=preceding))


@pytest.mark.parametrize(
    "deadline",
    [
        "demain",
        True,
        False,
        float("nan"),
        float("inf"),
        -float("inf"),
        object(),
        pytest.param(10**400, id="oversized-integer"),
    ],
)
@pytest.mark.parametrize("detector", [find_entropy_matches, find_line_matches])
def test_direct_functions_reject_invalid_deadlines(deadline: object, detector) -> None:
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(detector("abc", deadline=deadline))
    # No token or delimiter: validation must precede every early return.
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        check_multiline_overflow("", "", deadline=deadline)


@pytest.mark.parametrize(
    "line,following,config",
    [
        (None, "abc", EntropyConfig()),
        ("abc", None, EntropyConfig()),
        ("abc", "def", None),
        ("abc", "def", object()),
    ],
)
def test_direct_overflow_guard_rejects_invalid_inputs(line, following, config) -> None:
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        check_multiline_overflow(line, following, config)


@pytest.mark.parametrize("deadline", [None, 10**15, 1e300])
def test_direct_functions_accept_valid_deadlines(deadline: float | None) -> None:
    assert not tuple(find_entropy_matches("abc", deadline=deadline))
    assert check_multiline_overflow("abc", "def", deadline=deadline) is None


def test_empty_overflow_guard_still_checks_expired_deadline() -> None:
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        check_multiline_overflow("", "", deadline=0.0)


def test_benign_minified_json_overflow_is_an_explicit_refusal(tmp_path: Path) -> None:
    line = json.dumps({"a": [0] * 2500}, separators=(",", ":"))
    assert len(line) > 4096
    assert json.loads(line) == {"a": [0] * 2500}
    assert not tuple(find_entropy_matches(line))
    text = line + "\n{}"
    (tmp_path / "data.jsonl").write_text(text)
    hasher = SnippetHasher(key=b"T" * 32)
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        check_multiline_overflow(line, "{}")
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        TreeScanner(tmp_path, hasher=hasher).scan()
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        SignatureEngine(hasher).analyser(FileTarget("data.jsonl", text))


@pytest.mark.parametrize("separator", ["-", " ", ".", "_"])
def test_short_inline_hex_fragments_are_a_documented_known_limit(
    tmp_path: Path, separator: str
) -> None:
    value = synthetic_value("hex")
    fragmented = separator.join(value[index : index + 8] for index in range(0, len(value), 8))
    assert "".join(fragmented.split(separator)) == value
    text = f'credential = "{fragmented}"'
    assert not tuple(find_entropy_matches(text))
    (tmp_path / "config.py").write_text(text)
    hasher = SnippetHasher(key=b"T" * 32)
    assert TreeScanner(tmp_path, hasher=hasher).scan() == []
    assert SignatureEngine(hasher).analyser(FileTarget("config.py", text)) == []


def test_half_million_micro_tokens_use_one_lexical_pass(monkeypatch) -> None:
    original = module._tokens
    passes = 0
    visited = 0

    def counted(line, deadline):
        nonlocal passes, visited
        passes += 1
        for token in original(line, deadline):
            visited += 1
            yield token

    def forbidden(*args):
        pytest.fail("micro tokens must not reach signatures or Shannon in the entropy detector")

    monkeypatch.setattr(module, "_tokens", counted)
    monkeypatch.setattr(module, "find_signature_matches", forbidden)
    monkeypatch.setattr(module, "shannon_entropy", forbidden)
    assert not tuple(find_entropy_matches("a " * 500_000))
    assert passes == 1
    assert visited == 500_000


def test_expired_deadline_rejects_dense_line_before_any_work(tmp_path: Path, monkeypatch) -> None:
    def forbidden(*args):
        pytest.fail("expired deadline must refuse before lexical or signature work")

    text = "a " * 500_000
    (tmp_path / "config.py").write_text(text)
    monkeypatch.setattr(module, "_tokens", forbidden)
    monkeypatch.setattr(module, "find_signature_matches", forbidden)
    monkeypatch.setattr("heimdall.scanner.detect.find_signature_matches", forbidden)
    monkeypatch.setattr("heimdall.scanner.signature_engine.find_signature_matches", forbidden)
    hasher = SnippetHasher(key=b"T" * 32)
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(find_entropy_matches(text, deadline=0.0))
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(find_line_matches(text, deadline=0.0))
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        TreeScanner(tmp_path, hasher=hasher).scan(deadline=0.0)
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        SignatureEngine(hasher, deadline=0.0).analyser(FileTarget("config.py", text))


@pytest.mark.parametrize("engine", ["tree", "target"])
def test_signature_results_are_reused_for_lines_and_adjacent_windows(
    tmp_path: Path, monkeypatch, engine
):
    calls = []
    original = registry.find_signature_matches

    def counted(line):
        calls.append(line)
        return original(line)

    for path in (
        "heimdall.scanner.entropy_detection.find_signature_matches",
        "heimdall.scanner.detect.find_signature_matches",
        "heimdall.scanner.signature_engine.find_signature_matches",
    ):
        monkeypatch.setattr(path, counted)
    lines = ["aws_secret_access_key =", '"' + synthetic_value("hex")[:40] + '"', "benign"]
    text = "\n".join(lines)
    hasher = SnippetHasher(key=b"T" * 32)
    (tmp_path / "config.py").write_text(text)
    findings = (
        TreeScanner(tmp_path, hasher=hasher).scan()
        if engine == "tree"
        else SignatureEngine(hasher).analyser(FileTarget("config.py", text))
    )
    assert [(f.line, f.type, f.source) for f in findings] == [
        (1, "aws", "regex"), (1, "credential", "regex"),
    ]
    assert calls == [lines[0] + lines[1], lines[0], lines[1] + lines[2], lines[1], lines[2]]


def test_dense_line_checks_deadline_after_its_single_signature_scan(monkeypatch) -> None:
    now = 0.0
    signature_calls = 0

    def signatures(line):
        nonlocal now, signature_calls
        signature_calls += 1
        now = 2.0
        return ()

    monkeypatch.setattr(module.time, "monotonic", lambda: now)
    monkeypatch.setattr(module, "find_signature_matches", signatures)
    with pytest.raises(ScanError, match="^scan impossible : entrée non analysable$"):
        tuple(find_line_matches("a " * 500_000, deadline=1.0))
    assert signature_calls == 1
