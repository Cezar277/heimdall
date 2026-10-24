"""T23 : détection générique, seuils, contexte et non-régressions sécurité."""

import base64
import hashlib
from pathlib import Path

import pytest

from heimdall.scanner import DiffTarget, EntropyConfig, FileTarget, Finding, Scanner
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.entropy_detection import context_lines, find_entropy_matches
from heimdall.scanner.errors import ScanError
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.signature_engine import SignatureEngine


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


@pytest.mark.parametrize(
    "text",
    [
        "a" * 100,
        "550e8400-e29b-41d4-a716-446655440000",
        "sha256 = '" + synthetic_value("hex") + "'",
        "commit = '" + synthetic_value("hex")[:40] + "'",
        "integrity = 'sha512-" + synthetic_value("base64") + "'",
        "data:image/png;base64," + synthetic_value("base64"),
    ],
)
def test_documented_non_secret_forms(text: str) -> None:
    assert not tuple(find_entropy_matches(text))


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


def test_public_value_does_not_hide_a_second_value_on_same_line() -> None:
    value = synthetic_value("base64")
    line = f'checksum="{synthetic_value("hex")}"; credential="{value}"'
    assert [match.value for match in find_entropy_matches(line)] == [value]
    line = f'icon="data:image/png;base64,AAAA"; credential="{value}"'
    assert [match.value for match in find_entropy_matches(line)] == [value]


def test_context_has_five_lines_each_side_without_finding_extension() -> None:
    target = FileTarget("config.py", "\n".join(f"line {number}" for number in range(1, 20)))
    context = context_lines(target, 10)
    assert [number for number, _ in context.lines] == list(range(5, 16))
    assert "line 10" not in repr(context)
    assert [number for number, _ in context_lines(target, 1).lines] == list(range(1, 7))
    assert [number for number, _ in context_lines(target, 19).lines] == list(range(14, 20))
    diff = DiffTarget("config.py", ((1, "first"), (10, "candidate"), (12, "last")))
    assert context_lines(diff, 10).lines == ((10, "candidate"), (12, "last"))


@pytest.mark.parametrize("target,line", [(object(), 1), (FileTarget("x", ""), 0)])
def test_invalid_context_request_is_refused(target: object, line: int) -> None:
    with pytest.raises(ScanError):
        context_lines(target, line)


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
