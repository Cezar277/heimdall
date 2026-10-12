"""Adversarial document mutations; no Git state or network required."""

import importlib.util
import re
import shutil
import struct
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_model", REPO / "docs/security/check_model.py")
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


@pytest.fixture
def model(tmp_path: Path) -> Path:
    """Real baseline plus its local link targets in an isolated temporary tree."""
    root = tmp_path / "docs/security"
    shutil.copytree(REPO / "docs/security", root, ignore=shutil.ignore_patterns("__pycache__"))
    for doc in root.glob("*.md"):
        for link in re.findall(r"\]\(([^)]+)\)", doc.read_text(encoding="utf-8")):
            if link.startswith(("https://", "http://", "#")):
                continue
            target = (doc.parent / link.split("#")[0]).resolve()
            relative = target.relative_to(tmp_path.resolve())
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / relative, target)
    assert checker.check_model(root) == []
    return root


def replace(root: Path, name: str, old: str, new: str) -> None:
    path = root / name
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "old", "new", "error"),
    [
        ("stride.md", "| 3 | 3 | 9 |", "| 3 | 3 | 8 |", "Incorrect score"),
        ("stride.md", "| 3 | 3 | 9 |", "| x | 3 | 9 |", "Invalid numeric score"),
        ("stride.md", 'id="scn-s"', 'id="wrong-s"', "anchor mismatch"),
        ("stride.md", "</a>SCN-S", "</a>SCN-T", "Duplicate ID"),
        ("stride.md", "</a>SCN-S", "</a>invalid", "Malformed scenario"),
        ("stride.md", "#22/#19.", "sans ticket.", "missing mitigation owner"),
        ("stride.md", "| 3 | 2 | 6 |", "| 3 | 3 | 9 |", "higher scored scenario"),
        ("risks.md", "| R1 —", "| R99 —", "ten unique risks"),
        ("risks.md", "3 × 3 = 9", "3 × 2 = 6", "Top risk differs"),
        ("risks.md", "### REQ-T19-01", "### REQ-T19-99", "association missing"),
        ("dfd.md", "| F01 |", "| F99 |", "register and diagram disagree"),
        ("dfd.md", "(dfd.png)", "(missing.png)", "Missing local link"),
        ("risks.md", "stride.md#scn-t", "stride.md#absent", "Missing anchor"),
        ("dfd.drawio", 'id="B1"', 'id="absent"', "missing boundary B1"),
        ("dfd.drawio", 'id="E1"', 'id="E99"', "all twelve elements"),
        ("dfd.drawio", 'id="E1"', 'id="E2"', "Duplicate draw.io cell IDs"),
        ("dfd.drawio", 'id="F01"', 'id="F99"', "cover flows F01..F16"),
        ("dfd.drawio", 'target="P1"', 'target="missing"', "endpoint or label"),
        ("dfd.drawio", "</mxfile>", '<diagram id="extra"/></mxfile>', "one page"),
    ],
)
def test_document_mutations(model: Path, name: str, old: str, new: str, error: str) -> None:
    replace(model, name, old, new)
    assert any(error in issue for issue in checker.check_model(model))


def test_unsorted_top_ten(model: Path) -> None:
    path = model / "risks.md"
    lines = path.read_text(encoding="utf-8").splitlines()
    positions = [i for i, line in enumerate(lines) if line.startswith("| R") and " — " in line]
    first, last = positions[0], positions[-1]
    lines[first], lines[last] = lines[last], lines[first]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert "Top risks are not in decreasing score order" in checker.check_model(model)


@pytest.mark.parametrize(
    "payload",
    [
        b'<!DOCTYPE mxfile [<!ENTITY nested "&nested;">]><mxfile>&nested;</mxfile>',
        b'<!DOCTYPE mxfile SYSTEM "file:///never-read"><mxfile/>',
        b'<!ENTITY unsafe "value"><mxfile/>',
        '<!DOCTYPE mxfile [<!ENTITY a "x">]><mxfile>&a;</mxfile>'.encode("utf-16"),
        "<!DOCTYPE mxfile><mxfile/>".encode("utf-16-le"),
        "<!DOCTYPE mxfile><mxfile/>".encode("utf-32-le"),
        b"<mxfile>",
        b"\xff\xfe\xff",
        b" " * (checker.MAX_XML_BYTES + 1),
    ],
    ids=[
        "nested-entity",
        "external-dtd",
        "entity",
        "utf16",
        "utf16le",
        "utf32le",
        "malformed",
        "invalid-utf8",
        "oversize",
    ],
)
def test_untrusted_xml_is_rejected(model: Path, payload: bytes) -> None:
    (model / "dfd.drawio").write_bytes(payload)
    assert any("Invalid DFD XML" in error for error in checker.check_model(model))


def test_forbidden_xml_never_reaches_parser(model: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (model / "dfd.drawio").write_bytes(b"<!DOCTYPE mxfile><mxfile/>")

    def forbidden_parse(*args: object, **kwargs: object) -> None:
        pytest.fail("DTD was handed to ElementTree")

    monkeypatch.setattr(checker.ET, "fromstring", forbidden_parse)
    assert checker.check_model(model)


@pytest.mark.parametrize("name", ["dfd.drawio", "dfd.png"])
def test_missing_artifact(model: Path, name: str) -> None:
    (model / name).unlink()
    assert checker.check_model(model)


@pytest.mark.parametrize("payload", [b"", b"\x89PNG\r\n\x1a\n", b"not png" * 10])
def test_bad_png_header(model: Path, payload: bytes) -> None:
    (model / "dfd.png").write_bytes(payload)
    assert "Invalid PNG signature or IHDR" in checker.check_model(model)


@pytest.mark.parametrize(
    ("width", "height", "accepted"),
    [
        (1300, 840, True),
        (5200, 3360, True),
        (0, 1680, False),
        (2600, 0, False),
        (100, 100, False),
        (8193, 4000, False),
        (2600, 8000, False),
        (8192, 8192, False),
    ],
)
def test_png_export_dimensions(model: Path, width: int, height: int, accepted: bool) -> None:
    # Deliberately header-only fixture: success does NOT prove a valid image.
    path = model / "dfd.png"
    data = bytearray(path.read_bytes())
    data[16:24] = struct.pack(">II", width, height)
    path.write_bytes(data)
    errors = checker.check_model(model)
    assert (not errors) is accepted


def test_utf8_bom_is_supported(model: Path) -> None:
    path = model / "dfd.drawio"
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    assert checker.check_model(model) == []


def test_cli_reports_success(capsys: pytest.CaptureFixture[str]) -> None:
    assert checker.main(REPO / "docs/security") == 0
    assert "Document consistency only" in capsys.readouterr().out


def test_cli_reports_failure(model: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (model / "dfd.drawio").write_bytes(b"<broken>")
    assert checker.main(model) == 1
    assert "Invalid DFD XML" in capsys.readouterr().out
