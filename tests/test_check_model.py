"""Adversarial document mutations; no Git state or network required."""

import importlib.util
import os
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


@pytest.mark.parametrize("kind", ["relative-escape", "absolute", "symlink"])
def test_links_cannot_read_outside_repository(
    model: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = model.parent.parent
    outside = repository.parent / f"{repository.name}-outside.md"
    outside.write_text("# Outside\nSYNTHETIC_NON_SECRET_CANARY\n", encoding="utf-8")
    if kind == "symlink":
        link = model / "escape.md"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"OS does not permit symlink creation: {exc.errno}")
        destination = "escape.md"
    elif kind == "absolute":
        destination = outside.as_posix()
    else:
        destination = os.path.relpath(outside, model).replace(os.sep, "/")
    with (model / "risks.md").open("a", encoding="utf-8") as stream:
        stream.write(f"\n[Untrusted target]({destination}#outside)\n")
    original_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path.resolve() == outside.resolve():
            pytest.fail("Outside file was opened")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    errors = checker.check_model(model)
    assert any("Unsafe" in error for error in errors)
    assert "SYNTHETIC_NON_SECRET_CANARY" not in "\n".join(errors)


@pytest.mark.parametrize(
    "destination", ["/etc/hostname", "C:/outside.md", "C:outside.md", "\\\\host\\share\\x.md"]
)
def test_absolute_link_forms_are_rejected(model: Path, destination: str) -> None:
    with (model / "risks.md").open("a", encoding="utf-8") as stream:
        stream.write(f"\n[Link]({destination}#heading)\n")
    assert any("Unsafe local link" in error for error in checker.check_model(model))


def test_relative_links_within_repository_remain_valid(model: Path) -> None:
    (model.parent / "sibling.md").write_text("# Valid\n", encoding="utf-8")
    with (model / "risks.md").open("a", encoding="utf-8") as stream:
        stream.write("\n[Sibling](../sibling.md#valid)\n")
    assert checker.check_model(model) == []


@pytest.mark.parametrize("name", ["stride.md", "notes.md", "linked.md"])
def test_markdown_reads_are_bounded(model: Path, name: str) -> None:
    (model / name).write_bytes(b"x" * (checker.MAX_MARKDOWN_BYTES + 1))
    if name == "linked.md":
        with (model / "risks.md").open("a", encoding="utf-8") as stream:
            stream.write("\n[Too large](linked.md#heading)\n")
    assert checker.check_model(model)


def test_untrusted_text_is_not_echoed(model: Path, capsys: pytest.CaptureFixture[str]) -> None:
    marker = "SYNTHETIC_NON_SECRET_CANARY"
    with (model / "stride.md").open("a", encoding="utf-8") as stream:
        stream.write(f'\n| <a id="broken"></a> {marker} |\n')
    with (model / "risks.md").open("a", encoding="utf-8") as stream:
        stream.write(f"\n[Bad link](missing-{marker}.md#heading)\n")
    replace(model, "dfd.drawio", 'id="F01"', f'id="{marker}"')
    assert checker.main(model) == 1
    output = capsys.readouterr().out
    assert "Malformed scenario at line" in output
    assert marker not in output
