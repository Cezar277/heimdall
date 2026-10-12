"""Check cross-document consistency only; no runtime security assertions."""

import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath, PureWindowsPath

MAX_XML_BYTES = 2 * 1024 * 1024
MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
# Untrusted D1 input: baseline is 64 cells at ~6 nesting levels, so both
# bounds leave wide room for legitimate DFD evolution while failing closed
# before expat ever sees a mass or deeply nested payload.
MAX_XML_CELLS = 5000
MAX_XML_DEPTH = 64
SCENARIO_COLUMNS = 7
TOP_RISK_COUNT = 10
PNG_HEADER_BYTES = 33
PNG_MIN_WIDTH = 640
PNG_MIN_HEIGHT = 400
PNG_MAX_SIDE = 8192
PNG_MAX_RATIO = 2.2
PNG_MAX_PIXELS = 32_000_000


def confined_file(path: Path, repository: Path) -> Path:
    """Resolve a static checkout path before any content read, including symlinks."""
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(repository) or not resolved.is_file():
        raise ValueError("File outside repository or not a regular file")
    return resolved


def read_document(path: Path, repository: Path) -> str:
    """Bound Markdown reads; do not include file contents in diagnostics."""
    target = confined_file(path, repository)
    with target.open("rb") as stream:
        data = stream.read(MAX_MARKDOWN_BYTES + 1)
    if len(data) > MAX_MARKDOWN_BYTES:
        raise ValueError("Markdown exceeds 2 MiB")
    return data.decode("utf-8-sig")


def check_links(root: Path, repository: Path) -> list[str]:
    """Allow relative links within the checkout, never absolute/outgoing links."""
    errors: list[str] = []
    for doc_number, doc in enumerate(sorted(root.glob("*.md")), 1):
        try:
            content = read_document(doc, repository)
        except (OSError, ValueError, RuntimeError):
            errors.append(f"Invalid Markdown document {doc_number}")
            continue
        for link_number, destination in enumerate(re.findall(r"\]\(([^)]+)\)", content), 1):
            if destination.startswith(("https://", "http://")):
                continue
            location = f"document {doc_number}, link {link_number}"
            path, _, anchor = destination.partition("#")
            # Also reject Windows drives/UNC when running on Linux and vice versa.
            if (
                PurePosixPath(path).is_absolute()
                or PureWindowsPath(path).drive
                or path.startswith("\\")
            ):
                errors.append(f"Unsafe local link at {location}")
                continue
            try:
                target = confined_file(doc.parent / path if path else doc, repository)
                if anchor and target.suffix == ".md":
                    target_text = read_document(target, repository)
                    headings = {
                        re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-")
                        for h in re.findall(r"^#+ (.+)$", target_text, re.M)
                    }
                    if anchor not in headings and f'id="{anchor}"' not in target_text:
                        errors.append(f"Missing anchor at {location}")
            except FileNotFoundError:
                errors.append(f"Missing local link at {location}")
            except (OSError, ValueError, RuntimeError):
                errors.append(f"Unsafe or unreadable local link at {location}")
    return errors


def xml_nesting_exceeds(text: str, limit: int = MAX_XML_DEPTH) -> bool:
    """Quote-aware tag depth scan; fail-closed before handing text to expat."""
    depth = 0
    index = 0
    size = len(text)
    while index < size:
        if text[index] != "<":
            index += 1
            continue
        if text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            if end == -1:
                return True
            index = end + 3
            continue
        if text.startswith("<![CDATA[", index):
            end = text.find("]]>", index + 9)
            if end == -1:
                return True
            index = end + 3
            continue
        # Tag end respecting quotes: attribute values may legally hold '>'.
        cursor = index + 1
        quote: str | None = None
        while cursor < size:
            char = text[cursor]
            if quote is not None:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == ">":
                break
            cursor += 1
        if cursor >= size:
            return True
        tag = text[index : cursor + 1]
        if tag.startswith("</"):
            depth -= 1
            if depth < 0:
                return True
        elif tag.endswith("/>") or tag.startswith("<?") or tag.startswith("<!"):
            pass
        else:
            depth += 1
            if depth > limit:
                return True
        index = cursor + 1
    return False


def load_drawio(path: Path) -> ET.Element:
    """Parse only bounded UTF-8 XML without DTDs or entity declarations."""
    with path.open("rb") as stream:
        data = stream.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        raise ValueError("DFD XML exceeds 2 MiB")
    # Decode before inspection: UTF-16/32 cannot bypass the declaration guard
    # with interleaved NULs. Draw.io source in this repository is UTF-8 only.
    text = data.decode("utf-8-sig")
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
        raise ValueError("DFD XML must be UTF-8 without DTD or entity declarations")
    if xml_nesting_exceeds(text):
        raise ValueError("DFD XML nesting exceeds bound")
    return ET.fromstring(text)  # noqa: S314 -- bounded, DTD/entities rejected above


# This aggregator deliberately reports all independent document inconsistencies.
def check_model(root: Path) -> list[str]:  # noqa: PLR0912, PLR0915
    """Return human-readable errors without modifying files or using the network."""
    errors: list[str] = []
    repository = root.parent.parent.resolve()
    try:
        stride = read_document(root / "stride.md", repository)
        risks = read_document(root / "risks.md", repository)
        dfd = read_document(root / "dfd.md", repository)
    except (OSError, ValueError, RuntimeError):
        return ["Invalid required model document"]
    expected = {
        f"{c}-{s}"
        for c in ("SCN", "MCP", "LLM", "CLI", "HOOK", "VLT", "STO", "CI")
        for s in "STRIDE"
    }
    scores: dict[str, tuple[int, int, int]] = {}
    for line_number, line in enumerate(stride.splitlines(), 1):
        if not line.startswith('| <a id="'):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        match = re.fullmatch(r'<a id="([a-z]+-[a-z])"></a>([A-Z]+-[A-Z])', cols[0])
        if match is None or len(cols) != SCENARIO_COLUMNS:
            errors.append(f"Malformed scenario at line {line_number}")
            continue
        ident = match[2]
        if ident in scores or match[1] != ident.lower():
            errors.append(f"Duplicate ID / anchor mismatch at line {line_number}")
        try:
            impact, probability, score = map(int, cols[3:6])
        except ValueError:
            errors.append(f"Invalid numeric score at line {line_number}")
            continue
        scores[ident] = impact, probability, score
        if impact not in (1, 2, 3) or probability not in (1, 2, 3) or score != impact * probability:
            errors.append(f"Incorrect score at line {line_number}")
        if not all(cols) or not re.search(r"#\d+", cols[2]):
            errors.append(f"Empty field or missing mitigation owner at line {line_number}")
    if set(scores) != expected:
        errors.append("Expected exactly 8 components x 6 STRIDE scenarios")
    top = re.findall(
        r"^\| R(\d+) — .+?\| \[([A-Z]+-[A-Z])\]\(stride.md#.+?\) \| (\d) × (\d) = (\d) \|",
        risks,
        re.M,
    )
    if [int(row[0]) for row in top] != list(range(1, TOP_RISK_COUNT + 1)) or len(
        {row[1] for row in top}
    ) != TOP_RISK_COUNT:
        errors.append("Expected ten unique risks R1..R10")
    for number, ident, impact, probability, score in top:
        if scores.get(ident) != (int(impact), int(probability), int(score)):
            errors.append(f"Top risk differs from STRIDE: R{number}")
        if f"### REQ-T19-{int(number):02}" not in risks or f"**R{number}** ({ident})" not in risks:
            errors.append(f"Requirement / risk association missing: R{number}")
    ranked = [int(row[4]) for row in top]
    if ranked != sorted(ranked, reverse=True):
        errors.append("Top risks are not in decreasing score order")
    selected = {row[1] for row in top}
    if ranked and any(
        score[2] > min(ranked) for ident, score in scores.items() if ident not in selected
    ):
        errors.append("A higher scored scenario was omitted from the top ten")
    errors.extend(check_links(root, repository))
    try:
        tree = load_drawio(confined_file(root / "dfd.drawio", repository))
    except (OSError, ValueError, RuntimeError, ET.ParseError) as exc:
        errors.append(f"Invalid DFD XML: {type(exc).__name__}")
        return errors
    if len(tree.findall("diagram")) != 1:
        errors.append("DFD must have one page")
    cells = tree.findall(".//mxCell")
    if len(cells) > MAX_XML_CELLS:
        errors.append("Too many draw.io cells")
        return errors
    ids = [cell.get("id") for cell in cells]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate draw.io cell IDs")
    nodes = {ident for ident in ids if ident and re.fullmatch(r"[EPD]\d", ident)}
    if nodes != {"E1", "E2", "E3", "P1", "P2", "P3", "P4", "P5", "D1", "D2", "D3", "D4"}:
        errors.append("DFD must identify all twelve elements")
    # F13 legitimately splits into two edges; every other flow has one edge.
    # Exact whitelist: ident[:3] folding previously accepted F01-evil as F01.
    allowed_edges = {f"F{n:02}" for n in range(1, 17)} | {"F13a", "F13b"}
    flow_ids = set()
    for edge_number, edge in enumerate((c for c in cells if c.get("edge") == "1"), 1):
        ident = edge.get("id", "")
        if ident not in allowed_edges:
            errors.append(f"Unexpected DFD edge at edge {edge_number}")
            continue
        flow_ids.add("F13" if ident in ("F13a", "F13b") else ident)
        if (
            edge.get("source") not in nodes
            or edge.get("target") not in nodes
            or ident + "-label" not in ids
        ):
            errors.append(f"Missing DFD endpoint or label at edge {edge_number}")
    if flow_ids != {f"F{n:02}" for n in range(1, 17)}:
        errors.append("DFD must cover flows F01..F16")
    if set(re.findall(r"^\| (F\d{2}) \|", dfd, re.M)) != flow_ids:
        errors.append("DFD flow register and diagram disagree")
    for boundary in range(1, 6):
        if not any(
            ident == f"B{boundary}" or str(ident).startswith(f"B{boundary}-") for ident in ids
        ):
            errors.append(f"DFD missing boundary B{boundary}")
    # Header sanity only: no claim of image integrity or graphical equivalence.
    try:
        with confined_file(root / "dfd.png", repository).open("rb") as stream:
            png = stream.read(PNG_HEADER_BYTES)
    except (OSError, ValueError, RuntimeError):
        errors.append("Missing or unreadable PNG")
        return errors
    if (
        len(png) != PNG_HEADER_BYTES
        or png[:8] != b"\x89PNG\r\n\x1a\n"
        or png[8:16] != b"\x00\x00\x00\rIHDR"
    ):
        errors.append("Invalid PNG signature or IHDR")
    else:
        width, height = struct.unpack(">II", png[16:24])
        if not (
            PNG_MIN_WIDTH <= width <= PNG_MAX_SIDE
            and PNG_MIN_HEIGHT <= height <= PNG_MAX_SIDE
            and 1 <= width / height <= PNG_MAX_RATIO
            and width * height <= PNG_MAX_PIXELS
        ):
            errors.append(
                "PNG outside readable landscape bounds "
                "(640..8192 x 400..8192, ratio 1..2.2, <=32MP)"
            )
    return errors


def main(root: Path) -> int:
    """Report document checks, without claiming graphical or runtime validation."""
    problems = check_model(root)
    if problems:
        print("\n".join(problems))
        return 1
    print("OK: 48 STRIDE scenarios, valid scores, 10 linked risks/requirements, local links")
    print("OK: one DFD page, 12 elements, 16 flow IDs, 5 boundaries, PNG header")
    print("Document consistency only: visual review and runtime security evidence remain separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(__file__).resolve().parent))
