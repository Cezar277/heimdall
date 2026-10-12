"""Check cross-document consistency only; no runtime security assertions."""

from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET


def check_model(root: Path) -> list[str]:
    """Return human-readable errors without modifying files or using the network."""
    errors: list[str] = []
    stride = (root / "stride.md").read_text(encoding="utf-8")
    risks = (root / "risks.md").read_text(encoding="utf-8")
    expected = {f"{c}-{s}" for c in ("SCN", "MCP", "LLM", "CLI", "HOOK", "VLT", "STO", "CI") for s in "STRIDE"}
    scores: dict[str, tuple[int, int, int]] = {}
    for line in stride.splitlines():
        if not line.startswith('| <a id="'):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        match = re.fullmatch(r'<a id="([a-z]+-[a-z])"></a>([A-Z]+-[A-Z])', cols[0])
        if match is None or len(cols) != 7:
            errors.append(f"Malformed scenario: {line}")
            continue
        ident = match[2]
        if ident in scores or match[1] != ident.lower():
            errors.append(f"Duplicate ID / anchor mismatch: {ident}")
        try:
            impact, probability, score = map(int, cols[3:6])
        except ValueError:
            errors.append(f"Invalid numeric score: {ident}")
            continue
        scores[ident] = impact, probability, score
        if impact not in (1, 2, 3) or probability not in (1, 2, 3) or score != impact * probability:
            errors.append(f"Incorrect score: {ident}")
        if not all(cols) or not re.search(r"#\d+", cols[2]):
            errors.append(f"Empty field or missing mitigation owner: {ident}")
    if set(scores) != expected:
        errors.append("Expected exactly 8 components x 6 STRIDE scenarios")
    top = re.findall(r"^\| R(\d+) — .+?\| \[([A-Z]+-[A-Z])\]\(stride.md#.+?\) \| (\d) × (\d) = (\d) \|", risks, re.M)
    if [int(row[0]) for row in top] != list(range(1, 11)) or len({row[1] for row in top}) != 10:
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
    if ranked and any(score[2] > min(ranked) for ident, score in scores.items() if ident not in selected):
        errors.append("A higher scored scenario was omitted from the top ten")
    for doc in root.glob("*.md"):
        content = doc.read_text(encoding="utf-8")
        for destination in re.findall(r"\]\(([^)]+)\)", content):
            if destination.startswith(("https://", "http://")):
                continue
            path, _, anchor = destination.partition("#")
            target = (doc.parent / path) if path else doc
            if not target.is_file():
                errors.append(f"Missing local link in {doc.name}: {destination}")
            elif anchor and target.suffix == ".md":
                target_text = target.read_text(encoding="utf-8")
                headings = {re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in re.findall(r"^#+ (.+)$", target_text, re.M)}
                if anchor not in headings and f'id="{anchor}"' not in target_text:
                    errors.append(f"Missing anchor in {doc.name}: {destination}")
    tree = ET.parse(root / "dfd.drawio")
    if len(tree.findall("diagram")) != 1:
        errors.append("DFD must have one page")
    cells = tree.findall(".//mxCell")
    ids = [cell.get("id") for cell in cells]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate draw.io cell IDs")
    nodes = {ident for ident in ids if ident and re.fullmatch(r"[EPD]\d", ident)}
    if nodes != {"E1", "E2", "E3", "P1", "P2", "P3", "P4", "P5", "D1", "D2", "D3", "D4"}:
        errors.append("DFD must identify all twelve elements")
    flow_ids = set()
    for edge in (c for c in cells if c.get("edge") == "1"):
        ident = edge.get("id", "")
        flow_ids.add(ident[:3])
        if edge.get("source") not in nodes or edge.get("target") not in nodes or ident + "-label" not in ids:
            errors.append(f"Missing DFD endpoint or label: {ident}")
    if flow_ids != {f"F{n:02}" for n in range(1, 17)}:
        errors.append("DFD must cover flows F01..F16")
    dfd = (root / "dfd.md").read_text(encoding="utf-8")
    if set(re.findall(r"^\| (F\d{2}) \|", dfd, re.M)) != flow_ids:
        errors.append("DFD flow register and diagram disagree")
    for boundary in range(1, 6):
        if not any(ident == f"B{boundary}" or str(ident).startswith(f"B{boundary}-") for ident in ids):
            errors.append(f"DFD missing boundary B{boundary}")
    png = (root / "dfd.png").read_bytes()
    if png[:8] != b"\x89PNG\r\n\x1a\n" or len(png) < 24:
        errors.append("Missing PNG signature")
    elif struct.unpack(">II", png[16:24]) != (2600, 1680):
        errors.append("Unexpected diagram dimensions; review the export and update this check if intentional")
    return errors


if __name__ == "__main__":
    problems = check_model(Path(__file__).resolve().parent)
    if problems:
        print("\n".join(problems))
        raise SystemExit(1)
    print("OK: 48 STRIDE scenarios, valid scores, 10 linked risks/requirements, local links")
    print("OK: one DFD page, 12 elements, 16 flow IDs, 5 boundaries, PNG header")
    print("Document consistency only: visual review and runtime security evidence remain separate.")
