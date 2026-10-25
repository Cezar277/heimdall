"""Entonnoir déterministe puis qualification locale des seuls candidats (#107)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from heimdall.cli.scan import ScanReport, _read_worktree_file, collect, render_json, render_text
from heimdall.llm.qualify import ChatFn, Qualification
from heimdall.llm.rejections import RejectionJournal, qualify_finding
from heimdall.mcp.gitdiff import GitAccess
from heimdall.mcp.masking import mask_text
from heimdall.mcp.paths import confine
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.finding import Finding
from heimdall.scanner.interface import FileTarget, Scanner
from heimdall.scanner.signature_engine import SignatureEngine

CONTEXT_LINES = 5
MAX_CONTEXT_LINE = 128
MAX_QUALIFICATIONS = 256


@dataclass(frozen=True)
class CandidateOpinion:
    finding: Finding
    qualification: Qualification

    def as_dict(self) -> dict[str, object]:
        return {
            "finding": self.finding.as_dict(),
            "verdict": self.qualification.verdict,
            "reason": self.qualification.reason,
            "validation_humaine_requise": True,
        }


@dataclass(frozen=True)
class ColdStartReport:
    scan: ScanReport
    opinions: tuple[CandidateOpinion, ...]


def candidate_context(target: FileTarget, finding: Finding, findings: list[Finding]) -> str:
    """Candidat + cinq lignes de part et d'autre, < 2000 caractères.

    Toute ligne portant un finding est remplacée intégralement. Le contexte
    est masqué AVANT d'être tronqué, comme pour les outils MCP.
    """
    lines = target.lignes()
    if finding.file != target.path or finding.line > len(lines):
        raise ScanError("contexte de qualification invalide")
    sensitive = {item.line for item in findings}
    selected = lines[max(0, finding.line - CONTEXT_LINES - 1) : finding.line + CONTEXT_LINES]
    context = []
    for number, text in selected:
        masked = "<REDACTED:candidate>" if number in sensitive else mask_text(text)[0]
        context.append(f"{number}: {masked[:MAX_CONTEXT_LINE]}")
    return "\n".join(context)


def qualify_target(
    target: FileTarget,
    findings: list[Finding],
    *,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
) -> list[CandidateOpinion]:
    """L'avis ne supprime jamais un finding, même en cas de faux positif."""
    if len(findings) > MAX_QUALIFICATIONS:
        raise ScanError("trop de candidats pour la qualification locale")
    return [
        CandidateOpinion(
            finding,
            qualify_finding(
                finding, candidate_context(target, finding, findings), chat=chat, journal=journal
            ),
        )
        for finding in findings
    ]


def collect_cold_start(
    root: Path,
    *,
    ci: bool = False,
    llm: bool = True,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
) -> ColdStartReport:
    scan = collect(root, staged=False, ci=ci)
    if ci or not llm or not scan.findings:
        return ColdStartReport(scan, ())
    if len(scan.findings) > MAX_QUALIFICATIONS:
        raise ScanError("trop de candidats pour la qualification locale")
    access = GitAccess(root)
    by_file: dict[str, list[Finding]] = {}
    for finding in scan.findings:
        by_file.setdefault(finding.file, []).append(finding)
    opinions = []
    for file, findings in by_file.items():
        path = confine(access.root, file).absolute
        raw = _read_worktree_file(path, max_bytes=MAX_FILE_BYTES)
        text = decode_text(raw) if raw is not None else None
        if text is None:
            raise ScanError("contenu modifié depuis le scan déterministe")
        target = FileTarget(file, text)
        # Ne pas présenter au modèle le contexte d'un snapshot devenu périmé.
        current = Scanner(SignatureEngine()).scan(target)
        if any(finding not in current for finding in findings):
            raise ScanError("contenu modifié depuis le scan déterministe")
        opinions.extend(qualify_target(target, findings, chat=chat, journal=journal))
    return ColdStartReport(scan, tuple(opinions))


def render_cold_start(report: ColdStartReport, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(
            {
                "schema": "heimdall.cold-start.v1",
                "scan": json.loads(render_json(report.scan)),
                "opinions": [opinion.as_dict() for opinion in report.opinions],
            },
            ensure_ascii=True,
            allow_nan=False,
        )
    lines = [render_text(report.scan)]
    for opinion in report.opinions:
        result = opinion.qualification
        lines.append(
            f"Avis LLM : {result.verdict or result.reason} ; "
            "proposition uniquement, validation humaine requise."
        )
    return "\n".join(lines)
