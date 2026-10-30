"""Entonnoir déterministe puis qualification locale des seuls candidats (#107)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from heimdall.cli.scan import (
    ScanReport,
    _read_worktree_file,
    _verify_root_unchanged,
    collect,
    render_json,
    render_text,
)
from heimdall.llm.qualify import ChatFn, Qualification
from heimdall.llm.rejections import RejectionJournal, qualify_finding
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess
from heimdall.mcp.masking import mask_text
from heimdall.mcp.paths import PathEscape, confine
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.finding import Finding
from heimdall.scanner.interface import FileTarget, Scanner
from heimdall.scanner.signature_engine import SignatureEngine

CONTEXT_LINES = 5
MAX_CONTEXT_LINE = 128
MAX_QUALIFICATIONS = 256
MAX_QUALIFICATION_SECONDS = 300.0


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ScanError("limite de temps de qualification dépassée")


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
    skipped_files: tuple[str, ...] = ()


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


def qualify_target(  # noqa: PLR0913 - qualification with complete masking context
    target: FileTarget,
    findings: list[Finding],
    *,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
    deadline: float | None = None,
    context_findings: list[Finding] | None = None,
) -> list[CandidateOpinion]:
    """L'avis ne supprime jamais un finding, même en cas de faux positif."""
    if len(findings) > MAX_QUALIFICATIONS:
        raise ScanError("trop de candidats pour la qualification locale")
    if deadline is None:
        deadline = time.monotonic() + MAX_QUALIFICATION_SECONDS
    opinions = []
    for finding in findings:
        _check_deadline(deadline)
        opinion = qualify_finding(
            finding,
            candidate_context(
                target, finding, findings if context_findings is None else context_findings
            ),
            chat=chat,
            journal=journal,
        )
        # Un appel en cours conserve le timeout réseau de T28 (60 s).
        # Aucun appel suivant n'est lancé après la deadline globale.
        _check_deadline(deadline)
        opinions.append(CandidateOpinion(finding, opinion))
    return opinions


def collect_cold_start(  # noqa: PLR0913 - explicit scan and qualification options
    root: Path,
    *,
    ci: bool = False,
    llm: bool = True,
    max_file_bytes: int = MAX_FILE_BYTES,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
) -> ColdStartReport:
    """Collect and qualify candidates; Git failures use the scanner contract."""
    try:
        return _collect_cold_start(
            root, ci=ci, llm=llm, max_file_bytes=max_file_bytes, chat=chat, journal=journal
        )
    except ToolFailure:
        raise ScanError("scan impossible : entrée non analysable") from None


def _collect_cold_start(  # noqa: PLR0913 - explicit scan and qualification options
    root: Path,
    *,
    ci: bool = False,
    llm: bool = True,
    max_file_bytes: int = MAX_FILE_BYTES,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
) -> ColdStartReport:
    if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= MAX_FILE_BYTES:
        raise ScanError("limite de fichier invalide")
    # Capturer l'identité AVANT collect ferme aussi l'intervalle entre les
    # deux passes, et pas seulement les substitutions pendant la relecture.
    access = GitAccess(root) if llm and not ci else None
    skipped: list[str] = []
    scan = collect(root, staged=False, ci=ci, max_file_bytes=max_file_bytes, skipped_files=skipped)
    if access is not None:
        _verify_root_unchanged(access, root)
    if access is None or not scan.findings:
        return ColdStartReport(scan, (), tuple(skipped))
    if len(scan.findings) > MAX_QUALIFICATIONS:
        raise ScanError("trop de candidats pour la qualification locale")
    deadline = time.monotonic() + MAX_QUALIFICATION_SECONDS
    by_file: dict[str, list[Finding]] = {}
    for finding in scan.findings:
        by_file.setdefault(finding.file, []).append(finding)
    opinions = []
    for file, findings in by_file.items():
        _check_deadline(deadline)
        _verify_root_unchanged(access, root)
        try:
            path = confine(access.root, file).absolute
        except PathEscape:
            raise ScanError("chemin de qualification hors périmètre") from None
        raw = _read_worktree_file(path, max_bytes=max_file_bytes)
        try:
            text = decode_text(raw) if raw is not None else None
        except ScanError:
            raise ScanError("contenu modifié depuis le scan déterministe") from None
        if text is None:
            raise ScanError("contenu modifié depuis le scan déterministe")
        target = FileTarget(file, text)
        # Sur-ensemble volontaire sans allowlist : on vérifie l'appartenance
        # des findings retenus, pas l'égalité de deux rapports. TreeScanner et
        # SignatureEngine partagent DEFAULT_ENTROPY_CONFIG et la même clé HMAC
        # locale persistante via SnippetHasher() ; le test de parité le prouve.
        current = Scanner(SignatureEngine(deadline=deadline)).scan(target)
        if any(finding not in current for finding in findings):
            raise ScanError("contenu modifié depuis le scan déterministe")
        opinions.extend(
            qualify_target(target, findings, chat=chat, journal=journal, deadline=deadline)
        )
    _verify_root_unchanged(access, root)
    _check_deadline(deadline)
    return ColdStartReport(scan, tuple(opinions), tuple(skipped))


def render_cold_start(report: ColdStartReport, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(
            {
                "schema": "heimdall.cold-start.v1",
                "scan": json.loads(render_json(report.scan)),
                "opinions": [opinion.as_dict() for opinion in report.opinions],
                "complete": not report.skipped_files,
                "skipped_files": report.skipped_files,
            },
            ensure_ascii=True,
            allow_nan=False,
        )
    lines = [render_text(report.scan)]
    for file in report.skipped_files:
        lines.append(
            f"Fichier ignoré {json.dumps(file, ensure_ascii=True)} : "
            "taille maximale dépassée. Scan incomplet."
        )
    for opinion in report.opinions:
        result = opinion.qualification
        lines.append(
            f"Avis LLM : {result.verdict or result.reason} ; "
            "proposition uniquement, validation humaine requise."
        )
    return "\n".join(lines)
