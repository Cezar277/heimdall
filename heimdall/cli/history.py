"""Historical snapshots, read in bounded batches; no checkout or network (#108–#110)."""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from pathlib import Path

from heimdall.cli.cold_start import MAX_QUALIFICATIONS, CandidateOpinion, qualify_target
from heimdall.cli.scan import _call_timeout, _verify_root_unchanged
from heimdall.llm.qualify import ChatFn
from heimdall.llm.rejections import RejectionJournal
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess, _checked_object
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.finding import Finding, validate_relative_path
from heimdall.scanner.interface import FileTarget, Scanner
from heimdall.scanner.policy import ScanSkip, prepare_text
from heimdall.scanner.signature_engine import SignatureEngine

BATCH_SIZE = 128
MAX_COMMITS = 100_000
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 1_000_000
MAX_READ_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_OCCURRENCES = 1_000_000
MAX_SECONDS = 300.0
CACHE_SIZE = 4096
TREE_HEADER_FIELDS = 3
MAX_TEXT_COMMITS = 10
WARNING = "considéré compromis, à révoquer et remplacer"


@dataclass(frozen=True)
class HistoricalFinding:
    finding: Finding
    commits: tuple[str, ...]


@dataclass(frozen=True)
class HistoryReport:
    findings: tuple[HistoricalFinding, ...]
    opinions: tuple[CandidateOpinion, ...]
    skipped: tuple[tuple[str, str, str], ...]
    commits_scanned: int
    entries_scanned: int
    bytes_scanned: int
    elapsed_seconds: float

    @property
    def complete(self) -> bool:
        return not self.skipped


def _git(access: GitAccess, args: tuple[str, ...], cap: int, deadline: float) -> bytes:
    return access._read_capped(args, cap, timeout=_call_timeout(deadline))


def _history_object(value: bytes) -> str:
    try:
        return _checked_object(value.decode("ascii"))
    except (UnicodeDecodeError, ToolFailure):
        raise ScanError("historique non analysable") from None


def _tips(access: GitAccess, deadline: float) -> tuple[str, ...]:
    # Snapshot ref tips; the caller rechecks them before returning a verdict.
    # Annotated tags are peeled by rev-list. Replacements are disabled below.
    raw = _git(access, ("--no-replace-objects", "rev-parse", "--all"), MAX_TREE_BYTES, deadline)
    tips = [_history_object(value) for value in raw.splitlines()]
    head = access.execute(
        ("--no-replace-objects", "rev-parse", "--verify", "HEAD"),
        timeout=_call_timeout(deadline),
    )
    if head.returncode == 0:
        tips.append(_history_object(head.stdout.strip()))
    elif tips:
        raise ScanError("historique non analysable")
    return tuple(sorted(set(tips)))


def _entries(raw: bytes) -> list[tuple[str, str]]:
    if raw and not raw.endswith(b"\0"):
        raise ScanError("arbre historique non analysable")
    entries = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        header, separator, path = entry.partition(b"\t")
        fields = header.split()
        if not separator or len(fields) != TREE_HEADER_FIELDS:
            raise ScanError("arbre historique non analysable")
        mode, kind, oid = fields
        if mode == b"160000":
            continue  # submodule commits are not blobs
        if mode not in (b"100644", b"100755", b"120000") or kind != b"blob":
            raise ScanError("arbre historique non analysable")
        try:
            file = path.decode("utf-8")
            validate_relative_path(file)
            object_id = _checked_object(oid.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            raise ScanError("arbre historique non analysable") from None
        entries.append((file, object_id))
    return entries


def collect_history(  # noqa: PLR0913 - explicit scan and qualification options
    root: Path,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    ci: bool = False,
    llm: bool = True,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
    strict: bool = False,
) -> HistoryReport:
    """Scan historical blobs; Git failures become static ScanError errors."""
    try:
        return _collect_history(
            root,
            max_file_bytes=max_file_bytes,
            ci=ci,
            llm=llm,
            chat=chat,
            journal=journal,
            strict=strict,
        )
    except ToolFailure:
        raise ScanError("historique non analysable") from None


def _collect_history(  # noqa: PLR0912, PLR0913, PLR0914, PLR0915 - bounded scan accounting
    root: Path,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    ci: bool = False,
    llm: bool = True,
    chat: ChatFn | None = None,
    journal: RejectionJournal | None = None,
    strict: bool = False,
) -> HistoryReport:
    """Scan every reachable snapshot, including merges and deleted files.

    Commit IDs are paged, one tree and one blob are held at a time. The LRU
    contains only bounded findings, never raw secrets. No worker fan-out:
    sequential batches keep peak memory independent of repository size.
    Oversized files are reported as skipped and make the result incomplete.
    """
    if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= MAX_FILE_BYTES:
        raise ScanError("limite de fichier invalide")
    if type(strict) is not bool:
        raise ScanError("politique de contenu invalide")
    started = time.monotonic()
    deadline = started + MAX_SECONDS
    access = GitAccess(root)
    if not access.is_repository(timeout=_call_timeout(deadline)):
        raise ScanError("historique non analysable")
    shallow = _git(
        access, ("--no-replace-objects", "rev-parse", "--is-shallow-repository"), 16, deadline
    )
    if shallow.strip() != b"false":
        raise ScanError("historique incomplet : clone superficiel")
    tips = _tips(access, deadline)
    records: dict[tuple[str, str, str], tuple[Finding, dict[str, None]]] = {}
    qualified: set[tuple[str, str]] = set()
    cache: OrderedDict[str, tuple[Finding, ...] | str] = OrderedDict()
    cache_skips: dict[str, tuple[str, ...]] = {}
    skipped: list[tuple[str, str, str]] = []
    opinions: list[CandidateOpinion] = []
    commits = entries = volume = occurrences = cache_findings = 0
    scanner = Scanner(SignatureEngine(deadline=deadline, strict=strict))
    while tips:
        raw = _git(
            access,
            (
                "--no-replace-objects",
                "rev-list",
                f"--max-count={BATCH_SIZE}",
                f"--skip={commits}",
                *tips,
                "--",
            ),
            BATCH_SIZE * 65,
            deadline,
        )
        batch = raw.splitlines()
        if not batch:
            break
        for value in batch:
            commit = _history_object(value)
            commits += 1
            if commits > MAX_COMMITS:
                raise ScanError("limite historique dépassée")
            _verify_root_unchanged(access, root)
            tree = _git(
                access,
                ("--no-replace-objects", "ls-tree", "-r", "-z", "--full-tree", commit),
                MAX_TREE_BYTES,
                deadline,
            )
            for file, oid in _entries(tree):
                _call_timeout(deadline)
                entries += 1
                if entries > MAX_ENTRIES:
                    raise ScanError("limite historique dépassée")
                if oid in cache:
                    cached = cache[oid]
                    cache.move_to_end(oid)
                else:
                    size = access.blob_size(oid, timeout=_call_timeout(deadline))
                    if size > max_file_bytes:
                        if strict:
                            raise ScanError("historique non analysable")
                        cached = "taille maximale dépassée"
                    else:
                        volume += size
                        if volume > MAX_READ_BYTES:
                            raise ScanError("limite historique dépassée")
                        data = access.blob_bytes(oid, timeout=_call_timeout(deadline))
                        if len(data) != size:
                            raise ScanError("objet historique modifié")
                        text = decode_text(data, strict=strict)
                        content_skips: list[ScanSkip] = []
                        if text is None:
                            if strict:
                                raise ScanError("historique non analysable")
                            content_skips.append(ScanSkip(file, "binary"))
                            text = ""
                        text = prepare_text(text, file, strict=strict, skipped=content_skips)
                        cache_skips[oid] = tuple(item.reason for item in content_skips)
                        target = FileTarget(file, text)
                        cached = tuple(scanner.scan(target))
                        if llm and not ci:
                            unique = {(f.type, f.snippet_hash): f for f in cached}
                            new = [f for key, f in unique.items() if key not in qualified]
                            if len(opinions) + len(new) > MAX_QUALIFICATIONS:
                                raise ScanError("trop de candidats pour la qualification locale")
                            opinions.extend(
                                qualify_target(
                                    target,
                                    new,
                                    chat=chat,
                                    journal=journal,
                                    deadline=deadline,
                                    context_findings=list(cached),
                                    ci=ci,
                                )
                            )
                            qualified.update((f.type, f.snippet_hash) for f in new)
                    cache[oid] = cached
                    cache_findings += 0 if isinstance(cached, str) else len(cached)
                    while len(cache) > CACHE_SIZE or cache_findings > MAX_RECORDS:
                        evicted_oid, evicted = cache.popitem(last=False)
                        cache_skips.pop(evicted_oid, None)
                        cache_findings -= 0 if isinstance(evicted, str) else len(evicted)
                for reason in cache_skips.get(oid, ()):
                    skipped.append((file, commit, reason))
                    if len(skipped) > MAX_RECORDS:
                        raise ScanError("limite historique dépassée")
                if isinstance(cached, str):
                    skipped.append((file, commit, cached))
                    if len(skipped) > MAX_RECORDS:
                        raise ScanError("limite historique dépassée")
                    continue
                for original in cached:
                    finding = replace(original, file=file)
                    key = (finding.type, finding.snippet_hash, finding.file)
                    if key not in records:
                        records[key] = (finding, {})
                    related = records[key][1]
                    if commit not in related:
                        related[commit] = None
                        occurrences += 1
                    if len(records) > MAX_RECORDS or occurrences > MAX_OCCURRENCES:
                        raise ScanError("limite historique dépassée")
    _verify_root_unchanged(access, root)
    if _tips(access, deadline) != tips:
        raise ScanError("références modifiées depuis le début du scan")
    _call_timeout(deadline)
    return HistoryReport(
        tuple(HistoricalFinding(f, tuple(ids)) for f, ids in records.values()),
        tuple(opinions),
        tuple(skipped),
        commits,
        entries,
        volume,
        time.monotonic() - started,
    )


def render_history(report: HistoryReport, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(
            {
                "schema": "heimdall.history.v1",
                "complete": report.complete,
                "findings": [
                    {"finding": item.finding.as_dict(), "commits": item.commits, "warning": WARNING}
                    for item in report.findings
                ],
                "opinions": [item.as_dict() for item in report.opinions],
                "skipped": [{"file": f, "commit": c, "reason": r} for f, c, r in report.skipped],
                "commits_scanned": report.commits_scanned,
                "entries_scanned": report.entries_scanned,
                "bytes_scanned": report.bytes_scanned,
                "elapsed_seconds": report.elapsed_seconds,
            },
            ensure_ascii=True,
            allow_nan=False,
        )
    lines = [
        f"Historique : {report.commits_scanned} commits, "
        f"{len(report.findings)} secret(s), {report.elapsed_seconds:.3f} s."
    ]
    for item in report.findings:
        commits = ", ".join(item.commits[:MAX_TEXT_COMMITS])
        remaining = len(item.commits) - MAX_TEXT_COMMITS
        if remaining > 0:
            commits += f", … (+{remaining})"
        lines.append(
            f"Secret trouvé dans l'historique (commits {commits}) : "
            f"{WARNING}. {json.dumps(item.finding.file, ensure_ascii=True)}:"
            f"{item.finding.line} [{item.finding.type}]"
        )
    for file, commit, reason in report.skipped:
        lines.append(
            f"Fichier ignoré {json.dumps(file, ensure_ascii=True)} (commit {commit}) : "
            f"{reason}. Scan incomplet."
        )
    for opinion in report.opinions:
        result = opinion.qualification
        lines.append(
            f"Avis LLM : {result.verdict or result.reason} ; "
            "proposition uniquement, validation humaine requise."
        )
    return "\n".join(lines)
