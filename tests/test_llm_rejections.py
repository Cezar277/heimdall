"""T33 : audit durable, non-fuite, altération, CI sans LLM (hors ligne)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from heimdall.cli import main as cli_module
from heimdall.cli.main import app
from heimdall.cli.scan import ScanReport
from heimdall.llm import rejections as audit
from heimdall.llm.rejections import JournalError, RejectionJournal, qualify_finding
from heimdall.scanner.finding import Finding


@pytest.fixture
def finding() -> Finding:
    return Finding(file="src/example.py", line=12, type="aws", entropy=4.2, snippet_hash="a" * 64)


@pytest.fixture
def journal(tmp_path: Path) -> RejectionJournal:
    return RejectionJournal(tmp_path / "audit" / "rejections.jsonl")


def chat_reply(verdict: str = "faux_positif") -> Any:
    def chat(**kwargs: Any) -> SimpleNamespace:
        assert "<REDACTED:" in kwargs["messages"][1]["content"]
        return SimpleNamespace(
            message=SimpleNamespace(content=json.dumps({"verdict": verdict, "confidence": 0.9}))
        )

    return chat


def test_rejection_is_durable_visible_and_never_removes_finding(
    finding: Finding, journal: RejectionJournal, caplog: pytest.LogCaptureFixture
) -> None:
    before = finding.as_dict()
    result = qualify_finding(
        finding, "TOKEN='<REDACTED:aws:len=20>'", chat=chat_reply(), journal=journal
    )
    assert result.verdict == "faux_positif"
    assert result.status == "detecte"
    assert finding.as_dict() == before
    assert "1 candidat(s)" in caplog.text
    assert "heimdall rejections --details" in caplog.text
    entries = journal.read()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["file"] == finding.file
    assert entry["line"] == finding.line
    assert entry["model"] == audit.DEFAULT_MODEL
    assert entry["prompt_version"] == "qualify_v1"
    assert entry["prompt_sha256"] == audit.prompt_digest()
    assert entry["date"].endswith("+00:00")
    assert entry["justification"] == audit.JUSTIFICATION
    assert "REDACTED" not in journal.path.read_text()


def test_chain_survives_reopening(finding: Finding, journal: RejectionJournal) -> None:
    for _ in range(4):
        RejectionJournal(journal.path).append(finding, model="gemma3:270m")
    entries = journal.read()
    assert entries[0]["previous_hash"] == audit.GENESIS
    for index, entry in enumerate(entries):
        assert entry["sequence"] == index + 1
        if index:
            assert entry["previous_hash"] == entries[index - 1]["hash"]
        payload = {key: value for key, value in entry.items() if key != "hash"}
        assert entry["hash"] == hashlib.sha256(audit._encode(payload)).hexdigest()


@pytest.mark.parametrize("attack", ["change", "delete", "reorder", "truncate", "duplicate", "json"])
def test_tampering_refuses_read_and_append(
    finding: Finding, journal: RejectionJournal, attack: str
) -> None:
    for _ in range(3):
        journal.append(finding, model="gemma3:270m")
    lines = journal.path.read_bytes().splitlines(keepends=True)
    if attack == "change":
        lines[0] = lines[0].replace(b"example.py", b"changed.py")
    elif attack == "delete":
        del lines[1]
    elif attack == "reorder":
        lines[0], lines[1] = lines[1], lines[0]
    elif attack == "truncate":
        lines[-1] = lines[-1][:-4]
    elif attack == "duplicate":
        lines.append(lines[-1])
    else:
        lines.append(b"[]\n")
    damaged = b"".join(lines)
    journal.path.write_bytes(damaged)
    with pytest.raises(JournalError, match="journal des rejets"):
        journal.read()
    with pytest.raises(JournalError):
        journal.append(finding, model="gemma3:270m")
    assert journal.path.read_bytes() == damaged


@pytest.mark.parametrize("verdict", ["secret", "incertain"])
def test_non_rejections_do_not_create_journal(
    finding: Finding, journal: RejectionJournal, verdict: str
) -> None:
    result = qualify_finding(
        finding, "<REDACTED:aws:len=20>", chat=chat_reply(verdict), journal=journal
    )
    assert result.verdict == verdict
    assert not journal.path.exists()


def test_ci_never_calls_model_or_journal(finding: Finding, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("appel interdit en CI")

    monkeypatch.setattr(audit, "qualify_candidate", forbidden)
    monkeypatch.setattr(audit, "RejectionJournal", forbidden)
    result = qualify_finding(finding, "ignored", ci=True, chat=forbidden)
    assert result.status == "detecte"
    assert result.verdict is None


@pytest.mark.parametrize("content", ["garbage", '{"verdict":"faux_positif","reason":"ATTACK"}'])
def test_invalid_model_response_is_not_a_rejection(
    finding: Finding, journal: RejectionJournal, content: str
) -> None:
    result = qualify_finding(
        finding,
        "<REDACTED:aws:len=20>",
        chat=lambda **kwargs: SimpleNamespace(message=SimpleNamespace(content=content)),
        journal=journal,
    )
    assert result.reason == "invalid"
    assert not journal.path.exists()


@pytest.mark.parametrize("failure", ["write", "fsync"])
def test_io_failure_never_returns_rejection(
    finding: Finding, journal: RejectionJournal, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    def fail(*args: Any) -> Any:
        raise OSError("SYNTHETIC_PRIVATE_ERROR")

    monkeypatch.setattr(audit.os, failure, fail)
    with pytest.raises(JournalError) as error:
        qualify_finding(finding, "<REDACTED:aws:len=20>", chat=chat_reply(), journal=journal)
    assert "SYNTHETIC_PRIVATE_ERROR" not in str(error.value)


def test_short_writes_are_completed(
    finding: Finding, journal: RejectionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    write = os.write
    monkeypatch.setattr(audit.os, "write", lambda fd, data: write(fd, data[:17]))
    journal.append(finding, model="gemma3:270m")
    assert len(journal.read()) == 1


def test_concurrent_access_refuses_instead_of_forking_chain(
    finding: Finding, journal: RejectionJournal
) -> None:
    with audit._locked(journal.path):
        with pytest.raises(JournalError):
            journal.append(finding, model="gemma3:270m")
    journal.append(finding, model="gemma3:270m")
    assert len(journal.read()) == 1


def test_size_limit_refuses_without_truncation(
    finding: Finding, journal: RejectionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal.append(finding, model="gemma3:270m")
    before = journal.path.read_bytes()
    monkeypatch.setattr(audit, "MAX_JOURNAL_BYTES", len(before))
    with pytest.raises(JournalError):
        journal.append(finding, model="gemma3:270m")
    assert journal.path.read_bytes() == before


def test_cli_summary_and_escaped_details(
    finding: Finding, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    journal = RejectionJournal()
    for _ in range(4):
        journal.append(finding, model="gemma3:270m")
    result = CliRunner().invoke(app, ["rejections", "--details"])
    assert result.exit_code == 0
    assert "4 candidat(s)" in result.stdout
    lines = result.stdout.splitlines()
    assert len(lines) == 5
    assert json.loads(lines[-1])["sequence"] == 4


def test_cli_corruption_exit_two(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    journal = RejectionJournal()
    assert journal.read() == []
    journal.path.write_text("SYNTHETIC_PRIVATE_ERROR\n")
    result = CliRunner().invoke(app, ["rejections", "--details"])
    assert result.exit_code == 2
    assert "SYNTHETIC_PRIVATE_ERROR" not in result.output
    assert "indisponible ou invalide" in result.output


def test_insecure_paths_rejected(tmp_path: Path) -> None:
    with pytest.raises(JournalError):
        RejectionJournal(Path("relative.jsonl")).read()
    with pytest.raises(JournalError):
        RejectionJournal(tmp_path / ".." / "escape.jsonl").read()


def test_scan_ci_keeps_findings_and_never_reads_rejections(
    finding: Finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli_module, "collect", lambda *args, **kwargs: ScanReport("working-tree", (finding,))
    )

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("le scan CI ne doit jamais utiliser les rejets du LLM")

    monkeypatch.setattr(audit, "qualify_candidate", forbidden)
    monkeypatch.setattr(cli_module, "RejectionJournal", forbidden)
    result = CliRunner().invoke(app, ["scan", "--ci", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["findings"][0]["status"] == "detecte"


def test_terminal_direction_marks_are_escaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    finding = Finding(
        file="src/\u202eevil.py", line=1, type="aws", entropy=4.2, snippet_hash="b" * 64
    )
    RejectionJournal().append(finding, model="gemma3:270m")
    result = CliRunner().invoke(app, ["rejections", "--details"])
    assert result.exit_code == 0
    assert "\u202e" not in result.stdout
    assert r"\u202e" in result.stdout


@pytest.mark.parametrize("model", ["bad\nINJECTION", "", "x" * 65])
def test_model_metadata_is_closed(finding: Finding, journal: RejectionJournal, model: str) -> None:
    with pytest.raises(JournalError):
        journal.append(finding, model=model)
    assert not journal.path.exists()


@pytest.mark.skipif(os.name != "posix", reason="liens POSIX")
@pytest.mark.parametrize("target", ["journal", "parent", "lock", "hardlink"])
def test_link_targets_refused(tmp_path: Path, target: str) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    original = private / "original"
    original.write_bytes(b"KEEP_UNCHANGED")
    original.chmod(0o600)
    path = private / "audit.jsonl"
    if target == "parent":
        alias = tmp_path / "alias"
        alias.symlink_to(private, target_is_directory=True)
        path = alias / "audit.jsonl"
    elif target == "hardlink":
        os.link(original, path)
    else:
        (path if target == "journal" else path.with_suffix(".lock")).symlink_to(original)
    with pytest.raises(JournalError):
        RejectionJournal(path).read()
    assert original.read_bytes() == b"KEEP_UNCHANGED"


@pytest.mark.skipif(os.name != "posix", reason="permissions POSIX")
def test_private_permissions(finding: Finding, journal: RejectionJournal) -> None:
    journal.append(finding, model="gemma3:270m")
    assert journal.path.stat().st_mode & 0o777 == 0o600
    assert journal.path.parent.stat().st_mode & 0o777 == 0o700
    journal.path.chmod(0o644)
    with pytest.raises(JournalError):
        journal.read()
