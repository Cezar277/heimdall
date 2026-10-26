"""Entonnoir T38 : dépôts jetables et modèle simulé, jamais de vrai secret."""

import json
import shutil
import time
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner

import heimdall.cli.cold_start as cold_module
import heimdall.cli.main as main_module
from heimdall.cli.cold_start import (
    MAX_QUALIFICATION_SECONDS,
    MAX_QUALIFICATIONS,
    collect_cold_start,
    qualify_target,
    render_cold_start,
)
from heimdall.cli.main import app
from heimdall.llm.rejections import JournalError, RejectionJournal
from heimdall.mcp.paths import PathEscape
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.interface import FileTarget, Scanner
from heimdall.scanner.signature_engine import SignatureEngine

# Valeur d'exemple publique, explicitement factice, déjà utilisée par le corpus.
SYNTHETIC = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize("limit", [0, -1, True, 1_048_577])
def test_invalid_file_limit_is_static(tmp_path: Path, limit: int) -> None:
    with pytest.raises(ScanError, match="limite de fichier invalide"):
        collect_cold_start(tmp_path, max_file_bytes=limit)


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> Iterator[GitRepo]:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "01" * 32)
    value = GitRepo("heimdall-t38-")
    try:
        yield value
    finally:
        value.close()


def test_llm_only_sees_masked_candidates(repo: GitRepo) -> None:
    repo.write("app.py", "# safe\n" * 1000 + f'key = "{SYNTHETIC}"\n' + "# safe\n" * 1000)
    calls: list[str] = []

    def chat(**kwargs: Any) -> SimpleNamespace:
        calls.append(json.dumps(kwargs))
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"secret","confidence":1}')
        )

    report = collect_cold_start(repo.root, chat=chat)
    assert len(calls) == len(report.scan.findings) == 1
    assert SYNTHETIC not in calls[0]
    assert "1001:" in calls[0]
    assert "995:" not in calls[0]
    assert "1007:" not in calls[0]
    assert len(report.opinions) == 1
    assert SYNTHETIC not in render_cold_start(report, json_output=True)


def test_clean_repo_never_calls_llm(repo: GitRepo) -> None:
    repo.write("app.py", "print('hello')\n" * 100)

    def forbidden(**kwargs: Any) -> None:
        pytest.fail("aucun candidat, aucun appel LLM")

    assert collect_cold_start(repo.root, chat=forbidden).opinions == ()


def test_false_positive_is_kept_and_journaled(repo: GitRepo, tmp_path: Path) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')
    journal = RejectionJournal(tmp_path / "private" / "rejections.jsonl")

    def chat(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"faux_positif","confidence":1}')
        )

    report = collect_cold_start(repo.root, chat=chat, journal=journal)
    assert len(report.scan.findings) == 1
    assert report.opinions[0].qualification.verdict == "faux_positif"
    assert len(journal.read()) == 1


def test_ci_does_not_call_model_or_write_journal(repo: GitRepo, tmp_path: Path) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')
    journal_file = tmp_path / "private" / "rejections.jsonl"

    def forbidden(**kwargs: Any) -> None:
        pytest.fail("modèle interdit en CI")

    report = collect_cold_start(
        repo.root, ci=True, chat=forbidden, journal=RejectionJournal(journal_file)
    )
    assert len(report.scan.findings) == 1
    assert report.opinions == ()
    assert not journal_file.parent.exists()
    result = CliRunner().invoke(app, ["cold-start", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["opinions"] == []


def test_unavailable_model_retains_finding(repo: GitRepo) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')

    def unavailable(**kwargs: Any) -> None:
        raise RuntimeError(SYNTHETIC)

    report = collect_cold_start(repo.root, chat=unavailable)
    assert len(report.scan.findings) == 1
    assert report.opinions[0].qualification.verdict is None
    assert SYNTHETIC not in render_cold_start(report)


def _secret_chat(**kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(message=SimpleNamespace(content='{"verdict":"secret","confidence":1}'))


def test_qualification_limit_refuses_before_any_model_call(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n' * (MAX_QUALIFICATIONS + 1))

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("plafond dépassé : aucun appel LLM")

    monkeypatch.setattr(cold_module, "qualify_finding", forbidden)
    with pytest.raises(ScanError, match="trop de candidats"):
        collect_cold_start(repo.root)
    result = CliRunner().invoke(app, ["cold-start", str(repo.root)])
    assert result.exit_code == 2
    assert SYNTHETIC not in result.output


def test_qualification_limit_inclusive(repo: GitRepo) -> None:
    text = f'key = "{SYNTHETIC}"\n' * MAX_QUALIFICATIONS
    repo.write("app.py", text)
    report = collect_cold_start(repo.root, chat=_secret_chat)
    assert len(report.opinions) == MAX_QUALIFICATIONS
    target = FileTarget("app.py", text)
    with pytest.raises(ScanError, match="trop de candidats"):
        qualify_target(target, list(report.scan.findings) + [report.scan.findings[0]])


@pytest.mark.parametrize("mutation", ["removed", "binary", "undecodable", "unreadable"])
def test_content_mutation_refuses_api_and_cli(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    original = cold_module.collect

    def mutate(*args: Any, **kwargs: Any) -> Any:
        report = original(*args, **kwargs)
        if mutation == "removed":
            repo.write("app.py", "# candidate removed\n")
        elif mutation == "binary":
            repo.write_bytes("app.py", b"\x89PNG\r\n\x1a\n" + b"\x00\xff" * 100)
        elif mutation == "undecodable":
            repo.write_bytes("app.py", b"\x00" + SYNTHETIC.encode() + b"\n#")
        else:
            monkeypatch.setattr(cold_module, "_read_worktree_file", lambda *args, **kwargs: None)
        return report

    monkeypatch.setattr(cold_module, "collect", mutate)
    for cli in (False, True):
        repo.write("app.py", f'key = "{SYNTHETIC}"\n')
        if cli:
            result = CliRunner().invoke(app, ["cold-start", str(repo.root)])
            assert result.exit_code == 2
            assert SYNTHETIC not in result.output
        else:
            with pytest.raises(ScanError, match="^contenu modifié depuis le scan déterministe$"):
                collect_cold_start(repo.root, chat=_secret_chat)


def test_reread_respects_configured_size_limit(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = cold_module.collect

    def grow_after_scan(*args: Any, **kwargs: Any) -> Any:
        report = original(*args, **kwargs)
        repo.write("app.py", SYNTHETIC + "\n#" + " " * 64)
        return report

    def forbidden(**kwargs: Any) -> None:
        pytest.fail("file over configured limit must not reach LLM")

    monkeypatch.setattr(cold_module, "collect", grow_after_scan)
    repo.write("app.py", SYNTHETIC + "\n")
    with pytest.raises(ScanError, match="contenu modifié"):
        collect_cold_start(repo.root, max_file_bytes=32, chat=forbidden)
    repo.write("app.py", SYNTHETIC + "\n")
    result = CliRunner().invoke(app, ["cold-start", str(repo.root), "--max-file-bytes", "32"])
    assert result.exit_code == 2
    assert SYNTHETIC not in result.output


def test_broken_journal_refuses_api_and_cli(
    repo: GitRepo,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    journal = RejectionJournal(blocked / "rejections.jsonl")

    def false_positive(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"faux_positif","confidence":1}')
        )

    collect = partial(collect_cold_start, chat=false_positive, journal=journal)
    with pytest.raises(JournalError):
        collect(repo.root)
    monkeypatch.setattr(main_module, "collect_cold_start", collect)
    result = CliRunner().invoke(app, ["cold-start", str(repo.root)])
    assert result.exit_code == 2
    assert SYNTHETIC not in result.output


def test_explicit_ci_llm_never_qualifies_or_journals(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("modèle et journal interdits en CI")

    monkeypatch.setattr(cold_module, "qualify_finding", forbidden)
    monkeypatch.setattr(RejectionJournal, "append", forbidden)
    result = CliRunner().invoke(app, ["cold-start", str(repo.root), "--ci", "--llm", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["opinions"] == []
    assert SYNTHETIC not in result.output


def test_deadline_stops_between_candidates_in_same_file(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n' * 2)
    clock = SimpleNamespace(now=time.monotonic())
    monkeypatch.setattr(cold_module, "time", SimpleNamespace(monotonic=lambda: clock.now))
    calls = 0

    def slow_chat(**kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        clock.now += MAX_QUALIFICATION_SECONDS
        return _secret_chat()

    with pytest.raises(ScanError, match="limite de temps"):
        collect_cold_start(repo.root, chat=slow_chat)
    assert calls == 1


def test_deadline_expired_before_first_candidate(repo: GitRepo) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')
    report = collect_cold_start(repo.root, llm=False)
    with pytest.raises(ScanError, match="limite de temps"):
        qualify_target(
            FileTarget("app.py", f'key = "{SYNTHETIC}"\n'),
            list(report.scan.findings),
            chat=_secret_chat,
            deadline=time.monotonic() - 1,
        )


@pytest.mark.parametrize("phase", ["after_collect", "during_qualification"])
def test_root_substitution_with_identical_content_is_refused(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')

    def swap_root() -> None:
        old = repo.root.with_name("old-root")
        repo.root.rename(old)
        shutil.copytree(old, repo.root)

    original = cold_module.collect

    def collect_then_swap(*args: Any, **kwargs: Any) -> Any:
        report = original(*args, **kwargs)
        swap_root()
        return report

    def chat(**kwargs: Any) -> SimpleNamespace:
        if phase == "during_qualification":
            swap_root()
        return _secret_chat()

    if phase == "after_collect":
        monkeypatch.setattr(cold_module, "collect", collect_then_swap)
    with pytest.raises(ScanError):
        collect_cold_start(repo.root, chat=chat)


def test_path_escape_becomes_static_scan_error(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("app.py", f'key = "{SYNTHETIC}"\n')

    def escape(*args: Any, **kwargs: Any) -> None:
        raise PathEscape(SYNTHETIC)

    monkeypatch.setattr(cold_module, "confine", escape)
    with pytest.raises(ScanError, match="hors périmètre") as error:
        collect_cold_start(repo.root, chat=_secret_chat)
    assert SYNTHETIC not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("value", [SYNTHETIC, "aB3dE5fG7hI9jK1mN2pQ4rS6tU8vW0xY"])
def test_default_engines_share_entropy_and_hmac(repo: GitRepo, value: str) -> None:
    text = f'key = "{value}"\n'
    repo.write("app.py", text)
    tree = TreeScanner(repo.root, strict=True).scan()
    target = Scanner(SignatureEngine()).scan(FileTarget("app.py", text))
    assert tree
    assert tree == target
