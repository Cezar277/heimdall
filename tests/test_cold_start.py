"""Entonnoir T38 : dépôts jetables et modèle simulé, jamais de vrai secret."""

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli.cold_start import collect_cold_start, render_cold_start
from heimdall.cli.main import app
from heimdall.llm.rejections import RejectionJournal

# Valeur d'exemple publique, explicitement factice, déjà utilisée par le corpus.
SYNTHETIC = "AKIAIOSFODNN7EXAMPLE"


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
