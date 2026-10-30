"""Preuves T32 avec valeurs entièrement synthétiques."""

import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli.main import app
from heimdall.cli.review import (
    EDIT_CANCELLED,
    INVALID_CHOICE,
    MAX_PROMPTS,
    MAX_TEXT_CHARS,
    NON_INTERACTIVE,
    AskFn,
    Choice,
    Decision,
    DecisionJournal,
    Proposal,
    ReviewError,
    ReviewOutcome,
    ReviewReport,
    TextChange,
    decision_journal_path,
    is_interactive,
    parse_choice,
    render_diff,
    review_proposal,
    review_proposals,
)
from heimdall.llm.rejections import JournalError
from heimdall.scanner.finding import Finding


@pytest.fixture
def proposal() -> Proposal:
    return Proposal(
        finding=Finding(
            file="app.py",
            line=1,
            type="generic_secret",
            entropy=1.0,
            snippet_hash="0" * 64,
            status="detecte",
            source="regex",
        ),
        variable="APP_TOKEN",
        changes=(
            TextChange(
                "app.py", 'token = "SYNTHETIC_ONLY_VALUE"\n', 'token = os.getenv("APP_TOKEN")\n'
            ),
            TextChange(".env.example", "", "APP_TOKEN=\n"),
            TextChange(".gitignore", "", ".env\n"),
        ),
        secrets=("SYNTHETIC_ONLY_VALUE",),
    )


def test_masked_diff_includes_all_files(proposal: Proposal) -> None:
    diff = render_diff(proposal)
    assert "SYNTHETIC_ONLY_VALUE" not in diff
    assert "SYNTHETIC_ONLY_VALUE" not in repr(proposal)
    assert "SYNTHETIC_ONLY_VALUE" not in repr(proposal.changes[0])
    for expected in (
        "@@",
        "a/app.py",
        "b/app.py",
        "os.getenv",
        "APP_TOKEN",
        ".env.example",
        "+.env",
    ):
        assert expected in diff


def test_masks_context_and_terminal_controls(proposal: Proposal) -> None:
    changed = replace(
        proposal,
        changes=(
            TextChange(
                "app.py",
                "SYNTHETIC_ONLY_VALUE\n\x1b[2J\u202e\nold\n",
                "SYNTHETIC_ONLY_VALUE\n\x1b[2J\u202e\nnew\n",
            ),
        ),
    )
    diff = render_diff(changed)
    assert "SYNTHETIC_ONLY_VALUE" not in diff
    assert "\x1b" not in diff
    assert "\u202e" not in diff
    assert "\\x1b" in diff


@pytest.mark.parametrize(
    "file", ["../evil", "/outside/evil", "C:/evil", ".git/config", ".env", ".env.local"]
)
def test_rejects_unsafe_or_private_paths(file: str) -> None:
    with pytest.raises(ReviewError):
        TextChange(file, "", "")


@pytest.mark.parametrize("variable", ["", "hello world", "$(touch x)", "A\nY", "é", "a" * 65])
def test_rejects_invalid_variable(proposal: Proposal, variable: str) -> None:
    with pytest.raises(ReviewError):
        replace(proposal, variable=variable)


def test_rejects_incomplete_proposal(proposal: Proposal) -> None:
    for updates in ({"changes": ()}, {"secrets": ()}, {"changes": proposal.changes * 2}):
        with pytest.raises(ReviewError):
            replace(proposal, **updates)


def test_short_and_overlapping_secrets_are_fully_masked(proposal: Proposal) -> None:
    changed = replace(
        proposal, secrets=("a", "abc"), changes=(TextChange("app.py", "abc", "safe"),)
    )
    assert "abc" not in render_diff(changed)


# --- #88 / #89 / #90 : boucle Y/N/E, mode non interactif, tests du flux -------


def _asker(answers: list[str]) -> tuple[AskFn, list[str]]:
    """Simule le clavier (alternative documentée à ``CliRunner(input=...)``)."""
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return answers.pop(0)

    return ask, prompts


def _forbidden(*_args: object, **_kwargs: object) -> Any:
    pytest.fail("le mode non interactif ne doit toucher ni backend ni journal")


@pytest.fixture
def journal(tmp_path: Path) -> DecisionJournal:
    return DecisionJournal(tmp_path / "review-decisions.jsonl")


def test_validate_applies_after_journaling(proposal: Proposal, journal: DecisionJournal) -> None:
    applied: list[Proposal] = []
    ask, prompts = _asker(["y"])
    outcome = review_proposal(proposal, ask=ask, apply=applied.append, journal=journal)

    assert outcome.action is Choice.VALIDATE
    assert outcome.applied is True
    assert applied == [proposal]
    entries = journal.read()
    assert [entry["action"] for entry in entries] == ["y"]
    assert (entries[0]["file"], entries[0]["line"]) == ("app.py", 1)
    assert entries[0]["date"].endswith("+00:00")
    # Le prompt affiché est le diff masqué, jamais la valeur.
    assert "SYNTHETIC_ONLY_VALUE" not in prompts[0]
    assert "os.getenv" in prompts[0]
    assert journal.path.read_text(encoding="ascii").find("SYNTHETIC_ONLY_VALUE") == -1


def test_ignore_never_calls_the_backend(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, _prompts = _asker(["n"])
    outcome = review_proposal(proposal, ask=ask, apply=_forbidden, edit=_forbidden, journal=journal)

    assert outcome.action is Choice.IGNORE
    assert outcome.applied is False
    assert [entry["action"] for entry in journal.read()] == ["n"]


def test_edit_redisplays_the_diff_then_validates(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    edited = replace(proposal, variable="APP_SECRET")
    applied: list[Proposal] = []
    ask, prompts = _asker(["e", "y"])

    outcome = review_proposal(
        proposal, ask=ask, apply=applied.append, edit=lambda _p: edited, journal=journal
    )

    assert outcome.proposal is edited
    assert outcome.edits == 1
    assert applied == [edited]
    assert [entry["action"] for entry in journal.read()] == ["e", "y"]
    assert len(prompts) == 2
    assert "APP_SECRET" in prompts[1]


def test_invalid_answer_is_asked_again(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, prompts = _asker(["", "x", "Y"])
    notices: list[str] = []

    outcome = review_proposal(
        proposal,
        ask=ask,
        apply=lambda _p: None,
        journal=journal,
        notify=notices.append,
    )

    assert outcome.action is Choice.VALIDATE
    assert notices == [INVALID_CHOICE, INVALID_CHOICE]
    assert len(prompts) == 3
    assert [entry["action"] for entry in journal.read()] == ["y"]


def test_invalid_answers_exhaust_the_loop(proposal: Proposal, journal: DecisionJournal) -> None:
    notices: list[str] = []

    with pytest.raises(ReviewError):
        review_proposal(
            proposal,
            ask=lambda _prompt: "?",
            apply=lambda _p: None,
            journal=journal,
            notify=notices.append,
        )

    assert len(notices) == MAX_PROMPTS
    assert journal.read() == []


def test_validate_without_backend_is_refused(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, _prompts = _asker(["y"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, journal=journal)

    # Refus avant journal : aucune trace d'une action impossible.
    assert journal.read() == []


def test_edit_without_backend_is_refused(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, journal=journal)

    assert journal.read() == []


def test_cancelled_edit_asks_again(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, prompts = _asker(["e", "n"])
    notices: list[str] = []

    outcome = review_proposal(
        proposal,
        ask=ask,
        edit=lambda _p: None,
        journal=journal,
        notify=notices.append,
    )

    assert outcome.action is Choice.IGNORE
    assert notices == [EDIT_CANCELLED]
    assert len(prompts) == 2
    assert [entry["action"] for entry in journal.read()] == ["e", "n"]


def test_edit_loop_is_bounded(proposal: Proposal, journal: DecisionJournal) -> None:
    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=lambda _prompt: "e", edit=lambda p: p, journal=journal)


def test_edit_returning_a_foreign_object_is_refused(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, edit=lambda _p: cast(Proposal, "nope"), journal=journal)


def test_non_interactive_never_writes(proposal: Proposal, journal: DecisionJournal) -> None:
    outcome = review_proposal(
        proposal,
        interactive=False,
        ask=_forbidden,
        apply=_forbidden,
        edit=_forbidden,
        journal=journal,
        notify=_forbidden,
    )

    assert outcome.action is None
    assert outcome.applied is False
    assert journal.read() == []
    assert not journal.path.exists()


def test_ci_forces_non_interactive_even_if_requested(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    report = review_proposals(
        (proposal,),
        ci=True,
        interactive=True,
        ask=_forbidden,
        apply=_forbidden,
        edit=_forbidden,
        journal=journal,
    )

    assert report.interactive is False
    assert report.applied == 0
    assert report.remaining == 1
    assert journal.read() == []


def test_is_interactive_refuses_any_doubt() -> None:
    class Stream:
        def __init__(self, value: bool) -> None:
            self.value = value

        def isatty(self) -> bool:
            return self.value

    class Broken:
        def isatty(self) -> bool:
            raise OSError("terminal indisponible")

    assert is_interactive(stream=Stream(True)) is True
    assert is_interactive(stream=Stream(False)) is False
    assert is_interactive(ci=True, stream=Stream(True)) is False
    assert is_interactive(stream=object()) is False
    assert is_interactive(stream=Broken()) is False


def test_report_render_masks_and_counts(proposal: Proposal, journal: DecisionJournal) -> None:
    report = review_proposals((proposal,), ci=True, journal=journal)
    text = report.render()

    assert "SYNTHETIC_ONLY_VALUE" not in text
    assert NON_INTERACTIVE in text
    assert "1 proposition(s), 0 appliquée(s), 1 restante(s)." in text
    assert "non validée (aucune écriture)" in text


def test_journal_detects_tampering(proposal: Proposal, journal: DecisionJournal) -> None:
    journal.append(Decision.now(Choice.IGNORE, proposal.finding))
    journal.append(Decision.now(Choice.VALIDATE, proposal.finding))
    assert len(journal.read()) == 2

    tampered = journal.path.read_text(encoding="ascii").replace('"action": "y"', '"action": "n"')
    journal.path.write_text(tampered, encoding="ascii")

    with pytest.raises(JournalError):
        journal.read()


@pytest.mark.skipif(os.name != "posix", reason="permissions POSIX uniquement")
def test_journal_is_private(proposal: Proposal, journal: DecisionJournal) -> None:
    journal.append(Decision.now(Choice.IGNORE, proposal.finding))
    assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600


@pytest.mark.parametrize("answer", ["y", "Y", " y ", "yes", "o", "oui"])
def test_parse_choice_accepts_documented_answers(answer: str) -> None:
    assert parse_choice(answer) is Choice.VALIDATE


@pytest.mark.parametrize("answer", ["n", "N", "no", "non"])
def test_parse_choice_accepts_ignore(answer: str) -> None:
    assert parse_choice(answer) is Choice.IGNORE


@pytest.mark.parametrize("answer", ["e", "E", "edit"])
def test_parse_choice_accepts_edit(answer: str) -> None:
    assert parse_choice(answer) is Choice.EDIT


@pytest.mark.parametrize("answer", ["", " ", "x", "yy", "y" * 17, None, 1])
def test_parse_choice_rejects_everything_else(answer: object) -> None:
    with pytest.raises(ReviewError):
        parse_choice(answer)


def test_scan_ci_writes_nothing_in_the_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#89 : preuve demandée — ``git status`` propre après ``scan --ci``."""
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "00" * 32)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)
    repo = GitRepo("heimdall-t32-")
    try:
        (repo.root / "app.py").write_text('AWS = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        repo.git("add", "app.py")
        repo.git("commit", "-m", "exemple public AWS, non fonctionnel")
        assert repo.git_output("status", "--porcelain") == ""

        result = CliRunner().invoke(app, ["scan", "--ci", str(repo.root)])

        assert result.exit_code == 1
        assert repo.git_output("status", "--porcelain") == ""
        assert not (repo.root / ".env").exists()
        assert not (repo.root / ".env.example").exists()
        assert not (repo.root / ".gitignore").exists()
    finally:
        repo.close()


def test_invalid_proposal_is_refused(proposal: Proposal) -> None:
    with pytest.raises(ReviewError):
        review_proposal(cast(Proposal, "nope"))
    with pytest.raises(ReviewError):
        review_proposal(proposal, interactive=cast(bool, "yes"))


def test_review_proposals_rejects_foreign_items() -> None:
    with pytest.raises(ReviewError):
        review_proposals((cast(Proposal, "nope"),))
    with pytest.raises(ReviewError):
        review_proposals((), ci=cast(bool, "yes"))
    with pytest.raises(ReviewError):
        review_proposals((), interactive=cast(bool, "yes"))


def test_is_interactive_rejects_a_non_boolean_ci() -> None:
    with pytest.raises(ReviewError):
        is_interactive(ci=cast(bool, "yes"))


def test_decision_rejects_invalid_metadata(proposal: Proposal) -> None:
    for date in ("pas une date", "2026-01-01T00:00:00", "x" * 41):
        with pytest.raises(ReviewError):
            Decision(Choice.IGNORE, proposal.finding, date)
    with pytest.raises(ReviewError):
        Decision(cast(Choice, "y"), proposal.finding, "2026-01-01T00:00:00+00:00")
    with pytest.raises(ReviewError):
        Decision(Choice.IGNORE, cast(Finding, "nope"), "2026-01-01T00:00:00+00:00")


def test_decision_journal_path_follows_xdg_state_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert decision_journal_path() == tmp_path / "heimdall" / "review-decisions.jsonl"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert decision_journal_path().name == "review-decisions.jsonl"
    assert decision_journal_path().parent.name == "heimdall"


@pytest.mark.parametrize("payload", ["[]\n", '{"schema": "autre"}\n', "pas du json\n"])
def test_journal_rejects_foreign_entries(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "review-decisions.jsonl"
    path.write_text(payload, encoding="ascii")
    with pytest.raises(JournalError):
        DecisionJournal(path).read()


def test_journal_append_rejects_a_foreign_object(journal: DecisionJournal) -> None:
    with pytest.raises(JournalError):
        journal.append(cast(Decision, "nope"))


def test_ask_eof_aborts_without_journal(
    proposal: Proposal, journal: DecisionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_input(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", broken_input)
    with pytest.raises(ReviewError):
        review_proposal(proposal, apply=lambda _p: None, journal=journal)
    assert journal.read() == []


def test_broken_stderr_never_breaks_the_loop(proposal: Proposal, journal: DecisionJournal) -> None:
    class BrokenStderr:
        def write(self, _text: str) -> int:
            raise OSError("canal fermé")

        def flush(self) -> None:
            raise OSError("canal fermé")

    ask, _prompts = _asker(["x", "y"])
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("sys.stderr", BrokenStderr())
        outcome = review_proposal(proposal, ask=ask, apply=lambda _p: None, journal=journal)
    assert outcome.applied is True


def test_outcome_and_status_cover_every_action(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    report = review_proposals(
        (proposal, proposal),
        interactive=True,
        ask=_asker(["n", "y"])[0],
        apply=lambda _p: None,
        journal=journal,
    )
    statuses = report.render()
    assert "ignorée par l'opérateur" in statuses
    assert "validée et appliquée" in statuses
    assert report.applied == 1
    assert report.remaining == 1
    assert report.outcomes[0].as_dict()["action"] == "n"
    assert report.outcomes[1].as_dict()["applied"] is True


def test_text_change_is_bounded() -> None:
    with pytest.raises(ReviewError):
        TextChange("app.py", "x" * (MAX_TEXT_CHARS + 1), "")


def test_status_reports_an_unconfirmed_application(proposal: Proposal) -> None:
    outcome = ReviewOutcome(Choice.VALIDATE, False, 0, proposal)
    assert "application non confirmée" in ReviewReport((outcome,), True).render()
