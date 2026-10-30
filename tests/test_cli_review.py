"""Preuves T32 avec valeurs entièrement synthétiques."""

import io
import os
import stat
from collections.abc import Iterable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from support.fake_secrets import FAKE_GITHUB_TOKEN
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli import review as review_module
from heimdall.cli.main import app
from heimdall.cli.review import (
    _ENV_REFERENCE,
    DECISION_SCHEMA,
    EDIT_CANCELLED,
    INVALID_CHOICE,
    MASKED_MARKER,
    MAX_ANSWER_CHARS,
    MAX_CHANGES,
    MAX_PROMPTS,
    MAX_PROPOSALS,
    MAX_SECRETS,
    MAX_TEXT_CHARS,
    NON_INTERACTIVE,
    UNAPPLIED_TRACE,
    AskFn,
    Choice,
    Decision,
    DecisionJournal,
    Proposal,
    ReviewError,
    ReviewOutcome,
    ReviewReport,
    TextChange,
    _net,
    _stdin_ask,
    decision_journal_path,
    is_interactive,
    parse_choice,
    render_diff,
    review_proposal,
    review_proposals,
)
from heimdall.llm.rejections import GENESIS, JournalError, journal_digest, journal_encode
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


class _Tty:
    """Faux terminal : la boucle exige un TTY sûr, même en test."""

    def isatty(self) -> bool:
        return True


TTY = _Tty()


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
    outcome = review_proposal(proposal, ask=ask, apply=applied.append, journal=journal, stream=TTY)

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
    outcome = review_proposal(
        proposal,
        ask=ask,
        apply=_forbidden,
        edit=_forbidden,
        journal=journal,
        stream=TTY,
    )

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
        proposal,
        ask=ask,
        apply=applied.append,
        edit=lambda _p: edited,
        journal=journal,
        stream=TTY,
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
        stream=TTY,
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
            stream=TTY,
        )

    assert len(notices) == MAX_PROMPTS
    assert journal.read() == []


def test_validate_without_backend_is_refused(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, _prompts = _asker(["y"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, journal=journal, stream=TTY)

    # Refus avant journal : aucune trace d'une action impossible.
    assert journal.read() == []


def test_edit_without_backend_is_refused(proposal: Proposal, journal: DecisionJournal) -> None:
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, journal=journal, stream=TTY)

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
        stream=TTY,
    )

    assert outcome.action is Choice.IGNORE
    assert notices == [EDIT_CANCELLED]
    assert len(prompts) == 2
    assert [entry["action"] for entry in journal.read()] == ["e", "n"]


def test_edit_loop_is_bounded(proposal: Proposal, journal: DecisionJournal) -> None:
    with pytest.raises(ReviewError):
        review_proposal(
            proposal, ask=lambda _prompt: "e", edit=lambda p: p, journal=journal, stream=TTY
        )


def test_edit_returning_a_foreign_object_is_refused(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(
            proposal,
            ask=ask,
            edit=lambda _p: cast(Proposal, "nope"),
            journal=journal,
            stream=TTY,
        )


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
    stamp = "2026-01-01T00:00:00+00:00"
    for date in ("pas une date", "2026-01-01T00:00:00", "x" * 41):
        with pytest.raises(ReviewError):
            Decision(Choice.IGNORE, proposal.finding, date, False)
    with pytest.raises(ReviewError):
        Decision(cast(Choice, "y"), proposal.finding, stamp, False)
    with pytest.raises(ReviewError):
        Decision(Choice.IGNORE, cast(Finding, "nope"), stamp, False)
    with pytest.raises(ReviewError):
        Decision(Choice.IGNORE, proposal.finding, stamp, cast(bool, "yes"))
    # Un journal ne prétend jamais qu'une action autre que Y a été appliquée.
    with pytest.raises(ReviewError):
        Decision(Choice.IGNORE, proposal.finding, stamp, True)
    with pytest.raises(ReviewError):
        Decision(Choice.EDIT, proposal.finding, stamp, True)


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
        review_proposal(proposal, apply=lambda _p: None, journal=journal, stream=TTY)
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
        outcome = review_proposal(
            proposal, ask=ask, apply=lambda _p: None, journal=journal, stream=TTY
        )
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
        stream=TTY,
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


# --- Correctifs de revue : TTY, backend, masquage, grammaires, casse ---------


class _Pipe:
    """stdin pipé : pas de terminal, donc aucune validation possible."""

    def isatty(self) -> bool:
        return False


def test_explicit_interactive_does_not_bypass_a_pipe(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    report = review_proposals(
        (proposal,),
        interactive=True,
        ask=_forbidden,
        apply=_forbidden,
        edit=_forbidden,
        journal=journal,
        stream=_Pipe(),
    )

    assert report.interactive is False
    assert report.applied == 0
    assert report.remaining == 1
    assert journal.read() == []


def test_default_stream_without_tty_is_non_interactive(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    """Sous pytest, `sys.stdin` n'est pas un TTY : `interactive=True` ne suffit pas."""
    report = review_proposals(
        (proposal,), interactive=True, ask=_forbidden, apply=_forbidden, journal=journal
    )

    assert report.interactive is False
    assert journal.read() == []


def test_review_proposal_alone_also_requires_a_tty(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    outcome = review_proposal(
        proposal,
        ask=_forbidden,
        apply=_forbidden,
        journal=journal,
        interactive=True,
        stream=_Pipe(),
    )

    assert outcome.action is None
    assert outcome.applied is False
    assert journal.read() == []


def test_backend_failure_is_static_and_journal_is_truthful(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    def boom(_proposal: Proposal) -> None:
        raise RuntimeError("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    ask, _prompts = _asker(["y"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=ask, apply=boom, journal=journal, stream=TTY)

    message = str(excinfo.value)
    assert "SYNTHETIC_ONLY_VALUE" not in message
    assert "/etc/passwd" not in message
    assert excinfo.value.__cause__ is None
    entries = journal.read()
    assert [entry["action"] for entry in entries] == ["y"]
    assert entries[0]["applied"] is False
    assert "SYNTHETIC_ONLY_VALUE" not in journal.path.read_text(encoding="ascii")


def test_edit_failure_is_static_and_journal_is_truthful(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    def boom(_proposal: Proposal) -> Proposal | None:
        raise RuntimeError("échec SYNTHETIC_ONLY_VALUE")

    ask, _prompts = _asker(["e"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=ask, edit=boom, journal=journal, stream=TTY)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    entries = journal.read()
    assert [entry["action"] for entry in entries] == ["e"]
    assert entries[0]["applied"] is False


def test_validated_decision_is_journaled_as_applied(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    ask, _prompts = _asker(["y"])
    review_proposal(proposal, ask=ask, apply=lambda _p: None, journal=journal, stream=TTY)

    entries = journal.read()
    assert [(entry["action"], entry["applied"]) for entry in entries] == [("y", True)]


@pytest.mark.parametrize("error", [OSError("stdin fermé"), KeyboardInterrupt()])
def test_stdin_failures_become_static_errors(
    proposal: Proposal,
    journal: DecisionJournal,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    def broken(_prompt: str) -> str:
        raise error

    monkeypatch.setattr("builtins.input", broken)
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, apply=lambda _p: None, journal=journal, stream=TTY)

    assert "stdin fermé" not in str(excinfo.value)
    assert journal.read() == []


def test_is_interactive_treats_runtime_errors_as_no_tty() -> None:
    class Weird:
        def isatty(self) -> bool:
            raise RuntimeError("flux exotique")

    assert is_interactive(stream=Weird()) is False


def test_masking_pattern_is_bounded(proposal: Proposal) -> None:
    with pytest.raises(ReviewError):
        replace(proposal, secrets=("a" * 100_000, "b" * 100_000, "c" * 100_000))


def test_masking_supports_the_maximum_number_of_secrets(proposal: Proposal) -> None:
    secrets = tuple(f"{index:04d}" + "z" * 996 for index in range(MAX_SECRETS))
    changed = replace(
        proposal,
        secrets=secrets,
        changes=(TextChange("app.py", secrets[0], "safe"),),
    )

    diff = render_diff(changed)

    assert secrets[0] not in diff
    assert MASKED_MARKER in diff


@pytest.mark.parametrize("variable", ["_", "__", "A", "_A", "a" * 65])
def test_variable_grammar_matches_invariant_2(proposal: Proposal, variable: str) -> None:
    with pytest.raises(ReviewError):
        replace(proposal, variable=variable)


def test_env_reference_grammar_matches_the_variable_contract() -> None:
    assert _ENV_REFERENCE.fullmatch('os.getenv("APP_TOKEN")')
    assert _ENV_REFERENCE.fullmatch('os.environ["APP_TOKEN"]')
    assert _ENV_REFERENCE.fullmatch("process.env.APP_TOKEN")
    assert not _ENV_REFERENCE.fullmatch('os.getenv("_")')
    assert not _ENV_REFERENCE.fullmatch('os.getenv("A")')
    assert not _ENV_REFERENCE.fullmatch('os.getenv("_APP")')


@pytest.mark.parametrize(
    "file", [".Git/config", ".ENV", ".Env.local", "src/.GIT/config", "sub/.ENV.prod"]
)
def test_private_paths_are_rejected_case_insensitively(file: str) -> None:
    with pytest.raises(ReviewError):
        TextChange(file, "", "")


def test_env_example_is_allowed_in_any_case() -> None:
    assert TextChange(".ENV.EXAMPLE", "", "APP_TOKEN=\n").file == ".ENV.EXAMPLE"


def test_journal_rejects_an_inconsistent_applied_flag(tmp_path: Path) -> None:
    """Défense en profondeur : même avec un hash valide, `n` ne peut être appliqué."""
    path = tmp_path / "review-decisions.jsonl"
    entry = {
        "schema": DECISION_SCHEMA,
        "sequence": 1,
        "date": "2026-01-01T00:00:00+00:00",
        "action": "n",
        "applied": True,
        "file": "app.py",
        "line": 1,
        "snippet_hash": "0" * 64,
        "previous_hash": GENESIS,
    }
    path.write_bytes(journal_encode({**entry, "hash": journal_digest(entry)}) + b"\n")

    with pytest.raises(JournalError):
        DecisionJournal(path).read()


# --- Durcissements LOW sur les points d'injection (revue 2) -------------------


def test_injected_ask_failure_is_static(
    proposal: Proposal,
    journal: DecisionJournal,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken(_prompt: str) -> str:
        raise OSError("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=broken, apply=lambda _p: None, journal=journal, stream=TTY)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert "/etc/passwd" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""
    assert journal.read() == []


def test_injected_ask_review_error_is_preserved(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    def broken(_prompt: str) -> str:
        raise ReviewError

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=broken, apply=lambda _p: None, journal=journal, stream=TTY)

    assert journal.read() == []


def test_injected_notify_failure_never_leaks(
    proposal: Proposal,
    journal: DecisionJournal,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken_notify(_message: str) -> None:
        raise OSError("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    ask, _prompts = _asker(["x", "y"])
    outcome = review_proposal(
        proposal,
        ask=ask,
        apply=lambda _p: None,
        journal=journal,
        notify=broken_notify,
        stream=TTY,
    )

    assert outcome.applied is True
    assert capsys.readouterr().err == ""
    assert [entry["applied"] for entry in journal.read()] == [True]


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(1)])
def test_is_interactive_refuses_base_exceptions(error: BaseException) -> None:
    class Weird:
        def isatty(self) -> bool:
            raise error

    assert is_interactive(stream=Weird()) is False


@pytest.mark.parametrize("kind", ["relative", "parent"])
def test_journal_refuses_unsafe_state_paths(kind: str, proposal: Proposal, tmp_path: Path) -> None:
    """Garde `_prepare_path` réutilisée de T33 : chemin relatif ou `..` refusés."""
    path = Path("relative.jsonl") if kind == "relative" else tmp_path / "sub" / ".." / "j.jsonl"
    unsafe = DecisionJournal(path)
    decision = Decision.now(Choice.IGNORE, proposal.finding)

    with pytest.raises(JournalError):
        unsafe.append(decision)
    with pytest.raises(JournalError):
        unsafe.read()


def test_injected_ask_system_exit_is_static(
    proposal: Proposal,
    journal: DecisionJournal,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`SystemExit("<valeur>")` ferait imprimer son message sur stderr."""

    def broken(_prompt: str) -> str:
        raise SystemExit("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=broken, apply=lambda _p: None, journal=journal, stream=TTY)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert "/etc/passwd" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""
    assert journal.read() == []


# --- Durcissements LOW sur apply/edit/journal et borne de session (revue 4) ---


@pytest.mark.parametrize("error", [SystemExit("SYNTHETIC_ONLY_VALUE"), KeyboardInterrupt()])
def test_apply_base_exception_is_static_and_journaled(
    proposal: Proposal,
    journal: DecisionJournal,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
) -> None:
    def boom(_proposal: Proposal) -> None:
        raise error

    ask, _prompts = _asker(["y"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=ask, apply=boom, journal=journal, stream=TTY)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""
    entries = journal.read()
    assert [(entry["action"], entry["applied"]) for entry in entries] == [("y", False)]


@pytest.mark.parametrize("error", [SystemExit("SYNTHETIC_ONLY_VALUE"), KeyboardInterrupt()])
def test_edit_base_exception_is_static_and_journaled(
    proposal: Proposal,
    journal: DecisionJournal,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
) -> None:
    def boom(_proposal: Proposal) -> Proposal | None:
        raise error

    ask, _prompts = _asker(["e"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=ask, edit=boom, journal=journal, stream=TTY)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""
    assert [(entry["action"], entry["applied"]) for entry in journal.read()] == [("e", False)]


def test_injected_journal_failure_is_static(
    proposal: Proposal, capsys: pytest.CaptureFixture[str]
) -> None:
    class BrokenJournal:
        def append(self, _decision: object) -> None:
            raise OSError("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    ask, _prompts = _asker(["n"])
    with pytest.raises(JournalError) as excinfo:
        review_proposal(
            proposal,
            ask=ask,
            journal=cast(DecisionJournal, BrokenJournal()),
            stream=TTY,
        )

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert "/etc/passwd" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""


def test_injected_journal_without_append_is_static(proposal: Proposal) -> None:
    ask, _prompts = _asker(["n"])

    with pytest.raises(JournalError):
        review_proposal(proposal, ask=ask, journal=cast(DecisionJournal, object()), stream=TTY)


def test_review_proposals_is_bounded_and_lazy(proposal: Proposal, journal: DecisionJournal) -> None:
    consumed = 0

    def flood() -> Iterator[Proposal]:
        nonlocal consumed
        while True:
            consumed += 1
            yield proposal

    with pytest.raises(ReviewError):
        review_proposals(flood(), ci=True, journal=journal)

    # Consommation paresseuse : MAX_PROPOSALS + 1 au pire, jamais 100 000.
    assert consumed == MAX_PROPOSALS + 1
    assert journal.read() == []


def test_review_proposals_accepts_exactly_the_bound(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    report = review_proposals((proposal,) * MAX_PROPOSALS, ci=True, journal=journal)

    assert len(report.outcomes) == MAX_PROPOSALS
    assert report.remaining == MAX_PROPOSALS


@pytest.mark.parametrize("error", [JournalError(), ReviewError()])
def test_injected_journal_static_errors_are_preserved(proposal: Proposal, error: Exception) -> None:
    """Une erreur déjà statique n'est pas réemballée."""

    class BrokenJournal:
        def append(self, _decision: object) -> None:
            raise error

    ask, _prompts = _asker(["n"])
    with pytest.raises(type(error)):
        review_proposal(
            proposal, ask=ask, journal=cast(DecisionJournal, BrokenJournal()), stream=TTY
        )


# --- Durcissements LOW : environnement, producteur, rendu (revue 5) ----------


def test_journal_rejects_a_null_byte_path() -> None:
    """`Path` accepte un octet NUL ; la garde doit refuser avant tout I/O."""
    with pytest.raises(JournalError) as excinfo:
        DecisionJournal(Path("\x00/heimdall/review-decisions.jsonl"))
    assert excinfo.value.__cause__ is None


def test_journal_path_rejects_an_unavailable_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    def broken_home() -> Path:
        raise RuntimeError("HOME indisponible")

    monkeypatch.setattr(Path, "home", staticmethod(broken_home))
    with pytest.raises(JournalError):
        DecisionJournal()


def test_journal_rejects_a_non_path_argument(tmp_path: Path) -> None:
    with pytest.raises(JournalError):
        DecisionJournal(cast(Path, "relative.jsonl"))


def test_review_proposal_normalizes_a_broken_default_journal(
    proposal: Proposal, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_journal(_path: object = None) -> None:
        raise RuntimeError("HOME indisponible")

    monkeypatch.setattr(review_module, "DecisionJournal", broken_journal)
    ask, _prompts = _asker(["n"])

    with pytest.raises(JournalError) as excinfo:
        review_proposal(proposal, ask=ask, stream=TTY)
    assert excinfo.value.__cause__ is None


@pytest.mark.parametrize("proposals", [None, 123, object()])
def test_review_proposals_rejects_a_non_iterable(proposals: object) -> None:
    with pytest.raises(ReviewError):
        review_proposals(cast(Iterable[Proposal], proposals), ci=True)


def test_review_proposals_normalizes_a_failing_producer() -> None:
    def broken() -> Iterator[Proposal]:
        raise OSError("échec SYNTHETIC_ONLY_VALUE")
        yield  # pragma: no cover - jamais atteint

    with pytest.raises(ReviewError) as excinfo:
        review_proposals(broken(), ci=True)

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt()])
def test_render_failure_in_the_loop_is_static(
    proposal: Proposal,
    journal: DecisionJournal,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    def broken_mask(_text: str) -> tuple[str, int]:
        raise error

    monkeypatch.setattr(review_module, "mask_text", broken_mask)
    ask, _prompts = _asker(["y"])

    with pytest.raises(ReviewError) as excinfo:
        review_proposal(proposal, ask=ask, apply=lambda _p: None, journal=journal, stream=TTY)

    assert excinfo.value.__cause__ is None
    assert journal.read() == []


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt()])
def test_render_failure_in_the_report_is_static(
    proposal: Proposal, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    report = review_proposals((proposal,), ci=True)

    def broken_mask(_text: str) -> tuple[str, int]:
        raise error

    monkeypatch.setattr(review_module, "mask_text", broken_mask)
    with pytest.raises(ReviewError) as excinfo:
        report.render()

    assert excinfo.value.__cause__ is None


def test_review_proposal_preserves_a_static_journal_error(
    proposal: Proposal, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_journal(_path: object = None) -> None:
        raise JournalError

    monkeypatch.setattr(review_module, "DecisionJournal", broken_journal)
    ask, _prompts = _asker(["n"])

    with pytest.raises(JournalError):
        review_proposal(proposal, ask=ask, stream=TTY)


# --- Durcissements LOW : getattr, double faute, ordre, journal (revue 6) -----


def test_is_interactive_refuses_a_raising_getattr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Hostile:
        def __getattr__(self, _name: str) -> object:
            raise SystemExit("échec SYNTHETIC_ONLY_VALUE dans /etc/passwd")

    assert is_interactive(stream=Hostile()) is False
    assert capsys.readouterr().err == ""


def test_double_failure_has_no_exception_chain(
    proposal: Proposal, capsys: pytest.CaptureFixture[str]
) -> None:
    """Backend ET journal qui lèvent : erreur statique, aucune `__context__`."""

    class BrokenJournal:
        def append(self, _decision: object) -> None:
            raise OSError("journal SYNTHETIC_ONLY_VALUE")

    def boom(_proposal: Proposal) -> None:
        raise RuntimeError("backend SYNTHETIC_ONLY_VALUE /etc/passwd")

    ask, _prompts = _asker(["y"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(
            proposal,
            ask=ask,
            apply=boom,
            journal=cast(DecisionJournal, BrokenJournal()),
            stream=TTY,
        )

    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None
    assert capsys.readouterr().err == ""


def test_double_failure_on_edit_has_no_exception_chain(
    proposal: Proposal,
) -> None:
    class BrokenJournal:
        def append(self, _decision: object) -> None:
            raise OSError("journal SYNTHETIC_ONLY_VALUE")

    def boom(_proposal: Proposal) -> Proposal | None:
        raise RuntimeError("éditeur SYNTHETIC_ONLY_VALUE")

    ask, _prompts = _asker(["e"])
    with pytest.raises(ReviewError) as excinfo:
        review_proposal(
            proposal,
            ask=ask,
            edit=boom,
            journal=cast(DecisionJournal, BrokenJournal()),
            stream=TTY,
        )

    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None


def test_invalid_options_are_rejected_before_consuming_the_producer() -> None:
    consumed = 0

    def flood() -> Iterator[Proposal]:
        nonlocal consumed
        while True:
            consumed += 1
            yield cast(Proposal, None)

    with pytest.raises(ReviewError):
        review_proposals(flood(), ci=cast(bool, "yes"))
    assert consumed == 0

    with pytest.raises(ReviewError):
        review_proposals(flood(), interactive=cast(bool, "yes"))
    assert consumed == 0


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt()])
def test_journal_read_normalizes_base_exceptions(
    proposal: Proposal,
    journal: DecisionJournal,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    journal.append(Decision.now(Choice.IGNORE, proposal.finding))

    def broken_fstat(_descriptor: int) -> object:
        raise error

    monkeypatch.setattr("os.fstat", broken_fstat)
    with pytest.raises(JournalError) as excinfo:
        journal.read()
    assert excinfo.value.__cause__ is None


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt()])
def test_journal_append_normalizes_base_exceptions(
    proposal: Proposal,
    journal: DecisionJournal,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    def broken_fstat(_descriptor: int) -> object:
        raise error

    monkeypatch.setattr("os.fstat", broken_fstat)
    with pytest.raises(JournalError) as excinfo:
        journal.append(Decision.now(Choice.IGNORE, proposal.finding))
    assert excinfo.value.__cause__ is None


# --- Ré-ancrage de l'édition (revue 7) ---------------------------------------


def test_edit_cannot_change_the_finding(proposal: Proposal, journal: DecisionJournal) -> None:
    """Un éditeur bogué ne doit pas déplacer la proposition de périmètre."""
    # Même fichier (donc `Proposal` valide) mais autre ligne : périmètre déplacé.
    other = replace(proposal.finding, line=9, snippet_hash="1" * 64)
    edited = replace(proposal, finding=other)
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, edit=lambda _p: edited, journal=journal, stream=TTY)

    assert [(entry["action"], entry["applied"]) for entry in journal.read()] == [("e", False)]


def test_edit_cannot_drop_known_secrets(proposal: Proposal, journal: DecisionJournal) -> None:
    """Réduire `secrets` affaiblirait le masquage du ré-affichage."""
    edited = replace(proposal, secrets=("AUTRE_VALEUR",))
    ask, _prompts = _asker(["e"])

    with pytest.raises(ReviewError):
        review_proposal(proposal, ask=ask, edit=lambda _p: edited, journal=journal, stream=TTY)

    assert [(entry["action"], entry["applied"]) for entry in journal.read()] == [("e", False)]


def test_edit_may_add_known_secrets(proposal: Proposal, journal: DecisionJournal) -> None:
    """Ajouter une valeur connue reste permis : le masquage ne s'affaiblit pas."""
    edited = replace(proposal, secrets=(*proposal.secrets, "CONTEXTE_SECRET"))
    applied: list[Proposal] = []
    ask, _prompts = _asker(["e", "y"])

    outcome = review_proposal(
        proposal, ask=ask, apply=applied.append, edit=lambda _p: edited, journal=journal, stream=TTY
    )

    assert outcome.proposal is edited
    assert applied == [edited]
    assert [(entry["action"], entry["applied"]) for entry in journal.read()] == [
        ("e", False),
        ("y", True),
    ]


def test_maximal_proposal_renders_and_masks(proposal: Proposal) -> None:
    """Plafond de rendu : `MAX_CHANGES` textes dont un à `MAX_TEXT_CHARS`."""
    valeur = "SYNTHETIC_ONLY_VALUE"
    remplissage = "x" * (MAX_TEXT_CHARS - len(valeur) - 2)
    changes = [
        TextChange("fichier_0.py", f"{valeur}{remplissage}\n", f"{valeur}{remplissage}y\n"),
    ]
    changes.extend(
        TextChange(f"fichier_{index}.py", f"{valeur}\n", f"{valeur}y\n")
        for index in range(1, MAX_CHANGES)
    )
    maximal = replace(
        proposal,
        changes=tuple(changes),
        finding=replace(proposal.finding, file="fichier_0.py"),
    )

    diff = render_diff(maximal)

    assert valeur not in diff
    assert MASKED_MARKER in diff
    assert len(diff) <= 2 * MAX_TEXT_CHARS + 4096


# --- Durcissements LOW : marqueur, lecture bornée, journal (revue 8) ---------


def test_masked_marker_reveals_no_length(proposal: Proposal) -> None:
    """Le marqueur ne doit pas donner `len(valeur)` (oracle de longueur)."""
    court = replace(
        proposal,
        secrets=("A" * 8,),
        changes=(TextChange("app.py", "x = AAAAAAAA\n", "x = safe\n"),),
    )
    long = replace(
        proposal,
        secrets=("B" * 40,),
        changes=(TextChange("app.py", f"x = {'B' * 40}\n", "x = safe\n"),),
    )

    diff_court = render_diff(court)
    diff_long = render_diff(long)

    assert MASKED_MARKER in diff_court
    assert MASKED_MARKER in diff_long
    assert "<MASKED_8>" not in diff_court
    assert "<MASKED_40>" not in diff_long
    assert "A" * 8 not in diff_court
    assert "B" * 40 not in diff_long


def test_stdin_ask_reads_a_bounded_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un collage volumineux n'est pas matérialisé avant le refus."""
    limits: list[int] = []

    class FakeStdin:
        def readline(self, limit: int = -1) -> str:
            limits.append(limit)
            return "y" * (limit - 1) + "\n"

    class FakeStdout:
        def write(self, _text: str) -> int:
            return 0

        def flush(self) -> None:
            pass

    monkeypatch.setattr("sys.stdin", FakeStdin())
    monkeypatch.setattr("sys.stdout", FakeStdout())

    answer = _stdin_ask("prompt")

    assert limits == [MAX_ANSWER_CHARS + 2]
    assert len(answer) == MAX_ANSWER_CHARS + 2
    with pytest.raises(ReviewError):
        parse_choice(answer)


def test_stdin_ask_without_streams_is_static(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", None)
    with pytest.raises(ReviewError):
        _stdin_ask("prompt")


def test_stdin_ask_on_eof_is_static(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStdin:
        def readline(self, _limit: int = -1) -> str:
            return ""

    class FakeStdout:
        def write(self, _text: str) -> int:
            return 0

        def flush(self) -> None:
            pass

    monkeypatch.setattr("sys.stdin", FakeStdin())
    monkeypatch.setattr("sys.stdout", FakeStdout())
    with pytest.raises(ReviewError):
        _stdin_ask("prompt")


@pytest.mark.parametrize(
    "updates",
    [
        {"file": 123},
        {"file": "../evil"},
        {"line": "x"},
        {"line": 0},
        {"line": True},
        {"snippet_hash": "pas-un-hash"},
        {"snippet_hash": "A" * 64},
    ],
)
def test_journal_rejects_foreign_field_types(tmp_path: Path, updates: dict[str, object]) -> None:
    """Chaîne valide recalculée mais types arbitraires : refus statique."""
    path = tmp_path / "review-decisions.jsonl"
    entry: dict[str, object] = {
        "schema": DECISION_SCHEMA,
        "sequence": 1,
        "date": "2026-01-01T00:00:00+00:00",
        "action": "n",
        "applied": False,
        "file": "app.py",
        "line": 1,
        "snippet_hash": "0" * 64,
        "previous_hash": GENESIS,
    }
    entry.update(updates)
    path.write_bytes(journal_encode({**entry, "hash": journal_digest(entry)}) + b"\n")

    with pytest.raises(JournalError):
        DecisionJournal(path).read()


# --- Durcissements LOW : filet MCP, trace après apply, volume (revue 9) ------


def test_heuristic_net_uses_a_constant_marker(proposal: Proposal) -> None:
    """Un candidat heuristique hors `secrets` ne doit pas révéler type ni len."""
    heuristique = FAKE_GITHUB_TOKEN
    changed = replace(
        proposal,
        changes=(TextChange("app.py", f"token = {heuristique}\n", "token = safe\n"),),
    )

    diff = render_diff(changed)

    assert heuristique not in diff
    assert "len=" not in diff
    assert "<REDACTED:" not in diff
    assert MASKED_MARKER in diff


def test_apply_success_then_journal_failure_is_reported(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    """Patch appliqué mais journal en panne : trace signalée, erreur statique."""
    applied: list[Proposal] = []
    notices: list[str] = []

    class BrokenJournal:
        def append(self, _decision: object) -> None:
            raise OSError("disque plein SYNTHETIC_ONLY_VALUE")

    ask, _prompts = _asker(["y"])
    with pytest.raises(JournalError) as excinfo:
        review_proposal(
            proposal,
            ask=ask,
            apply=applied.append,
            journal=cast(DecisionJournal, BrokenJournal()),
            notify=notices.append,
            stream=TTY,
        )

    assert applied == [proposal]
    assert notices == [UNAPPLIED_TRACE]
    assert "SYNTHETIC_ONLY_VALUE" not in str(excinfo.value)
    assert excinfo.value.__context__ is None
    assert journal.read() == []


def test_session_volume_is_bounded(
    proposal: Proposal, journal: DecisionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(review_module, "MAX_SESSION_BYTES", 64)

    with pytest.raises(ReviewError):
        review_proposals((proposal,), ci=True, journal=journal)


def test_session_volume_accepts_a_normal_proposal(
    proposal: Proposal, journal: DecisionJournal
) -> None:
    report = review_proposals((proposal,), ci=True, journal=journal)

    assert len(report.outcomes) == 1


# --- Durcissements LOW : flux lu, filet large, octets, stderr (revue 10) -----


def test_ask_reads_the_same_stream_that_was_checked(
    proposal: Proposal, journal: DecisionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`stream` vérifié TTY mais `sys.stdin` pipé : on lit le flux vérifié."""

    class TtyStream:
        def __init__(self) -> None:
            self.reads = 0

        def isatty(self) -> bool:
            return True

        def readline(self, _limit: int = -1) -> str:
            self.reads += 1
            return "y\n"

    class Pipe:
        def isatty(self) -> bool:
            return False

        def readline(self, _limit: int = -1) -> str:
            pytest.fail("le pipe ne doit jamais être lu")

    tty = TtyStream()
    monkeypatch.setattr("sys.stdin", Pipe())
    monkeypatch.setattr("sys.stdout", io.StringIO())

    applied: list[Proposal] = []
    outcome = review_proposal(proposal, apply=applied.append, journal=journal, stream=tty)

    assert outcome.applied is True
    assert tty.reads == 1
    assert applied == [proposal]


@pytest.mark.parametrize(
    "marker",
    [
        "<REDACTED:github:len=40>",
        "<REDACTED:Type-X:len=12>",
        "<REDACTED:a.b:len=3>",
        "<REDACTED:>",
    ],
)
def test_net_rewrites_every_redaction_marker(marker: str) -> None:
    """Motif large : un type hors `[a-z_]` est réécrit comme les autres."""
    assert _net(f"avant {marker} après") == f"avant {MASKED_MARKER} après"


@pytest.mark.parametrize(
    "text",
    [
        "avant <REDACTED: après",  # marqueur non fermé
        "avant <REDACTED:url_password:len=8> après",  # imbriqué, non fermé
        "avant <REDACTED:<REDACTED:x:len=1>> après",  # imbriqué, non fermé
    ],
)
def test_net_refuses_an_unrecognized_marker(text: str) -> None:
    """Filet non reconnu : refus plutôt que réaffichage d'un type/longueur."""
    with pytest.raises(ReviewError):
        _net(text)


def test_session_volume_counts_utf8_bytes(
    proposal: Proposal, journal: DecisionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`é` = 2 octets : 200 caractères valent 400 octets, pas 200."""
    monkeypatch.setattr(review_module, "MAX_SESSION_BYTES", 300)
    non_ascii = replace(
        proposal,
        changes=(TextChange("app.py", "é" * 100, "é" * 100),),
        secrets=("é",),
    )

    with pytest.raises(ReviewError):
        review_proposals((non_ascii,), ci=True, journal=journal)


def test_stderr_notify_silences_base_exceptions(
    proposal: Proposal, journal: DecisionJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un `sys.stderr` levant `SystemExit("<valeur>")` ne doit rien laisser sortir."""

    class HostileStderr:
        def write(self, _text: str) -> int:
            raise SystemExit("SYNTHETIC_ONLY_VALUE /etc/passwd")

        def flush(self) -> None:
            raise SystemExit("SYNTHETIC_ONLY_VALUE /etc/passwd")

    ask, _prompts = _asker(["x", "y"])
    monkeypatch.setattr("sys.stderr", HostileStderr())
    outcome = review_proposal(proposal, ask=ask, apply=lambda _p: None, journal=journal, stream=TTY)

    assert outcome.applied is True
