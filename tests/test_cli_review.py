"""Preuves T32 avec valeurs entièrement synthétiques."""

from dataclasses import replace

import pytest

from heimdall.cli.review import Proposal, ReviewError, TextChange, render_diff
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
