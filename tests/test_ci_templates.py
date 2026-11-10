"""Statique : les modèles CI de ``docs/ci/`` gardent les gardes de #37."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
CI = REPO / "docs" / "ci"


def _load(name: str) -> dict[str, Any]:
    document = yaml.safe_load((CI / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _joined_runs(job: dict[str, Any]) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_github_template_fetches_full_history_and_scans_the_diff() -> None:
    document = _load("github-actions.yml")
    job = document["jobs"]["heimdall"]
    checkout = job["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0
    script = _joined_runs(job)
    assert "--ci" in script
    assert "--diff" in script
    assert "origin/$BASE_REF" in script
    assert "--no-allowlist" in script
    assert "${{" not in script
    scan_step = job["steps"][-1]
    assert scan_step["env"]["BASE_REF"] == "${{ github.base_ref }}"
    assert document["permissions"] == {"contents": "read"}
    # PyYAML 1.1 lit la clé `on` comme le booléen True.
    triggers = document.get(True, document.get("on"))
    assert triggers == {"pull_request": None}


def test_gitlab_template_fetches_full_history_and_scans_the_diff() -> None:
    document = _load("gitlab-ci.yml")
    job = document["heimdall"]
    assert job["variables"]["GIT_DEPTH"] == "0"
    script = "\n".join(job["script"])
    assert "--ci" in script
    assert "--diff" in script
    assert "CI_MERGE_REQUEST_TARGET_BRANCH_NAME" in script
    assert 'git fetch --no-tags origin -- "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"' in script
    assert "--no-allowlist" in script
    assert "> heimdall-scan.json; code=$?; cat heimdall-scan.json; exit $code" in script
    assert "| tee" not in script
    assert "set -o pipefail" not in script
    assert job["artifacts"]["when"] == "always"
