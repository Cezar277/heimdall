"""Mode CI différentiel ``heimdall scan --ci --diff REF`` (#37).

Le périmètre est ``merge-base(REF, HEAD)...HEAD`` (trois points) : seuls les
blobs ajoutés ou modifiés par la branche courante sont scannés. Les tests
couvrent le verdict (0/1/2), l'absence de fuite, le JSON, les bornes, le
clone superficiel et les gardes de référence/TOCTOU.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GIT, GitRepo
from typer.testing import CliRunner

import heimdall.cli.scan as scan_module
from heimdall.cli.main import app
from heimdall.cli.scan import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    JSON_SCHEMA,
    collect,
)
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner.errors import ScanError

#: Exemple officiel de la documentation AWS : jamais une clé fonctionnelle.
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
#: Clé HMAC locale de test : empreintes déterministes, aucun fichier créé.
TEST_HMAC_KEY = "00" * 32
#: Libellé unique du code 2 (invariant 8 : aucune entrée reflétée).
SCAN_ERROR_MESSAGE = "heimdall scan : scan impossible (erreur d'outillage)."


@pytest.fixture(autouse=True)
def _cle_hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.delenv("HEIMDALL_SNIPPET_HMAC_KEY_FILE", raising=False)


@pytest.fixture
def git_repo() -> Iterator[GitRepo]:
    repo = GitRepo("heimdall-t37-")
    try:
        yield repo
    finally:
        repo.close()


def _run(*arguments: str) -> object:
    return CliRunner().invoke(app, list(arguments))


def _base_and_feature(repo: GitRepo) -> None:
    """Crée ``main`` (base), ``origin/main`` puis la branche ``feature``."""
    repo.write("app.py", "x = 1\n")
    repo.commit_all("base")
    repo.git("branch", "-M", "main")
    repo.git("update-ref", "refs/remotes/origin/main", "main")
    repo.git("checkout", "-q", "-b", "feature")


def _commit(repo: GitRepo, message: str) -> None:
    repo.commit_all(message)


# --- résolution de référence et plage de commits ---------------------------


def test_resolve_commit_returns_a_full_sha(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    access = GitAccess(git_repo.root)
    sha = access.resolve_commit("origin/main")
    assert len(sha) == 40
    assert set(sha) <= set("0123456789abcdef")
    assert access.resolve_commit("HEAD") == sha


def test_resolve_commit_accepts_at_as_head(git_repo: GitRepo) -> None:
    """``@`` seul est l'alias git de ``HEAD`` (accepté, pas une option)."""
    _base_and_feature(git_repo)
    access = GitAccess(git_repo.root)
    assert access.resolve_commit("@") == access.resolve_commit("HEAD")


def test_resolve_commit_refuses_an_overlong_ref(git_repo: GitRepo) -> None:
    """Une référence géante est refusée avant de devenir un argv démesuré."""
    _base_and_feature(git_repo)
    access = GitAccess(git_repo.root)
    with pytest.raises(ToolFailure):
        access.resolve_commit("a" * 257)


def test_resolve_commit_refuses_an_unknown_ref(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    access = GitAccess(git_repo.root)
    with pytest.raises(ToolFailure):
        access.resolve_commit("absente")


@pytest.mark.parametrize(
    "ref",
    [
        "-x",
        "--help",
        "a..b",
        "a@{1}",
        "a b",
        "a//b",
        ".hidden",
        "a.lock",
        "a~1",
        "a^",
        "a:b",
        "a?",
        "a*",
        "a[",
        "a\\b",
        "a/./b",
        "a/.hidden",
    ],
)
def test_resolve_commit_refuses_option_like_refs(git_repo: GitRepo, ref: str) -> None:
    _base_and_feature(git_repo)
    access = GitAccess(git_repo.root)
    with pytest.raises(ToolFailure):
        access.resolve_commit(ref)


def test_diff_changes_uses_three_dots(git_repo: GitRepo) -> None:
    """Un secret de la branche cible, absent de la branche courante, n'est pas scanné."""
    _base_and_feature(git_repo)
    git_repo.git("checkout", "-q", "main")
    git_repo.write("main-only.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "main advance")
    git_repo.git("update-ref", "refs/remotes/origin/main", "main")
    git_repo.git("checkout", "-q", "feature")
    git_repo.write("feature-only.py", "x = 2\n")
    _commit(git_repo, "feature")

    access = GitAccess(git_repo.root)
    base = access.resolve_commit("origin/main")
    head = access.resolve_commit("HEAD")
    changes = access.diff_changes(base, head)

    assert [change.path for change in changes] == ["feature-only.py"]


def test_diff_changes_ignores_deleted_files(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("old.py", "x = 1\n")
    _commit(git_repo, "add old")
    git_repo.git("update-ref", "refs/remotes/origin/main", "feature")
    git_repo.git("checkout", "-q", "-b", "delete", "feature")
    git_repo.git("rm", "-q", "old.py")
    _commit(git_repo, "delete old")

    access = GitAccess(git_repo.root)
    base = access.resolve_commit("feature")
    head = access.resolve_commit("HEAD")
    assert access.diff_changes(base, head) == []


def test_diff_changes_refuses_a_missing_merge_base(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("feature.py", "x = 2\n")
    _commit(git_repo, "feature")
    git_repo.git("checkout", "-q", "--orphan", "orphan")
    git_repo.git("rm", "-rf", ".")
    git_repo.write("orphan.py", "y = 3\n")
    _commit(git_repo, "orphan")

    access = GitAccess(git_repo.root)
    base = access.resolve_commit("feature")
    head = access.resolve_commit("HEAD")
    with pytest.raises(ToolFailure):
        access.diff_changes(base, head)


# --- verdict CLI -----------------------------------------------------------


def test_scan_diff_detects_a_secret_added_on_the_branch(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("new.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "feature")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_FINDINGS
    assert "new.py:1" in result.stdout
    assert FAKE_AWS_KEY not in result.stdout
    assert FAKE_AWS_KEY not in result.stderr


def test_scan_diff_clean_branch_exits_zero(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("new.py", "x = 2\n")
    _commit(git_repo, "feature")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_CLEAN
    assert "Aucun secret détecté" in result.stdout
    assert "1 fichier(s) analysé(s)" in result.stderr


def test_scan_diff_empty_range_reports_zero_files(git_repo: GitRepo) -> None:
    """``--diff HEAD`` est une plage vide : le résumé CI doit le rendre visible."""
    _base_and_feature(git_repo)

    result = _run(
        "scan", "--ci", "--diff", "HEAD", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_CLEAN
    assert "0 fichier(s) analysé(s)" in result.stderr


def test_scan_diff_ignores_a_secret_outside_the_diff(git_repo: GitRepo) -> None:
    """Le secret est dans la base, pas dans les changements de la branche."""
    _base_and_feature(git_repo)
    git_repo.write("unchanged.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "base secret")
    git_repo.git("update-ref", "refs/remotes/origin/main", "feature")
    git_repo.git("checkout", "-q", "-b", "clean", "feature")
    git_repo.write("clean.py", "x = 2\n")
    _commit(git_repo, "clean feature")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_CLEAN


def test_scan_diff_ignores_a_secret_deleted_on_the_branch(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("old.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "base secret")
    git_repo.git("update-ref", "refs/remotes/origin/main", "feature")
    git_repo.git("checkout", "-q", "-b", "delete", "feature")
    git_repo.git("rm", "-q", "old.py")
    _commit(git_repo, "delete secret")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_CLEAN


def test_scan_diff_scans_the_whole_modified_blob(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("config.py", "x = 1\n")
    _commit(git_repo, "base config")
    git_repo.git("update-ref", "refs/remotes/origin/main", "feature")
    git_repo.git("checkout", "-q", "-b", "modify", "feature")
    git_repo.write("config.py", f'x = 1\nAWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "modify config")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )

    assert result.exit_code == EXIT_FINDINGS
    assert "config.py:2" in result.stdout


def test_scan_diff_requires_ci(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    result = _run("scan", "--diff", "origin/main", str(git_repo.root))
    assert result.exit_code == EXIT_ERROR
    assert "--diff exige --ci" in result.stderr


def test_scan_diff_and_staged_are_mutually_exclusive(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    result = _run(
        "scan", "--ci", "--staged", "--diff", "origin/main", str(git_repo.root)
    )
    assert result.exit_code == EXIT_ERROR
    assert "--diff et --staged" in result.stderr


def test_scan_diff_missing_ref_exits_two(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    result = _run(
        "scan", "--ci", "--diff", "absente", "--no-allowlist", str(git_repo.root)
    )
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_diff_json_contract(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("new.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "feature")

    result = _run(
        "scan",
        "--ci",
        "--json",
        "--diff",
        "origin/main",
        "--no-allowlist",
        str(git_repo.root),
    )

    assert result.exit_code == EXIT_FINDINGS
    document = json.loads(result.stdout)
    assert document["schema"] == JSON_SCHEMA
    assert document["scope"] == "diff"
    assert document["count"] == 1
    assert document["findings"][0]["file"] == "new.py"
    assert FAKE_AWS_KEY not in result.stdout
    assert FAKE_AWS_KEY not in result.stderr


def test_scan_diff_refuses_a_repo_config_in_ci(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write("heimdall.toml", '[allowlist]\nversion = "1"\n')
    _commit(git_repo, "config")
    git_repo.write("new.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "feature")

    result = _run("scan", "--ci", "--diff", "origin/main", str(git_repo.root))
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )
    assert result.exit_code == EXIT_FINDINGS


def test_scan_diff_accepts_an_external_config(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    """Un ``--config`` hors dépôt reste autorisé en ``--ci --diff``."""
    _base_and_feature(git_repo)
    git_repo.write("new.py", f'AWS = "{FAKE_AWS_KEY}"\n')
    _commit(git_repo, "feature")
    external = tmp_path / "allowlist.toml"
    external.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")

    result = _run(
        "scan",
        "--ci",
        "--diff",
        "origin/main",
        "--config",
        str(external),
        "--json",
        str(git_repo.root),
    )

    assert result.exit_code == EXIT_FINDINGS
    document = json.loads(result.stdout)
    assert document["scope"] == "diff"
    assert document["config_hash"] is not None


@pytest.mark.parametrize(
    "options",
    [{"max_file_bytes": 1024}, {"skipped_files": []}],
)
def test_collect_diff_rejects_tree_options(
    git_repo: GitRepo, options: dict[str, object]
) -> None:
    """Le contrat API refuse les options d'arbre avec ``diff``."""
    _base_and_feature(git_repo)
    with pytest.raises(ScanError):
        collect(
            git_repo.root,
            staged=False,
            diff="origin/main",
            ci=True,
            **options,
        )


def test_collect_diff_rejects_staged_and_non_ci(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=True, diff="origin/main", ci=True)
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=False, diff="origin/main", ci=False)


def test_scan_diff_shallow_clone_exits_two(git_repo: GitRepo, tmp_path: Path) -> None:
    """Sans ancêtre commun (clone superficiel), git échoue : code 2, jamais 0."""
    _base_and_feature(git_repo)
    git_repo.write("feature.py", "x = 2\n")
    _commit(git_repo, "feature")
    git_repo.git("checkout", "-q", "main")
    git_repo.write("main.py", "y = 3\n")
    _commit(git_repo, "main advance")
    git_repo.git("checkout", "-q", "feature")

    assert GIT is not None
    clone = tmp_path / "shallow"
    completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [
            GIT,
            "clone",
            "--depth",
            "1",
            "--no-single-branch",
            f"file://{git_repo.root}",
            str(clone),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(clone)
    )
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_diff_refuses_head_moved_mid_scan(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_and_feature(git_repo)
    git_repo.write("new.py", "x = 2\n")
    _commit(git_repo, "feature")

    original = GitAccess.resolve_commit
    calls = {"head": 0}

    def changing(self: GitAccess, ref: str, **options: object) -> str:
        sha = original(self, ref, **options)  # type: ignore[arg-type]
        if ref == "HEAD":
            calls["head"] += 1
            if calls["head"] == 2:
                return "0" * 40
        return sha

    monkeypatch.setattr(GitAccess, "resolve_commit", changing)

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_diff_refuses_a_binary_blob(git_repo: GitRepo) -> None:
    _base_and_feature(git_repo)
    git_repo.write_bytes("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    _commit(git_repo, "binary")

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE


def test_scan_diff_refuses_too_many_files(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_and_feature(git_repo)
    git_repo.write("one.py", "x = 1\n")
    git_repo.write("two.py", "y = 2\n")
    _commit(git_repo, "two files")
    monkeypatch.setattr(scan_module, "MAX_STAGED_FILES", 1)

    result = _run(
        "scan", "--ci", "--diff", "origin/main", "--no-allowlist", str(git_repo.root)
    )
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == SCAN_ERROR_MESSAGE
