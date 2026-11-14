"""T38: disposable history, synthetic secrets, bounded reads and safe output."""

import errno
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner

from heimdall.cli import history
from heimdall.cli.cold_start import collect_cold_start
from heimdall.cli.main import app
from heimdall.cli.scan import collect
from heimdall.llm.rejections import RejectionJournal
from heimdall.mcp import gitdiff
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner.allowlist import Allowlist
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding

SYNTHETIC = "AKIAIOSFODNN7EXAMPLE"


def test_history_keeps_skip_lines_on_cache_hits(repo: GitRepo) -> None:
    content = "safe\nsafe\n" + "A" * 5000 + "\n"
    repo.write("original.dat", content)
    repo.commit_all("first")
    repo.git("mv", "original.dat", "renamed.dat")
    repo.commit_all("rename")
    report = history.collect_history(repo.root, ci=True, strict=False)
    payload = json.loads(history.render_history(report, json_output=True))
    long_tokens = [item for item in payload["skipped"] if item["reason"] == "long_token"]
    assert {item["file"] for item in long_tokens} == {"original.dat", "renamed.dat"}
    assert len(long_tokens) == 2
    assert all(item["line"] == 3 for item in long_tokens)
    assert all(
        item["line"] == 2 for item in payload["skipped"] if item["reason"] == "multiline_limit"
    )
    assert '"original.dat":3' in history.render_history(report)
    assert '"renamed.dat":3' in history.render_history(report)
    assert report.bytes_scanned == len(content.encode())
    assert not report.complete


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> Iterator[GitRepo]:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "01" * 32)
    value = GitRepo("heimdall-history-")
    try:
        yield value
    finally:
        value.close()


def test_deleted_secret_deduplicates_all_snapshots(repo: GitRepo) -> None:
    repo.write("config.py", f'key = "{SYNTHETIC}"\n')
    repo.commit_all("synthetic secret")
    first = repo.git_output("rev-parse", "HEAD").strip()
    repo.write("readme.txt", "safe\n")
    repo.commit_all("unchanged secret")
    second = repo.git_output("rev-parse", "HEAD").strip()
    (repo.root / "config.py").unlink()
    repo.commit_all("remove secret")
    report = history.collect_history(repo.root, ci=True)
    assert report.complete
    assert report.commits_scanned == 3
    assert len(report.findings) == 1
    assert set(report.findings[0].commits) == {first, second}
    assert SYNTHETIC not in history.render_history(report, json_output=True)
    assert "compromis" in history.render_history(report)
    assert "révoquer et remplacer" in history.render_history(report)
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["complete"] is True


def test_all_branches_tags_and_detached_head(repo: GitRepo) -> None:
    repo.write("readme", "safe")
    repo.commit_all("root")
    base = repo.git_output("rev-parse", "HEAD").strip()
    repo.git("checkout", "-qb", "side")
    repo.write("hidden.py", SYNTHETIC)
    repo.commit_all("side secret")
    repo.git("tag", "-a", "archive", "-m", "archive")
    repo.git("checkout", "--detach", base)
    repo.git("branch", "-D", "side")
    report = history.collect_history(repo.root, ci=True)
    assert report.commits_scanned == 2
    assert len(report.findings) == 1


def test_batches_merge_and_renames(repo: GitRepo, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "BATCH_SIZE", 1)
    repo.write("first name.py", SYNTHETIC)
    repo.commit_all("root")
    base = repo.git_output("branch", "--show-current").strip()
    repo.git("checkout", "-qb", "side")
    repo.git("mv", "first name.py", "renamed.py")
    repo.commit_all("rename")
    repo.git("checkout", base)
    repo.write("readme", "safe")
    repo.commit_all("main")
    repo.git("merge", "--no-ff", "side", "-m", "merge")
    report = history.collect_history(repo.root, ci=True)
    assert report.commits_scanned == 4
    assert {f.finding.file for f in report.findings} == {"first name.py", "renamed.py"}
    assert [len(f.commits) for f in report.findings] == [2, 2]


def test_ci_disables_llm_and_local_context_is_masked(repo: GitRepo) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    calls = []

    def chat(**kwargs: Any) -> SimpleNamespace:
        calls.append(json.dumps(kwargs))
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"secret","confidence":1}')
        )

    assert not history.collect_history(repo.root, ci=True, llm=True, chat=chat).opinions
    assert not calls
    report = history.collect_history(repo.root, chat=chat)
    assert len(calls) == len(report.opinions) == 1
    assert SYNTHETIC not in calls[0]


def test_oversized_blobs_never_read_and_cli_is_incomplete(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("large.txt", "x" * 100)
    repo.commit_all("large")

    def forbidden(*args: Any, **kwargs: Any) -> bytes:
        pytest.fail("oversized content must not be read")

    monkeypatch.setattr(GitAccess, "blob_bytes", forbidden)
    report = history.collect_history(repo.root, ci=True, max_file_bytes=10, strict=False)
    assert not report.complete
    assert report.bytes_scanned == 0
    assert report.skipped[0][0] == "large.txt"
    result = CliRunner().invoke(
        app, ["deep-scan", str(repo.root), "--ci", "--json", "--max-file-bytes", "10"]
    )
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False


def test_cold_start_size_limit_reports_skip(repo: GitRepo) -> None:
    repo.write("large.txt", "x" * 100)
    report = collect_cold_start(repo.root, ci=True, max_file_bytes=10)
    assert report.skipped_files == ("large.txt",)
    result = CliRunner().invoke(
        app, ["cold-start", str(repo.root), "--ci", "--json", "--max-file-bytes", "10"]
    )
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False


@pytest.mark.parametrize("limit", [0, -1, True, MAX_FILE_BYTES + 1])
def test_invalid_file_limit(repo: GitRepo, limit: int) -> None:
    with pytest.raises(ScanError):
        history.collect_history(repo.root, max_file_bytes=limit)


@pytest.mark.parametrize("filename", ["image.png", "archive.zip", "binary.txt", "binary"])
def test_empty_repo_and_binary(repo: GitRepo, filename: str) -> None:
    assert history.collect_history(repo.root, ci=True).commits_scanned == 0
    repo.write_bytes(filename, b"\x89PNG\r\n\x1a\n" + b"\x00\xff" * 100)
    repo.commit_all("binary")
    report = history.collect_history(repo.root, ci=True, strict=False)
    assert report.findings == ()
    assert report.skipped[0][0] == filename
    assert report.skipped[0][2] == "binary"
    assert not report.complete
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False


def test_bounds_fail_closed(repo: GitRepo, monkeypatch: pytest.MonkeyPatch) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    for name in (
        "MAX_COMMITS",
        "MAX_ENTRIES",
        "MAX_READ_BYTES",
        "MAX_RECORDS",
        "MAX_OCCURRENCES",
        "MAX_SECONDS",
    ):
        with monkeypatch.context() as patch:
            patch.setattr(history, name, 0)
            with pytest.raises(ScanError):
                history.collect_history(repo.root, ci=True)


def test_shallow_repository_refused(repo: GitRepo) -> None:
    repo.write("readme", "safe")
    repo.commit_all("root")
    (repo.root / ".git" / "shallow").write_text(repo.git_output("rev-parse", "HEAD"))
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci"])
    assert result.exit_code == 2
    assert "erreur d'outillage" in result.output


def test_replacements_cannot_hide_committed_secret(repo: GitRepo) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    secret_blob = repo.git_output("rev-parse", "HEAD:config.py").strip()
    repo.write("safe", "safe")
    repo.commit_all("safe blob")
    safe_blob = repo.git_output("rev-parse", "HEAD:safe").strip()
    repo.git("replace", secret_blob, safe_blob)
    assert len(history.collect_history(repo.root, ci=True).findings) == 1


def test_no_repository_and_output_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert CliRunner().invoke(app, ["deep-scan", str(tmp_path), "--ci"]).exit_code == 2


def test_sha256_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEIMDALL_SNIPPET_HMAC_KEY", "01" * 32)
    repo = GitRepo("heimdall-history-sha256-", object_format="sha256")
    try:
        repo.write("config.py", SYNTHETIC)
        repo.commit_all("synthetic")
        report = history.collect_history(repo.root, ci=True)
        assert len(report.findings[0].commits[0]) == 64
    finally:
        repo.close()


def test_rejection_is_displayed_and_does_not_remove_finding(
    repo: GitRepo,
    tmp_path: Path,
) -> None:
    repo.write("config.py", SYNTHETIC + "\n" + SYNTHETIC)
    repo.commit_all("duplicate synthetic")
    journal = RejectionJournal(tmp_path / "private" / "rejections.jsonl")
    calls = []

    def chat(**kwargs: Any) -> SimpleNamespace:
        calls.append(json.dumps(kwargs))
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"faux_positif","confidence":1}')
        )

    report = history.collect_history(repo.root, chat=chat, journal=journal)
    assert len(calls) == len(report.findings) == len(report.opinions) == 1
    assert SYNTHETIC not in calls[0]
    assert "faux_positif" in history.render_history(report)
    assert len(journal.read()) == 1


def test_cache_eviction_preserves_commits(repo: GitRepo, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "CACHE_SIZE", 1)
    repo.write("config.py", SYNTHETIC)
    repo.write("readme", "safe")
    repo.commit_all("first")
    repo.write("readme", "still safe")
    repo.commit_all("second")
    assert len(history.collect_history(repo.root, ci=True).findings[0].commits) == 2


@pytest.mark.parametrize(
    "raw",
    [
        b"100644 blob " + b"a" * 40 + b"\t../escape\0",
        b"100644 blob " + b"a" * 40 + b"\tfile",
        b"malformed\0",
        b"100600 blob " + b"a" * 40 + b"\tfile\0",
        b"100644 blob " + b"a" * 40 + b"\tbad\xff.png\0",
        b"100644 blob " + b"\xff" * 40 + b"\tfile\0",
    ],
)
def test_malformed_tree_is_refused(raw: bytes) -> None:
    with pytest.raises(ScanError, match="arbre historique non analysable"):
        history._entries(raw)


def test_symlink_blob_is_included_and_submodule_is_excluded() -> None:
    oid = b"a" * 40
    assert history._entries(
        b"120000 blob " + oid + b"\tlink\0" + b"160000 commit " + oid + b"\tsubmodule\0"
    ) == [("link", "a" * 40)]


def test_graft_cannot_hide_deleted_secret(repo: GitRepo) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    (repo.root / "config.py").unlink()
    repo.commit_all("deleted")
    (repo.root / ".git" / "info" / "grafts").write_text(repo.git_output("rev-parse", "HEAD"))
    assert history.collect_history(repo.root, ci=True).findings


@pytest.mark.parametrize("suffix", ["png", "zip", "txt"])
def test_unknown_binary_cannot_hide_secret(repo: GitRepo, suffix: str) -> None:
    repo.write_bytes(f"evil.{suffix}", b"\x00" + SYNTHETIC.encode() + b"\n#")
    repo.commit_all("unknown binary with synthetic secret")
    report = history.collect_history(repo.root, ci=True, strict=False)
    assert report.skipped[0][0] == f"evil.{suffix}"
    assert not report.complete
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["complete"] is False
    assert SYNTHETIC not in result.output


def test_reference_mutation_refuses_api_and_cli(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("config.py", "# safe\n")
    repo.commit_all("root")
    original = history._tips
    calls = 0

    def mutate(access: GitAccess, deadline: float) -> tuple[str, ...]:
        nonlocal calls
        tips = original(access, deadline)
        if calls % 2 == 0:
            repo.write("config.py", SYNTHETIC + f"\n# revision {calls}\n")
            repo.commit_all("concurrent synthetic secret")
        calls += 1
        return tips

    monkeypatch.setattr(history, "_tips", mutate)
    with pytest.raises(ScanError, match="références modifiées"):
        history.collect_history(repo.root, ci=True)
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert SYNTHETIC not in result.output


@pytest.mark.parametrize("source", ["tips", "head", "rev-list"])
@pytest.mark.parametrize("payload", [b"\xff", b"invalid-object-id"])
def test_invalid_history_object_is_static_scan_error(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    payload: bytes,
) -> None:
    repo.write("readme", "safe\n")
    repo.commit_all("root")
    original_git = history._git
    original_execute = GitAccess.execute

    def corrupt_git(access: GitAccess, args: tuple[str, ...], cap: int, deadline: float) -> bytes:
        if (source == "tips" and args[1:] == ("rev-parse", "--all")) or (
            source == "rev-list" and "rev-list" in args
        ):
            return payload + b"\n"
        return original_git(access, args, cap, deadline)

    def corrupt_head(access: GitAccess, args: Any, **kwargs: Any) -> Any:
        if source == "head" and args[-3:] == ("rev-parse", "--verify", "HEAD"):
            assert args[0] == "--no-replace-objects"
            return SimpleNamespace(returncode=0, stdout=payload + b"\n")
        return original_execute(access, args, **kwargs)

    monkeypatch.setattr(history, "_git", corrupt_git)
    monkeypatch.setattr(GitAccess, "execute", corrupt_head)
    with pytest.raises(ScanError, match="^historique non analysable$"):
        history.collect_history(repo.root, ci=True)
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "invalid-object-id" not in result.output


@pytest.mark.parametrize("count", [10, 11, 10_000])
@pytest.mark.parametrize("width", [40, 64])
def test_text_commit_list_is_bounded_and_json_is_exhaustive(count: int, width: int) -> None:
    commits = tuple(f"{number:0{width}x}" for number in range(count))
    finding = Finding(file="config.py", line=1, type="aws", entropy=3.0, snippet_hash="a" * 64)
    report = history.HistoryReport(
        findings=(history.HistoricalFinding(finding, commits),),
        opinions=(),
        skipped=(),
        commits_scanned=count,
        entries_scanned=count,
        bytes_scanned=20,
        elapsed_seconds=0.1,
    )
    text = history.render_history(report)
    assert len(text.encode("utf-8")) < 1200
    assert all(commit in text for commit in commits[:10])
    if count > 10:
        assert commits[10] not in text
        assert f"… (+{count - 10})" in text
    else:
        assert "… (+" not in text
    data = json.loads(history.render_history(report, json_output=True))
    assert data["findings"][0]["commits"] == list(commits)


@pytest.mark.parametrize("same_blob", [True, False])
def test_same_secret_preserves_each_file_after_deletion(repo: GitRepo, same_blob: bool) -> None:
    repo.write("config.py", SYNTHETIC + "\n")
    repo.commit_all("first location")
    first = repo.git_output("rev-parse", "HEAD").strip()
    repo.write("other.py", SYNTHETIC + ("\n" if same_blob else "\n# second location\n"))
    repo.commit_all("second location")
    second = repo.git_output("rev-parse", "HEAD").strip()
    (repo.root / "config.py").unlink()
    (repo.root / "other.py").unlink()
    repo.commit_all("delete both")
    calls = []

    def chat(**kwargs: Any) -> SimpleNamespace:
        calls.append(kwargs)
        return SimpleNamespace(
            message=SimpleNamespace(content='{"verdict":"secret","confidence":1}')
        )

    report = history.collect_history(repo.root, chat=chat)
    locations = {item.finding.file: set(item.commits) for item in report.findings}
    assert locations == {"config.py": {first, second}, "other.py": {second}}
    assert len(calls) == 1
    text = history.render_history(report)
    assert "config.py" in text and "other.py" in text
    data = json.loads(history.render_history(report, json_output=True))
    assert {item["finding"]["file"] for item in data["findings"]} == set(locations)
    assert SYNTHETIC not in text


@pytest.mark.parametrize("collector", ["history", "cold-start", "collect"])
def test_invalid_root_uses_scan_error(tmp_path: Path, collector: str) -> None:
    root = tmp_path / "missing"
    with pytest.raises(ScanError):
        if collector == "history":
            history.collect_history(root)
        elif collector == "cold-start":
            collect_cold_start(root)
        else:
            collect(root, staged=False)


@pytest.mark.parametrize("method", ["__init__", "execute", "_read_capped"])
@pytest.mark.parametrize("collector", ["history", "cold-start", "collect"])
def test_git_failures_use_scan_error(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    collector: str,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ToolFailure("INTERNAL")

    monkeypatch.setattr(GitAccess, method, fail)
    with pytest.raises(ScanError):
        if collector == "history":
            history.collect_history(repo.root)
        elif collector == "cold-start":
            collect_cold_start(repo.root)
        else:
            collect(repo.root, staged=False)


@pytest.mark.parametrize("staged", [False, True])
@pytest.mark.parametrize("limit", [True, -1, 0, 10**12])
def test_collect_invalid_limit_uses_scan_error(repo: GitRepo, staged: bool, limit: int) -> None:
    with pytest.raises(ScanError, match="limite de fichier invalide"):
        collect(repo.root, staged=staged, max_file_bytes=limit)


@pytest.mark.parametrize("method", ["blob_size", "blob_bytes", "negative-size"])
def test_history_blob_failures_use_scan_error(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    original = GitAccess._read_capped

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ToolFailure("INTERNAL")

    def negative(access: GitAccess, args: Any, *rest: Any, **kwargs: Any) -> bytes:
        if "cat-file" in args and "-s" in args:
            return b"-1\n"
        return original(access, args, *rest, **kwargs)

    if method == "negative-size":
        monkeypatch.setattr(GitAccess, "_read_capped", negative)
    else:
        monkeypatch.setattr(GitAccess, method, fail)
    with pytest.raises(ScanError, match="historique non analysable"):
        history.collect_history(repo.root, ci=True)


@pytest.mark.parametrize(
    "options",
    [
        {"max_file_bytes": 10},
        {"max_file_bytes": MAX_FILE_BYTES},
        {"skipped_files": []},
        {"max_file_bytes": 10, "skipped_files": []},
    ],
)
def test_staged_rejects_tree_options_before_git_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    options: dict[str, Any],
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("invalid staged options must be refused before Git access")

    monkeypatch.setattr(GitAccess, "__init__", forbidden)
    with pytest.raises(ScanError, match="^limite de fichier invalide$"):
        collect(tmp_path, staged=True, **options)


def test_ci_does_not_write_injected_journal(repo: GitRepo, tmp_path: Path) -> None:
    repo.write("config.py", SYNTHETIC)
    repo.commit_all("synthetic")
    path = tmp_path / "private" / "journal.jsonl"
    journal = RejectionJournal(path)

    def forbidden(**kwargs: Any) -> Any:
        pytest.fail("CI must not call model")

    assert not history.collect_history(repo.root, ci=True, chat=forbidden, journal=journal).opinions
    assert not path.exists()


def test_historical_symlink_target_is_scanned_as_blob(repo: GitRepo) -> None:
    path = repo.write("blob-input", SYNTHETIC)
    oid = repo.git_output("hash-object", "-w", "blob-input").strip()
    path.unlink()
    repo.git("update-index", "--add", "--cacheinfo", f"120000,{oid},link")
    staged = collect(repo.root, staged=True, allowlist=Allowlist.empty())
    assert len(staged.findings) == 1
    repo.git("commit", "-qm", "synthetic symlink target")
    secret_commit = repo.git_output("rev-parse", "HEAD").strip()
    repo.git("rm", "--cached", "link")
    repo.git("commit", "-qm", "remove link")
    report = history.collect_history(repo.root, ci=True)
    assert len(report.findings) == 1
    assert report.findings[0].finding.file == "link"
    assert report.findings[0].commits == (secret_commit,)
    assert not (repo.root / "link").exists()


def test_many_tips_argv_failure_is_static_and_cli_exits_two(
    repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo.write("readme", "safe\n")
    repo.commit_all("root")
    tips = tuple(f"{number:040x}" for number in range(1, 20_001))
    monkeypatch.setattr(history, "BATCH_SIZE", 1)
    monkeypatch.setattr(history, "_tips", lambda access, deadline: tips)
    original = gitdiff.subprocess.Popen
    attempts = 0

    def reject_large_argv(args: Any, **kwargs: Any) -> Any:
        nonlocal attempts
        if "rev-list" in args:
            assert args[-len(tips) - 1 : -1] == list(tips)
            assert args[-1] == "--"
            assert "--max-count=1" in args
            attempts += 1
            raise OSError(errno.E2BIG, SYNTHETIC)
        return original(args, **kwargs)

    monkeypatch.setattr(gitdiff.subprocess, "Popen", reject_large_argv)
    with pytest.raises(ScanError, match="^historique non analysable$"):
        history.collect_history(repo.root, ci=True)
    result = CliRunner().invoke(app, ["deep-scan", str(repo.root), "--ci", "--json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert SYNTHETIC not in result.output
    assert "erreur d'outillage" in result.output
    assert attempts == 2
