"""Tests de non-régression et bout en bout pour #233 (M-04..M-09, F-01..F-11)."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from heimdall.cli.fix import (
    _default_variable_name,
    _existing_env_names,
    _find_single_quoted_literal,
    run_fix,
)
from heimdall.cli.main import app
from heimdall.cli.review import Choice, ReviewOutcome, ReviewReport
from heimdall.cli.scan import collect
from heimdall.cli.vault_client import _pull_secrets_from_vault, vault_pull
from heimdall.remediation.apply import (
    AppliedPatch,
    ApplyError,
    apply_replacement,
    cleanup_backup_file,
)
from heimdall.remediation.env import EnvRemediationError
from heimdall.remediation.naming import (
    _MAX_TAKEN,
    DANGEROUS_ENV_EXACT,
    DANGEROUS_ENV_PREFIXES,
    EXECUTION_DANGEROUS_ENV_EXACT,
    EXECUTION_DANGEROUS_ENV_PREFIXES,
    is_dangerous_env_var,
    is_dangerous_exec_env_var,
)
from heimdall.remediation.templates import plan_for_finding
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding
from heimdall.vault.atomic import (
    _get_git_toplevel,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    parse_example_names,
)
from heimdall.vault.client import (
    VaultClient,
    VaultClientError,
    _detect_from_git,
    _validate_secret_read_response,
)

_TEST_API_KEY = "A" * 43
_FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105


@pytest.mark.parametrize("ci", [False, True])
@pytest.mark.parametrize("json_output", [False, True])
def test_fix_rejects_config_with_no_allowlist_before_work(
    tmp_path: Path, ci: bool, json_output: bool,
) -> None:
    for name in ("app.py", "app.py.bak", ".env", ".env.example", ".gitignore", "private.toml"):
        (tmp_path / name).write_text("unchanged\n", encoding="utf-8")
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        for path in tmp_path.iterdir()
    }
    args = ["fix", str(tmp_path), "--config", str(tmp_path / "private.toml"), "--no-allowlist"]
    if ci:
        args.append("--ci")
    if json_output:
        args.append("--json")
    with patch("heimdall.cli.fix.run_fix") as run:
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "options incompatibles : --config et --no-allowlist\n"
    run.assert_not_called()
    after = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        for path in tmp_path.iterdir()
    }
    assert after == before


def test_run_fix_rejects_conflicting_options_before_io(tmp_path: Path) -> None:
    with (
        patch.object(Path, "is_symlink") as symlink_check,
        patch("heimdall.cli.fix.collect") as collect,
        patch("heimdall.cli.fix.review_proposals") as review,
        pytest.raises(ScanError, match="^options incompatibles : --config et --no-allowlist$"),
    ):
        run_fix(tmp_path / "absent", config_path=tmp_path / "private.toml", no_allowlist=True)
    symlink_check.assert_not_called()
    collect.assert_not_called()
    review.assert_not_called()


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('export FOO="x"', "FOO"),
        ('export\tFOO="x"', "FOO"),
        (' \texport \tFOO="x"', "FOO"),
        ('FOO="x"', "FOO"),
        ('exportFOO="x"', "EXPORTFOO"),
        ('export FOO-BAR="x"', "SECRET_AWS_KEY"),
    ],
)
def test_default_variable_name_handles_export_prefix(line: str, expected: str) -> None:
    finding = Finding(file=".env", line=1, type="aws_key", entropy=3.5, snippet_hash="a" * 64)
    assert _default_variable_name(line, finding) == expected


@pytest.mark.parametrize(
    "name",
    [
        "AWS_SECRET_ACCESS_KEY",
        "DOCKER_PASSWORD",
        "NPM_TOKEN",
        "GIT_TOKEN",
        "TF_VAR_TOKEN",
        "KUBE_TOKEN",
        "NODE_ENV",
    ],
)
def test_m08_allows_cloud_and_tool_secret_names(name: str) -> None:
    assert is_dangerous_exec_env_var(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "CUSTOM_PROXY",
        "SSLKEYLOGFILE",
        "CLASSPATH",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "CURL_HOME",
        "WGETRC",
        "GNUPGHOME",
        "ELECTRON_RUN_AS_NODE",
        "NODE_OPTIONS",
        "LD_PRELOAD",
        "BASH_ENV",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "NODE_PATH",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "DOCKER_CONFIG",
        "NPM_CONFIG_PREFIX",
        "PIP_FIND_LINKS",
        "TF_DATA_DIR",
    ],
)
def test_m08_blocks_execution_hijack_env_vars(name: str) -> None:
    assert is_dangerous_exec_env_var(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "NODE_PATH",
        "AWS_CONFIG_FILE",
        "DOCKER_CONFIG",
        "PIP_FIND_LINKS",
        "TF_DATA_DIR",
    ],
)
def test_m08_vault_push_and_pull_reject_tool_redirectors(tmp_path: Path, name: str) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"{name}=/tmp/evil\n", encoding="utf-8")
    env_file.chmod(0o600)
    runner = CliRunner()
    with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            mock_init.return_value = client
            push_res = runner.invoke(
                app, ["vault", "push", "--project", "demo", "--file", str(env_file)]
            )
            assert push_res.exit_code == 2
            pull_res = runner.invoke(
                app,
                ["vault", "pull", "--project", "demo", "--name", name, "--output", str(env_file)],
            )
            assert pull_res.exit_code == 1


def test_m08_vault_push_allows_aws_secret_access_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"AWS_SECRET_ACCESS_KEY={_FAKE_SECRET}\n", encoding="utf-8")
    env_file.chmod(0o600)
    runner = CliRunner()
    with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            mock_init.return_value = client
            result = runner.invoke(
                app,
                ["vault", "push", "--project", "demo", "--file", str(env_file)],
            )
    assert result.exit_code == 0, result.output
    client.create_secret.assert_called_once_with(
        "demo", "dev", "AWS_SECRET_ACCESS_KEY", _FAKE_SECRET
    )


def test_m06_vault_run_strips_heimdall_credentials_from_child_env(tmp_path: Path) -> None:
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    runner = CliRunner()
    env_vars = {
        "HEIMDALL_API_KEY": _TEST_API_KEY,
        "HEIMDALL_API_KEY_FILE": str(tmp_path / "keyfile"),
        "HEIMDALL_VAULT_URL": "https://127.0.0.1:8443",
        "HEIMDALL_VAULT_CA": str(tmp_path / "ca.pem"),
    }
    with patch.dict(os.environ, env_vars):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            client.get_secret.return_value = {
                "project": "demo",
                "env": "dev",
                "name": "AWS_SECRET_ACCESS_KEY",
                "status": "vaulte",
                "value": _FAKE_SECRET,
            }
            mock_init.return_value = client
            with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = runner.invoke(
                    app,
                    [
                        "run",
                        "--project",
                        "demo",
                        "--name",
                        "AWS_SECRET_ACCESS_KEY",
                        "--",
                        str(exe),
                    ],
                )
    assert result.exit_code == 0, result.output
    child_env = mock_run.call_args.kwargs["env"]
    assert child_env["AWS_SECRET_ACCESS_KEY"] == _FAKE_SECRET
    assert "HEIMDALL_API_KEY" not in child_env
    assert "HEIMDALL_API_KEY_FILE" not in child_env
    assert "HEIMDALL_VAULT_URL" not in child_env
    assert "HEIMDALL_VAULT_CA" not in child_env


@pytest.mark.parametrize("secret_name", ["HEIMDALL_API_KEY", "HEIMDALL_VAULT_URL"])
def test_m06_vault_run_rejects_heimdall_prefixed_secret_name(
    tmp_path: Path, secret_name: str
) -> None:
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    runner = CliRunner()
    with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            client.get_secret.return_value = {
                "project": "demo",
                "env": "dev",
                "name": secret_name,
                "status": "vaulte",
                "value": _FAKE_SECRET,
            }
            mock_init.return_value = client
            with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                result = runner.invoke(
                    app,
                    ["run", "--project", "demo", "--name", secret_name, "--", str(exe)],
                )
    assert result.exit_code == 1
    mock_run.assert_not_called()


def test_m04_vault_client_disables_trust_env() -> None:
    client = VaultClient(base_url="https://127.0.0.1:8443", api_key=_TEST_API_KEY)
    try:
        http_client = client._get_client()
        assert http_client.trust_env is False
    finally:
        client.close()


def test_m05_git_helpers_use_git_access(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("X=1\n", encoding="utf-8")
    with patch("heimdall.vault.client.GitAccess") as mock_client_git:
        mock_client_git.return_value.execute.return_value = MagicMock(
            returncode=0, stdout=b"/tmp/demo-repo\n"
        )
        assert _detect_from_git(tmp_path) == "demo-repo"
        mock_client_git.assert_called_once_with(tmp_path)

    with patch("heimdall.vault.atomic.GitAccess") as mock_atomic_git:
        (tmp_path / ".git").mkdir()
        mock_atomic_git.return_value.root = tmp_path
        mock_atomic_git.return_value.execute.return_value = MagicMock(
            returncode=0, stdout=str(tmp_path).encode("utf-8")
        )
        assert _get_git_toplevel(target) == tmp_path
        assert is_git_tracked(target) is True
        assert is_git_ignored(target) is True
        assert mock_atomic_git.call_count >= 3


def test_f01_detect_from_git_uses_fullmatch(tmp_path: Path) -> None:
    with patch("heimdall.vault.client.GitAccess") as mock_git:
        mock_git.return_value.execute.return_value = MagicMock(
            returncode=0, stdout=b"/tmp/a" + b"b" * 70 + b"\n"
        )
        assert _detect_from_git(tmp_path) is None


def test_f02_validate_secret_payload_accepts_vaulte_and_rote() -> None:
    for status in ("vaulte", "rote"):
        payload = {
            "project": "demo",
            "env": "dev",
            "name": "APP_KEY",
            "status": status,
            "value": "secret-val",
        }
        assert _validate_secret_read_response(payload)["status"] == status


def test_f10_apply_replacement_cleanup_backup_removes_bak(tmp_path: Path) -> None:
    source = f'API_KEY = "{_FAKE_SECRET}"\n'
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")
    finding = Finding(
        file="app.py",
        line=1,
        type="aws_key",
        entropy=3.5,
        snippet_hash="a" * 64,
    )
    plan = plan_for_finding(finding, source, _FAKE_SECRET, "API_KEY")
    apply_replacement(tmp_path, plan, cleanup_backup=True)
    assert not (tmp_path / "app.py.bak").exists()
    assert 'os.environ["API_KEY"]' in target.read_text(encoding="utf-8")


def test_f10_apply_replacement_cleanup_backup_tolerates_missing_bak(tmp_path: Path) -> None:
    source = f'API_KEY = "{_FAKE_SECRET}"\n'
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")
    finding = Finding(
        file="app.py",
        line=1,
        type="aws_key",
        entropy=3.5,
        snippet_hash="a" * 64,
    )
    plan = plan_for_finding(finding, source, _FAKE_SECRET, "API_KEY")
    with patch("heimdall.remediation.apply.os.unlink", side_effect=FileNotFoundError):
        receipt = apply_replacement(tmp_path, plan, cleanup_backup=True)
    assert receipt.file == "app.py"
    assert 'os.environ["API_KEY"]' in target.read_text(encoding="utf-8")


def test_f10_cleanup_backup_file_rejects_mismatched_receipt(tmp_path: Path) -> None:
    victim = tmp_path / "other.py"
    victim.write_text("keep me\n", encoding="utf-8")
    forged = AppliedPatch(file="app.py", backup="other.py", mode=0o600, after="x\n")
    with pytest.raises(ApplyError):
        cleanup_backup_file(tmp_path, forged)
    assert victim.read_text(encoding="utf-8") == "keep me\n"


def test_f11_parse_example_names_handles_export_prefix(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    example.write_text("export FOO=bar # comment\n", encoding="utf-8")
    assert parse_example_names(example) == ["FOO"]


def test_f11_parse_env_file_does_not_truncate_trailing_garbage_after_quote(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=\"a\"b\nBAR='a'b\n", encoding="utf-8")
    parsed = parse_env_file(env_file)
    assert parsed == {"FOO": '"a"b', "BAR": "'a'b"}


def test_m09_fix_linear_scanner_avoids_redos_on_20kb_backslashes(tmp_path: Path) -> None:
    evil_line = '"' + ("\\" * 20_000)
    start = time.monotonic()
    assert _find_single_quoted_literal(evil_line) is None
    assert time.monotonic() - start < 0.2


def test_m09_fix_deduplication_overflow_marks_unfixable_not_exit2(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    app_file = tmp_path / "app.py"
    app_file.write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")
    with patch(
        "heimdall.cli.fix._existing_env_names",
        return_value={f"K_{i}" for i in range(10_005)},
    ):
        report, remaining = run_fix(tmp_path, ci=True)
    assert remaining == 1
    assert report.outcomes == ()


@pytest.mark.parametrize("bad_status", ["rote", "actif", "confirme"])
def test_f02_vault_pull_and_run_reject_non_vaulte_secret(tmp_path: Path, bad_status: str) -> None:
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    runner = CliRunner()
    with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            client.get_secret.return_value = {
                "project": "demo",
                "env": "dev",
                "name": "APP_KEY",
                "status": bad_status,
                "value": _FAKE_SECRET,
            }
            mock_init.return_value = client
            with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                run_res = runner.invoke(
                    app, ["run", "--project", "demo", "--name", "APP_KEY", "--", str(exe)]
                )
                pull_res = runner.invoke(
                    app,
                    [
                        "vault",
                        "pull",
                        "--project",
                        "demo",
                        "--name",
                        "APP_KEY",
                        "--output",
                        str(tmp_path / ".env"),
                    ],
                )
    assert run_res.exit_code == 1
    assert pull_res.exit_code == 1
    mock_run.assert_not_called()
    assert not (tmp_path / ".env").exists()


@pytest.mark.parametrize(
    "name",
    ["CUSTOM_PROXY", *sorted(DANGEROUS_ENV_EXACT | EXECUTION_DANGEROUS_ENV_EXACT)],
)
def test_m08_denylist_sync_between_remediation_and_exec(name: str) -> None:
    assert is_dangerous_env_var(name) is True
    assert is_dangerous_exec_env_var(name) is True


def test_m09_fix_oversized_source_is_unfixable_and_others_still_processed(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    large = tmp_path / "large.py"
    large_original = f'API_KEY = "{_FAKE_SECRET}"\n' + ("# padding\n" * 12_000)
    large.write_text(large_original, encoding="utf-8")
    small = tmp_path / "small.py"
    small.write_text(f'OTHER_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")

    def _fake_review(proposals, *, apply=None, **_kwargs):
        outcomes = []
        for prop in proposals:
            if apply is not None:
                apply(prop)
            outcomes.append(ReviewOutcome(Choice.VALIDATE, True, 0, prop))
        return ReviewReport(tuple(outcomes), True)

    with patch("heimdall.cli.fix.review_proposals", side_effect=_fake_review):
        report, remaining = run_fix(tmp_path, interactive=True)

    assert report.applied == 1
    assert remaining == 1
    assert large.read_text(encoding="utf-8") == large_original
    assert 'os.environ["OTHER_KEY"]' in small.read_text(encoding="utf-8")
    assert not (tmp_path / "small.py.bak").exists()
    assert not (tmp_path / "large.py.bak").exists()
    assert "OTHER_KEY=" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_m09_fix_refuses_edit_without_writing(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    app_file = tmp_path / "app.py"
    original = f'API_KEY = "{_FAKE_SECRET}"\n'
    app_file.write_text(original, encoding="utf-8")
    prompts: list[str] = []

    def _fake_stdin_ask(prompt: str, **_kwargs: object) -> str:
        prompts.append(prompt)
        return "e"

    with (
        patch("heimdall.cli.review.is_interactive", return_value=True),
        patch("heimdall.cli.review._stdin_ask", side_effect=_fake_stdin_ask),
    ):
        runner = CliRunner()
        res = runner.invoke(app, ["fix", str(tmp_path)])

    assert res.exit_code == 2, res.output
    assert prompts
    assert "éditer (E)" not in prompts[0]
    assert "Valider (Y) ou ignorer (N)" in prompts[0]
    assert app_file.read_text(encoding="utf-8") == original
    assert not (tmp_path / "app.py.bak").exists()
    assert not (tmp_path / ".env").exists()


def test_m09_fix_rejects_replaced_root_inode(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)  # noqa: S603, S607  # nosec B603, B607
    (repo / "app.py").write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")

    def _swap_and_apply(proposals, *, apply=None, **_kwargs):
        shutil.rmtree(repo)
        repo.mkdir()
        (repo / "app.py").write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")
        for prop in proposals:
            if apply is not None:
                apply(prop)
        return ReviewReport((), True)

    with patch("heimdall.cli.fix.review_proposals", side_effect=_swap_and_apply):
        runner = CliRunner()
        res = runner.invoke(app, ["fix", str(repo)])
    assert res.exit_code == 2
    assert _FAKE_SECRET in (repo / "app.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("cli", [False, True])
@pytest.mark.parametrize("moment", ["before_rescan", "during_rescan"])
def test_fix_refuses_replaced_root_after_apply(tmp_path: Path, cli: bool, moment: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)  # noqa: S603, S607
    (repo / "app.py").write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")
    (repo / "unfixable.py").write_text(f'KEY = "{_FAKE_SECRET}"; OTHER = "x"\n', encoding="utf-8")
    original_repo = tmp_path / "original"
    (repo / ".gitignore").write_text("*.bak\n", encoding="utf-8")

    def swap_root() -> None:
        before = repo.stat()
        repo.rename(original_repo)
        repo.mkdir()
        assert repo.stat().st_ino != before.st_ino
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)  # noqa: S603, S607

    def review(proposals, *, apply, **kwargs):
        outcomes = []
        for proposal in proposals:
            apply(proposal)
            outcomes.append(ReviewOutcome(Choice.VALIDATE, True, 0, proposal))
        assert outcomes
        if moment == "before_rescan":
            swap_root()
        return ReviewReport(tuple(outcomes), True)

    calls = 0

    def scan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            assert moment == "during_rescan"
            swap_root()
        return collect(*args, **kwargs)

    with (
        patch("heimdall.cli.fix.review_proposals", side_effect=review),
        patch("heimdall.cli.fix.collect", side_effect=scan),
    ):
        if cli:
            result = CliRunner().invoke(app, ["fix", str(repo), "--json"])
            assert result.exit_code == 2
            assert result.stdout == ""
            assert result.stderr == "heimdall fix : remédiation impossible (erreur d'outillage).\n"
        else:
            with pytest.raises(ScanError, match="^racine modifiée depuis le scan$"):
                run_fix(repo, interactive=True)
    assert calls == (1 if moment == "before_rescan" else 2)
    assert _FAKE_SECRET in (original_repo / "unfixable.py").read_text(encoding="utf-8")
    assert not (repo / "app.py").exists()


def test_fix_multiple_patches_refresh_only_own_root_ctime(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607
    (tmp_path / ".gitignore").write_text("*.bak\n", encoding="utf-8")
    for name, variable in (("first.py", "FIRST_KEY"), ("second.py", "SECOND_KEY")):
        (tmp_path / name).write_text(f'{variable} = "{_FAKE_SECRET}"\n', encoding="utf-8")

    def review(proposals, *, apply, **kwargs):
        outcomes = []
        for proposal in proposals:
            apply(proposal)
            outcomes.append(ReviewOutcome(Choice.VALIDATE, True, 0, proposal))
        return ReviewReport(tuple(outcomes), True)

    with patch("heimdall.cli.fix.review_proposals", side_effect=review):
        report, remaining = run_fix(tmp_path, interactive=True)
    assert len(report.outcomes) == 2
    assert all(outcome.applied for outcome in report.outcomes)
    assert remaining == 0


def test_f10_cleanup_backup_file_rejects_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("do not delete\n", encoding="utf-8")
    bak_link = tmp_path / "app.py.bak"
    bak_link.symlink_to(outside)
    receipt = AppliedPatch(file="app.py", backup="app.py.bak", mode=0o600, after="x\n")
    with pytest.raises(ApplyError):
        cleanup_backup_file(tmp_path, receipt)
    assert outside.read_text(encoding="utf-8") == "do not delete\n"


def test_f10_cleanup_backup_file_rejects_symlink_redirect_inside_root(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("keep me\n", encoding="utf-8")
    (tmp_path / "app.py.bak").symlink_to(target)
    receipt = AppliedPatch(file="app.py", backup="app.py.bak", mode=0o600, after="x\n")
    with pytest.raises(ApplyError):
        cleanup_backup_file(tmp_path, receipt)
    assert target.read_text(encoding="utf-8") == "keep me\n"


def test_m09_existing_env_names_is_bounded_on_large_env(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "".join(f"VAR_{i}=x\n" for i in range(_MAX_TAKEN + 500)),
        encoding="utf-8",
    )
    names = _existing_env_names(tmp_path)
    assert len(names) == _MAX_TAKEN + 1


def test_m09_fix_rejects_symlink_root_before_apply(tmp_path: Path) -> None:
    real_repo = tmp_path / "real"
    real_repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=real_repo, check=True)  # noqa: S603, S607  # nosec B603, B607
    (real_repo / "app.py").write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")
    link_repo = tmp_path / "link"
    link_repo.symlink_to(real_repo)

    runner = CliRunner()
    res = runner.invoke(app, ["fix", str(link_repo)])
    assert res.exit_code == 2
    assert _FAKE_SECRET in (real_repo / "app.py").read_text(encoding="utf-8")


def test_f11_parse_env_file_handles_export_and_inline_comments(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "# full line comment",
                "export FOO=bar # trailing comment",
                'BAR="baz # kept" # trailing comment',
                "BAZ='qux # kept' # trailing comment",
                "RAW=abc#123",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)
    assert parsed == {
        "FOO": "bar",
        "BAR": "baz # kept",
        "BAZ": "qux # kept",
        "RAW": "abc#123",
    }


def test_m09_fix_cli_ci_and_interactive_apply_e2e(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    app_file = tmp_path / "app.py"
    app_file.write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")

    # 1. Mode --ci via CLI : rapport seul, aucune écriture (mtime/.bak/.env inchangés), code 1.
    mtime_before = app_file.stat().st_mtime_ns
    runner = CliRunner()
    ci_result = runner.invoke(app, ["fix", str(tmp_path), "--ci", "--json"])
    assert ci_result.exit_code == 1, ci_result.output
    assert _FAKE_SECRET not in ci_result.output
    assert _FAKE_SECRET in app_file.read_text(encoding="utf-8")
    assert app_file.stat().st_mtime_ns == mtime_before
    assert not (tmp_path / "app.py.bak").exists()
    assert not (tmp_path / ".env").exists()

    # 2. Mode interactif simulé : validation humaine -> patch + .env + .env.example + .gitignore.
    def _fake_review(proposals, *, ci=False, interactive=None, apply=None, **_kwargs):
        outcomes = []
        for prop in proposals:
            if apply is not None:
                apply(prop)
            outcomes.append(ReviewOutcome(Choice.VALIDATE, True, 0, prop))
        return ReviewReport(tuple(outcomes), True)

    with patch("heimdall.cli.fix.review_proposals", side_effect=_fake_review):
        report, remaining = run_fix(tmp_path, interactive=True)

    assert report.interactive is True
    assert remaining == 0
    assert 'os.environ["API_KEY"]' in app_file.read_text(encoding="utf-8")
    assert not (tmp_path / "app.py.bak").exists()
    env_file = tmp_path / ".env"
    assert env_file.is_file()
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert "API_KEY=" in (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_m09_fix_refuses_ambiguous_multi_literal_line_fail_closed(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    app_file = tmp_path / "app.py"
    original = f'key = "public"; aws = "{_FAKE_SECRET}"\n'
    app_file.write_text(original, encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(app, ["fix", str(tmp_path), "--json"])
    assert res.exit_code == 1, res.output
    assert app_file.read_text(encoding="utf-8") == original
    assert not (tmp_path / ".env").exists()


def test_m09_fix_preserves_bak_if_env_remediation_fails(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607  # nosec B603, B607
    app_file = tmp_path / "app.py"
    app_file.write_text(f'API_KEY = "{_FAKE_SECRET}"\n', encoding="utf-8")

    def _fake_review(proposals, *, apply=None, **_kwargs):
        for prop in proposals:
            if apply is not None:
                apply(prop)
        return ReviewReport((), True)

    with patch("heimdall.cli.fix.review_proposals", side_effect=_fake_review):
        with patch(
            "heimdall.cli.fix.remediate_environment",
            side_effect=EnvRemediationError("disk full"),
        ):
            runner = CliRunner()
            res = runner.invoke(app, ["fix", str(tmp_path)])

    assert res.exit_code == 2
    assert (tmp_path / "app.py.bak").is_file()


def test_m08_vault_run_previews_dangerous_injected_name(tmp_path: Path) -> None:
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    evil_name = "HEIMDALL_\nINJECTED_LOG"
    runner = CliRunner()
    with patch.dict(os.environ, {"HEIMDALL_API_KEY": _TEST_API_KEY}):
        with patch("heimdall.cli.vault_client._init_client") as mock_init:
            client = MagicMock()
            client.__enter__.return_value = client
            mock_init.return_value = client
            with patch(
                "heimdall.cli.vault_client._pull_secrets_from_vault",
                return_value={evil_name: "x"},
            ):
                with patch("heimdall.cli.vault_client.subprocess.run") as mock_run:
                    result = runner.invoke(
                        app,
                        ["run", "--project", "demo", "--name", "SAFE_VAR", "--", str(exe)],
                    )
    assert result.exit_code == 1
    assert "\nINJECTED_LOG" not in result.stderr
    assert "HEIMDALL_\\nINJECTED_LOG" in result.stderr
    mock_run.assert_not_called()


def test_m08_pull_secrets_uses_preview_name_on_null_byte_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = MagicMock()
    client.get_secret.return_value = {"status": "vaulte", "value": "abc\x00def"}
    evil_name = "BAD\nINJECTED_LOG"
    with patch("heimdall.cli.vault_client._SECRET_NAME_PATTERN", re.compile(r".*", re.DOTALL)):
        with pytest.raises(typer.Exit) as exc_info:
            _pull_secrets_from_vault(client, "proj", "dev", [evil_name])
    assert exc_info.value.exit_code == 1
    err = capsys.readouterr().err
    assert "\nINJECTED_LOG" not in err
    assert "octet nul" in err


def test_f10_cleanup_backup_file_unresolved_root_with_symlink_prevents_outside_delete(
    tmp_path: Path,
) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me\n", encoding="utf-8")

    (real_root / "app.py.bak").symlink_to(outside)
    unresolved_root = tmp_path / "link_root"
    unresolved_root.symlink_to(real_root)

    receipt = AppliedPatch(file="app.py", backup="app.py.bak", mode=0o600, after="x\n")
    with pytest.raises(ApplyError):
        cleanup_backup_file(unresolved_root, receipt)
    assert outside.read_text(encoding="utf-8") == "keep me\n"


def test_m08_execution_dangerous_env_prefixes_enforced_and_in_sync() -> None:
    assert EXECUTION_DANGEROUS_ENV_PREFIXES == DANGEROUS_ENV_PREFIXES
    assert not is_dangerous_exec_env_var("CUSTOM_EXEC_TOKEN")
    with patch("heimdall.remediation.naming.EXECUTION_DANGEROUS_ENV_PREFIXES", ("CUSTOM_EXEC_",)):
        assert is_dangerous_exec_env_var("CUSTOM_EXEC_TOKEN") is True


def test_m08_pull_secrets_uses_preview_name_on_client_error_and_newline_value(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evil_name = "BAD\nINJECTED_LOG"
    client = MagicMock()
    client.get_secret.side_effect = VaultClientError("network error")
    with patch("heimdall.cli.vault_client._SECRET_NAME_PATTERN", re.compile(r".*", re.DOTALL)):
        with pytest.raises(typer.Exit) as exc_info:
            _pull_secrets_from_vault(client, "proj", "dev", [evil_name])
    assert exc_info.value.exit_code == 1
    err = capsys.readouterr().err
    assert "\nINJECTED_LOG" not in err
    assert "BAD\\nINJECTED_LOG" in err

    with (
        patch("heimdall.cli.vault_client._validate_project_and_env", return_value="proj"),
        patch("heimdall.cli.vault_client._validate_requested_names"),
        patch("heimdall.cli.vault_client._resolve_pull_names", return_value=[evil_name]),
        patch("heimdall.cli.vault_client._init_client", return_value=MagicMock()),
        patch(
            "heimdall.cli.vault_client._pull_secrets_from_vault",
            return_value={evil_name: "line1\nline2"},
        ),
    ):
        with pytest.raises(typer.Exit) as pull_exc:
            vault_pull(
                project="proj",
                env="dev",
                names=[evil_name],
                output=tmp_path / ".env",
                example_file=tmp_path / ".env.example",
                backup=False,
                vault_url=None,
                ca_cert=None,
            )
    assert pull_exc.value.exit_code == 1
    pull_err = capsys.readouterr().err
    assert "\nINJECTED_LOG" not in pull_err
    assert "BAD\\nINJECTED_LOG" in pull_err
