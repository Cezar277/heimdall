"""Tests de non-régression et bout en bout pour #233 (M-04..M-09, F-01..F-11)."""

from __future__ import annotations

import os
import stat
import subprocess  # nosec B404
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from heimdall.cli.fix import _find_single_quoted_literal, run_fix
from heimdall.cli.main import app
from heimdall.cli.review import Choice, ReviewOutcome, ReviewReport
from heimdall.remediation.apply import (
    AppliedPatch,
    ApplyError,
    apply_replacement,
    cleanup_backup_file,
)
from heimdall.remediation.env import EnvRemediationError
from heimdall.remediation.naming import is_dangerous_exec_env_var
from heimdall.remediation.templates import plan_for_finding
from heimdall.scanner.finding import Finding
from heimdall.vault.atomic import (
    _get_git_toplevel,
    is_git_ignored,
    is_git_tracked,
    parse_env_file,
    parse_example_names,
)
from heimdall.vault.client import VaultClient, _detect_from_git, _validate_secret_read_response

_TEST_API_KEY = "A" * 43
_FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105


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
    env_file.write_text('FOO="a"b\nBAR=\'a\'b\n', encoding="utf-8")
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
def test_f02_vault_pull_and_run_reject_non_vaulte_secret(
    tmp_path: Path, bad_status: str
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
