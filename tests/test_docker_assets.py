"""Tests statiques des livrables Docker T41 (#119/#120/#121/#122).

Aucun démon Docker n'est requis : ces tests vérifient les invariants de
sécurité des fichiers livrés (Dockerfile, compose, .dockerignore, lock runtime,
guide) et le healthcheck. Le test à froid réel est archivé dans
``docs/t122-cold-test.md``.
"""

from __future__ import annotations

import importlib.util
import io
import re
import shutil
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
DOCKERIGNORE = ROOT / ".dockerignore"
ENV_EXAMPLE = ROOT / ".env.example"
RUNTIME_LOCK = ROOT / "requirements-runtime.lock"
INSTALL_GUIDE = ROOT / "docs" / "install.md"
HEALTHCHECK = ROOT / "docker" / "healthcheck.py"
ENTRYPOINT = ROOT / "docker" / "entrypoint.py"


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_healthcheck():
    return _load_script("heimdall_docker_healthcheck", HEALTHCHECK)


def _load_entrypoint():
    return _load_script("heimdall_docker_entrypoint", ENTRYPOINT)


class DockerfileSecurityTests(unittest.TestCase):
    def test_image_is_multi_stage_and_pinned(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertEqual(text.count("FROM python:3.12-slim@sha256:"), 2)
        self.assertIn("AS builder", text)
        self.assertIn("AS runtime", text)
        self.assertIn("--require-hashes", text)
        self.assertIn("--no-deps", text)
        self.assertIn("--no-build-isolation", text)
        self.assertIn("python -m pip uninstall -y pip setuptools", text)
        # Durcissement revue 32b8afd : ensurepip stdlib retiré du runtime.
        self.assertIn("ensurepip", text)
        self.assertIn("rm -rf /usr/local/lib/python3.12/ensurepip", text)

    def test_image_runs_as_non_root_and_has_healthcheck(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("USER 10001:10001", text)
        self.assertIn("HEALTHCHECK", text)
        self.assertIn('ENTRYPOINT ["python", "/app/entrypoint.py"]', text)
        self.assertIn("STOPSIGNAL SIGTERM", text)
        self.assertIn('VOLUME ["/data"]', text)

    def test_no_secret_or_dev_tool_is_baked_into_the_image(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        for forbidden in (
            "HEIMDALL_VAULT_MASTER_KEY=",
            "HEIMDALL_VAULT_API_KEY_PEPPER=",
            "HEIMDALL_VAULT_KEK=",
            "HEIMDALL_VAULT_KEK_SALT=",
            "apt-get",
            "COPY . .",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_dockerignore_excludes_secrets_and_dev_context(self) -> None:
        lines = {
            line.strip()
            for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        for expected in (
            ".git",
            ".env",
            ".env.*",
            "secrets",
            "certs",
            "*.pem",
            "*.key",
            "*.db",
            "heimdall-backup-*.tgz.gpg",
            "tests",
            "docs",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, lines)


class ComposeSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        self.service = self.compose["services"]["vault"]

    def test_vault_is_loopback_only_via_host_network(self) -> None:
        self.assertEqual(self.service["network_mode"], "host")
        self.assertNotIn("ports", self.service)
        self.assertNotIn("privileged", self.service)
        self.assertNotIn("cap_add", self.service)
        self.assertNotIn("pid", self.service)

    def test_container_is_hardened(self) -> None:
        self.assertIs(self.service["read_only"], True)
        self.assertEqual(self.service["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", self.service["security_opt"])
        # UID figé : aucune variable résolvable en 0, aucun démarrage
        # transitoire en root même si l'opérateur saute le §4 du guide.
        self.assertEqual(self.service["user"], "10001:10001")
        self.assertNotIn("HEIMDALL_UID", str(self.service["user"]))
        self.assertNotIn("HEIMDALL_GID", str(self.service["user"]))
        self.assertNotIn("0:0", str(self.service["user"]))
        serialized = COMPOSE.read_text(encoding="utf-8")
        self.assertNotIn("HEIMDALL_UID", serialized)
        self.assertNotIn("HEIMDALL_GID", serialized)
        self.assertIn("/tmp:rw,noexec,nosuid,size=64m", self.service["tmpfs"])  # noqa: S108
        self.assertEqual(self.service["pids_limit"], 256)

    def test_secrets_are_not_hardcoded_and_are_mounted_read_only(self) -> None:
        environment = self.service["environment"]
        self.assertEqual(
            environment["HEIMDALL_VAULT_SSL_CERTFILE"],
            "/run/secrets/vault_tls_cert.pem",
        )
        self.assertEqual(
            environment["HEIMDALL_VAULT_SSL_KEYFILE"],
            "/run/secrets/vault_tls_key.pem",
        )
        self.assertIn("./data:/data", self.service["volumes"])
        self.assertIn("./secrets:/run/secrets:ro", self.service["volumes"])
        self.assertIn(".env", self.service["env_file"])
        serialized = COMPOSE.read_text(encoding="utf-8")
        self.assertNotIn("MASTER_KEY:", serialized)
        self.assertNotIn("API_KEY_PEPPER:", serialized)

    def test_env_example_has_no_real_secret(self) -> None:
        values = {}
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key] = value
        for key in (
            "HEIMDALL_VAULT_MASTER_KEY",
            "HEIMDALL_VAULT_API_KEY_PEPPER",
            "HEIMDALL_VAULT_KEK_SALT",
        ):
            with self.subTest(key=key):
                self.assertEqual(values[key], "")

    def test_runtime_lock_excludes_dev_tools(self) -> None:
        text = RUNTIME_LOCK.read_text(encoding="utf-8")
        for package in ("pytest", "mypy", "ruff", "bandit", "pip-audit"):
            with self.subTest(package=package):
                self.assertNotRegex(text, rf"(?m)^{package}==")
        for package in ("fastapi", "cryptography", "argon2-cffi"):
            with self.subTest(package=package):
                self.assertRegex(text, rf"(?m)^{package}==")
        # setuptools reste dans le lock pour le builder, mais l'image runtime
        # l'uninstalle explicitement avant le COPY.
        self.assertRegex(text, r"(?m)^setuptools==")


class InstallGuideTests(unittest.TestCase):
    def test_guide_covers_the_cold_start_path(self) -> None:
        text = INSTALL_GUIDE.read_text(encoding="utf-8")
        for expected in (
            '[[ "$(id -u)" != 0 ]]',
            "git checkout t41-audit",
            "git status --porcelain",
            "git archive HEAD",
            "set -euo pipefail",
            "git fetch origin",
            "10001:10001",
            "sudo chown -R --no-dereference 10001:10001 data secrets",
            "docker compose stop vault || exit 1",
            "basicConstraints=critical,CA:FALSE",
            ".env.??????",
            "mktemp -d /tmp/heimdall-clean.XXXXXX",
            "docker compose up -d --build",
            "curl --cacert secrets/vault_tls_cert.pem",
            "heimdall vault key create --project demo",
            "heimdall scan",
            "docs/t122-cold-test.md",
            "chmod 700 data secrets",
            'chmod 600 "$ENV_TMP"',
            "test ! -L data",
            "test ! -L secrets",
            "A-Za-z0-9_-]{43,}",
            "mktemp /tmp/heimdall-auth.XXXXXX",
            '-K "$AUTH_HEADER"',
            "trap 'rm -f \"$AUTH_HEADER\"' EXIT INT TERM HUP",
            'rm -f "$AUTH_HEADER"',
            "mktemp .env.XXXXXX",
            'mv -f "$ENV_TMP" .env',
            "docker compose config --quiet",
            "gpg --symmetric --cipher-algo AES256",
            "docker compose stop vault",
            "ls data/vault.db-*",
            "WAL/SHM résiduel",
            'F="${HOME}/heimdall-backup-$(date +%F-%H%M).tgz.gpg"',
            'test ! -e "$F"',
            "archive déjà existante",
            "trap 'docker compose start vault' EXIT INT TERM HUP",
            'chmod 600 "$F"',
            "docker compose start vault",
            "install -m 600 .env.example .env",
            "docker inspect",
            "network_mode: host",
            'SHA_PRE="$(git rev-parse HEAD)"',
            'test "$(git rev-parse HEAD)" = "$SHA_PRE"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        self.assertNotIn('curl -H "X-Heimdall-API-Key: $HEIMDALL_API_KEY"', text)
        self.assertNotIn("export HEIMDALL_API_KEY=", text)
        self.assertNotIn("/tmp/heimdall-auth.header", text)  # noqa: S108
        # UID figé : aucune garde variable, aucun sourcing du .env au §4.
        self.assertNotIn("HEIMDALL_UID=$(id -u)", text)
        self.assertNotIn("HEIMDALL_GID=$(id -g)", text)
        self.assertNotIn("HEIMDALL_(UID|GID)", text)
        # chown préserve les bits : aucun `chmod` sans sudo après le chown.
        self.assertIn("`chown` préserve les bits", text)
        self.assertNotIn("data secrets\nchmod 700 data secrets", text)
        # Durcissements revue 6b748c0 : liens internes, restauration confinée.
        self.assertIn("--no-dereference 10001:10001 data secrets", text)
        self.assertIn('test -z "$(find data secrets -type l)"', text)
        self.assertIn('tar -tzf "$T"', text)
        self.assertIn("--exclude='.git/*'", text)
        self.assertIn('-xzf "$T" data .env secrets', text)
        self.assertIn("ne jamais ajouter `-P`", text)
        # Durcissements revue c5db82c : snapshot sans fuite, refus automatisé.
        self.assertIn('D_SNAP="$(mktemp -d /tmp/heimdall-snap.XXXXXX)"', text)
        self.assertIn('D_CLEAN="$(mktemp -d /tmp/heimdall-clean.XXXXXX)"', text)
        self.assertIn('trap \'rm -rf "${D_SNAP:-}" "$D_CLEAN"\' EXIT', text)
        self.assertIn('D_SNAP="${D_SNAP:-}"', text)
        self.assertNotIn('D="$(mktemp -d)"', text)
        self.assertIn("grep -Ev", text)
        self.assertIn("membre inattendu", text)
        self.assertIn("--no-absolute-filenames", text)
        # Durcissements revue 89510d7 : §7 fail-closed, quickstart sans écrasement.
        self.assertIn('git archive HEAD | tar -x -C "$D_SNAP" || {', text)
        self.assertIn('cd "$D_CLEAN" || exit 1', text)
        self.assertGreaterEqual(text.count("set -euo pipefail"), 4)
        # Durcissements revue db325b4 : restauration à déchiffrement unique,
        # dépannage sans écrasement.
        self.assertIn('T="$(mktemp)"', text)
        self.assertIn('gpg --output "$T" --decrypt "$BK"', text)
        self.assertEqual(text.count("--decrypt"), 1)
        self.assertIn("test ! -e .env", text)
        # Durcissements revue f49a8ad : anti-écrasement restauration, trap set -u,
        # archive vide refusée.
        self.assertIn("archive sans data/", text)
        self.assertIn("archive sans secrets/", text)
        self.assertIn("archive sans .env", text)
        self.assertIn("lien symbolique interne refusé après restauration", text)
        self.assertIn("existant : sauvegarder puis rm -rf data secrets .env", text)
        # Durcissements revue 32b8afd : pas de test -a, re-vérification après chown.
        self.assertIn("test ! -e .env && test ! -e secrets && test ! -e data", text)
        self.assertNotIn("test ! -e .env -a ", text)
        self.assertIn("lien symbolique interne refusé après chown", text)
        self.assertGreaterEqual(text.count("test ! -L data"), 2)
        self.assertGreaterEqual(text.count("set -euo pipefail"), 2)


class CliSnapshotInstallationTests(unittest.TestCase):
    def test_git_status_and_archive_rejects_dirty_worktree(self) -> None:
        """Vérifie que le couple status + archive refuse un arbre modifié (fenêtre TOCTOU)."""
        git = shutil.which("git")
        bash = shutil.which("bash")
        self.assertIsNotNone(git)
        self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run([git, "init", "-q", str(repo)], check=True)  # noqa: S603
            subprocess.run(  # noqa: S603
                [git, "-C", str(repo), "config", "user.name", "Test"],
                check=True,
            )
            subprocess.run(  # noqa: S603
                [git, "-C", str(repo), "config", "user.email", "test@example.com"],
                check=True,
            )
            dummy = repo / "file.txt"
            dummy.write_text("v1\n", encoding="utf-8")
            subprocess.run([git, "-C", str(repo), "add", "file.txt"], check=True)  # noqa: S603
            subprocess.run(  # noqa: S603
                [git, "-C", str(repo), "commit", "-qm", "init"],
                check=True,
            )

            script = (
                "set -eu\n"
                'test -z "$(git status --porcelain)" || exit 2\n'
                'SHA_PRE="$(git rev-parse HEAD)"\n'
                'D="$(mktemp -d)"\n'
                'trap \'rm -rf "$D"\' EXIT\n'
                'git archive HEAD | tar -x -C "$D"\n'
                'test "$(git rev-parse HEAD)" = "$SHA_PRE" || exit 3\n'
                'test -z "$(git status --porcelain)" || exit 4\n'
                "exit 0\n"
            )

            res = subprocess.run([bash, "-c", script], cwd=repo, check=False)  # noqa: S603
            self.assertEqual(res.returncode, 0)

            dummy.write_text("v2 uncommitted\n", encoding="utf-8")
            res_dirty = subprocess.run([bash, "-c", script], cwd=repo, check=False)  # noqa: S603
            self.assertEqual(res_dirty.returncode, 2)


class SamnAndPinTests(unittest.TestCase):
    def test_samm_scan_snippet_uses_mktemp(self) -> None:
        text = (ROOT / "docs" / "t41-samm.md").read_text(encoding="utf-8")
        self.assertIn("mktemp -d /tmp/heimdall-clean.XXXXXX", text)
        self.assertNotIn("mkdir -p /tmp/heimdall-clean", text)

    def test_install_and_samm_pin_the_same_audited_sha(self) -> None:
        sha = "49bb5ccce63a102e1f00a075f1cd6c83dfbe366e"
        install = INSTALL_GUIDE.read_text(encoding="utf-8")
        samm = (ROOT / "docs" / "t41-samm.md").read_text(encoding="utf-8")
        self.assertIn("git checkout t41-audit", install)
        self.assertIn("git rev-parse --short HEAD", install)
        self.assertIn("49bb5ccce63a102e1f00a075f1cd6c83dfbe366e", install)
        self.assertIn(sha, samm)
        self.assertIn("t41-audit", install + samm)

    def test_pins_coherence_between_guide_and_samm(self) -> None:
        """Vérifie la cohérence des pins (install.md §2 == mise à jour == t41-samm.md:7)."""
        install = INSTALL_GUIDE.read_text(encoding="utf-8")
        samm = (ROOT / "docs" / "t41-samm.md").read_text(encoding="utf-8")
        shas_install = re.findall(
            r'test "\$\(git rev-parse HEAD\)" = "([0-9a-f]{40})"',
            install,
        )
        self.assertGreaterEqual(
            len(shas_install),
            2,
            "Au moins 2 vérifications de SHA attendues dans docs/install.md (§2 et §Mise à jour)",
        )
        self.assertEqual(
            shas_install[0],
            shas_install[1],
            f"docs/install.md désynchronisé: §2 ({shas_install[0]}) != maj ({shas_install[1]})",
        )
        match_samm = re.search(
            r"tag `t41-audit` vérifié par `git rev-parse` = `([0-9a-f]{40})`",
            samm,
        )
        self.assertIsNotNone(match_samm, "SHA du tag t41-audit introuvable dans docs/t41-samm.md:7")
        assert match_samm is not None
        sha_samm = match_samm.group(1)
        self.assertEqual(
            shas_install[0],
            sha_samm,
            f"Désynchronisation: install.md ({shas_install[0]}) != samm.md ({sha_samm})",
        )

    def test_samm_cli_snippet_imposes_clean_status_and_snapshot(self) -> None:
        """Vérifie que la SAMM impose status propre + git archive + contrôle SHA_PRE."""
        samm = (ROOT / "docs" / "t41-samm.md").read_text(encoding="utf-8")
        self.assertIn("git status --porcelain", samm)
        self.assertIn("git archive HEAD", samm)
        self.assertIn('SHA_PRE="$(git rev-parse HEAD)"', samm)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SHA_PRE"', samm)
        # Durcissement revue c5db82c : pas de fuite mktemp dans la SAMM non plus.
        self.assertIn('D_SNAP="$(mktemp -d /tmp/heimdall-snap.XXXXXX)"', samm)
        self.assertIn('D_CLEAN="$(mktemp -d /tmp/heimdall-clean.XXXXXX)"', samm)
        self.assertIn('D_SNAP="${D_SNAP:-}"', samm)
        self.assertNotIn('D="$(mktemp -d)"', samm)

    def test_runtime_lock_script_writes_atomically(self) -> None:
        script = (ROOT / "scripts" / "regen_runtime_lock.py").read_text(encoding="utf-8")
        self.assertIn("os.replace", script)
        self.assertIn("os.fsync", script)
        # Durcissement revue 6b748c0 : ne jamais suivre un symlink sur le .tmp.
        self.assertIn("is_symlink", script)
        self.assertIn("O_EXCL", script)
        self.assertIn("O_CREAT", script)
        self.assertIn("os.open", script)


class BackupIgnoreTests(unittest.TestCase):
    def test_backup_archives_are_ignored_by_git_and_docker(self) -> None:
        name = "heimdall-backup-2026-11-10.tgz.gpg"
        git = shutil.which("git")
        self.assertIsNotNone(git)
        ignored = subprocess.run(  # noqa: S603
            [git, "check-ignore", "-q", name],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(ignored.returncode, 0, "archive de sauvegarde non ignorée par Git")
        dockerignore = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertIn("heimdall-backup-*.tgz.gpg", dockerignore)


class ReadmeQuickstartTests(unittest.TestCase):
    def test_readme_quickstart_protects_env(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("install -m 600 .env.example .env", text)
        self.assertIn("test ! -e .env", text)
        self.assertIn(".env existe déjà", text)
        self.assertIn("docs/install.md", text)
        self.assertIn("docs/install.md §3", text)
        self.assertIn("docs/install.md §4", text)
        self.assertIn("jamais en root hôte", text)
        self.assertIn('user: "10001:10001"', text)
        self.assertIn("sudo chown -R --no-dereference 10001:10001 data secrets", text)
        self.assertNotIn("HEIMDALL_UID", text)


class HealthcheckTests(unittest.TestCase):
    @staticmethod
    def _response(status: int) -> MagicMock:
        response = MagicMock()
        response.status = status
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        return response

    def test_http_healthcheck_disables_proxies_and_returns_zero_on_200(self) -> None:
        module = _load_healthcheck()
        opener = MagicMock()
        opener.open.return_value = self._response(200)
        with (
            patch.dict("os.environ", {"HEIMDALL_VAULT_PORT": "8443"}, clear=True),
            patch("urllib.request.build_opener", return_value=opener) as build_opener,
        ):
            self.assertEqual(module.main(), 0)
        self.assertIsInstance(build_opener.call_args.args[0], urllib.request.ProxyHandler)
        self.assertEqual(len(build_opener.call_args.args), 1)
        opener.open.assert_called_once_with("http://127.0.0.1:8443/api/v1/health", timeout=2)

    def test_https_healthcheck_verifies_the_local_certificate(self) -> None:
        module = _load_healthcheck()
        opener = MagicMock()
        opener.open.return_value = self._response(200)
        context = MagicMock()
        with (
            patch.dict(
                "os.environ",
                {
                    "HEIMDALL_VAULT_PORT": "9443",
                    "HEIMDALL_VAULT_SSL_CERTFILE": "/run/secrets/cert.pem",
                },
                clear=True,
            ),
            patch("ssl.create_default_context", return_value=context) as create_context,
            patch("urllib.request.build_opener", return_value=opener) as build_opener,
        ):
            self.assertEqual(module.main(), 0)
        create_context.assert_called_once_with(cafile="/run/secrets/cert.pem")
        self.assertIsInstance(build_opener.call_args.args[0], urllib.request.ProxyHandler)
        self.assertIsInstance(build_opener.call_args.args[1], urllib.request.HTTPSHandler)
        opener.open.assert_called_once_with("https://127.0.0.1:9443/api/v1/health", timeout=2)

    def test_healthcheck_rejects_malformed_port_without_reflection(self) -> None:
        module = _load_healthcheck()
        for port in ("", "abc", "0", "65536", "8443/x", "-1"):
            with self.subTest(port=port):
                stderr = io.StringIO()
                with (
                    patch.dict("os.environ", {"HEIMDALL_VAULT_PORT": port}, clear=True),
                    patch("sys.stderr", stderr),
                ):
                    self.assertEqual(module.main(), 1)
                if port:
                    self.assertNotIn(port, stderr.getvalue())

    def test_healthcheck_fails_closed_on_error_or_non_200(self) -> None:
        module = _load_healthcheck()
        opener = MagicMock()
        opener.open.return_value = self._response(503)
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("urllib.request.build_opener", return_value=opener),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(module.main(), 1)
        opener.open.side_effect = OSError("down")
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("urllib.request.build_opener", return_value=opener),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(module.main(), 1)


class EntrypointTests(unittest.TestCase):
    def test_entrypoint_refuses_root(self) -> None:
        module = _load_entrypoint()
        stderr = io.StringIO()
        with (
            patch("os.geteuid", return_value=0),
            patch("os.getegid", return_value=10001),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(module.main(), 1)
        self.assertIn("root", stderr.getvalue())

    def test_entrypoint_refuses_root_group(self) -> None:
        module = _load_entrypoint()
        stderr = io.StringIO()
        with (
            patch("os.geteuid", return_value=10001),
            patch("os.getegid", return_value=0),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(module.main(), 1)
        self.assertIn("root", stderr.getvalue())

    def test_entrypoint_drops_to_the_server_for_non_root(self) -> None:
        module = _load_entrypoint()
        with (
            patch("os.geteuid", return_value=10001),
            patch("os.getegid", return_value=10001),
            patch("os.execvp") as execvp,
        ):
            self.assertEqual(module.main(), 1)
        execvp.assert_called_once()
        self.assertEqual(execvp.call_args.args[1][1:], ["-m", "heimdall.vault.app"])

    def test_entrypoint_exec_failure_is_fail_closed_without_traceback(self) -> None:
        """Vérifie qu'un exec raté reste fail-closed avec message générique."""
        module = _load_entrypoint()
        stderr = io.StringIO()
        with (
            patch("os.geteuid", return_value=10001),
            patch("os.getegid", return_value=10001),
            patch("os.execvp", side_effect=OSError("corrompu")),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(module.main(), 1)
        self.assertIn("démarrage impossible", stderr.getvalue())
        self.assertNotIn("corrompu", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


class GuideApiKeyValidationTests(unittest.TestCase):
    def test_guide_rejects_header_injection_before_writing_the_file(self) -> None:
        guide = INSTALL_GUIDE.read_text(encoding="utf-8")
        self.assertIn("^[A-Za-z0-9_-]{43,}$", guide)
        pattern = re.compile(r"^[A-Za-z0-9_-]{43,}$")
        self.assertIsNotNone(pattern.fullmatch("A" * 43))
        for invalid in ("A" * 42, "A" * 43 + '"', "A" * 43 + "\n", "A" * 43 + "\\"):
            with self.subTest(invalid=repr(invalid)):
                self.assertIsNone(pattern.fullmatch(invalid))


class UidGidGuardTests(unittest.TestCase):
    def test_compose_user_is_pinned_non_root(self) -> None:
        """Prouve que le compose fige un UID non-root, sans variable résolvable en 0."""
        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        user = compose["services"]["vault"]["user"]
        self.assertEqual(user, "10001:10001")
        serialized = COMPOSE.read_text(encoding="utf-8")
        self.assertNotIn("HEIMDALL_UID", serialized)
        self.assertNotIn("HEIMDALL_GID", serialized)
        guide = INSTALL_GUIDE.read_text(encoding="utf-8")
        self.assertIn("10001:10001", guide)
        self.assertIn("sudo chown -R --no-dereference 10001:10001 data secrets", guide)
        self.assertIn('[[ "$(id -u)" != 0 ]]', guide)
        self.assertNotIn("${HEIMDALL_UID", guide)
        self.assertNotIn("HEIMDALL_UID=$(id -u)", guide)

    def test_compose_config_user_resolution_nominal_and_zero(self) -> None:
        """Prouve que même avec HEIMDALL_UID=0, `config` reste en 10001:10001."""
        docker = shutil.which("docker")
        if not docker:
            self.skipTest("docker non disponible")
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            shutil.copy(COMPOSE, workdir / "docker-compose.yml")
            (workdir / ".env").write_text("HEIMDALL_ENV=production\n", encoding="utf-8")
            res_nom = subprocess.run(  # noqa: S603
                [docker, "compose", "config"],
                cwd=workdir,
                capture_output=True,
                text=True,
                check=False,
            )
            if res_nom.returncode == 0:
                self.assertIn("10001", res_nom.stdout)
                self.assertNotIn("0:0", res_nom.stdout)
                (workdir / ".env").write_text(
                    "HEIMDALL_UID=0\nHEIMDALL_GID=0\n",
                    encoding="utf-8",
                )
                res_zero = subprocess.run(  # noqa: S603
                    [docker, "compose", "config"],
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(res_zero.returncode, 0)
                self.assertIn("10001", res_zero.stdout)
                self.assertNotIn("0:0", res_zero.stdout)

    def test_guide_does_not_source_env(self) -> None:
        """Vérifie que le §4 ne source jamais le .env (aucune exécution, aucune fuite)."""
        guide = INSTALL_GUIDE.read_text(encoding="utf-8")
        self.assertNotIn(". ./.env", guide)
        self.assertNotIn("set -a", guide)


if __name__ == "__main__":
    unittest.main()
