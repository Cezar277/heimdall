"""Tests statiques des livrables Docker T41 (#119/#120/#121/#122).

Aucun démon Docker n'est requis : ces tests vérifient les invariants de
sécurité des fichiers livrés (Dockerfile, compose, .dockerignore, lock runtime,
guide) et le healthcheck. Le test à froid réel est archivé dans
``docs/t122-cold-test.md``.
"""

from __future__ import annotations

import importlib.util
import io
import unittest
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


def _load_healthcheck():
    spec = importlib.util.spec_from_file_location("heimdall_docker_healthcheck", HEALTHCHECK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DockerfileSecurityTests(unittest.TestCase):
    def test_image_is_multi_stage_and_pinned(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertEqual(text.count("FROM python:3.12-slim"), 2)
        self.assertIn("AS builder", text)
        self.assertIn("AS runtime", text)
        self.assertIn("--require-hashes", text)
        self.assertIn("--no-deps", text)
        self.assertIn("--no-build-isolation", text)

    def test_image_runs_as_non_root_and_has_healthcheck(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("USER 10001:10001", text)
        self.assertIn("HEALTHCHECK", text)
        self.assertIn('ENTRYPOINT ["python", "-m", "heimdall.vault.app"]', text)
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

    def test_container_is_hardened(self) -> None:
        self.assertIs(self.service["read_only"], True)
        self.assertEqual(self.service["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", self.service["security_opt"])
        self.assertIn("HEIMDALL_UID", self.service["user"])
        self.assertIn("HEIMDALL_GID", self.service["user"])
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
        for package in ("fastapi", "cryptography", "argon2-cffi", "setuptools"):
            with self.subTest(package=package):
                self.assertRegex(text, rf"(?m)^{package}==")


class InstallGuideTests(unittest.TestCase):
    def test_guide_covers_the_cold_start_path(self) -> None:
        text = INSTALL_GUIDE.read_text(encoding="utf-8")
        for expected in (
            "docker compose up -d --build",
            "curl --cacert secrets/vault_tls_cert.pem",
            "heimdall vault key create --project demo",
            "heimdall scan",
            "docs/t122-cold-test.md",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


class HealthcheckTests(unittest.TestCase):
    def test_http_healthcheck_returns_zero_on_200(self) -> None:
        module = _load_healthcheck()
        response = MagicMock()
        response.status = 200
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        with (
            patch.dict("os.environ", {"HEIMDALL_VAULT_PORT": "8443"}, clear=True),
            patch("urllib.request.urlopen", return_value=response) as urlopen,
        ):
            self.assertEqual(module.main(), 0)
        urlopen.assert_called_once_with(
            "http://127.0.0.1:8443/api/v1/health", timeout=2, context=None
        )

    def test_https_healthcheck_verifies_the_local_certificate(self) -> None:
        module = _load_healthcheck()
        response = MagicMock()
        response.status = 200
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
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
            patch("urllib.request.urlopen", return_value=response) as urlopen,
        ):
            self.assertEqual(module.main(), 0)
        create_context.assert_called_once_with(cafile="/run/secrets/cert.pem")
        urlopen.assert_called_once_with(
            "https://127.0.0.1:9443/api/v1/health", timeout=2, context=context
        )

    def test_healthcheck_fails_closed_on_error_or_non_200(self) -> None:
        module = _load_healthcheck()
        response = MagicMock()
        response.status = 503
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("urllib.request.urlopen", return_value=response),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(module.main(), 1)
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("urllib.request.urlopen", side_effect=OSError("down")),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(module.main(), 1)


if __name__ == "__main__":
    unittest.main()
