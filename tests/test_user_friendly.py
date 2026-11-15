"""Mise en route simplifiée : init, vault init/serve/login, --debug, aide lisible.

Chaque test vérifie aussi la propriété de sécurité associée : aucune valeur
reflétée en --debug, jamais d'écrasement, permissions privées, et la clé
maîtresse jamais transmise au processus lancé par ``heimdall run``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import stat
import subprocess  # nosec B404
import threading
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from cryptography import x509
from typer.testing import CliRunner

from heimdall.cli import diagnostics, vault_setup
from heimdall.cli.main import app
from heimdall.vault.app import VaultSettings, get_settings
from heimdall.vault.atomic import parse_env_file
from heimdall.vault.client import resolve_ca_cert
from heimdall.vault.crypto import generate_loopback_tls_pair

_SECRET = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # noqa: S105 - clé de test Stripe documentée


@pytest.fixture(autouse=True)
def _restore_environment() -> Iterator[None]:
    """``load_server_env`` écrit dans ``os.environ`` : tout est restauré après.

    ``get_settings`` est mis en cache (``lru_cache``) : vidé avant et après,
    sinon les réglages d'un test fuiraient dans les suivants.
    """
    get_settings.cache_clear()
    with patch.dict(os.environ, clear=False):
        yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_home(
    _restore_environment: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """HOME et répertoires XDG isolés : aucun test ne touche la config réelle."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    for name in list(os.environ):
        if name.startswith(("HEIMDALL_VAULT_", "HEIMDALL_API_KEY")) or name in {
            "HEIMDALL_ENV",
            "HEIMDALL_DEBUG",
        }:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(diagnostics, "_debug_flag", False)
    monkeypatch.setattr(diagnostics, "_remembered", None)
    return home


def _git_repo(root: Path, *, secret: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)  # noqa: S603, S607  # nosec B603, B607
    if secret:
        (root / "a.py").write_text(f'KEY = "{_SECRET}"\n', encoding="utf-8")
    return root


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# -- --debug : cause statique et action, jamais de valeur ----------------------


def _repo_with_config(root: Path) -> Path:
    _git_repo(root, secret=False)
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "heimdall.toml").write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)  # noqa: S603, S607  # nosec B603, B607
    subprocess.run(  # noqa: S603  # nosec B603, B607
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],  # noqa: S607
        cwd=root,
        check=True,
    )
    return root


def test_default_error_is_one_static_line_with_debug_hint(tmp_path: Path) -> None:
    repo = _repo_with_config(tmp_path / "repo")
    result = CliRunner().invoke(app, ["cold-start", "--ci", str(repo)])
    assert result.exit_code == 2
    assert result.stderr.strip() == (
        "heimdall scan : scan impossible (erreur d'outillage). "
        "Relancez avec --debug pour afficher la cause."
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["cold-start", "--ci", "--debug"],
        ["--debug", "scan", "--ci"],
        ["scan", "--ci", "--debug"],
    ],
)
def test_debug_shows_static_cause_and_action(tmp_path: Path, argv: list[str]) -> None:
    repo = _repo_with_config(tmp_path / "repo")
    result = CliRunner().invoke(app, [*argv, str(repo)])
    assert result.exit_code == 2
    assert "cause : auto-attestation refusée" in result.stderr
    assert "action : en --ci, passez --config" in result.stderr
    assert "Relancez avec --debug" not in result.stderr


def test_debug_env_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo_with_config(tmp_path / "repo")
    monkeypatch.setenv("HEIMDALL_DEBUG", "1")
    result = CliRunner().invoke(app, ["scan", "--ci", str(repo)])
    assert "cause : auto-attestation refusée" in result.stderr


def test_debug_never_reflects_unexpected_exception_message(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    with patch("heimdall.cli.main.collect", side_effect=RuntimeError(_SECRET)):
        result = CliRunner().invoke(app, ["scan", "--debug", str(repo)])
    assert result.exit_code == 2
    assert "cause : panne inattendue (RuntimeError)" in result.stderr
    assert _SECRET not in result.stderr
    assert _SECRET not in result.output


def test_fix_debug_reports_the_masked_env_cause(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / ".env").write_text("export FOO=bar\n", encoding="utf-8")

    def _validate_all(proposals: object, *, apply: object = None, **_kwargs: object) -> object:
        from heimdall.cli.review import ReviewError  # noqa: PLC0415

        for proposal in proposals:  # type: ignore[attr-defined]
            try:
                apply(proposal)  # type: ignore[operator]
            except BaseException:
                raise ReviewError from None
        raise AssertionError("l'application aurait dû échouer")

    with patch("heimdall.cli.fix.review_proposals", side_effect=_validate_all):
        result = CliRunner().invoke(app, ["fix", "--debug", str(repo)])
    assert result.exit_code == 2
    assert "cause : clé existante invalide ou dangereuse dans .env" in result.stderr
    assert "« export »" in result.stderr
    assert _SECRET not in result.output


def test_fix_without_terminal_explains_why_nothing_changed(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    result = CliRunner().invoke(app, ["fix", str(repo)])
    assert result.exit_code == 1
    assert "Aucun terminal interactif détecté" in result.stderr
    assert (repo / "a.py").read_text(encoding="utf-8") == f'KEY = "{_SECRET}"\n'


# -- Aide lisible -------------------------------------------------------------


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _help(*argv: str) -> str:
    """Aide rendue en texte brut : Rich colore la sortie si la CI force la couleur
    (``FORCE_COLOR``), et les codes ANSI découpent alors ``--debug``."""
    result = CliRunner().invoke(app, [*argv, "--help"], terminal_width=200)
    assert result.exit_code == 0, argv
    return _ANSI.sub("", result.output)


def _all_command_paths(command: object, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    paths = [prefix]
    for name, sub in getattr(command, "commands", {}).items():
        paths.extend(_all_command_paths(sub, (*prefix, name)))
    return paths


def test_help_has_no_internal_ticket_references() -> None:
    root = typer.main.get_command(app)
    offenders = []
    for path in _all_command_paths(root):
        if re.search(r"#\d+|\bticket", _help(*path)):
            offenders.append(" ".join(path) or "heimdall")
    assert offenders == []


def test_root_help_says_where_to_start() -> None:
    output = _help()
    assert "heimdall init" in output
    assert "--debug" in output


def test_project_id_help_is_rendered_in_full() -> None:
    output = _help("vault", "key", "create")
    assert "^{0,63}$" not in output
    assert "minuscules, chiffres" in output


# -- heimdall init --------------------------------------------------------------


def test_init_outside_git_repository(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 2
    assert "n'est pas un dépôt Git" in result.stderr


def test_init_installs_hook_ignores_env_and_scans(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    result = CliRunner().invoke(app, ["init", str(repo)])
    assert result.exit_code == 0, result.output
    assert "hook pre-commit installé" in result.output
    assert (repo / ".git" / "hooks" / "pre-commit").is_file()
    assert ".env" in (repo / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "a.py:1  stripe" in result.output
    assert "heimdall fix" in result.output
    assert _SECRET not in result.output
    # Aucune configuration créée : `scan --ci` reste utilisable sans option.
    assert not (repo / "heimdall.toml").exists()


def test_init_is_idempotent(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo", secret=False)
    (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    assert CliRunner().invoke(app, ["init", str(repo)]).exit_code == 0
    second = CliRunner().invoke(app, ["init", str(repo)])
    assert second.exit_code == 0
    assert ".env déjà ignoré" in second.output
    assert "aucun secret détecté" in second.output
    assert (repo / ".gitignore").read_text(encoding="utf-8") == "node_modules/\n.env\n"


# -- Certificat TLS local -------------------------------------------------------


def test_loopback_certificate_profile() -> None:
    cert_pem, key_pem, expires = generate_loopback_tls_pair()
    cert = x509.load_pem_x509_certificate(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.IPAddress)) == {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert cert.not_valid_after_utc == expires.replace(microsecond=0)
    assert b"PRIVATE KEY" in key_pem


@pytest.mark.parametrize("days", [0, -1, 3651, True])
def test_loopback_certificate_rejects_bad_validity(days: int) -> None:
    with pytest.raises(ValueError, match="durée de validité"):
        generate_loopback_tls_pair(days=days)


def test_generated_certificate_completes_a_verified_tls_handshake(tmp_path: Path) -> None:
    """Le client approuve le certificat généré et vérifie l'IP 127.0.0.1."""
    cert_pem, key_pem, _ = generate_loopback_tls_pair()
    certfile, keyfile = tmp_path / "c.pem", tmp_path / "k.pem"
    certfile.write_bytes(cert_pem)
    keyfile.write_bytes(key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)
    client_ctx = ssl.create_default_context()
    client_ctx.load_verify_locations(cadata=cert_pem.decode("ascii"))
    server_sock, client_sock = socket.socketpair()
    errors: list[BaseException] = []

    def _serve() -> None:
        try:
            with server_ctx.wrap_socket(server_sock, server_side=True) as tls:
                tls.sendall(b"ok")
        except BaseException as exc:  # pragma: no cover - diagnostic du test
            errors.append(exc)

    thread = threading.Thread(target=_serve)
    thread.start()
    with client_ctx.wrap_socket(client_sock, server_hostname="127.0.0.1") as tls:
        assert tls.recv(2) == b"ok"
    thread.join(timeout=10)
    assert errors == []


# -- vault init / serve / login -------------------------------------------------


def test_vault_init_local_writes_private_complete_config(_isolated_home: Path) -> None:
    result = CliRunner().invoke(app, ["vault", "init"])
    assert result.exit_code == 0, result.output
    server_dir = _isolated_home / ".config" / "heimdall" / "server"
    env_file = server_dir / "server.env"
    assert _mode(server_dir) == 0o700
    for name in ("server.env", "tls-cert.pem", "tls-key.pem"):
        assert _mode(server_dir / name) == 0o600
    assert _mode(_isolated_home / ".config" / "heimdall" / "vault-ca.pem") == 0o600
    values = parse_env_file(env_file)
    assert values is not None
    assert values["HEIMDALL_ENV"] == "production"
    assert values["HEIMDALL_VAULT_SSL_KEYFILE"] == str(server_dir / "tls-key.pem")
    # Les valeurs générées passent toutes les validations du serveur
    # (complexité, séparation clé maîtresse / pepper / clé HMAC).
    settings = VaultSettings(
        master_key=values["HEIMDALL_VAULT_MASTER_KEY"],
        kek_salt=values["HEIMDALL_VAULT_KEK_SALT"],
        api_key_pepper=values["HEIMDALL_VAULT_API_KEY_PEPPER"],
        server_hmac_key=values["HEIMDALL_VAULT_SERVER_HMAC_KEY"],
        audit_hmac_key=values["HEIMDALL_VAULT_AUDIT_HMAC_KEY"],
        storage_backend="sqlite",
        db_path=values["HEIMDALL_VAULT_DB_PATH"],
    )
    assert settings.master_key is not None
    # Aucun secret affiché.
    for key in ("HEIMDALL_VAULT_MASTER_KEY", "HEIMDALL_VAULT_API_KEY_PEPPER"):
        assert values[key] not in result.output


def test_vault_init_never_overwrites(_isolated_home: Path) -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    env_file = _isolated_home / ".config" / "heimdall" / "server" / "server.env"
    before = env_file.read_bytes()
    second = CliRunner().invoke(app, ["vault", "init"])
    assert second.exit_code == 1
    assert "déjà initialisé" in second.stderr
    assert env_file.read_bytes() == before


def test_vault_init_refuses_when_a_database_exists(_isolated_home: Path) -> None:
    db = _isolated_home / ".local" / "share" / "heimdall" / "vault.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"existing")
    result = CliRunner().invoke(app, ["vault", "init"])
    assert result.exit_code == 1
    assert "vault.db" in result.stderr
    assert not (_isolated_home / ".config" / "heimdall" / "server").exists()


def test_vault_init_docker_layout(tmp_path: Path) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["vault", "init", "--docker", str(deploy)])
    assert result.exit_code == 0, result.output
    assert _mode(deploy / ".env") == 0o600
    assert _mode(deploy / "secrets") == 0o700
    assert _mode(deploy / "data") == 0o700
    assert _mode(deploy / "secrets" / "vault_tls_key.pem") == 0o600
    values = parse_env_file(deploy / ".env")
    assert values is not None
    assert set(values) == {
        "HEIMDALL_VAULT_MASTER_KEY",
        "HEIMDALL_VAULT_KEK_SALT",
        "HEIMDALL_VAULT_API_KEY_PEPPER",
        "HEIMDALL_VAULT_SERVER_HMAC_KEY",
        "HEIMDALL_VAULT_AUDIT_HMAC_KEY",
    }
    assert "sudo chown -R --no-dereference 10001" in result.output


def test_vault_init_docker_requires_compose_file(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["vault", "init", "--docker", str(tmp_path)])
    assert result.exit_code == 1
    assert "docker-compose.yml" in result.stderr
    assert not (tmp_path / ".env").exists()


def test_vault_serve_without_config_explains_what_to_do() -> None:
    result = CliRunner().invoke(app, ["vault", "serve"])
    assert result.exit_code == 2
    assert "heimdall vault init" in result.stderr


def test_vault_serve_runs_server_with_loaded_config() -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    seen: dict[str, str | None] = {}

    def _fake_run_server() -> None:
        seen["env"] = os.environ.get("HEIMDALL_ENV")
        seen["cert"] = os.environ.get("HEIMDALL_VAULT_SSL_CERTFILE")

    with patch("heimdall.vault.app.run_server", side_effect=_fake_run_server):
        result = CliRunner().invoke(app, ["vault", "serve"])
    assert result.exit_code == 0, result.output
    assert seen["env"] == "production"
    assert seen["cert"] is not None
    assert seen["cert"].endswith("tls-cert.pem")


def test_server_env_does_not_override_explicit_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    monkeypatch.setenv("HEIMDALL_VAULT_DB_PATH", "/explicit/vault.db")
    assert vault_setup.load_server_env() is True
    assert os.environ["HEIMDALL_VAULT_DB_PATH"] == "/explicit/vault.db"


def test_server_env_readable_by_others_is_refused(_isolated_home: Path) -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    env_file = _isolated_home / ".config" / "heimdall" / "server" / "server.env"
    env_file.chmod(0o644)
    with pytest.raises(vault_setup.SetupError, match="0600"):
        vault_setup.load_server_env()


def test_run_never_passes_server_secrets_to_the_child(tmp_path: Path) -> None:
    """`heimdall run` ne charge pas server.env : la clé maîtresse ne fuit pas."""
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    client = MagicMock()
    client.__enter__.return_value = client
    with (
        patch.dict(os.environ, {"HEIMDALL_API_KEY": "A" * 43}),
        patch("heimdall.cli.vault_client._init_client", return_value=client),
        patch(
            "heimdall.cli.vault_client._pull_secrets_from_vault",
            return_value={"APP_TOKEN": "x"},
        ),
        patch("heimdall.cli.vault_client.subprocess.run") as mock_run,
    ):
        mock_run.return_value.returncode = 0
        result = CliRunner().invoke(
            app, ["run", "--project", "demo", "--name", "APP_TOKEN", "--", str(exe)]
        )
    assert result.exit_code == 0, result.output
    child_env = mock_run.call_args.kwargs["env"]
    assert child_env["APP_TOKEN"] == "x"  # noqa: S105 - valeur factice injectée
    assert not any(name.startswith("HEIMDALL_VAULT_") for name in child_env)


def test_key_create_save_writes_client_key_without_printing_it(_isolated_home: Path) -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    result = CliRunner().invoke(app, ["vault", "key", "create", "--project", "demo", "--save"])
    assert result.exit_code == 0, result.output
    key_file = _isolated_home / ".config" / "heimdall" / "vault.key"
    assert _mode(key_file) == 0o600
    raw_key = key_file.read_text(encoding="utf-8").strip()
    assert len(raw_key) >= 32
    assert raw_key not in result.output
    assert "~/.config/heimdall/vault.key" in result.output


def test_key_create_save_never_loses_the_key_when_one_exists(_isolated_home: Path) -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    key_file = _isolated_home / ".config" / "heimdall" / "vault.key"
    key_file.write_text("ancienne\n", encoding="utf-8")
    key_file.chmod(0o600)
    result = CliRunner().invoke(app, ["vault", "key", "create", "--project", "demo", "--save"])
    assert result.exit_code == 0
    assert key_file.read_text(encoding="utf-8") == "ancienne\n"
    # Repli : la nouvelle clé est affichée une fois plutôt que perdue.
    assert "affichée UNE SEULE FOIS" in result.output


def test_vault_login_saves_key_privately(_isolated_home: Path) -> None:
    result = CliRunner().invoke(app, ["vault", "login"], input="cle_api_de_test_0123456789\n")
    assert result.exit_code == 0, result.output
    key_file = _isolated_home / ".config" / "heimdall" / "vault.key"
    assert key_file.read_text(encoding="utf-8") == "cle_api_de_test_0123456789\n"
    assert _mode(key_file) == 0o600
    again = CliRunner().invoke(app, ["vault", "login"], input="autre_cle_0123456789\n")
    assert again.exit_code == 2
    assert "--force" in again.stderr
    forced = CliRunner().invoke(
        app, ["vault", "login", "--force"], input="autre_cle_0123456789\n"
    )
    assert forced.exit_code == 0
    assert key_file.read_text(encoding="utf-8") == "autre_cle_0123456789\n"


@pytest.mark.parametrize("raw", ["", "   \n", "deux mots\n", "a" * 600])
def test_vault_login_rejects_invalid_keys(raw: str) -> None:
    result = CliRunner().invoke(app, ["vault", "login"], input=raw)
    assert result.exit_code == 2
    assert "clé API invalide" in result.stderr


# -- Certificat CA trouvé automatiquement ---------------------------------------


def test_resolve_ca_cert_precedence(
    _isolated_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert resolve_ca_cert() is None
    default = _isolated_home / ".config" / "heimdall" / "vault-ca.pem"
    default.parent.mkdir(parents=True)
    default.write_text("pem", encoding="utf-8")
    assert resolve_ca_cert() == default
    monkeypatch.setenv("HEIMDALL_VAULT_CA_CERT", str(tmp_path / "env.pem"))
    assert resolve_ca_cert() == tmp_path / "env.pem"
    assert resolve_ca_cert(tmp_path / "explicit.pem") == tmp_path / "explicit.pem"


# -- Correctifs de revue ----------------------------------------------------------


@pytest.mark.parametrize("umask", [0o022, 0o002])
def test_vault_init_private_client_dir_under_any_umask(_isolated_home: Path, umask: int) -> None:
    """`~/.config/heimdall` créé en 0700, même sous umask 0002 (groupes privés)."""
    previous = os.umask(umask)
    try:
        result = CliRunner().invoke(app, ["vault", "init"])
    finally:
        os.umask(previous)
    assert result.exit_code == 0, result.output
    assert _mode(_isolated_home / ".config" / "heimdall") == 0o700
    assert _mode(_isolated_home / ".config" / "heimdall" / "server") == 0o700


def test_vault_init_tightens_an_existing_client_dir(_isolated_home: Path) -> None:
    client_dir = _isolated_home / ".config" / "heimdall"
    client_dir.mkdir(parents=True)
    client_dir.chmod(0o775)
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    assert _mode(client_dir) == 0o700


def test_vault_init_rolls_back_on_failure(_isolated_home: Path) -> None:
    """Une écriture qui échoue ne laisse aucun état partiel bloquant la relance."""
    real_write = vault_setup._write_private

    def _fail_on_env(path: Path, content: str | bytes) -> None:
        if path.name == "server.env":
            raise vault_setup.SetupError("échec simulé")
        real_write(path, content)

    with patch.object(vault_setup, "_write_private", side_effect=_fail_on_env):
        failed = CliRunner().invoke(app, ["vault", "init"])
    assert failed.exit_code == 1
    server_dir = _isolated_home / ".config" / "heimdall" / "server"
    assert not server_dir.exists()
    assert not (_isolated_home / ".config" / "heimdall" / "vault-ca.pem").exists()
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0


def test_vault_init_generates_dedicated_audit_key(_isolated_home: Path) -> None:
    """Clé d'audit dédiée : `rotate-kek` reste possible sans migration d'audit."""
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    values = parse_env_file(_isolated_home / ".config" / "heimdall" / "server" / "server.env")
    assert values is not None
    keys = [
        values[name]
        for name in (
            "HEIMDALL_VAULT_MASTER_KEY",
            "HEIMDALL_VAULT_API_KEY_PEPPER",
            "HEIMDALL_VAULT_SERVER_HMAC_KEY",
            "HEIMDALL_VAULT_AUDIT_HMAC_KEY",
        )
    ]
    assert len(set(keys)) == len(keys)


def test_vault_serve_does_not_announce_a_server_that_fails_validation() -> None:
    assert CliRunner().invoke(app, ["vault", "init"]).exit_code == 0
    with patch("heimdall.vault.app.get_settings", side_effect=ValueError("réglage invalide")):
        result = CliRunner().invoke(app, ["vault", "serve"])
    assert result.exit_code == 2
    assert "Vault Heimdall sur" not in result.output
    assert "réglage invalide" in result.stderr


def test_init_refuses_symlinked_root(tmp_path: Path) -> None:
    real = _git_repo(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real)
    result = CliRunner().invoke(app, ["init", str(link)])
    assert result.exit_code == 2
    assert "lien symbolique" in result.stderr
    assert not (real / ".gitignore").exists()
    assert not (real / ".git" / "hooks" / "pre-commit").exists()


def test_init_refuses_empty_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _git_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(app, ["init", ""])
    assert result.exit_code == 2
    assert "vide" in result.stderr
    assert not (repo / ".gitignore").exists()


def test_init_unexpected_scan_failure_exits_two_without_reflection(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    with patch("heimdall.cli.onboarding.collect", side_effect=RuntimeError(_SECRET)):
        result = CliRunner().invoke(app, ["init", "--debug", str(repo)])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "panne inattendue (RuntimeError)" in result.output
    assert _SECRET not in result.output


def test_debug_does_not_leak_into_the_next_invocation(tmp_path: Path) -> None:
    repo = _repo_with_config(tmp_path / "repo")
    first = CliRunner().invoke(app, ["--debug", "scan", "--ci", str(repo)])
    assert "cause :" in first.stderr
    second = CliRunner().invoke(app, ["scan", "--ci", str(repo)])
    assert "cause :" not in second.stderr
    assert "Relancez avec --debug" in second.stderr
