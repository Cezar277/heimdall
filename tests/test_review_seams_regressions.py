"""Régressions des défauts trouvés aux coutures entre modules.

1. ``heimdall fix`` : apostrophe dans un commentaire et échappements simples.
2. ``heimdall cold-start --ci`` avec un ``heimdall.toml`` dans le dépôt.
3. ``GET …/state`` ne déchiffre jamais la valeur.
4. ``format_env_value`` refuse les sauts de ligne.
7. ``VaultSettings`` applique la complexité de la clé maîtresse.
8. Un secret ``rote`` (purgé par F-03) ne bloque plus la rotation de KEK.
9. Un secret ``rote`` ou à l'état corrompu n'est ni déchiffré ni apparié.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
import subprocess  # nosec B404
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from heimdall.cli import fix as fix_module
from heimdall.cli.fix import _extract_secret_for_finding, _find_single_quoted_literal
from heimdall.cli.main import app as cli_app
from heimdall.scanner.finding import Finding
from heimdall.vault import store as vault_store
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.atomic import format_env_value
from heimdall.vault.auth import generate_project_api_key
from heimdall.vault.crypto import (
    ARGON2ID_SALT_BYTES,
    VaultCipher,
    VaultCipherError,
    generate_server_hmac_key,
)
from heimdall.vault.store import InMemorySecretStore, SqliteSecretStore

_KEK = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")
_PEPPER = "p3pp3r_s3rv3r_s3cur3_t0k3n_256_b1ts_v4ult"
_SALT = base64.urlsafe_b64encode(b"A" * ARGON2ID_SALT_BYTES).decode("ascii")


# -- 1. heimdall fix -----------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "marker", "expected"),
    [
        ('API_KEY = "sk_live_1234567890"  # clé d\'API de prod', "#", "sk_live_1234567890"),
        ('const k = "sk_live_1234567890"; // clé d\'API', "//", "sk_live_1234567890"),
        ('URL = "https://x.test/#frag"  # c\'est la prod', "#", "https://x.test/#frag"),
        (r'API_KEY = "ab\"cd1234567890"', "#", 'ab"cd1234567890'),
        (r"API_KEY = 'it\'s_1234567890'", "#", "it's_1234567890"),
        (r'API_KEY = "a\\b1234567890"', "#", "a\\b1234567890"),
    ],
)
def test_literal_finder_ignores_comments_and_decodes_simple_escapes(
    line: str, marker: str, expected: str
) -> None:
    assert _find_single_quoted_literal(line, marker) == expected


@pytest.mark.parametrize(
    ("line", "marker"),
    [
        (r'API_KEY = "a\nb1234567890"', "#"),  # échappement non trivial : ambigu
        (r'API_KEY = "a\x41b1234567890"', "#"),
        (r'API_KEY = r"a\"b1234567890"', "#"),  # chaîne brute : pas de décodage sûr
        ('API_KEY = "a" + "b"', "#"),  # deux littéraux : ambigu
        ('API_KEY = "sk_live_1234567890"  # clé d\'API', None),  # sans marqueur : inchangé
    ],
)
def test_literal_finder_stays_fail_closed(line: str, marker: str | None) -> None:
    assert _find_single_quoted_literal(line, marker) is None


def _finding(file: str) -> Finding:
    return Finding(
        file=file,
        line=1,
        type="generic_api_key",
        entropy=4.5,
        snippet_hash=hashlib.sha256(b"x").hexdigest(),
    )


def test_extract_secret_python_comment_with_apostrophe_is_fixable() -> None:
    source = 'API_KEY = "sk_live_1234567890abcdef"  # clé d\'API de prod\n'
    extracted = _extract_secret_for_finding(source, _finding("app.py"), "API_KEY")
    assert extracted is not None
    literal, plan = extracted
    assert literal == "sk_live_1234567890abcdef"
    assert "sk_live_1234567890abcdef" not in plan.after


def test_extract_secret_decodes_escape_to_match_ast_value() -> None:
    source = 'API_KEY = "sk_live_12\\"34567890abcdef"\n'
    extracted = _extract_secret_for_finding(source, _finding("app.py"), "API_KEY")
    assert extracted is not None
    literal, _ = extracted
    # Valeur décodée (celle que le code verrait), jamais la forme source.
    assert literal == 'sk_live_12"34567890abcdef'


def test_extract_secret_javascript_line_comment_with_apostrophe() -> None:
    source = 'const apiKey = "sk_live_1234567890abcdef"; // clé d\'API\n'
    extracted = _extract_secret_for_finding(source, _finding("app.js"), "API_KEY")
    assert extracted is not None
    assert extracted[0] == "sk_live_1234567890abcdef"


def test_comment_markers_cover_supported_languages() -> None:
    assert set(fix_module._LINE_COMMENT_MARKERS) == set(fix_module.Language)


# -- 2. cold-start --ci ----------------------------------------------------------


def _git_repo_with_config(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)  # noqa: S603, S607  # nosec B603, B607
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "heimdall.toml").write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)  # noqa: S603, S607  # nosec B603, B607
    subprocess.run(  # noqa: S603  # nosec B603, B607
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],  # noqa: S607
        cwd=root,
        check=True,
    )


def test_cold_start_ci_repo_config_still_refused_without_escape_hatch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo_with_config(repo)
    result = CliRunner().invoke(cli_app, ["cold-start", "--ci", str(repo)])
    assert result.exit_code == 2


def test_cold_start_ci_accepts_no_allowlist(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo_with_config(repo)
    result = CliRunner().invoke(cli_app, ["cold-start", "--ci", "--no-allowlist", str(repo)])
    assert result.exit_code == 0, result.output


def test_cold_start_ci_accepts_external_config(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo_with_config(repo)
    external = tmp_path / "external.toml"
    external.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    result = CliRunner().invoke(
        cli_app, ["cold-start", "--ci", "--config", str(external), str(repo)]
    )
    assert result.exit_code == 0, result.output


def test_cold_start_ci_refuses_in_repo_config(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo_with_config(repo)
    result = CliRunner().invoke(
        cli_app, ["cold-start", "--ci", "--config", str(repo / "heimdall.toml"), str(repo)]
    )
    assert result.exit_code == 2


def test_cold_start_config_and_no_allowlist_are_exclusive(tmp_path: Path) -> None:
    external = tmp_path / "external.toml"
    external.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    result = CliRunner().invoke(
        cli_app,
        ["cold-start", "--ci", "--config", str(external), "--no-allowlist", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert "incompatibles" in result.output


# -- 3. /state sans déchiffrement -----------------------------------------------


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_state_endpoint_never_decrypts(
    backend: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs: dict[str, object] = {}
    if backend == "sqlite":
        kwargs = {"storage_backend": "sqlite", "db_path": str(tmp_path / "vault.db")}
    settings = VaultSettings(kek=_KEK, api_key_pepper=_PEPPER, require_auth=True, **kwargs)
    application = create_app(settings)
    client = TestClient(
        application, base_url="http://127.0.0.1:8443", client=("127.0.0.1", 50000)
    )
    api_key = generate_project_api_key()
    application.state.register_api_key(api_key, "myproj")
    headers = {"X-Heimdall-API-Key": api_key}
    created = client.post(
        "/api/v1/secrets",
        json={"project": "myproj", "env": "prod", "name": "TOKEN", "value": "v4lue_42"},
        headers=headers,
    )
    assert created.status_code == 201

    def _forbidden(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise AssertionError("/state ne doit jamais déchiffrer")

    monkeypatch.setattr(vault_store, "_decrypt_record", _forbidden)
    response = client.get("/api/v1/secrets/myproj/prod/TOKEN/state", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "project": "myproj",
        "env": "prod",
        "name": "TOKEN",
        "status": "vaulte",
    }
    assert response.headers["Cache-Control"] == "no-store"
    missing = client.get("/api/v1/secrets/myproj/prod/ABSENT/state", headers=headers)
    assert missing.status_code == 404


# -- 4. format_env_value ----------------------------------------------------------


@pytest.mark.parametrize("value", ["a\nB=injected", "a\rb", "a\r\nb"])
def test_format_env_value_refuses_newlines(value: str) -> None:
    with pytest.raises(ValueError, match="Saut de ligne"):
        format_env_value(value)


def test_format_env_value_still_escapes_shell_characters() -> None:
    assert format_env_value('a"$`\\b') == '"a\\"\\$\\`\\\\b"'


# -- 7. complexité de la clé maîtresse ------------------------------------------


def test_settings_reject_low_diversity_master_key() -> None:
    with pytest.raises(ValidationError, match="diversité insuffisante"):
        VaultSettings(master_key="a" * 32, kek_salt=_SALT, api_key_pepper=_PEPPER)


def test_settings_short_master_key_message_states_256_bits() -> None:
    with pytest.raises(ValidationError, match="256 bits"):
        VaultSettings(master_key="Ab1-" * 4, kek_salt=_SALT, api_key_pepper=_PEPPER)


# -- 8/9. secrets rotés : rotation de KEK et détection de fuite -----------------

_HMAC_KEY = generate_server_hmac_key()


def _cipher() -> VaultCipher:
    return VaultCipher.from_encoded_key(generate_server_hmac_key(), server_hmac_key=_HMAC_KEY)


def _store(
    backend: str, tmp_path: Path, cipher: VaultCipher
) -> InMemorySecretStore | SqliteSecretStore:
    if backend == "memory":
        return InMemorySecretStore(cipher=cipher)
    return SqliteSecretStore(tmp_path / "vault.db", cipher)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_kek_rotation_succeeds_with_a_rote_secret(backend: str, tmp_path: Path) -> None:
    old = _cipher()
    store = _store(backend, tmp_path, old)

    async def scenario() -> None:
        await store.create("p", "dev", "OLD", "valeur_old_1234")
        await store.create("p", "dev", "LIVE", "valeur_live_1234")
        await store.transition("p", "dev", "OLD", "rote")
        new = _cipher()
        # Seul le secret vivant est réenveloppé ; le roté purgé n'est pas compté.
        assert await store.rotate_kek(new, old_cipher=old) == 1
        live = await store.get("p", "dev", "LIVE")
        assert live is not None
        assert live["value"] == "valeur_live_1234"
        assert await store.get_state("p", "dev", "OLD") == {
            "project": "p",
            "env": "dev",
            "name": "OLD",
            "status": "rote",
        }
        # Une seconde rotation reste possible (la version du roté a suivi).
        assert await store.rotate_kek(_cipher(), old_cipher=new) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_kek_rotation_with_only_rote_secrets_is_a_noop(backend: str, tmp_path: Path) -> None:
    """Uniquement des rotés purgés : aucune écriture, store toujours utilisable."""
    old = _cipher()
    store = _store(backend, tmp_path, old)

    async def scenario() -> None:
        await store.create("p", "dev", "OLD", "valeur_old_1234")
        await store.transition("p", "dev", "OLD", "rote")
        before_version = store.kek_version
        assert await store.rotate_kek(_cipher(), old_cipher=old) == 0
        assert store.kek_version == before_version
        if isinstance(store, SqliteSecretStore):
            with closing(sqlite3.connect(store.db_path)) as conn:
                (db_version,) = conn.execute("SELECT MAX(kek_version) FROM secrets").fetchone()
            assert db_version == before_version
        # Le store n'est pas désynchronisé : une création reste possible.
        await store.create("p", "dev", "NEW", "valeur_new_1234")
        created = await store.get("p", "dev", "NEW")
        assert created is not None
        assert created["value"] == "valeur_new_1234"

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_kek_rotation_with_only_legacy_rows_still_refused(backend: str, tmp_path: Path) -> None:
    old = _cipher()
    store = _store(backend, tmp_path, old)

    async def scenario() -> None:
        await store.create("p", "dev", "OLD", "valeur_old_1234")
        await store.transition("p", "dev", "OLD", "rote")
        await store.create("p", "dev", "LEGACY", "valeur_legacy_1234")
        if isinstance(store, InMemorySecretStore):
            store._secrets[("p", "dev", "LEGACY")]["encrypted_dek"] = None
        else:
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("UPDATE secrets SET encrypted_dek = NULL WHERE name = 'LEGACY'")
                conn.commit()
        with pytest.raises(VaultCipherError, match="sans enveloppe de DEK"):
            await store.rotate_kek(_cipher(), old_cipher=old)

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_kek_rotation_still_refuses_legacy_rows_without_dek(
    backend: str, tmp_path: Path
) -> None:
    old = _cipher()
    store = _store(backend, tmp_path, old)

    async def scenario() -> None:
        await store.create("p", "dev", "LEGACY", "valeur_legacy_1234")
        if isinstance(store, InMemorySecretStore):
            store._secrets[("p", "dev", "LEGACY")]["encrypted_dek"] = None
        else:
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("UPDATE secrets SET encrypted_dek = NULL")
                conn.commit()
        with pytest.raises(VaultCipherError, match="sans enveloppe de DEK"):
            await store.rotate_kek(_cipher(), old_cipher=old)

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_leak_detection_ignores_rote_secrets(backend: str, tmp_path: Path) -> None:
    cipher = _cipher()
    store = _store(backend, tmp_path, cipher)

    async def scenario() -> None:
        await store.create("p", "dev", "OLD", "valeur_fuitee_1234")
        await store.create("p", "prod", "LIVE", "valeur_fuitee_1234")
        aad = VaultCipher.aad("p", "dev", "OLD")
        old_fp = cipher.fingerprint(b"valeur_fuitee_1234", aad=aad)
        await store.transition("p", "dev", "OLD", "rote")
        assert not await store.is_secret_value_matching("p", "dev", "OLD", "valeur_fuitee_1234")
        assert await store.is_secret_value_matching("p", "prod", "LIVE", "valeur_fuitee_1234")
        matches = await store.find_secrets_matching_value("p", "valeur_fuitee_1234")
        assert [(m["env"], m["name"]) for m in matches] == [("prod", "LIVE")]
        assert await store.find_secrets_by_fingerprint("p", old_fp) == []

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("corrupted", [" ROTE ", "Rote", "corrompu"])
def test_get_on_purged_secret_with_corrupted_status_is_404_not_500(
    backend: str, corrupted: str, tmp_path: Path
) -> None:
    kwargs: dict[str, object] = {}
    if backend == "sqlite":
        kwargs = {"storage_backend": "sqlite", "db_path": str(tmp_path / "vault.db")}
    settings = VaultSettings(kek=_KEK, api_key_pepper=_PEPPER, require_auth=True, **kwargs)
    application = create_app(settings)
    client = TestClient(
        application, base_url="http://127.0.0.1:8443", client=("127.0.0.1", 50000)
    )
    api_key = generate_project_api_key()
    application.state.register_api_key(api_key, "myproj")
    headers = {"X-Heimdall-API-Key": api_key}
    created = client.post(
        "/api/v1/secrets",
        json={"project": "myproj", "env": "prod", "name": "TOKEN", "value": "v4lue_42"},
        headers=headers,
    )
    assert created.status_code == 201
    store = application.state.secret_store
    asyncio.run(store.transition("myproj", "prod", "TOKEN", "rote"))
    if isinstance(store, InMemorySecretStore):
        store._secrets[("myproj", "prod", "TOKEN")]["status"] = corrupted
    else:
        with closing(sqlite3.connect(store.db_path)) as conn:
            conn.execute("PRAGMA ignore_check_constraints = ON;")
            conn.execute("UPDATE secrets SET status = ?", (corrupted,))
            conn.commit()
    response = client.get("/api/v1/secrets/myproj/prod/TOKEN", headers=headers)
    assert response.status_code == 404
