"""API de transition d'état du Vault (ticket #117).

Preuves couvertes :
- transition valide ``vaulte -> rote`` acceptée (200, ``no-store``), sans
  valeur ni acteur dans la réponse ;
- transitions interdites/reflexives, cibles inconnues et corps hors contrat
  refusés en 400 statique, sans reflet de l'entrée ;
- authentification 401, isolement projet 403 et ressource absente 404,
  décidés avant toute écriture ;
- journal atomique (acteur, horodatage, ancien état, nouvel état) sur les deux
  backends, sans valeur de secret ni empreinte ;
- terminalité de ``rote`` et non-régression de la lecture de l'ancienne valeur ;
- rétention bornée du journal et concurrence sur la transition.
"""

import asyncio
import inspect
import logging
import sqlite3
import threading
from collections import deque
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import heimdall.vault.database as database_module
import heimdall.vault.store as store_module
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import VaultCipher, generate_api_key
from heimdall.vault.database import DEFAULT_TRANSITION_LIST_LIMIT, TransitionConcurrencyError
from heimdall.vault.store import InMemorySecretStore, SqliteSecretStore
from heimdall.vault.transitions import InvalidTransitionError

_CANARY = "PLACEHOLDER_TRANSITION_CANARY_NEVER_RETURNED"
_PROJECT = "demo"
_ENV = "dev"
_NAME = "DEMO_TRANSITION"
_CREATE = "/api/v1/secrets"
_RESOURCE = f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}"
_TRANSITION = f"{_RESOURCE}/transition"
_STATE = f"{_RESOURCE}/state"
_BAD_REQUEST = {"code": "bad_request", "message": "Requête invalide"}
_NOT_FOUND = {"code": "not_found", "message": "Ressource introuvable"}
_UNAUTHORIZED = {"code": "unauthorized", "message": "Authentification requise"}
_FORBIDDEN = {"code": "forbidden", "message": "Accès interdit"}


@pytest.fixture(params=["memory", "sqlite"])
def vault(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[TestClient]:
    """Application neuve par test, store mémoire ou SQLite temporaire."""
    cipher = VaultCipher.generate()
    if request.param == "sqlite":
        store: InMemorySecretStore | SqliteSecretStore = SqliteSecretStore(
            tmp_path / "vault.db", cipher
        )
    else:
        store = InMemorySecretStore(cipher=cipher)
    app = create_app(
        VaultSettings(
            storage_backend=request.param,
            db_path=str(tmp_path / "vault.db"),
            api_key_pepper=generate_api_key(),
            rate_limit_per_key=10_000,
            rate_limit_per_peer=20_000,
            rate_limit_global=30_000,
        ),
        secret_store=store,
    )
    key = generate_api_key()
    app.state.register_api_key(key, _PROJECT)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        client.headers["X-Heimdall-API-Key"] = key
        yield client


def _create(client: TestClient, name: str = _NAME) -> None:
    response = client.post(
        _CREATE,
        json={"project": _PROJECT, "env": _ENV, "name": name, "value": _CANARY},
    )
    assert response.status_code == 201
    assert _CANARY not in response.text


def _transitions(client: TestClient, name: str = _NAME) -> list[dict[str, str]]:
    """Lit le journal sans traverser une boucle asyncio déjà utilisée par le client."""
    store = client.app.state.secret_store
    if isinstance(store, InMemorySecretStore):
        return [
            dict(entry)
            for entry in store._transitions.get(_PROJECT, ())
            if entry["env"] == _ENV and entry["name"] == name
        ]
    with closing(sqlite3.connect(store.db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT project_id AS project, env, name, actor, occurred_at, "
            "previous_status, new_status AS status "
            "FROM secret_transitions "
            "WHERE project_id = ? AND env = ? AND name = ? ORDER BY id ASC",
            (_PROJECT, _ENV, name),
        ).fetchall()
    return [dict(row) for row in rows]


async def _list_journal_entries(
    store: InMemorySecretStore | SqliteSecretStore,
    project: str,
    env: str,
    name: str,
    limit: int = DEFAULT_TRANSITION_LIST_LIMIT,
) -> list[dict[str, str]]:
    """Lit le journal via les helpers privés des deux backends (diagnostics tests)."""
    if isinstance(store, InMemorySecretStore):
        return await store._list_transitions(project, env, name, limit)
    return store._list_transitions(project, env, name, limit)


def test_valid_transition_changes_state_and_returns_metadata_only(vault: TestClient) -> None:
    _create(vault)
    response = vault.post(_TRANSITION, json={"target_status": "rote"})

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {
        "project": _PROJECT,
        "env": _ENV,
        "name": _NAME,
        "previous_status": "vaulte",
        "status": "rote",
    }
    assert _CANARY not in response.text
    assert "actor" not in response.json()

    state = vault.get(_STATE)
    assert state.status_code == 200
    assert state.json()["status"] == "rote"

    # Un secret roté ne restitue jamais l'ancienne valeur.
    old_value = vault.get(_RESOURCE)
    assert old_value.status_code == 404
    assert old_value.json() == _NOT_FOUND
    assert _CANARY not in old_value.text


def test_rote_clears_encrypted_value_and_dek(vault: TestClient) -> None:
    """Audit F-03 : la valeur chiffrée et la DEK sont effacées à la transition rote."""
    _create(vault)
    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200
    store = vault.app.state.secret_store
    if isinstance(store, InMemorySecretStore):
        record = store._secrets[(_PROJECT, _ENV, _NAME)]
        assert record["encrypted_value"] == ""
        assert record["encrypted_dek"] is None
    else:
        with closing(sqlite3.connect(store.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT encrypted_value, encrypted_dek FROM secrets "
                "WHERE project_id = ? AND env = ? AND name = ?",
                (_PROJECT, _ENV, _NAME),
            ).fetchone()
        assert row is not None
        assert row["encrypted_value"] == ""
        assert row["encrypted_dek"] is None


def test_rote_value_cannot_be_resurrected_by_a_status_flip(vault: TestClient) -> None:
    """Audit F-03 : même en repassant le statut à vaulte, l'ancienne valeur est vide."""
    _create(vault)
    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200
    store = vault.app.state.secret_store
    if isinstance(store, InMemorySecretStore):
        store._secrets[(_PROJECT, _ENV, _NAME)]["status"] = "vaulte"
    else:
        with closing(sqlite3.connect(store.db_path)) as connection:
            connection.execute(
                "UPDATE secrets SET status = 'vaulte' "
                "WHERE project_id = ? AND env = ? AND name = ?",
                (_PROJECT, _ENV, _NAME),
            )
            connection.commit()
    response = vault.get(_RESOURCE)
    assert response.status_code != 200
    assert _CANARY not in response.text


def test_transition_journal_contains_actor_timestamp_and_states(vault: TestClient) -> None:
    _create(vault)
    key_id = vault.app.state.api_key_registry.list_entries()[0].key_id

    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200
    entries = _transitions(vault)

    assert len(entries) == 1
    entry = entries[0]
    assert entry["project"] == _PROJECT
    assert entry["env"] == _ENV
    assert entry["name"] == _NAME
    assert entry["actor"] == key_id
    assert entry["actor"].startswith("key_")
    assert entry["previous_status"] == "vaulte"
    assert entry["status"] == "rote"
    assert entry["occurred_at"]
    assert _CANARY not in str(entry)


def test_reflexive_and_forbidden_transitions_are_400_without_mutation(vault: TestClient) -> None:
    _create(vault)

    forbidden_targets = ["vaulte", "detecte", "confirme", "faux_positif"]
    for target in forbidden_targets:
        response = vault.post(_TRANSITION, json={"target_status": target})
        assert response.status_code == 400
        assert response.json() == _BAD_REQUEST
        assert target not in response.text
        assert _CANARY not in response.text

    assert vault.get(_STATE).json()["status"] == "vaulte"
    assert _transitions(vault) == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"target_status": "unknown"},
        {"target_status": ""},
        {"target_status": None},
        {"target_status": "ROTE"},
        {"target_status": " rote "},
        {"source_status": "vaulte", "target_status": "rote"},
        {"target_status": "rote", "actor": "attacker"},
    ],
)
def test_invalid_transition_body_is_400_without_reflection(
    vault: TestClient, body: dict[str, object]
) -> None:
    _create(vault)
    response = vault.post(_TRANSITION, json=body)
    assert response.status_code == 400
    assert response.json() == _BAD_REQUEST
    assert _CANARY not in response.text
    for value in body.values():
        if isinstance(value, str) and value:
            assert value not in response.text
    assert vault.get(_STATE).json()["status"] == "vaulte"
    assert _transitions(vault) == []


@pytest.mark.parametrize(
    "target",
    [
        "sk_live_51H8xkZK2eZvKYloR0000SECRETvalue",
        "0" * 64,
        "AKIAIOSFODNN7EXAMPLE",
        "key_" + "0" * 32,
    ],
)
def test_hostile_target_status_is_400_static_without_reflection(
    vault: TestClient, target: str
) -> None:
    """Une cible qui *ressemble* à un secret ou à une clé est refusée sans être reflétée.

    Ces valeurs ne sont pas des états du cycle de vie : elles doivent être
    refusées en 400 statique, sans reflet de l'entrée ni de la valeur du
    secret, et sans effet de bord (état et journal inchangés).
    """
    _create(vault)
    response = vault.post(_TRANSITION, json={"target_status": target})
    assert response.status_code == 400
    assert response.json() == _BAD_REQUEST
    assert target not in response.text
    assert _CANARY not in response.text
    assert vault.get(_STATE).json()["status"] == "vaulte"
    assert _transitions(vault) == []


def test_authentication_and_project_isolation_precede_any_write(vault: TestClient) -> None:
    _create(vault)
    owner_key = vault.headers["X-Heimdall-API-Key"]

    vault.headers.pop("X-Heimdall-API-Key")
    anonymous = vault.post(_TRANSITION, json={"target_status": "rote"})
    assert anonymous.status_code == 401
    assert anonymous.json() == _UNAUTHORIZED
    assert anonymous.headers["Cache-Control"] == "no-store"

    other_key = generate_api_key()
    vault.app.state.register_api_key(other_key, "other")
    forbidden = vault.post(
        _TRANSITION,
        json={"target_status": "rote"},
        headers={"X-Heimdall-API-Key": other_key},
    )
    assert forbidden.status_code == 403
    assert forbidden.json() == _FORBIDDEN
    assert forbidden.headers["Cache-Control"] == "no-store"

    vault.headers["X-Heimdall-API-Key"] = owner_key
    assert vault.get(_STATE).json()["status"] == "vaulte"
    assert _transitions(vault) == []


def test_missing_secret_is_404_and_creates_no_journal_entry(vault: TestClient) -> None:
    response = vault.post(_TRANSITION, json={"target_status": "rote"})
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert response.headers["Cache-Control"] == "no-store"
    assert _transitions(vault) == []


def test_rote_is_terminal(vault: TestClient) -> None:
    _create(vault)
    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200

    for target in ("rote", "vaulte", "detecte", "confirme", "faux_positif"):
        response = vault.post(_TRANSITION, json={"target_status": target})
        assert response.status_code == 400
        assert response.json() == _BAD_REQUEST
    assert len(_transitions(vault)) == 1


def test_invalid_path_is_400(vault: TestClient) -> None:
    response = vault.post(
        "/api/v1/secrets/BAD!/dev/DEMO_TRANSITION/transition",
        json={"target_status": "rote"},
    )
    assert response.status_code == 400
    assert response.json() == _BAD_REQUEST


def test_journal_survives_secret_deletion(vault: TestClient) -> None:
    _create(vault)
    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200
    assert vault.delete(_RESOURCE).status_code == 204

    entries = _transitions(vault)
    assert len(entries) == 1
    assert entries[0]["previous_status"] == "vaulte"
    assert entries[0]["status"] == "rote"
    assert vault.post(_TRANSITION, json={"target_status": "rote"}).status_code == 404


def test_actor_is_normalized_and_never_taken_from_request() -> None:
    async def scenario() -> None:
        store = InMemorySecretStore()
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        record = await store.transition(
            _PROJECT,
            _ENV,
            _NAME,
            "rote",
            actor="forged\nactor_not_a_key",
        )
        assert record is not None
        assert record["actor"] == "unknown"
        entries = await store._list_transitions(_PROJECT, _ENV, _NAME)
        assert entries[0]["actor"] == "unknown"
        assert "forged" not in str(entries)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "actor",
    [
        "forged\nactor_not_a_key",
        "'; DROP TABLE secret_transitions; --",
        "actor' OR '1'='1",
        _CANARY,
    ],
)
def test_hostile_actor_is_normalized_to_unknown_and_never_persisted(actor: str) -> None:
    """Un acteur hostile (saut de ligne, injection SQL, clé brute) retombe sur ``unknown``.

    L'acteur interne est toujours normalisé avant écriture : seule la forme
    ``key_<32 hex>`` est acceptée, tout le reste devient ``unknown``. Ni la
    valeur du secret ni l'acteur forgé ne doivent atteindre le journal.
    """

    async def scenario() -> None:
        store = InMemorySecretStore()
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        record = await store.transition(_PROJECT, _ENV, _NAME, "rote", actor=actor)
        assert record is not None
        assert record["actor"] == "unknown"
        entries = await store._list_transitions(_PROJECT, _ENV, _NAME)
        assert entries[0]["actor"] == "unknown"
        journal = str(entries)
        assert _CANARY not in journal
        assert "forged" not in journal
        assert "DROP TABLE" not in journal
        assert "1'='1" not in journal

    asyncio.run(scenario())


def test_concurrent_transitions_accept_exactly_one(vault: TestClient) -> None:
    _create(vault)
    barrier = threading.Barrier(2)

    def transition_once() -> int:
        barrier.wait()
        return vault.post(_TRANSITION, json={"target_status": "rote"}).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = sorted(executor.map(lambda _: transition_once(), range(2)))

    assert statuses == [200, 400]
    entries = _transitions(vault)
    assert len(entries) == 1
    assert entries[0]["status"] == "rote"


def test_memory_journal_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_module, "MAX_SECRET_TRANSITIONS", 2)

    async def scenario() -> None:
        store = InMemorySecretStore()
        for index in range(3):
            name = f"DEMO_{index}"
            await store.create(_PROJECT, _ENV, name, _CANARY)
            assert await store.transition(_PROJECT, _ENV, name, "rote") is not None
        assert isinstance(store._transitions, dict)
        journal = store._transitions[_PROJECT]
        assert isinstance(journal, deque)
        assert len(journal) == 2
        assert [entry["name"] for entry in journal] == ["DEMO_1", "DEMO_2"]
        await store.clear()
        assert store._transitions == {}

    asyncio.run(scenario())


def test_sqlite_journal_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(database_module, "MAX_SECRET_TRANSITIONS", 2)
    store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())

    async def scenario() -> None:
        for index in range(3):
            name = f"DEMO_{index}"
            await store.create(_PROJECT, _ENV, name, _CANARY)
            assert await store.transition(_PROJECT, _ENV, name, "rote") is not None
        with closing(sqlite3.connect(store.db_path)) as connection:
            rows = connection.execute(
                "SELECT project_id, env, name, actor, previous_status, new_status "
                "FROM secret_transitions ORDER BY id ASC"
            ).fetchall()
        assert rows == [
            (_PROJECT, _ENV, "DEMO_1", "unknown", "vaulte", "rote"),
            (_PROJECT, _ENV, "DEMO_2", "unknown", "vaulte", "rote"),
        ]
        assert store._list_transitions(_PROJECT, _ENV, "DEMO_1") != []
        assert store._list_transitions(_PROJECT, _ENV, "DEMO_0") == []
        await store.clear()
        assert store._list_transitions(_PROJECT, _ENV, "DEMO_1") == []

    asyncio.run(scenario())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_journal_purge_emits_warning_without_secret(
    backend: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Une éviction mémoire ou SQLite alerte sans journaliser de secret."""
    monkeypatch.setattr(store_module, "MAX_SECRET_TRANSITIONS", 2)
    monkeypatch.setattr(database_module, "MAX_SECRET_TRANSITIONS", 2)

    async def scenario() -> None:
        store: InMemorySecretStore | SqliteSecretStore
        if backend == "memory":
            store = InMemorySecretStore()
        else:
            store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())
        for index in range(3):
            name = f"DEMO_{index}"
            await store.create(_PROJECT, _ENV, name, _CANARY)
            assert await store.transition(_PROJECT, _ENV, name, "rote") is not None
        await store.clear()

    with caplog.at_level(logging.WARNING):
        asyncio.run(scenario())

    purge_records = [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING
        and "Rétention du journal de transitions" in record.getMessage()
    ]
    assert len(purge_records) == 1
    assert _PROJECT in purge_records[0].getMessage()
    assert _CANARY not in caplog.text
    assert "key_" not in caplog.text


def test_journal_maintenance_helpers_are_private_test_only() -> None:
    """Le journal ne doit être lisible/supprimable que par des helpers privés."""
    assert not hasattr(database_module, "list_secret_transitions")
    assert not hasattr(database_module, "delete_all_secret_transitions")
    assert database_module._list_secret_transitions.__name__.startswith("_")
    assert database_module._delete_all_secret_transitions.__name__.startswith("_")
    # Les stores ne doivent exposer aucun lecteur/effaceur de journal public :
    # la frontière « test-only » est matérialisée par le préfixe privé.
    assert not hasattr(InMemorySecretStore, "list_transitions")
    assert not hasattr(SqliteSecretStore, "list_transitions")
    assert InMemorySecretStore._list_transitions.__name__.startswith("_")
    assert SqliteSecretStore._list_transitions.__name__.startswith("_")


def test_journal_listing_is_bounded() -> None:
    async def scenario() -> None:
        store = InMemorySecretStore()
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        await store.transition(_PROJECT, _ENV, _NAME, "rote")
        for limit in (0, -1, 1_001, True):
            with pytest.raises(ValueError, match="hors bornes"):
                await store._list_transitions(_PROJECT, _ENV, _NAME, limit)

    asyncio.run(scenario())


def test_sqlite_journal_never_contains_secret_value_or_fingerprint(
    tmp_path: Path,
) -> None:
    store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())

    async def scenario() -> None:
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        await store.transition(_PROJECT, _ENV, _NAME, "rote")
        with closing(sqlite3.connect(store.db_path)) as connection:
            columns = [
                row[1]
                for row in connection.execute("PRAGMA table_info(secret_transitions)")
            ]
            rows = connection.execute("SELECT * FROM secret_transitions").fetchall()
        assert columns == [
            "id",
            "occurred_at",
            "project_id",
            "env",
            "name",
            "actor",
            "previous_status",
            "new_status",
        ]
        assert len(rows) == 1
        serialized = repr(rows)
        assert _CANARY not in serialized
        assert "fingerprint" not in serialized

    asyncio.run(scenario())


def test_transition_uses_server_side_source_state(tmp_path: Path) -> None:
    """Le store ignore tout état source : seule la valeur lue en base compte."""
    cipher = VaultCipher.generate()
    store = SqliteSecretStore(tmp_path / "vault.db", cipher)

    async def scenario() -> None:
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        result = await store.transition(_PROJECT, _ENV, _NAME, "rote")
        assert result is not None
        assert result["previous_status"] == "vaulte"
        assert result["status"] == "rote"
        # La signature n'accepte pas d'état source ; un appel direct répété
        # échoue sur l'état réellement persisté (rote terminal).
        with pytest.raises(InvalidTransitionError):
            await store.transition(_PROJECT, _ENV, _NAME, "vaulte")

    asyncio.run(scenario())


def test_journal_retention_is_isolated_by_project(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Une inondation dans un projet n'évince pas le journal d'un autre projet."""
    monkeypatch.setattr(store_module, "MAX_SECRET_TRANSITIONS", 2)
    monkeypatch.setattr(database_module, "MAX_SECRET_TRANSITIONS", 2)

    async def scenario() -> None:
        memory = InMemorySecretStore()
        sqlite = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())
        for store in (memory, sqlite):
            # « other » écrit d'abord, puis « demo » inonde son propre journal.
            for index in range(2):
                name = f"OTHER_{index}"
                await store.create("other", _ENV, name, _CANARY)
                assert await store.transition("other", _ENV, name, "rote") is not None
            for index in range(3):
                name = f"DEMO_{index}"
                await store.create(_PROJECT, _ENV, name, _CANARY)
                assert await store.transition(_PROJECT, _ENV, name, "rote") is not None

            # Les deux entrées de « other » survivent à l'inondation de « demo ».
            assert len(await _list_journal_entries(store, "other", _ENV, "OTHER_0")) == 1
            assert len(await _list_journal_entries(store, "other", _ENV, "OTHER_1")) == 1
            # La borne s'applique au projet « demo » lui-même.
            assert await _list_journal_entries(store, _PROJECT, _ENV, "DEMO_0") == []
            assert len(await _list_journal_entries(store, _PROJECT, _ENV, "DEMO_2")) == 1
            # Aucune lecture croisée : « demo » ne voit pas le journal de « other ».
            assert await _list_journal_entries(store, _PROJECT, _ENV, "OTHER_0") == []
            assert await _list_journal_entries(store, "other", _ENV, "DEMO_2") == []

        await memory.clear()
        await sqlite.clear()

    asyncio.run(scenario())


def test_transition_concurrency_error_maps_to_static_400(
    vault: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un CAS perdant remonte un 400 statique, sans fuite ni mutation."""
    _create(vault)
    store = vault.app.state.secret_store

    async def losing_transition(**_: object) -> dict[str, str] | None:
        raise TransitionConcurrencyError("Concurrence détectée sur la transition d'état.")

    monkeypatch.setattr(store, "transition", losing_transition)
    response = vault.post(_TRANSITION, json={"target_status": "rote"})

    assert response.status_code == 400
    assert response.json() == _BAD_REQUEST
    assert _CANARY not in response.text
    assert "Concurrence" not in response.text
    assert vault.get(_STATE).json()["status"] == "vaulte"
    assert _transitions(vault) == []


def test_transition_secret_rejects_lost_compare_and_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force ``rowcount != 1`` : la transition lève sans écrire de journal."""

    class _FakeCursor:
        def __init__(self, row: dict[str, str] | None = None, rowcount: int = 0) -> None:
            self._row = row
            self.rowcount = rowcount

        def fetchone(self) -> dict[str, str] | None:
            return self._row

    class _FakeConnection:
        def __init__(self) -> None:
            self.statements: list[str] = []

        def execute(self, sql: str, params: tuple[object, ...] = ()) -> _FakeCursor:
            self.statements.append(sql)
            if "SELECT status FROM secrets" in sql:
                return _FakeCursor({"status": "vaulte"})
            if sql.startswith("UPDATE secrets SET status"):
                return _FakeCursor(rowcount=0)
            raise AssertionError(f"requête inattendue après un CAS perdant : {sql}")

    @contextmanager
    def _noop_write_transaction(conn: object) -> Iterator[None]:
        yield

    monkeypatch.setattr(database_module, "_write_transaction", _noop_write_transaction)
    connection = _FakeConnection()

    with pytest.raises(TransitionConcurrencyError):
        database_module.transition_secret(
            connection,  # type: ignore[arg-type]
            _PROJECT,
            _ENV,
            _NAME,
            "rote",
        )
    # Le CAS perdant ne doit jamais atteindre l'INSERT du journal.
    assert not any("INSERT INTO secret_transitions" in sql for sql in connection.statements)


def test_occurred_at_cannot_be_forged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L'horodatage est toujours serveur ; aucun paramètre ne permet de le forger."""
    assert "occurred_at" not in inspect.signature(database_module.transition_secret).parameters
    for forged in ("pas-une-date", "2099-01-01T00:00:00+00:00"):
        with pytest.raises(TypeError):
            database_module.transition_secret(  # type: ignore[call-arg]
                None,  # type: ignore[arg-type]
                _PROJECT,
                _ENV,
                _NAME,
                "rote",
                occurred_at=forged,
            )

    fixed_timestamp = "2026-01-01T00:00:00+00:00"
    monkeypatch.setattr(database_module, "get_iso_timestamp", lambda: fixed_timestamp)
    store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())

    async def scenario() -> None:
        await store.create(_PROJECT, _ENV, _NAME, _CANARY)
        result = await store.transition(_PROJECT, _ENV, _NAME, "rote")
        assert result is not None
        assert result["occurred_at"] == fixed_timestamp
        # ``SqliteSecretStore._list_transitions`` est un helper privé synchrone.
        entries = store._list_transitions(_PROJECT, _ENV, _NAME)
        assert entries[0]["occurred_at"] == fixed_timestamp

    asyncio.run(scenario())


@pytest.mark.parametrize("corrupted_status", [" ROTE ", "Rote", "corrompu"])
def test_get_secret_rejects_corrupted_status(
    vault: TestClient, corrupted_status: str
) -> None:
    """Un statut non canonique ne restitue jamais l'ancienne valeur."""
    _create(vault)
    store = vault.app.state.secret_store
    if isinstance(store, InMemorySecretStore):
        store._secrets[(_PROJECT, _ENV, _NAME)]["status"] = corrupted_status
    else:
        with closing(sqlite3.connect(store.db_path)) as connection:
            connection.execute("PRAGMA ignore_check_constraints = ON;")
            connection.execute(
                "UPDATE secrets SET status = ? "
                "WHERE project_id = ? AND env = ? AND name = ?",
                (corrupted_status, _PROJECT, _ENV, _NAME),
            )
            connection.commit()

    response = vault.get(_RESOURCE)
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert _CANARY not in response.text

    state = vault.get(_STATE)
    if corrupted_status.strip().lower() == "rote":
        assert state.status_code == 200
        assert state.json()["status"] == "rote"
        assert _CANARY not in state.text
    else:
        assert state.status_code == 404
        assert state.json() == _NOT_FOUND
