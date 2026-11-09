"""Acceptation #158 : capacité récupérable, liste bornée et métadonnées seules."""

import asyncio
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import VaultCipher, generate_api_key
from heimdall.vault.database import DatabaseUnavailableError
from heimdall.vault.ratelimit import RateLimiter
from heimdall.vault.store import InMemorySecretStore, SqliteSecretStore

_CANARY = "PLACEHOLDER_CAPACITY_CANARY_NEVER_RETURNED"
_COLLECTION = "/api/v1/secrets"
_RESOURCE = "/api/v1/secrets/demo/dev/DEMO_A"


@pytest.fixture(params=["memory", "sqlite"])
def vault(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[TestClient]:
    cipher = VaultCipher.generate()
    if request.param == "sqlite":
        store: InMemorySecretStore | SqliteSecretStore = SqliteSecretStore(
            tmp_path / "vault.db", cipher, max_secrets=120, max_secrets_per_project=110
        )
    else:
        store = InMemorySecretStore(cipher=cipher, max_secrets=120, max_secrets_per_project=110)
    app = create_app(
        VaultSettings(
            storage_backend=request.param,
            db_path=str(tmp_path / "vault.db"),
            api_key_pepper=generate_api_key(),
            rate_limit_per_key=1000,
            rate_limit_per_peer=2000,
            rate_limit_global=3000,
        ),
        secret_store=store,
    )
    key = generate_api_key()
    app.state.register_api_key(key, "demo")
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        client.headers["X-Heimdall-API-Key"] = key
        yield client


def _create(client: TestClient, name: str = "DEMO_A", env: str = "dev") -> None:
    response = client.post(
        _COLLECTION, json={"project": "demo", "env": env, "name": name, "value": _CANARY}
    )
    assert response.status_code == 201
    assert _CANARY not in response.text


@pytest.mark.parametrize("quota", ["_max_secrets", "_max_secrets_per_project"])
def test_delete_releases_quota(vault: TestClient, quota: str) -> None:
    setattr(vault.app.state.secret_store, quota, 1)
    _create(vault)
    payload = {"project": "demo", "env": "dev", "name": "DEMO_B", "value": _CANARY}
    full = vault.post(_COLLECTION, json=payload)
    assert full.status_code == 429
    assert full.headers["Retry-After"] == "60"
    assert vault.post(_COLLECTION, json={**payload, "name": "DEMO_A"}).status_code == 409
    deleted = vault.delete(_RESOURCE)
    assert deleted.status_code == 204
    assert deleted.content == b""
    assert deleted.headers["Cache-Control"] == "no-store"
    assert vault.get(_RESOURCE).status_code == 404
    assert vault.delete(_RESOURCE).status_code == 404
    assert vault.post(_COLLECTION, json=payload).status_code == 201


def test_pages_are_bounded_ordered_and_never_decrypt(vault: TestClient) -> None:
    for name, env in [("DEMO_C", "prod"), ("DEMO_B", "dev"), ("DEMO_A", "dev")]:
        _create(vault, name, env)
    with patch("heimdall.vault.store._decrypt_record", side_effect=AssertionError("decrypt")):
        first = vault.get(_COLLECTION, params={"project": "demo", "limit": 2})
        assert first.status_code == 200
        assert first.headers["Cache-Control"] == "no-store"
        assert [item["name"] for item in first.json()["items"]] == ["DEMO_A", "DEMO_B"]
        assert first.json()["next_offset"] == 2
        second = vault.get(_COLLECTION, params={"project": "demo", "limit": 2, "offset": 2})
        assert [item["name"] for item in second.json()["items"]] == ["DEMO_C"]
        assert second.json()["next_offset"] is None
        assert vault.delete(_RESOURCE).status_code == 204
    for response in (first, second):
        assert _CANARY not in response.text
        for item in response.json()["items"]:
            assert set(item) == {"project", "env", "name", "status"}
    empty = vault.get(_COLLECTION, params={"project": "demo", "offset": 100})
    assert empty.json() == {"items": [], "next_offset": None}


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"project": "../bad"},
        {"project": "demo", "limit": 0},
        {"project": "demo", "limit": 101},
        {"project": "demo", "offset": -1},
        {"project": "demo", "offset": 1000001},
        {"project": "demo", "limit": "invalid"},
    ],
)
def test_invalid_pagination_is_400(vault: TestClient, params: dict[str, str | int]) -> None:
    response = vault.get(_COLLECTION, params=params)
    assert response.status_code == 400
    assert response.json()["code"] == "bad_request"
    assert _CANARY not in response.text


@pytest.mark.parametrize(
    "limit, offset",
    [(0, 0), (-1, 0), (102, 0), (1, -1), (101, -1), (1, 1_000_001)],
)
def test_store_rejects_out_of_bounds_pagination(vault: TestClient, limit: int, offset: int) -> None:
    store = vault.app.state.secret_store
    with pytest.raises(ValueError, match="pagination hors bornes"):
        asyncio.run(store.list_page("demo", limit, offset))


def test_store_accepts_pagination_boundaries(vault: TestClient) -> None:
    store = vault.app.state.secret_store
    assert asyncio.run(store.list_page("demo", 101, 0)) == []
    assert asyncio.run(store.list_page("demo", 1, 1_000_000)) == []


def test_memory_list_page_caches_order_and_invalidates() -> None:
    async def scenario() -> None:
        store = InMemorySecretStore()
        for name in ("DEMO_C", "DEMO_A", "DEMO_B"):
            await store.create("demo", "dev", name, _CANARY)
        first = await store.list_page("demo", 10, 0)
        assert [item["name"] for item in first] == ["DEMO_A", "DEMO_B", "DEMO_C"]
        cached = store._sorted_keys_by_project["demo"]
        second = await store.list_page("demo", 10, 0)
        assert [item["name"] for item in second] == ["DEMO_A", "DEMO_B", "DEMO_C"]
        assert store._sorted_keys_by_project["demo"] is cached
        await store.create("demo", "dev", "DEMO_D", _CANARY)
        assert "demo" not in store._sorted_keys_by_project
        third = await store.list_page("demo", 10, 0)
        assert [item["name"] for item in third] == [
            "DEMO_A",
            "DEMO_B",
            "DEMO_C",
            "DEMO_D",
        ]
        assert await store.delete("demo", "dev", "DEMO_B") is True
        assert "demo" not in store._sorted_keys_by_project
        fourth = await store.list_page("demo", 10, 0)
        assert [item["name"] for item in fourth] == ["DEMO_A", "DEMO_C", "DEMO_D"]
        await store.clear()
        assert store._sorted_keys_by_project == {}

    asyncio.run(scenario())


def test_default_and_maximum_page_size(vault: TestClient) -> None:
    async def populate() -> None:
        for index in range(101):
            await vault.app.state.secret_store.create("demo", "dev", f"DEMO_{index:03}", _CANARY)

    asyncio.run(populate())
    default = vault.get(_COLLECTION, params={"project": "demo"})
    maximum = vault.get(_COLLECTION, params={"project": "demo", "limit": 100})
    assert len(default.json()["items"]) == 50
    assert default.json()["next_offset"] == 50
    assert len(maximum.json()["items"]) == 100
    assert maximum.json()["next_offset"] == 100
    assert _CANARY not in default.text + maximum.text


@pytest.mark.parametrize(
    "method, path, params, expected_status",
    [
        ("get", _COLLECTION, {"project": "other"}, 403),
        ("get", _COLLECTION, {"project": "demo", "limit": 0}, 400),
        ("delete", _RESOURCE, None, 404),
    ],
)
def test_error_responses_are_no_store(
    vault: TestClient,
    method: str,
    path: str,
    params: dict[str, str | int] | None,
    expected_status: int,
) -> None:
    response = getattr(vault, method)(path, params=params)
    assert response.status_code == expected_status
    assert response.headers["Cache-Control"] == "no-store"


def test_auth_error_response_is_no_store(vault: TestClient) -> None:
    vault.headers.pop("X-Heimdall-API-Key")
    response = vault.get(_COLLECTION, params={"project": "demo"})
    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"


def test_project_access_precedes_storage(vault: TestClient) -> None:
    _create(vault)
    store = vault.app.state.secret_store
    with (
        patch.object(store, "list_page", side_effect=AssertionError("storage")),
        patch.object(store, "delete", side_effect=AssertionError("storage")),
    ):
        assert vault.get(_COLLECTION, params={"project": "other"}).status_code == 403
        assert vault.delete("/api/v1/secrets/other/dev/DEMO_A").status_code == 403
        vault.headers.pop("X-Heimdall-API-Key")
        assert vault.get(_COLLECTION, params={"project": "demo"}).status_code == 401
        assert vault.delete(_RESOURCE).status_code == 401


def test_sqlite_delete_visible_to_other_worker(vault: TestClient) -> None:
    store = vault.app.state.secret_store
    if not isinstance(store, SqliteSecretStore):
        pytest.skip("Partage inter-workers propre au backend SQLite")
    _create(vault)
    other = SqliteSecretStore(store.db_path, VaultCipher.generate(), max_secrets=1)
    assert vault.delete(_RESOURCE).status_code == 204
    # Pas besoin de la KEK du premier worker pour lister/supprimer/créer après DELETE.
    assert asyncio.run(other.list_page("demo", 10, 0)) == []
    assert asyncio.run(other.create("demo", "dev", "DEMO_B", _CANARY))["status"] == "vaulte"


def test_rate_limit_also_applies_to_new_routes(vault: TestClient) -> None:
    vault.app.state.rate_limiter = RateLimiter(
        per_key=1, per_peer=100, global_limit=100, window_seconds=2
    )
    assert vault.get(_COLLECTION, params={"project": "demo"}).status_code == 200
    limited = vault.delete(_RESOURCE)
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 2
    assert limited.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("operation", ["list_page", "delete"])
def test_unavailable_storage_is_generic_503(vault: TestClient, operation: str) -> None:
    with patch.object(
        vault.app.state.secret_store, operation, side_effect=DatabaseUnavailableError(_CANARY)
    ):
        if operation == "list_page":
            response = vault.get(_COLLECTION, params={"project": "demo"})
        else:
            response = vault.delete(_RESOURCE)
    assert response.status_code == 503
    assert 1 <= int(response.headers["Retry-After"]) <= 3600
    assert _CANARY not in response.text


@pytest.mark.parametrize(
    "offset, expected_next", [(999900, 1000000), (999901, None), (1000000, None)]
)
def test_next_offset_remains_reusable(
    vault: TestClient, offset: int, expected_next: int | None
) -> None:
    # Simuler les pages lointaines sans créer un million de secrets.
    records = [{"project": "demo", "env": "dev", "name": "DEMO_A", "status": "vaulte"}] * 101
    with patch.object(vault.app.state.secret_store, "list_page", return_value=records) as listing:
        response = vault.get(
            _COLLECTION, params={"project": "demo", "limit": 100, "offset": offset}
        )
        assert response.status_code == 200
        assert len(response.json()["items"]) == 100
        assert response.json()["next_offset"] == expected_next
        listing.assert_awaited_once_with("demo", 101, offset)
        if expected_next is not None:
            following = vault.get(
                _COLLECTION, params={"project": "demo", "limit": 100, "offset": expected_next}
            )
            assert following.status_code == 200
            assert following.json()["next_offset"] is None


@pytest.mark.parametrize("count", [None, 0, -1, 1, 2])
@pytest.mark.parametrize("vault", ["memory"], indirect=True)
def test_delete_tolerates_desynchronized_memory_counter(
    vault: TestClient, count: int | None
) -> None:
    store = vault.app.state.secret_store
    assert isinstance(store, InMemorySecretStore)
    _create(vault)
    if count is None:
        store._project_counts.pop("demo")
    else:
        store._project_counts["demo"] = count
    deleted = vault.delete(_RESOURCE)
    assert deleted.status_code == 204
    assert deleted.content == b""
    assert vault.delete(_RESOURCE).status_code == 404
    assert store._project_counts.get("demo", 0) == (1 if count == 2 else 0)


def test_concurrent_double_delete_returns_204_and_404(vault: TestClient) -> None:
    _create(vault)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(vault.delete, [_RESOURCE, _RESOURCE]))
    assert sorted(response.status_code for response in responses) == [204, 404]
    for response in responses:
        assert _CANARY not in response.text
