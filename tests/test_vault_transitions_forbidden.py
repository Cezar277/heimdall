"""Tests des transitions interdites de la machine d'états du secret (#40, #118).

Sous-ticket **T404** du grand ticket ``#40 « États du secret dans le Vault »``.

Objectif : prouver, de façon exhaustive et mécanique, que **toute** transition
interdite par la matrice fermée #115 est refusée, et que la machine d'états
est couverte à 100 % (instructions et branches).

Trois niveaux de preuve, du plus abstrait au plus opérationnel :

1. **Machine d'états** (``heimdall/vault/transitions.py``) : chacune des 20
   paires interdites de la matrice 5x5 lève ``InvalidTransitionError`` avec la
   justification formelle associée ; les 5 paires autorisées passent.
2. **Stores du Vault** (mémoire et SQLite) : une transition interdite ne mute
   ni l'état ni le journal ; un état source non persistable ne peut pas
   davantage sortir du Vault.
3. **API HTTP** (``POST /api/v1/secrets/{project}/{env}/{name}/transition``) :
   refus contractuel 400 statique, sans reflet de l'entrée, sans effet de bord.

Le canari utilisé est un placeholder factice : aucun secret réel (ni réel ni
expiré) n'apparaît dans ce fichier (règle CONTRIBUTING §8).
"""

from __future__ import annotations

import asyncio
import importlib
import io
import json
import re
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from types import ModuleType
from typing import Final

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import coverage
import pytest
from fastapi.testclient import TestClient

import heimdall.vault.transitions as transitions_module
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import VaultCipher, generate_api_key
from heimdall.vault.database import PERSISTED_STATUSES
from heimdall.vault.store import InMemorySecretStore, SqliteSecretStore
from heimdall.vault.transitions import (
    ALLOWED_TRANSITIONS,
    FORBIDDEN_TRANSITION_REASONS,
    LIFECYCLE_STATES,
    LIFECYCLE_STATES_SET,
    InvalidTransitionError,
    UnknownStateError,
    canonicalize_state,
    get_allowed_transitions,
    get_forbidden_transitions,
    get_transition_matrix,
    is_transition_allowed,
    is_valid_state,
    validate_transition,
)

# --- Constantes de test (fictives, jamais des secrets) -------------------------

_PROJECT: Final[str] = "demo"
_ENV: Final[str] = "dev"
_NAME: Final[str] = "DEMO_FORBIDDEN"
_CANARY: Final[str] = "PLACEHOLDER_FORBIDDEN_CANARY_NEVER_RETURNED"
_CREATE: Final[str] = "/api/v1/secrets"
_RESOURCE: Final[str] = f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}"
_TRANSITION: Final[str] = f"{_RESOURCE}/transition"
_STATE: Final[str] = f"{_RESOURCE}/state"
_BAD_REQUEST: Final[dict[str, str]] = {"code": "bad_request", "message": "Requête invalide"}
_TRANSITIONS_RELATIVE_PATH: Final[str] = "heimdall/vault/transitions.py"

# --- Matrice des paires (état de départ, état d'arrivée) -----------------------

_ALL_PAIRS: Final[tuple[tuple[str, str], ...]] = tuple(
    (source, target) for source in LIFECYCLE_STATES for target in LIFECYCLE_STATES
)
_ALLOWED_PAIRS: Final[frozenset[tuple[str, str]]] = frozenset(
    pair for pair in _ALL_PAIRS if pair[1] in ALLOWED_TRANSITIONS[pair[0]]
)
_FORBIDDEN_PAIRS: Final[tuple[tuple[str, str], ...]] = tuple(
    pair for pair in _ALL_PAIRS if pair not in _ALLOWED_PAIRS
)
#: Paires dont l'état source est persistable dans le Vault (``vaulte``/``rote``).
_PERSISTED_SOURCE_PAIRS: Final[tuple[tuple[str, str], ...]] = tuple(
    pair for pair in _ALL_PAIRS if pair[0] in PERSISTED_STATUSES
)
#: Paires interdites atteignables depuis un état réellement persisté.
_API_FORBIDDEN_PAIRS: Final[tuple[tuple[str, str], ...]] = tuple(
    pair for pair in _PERSISTED_SOURCE_PAIRS if pair not in _ALLOWED_PAIRS
)


def _pair_id(pair: tuple[str, str]) -> str:
    """Identifiant lisible d'une paire d'états (``detecte->rote``)."""
    return f"{pair[0]}->{pair[1]}"


def _ids(pairs: tuple[tuple[str, str], ...]) -> list[str]:
    """Identifiants pytest de la liste de paires."""
    return [_pair_id(pair) for pair in pairs]


# ==============================================================================
# 1. Intégrité de la matrice : la table des transitions est une partition fermée
# ==============================================================================


class TestTransitionMatrixIntegrity:
    """Garde-fous structurels : sans eux, la preuve « 20 transitions » dériverait
    de la table testée et ne prouverait donc rien."""

    def test_matrix_partitions_the_25_ordered_pairs(self) -> None:
        """Les 25 couples (état de départ, état d'arrivée) sont tous classés."""
        assert len(_ALL_PAIRS) == 25
        assert len(set(_ALL_PAIRS)) == 25
        assert len(_ALLOWED_PAIRS) == 5
        assert len(_FORBIDDEN_PAIRS) == 20
        assert set(_ALLOWED_PAIRS) | set(_FORBIDDEN_PAIRS) == set(_ALL_PAIRS)
        assert set(_ALLOWED_PAIRS) & set(_FORBIDDEN_PAIRS) == set()

    def test_forbidden_reason_table_covers_exactly_the_forbidden_pairs(self) -> None:
        """Chaque transition interdite a une justification, et elle seule."""
        reasons = set(FORBIDDEN_TRANSITION_REASONS)
        assert reasons == set(_FORBIDDEN_PAIRS)
        assert not reasons & set(_ALLOWED_PAIRS)

    def test_every_forbidden_reason_is_a_static_non_empty_justification(self) -> None:
        """Les justifications sont du texte statique, sans secret ni valeur."""
        for (source, target), reason in FORBIDDEN_TRANSITION_REASONS.items():
            assert isinstance(reason, str)
            assert reason.strip()
            assert "\n" not in reason
            assert len(reason) <= 300
            assert _CANARY not in reason
            assert source != target or "inchangé" in reason

    def test_every_forbidden_pair_uses_its_own_table_entry(self) -> None:
        """La table de justifications est bien la source du refus (pas un repli)."""
        for source, target in _FORBIDDEN_PAIRS:
            with pytest.raises(InvalidTransitionError) as ctx:
                validate_transition(source, target)
            assert ctx.value.reason == FORBIDDEN_TRANSITION_REASONS[(source, target)]

    def test_transition_tables_cannot_be_altered_at_runtime(self) -> None:
        """Les tables restent immuables pendant l'exécution (MappingProxyType)."""
        with pytest.raises(TypeError):
            ALLOWED_TRANSITIONS["rote"] = frozenset({"detecte"})  # type: ignore[index]
        with pytest.raises(AttributeError):
            FORBIDDEN_TRANSITION_REASONS.clear()  # type: ignore[attr-defined]


# ==============================================================================
# 2. Machine d'états : les 20 transitions interdites sont refusées
# ==============================================================================


class TestForbiddenTransitionMatrix:
    """Preuve exhaustive au niveau de la matrice (#115)."""

    @pytest.mark.parametrize(("source", "target"), _FORBIDDEN_PAIRS, ids=_ids(_FORBIDDEN_PAIRS))
    def test_forbidden_transition_raises_with_the_formal_reason(
        self, source: str, target: str
    ) -> None:
        """Toute paire interdite lève ``InvalidTransitionError`` et sa justification."""
        with pytest.raises(InvalidTransitionError) as ctx:
            validate_transition(source, target)

        error = ctx.value
        assert error.source == source
        assert error.target == target
        assert error.reason == FORBIDDEN_TRANSITION_REASONS[(source, target)]
        assert f"Transition interdite de '{source}' vers '{target}'" in str(error)

        # Le refus est fail-closed et cohérent avec les prédicats publics.
        assert not is_transition_allowed(source, target)
        assert target in get_forbidden_transitions(source)
        assert target not in get_allowed_transitions(source)
        assert get_transition_matrix()[source][target] is False

    @pytest.mark.parametrize(("source", "target"), _ALLOWED_PAIRS, ids=_ids(_ALLOWED_PAIRS))
    def test_allowed_transition_is_accepted(self, source: str, target: str) -> None:
        """Les 5 transitions autorisées passent : la preuve ne bloque pas tout."""
        assert validate_transition(source, target) is None
        assert is_transition_allowed(source, target)
        assert target in get_allowed_transitions(source)
        assert target not in get_forbidden_transitions(source)

    @pytest.mark.parametrize(
        ("source", "target"),
        [("detecte", "rote"), ("detecte", "vaulte"), ("confirme", "rote")],
    )
    def test_skipping_a_step_is_refused(self, source: str, target: str) -> None:
        """Les sauts d'étape (détecté -> vaulté/roté) sont explicitement refusés."""
        with pytest.raises(InvalidTransitionError):
            validate_transition(source, target)

    @pytest.mark.parametrize("state", LIFECYCLE_STATES)
    def test_reflexive_transition_is_refused(self, state: str) -> None:
        """Une transition réflexive n'est pas un avancement : elle est refusée."""
        with pytest.raises(InvalidTransitionError) as ctx:
            validate_transition(state, state)
        assert "inchangé" in ctx.value.reason.lower()

    @pytest.mark.parametrize(
        ("source", "target"),
        [("rote", "ecarte"), ("faux_positif", "ecarte"), ("vaulte", "ecarte")],
    )
    def test_alias_is_canonicalized_before_the_matrix_is_applied(
        self, source: str, target: str
    ) -> None:
        """L'alias ``ecarte`` est canonisé (``faux_positif``) avant l'application."""
        canonical = canonicalize_state(target)
        assert canonical == "faux_positif"
        with pytest.raises(InvalidTransitionError) as ctx:
            validate_transition(source, target)
        assert ctx.value.target == canonical

    @pytest.mark.parametrize(
        ("source", "target"),
        [("detecte", "inconnu"), ("inconnu", "detecte"), ("", "detecte"), (42, "detecte")],
    )
    def test_unknown_state_fails_closed(self, source: object, target: object) -> None:
        """Un état inconnu n'est jamais accepté et n'est jamais reflété."""
        with pytest.raises(UnknownStateError) as ctx:
            validate_transition(source, target)
        assert str(ctx.value) == "État de cycle de vie inconnu."
        assert not hasattr(ctx.value, "state")

    def test_public_predicates_are_fail_closed_on_unknown_states(self) -> None:
        """Les prédicats publics ne valident jamais un état inconnu."""
        assert is_valid_state("detecte") is True
        assert is_valid_state("ecarte") is True
        assert is_valid_state("inconnu") is False
        assert is_transition_allowed("inconnu", "detecte") is False
        assert is_transition_allowed("detecte", "inconnu") is False
        assert is_transition_allowed("inconnu", "inconnu") is False
        assert is_transition_allowed("detecte", "confirme") is True

    def test_error_message_never_reflects_a_secret(self) -> None:
        """Invariant 8 : aucun secret ni entrée brute dans le message d'erreur."""
        for source, target in _FORBIDDEN_PAIRS:
            with pytest.raises(InvalidTransitionError) as ctx:
                validate_transition(source, target)
            message = str(ctx.value)
            assert _CANARY not in message
            assert "sk_live" not in message
            assert "PRIVATE KEY" not in message

    def test_forbidden_reason_is_deterministic(self) -> None:
        """Le refus est déterministe : même message à chaque appel."""
        messages = set()
        for _ in range(3):
            with pytest.raises(InvalidTransitionError) as ctx:
                validate_transition("vaulte", "faux_positif")
            messages.add(str(ctx.value))
        assert len(messages) == 1


# ==============================================================================
# 3. Stores du Vault : un refus ne mute rien et ne journalise rien
# ==============================================================================


def _memory_status(store: InMemorySecretStore) -> str:
    """État persisté du secret dans le backend mémoire (lecture test-only)."""
    return str(store._secrets[(_PROJECT, _ENV, _NAME)]["status"])


def _memory_journal(store: InMemorySecretStore) -> list[dict[str, str]]:
    """Journal de transitions du backend mémoire (lecture test-only)."""
    return [dict(entry) for entry in store._transitions.get(_PROJECT, ())]


def _sqlite_status(store: SqliteSecretStore) -> str:
    """État persisté du secret dans le backend SQLite (lecture test-only)."""
    with closing(sqlite3.connect(store.db_path)) as connection:
        row = connection.execute(
            "SELECT status FROM secrets WHERE project_id = ? AND env = ? AND name = ?",
            (_PROJECT, _ENV, _NAME),
        ).fetchone()
    assert row is not None
    return str(row[0])


def _sqlite_journal(store: SqliteSecretStore) -> list[dict[str, str]]:
    """Journal de transitions du backend SQLite (lecture test-only)."""
    with closing(sqlite3.connect(store.db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT project_id AS project, env, name, actor, occurred_at, "
            "previous_status, new_status AS status FROM secret_transitions "
            "WHERE project_id = ? AND env = ? AND name = ? ORDER BY id ASC",
            (_PROJECT, _ENV, _NAME),
        ).fetchall()
    return [dict(row) for row in rows]


def _set_sqlite_status(store: SqliteSecretStore, status: str) -> None:
    """Force l'état source en base (uniquement ``vaulte``/``rote`` : voir CHECK)."""
    with closing(sqlite3.connect(store.db_path)) as connection:
        connection.execute(
            "UPDATE secrets SET status = ? WHERE project_id = ? AND env = ? AND name = ?",
            (status, _PROJECT, _ENV, _NAME),
        )
        connection.commit()


class TestForbiddenTransitionStore:
    """Preuve exhaustive au niveau des stores (les deux backends)."""

    @pytest.mark.parametrize(("source", "target"), _ALL_PAIRS, ids=_ids(_ALL_PAIRS))
    def test_memory_store_applies_the_matrix_without_side_effect(
        self, source: str, target: str
    ) -> None:
        """Backend mémoire : la matrice est la seule source de vérité.

        Le store n'accepte une transition que si la matrice l'autorise **et**
        que la cible est persistable ; sinon il refuse sans muter l'état ni
        écrire au journal.
        """
        store = InMemorySecretStore(cipher=VaultCipher.generate())

        async def scenario() -> None:
            await store.create(_PROJECT, _ENV, _NAME, _CANARY)
            # État source forcé : simule une ligne dans un état antérieur au
            # vaultage (non persistable en production, cf. test CHECK SQLite).
            store._secrets[(_PROJECT, _ENV, _NAME)]["status"] = source
            accepted = (source, target) in _ALLOWED_PAIRS and target in PERSISTED_STATUSES

            if accepted:
                record = await store.transition(_PROJECT, _ENV, _NAME, target)
                assert record is not None
                assert record["previous_status"] == source
                assert record["status"] == target
                assert _memory_status(store) == target
                assert len(_memory_journal(store)) == 1
                return

            with pytest.raises(InvalidTransitionError):
                await store.transition(_PROJECT, _ENV, _NAME, target)
            # Refus = zéro effet de bord : ni l'état ni le journal n'ont bougé.
            assert _memory_status(store) == source
            assert _memory_journal(store) == []

        asyncio.run(scenario())

    @pytest.mark.parametrize(
        ("source", "target"), _PERSISTED_SOURCE_PAIRS, ids=_ids(_PERSISTED_SOURCE_PAIRS)
    )
    def test_sqlite_store_applies_the_matrix_without_side_effect(
        self, source: str, target: str, tmp_path: Path
    ) -> None:
        """Backend SQLite (production) : même règle, en plus de la contrainte SQL.

        En SQLite, l'état source est forcément ``vaulte`` ou ``rote`` (contrainte
        ``CHECK``) : les paires à source non persistable sont inaccessibles par
        construction, ce que prouve ``test_sqlite_check_constraint_blocks_*``.
        """
        store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())

        async def scenario() -> None:
            await store.create(_PROJECT, _ENV, _NAME, _CANARY)
            _set_sqlite_status(store, source)
            accepted = (source, target) in _ALLOWED_PAIRS and target in PERSISTED_STATUSES

            if accepted:
                record = await store.transition(_PROJECT, _ENV, _NAME, target)
                assert record is not None
                assert record["previous_status"] == source
                assert record["status"] == target
                assert _sqlite_status(store) == target
                assert len(_sqlite_journal(store)) == 1
                return

            with pytest.raises(InvalidTransitionError):
                await store.transition(_PROJECT, _ENV, _NAME, target)
            assert _sqlite_status(store) == source
            assert _sqlite_journal(store) == []

        asyncio.run(scenario())

    def test_sqlite_check_constraint_blocks_non_persistable_source_states(
        self, tmp_path: Path
    ) -> None:
        """Les paires à source non persistable sont inaccessibles en base.

        Le ``CHECK(status IN ('vaulte','rote'))`` interdit d'écrire un état
        source interdit : une base ne peut pas se trouver dans un état que la
        machine refuse de quitter.
        """
        store = SqliteSecretStore(tmp_path / "vault.db", VaultCipher.generate())

        async def scenario() -> None:
            await store.create(_PROJECT, _ENV, _NAME, _CANARY)

        asyncio.run(scenario())

        for state in ("detecte", "confirme", "faux_positif"):
            with closing(sqlite3.connect(store.db_path)) as connection:
                with pytest.raises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE secrets SET status = ? "
                        "WHERE project_id = ? AND env = ? AND name = ?",
                        (state, _PROJECT, _ENV, _NAME),
                    )

    @pytest.mark.parametrize("source", ["detecte", "confirme", "faux_positif"])
    def test_memory_store_never_leaves_a_non_persistable_state(self, source: str) -> None:
        """Depuis un état non persistable, seule la matrice décide.

        Une transition vers un état non persistable est refusée même si la
        matrice l'autorise : le Vault ne conserve que ``vaulte``/``rote``.
        """
        store = InMemorySecretStore(cipher=VaultCipher.generate())

        async def scenario() -> None:
            await store.create(_PROJECT, _ENV, _NAME, _CANARY)
            store._secrets[(_PROJECT, _ENV, _NAME)]["status"] = source
            for target in LIFECYCLE_STATES:
                accepted = (source, target) in _ALLOWED_PAIRS and target in PERSISTED_STATUSES
                if accepted:
                    continue
                with pytest.raises(InvalidTransitionError):
                    await store.transition(_PROJECT, _ENV, _NAME, target)
                assert _memory_status(store) == source
                assert _memory_journal(store) == []

        asyncio.run(scenario())


# ==============================================================================
# 4. API HTTP : refus contractuel, statique et sans effet de bord
# ==============================================================================


@pytest.fixture(params=["memory", "sqlite"])
def vault_client(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[TestClient]:
    """Application neuve par test, backend mémoire ou SQLite temporaire."""
    cipher = VaultCipher.generate()
    store: InMemorySecretStore | SqliteSecretStore
    if request.param == "sqlite":
        store = SqliteSecretStore(tmp_path / "vault.db", cipher)
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


def _create_secret(client: TestClient) -> None:
    """Crée le secret de test (le canari ne doit jamais ressortir)."""
    response = client.post(
        _CREATE,
        json={"project": _PROJECT, "env": _ENV, "name": _NAME, "value": _CANARY},
    )
    assert response.status_code == 201
    assert _CANARY not in response.text


def _journal(client: TestClient) -> list[dict[str, str]]:
    """Journal de transitions du backend du client (lecture test-only)."""
    store = client.app.state.secret_store
    if isinstance(store, InMemorySecretStore):
        return _memory_journal(store)
    return _sqlite_journal(store)


class TestForbiddenTransitionApi:
    """Preuve exhaustive au niveau HTTP (la frontière réellement exposée)."""

    @pytest.mark.parametrize(
        ("source", "target"), _API_FORBIDDEN_PAIRS, ids=_ids(_API_FORBIDDEN_PAIRS)
    )
    def test_forbidden_transition_is_refused_without_side_effect(
        self, vault_client: TestClient, source: str, target: str
    ) -> None:
        """Chaque transition interdite est refusée en 400 statique et sans effet."""
        _create_secret(vault_client)
        expected_journal = 0
        if source == "rote":
            # État terminal : on y entre par la seule transition autorisée.
            rotation = vault_client.post(_TRANSITION, json={"target_status": "rote"})
            assert rotation.status_code == 200
            expected_journal = 1

        response = vault_client.post(_TRANSITION, json={"target_status": target})

        assert response.status_code == 400
        assert response.json() == _BAD_REQUEST
        assert response.headers["Cache-Control"] == "no-store"
        # Aucun reflet de l'état demandé ni du secret dans la réponse.
        # Le non-reflet de l'état se mesure sur le corps JSON : les noms d'état
        # sont des mots courts qu'une recherche en sous-chaîne sur la réponse
        # entière confondrait avec un autre mot ("rote" dans "protégé") ; le
        # canari, lui, est un jeton unique — il est cherché partout, en-têtes
        # compris.
        assert target not in json.dumps(response.json())
        assert _CANARY not in response.text

        # Aucun effet de bord : l'état et le journal sont inchangés.
        assert vault_client.get(_STATE).json()["status"] == source
        assert len(_journal(vault_client)) == expected_journal

    @pytest.mark.parametrize(
        ("source", "target"), _API_FORBIDDEN_PAIRS, ids=_ids(_API_FORBIDDEN_PAIRS)
    )
    def test_refused_transition_keeps_the_secret_readable(
        self, vault_client: TestClient, source: str, target: str
    ) -> None:
        """Un refus ne corrompt pas le secret : il reste lisible et inchangé."""
        _create_secret(vault_client)
        if source == "rote":
            rotation = vault_client.post(_TRANSITION, json={"target_status": "rote"})
            assert rotation.status_code == 200

        assert vault_client.post(_TRANSITION, json={"target_status": target}).status_code == 400

        read = vault_client.get(_RESOURCE)
        if source == "vaulte":
            # Le secret n'a pas été altéré : la valeur est toujours la sienne.
            assert read.status_code == 200
            assert read.json()["value"] == _CANARY
        else:
            # Un secret roté reste inaccessible en valeur (comportement #117).
            assert read.status_code == 404

    def test_client_cannot_forge_the_source_state(self, vault_client: TestClient) -> None:
        """L'état source vient du serveur : le client ne peut pas l'imposer."""
        _create_secret(vault_client)
        response = vault_client.post(
            _TRANSITION,
            json={"source_status": "detecte", "target_status": "rote"},
        )
        assert response.status_code == 400
        assert response.json() == _BAD_REQUEST
        assert vault_client.get(_STATE).json()["status"] == "vaulte"
        assert _journal(vault_client) == []

    def test_unknown_target_state_is_refused(self, vault_client: TestClient) -> None:
        """Un état cible inconnu est refusé sans mutation (fail-closed)."""
        _create_secret(vault_client)
        response = vault_client.post(_TRANSITION, json={"target_status": "revoked"})
        assert response.status_code == 400
        assert response.json() == _BAD_REQUEST
        assert "revoked" not in json.dumps(response.json())
        assert vault_client.get(_STATE).json()["status"] == "vaulte"
        assert _journal(vault_client) == []

    def test_refused_transition_is_audited_without_leaking(self, vault_client: TestClient) -> None:
        """Un refus est tracé (outcome ``rejected``), sans secret ni clé brute."""
        _create_secret(vault_client)
        response = vault_client.post(_TRANSITION, json={"target_status": "faux_positif"})
        assert response.status_code == 400

        events = vault_client.app.state.audit_log.list_events(limit=10)
        refusals = [event for event in events if event["status_code"] == 400]
        assert refusals, "le refus de transition doit laisser une trace d'audit"
        assert refusals[-1]["outcome"] == "rejected"
        assert refusals[-1]["target"] == f"{_PROJECT}/{_ENV}/{_NAME}"

        serialized = json.dumps(events)
        assert _CANARY not in serialized
        assert vault_client.headers["X-Heimdall-API-Key"] not in serialized


# ==============================================================================
# 5. Scénarios d'attaque explicitement visés (audit croisé / pentest)
# ==============================================================================


class TestForbiddenTransitionAttackScenarios:
    """Scénarios d'attaque nommés : ce qu'un auditeur adverse tentera."""

    def test_unvaulting_a_secret_to_hide_it_is_refused(self, vault_client: TestClient) -> None:
        """``vaulte -> detecte`` : déclasser un secret pour le soustraire au scan."""
        _create_secret(vault_client)
        response = vault_client.post(_TRANSITION, json={"target_status": "detecte"})
        assert response.status_code == 400
        assert vault_client.get(_STATE).json()["status"] == "vaulte"
        assert _journal(vault_client) == []

    def test_relabelling_a_vaulted_secret_as_false_positive_is_refused(
        self, vault_client: TestClient
    ) -> None:
        """``vaulte -> faux_positif`` : effacer la trace d'un secret compromis."""
        _create_secret(vault_client)
        response = vault_client.post(_TRANSITION, json={"target_status": "faux_positif"})
        assert response.status_code == 400
        assert vault_client.get(_STATE).json()["status"] == "vaulte"
        assert _journal(vault_client) == []

    def test_rotating_without_confirmation_is_refused(self) -> None:
        """``detecte -> rote`` : court-circuiter la validation humaine."""
        with pytest.raises(InvalidTransitionError):
            validate_transition("detecte", "rote")

    def test_resurrecting_a_rotated_secret_is_refused(self, vault_client: TestClient) -> None:
        """``rote -> vaulte`` : ressusciter une version révoquée."""
        _create_secret(vault_client)
        assert vault_client.post(_TRANSITION, json={"target_status": "rote"}).status_code == 200
        response = vault_client.post(_TRANSITION, json={"target_status": "vaulte"})
        assert response.status_code == 400
        assert vault_client.get(_STATE).json()["status"] == "rote"
        assert len(_journal(vault_client)) == 1

    def test_reflexive_transition_cannot_rewrite_the_journal(
        self, vault_client: TestClient
    ) -> None:
        """``vaulte -> vaulte`` : rejouer une écriture pour polluer la piste."""
        _create_secret(vault_client)
        response = vault_client.post(_TRANSITION, json={"target_status": "vaulte"})
        assert response.status_code == 400
        assert _journal(vault_client) == []


# ==============================================================================
# 6. Couverture de la machine d'états : 100 % (instructions et branches)
# ==============================================================================


def _exhaust_state_machine(module: ModuleType) -> None:
    """Exécute tous les chemins de la machine d'états (pour la mesure de couverture)."""
    for state in LIFECYCLE_STATES:
        assert module.canonicalize_state(state) == state
    assert module.canonicalize_state("  ECARTE  ") == "faux_positif"
    assert module.canonicalize_state("ecarté") == "faux_positif"
    assert module.canonicalize_state("discarded") == "faux_positif"
    for hostile in ("inconnu", "", " ", None, 42, b"detecte", ["detecte"], "a" * 65):
        with pytest.raises(module.UnknownStateError):
            module.canonicalize_state(hostile)

    assert module.is_valid_state("detecte") is True
    assert module.is_valid_state("ecarte") is True
    assert module.is_valid_state("inconnu") is False

    for source in module.LIFECYCLE_STATES:
        for target in module.LIFECYCLE_STATES:
            if module.is_transition_allowed(source, target):
                module.validate_transition(source, target)
            else:
                with pytest.raises(module.InvalidTransitionError):
                    module.validate_transition(source, target)

    assert module.is_transition_allowed("inconnu", "detecte") is False
    assert module.is_transition_allowed("detecte", "inconnu") is False
    with pytest.raises(module.UnknownStateError):
        module.validate_transition("detecte", "inconnu")

    for source in module.LIFECYCLE_STATES:
        allowed = module.get_allowed_transitions(source)
        forbidden = module.get_forbidden_transitions(source)
        assert allowed & forbidden == frozenset()
        assert allowed | forbidden == frozenset(module.LIFECYCLE_STATES)
    assert len(module.get_transition_matrix()) == len(module.LIFECYCLE_STATES)


class TestStateMachineCoverage:
    """DoD « Couverture de la machine d'états à 100 % », vérifié mécaniquement."""

    def test_state_machine_module_is_fully_covered(self) -> None:
        """Toutes les instructions et toutes les branches de ``transitions.py`` sont couvertes.

        La mesure est faite dans un traceur dédié, sur un module rechargé
        sous ce traceur : le fichier est ainsi couvert ligne par ligne, y
        compris ses définitions de module. Aucune donnée n'est écrite sur le
        disque (``data_file=None``).
        """
        original = sys.modules.get("heimdall.vault.transitions")
        cov = coverage.Coverage(
            data_file=None,
            branch=True,
            include=[f"*/{_TRANSITIONS_RELATIVE_PATH}"],
        )
        cov.start()
        try:
            sys.modules.pop("heimdall.vault.transitions", None)
            module = importlib.import_module("heimdall.vault.transitions")
            _exhaust_state_machine(module)
        finally:
            cov.stop()
            if original is not None:
                sys.modules["heimdall.vault.transitions"] = original

        # Le pourcentage publié par coverage inclut les branches : 100 % impose
        # zéro ligne manquante ET zéro branche partielle.
        buffer = io.StringIO()
        total = cov.report(file=buffer, show_missing=True)
        report = buffer.getvalue()
        assert float(total) == 100.0, "couverture incomplète de la machine d'états :\n" + report
        assert transitions_module.__file__ is not None
        assert "transitions.py" in report

    def test_state_machine_constants_are_consistent_with_the_contract(self) -> None:
        """Les 5 états du module sont bien ceux de la matrice testée."""
        assert LIFECYCLE_STATES_SET == frozenset(LIFECYCLE_STATES)
        assert len(LIFECYCLE_STATES) == 5
        assert get_transition_matrix().keys() == LIFECYCLE_STATES_SET


# ==============================================================================
# 7. Reproductibilité de la preuve : l'outil de mesure est épinglé
# ==============================================================================


class TestCoverageToolPinning:
    """Garde-fou de la preuve « 100 % » : l'outil de mesure est déclaré.

    La couverture de la machine d'états est mesurée *en processus* par
    ``coverage`` (import direct de ce module de test). Résolu seulement
    transitivement via ``pytest-cov``, ce paquet pourrait dériver de version et
    la preuve « 100 % » cesserait d'être reproductible à l'identique : le pin
    est donc direct, exact, et aligné sur le lock — c'est ce qui est vérifié ici.
    """

    def test_coverage_is_a_pinned_direct_dev_dependency(self) -> None:
        """``coverage`` est déclaré en dev, épinglé, et c'est cette version qui mesure."""
        root = Path(__file__).resolve().parents[1]
        document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        dev = document["project"]["optional-dependencies"]["dev"]

        # (a) Déclaration directe avec un pin exact — jamais une résolution transitive.
        pins = [
            match.group(1)
            for match in (
                re.fullmatch(r"coverage(?:\[[^\]]+\])?==(\d+\.\d+\.\d+)", requirement)
                for requirement in dev
            )
            if match is not None
        ]
        assert len(pins) == 1, (
            f"coverage doit être déclaré une seule fois en dev, avec un pin exact : {dev}"
        )
        version = pins[0]

        # (b) La CI installe depuis le lock : il doit porter le même pin.
        lock = (root / "requirements.lock").read_text(encoding="utf-8")
        assert re.search(
            rf"^coverage(?:\[[^\]]+\])?=={re.escape(version)}\b", lock, re.MULTILINE
        ), f"requirements.lock ne pin pas coverage {version}"

        # (c) La version qui mesure effectivement la preuve est celle qui est épinglée.
        assert coverage.__version__ == version, (
            f"coverage {coverage.__version__} est installé alors que le pin est {version} : "
            "la preuve de couverture n'est plus reproductible à l'identique."
        )
