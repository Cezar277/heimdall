"""Tests du ticket #64 — authentification par clé API de projet.

Ce fichier couvre la brique #64 (`heimdall/vault/auth.py`) :

- génération d'une clé aléatoire à ≥ 256 bits (`secrets.token_urlsafe(32)`) ;
- stockage du HACHÉ de vérification uniquement (jamais la clé brute) ;
- dépendance FastAPI qui lit l'en-tête `X-Heimdall-API-Key`, retrouve la clé et
  vérifie qu'elle appartient AU projet demandé (401 / 403) ;
- clé jamais stockée, journalisée ni affichée en clair après sa création ;
- cycle de vie complet (émission, révocation) via la CLI `heimdall vault key`.

Preuves SAMM : module + ligne (voir `docs/t64-samm.md`).
"""

import base64
import hashlib
import hmac
import logging
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from typer.testing import CliRunner

from heimdall.cli.main import app as cli_app
from heimdall.vault import auth as vault_auth
from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import VaultCipher, generate_api_key, generate_encryption_key
from heimdall.vault.database import init_db
from heimdall.vault.store import SqliteSecretStore

PEPPER = "t64_pepper_value_0123456789abcdef"
OTHER_PEPPER = "t64_other_pepper_value_9876543210abcd"

_UNAUTHORIZED_BODY = {"code": "unauthorized", "message": "Authentification requise"}
_FORBIDDEN_BODY = {"code": "forbidden", "message": "Accès interdit"}


class ApiKeyGenerationTests(unittest.TestCase):
    """Émission de la clé : entropie, unicité, affichage unique."""

    def test_generated_key_has_at_least_256_bits(self) -> None:
        """La clé émise est un token base64url de 32 octets (256 bits)."""
        key = vault_auth.generate_project_api_key()
        self.assertEqual(len(key), 43)
        # 43 caractères base64url -> 32 octets d'entropie (secrets.token_urlsafe).
        padding = "=" * (-len(key) % 4)
        self.assertEqual(len(base64.urlsafe_b64decode(key + padding)), 32)
        self.assertNotEqual(key, vault_auth.generate_project_api_key())

    def test_issued_key_is_returned_once_and_never_kept(self) -> None:
        """La clé brute est rendue une fois puis abandonnée (repr expurgé)."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        issued = registry.issue("demo")
        self.assertEqual(issued.project_id, "demo")
        self.assertTrue(issued.key_id.startswith("key_"))
        # La clé brute n'est conservée nulle part dans le registre.
        self.assertNotIn(issued.raw_key, repr(issued))
        self.assertNotIn(issued.raw_key, repr(registry.active_hashes))
        self.assertNotIn(issued.raw_key, repr(registry.list_entries()))
        # Une seconde émission produit une clé différente.
        self.assertNotEqual(registry.issue("demo").raw_key, issued.raw_key)

    def test_issued_key_is_stored_only_as_a_hash(self) -> None:
        """Seul le haché de vérification est persisté, jamais la clé brute."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.db"
            init_db(db_path)
            issued = vault_auth.issue_api_key(db_path, "demo", PEPPER)
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute("SELECT id, project_id, key_hash FROM api_keys").fetchall()
            self.assertEqual(len(rows), 1)
            key_id, project_id, key_hash = rows[0]
            self.assertEqual(key_id, issued.key_id)
            self.assertEqual(project_id, "demo")
            self.assertNotEqual(key_hash, issued.raw_key)
            self.assertNotIn(issued.raw_key, key_hash)
            # HMAC-SHA256 du pepper serveur : 64 caractères hexadécimaux.
            self.assertRegex(key_hash, r"^[0-9a-f]{64}$")
            expected = hmac.new(
                PEPPER.encode(), issued.raw_key.encode(), hashlib.sha256
            ).hexdigest()
            self.assertEqual(key_hash, expected)

    def test_hash_depends_on_the_server_pepper(self) -> None:
        """Deux peppers différents donnent deux empreintes différentes."""
        key = generate_api_key()
        first = vault_auth.hash_project_api_key(key, PEPPER)
        second = vault_auth.hash_project_api_key(key, OTHER_PEPPER)
        self.assertNotEqual(first, second)
        # Jamais un SHA-256 nu : le pepper rend l'empreinte indéchiffrable
        # hors ligne si la base fuit (openapi.yaml:197-200).
        self.assertNotEqual(first, hashlib.sha256(key.encode()).hexdigest())

    def test_hash_requires_an_explicit_long_pepper(self) -> None:
        """Sans pepper explicite ou trop court, le hachage échoue (fail-closed)."""
        key = generate_api_key()
        with self.assertRaises(ValueError):
            vault_auth.hash_project_api_key(key, "")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            vault_auth.hash_project_api_key(key, "court")


class ApiKeyVerificationTests(unittest.IsolatedAsyncioTestCase):
    """Dépendance FastAPI : 401 générique, 403 hors projet, aucun écho."""

    async def _request(self, target: FastAPI, path: str, key: str | None) -> Response:
        headers = {} if key is None else {"X-Heimdall-API-Key": key}
        transport = ASGITransport(app=target, client=("127.0.0.1", 54321))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8443") as client:
            return await client.get(path, headers=headers)

    async def test_missing_unknown_and_revoked_keys_return_the_same_401(self) -> None:
        """Clé absente, inconnue ou révoquée : un 401 générique identique."""
        target = create_app(VaultSettings(api_key_pepper=PEPPER))
        raw_key = generate_api_key()
        target.state.register_api_key(raw_key, "demo")
        registry = target.state.api_key_registry
        key_id = registry.list_entries()[0].key_id
        self.assertTrue(registry.revoke(key_id))

        responses = []
        for candidate in (None, "inconnue-cle-api-de-project", raw_key):
            with self.subTest(candidate=candidate):
                response = await self._request(
                    target, "/api/v1/secrets/demo/dev/MY_KEY", candidate
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), _UNAUTHORIZED_BODY)
                responses.append(response.text)

    async def test_key_of_another_project_is_forbidden(self) -> None:
        """Une clé valide d'un projet A obtient 403 sur le projet B."""
        target = create_app(VaultSettings(api_key_pepper=PEPPER))
        raw_key = generate_api_key()
        target.state.register_api_key(raw_key, "project_alpha")

        # Le 403 ne dépend pas de l'existence du secret : l'autorisation est
        # tranchée AVANT la recherche de ressource (openapi.yaml:83-85).
        paths = (
            "/api/v1/secrets/project_beta/dev/ABSENT",
            "/api/v1/secrets/project_beta/dev/PRESENT",
        )
        for path in paths:
            with self.subTest(path=path):
                response = await self._request(target, path, raw_key)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), _FORBIDDEN_BODY)

    async def test_valid_key_authorizes_its_own_project(self) -> None:
        """Une clé valide accède aux secrets de SON projet."""
        target = create_app(VaultSettings(api_key_pepper=PEPPER))
        raw_key = generate_api_key()
        target.state.register_api_key(raw_key, "demo")
        response = await self._request(target, "/api/v1/secrets/demo/dev/MY_KEY", raw_key)
        # 404 : autorisé mais le secret n'existe pas (le store mémoire est vide).
        self.assertEqual(response.status_code, 404)

    async def test_explicit_secret_store_path_is_shared_by_auth(self) -> None:
        """Un store explicite sur un autre fichier aligne écriture ET lecture.

        Régression de l'extraction #64 : le registre était construit avec le
        chemin des settings (``resolved_db``) alors que ``create_app`` venait
        d'aligner ``app.state.db_path`` sur le store explicite. L'écriture
        allait dans A et la vérification lisait B → 401 permanent.
        """
        with tempfile.TemporaryDirectory() as tmp:
            settings_db = Path(tmp) / "settings.db"
            store_db = Path(tmp) / "store.db"
            store = SqliteSecretStore(store_db, VaultCipher(b"S" * 32))
            target = create_app(
                VaultSettings(
                    db_path=str(settings_db),
                    storage_backend="sqlite",
                    kek=generate_encryption_key(),
                    api_key_pepper=PEPPER,
                ),
                secret_store=store,
            )
            registry = target.state.api_key_registry
            self.assertEqual(registry.db_path, store_db)

            raw_key = generate_api_key()
            key_id = target.state.register_api_key(raw_key, "demo")

            # La clé enregistrée doit être retrouvée par l'authentification :
            # création puis lecture du secret prouvent que le registre écrit
            # et lit le MÊME fichier que le store explicite.
            transport = ASGITransport(app=target, client=("127.0.0.1", 54321))
            async with AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1:8443",
                headers={"X-Heimdall-API-Key": raw_key},
            ) as client:
                created = await client.post(
                    "/api/v1/secrets",
                    json={
                        "project": "demo",
                        "env": "dev",
                        "name": "ABSENT",
                        "value": "valeur-de-test",
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                response = await client.get("/api/v1/secrets/demo/dev/ABSENT")
                self.assertEqual(response.status_code, 200, response.text)

                # La révocation doit viser le même fichier que l'authentification.
                self.assertTrue(registry.revoke(key_id))
                revoked = await client.get("/api/v1/secrets/demo/dev/ABSENT")
            self.assertEqual(revoked.status_code, 401)
            self.assertEqual(revoked.json(), _UNAUTHORIZED_BODY)

    async def test_received_key_is_never_echoed_in_the_response(self) -> None:
        """La clé reçue n'apparaît ni dans le corps d'erreur ni dans l'en-tête."""
        target = create_app(VaultSettings(api_key_pepper=PEPPER))
        raw_key = generate_api_key()
        response = await self._request(target, "/api/v1/secrets/demo/dev/MY_KEY", raw_key)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(raw_key, response.text)
        for header_value in response.headers.values():
            self.assertNotIn(raw_key, header_value)

    async def test_received_key_is_never_logged(self) -> None:
        """La clé reçue n'apparaît dans aucun journal (invariant 8)."""
        target = create_app(VaultSettings(api_key_pepper=PEPPER))
        raw_key = generate_api_key()
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = logging.getLogger("heimdall.vault")
        handler = _Capture()
        previous_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        try:
            await self._request(target, "/api/v1/secrets/demo/dev/MY_KEY", raw_key)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous_level)
        joined = "\n".join(record.getMessage() for record in records)
        self.assertNotIn(raw_key, joined)
        self.assertNotIn(raw_key, repr(records))


class ApiKeyRegistryTests(unittest.TestCase):
    """Registre : idempotence, révocation, pas de réactivation."""

    def test_registration_is_idempotent_for_the_same_project(self) -> None:
        """Réenregistrer la même clé pour le même projet ne duplique rien."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        raw_key = generate_api_key()
        first = registry.register(raw_key, "demo")
        second = registry.register(raw_key, "demo")
        self.assertEqual(first, second)
        self.assertEqual(len(registry.active_hashes), 1)

    def test_a_key_cannot_be_reassigned_to_another_project(self) -> None:
        """Une clé déjà liée à un projet ne peut pas être liée à un autre."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        raw_key = generate_api_key()
        registry.register(raw_key, "demo")
        with self.assertRaisesRegex(ValueError, "déjà associée"):
            registry.register(raw_key, "other")

    def test_revoked_key_cannot_be_reactivated(self) -> None:
        """Une clé révoquée ne redevient pas active par ré-enregistrement."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        raw_key = generate_api_key()
        key_id = registry.register(raw_key, "demo")
        self.assertTrue(registry.revoke(key_id))
        self.assertFalse(registry.revoke(key_id))
        self.assertNotIn(vault_auth.hash_project_api_key(raw_key, PEPPER), registry.active_hashes)
        # Ré-enregistrer la clé révoquée ne la réactive pas.
        registry.register(raw_key, "demo")
        self.assertNotIn(vault_auth.hash_project_api_key(raw_key, PEPPER), registry.active_hashes)

    def test_trivial_key_patterns_are_refused_without_echo(self) -> None:
        """Les motifs triviaux sont refusés, sans jamais répéter la clé."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        for weak in (
            "a" * 43,
            "abcdefghijkl" * 4,
            "short",
            "avec espace" * 5,
            # Suite monotone de 8+ caractères (5e contrôle).
            "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE",
            # Ligne de clavier connue (6e contrôle).
            "qwertyuiopZx9-plQv2Mw4Rt6Yb8Nd3Ff7Hg5Jj1Kk0Ll",
            # `fullmatch` : un `\n` final ne doit pas passer via `$`.
            "A" * 42 + "\n",
        ):
            with self.subTest(weak=weak[:12]):
                with self.assertRaises(ValueError) as ctx:
                    registry.register(weak, "demo")
                self.assertNotIn(weak, str(ctx.exception))

    def test_invalid_project_id_is_refused_without_echo(self) -> None:
        """Un identifiant de projet hors contrat est refusé sans écho."""
        registry = vault_auth.ApiKeyRegistry(pepper=PEPPER)
        raw_key = generate_api_key()
        for bad_project in ("../..", "Demo", "demo!", "a" * 65, ""):
            with self.subTest(project=bad_project):
                with self.assertRaises(ValueError) as ctx:
                    registry.register(raw_key, bad_project)
                self.assertIn("Identifiant de projet invalide", str(ctx.exception))
                if bad_project:
                    self.assertNotIn(bad_project, str(ctx.exception))

    def test_registry_without_pepper_refuses_every_write(self) -> None:
        """Un registre à pepper vide ne peut ni enregistrer ni émettre."""
        registry = vault_auth.ApiKeyRegistry(pepper="")
        with self.assertRaises(ValueError):
            registry.register(generate_api_key(), "demo")
        with self.assertRaises(ValueError):
            registry.issue("demo")
        with self.assertRaises(ValueError):
            registry.register_hash("a" * 64, "demo")
        self.assertEqual(registry.active_hashes, {})

    def test_key_id_with_trailing_newline_is_refused(self) -> None:
        """``fullmatch`` : un ``\\n`` final ne doit pas passer avant l'écho CLI."""
        for malformed in (
            "key_" + "a" * 32 + "\n",
            "key_" + "a" * 32 + "\r\n",
            "key_" + "a" * 32 + " ",
        ):
            with self.subTest(malformed=repr(malformed[-2:])):
                with self.assertRaises(ValueError) as ctx:
                    vault_auth.validate_key_id(malformed)
                self.assertNotIn(malformed, str(ctx.exception))

    def test_public_dev_pepper_is_refused_outside_test_mode(self) -> None:
        """Le pepper public committé est refusé hors HEIMDALL_ENV=test."""
        with self.assertRaises(ValueError):
            vault_auth.validate_api_key_pepper(vault_auth.INSECURE_DEFAULT_PEPPER)
        with self.assertRaises(ValueError):
            vault_auth.validate_api_key_pepper("trop-court")


class VaultKeyCliTests(unittest.IsolatedAsyncioTestCase):
    """CLI `heimdall vault key` : émission, listage, révocation."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "vault.db"
        self.runner = CliRunner()
        self._pepper_env = os.environ.get("HEIMDALL_VAULT_API_KEY_PEPPER")
        os.environ["HEIMDALL_VAULT_API_KEY_PEPPER"] = PEPPER

    def tearDown(self) -> None:
        if self._pepper_env is None:
            os.environ.pop("HEIMDALL_VAULT_API_KEY_PEPPER", None)
        else:
            os.environ["HEIMDALL_VAULT_API_KEY_PEPPER"] = self._pepper_env
        self._tmp.cleanup()

    def _create(self) -> str:
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "create", "--project", "demo", "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        return result.output

    @staticmethod
    def _extract_key(output: str) -> str:
        """Extrait la clé affichée : ligne suivant l'en-tête d'émission."""
        lines = output.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("Clé API de projet émise"):
                return lines[index + 1].strip()
        raise AssertionError("Clé API non affichée")

    def test_create_displays_the_key_once_and_stores_only_the_hash(self) -> None:
        """La clé est affichée une fois ; la base ne contient que son haché."""
        output = self._create()
        raw_key = self._extract_key(output)
        self.assertGreaterEqual(len(raw_key), 43)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT id, key_hash FROM api_keys").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0][1], raw_key)
        self.assertNotIn(raw_key, rows[0][1])

    def test_list_shows_metadata_only(self) -> None:
        """Le listage n'expose ni la clé brute ni son empreinte."""
        output = self._create()
        raw_key = self._extract_key(output)
        result = self.runner.invoke(
            cli_app, ["vault", "key", "list", "--db-path", str(self.db_path)]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn(raw_key, result.output)
        self.assertNotIn(vault_auth.hash_project_api_key(raw_key, PEPPER), result.output)
        self.assertIn("projet=demo", result.output)

    async def test_revoke_stops_the_key_from_authenticating(self) -> None:
        """Cycle CLI complet : create → authentifié → revoke → 401 générique."""
        output = self._create()
        raw_key = self._extract_key(output)
        self.assertGreaterEqual(len(raw_key), 43)
        key_id = next(
            line for line in output.splitlines() if line.startswith("Identifiant")
        ).split(":", 1)[1].strip()

        # Le serveur configuré sur la même base voit la clé avant révocation.
        target = create_app(
            VaultSettings(
                db_path=str(self.db_path),
                storage_backend="sqlite",
                kek=generate_encryption_key(),
                api_key_pepper=PEPPER,
            )
        )
        transport = ASGITransport(app=target, client=("127.0.0.1", 54321))
        async with AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8443",
            headers={"X-Heimdall-API-Key": raw_key},
        ) as client:
            # Avant révocation : la clé authentifie et accède à SA ressource.
            created = await client.post(
                "/api/v1/secrets",
                json={
                    "project": "demo",
                    "env": "dev",
                    "name": "MY_KEY",
                    "value": "valeur-de-test",
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            before = await client.get("/api/v1/secrets/demo/dev/MY_KEY")
            self.assertEqual(before.status_code, 200, before.text)

            result = self.runner.invoke(
                cli_app,
                ["vault", "key", "revoke", key_id, "--db-path", str(self.db_path)],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            with sqlite3.connect(self.db_path) as conn:
                revoked_at = conn.execute(
                    "SELECT revoked_at FROM api_keys WHERE id = ?", (key_id,)
                ).fetchone()[0]
            self.assertIsNotNone(revoked_at)

            # La même instance applicative refuse désormais la clé révoquée :
            # la lecture SQLite est l'autorité, pas l'instantané mémoire.
            after = await client.get("/api/v1/secrets/demo/dev/MY_KEY")
        self.assertEqual(after.status_code, 401)
        self.assertEqual(after.json(), _UNAUTHORIZED_BODY)
        self.assertNotIn(raw_key, after.text)

    def test_create_without_explicit_pepper_fails_closed(self) -> None:
        """Sans pepper explicite, la CLI refuse d'émettre une clé morte."""
        os.environ.pop("HEIMDALL_VAULT_API_KEY_PEPPER", None)
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "create", "--project", "demo", "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("HEIMDALL_VAULT_API_KEY_PEPPER", result.output)

    def test_relative_db_path_is_refused(self) -> None:
        """Un chemin relatif est refusé (dépend du répertoire courant)."""
        result = self.runner.invoke(
            cli_app, ["vault", "key", "create", "--project", "demo", "--db-path", "relatif.db"]
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("absolu", result.output)

    def test_revoke_works_without_a_server_pepper(self) -> None:
        """La révocation n'a pas de pepper : aucun registre « pepper vide ».

        La révocation ne calcule ni ne vérifie d'empreinte : elle écrit
        directement dans la base. Elle doit donc fonctionner sans pepper
        serveur, sans construire de registre capable d'émettre des
        empreintes faibles.
        """
        output = self._create()
        key_id = next(
            line for line in output.splitlines() if line.startswith("Identifiant")
        ).split(":", 1)[1].strip()
        os.environ.pop("HEIMDALL_VAULT_API_KEY_PEPPER", None)
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "revoke", key_id, "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        with sqlite3.connect(self.db_path) as conn:
            revoked_at = conn.execute(
                "SELECT revoked_at FROM api_keys WHERE id = ?", (key_id,)
            ).fetchone()[0]
        self.assertIsNotNone(revoked_at)

    def test_list_rejects_an_invalid_project_filter(self) -> None:
        """Un filtre ``--project`` hors contrat échoue en 2, sans écho."""
        init_db(self.db_path)
        result = self.runner.invoke(
            cli_app,
            [
                "vault",
                "key",
                "list",
                "--project",
                "../..",
                "--db-path",
                str(self.db_path),
            ],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Identifiant de projet invalide", result.output)
        self.assertNotIn("../..", result.output)

    def test_list_on_empty_registry_says_nothing_registered(self) -> None:
        """Un registre vide est signalé explicitement (pas de ligne fantôme)."""
        init_db(self.db_path)
        result = self.runner.invoke(
            cli_app, ["vault", "key", "list", "--db-path", str(self.db_path)]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Aucune clé API enregistrée", result.output)

    def test_revoke_unknown_key_id_fails(self) -> None:
        """Révoquer une clé inconnue échoue sans rien modifier."""
        init_db(self.db_path)
        unknown = "key_" + "0" * 32
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "revoke", unknown, "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("introuvable", result.output)

    def test_revoke_rejects_a_malformed_key_id_without_echo(self) -> None:
        """Un identifiant de clé hors format est refusé sans être réfléchi."""
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "revoke", "pas-un-identifiant", "--db-path", str(self.db_path)],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Identifiant de clé API invalide", result.output)
        self.assertNotIn("pas-un-identifiant", result.output)

    def test_memory_db_is_refused(self) -> None:
        """Le mode ':memory:' est interdit en CLI (base éphémère)."""
        result = self.runner.invoke(
            cli_app,
            ["vault", "key", "create", "--project", "demo", "--db-path", ":memory:"],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn(":memory:", result.output)


if __name__ == "__main__":
    unittest.main()
