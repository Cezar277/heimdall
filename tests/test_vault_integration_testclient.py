"""Tests d'intégration du Vault avec le `TestClient` FastAPI (ticket #65).

Ce fichier est la preuve automatisée que le Vault **respecte le contrat
OpenAPI** (`openapi.yaml`, ticket #15) et **refuse ce qu'il doit refuser** :

- **cas nominal** : `POST /api/v1/secrets` puis
  `GET /api/v1/secrets/{project}/{env}/{name}` (201 sans la valeur, 200 avec la
  valeur, `Cache-Control: no-store` sur les deux) ;
- **clé invalide** (absente, inconnue, révoquée, malformée) -> 401 générique,
  jamais d'écho de la clé reçue ;
- **secret d'un autre projet** -> 403 (autorisation tranchée AVANT toute
  recherche de ressource : l'existence d'un secret n'est jamais révélée) ;
- **conformité OpenAPI** : chaque réponse produite est validée contre le schéma
  du contrat (`jsonschema`, JSON Schema 2020-12 comme OpenAPI 3.1) et le schéma
  OpenAPI produit par l'application est comparé à `openapi.yaml` ;
- **chiffrement au repos** : la valeur en clair n'apparaît jamais dans le
  fichier SQLite ;
- **refus de transport** : une origine hors boucle locale est rejetée en 403 ;
- **débit** : au-delà du quota de clé, 429 contractuel avec `Retry-After` borné ;
- **abus d'entrée** : corps > 1 Mio, identifiants hors contrat et tentatives de
  traversée de chemin sont refusés (400/404), sans jamais refléter l'entrée.

ISOLATION (piège du ticket) : aucun test ne partage de base. Chaque test crée
SA propre base SQLite dans SON propre répertoire temporaire, SA propre
application et SON propre `TestClient` ; aucun état global n'est muté (le
singleton `get_app()` n'est jamais appelé). Les tests sont donc indépendants et
réexécutables dans n'importe quel ordre.

Choix techniques :
- `fastapi.testclient.TestClient` (starlette) pilote l'application **en
  mémoire**, sans port réseau : le test reste 100 % local (invariant « aucun
  appel réseau sortant ») ;
- le client est présenté comme `127.0.0.1` : la garde middleware loopback
  (`heimdall/vault/app.py`) rejette en 403 toute autre origine, y compris
  l'hôte par défaut `testclient` du `TestClient` ;
- la base est le backend **SQLite** (le backend de production) : le test
  couvre donc le chemin chiffré et persistant, pas seulement le store mémoire ;
- la KEK et le pepper sont générés à l'exécution (`generate_encryption_key`,
  `generate_api_key`) : aucun secret, même factice, n'est commité.

Preuves SAMM : module + ligne (voir `docs/t255-samm.md`).
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import generate_api_key, generate_encryption_key

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT: dict[str, Any] = yaml.safe_load((REPO_ROOT / "openapi.yaml").read_text(encoding="utf-8"))

_API_KEY_HEADER = "X-Heimdall-API-Key"
_BASE_URL = "http://127.0.0.1:8443"
# La garde loopback refuse toute origine hors allowlist : le `TestClient` doit
# donc se présenter comme une connexion locale explicite.
_LOOPBACK_CLIENT = ("127.0.0.1", 50000)

_PROJECT = "demo"
_OTHER_PROJECT = "autre"
_ENV = "dev"
_NAME = "DEMO_PASSWORD"
# Valeur factice VOLONTAIRE de fixture : entropie nulle, ce n'est pas un secret
# (invariant « fixtures non secrètes » du dépôt). Elle sert à prouver que la
# valeur en clair n'atterrit ni dans une réponse 201 ni dans le fichier SQLite.
_TEST_VALUE = "valeur-de-test"

# Gabarits de chemins du CONTRAT (la requête, elle, utilise le triplet réel).
# Noms sans « secret » : S105 (bandit) les traiterait comme des mots de passe.
_COLLECTION_ROUTE = "/api/v1/secrets"
_READ_ROUTE = "/api/v1/secrets/{project}/{env}/{name}"

_UNAUTHORIZED_BODY = {"code": "unauthorized", "message": "Authentification requise"}
_FORBIDDEN_BODY = {"code": "forbidden", "message": "Accès interdit"}
_NOT_FOUND_BODY = {"code": "not_found", "message": "Ressource introuvable"}
_BAD_REQUEST_BODY = {"code": "bad_request", "message": "Requête invalide"}

# Modèles du contrat dont le nom diffère côté application (`HealthResponse`).
_SCHEMA_ALIASES = {"Health": "HealthResponse"}


def _resolve(document: dict[str, Any], node: Any) -> Any:
    """Résout les `$ref` internes du contrat (hors ligne, sans accès réseau)."""
    if isinstance(node, list):
        return [_resolve(document, item) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        reference = node["$ref"]
        if not reference.startswith("#/"):
            raise ValueError("Référence externe interdite dans les tests hors ligne")
        target: Any = document
        for segment in reference[2:].split("/"):
            target = target[segment.replace("~1", "/").replace("~0", "~")]
        return _resolve(document, target)
    return {key: _resolve(document, value) for key, value in node.items()}


def _structural(schema: Any) -> Any:
    """Normalise un schéma pour comparaison : annotations documentaires écartées.

    Clés écartées (et UNIQUEMENT celles-là) : `title`, `description`,
    `examples`, `example` — des annotations purement documentaires, qui ne
    modifient ni l'ensemble des instances acceptées ni les contraintes. C'est
    la convention déjà retenue par le test de contrat du dépôt
    (`tests/contracts/test_vault_openapi.py`).

    Toutes les CONTRAINTES sont conservées et comparées : `required`,
    `additionalProperties`, `pattern`, `minLength`, `maxLength`, `const`,
    `enum`. AUCUNE normalisation n'est appliquée à `required` : un écart de
    contrat sur la présence d'un champ fait échouer la suite.
    """
    if isinstance(schema, list):
        return [_structural(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result: dict[str, Any] = {}
    for key, value in schema.items():
        if key in {"title", "description", "examples", "example"}:
            continue
        result[key] = (
            sorted(value) if key == "required" and isinstance(value, list) else _structural(value)
        )
    return result


class VaultIntegrationTestCase(unittest.TestCase):
    """Base commune : une base temporaire, une application et un client NEUFS par test."""

    # Surcharges de configuration par classe fille (ex. quotas de débit).
    settings_overrides: dict[str, Any] = {}

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heimdall-t65-")
        self.addCleanup(self._tmp.cleanup)
        # `resolve()` : le chemin doit être absolu et sans lien symbolique
        # (garde fail-closed de la couche DB).
        self.db_path = Path(self._tmp.name).resolve() / "vault.db"
        self.app = create_app(self._build_settings(self.db_path))
        self.client = TestClient(
            self.app,
            base_url=_BASE_URL,
            client=_LOOPBACK_CLIENT,
        )
        self.addCleanup(self.client.close)
        self.api_key = generate_api_key()
        self.app.state.register_api_key(self.api_key, _PROJECT)

    @classmethod
    def _build_settings(cls, db_path: Path) -> VaultSettings:
        """Configuration de test : KEK et pepper ALÉATOIRES (jamais committés).

        Surchargable par une classe fille via `settings_overrides` (débit,
        par exemple) sans jamais toucher à une base partagée.
        """
        settings: dict[str, Any] = {
            "db_path": str(db_path),
            "storage_backend": "sqlite",
            "kek": generate_encryption_key(),
            "api_key_pepper": generate_api_key(),
        }
        settings.update(cls.settings_overrides)
        return VaultSettings(**settings)

    def _auth(self, key: str | None = None) -> dict[str, str]:
        """En-têtes de requête, avec la clé API si elle est fournie."""
        return {} if key is None else {_API_KEY_HEADER: key}

    def _create_secret(self, key: str | None = None) -> Any:
        """POST nominal d'un secret (projet courant, environnement `dev`)."""
        return self.client.post(
            "/api/v1/secrets",
            json={
                "project": _PROJECT,
                "env": _ENV,
                "name": _NAME,
                "value": _TEST_VALUE,
            },
            headers=self._auth(key),
        )

    def _read_secret(self, key: str | None = None, name: str = _NAME) -> Any:
        """GET nominal de la valeur d'un secret."""
        return self.client.get(
            f"/api/v1/secrets/{_PROJECT}/{_ENV}/{name}",
            headers=self._auth(key),
        )

    def _contract_response(self, path: str, method: str, status: int) -> dict[str, Any]:
        """Retourne la réponse du contrat pour (chemin, méthode, statut).

        Les réponses du contrat sont des `$ref` vers `components/responses` :
        elles sont résolues ici pour obtenir le corps et les en-têtes réels.
        """
        responses = CONTRACT["paths"][path][method]["responses"]
        self.assertIn(str(status), responses, f"{status} absent du contrat pour {method} {path}")
        return _resolve(CONTRACT, responses[str(status)])

    def _assert_contract_body(self, response: Any, path: str, method: str, status: int) -> None:
        """Valide le corps de la réponse LIVE contre le schéma du contrat OpenAPI."""
        contract_response = self._contract_response(path, method, status)
        schema = _resolve(
            CONTRACT,
            contract_response["content"]["application/json"]["schema"],
        )
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(response.json()), key=lambda error: error.message)
        self.assertEqual(
            errors,
            [],
            f"Réponse {status} non conforme au contrat pour {method} {path} : {errors}",
        )
        self.assertEqual(response.headers.get("content-type"), "application/json")

    def _assert_contract_headers(self, response: Any, path: str, method: str, status: int) -> None:
        """Vérifie les en-têtes EXIGÉS par le contrat pour cette réponse."""
        contract_response = self._contract_response(path, method, status)
        headers = _resolve(CONTRACT, contract_response.get("headers", {}))
        for name, specification in headers.items():
            if not specification.get("required"):
                continue
            self.assertIn(name.lower(), {key.lower() for key in response.headers})
            schema = specification.get("schema", {})
            if "const" in schema:
                self.assertEqual(response.headers[name], schema["const"])


class VaultNominalFlowTests(VaultIntegrationTestCase):
    """Cas nominal : POST puis GET sur le backend SQLite chiffré."""

    def test_post_then_get_returns_the_created_secret(self) -> None:
        """POST 201 (métadonnées sans la valeur) puis GET 200 (avec la valeur)."""
        created = self._create_secret(self.api_key)
        self.assertEqual(created.status_code, 201)
        self.assertEqual(
            created.json(),
            {
                "project": _PROJECT,
                "env": _ENV,
                "name": _NAME,
                "status": "vaulte",
            },
        )

        read = self._read_secret(self.api_key)
        self.assertEqual(read.status_code, 200)
        self.assertEqual(
            read.json(),
            {
                "project": _PROJECT,
                "env": _ENV,
                "name": _NAME,
                "status": "vaulte",
                "value": _TEST_VALUE,
            },
        )

    def test_creation_response_never_contains_the_value(self) -> None:
        """La réponse 201 ne renvoie que des métadonnées : jamais la valeur."""
        created = self._create_secret(self.api_key)
        self.assertEqual(created.status_code, 201)
        self.assertNotIn("value", created.json())
        self.assertNotIn(_TEST_VALUE, created.text)

    def test_secret_responses_are_not_cacheable(self) -> None:
        """`Cache-Control: no-store` exigé par le contrat sur 201 et 200."""
        created = self._create_secret(self.api_key)
        read = self._read_secret(self.api_key)
        for response, path, method, status in (
            (created, _COLLECTION_ROUTE, "post", 201),
            (read, _READ_ROUTE, "get", 200),
        ):
            with self.subTest(status=status):
                self.assertEqual(response.headers.get("cache-control"), "no-store")
                self._assert_contract_headers(response, path, method, status)

    def test_value_is_encrypted_at_rest(self) -> None:
        """La valeur en clair n'apparaît jamais dans le fichier SQLite."""
        created = self._create_secret(self.api_key)
        self.assertEqual(created.status_code, 201)
        self.assertTrue(self.db_path.is_file())
        raw_database = self.db_path.read_bytes()
        self.assertNotIn(_TEST_VALUE.encode("utf-8"), raw_database)
        # La ligne existe bien et n'est pas vide : le secret est stocké, chiffré.
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT encrypted_value, status FROM secrets WHERE project_id = ? AND name = ?",
                (_PROJECT, _NAME),
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0][0])
        self.assertEqual(rows[0][1], "vaulte")

    def test_database_file_is_not_world_readable(self) -> None:
        """La base temporaire est créée en 0o600 (permissions durcies, invariants 1/10)."""
        self._create_secret(self.api_key)
        mode = self.db_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_unknown_secret_of_own_project_is_not_found(self) -> None:
        """404 pour un secret inexistant du projet autorisé (pas de fuite d'information)."""
        response = self._read_secret(self.api_key, name="ABSENT_KEY")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), _NOT_FOUND_BODY)


class VaultInvalidApiKeyTests(VaultIntegrationTestCase):
    """Clé invalide : 401 générique, jamais d'écho de la clé reçue."""

    def test_missing_unknown_revoked_and_malformed_keys_are_rejected(self) -> None:
        """Absente, inconnue, révoquée ou malformée : 401 identique à chaque fois."""
        self._create_secret(self.api_key)
        registry = self.app.state.api_key_registry
        key_id = registry.list_entries()[0].key_id
        self.assertTrue(registry.revoke(key_id))

        cases = {
            "absente": None,
            "inconnue": generate_api_key(),
            "révoquée": self.api_key,
            "malformée": "cle-courte",
            "espaces": f" {self.api_key}",
        }
        for label, candidate in cases.items():
            with self.subTest(cas=label):
                response = self._read_secret(candidate)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), _UNAUTHORIZED_BODY)

    def test_responses_are_identical_whatever_the_failure_cause(self) -> None:
        """Aucun oracle : le corps 401 est identique (clé absente vs clé inconnue)."""
        without_key = self._read_secret(None)
        with_unknown_key = self._read_secret(generate_api_key())
        self.assertEqual(without_key.status_code, 401)
        self.assertEqual(with_unknown_key.status_code, 401)
        self.assertEqual(without_key.text, with_unknown_key.text)

    def test_rejected_key_is_never_echoed(self) -> None:
        """La clé reçue n'apparaît ni dans le corps ni dans les en-têtes de réponse."""
        candidate = generate_api_key()
        response = self._read_secret(candidate)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(candidate, response.text)
        for header_value in response.headers.values():
            self.assertNotIn(candidate, header_value)

    def test_write_is_rejected_without_a_valid_key(self) -> None:
        """Un POST sans clé valide est refusé 401 : rien n'est écrit."""
        response = self._create_secret(generate_api_key())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), _UNAUTHORIZED_BODY)
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
        self.assertEqual(count, 0)


class VaultCrossProjectAccessTests(VaultIntegrationTestCase):
    """Secret d'un autre projet : refus 403, existence jamais révélée."""

    def _other_project_key(self) -> str:
        """Enregistre et retourne une clé API d'un projet tiers."""
        other_key = generate_api_key()
        self.app.state.register_api_key(other_key, _OTHER_PROJECT)
        return other_key

    def test_reading_another_project_secret_is_forbidden(self) -> None:
        """Une clé valide d'un autre projet obtient 403 sur un secret existant."""
        self._create_secret(self.api_key)
        other_key = self._other_project_key()
        response = self.client.get(
            f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}",
            headers=self._auth(other_key),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), _FORBIDDEN_BODY)

    def test_forbidden_is_decided_before_the_resource_lookup(self) -> None:
        """403 que le secret existe ou non : l'existence n'est pas révélée."""
        other_key = self._other_project_key()
        for name in (_NAME, "ABSENT_KEY"):
            with self.subTest(secret=name):
                response = self.client.get(
                    f"/api/v1/secrets/{_PROJECT}/{_ENV}/{name}",
                    headers=self._auth(other_key),
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), _FORBIDDEN_BODY)

    def test_writing_into_another_project_is_forbidden_and_writes_nothing(self) -> None:
        """Un POST sur un projet tiers est refusé 403 et n'écrit aucun secret."""
        other_key = self._other_project_key()
        response = self.client.post(
            "/api/v1/secrets",
            json={
                "project": _PROJECT,
                "env": _ENV,
                "name": _NAME,
                "value": _TEST_VALUE,
            },
            headers=self._auth(other_key),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), _FORBIDDEN_BODY)
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
        self.assertEqual(count, 0)

    def test_owner_key_still_reads_its_own_secret_after_a_forbidden_attempt(self) -> None:
        """Le refus du projet tiers n'altère pas l'accès du propriétaire."""
        self._create_secret(self.api_key)
        other_key = self._other_project_key()
        forbidden = self.client.get(
            f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}",
            headers=self._auth(other_key),
        )
        self.assertEqual(forbidden.status_code, 403)
        allowed = self._read_secret(self.api_key)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.json()["value"], _TEST_VALUE)


class VaultOpenapiContractTests(VaultIntegrationTestCase):
    """Le Vault produit exactement ce que le contrat OpenAPI annonce."""

    def test_live_responses_match_the_contract_schemas(self) -> None:
        """Chaque réponse live est validée contre le schéma du contrat OpenAPI."""
        created = self._create_secret(self.api_key)
        self.assertEqual(created.status_code, 201)
        self._assert_contract_body(created, _COLLECTION_ROUTE, "post", 201)

        read = self._read_secret(self.api_key)
        self.assertEqual(read.status_code, 200)
        self._assert_contract_body(read, _READ_ROUTE, "get", 200)

        unauthorized = self._read_secret(None)
        self.assertEqual(unauthorized.status_code, 401)
        self._assert_contract_body(unauthorized, _READ_ROUTE, "get", 401)

        forbidden = self.client.get(
            f"/api/v1/secrets/{_OTHER_PROJECT}/{_ENV}/{_NAME}",
            headers=self._auth(self.api_key),
        )
        self.assertEqual(forbidden.status_code, 403)
        self._assert_contract_body(forbidden, _READ_ROUTE, "get", 403)

    def test_live_error_bodies_carry_the_contract_required_fields(self) -> None:
        """Le contrat exige `code` et `message` : les réponses d'erreur les portent."""
        unauthorized = self._read_secret(None)
        forbidden = self.client.get(
            f"/api/v1/secrets/{_OTHER_PROJECT}/{_ENV}/{_NAME}",
            headers=self._auth(self.api_key),
        )
        for response in (unauthorized, forbidden):
            with self.subTest(status=response.status_code):
                body = response.json()
                self.assertEqual(set(body), {"code", "message"})
                self.assertIn(body["code"], {"unauthorized", "forbidden"})
                self.assertIsInstance(body["message"], str)
                self.assertTrue(body["message"])

    def test_runtime_schema_declares_the_contract_operations(self) -> None:
        """Le schéma OpenAPI de l'application expose les mêmes opérations que le contrat."""
        runtime = self.app.openapi()
        self.assertEqual(set(runtime["paths"]), set(CONTRACT["paths"]))
        for path, path_item in CONTRACT["paths"].items():
            for method, operation in path_item.items():
                if method not in ("get", "post"):
                    continue
                with self.subTest(path=path, method=method):
                    runtime_operation = runtime["paths"][path][method]
                    self.assertEqual(runtime_operation["operationId"], operation["operationId"])
                    self.assertEqual(
                        set(runtime_operation["responses"]),
                        set(operation["responses"]),
                    )

    def test_runtime_payload_schemas_match_the_contract(self) -> None:
        """Les schémas de charge utile produits par l'application respectent le contrat."""
        runtime = self.app.openapi()["components"]["schemas"]
        for name in ("SecretCreate", "SecretMetadata", "SecretRead"):
            with self.subTest(schema=name):
                contract_schema = _structural(
                    _resolve(CONTRACT, {"$ref": f"#/components/schemas/{name}"})
                )
                runtime_schema = _structural(runtime[name])
                self.assertEqual(runtime_schema, contract_schema)

    def test_runtime_error_schemas_match_the_contract(self) -> None:
        """Comparaison STRICTE : le schéma publié DOIT exposer `required`.

        Aucun écart toléré : le schéma OpenAPI publié par l'application est
        comparé champ par champ au contrat, `required` compris. C'est
        possible parce que les modèles d'erreur de `heimdall/vault/app.py`
        déclarent `code`/`message` (et `status` pour `HealthResponse`) SANS
        valeur par défaut : Pydantic les inscrit donc dans `required`, comme
        l'exige `openapi.yaml`.

        Un drift futur sur `required` (ou sur toute autre contrainte) fait
        ÉCHOUER ce test : il n'est plus masqué par une normalisation.
        """
        runtime = self.app.openapi()["components"]["schemas"]
        error_names = (
            "BadRequestError",
            "UnauthorizedError",
            "ForbiddenError",
            "NotFoundError",
            "MethodNotAllowedError",
            "ConflictError",
            "RateLimitedError",
            "UnavailableError",
            "InternalError",
            "Health",
        )
        for name in error_names:
            with self.subTest(schema=name):
                contract_schema = _structural(
                    _resolve(CONTRACT, {"$ref": f"#/components/schemas/{name}"})
                )
                runtime_schema = _structural(runtime[_SCHEMA_ALIASES.get(name, name)])
                self.assertEqual(runtime_schema, contract_schema)

    def test_published_error_schema_declares_the_contract_required_fields(self) -> None:
        """Le schéma publié déclare explicitement les champs exigés par le contrat."""
        runtime = self.app.openapi()["components"]["schemas"]
        for name, required in (
            ("BadRequestError", ["code", "message"]),
            ("UnauthorizedError", ["code", "message"]),
            ("ForbiddenError", ["code", "message"]),
            ("NotFoundError", ["code", "message"]),
            ("MethodNotAllowedError", ["code", "message"]),
            ("ConflictError", ["code", "message"]),
            ("RateLimitedError", ["code", "message"]),
            ("UnavailableError", ["code", "message"]),
            ("InternalError", ["code", "message"]),
            ("HealthResponse", ["status"]),
        ):
            with self.subTest(schema=name):
                self.assertEqual(runtime[name].get("required"), required)


class VaultTransportGuardTests(VaultIntegrationTestCase):
    """Garde de boucle locale : toute origine hors allowlist est refusée."""

    def test_non_loopback_origin_is_forbidden(self) -> None:
        """Une origine non loopback est rejetée en 403, avant tout routage."""
        with TestClient(
            self.app,
            base_url=_BASE_URL,
            client=("192.0.2.1", 50000),
        ) as remote:
            response = remote.get("/api/v1/health")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), _FORBIDDEN_BODY)

    def test_non_loopback_origin_cannot_reach_the_secrets(self) -> None:
        """Même avec une clé valide, une origine non loopback n'atteint pas les secrets."""
        self._create_secret(self.api_key)
        with TestClient(
            self.app,
            base_url=_BASE_URL,
            client=("192.0.2.1", 50000),
        ) as remote:
            response = remote.get(
                f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}",
                headers=self._auth(self.api_key),
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), _FORBIDDEN_BODY)
        self.assertNotIn(_TEST_VALUE, response.text)


class VaultRateLimitTests(VaultIntegrationTestCase):
    """Débit : au-delà du quota, 429 contractuel avec `Retry-After` borné."""

    settings_overrides = {
        "rate_limit_per_key": 1,
        "rate_limit_per_peer": 10,
        "rate_limit_global": 100,
        "rate_limit_window_seconds": 30,
    }

    def test_rate_limited_request_returns_429_with_bounded_retry_after(self) -> None:
        """La première requête passe, la suivante est refusée 429 + `Retry-After`."""
        first = self._read_secret(self.api_key)
        self.assertEqual(first.status_code, 404)

        limited = self._read_secret(self.api_key)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(
            limited.json(),
            {"code": "rate_limited", "message": "Trop de requêtes"},
        )
        # Le contrat impose `Retry-After` sur TOUT 429, borné à 1..3600.
        self.assertIn("retry-after", {key.lower() for key in limited.headers})
        retry_after = int(limited.headers["retry-after"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 3600)
        self._assert_contract_headers(limited, _READ_ROUTE, "get", 429)

    def test_rate_limited_response_matches_the_contract_body(self) -> None:
        """Le corps du 429 de débit est celui du contrat, sans fuite."""
        self._read_secret(self.api_key)
        limited = self._read_secret(self.api_key)
        self.assertEqual(limited.status_code, 429)
        self._assert_contract_body(limited, _READ_ROUTE, "get", 429)
        self.assertNotIn(_TEST_VALUE, limited.text)


class VaultInputAbuseTests(VaultIntegrationTestCase):
    """Abus d'entrée : le Vault refuse, sans jamais refléter l'entrée."""

    def test_oversized_body_is_rejected_with_400(self) -> None:
        """Un corps > 1 Mio est refusé 400 avant parsing (openapi.yaml)."""
        response = self.client.post(
            "/api/v1/secrets",
            content=b"x" * 1_048_577,
            headers={_API_KEY_HEADER: self.api_key, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), _BAD_REQUEST_BODY)

    def test_identifiers_outside_the_contract_are_rejected_with_400(self) -> None:
        """Un identifiant hors contrat (majuscule, NUL, « .. ») donne 400."""
        for path in (
            "/api/v1/secrets/BAD!/dev/KEY",
            "/api/v1/secrets/demo/Dev/KEY",
            "/api/v1/secrets/demo/dev/key_name",
            "/api/v1/secrets/demo/dev/KEY%00",
            "/api/v1/secrets/%2E%2E/dev/KEY",
        ):
            with self.subTest(path=path):
                response = self.client.get(path, headers=self._auth(self.api_key))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), _BAD_REQUEST_BODY)

    def test_path_traversal_attempts_never_expose_a_resource(self) -> None:
        """Une traversée de chemin est refusée (400/404) et n'expose rien."""
        for path in (
            "/api/v1/secrets/..%2F..%2Fetc/dev/KEY",
            "/api/v1/secrets/demo/dev/..%2F..%2Fetc%2Fpasswd",
            "/api/v1/secrets/%2E%2E%2F%2E%2E%2Fetc/dev/KEY",
        ):
            with self.subTest(path=path):
                response = self.client.get(path, headers=self._auth(self.api_key))
                self.assertIn(response.status_code, (400, 404))
                self.assertIn(
                    response.json()["code"],
                    ("bad_request", "not_found"),
                )
                # Aucune trace du chemin visé ni du contenu du fichier.
                self.assertNotIn("etc", response.text)
                self.assertNotIn("passwd", response.text)
                self.assertNotIn("root:", response.text)

    def test_malformed_json_is_rejected_with_400(self) -> None:
        """Un corps JSON mal formé donne 400, sans écho de l'entrée."""
        response = self.client.post(
            "/api/v1/secrets",
            content=b"{ceci nest pas du json",
            headers={_API_KEY_HEADER: self.api_key, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), _BAD_REQUEST_BODY)
        self.assertNotIn("ceci nest pas du json", response.text)


class VaultTestIsolationTests(VaultIntegrationTestCase):
    """Chaque test possède sa base : aucun état partagé (piège du ticket)."""

    def test_each_test_uses_its_own_temporary_database(self) -> None:
        """Deux tests n'ont ni base ni registre de clés partagés (piège du ticket).

        Preuve : une DEUXIÈME application, construite sur une AUTRE base
        temporaire, démarre avec un registre de clés VIDE et ne connaît pas
        les empreintes du test courant. Aucun état ne fuite donc d'un test à
        l'autre (ni la base, ni les clés API, ni les secrets).
        """
        # La base du test est un fichier ABSOLU (la couche DB refuse les
        # chemins relatifs) situé hors du dépôt.
        self.assertTrue(self.db_path.is_absolute())
        self.assertNotIn(str(self.db_path), str(Path.cwd()))

        with tempfile.TemporaryDirectory(prefix="heimdall-t65-other-") as other_tmp:
            other_db = Path(other_tmp).resolve() / "vault.db"
            other_app = create_app(self._build_settings(other_db))

            # 1. Deux bases distinctes.
            self.assertNotEqual(other_db, self.db_path)
            self.assertNotEqual(other_app.state.db_path, self.app.state.db_path)

            # 2. Registre neuf : la clé du test courant n'y figure pas.
            self.assertEqual(other_app.state.api_key_registry.list_entries(), [])

            # 3. Les empreintes des deux applications sont disjointes.
            other_key = generate_api_key()
            other_app.state.register_api_key(other_key, _PROJECT)
            current_hashes = set(self.app.state.api_key_registry.active_hashes)
            other_hashes = set(other_app.state.api_key_registry.active_hashes)
            self.assertEqual(len(current_hashes), 1)
            self.assertEqual(len(other_hashes), 1)
            self.assertEqual(current_hashes & other_hashes, set())

    def test_a_secret_is_invisible_from_another_database(self) -> None:
        """Un secret écrit dans une base n'apparaît pas dans une autre base."""
        created = self._create_secret(self.api_key)
        self.assertEqual(created.status_code, 201)

        with tempfile.TemporaryDirectory(prefix="heimdall-t65-other-") as other_tmp:
            other_db = Path(other_tmp).resolve() / "vault.db"
            other_app = create_app(self._build_settings(other_db))
            other_key = generate_api_key()
            other_app.state.register_api_key(other_key, _PROJECT)
            with TestClient(
                other_app,
                base_url=_BASE_URL,
                client=_LOOPBACK_CLIENT,
            ) as other_client:
                response = other_client.get(
                    f"/api/v1/secrets/{_PROJECT}/{_ENV}/{_NAME}",
                    headers=self._auth(other_key),
                )
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json(), _NOT_FOUND_BODY)

        # La base d'origine est intacte : le secret n'a pas migré.
        read = self._read_secret(self.api_key)
        self.assertEqual(read.status_code, 200)
        self.assertEqual(read.json()["value"], _TEST_VALUE)


if __name__ == "__main__":
    unittest.main()
