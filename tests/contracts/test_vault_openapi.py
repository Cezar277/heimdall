"""Validation hors ligne et comparaison indépendante avec FastAPI."""
import copy
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

from fastapi_contract_fixture import build_app


ROOT = Path(__file__).resolve().parent
if not (ROOT / "openapi.yaml").exists():
    ROOT = Path(__file__).resolve().parents[2]
SPEC = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))


def resolve(value, document):
    if isinstance(value, list):
        return [resolve(item, document) for item in value]
    if not isinstance(value, dict):
        return value
    if "$ref" in value:
        reference = value["$ref"]
        if not reference.startswith("#/"):
            raise ValueError("Référence externe interdite dans ces tests hors ligne")
        target = document
        for segment in reference[2:].split("/"):
            target = target[segment.replace("~1", "/").replace("~0", "~")]
        return resolve(target, document)
    return {key: resolve(item, document) for key, item in value.items()}


def structural(value):
    """Ignore uniquement annotations documentaires ; conserve les contraintes."""
    if isinstance(value, list):
        return [structural(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"title", "description", "examples", "example"}:
            continue
        result[key] = sorted(item) if key == "required" and isinstance(item, list) else structural(item)
    # Pydantic émet enum pour Literal avec plusieurs valeurs et const pour une.
    return result


def wire_contract(document):
    result = {}
    for path, path_item in document["paths"].items():
        for method in ("get", "post", "put", "patch", "delete", "head", "options", "trace"):
            if method not in path_item:
                continue
            operation = path_item[method]
            parameters = path_item.get("parameters", []) + operation.get("parameters", [])
            parameters = sorted((resolve(p, document) for p in parameters), key=lambda p: p["name"])
            result[(path, method)] = {
                "operationId": operation["operationId"],
                "parameters": structural(parameters),
                "security": operation.get("security", document.get("security", [])),
                "requestBody": structural(resolve(operation.get("requestBody"), document)),
                "responses": {
                    code: {
                        "content": structural(resolve(response.get("content", {}), document)),
                        "headers": structural(resolve(response.get("headers", {}), document)),
                    }
                    for code, response in ((code, resolve(response, document)) for code, response in operation["responses"].items())
                },
            }
    return {"operations": result, "securitySchemes": structural(document["components"].get("securitySchemes", {}))}


class VaultContractTests(unittest.TestCase):
    def test_openapi_valid(self):
        validate(SPEC)

    def test_fastapi_wire_contract_matches(self):
        self.assertEqual(wire_contract(SPEC), wire_contract(build_app().openapi()))

    def test_drift_is_detected(self):
        changed = copy.deepcopy(build_app().openapi())
        changed["components"]["schemas"]["SecretCreate"]["properties"]["value"]["maxLength"] = 1
        self.assertNotEqual(wire_contract(SPEC), wire_contract(changed))
        changed = copy.deepcopy(build_app().openapi())
        changed["paths"]["/api/v1/secrets"]["delete"] = copy.deepcopy(
            changed["paths"]["/api/v1/secrets"]["post"])
        self.assertNotEqual(wire_contract(SPEC), wire_contract(changed))

    def test_identifiers_reject_noncanonical_values(self):
        for name in ("ProjectId", "EnvironmentId", "SecretName"):
            validator = Draft202012Validator(SPEC["components"]["schemas"][name])
            for value in ("", "../", "x/y", "x\\y", "demo\n", "DEMO\n", "a" * 129):
                with self.subTest(schema=name, value=value):
                    self.assertFalse(validator.is_valid(value))

    def test_metadata_excludes_value(self):
        schema = resolve(SPEC["components"]["schemas"]["SecretMetadata"], SPEC)
        value = dict(project="demo", env="dev", name="DEMO_PASSWORD", status="vaulte")
        Draft202012Validator(schema).validate(value)
        self.assertFalse(Draft202012Validator(schema).is_valid(dict(value, value="PLACEHOLDER")))

    def test_request_rejects_client_controlled_state(self):
        schema = resolve(SPEC["components"]["schemas"]["SecretCreate"], SPEC)
        value = dict(project="demo", env="dev", name="DEMO_PASSWORD", value="PLACEHOLDER")
        Draft202012Validator(schema).validate(value)
        self.assertFalse(Draft202012Validator(schema).is_valid(dict(value, status="rote")))

    def test_examples_valid(self):
        for path_item in SPEC["paths"].values():
            for method in ("get", "post"):
                operation = path_item.get(method, {})
                bodies = [operation.get("requestBody", {})] + list(operation.get("responses", {}).values())
                for body in bodies:
                    for media in resolve(body, SPEC).get("content", {}).values():
                        if "example" in media:
                            Draft202012Validator(media["schema"]).validate(media["example"])

    def test_all_secret_routes_authenticated(self):
        for path, item in SPEC["paths"].items():
            for method in ("get", "post"):
                if method in item and "secrets" in path:
                    self.assertEqual(item[method].get("security", SPEC["security"]), [{"ProjectApiKey": []}])

    def test_error_format_and_codes(self):
        expected = {"400": "bad_request", "401": "unauthorized", "403": "forbidden",
                    "404": "not_found", "409": "conflict", "429": "rate_limited",
                    "503": "unavailable", "default": "internal_error"}
        schema = SPEC["components"]["schemas"]["Error"]
        for item in SPEC["paths"].values():
            for method in ("get", "post"):
                for code, response in item.get(method, {}).get("responses", {}).items():
                    if code in expected:
                        error_schema = resolve(response, SPEC)["content"]["application/json"]["schema"]
                        self.assertEqual(error_schema, schema)
                        Draft202012Validator(error_schema).validate(
                            {"code": expected[code], "message": "Message générique"})

    def test_error_rejects_sensitive_extra_fields(self):
        validator = Draft202012Validator(SPEC["components"]["schemas"]["Error"])
        for field in ("value", "traceback", "api_key", "input"):
            self.assertFalse(validator.is_valid(
                dict(code="bad_request", message="Requête invalide", **{field: "PLACEHOLDER"})))

    def test_health_is_public_and_minimal(self):
        self.assertEqual(SPEC["paths"]["/api/v1/health"]["get"]["security"], [])
        validator = Draft202012Validator(SPEC["components"]["schemas"]["Health"])
        validator.validate({"status": "ok"})
        self.assertFalse(validator.is_valid({"status": "ok", "version": "1.0.0"}))

    def test_secret_value_bounds_and_multiline(self):
        validator = Draft202012Validator(SPEC["components"]["schemas"]["SecretValue"])
        for value in ("PLACEHOLDER\nMULTILINE", "x" * 65536):
            validator.validate(value)
        for value in ("", "x" * 65537, None):
            self.assertFalse(validator.is_valid(value))


if __name__ == "__main__":
    unittest.main()
