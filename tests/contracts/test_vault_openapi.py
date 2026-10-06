"""Validation hors ligne et comparaison indépendante avec FastAPI."""
import copy
import json
import unittest
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

from fastapi_contract_fixture import Error, InternalError, build_app
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parent
if not (ROOT / "openapi.yaml").exists():
    ROOT = Path(__file__).resolve().parents[2]
SPEC = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
MESSAGES = {
    "bad_request": "Requête invalide", "unauthorized": "Authentification requise",
    "forbidden": "Accès interdit", "not_found": "Ressource introuvable",
    "conflict": "Secret déjà existant", "rate_limited": "Trop de requêtes",
    "unavailable": "Service indisponible", "internal_error": "Erreur interne",
}


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

    def test_drift_detects_weakened_object_and_error_constraints(self):
        baseline = build_app().openapi()
        for model in ("SecretCreate", "SecretMetadata", "SecretRead", "Error", "InternalError", "Health"):
            with self.subTest(model=model):
                changed = copy.deepcopy(baseline)
                del changed["components"]["schemas"][model]["additionalProperties"]
                self.assertNotEqual(wire_contract(SPEC), wire_contract(changed))
        changed = copy.deepcopy(baseline)
        changed["components"]["schemas"]["Error"]["properties"]["message"] = {"type": "string"}
        self.assertNotEqual(wire_contract(SPEC), wire_contract(changed))
        # Retirer aussi les conditions simule un message réellement libre.
        del changed["components"]["schemas"]["Error"]["allOf"]
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
                    "500": "internal_error", "503": "unavailable", "default": "internal_error"}
        schema = SPEC["components"]["schemas"]["Error"]
        for item in SPEC["paths"].values():
            for method in ("get", "post"):
                for code, response in item.get(method, {}).get("responses", {}).items():
                    if code in expected:
                        error_schema = resolve(response, SPEC)["content"]["application/json"]["schema"]
                        self.assertEqual(error_schema, SPEC["components"]["schemas"]["InternalError"] if code == "500" else schema)
                        Draft202012Validator(error_schema).validate(
                            {"code": expected[code], "message": MESSAGES[expected[code]]})

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

    def test_error_message_cannot_reflect_input_or_traceback(self):
        validator = Draft202012Validator(SPEC["components"]["schemas"]["Error"])
        for code, message in MESSAGES.items():
            value = {"code": code, "message": message}
            validator.validate(value)
            Error.model_validate(value)
            for invalid in ("Entrée invalide DEMO_PASSWORD", "Traceback: internal/path.py",
                            message + " DEMO_PASSWORD", "Message générique"):
                with self.subTest(code=code, message=invalid):
                    value = {"code": code, "message": invalid}
                    self.assertFalse(validator.is_valid(value))
                    with self.assertRaises(ValidationError):
                        Error.model_validate(value)

    def test_error_message_must_match_code(self):
        validator = Draft202012Validator(SPEC["components"]["schemas"]["Error"])
        for code in MESSAGES:
            for other_code, message in MESSAGES.items():
                if other_code != code:
                    value = {"code": code, "message": message}
                    self.assertFalse(validator.is_valid(value))
                    with self.assertRaises(ValidationError):
                        Error.model_validate(value)

    def test_decoded_url_identifiers_rejected(self):
        for name in ("ProjectId", "EnvironmentId", "SecretName"):
            validator = Draft202012Validator(SPEC["components"]["schemas"][name])
            for encoded in ("%2F", "%2E%2E", "%5C", "%0A", ".", "..",
                            "demo%2Fname", "DEMO%0A"):
                with self.subTest(schema=name, encoded=encoded):
                    self.assertFalse(validator.is_valid(encoded))
                    self.assertFalse(validator.is_valid(unquote(encoded)))

    def test_identifier_exact_boundaries(self):
        for name, minimum, maximum, character in (
                ("ProjectId", 1, 64, "a"), ("EnvironmentId", 1, 32, "a"),
                ("SecretName", 2, 64, "A")):
            schema = SPEC["components"]["schemas"][name]
            validator = Draft202012Validator(schema)
            for length in (minimum, maximum):
                validator.validate(character * length)
            for length in (minimum - 1, maximum + 1):
                errors = list(validator.iter_errors(character * length))
                self.assertTrue(any(error.validator == "pattern" for error in errors))
                self.assertTrue(any(error.validator in ("minLength", "maxLength") for error in errors))

    def test_secret_name_matches_mcp_variable_invariant(self):
        mcp = json.loads((ROOT / "schemas/mcp-tools.schema.json").read_text(encoding="utf-8"))
        expected = mcp["$defs"]["EnvVarName"]
        actual = SPEC["components"]["schemas"]["SecretName"]
        self.assertEqual(actual["pattern"], expected["pattern"])
        validator = Draft202012Validator(actual)
        mcp_validator = Draft202012Validator(expected)
        for value in ("_FOO", "A", "A" * 65, "A" * 129):
            self.assertFalse(validator.is_valid(value))
            self.assertFalse(mcp_validator.is_valid(value))
        for value in ("AB", "DEMO_PASSWORD", "A" * 64):
            validator.validate(value)
            mcp_validator.validate(value)

    def test_health_rate_limit_and_post_responses(self):
        response = resolve(SPEC["paths"]["/api/v1/health"]["get"]["responses"]["429"], SPEC)
        self.assertEqual(response["headers"]["Retry-After"]["schema"],
                         {"type": "integer", "minimum": 1, "maximum": 3600})
        self.assertNotIn("404", SPEC["paths"]["/api/v1/secrets"]["post"]["responses"])
        self.assertEqual(SPEC["servers"][0]["url"], "https://127.0.0.1:8443")

    def test_retry_after_bounds_on_every_rate_limited_route(self):
        for path, item in SPEC["paths"].items():
            for method in ("get", "post"):
                if method not in item:
                    continue
                with self.subTest(path=path, method=method):
                    response = resolve(item[method]["responses"]["429"], SPEC)
                    validator = Draft202012Validator(response["headers"]["Retry-After"]["schema"])
                    for value in (1, 3600):
                        validator.validate(value)
                    for value in (0, -1, 3601, 10**20, 1.5, "tomorrow", None, True):
                        self.assertFalse(validator.is_valid(value))

    def test_500_requires_exact_json_error_on_every_route(self):
        valid = {"code": "internal_error", "message": "Erreur interne"}
        invalid = ["<html>Traceback</html>",
                   {"code": "bad_request", "message": "Requête invalide"},
                   {"code": "internal_error", "message": "Traceback DEMO_PASSWORD"},
                   {**valid, "traceback": "PLACEHOLDER"}]
        for path, item in SPEC["paths"].items():
            for method in ("get", "post"):
                if method not in item:
                    continue
                with self.subTest(path=path, method=method):
                    responses = item[method]["responses"]
                    self.assertIn("default", responses)
                    content = resolve(responses["500"], SPEC)["content"]
                    self.assertEqual(set(content), {"application/json"})
                    validator = Draft202012Validator(content["application/json"]["schema"])
                    validator.validate(valid)
                    InternalError.model_validate(valid)
                    for value in invalid:
                        self.assertFalse(validator.is_valid(value))
                        with self.assertRaises(ValidationError):
                            InternalError.model_validate(value)


if __name__ == "__main__":
    unittest.main()
