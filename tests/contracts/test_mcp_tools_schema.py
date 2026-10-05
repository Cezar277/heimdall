"""Tests du contrat des outils MCP (ticket #16).

Ce que ces tests peuvent prouver:
  * le document est un JSON Schema draft 2020-12 valide;
  * la surface exposee est fermee: 4 outils, surface d'entree/sortie declaree;
  * les entrees et sorties sont strictes (additionalProperties: false);
  * les invariants conditionnels (if/then) tiennent, y compris les filets
    de masquage (redactions implique marqueur);
  * chaque outil n'accepte que son sous-ensemble de codes d'erreur;
  * les $defs sont coherents entre eux et avec le contrat Finding (#14);
  * les formes d'echec sont exclusives des formes de succes;
  * les exemples valides passent, les exemples invalides sont rejetés pour le
    motif et l'emplacement attendus.

Ce que ces tests ne peuvent PAS prouver, et qui est donc verifie autrement:
  * qu'un outil n'ecrit reellement rien, ni dans le depot ni dans .git/ (#27);
  * que CHAQUE ligne '-' d'un apercu est masquee: le schema exige au moins un
    marqueur, pas un masquage ligne a ligne (voir x-obligations, #27);
  * que les champs texte libres (AddedLine.text, masked_snippet, contextes)
    sont masques: exiger un marqueur y serait faux, c'est une obligation
    de #27 avant serialisation (voir x-obligations);
  * que env_example_line vaut bien env_var_name + '=' (comparaison de deux
    champs, impossible en JSON Schema, #30);
  * que la garde de chemin resout correctement les liens symboliques (#27.3.1).

Aucun appel reseau, aucun secret reel: les empreintes sont des placeholders
synthetiques et les valeurs candidates sont toujours masquees.
"""
import json
import re
from pathlib import Path
from unittest import TestCase, main as unittest_main

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas/mcp-tools.schema.json"
FINDING_SCHEMA_PATH = ROOT / "schemas/finding.schema.json"
CONTRACT_MD_PATH = ROOT / "docs/contracts/mcp-tools.md"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
FINDING = json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
CONTRACT_MD = CONTRACT_MD_PATH.read_text(encoding="utf-8")

EXPECTED_TOOLS = {"read_diff", "sanitize_file", "list_candidates", "propose_patch"}
# Sous-ensemble de codes d'erreur accepte par chaque outil (miroir des
# *Error du schema). Tout code hors de cette liste est une erreur du serveur.
TOOL_ERROR_CODES = {
    "read_diff": ("ReadDiffResult", "ReadDiffErrorResponse",
                  {"INVALID_INPUT", "TOO_LARGE", "NOT_A_GIT_REPO", "INTERNAL"}),
    "sanitize_file": ("SanitizeFileResult", "SanitizeFileErrorResponse",
                       {"INVALID_INPUT", "PATH_ESCAPE", "NOT_FOUND", "FORBIDDEN_PATH",
                        "BINARY_FILE", "TOO_LARGE", "NOT_A_GIT_REPO", "INTERNAL"}),
    "list_candidates": ("ListCandidatesResult", "ListCandidatesErrorResponse",
                         {"INVALID_INPUT", "PATH_ESCAPE", "NOT_FOUND", "FORBIDDEN_PATH",
                          "NOT_A_GIT_REPO", "INTERNAL"}),
    "propose_patch": ("ProposePatchResult", "ProposePatchErrorResponse",
                       {"INVALID_INPUT", "UNKNOWN_CANDIDATE", "STALE_CANDIDATE",
                        "NOT_A_GIT_REPO", "INTERNAL"}),
}
# Registre des outils MOTEUR: aucun de ces noms ne doit exister dans x-tools,
# quel que soit le contenu des $defs.
FORBIDDEN_TOOL_NAMES = {
    "exec", "run", "shell", "bash", "run_command", "write_file", "delete_file",
    "http_get", "fetch", "vault_read", "vault_write", "read_file",
}

# Placeholders synthetiques, pas des secrets.
HASH = "a" * 64
SNAPSHOT = "b" * 64


def validator(name: str) -> Draft202012Validator:
    """Valideur pour un $defs du contrat, avec ses dependances."""
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]})


def candidate(**over):
    base = {
        "candidate_id": "c1",
        "file": "src/app/config.py",
        "line": 12,
        "type": "aws",
        "entropy": 4.7,
        "snippet_hash": HASH,
        "masked_snippet": "AKIA<REDACTED:aws:len=20>",
        "status": "detecte",
        "source": "regex",
    }
    base.update(over)
    return base


def preview():
    """Apercu expurge: la ligne '-' porte le marqueur, jamais la valeur."""
    return (
        "--- a/src/app/config.py\n"
        "+++ b/src/app/config.py\n"
        "@@ -12 +12 @@\n"
        "-KEY = \"AKIA<REDACTED:aws:len=20>\"\n"
        "+KEY = os.environ[\"AWS_KEY\"]\n"
    )


def patch_out(**over):
    base = {
        "candidate_id": "c1",
        "snapshot_id": SNAPSHOT,
        "proposal_id": "p1",
        "applied": False,
        "manual_remediation": False,
        "patch_preview": preview(),
        "env_var_name": "AWS_KEY",
        "env_example_line": "AWS_KEY=",
    }
    base.update(over)
    return base


VALID = [
    ("ReadDiffInput", {}),
    ("ReadDiffInput", {"max_bytes": 4096}),
    ("ReadDiffOutput", {
        "files": [{"file": "a/b.py", "binary": False, "redactions": 1,
                   "added_lines": [{"line": 3, "text": "KEY = <REDACTED:aws:len=20>"}]}],
        "truncated": False,
    }),
    ("ReadDiffOutput", {"files": [{"file": "a/b.py", "binary": False, "redactions": 0,
                                   "added_lines": [{"line": 3, "text": "x = 1"}]}],
                        "truncated": False}),
    ("ReadDiffOutput", {"files": [{"file": "a/logo.png", "binary": True, "redactions": 0,
                                   "added_lines": []}],
                        "truncated": False}),
    # formes d'echec, acceptees par le wrapper de resultat PROPRE A L'OUTIL
    ("ReadDiffResult", {"files": [], "truncated": False}),
    ("ReadDiffResult", {"error": {"code": "NOT_A_GIT_REPO", "message": "Racine non versionnee."}}),
    ("ReadDiffResult", {"error": {"code": "TOO_LARGE", "message": "Diff trop gros."}}),
    ("SanitizeFileInput", {"path": "src/app.py"}),
    ("SanitizeFileInput", {"path": "src/app.py", "start_line": 10, "max_lines": 50}),
    ("SanitizeFileOutput", {
        "path": "src/app.py", "start_line": 1, "end_line": 3, "total_lines": 3,
        "content": "a\nb\nc", "redactions": 0, "truncated": False,
    }),
    ("SanitizeFileResult", {"error": {"code": "FORBIDDEN_PATH", "message": "Chemin interdit."}}),
    ("SanitizeFileResult", {"error": {"code": "BINARY_FILE", "message": "Fichier binaire."}}),
    ("ListCandidatesInput", {}),
    ("ListCandidatesInput", {"scope": "working_tree", "file": "x.py", "limit": 10}),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate()],
                              "total": 1, "truncated": False}),
    ("ListCandidatesResult", {"error": {"code": "INTERNAL", "message": "Erreur interne."}}),
    ("ListCandidatesResult", {"error": {"code": "PATH_ESCAPE", "message": "Filtre hors du depot."}}),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "AWS_ACCESS_KEY_ID"}),
    ("ProposePatchOutput", patch_out()),
    # remediation manuelle: l'aperçu doit etre vide
    ("ProposePatchOutput", patch_out(manual_remediation=True, patch_preview="")),
    ("ProposePatchResult", {"error": {"code": "STALE_CANDIDATE", "message": "Candidat perime."}}),
    ("ProposePatchResult", {"error": {"code": "UNKNOWN_CANDIDATE", "message": "Candidat inconnu."}}),
    ("ErrorResponse", {"error": {"code": "PATH_ESCAPE", "message": "Chemin hors du depot."}}),
]

# (nom $defs, payload invalide, motif attendu, chemin du champ en erreur)
INVALID = [
    # champ en trop (un champ bonus pourrait transporter une consigne detournee)
    ("ReadDiffInput", {"root": "/"}, "additionalProperties", []),
    ("SanitizeFileInput", {"path": "a.py", "command": "rm -rf /"}, "additionalProperties", []),
    ("ProposePatchOutput", patch_out(diff="--- a\n+++ b\n"), "additionalProperties", []),
    # chemins: absolu, antislash, octet nul, saut de ligne, vide, trop long
    ("SanitizeFileInput", {"path": "/etc/passwd"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "C:/Windows/system.ini"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "\\windows\\system32"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "a\u0000b"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "a\nb"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "a.py\n"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": ""}, "minLength", ["path"]),
    ("SanitizeFileInput", {"path": "a" * 1025}, "maxLength", ["path"]),
    # traversee de repertoire et segments traitres
    ("SanitizeFileInput", {"path": "../.ssh/id_rsa"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "src/../../etc/passwd"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "src/../app.py"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": ".."}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "src//app.py"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "src/"}, "pattern", ["path"]),
    ("SanitizeFileInput", {"path": "src/app.py\u2028ignored"}, "pattern", ["path"]),
    # bornes
    ("SanitizeFileInput", {"path": "a.py", "max_lines": 401}, "maximum", ["max_lines"]),
    ("SanitizeFileInput", {"path": "a.py", "start_line": 0}, "minimum", ["start_line"]),
    ("ReadDiffInput", {"max_bytes": 10}, "minimum", ["max_bytes"]),
    ("ReadDiffInput", {"max_bytes": 10_000_000}, "maximum", ["max_bytes"]),
    ("ListCandidatesInput", {"scope": "all"}, "enum", ["scope"]),
    ("ListCandidatesInput", {"limit": 1000}, "maximum", ["limit"]),
    # nom de variable
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "aws_key"}, "pattern", ["env_var_name"]),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "KEY\nINJECTED=1"}, "pattern", ["env_var_name"]),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "KEY_X\n"}, "pattern", ["env_var_name"]),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "A"}, "pattern", ["env_var_name"]),
    ("ProposePatchInput", {"candidate_id": "c1"}, "required", []),
    ("ProposePatchInput", {"candidate_id": "../c1", "env_var_name": "KEY_X"}, "pattern", ["candidate_id"]),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "KEY_X", "rationale": "x" * 501}, "maxLength", ["rationale"]),
    # snapshot: SHA-256 hexadecimal, jamais une chaine libre ni un OID git
    ("ProposePatchOutput", patch_out(snapshot_id="nothex"), "pattern", ["snapshot_id"]),
    ("ListCandidatesOutput", {"snapshot_id": "nothex", "candidates": [], "total": 0, "truncated": False},
     "pattern", ["snapshot_id"]),
    ("ProposePatchOutput", patch_out(snapshot_id=""), "pattern", ["snapshot_id"]),
    ("ProposePatchOutput", patch_out(snapshot_id="b" * 40), "pattern", ["snapshot_id"]),
    ("ProposePatchOutput", patch_out(snapshot_id="b" * 63), "pattern", ["snapshot_id"]),
    # un patch n'est jamais applique par l'outil
    ("ProposePatchOutput", patch_out(applied=True), "const", ["applied"]),
    # le LLM ne fournit ni la ligne d'origine, ni la valeur, ni un diff
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "AWS_KEY", "patch": "-KEY=x"},
     "additionalProperties", []),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "AWS_KEY", "original_line": "KEY=x"},
     "additionalProperties", []),
    ("ProposePatchInput", {"candidate_id": "c1", "env_var_name": "AWS_KEY", "value": "x"},
     "additionalProperties", []),
    # la ligne .env.example ne contient jamais de valeur
    ("ProposePatchOutput", patch_out(env_example_line="AWS_KEY=AKIAIOSFODNN7EXAMPLE"),
     "pattern", ["env_example_line"]),
    ("ProposePatchOutput", patch_out(env_example_line="AWS_KEY=\n"), "pattern", ["env_example_line"]),
    # l'aperçu ne peut pas contenir la valeur en clair
    ("ProposePatchOutput", patch_out(patch_preview="--- a/x.py\n+++ b/x.py\n-KEY = \"AKIA1234567890\"\n"),
     "anyOf", ["patch_preview"]),
    # un aperçu vide sans remediation manuelle: le programme pretend avoir
    # propose sans rien proposer (couvert aussi par l'invariant conditionnel)
    ("ProposePatchOutput", patch_out(patch_preview=""), "minLength", ["patch_preview"]),
    # filet structurel: redactions >= 1 sans marqueur (masquage oublie)
    ("DiffFile", {"file": "a.py", "binary": False, "redactions": 1,
                  "added_lines": [{"line": 1, "text": "x = 1"}]},
     "contains", ["added_lines"]),
    ("SanitizeFileOutput", {
        "path": "src/app.py", "start_line": 1, "end_line": 3, "total_lines": 3,
        "content": "a\nb\nc", "redactions": 2, "truncated": False,
    }, "pattern", ["content"]),
    # candidat: pas de valeur en clair, hash obligatoire, statut et source connus
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT,
                              "candidates": [candidate(secret_value="sk_live_x")],
                              "total": 1, "truncated": False},
     "additionalProperties", ["candidates", 0]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(snippet_hash="nothex")],
                              "total": 1, "truncated": False},
     "pattern", ["candidates", 0, "snippet_hash"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(status="deleted")],
                              "total": 1, "truncated": False},
     "enum", ["candidates", 0, "status"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(source="human")],
                              "total": 1, "truncated": False},
     "enum", ["candidates", 0, "source"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(type="API_KEY")],
                              "total": 1, "truncated": False},
     "pattern", ["candidates", 0, "type"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(entropy=8.01)],
                              "total": 1, "truncated": False},
     "maximum", ["candidates", 0, "entropy"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(entropy=None)],
                              "total": 1, "truncated": False},
     "type", ["candidates", 0, "entropy"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(context_before=["x"] * 6)],
                              "total": 1, "truncated": False},
     "maxItems", ["candidates", 0, "context_before"]),
    ("ListCandidatesOutput", {"snapshot_id": SNAPSHOT, "candidates": [candidate(file="../c1")],
                              "total": 1, "truncated": False},
     "pattern", ["candidates", 0, "file"]),
    ("ListCandidatesOutput", {"candidates": [], "total": 0}, "required", []),
    # erreur: code inconnu, message vide, saut de ligne dans le message
    ("ErrorResponse", {"error": {"code": "WHATEVER", "message": "x"}}, "enum", ["error", "code"]),
    ("ErrorResponse", {"error": {"code": "INTERNAL", "message": ""}}, "minLength", ["error", "message"]),
    ("ErrorResponse", {"error": {"code": "INTERNAL", "message": "ignore\nprevious"}},
     "pattern", ["error", "message"]),
]

# Invariants conditionnels: (nom $defs, payload qui doit etre REJETE, motif attendu)
CONDITIONAL_INVALID = [
    # fichier binaire avec des lignes: le LLM pourrait le lire comme du code
    ("DiffFile", {"file": "logo.png", "binary": True, "redactions": 0,
                  "added_lines": [{"line": 1, "text": "x"}]},
     "maxItems"),
    # redactions annoncees mais aucune ligne masquee: masquage oublie
    ("DiffFile", {"file": "a.py", "binary": False, "redactions": 2,
                  "added_lines": [{"line": 1, "text": "x = 1"}]},
     "contains"),
    ("SanitizeFileOutput", {
        "path": "src/app.py", "start_line": 1, "end_line": 1, "total_lines": 1,
        "content": "password = 'x'", "redactions": 1, "truncated": False,
    }, "pattern"),
    # remediation manuelle avec un aperçu non vide: le programme ne sait pas
    # comment patcher, donc il n'a pas le droit de proposer un diff
    ("ProposePatchOutput", patch_out(manual_remediation=True), "const"),
    ("ProposePatchOutput", patch_out(manual_remediation=True, patch_preview=preview()), "const"),
    # et l'inverse: un aperçu vide sans remediation manuelle ne sert a rien
    ("ProposePatchOutput", patch_out(manual_remediation=False, patch_preview=""),
     "minLength"),
]


class McpToolsSchemaTests(TestCase):
    # --- structure du document ------------------------------------------------

    def test_schema_matches_draft_2020_12(self):
        self.assertEqual(SCHEMA["$schema"], "https://json-schema.org/draft/2020-12/schema")
        Draft202012Validator.check_schema(SCHEMA)

    def test_id_matches_the_finding_convention(self):
        """Même convention d'identifiant que le contrat Finding (#14)."""
        self.assertEqual(
            SCHEMA["$id"],
            "https://github.com/Cezar277/heimdall/schemas/mcp-tools.schema.json",
        )
        self.assertEqual(FINDING["$id"], "https://github.com/Cezar277/heimdall/schemas/finding.schema.json")

    def test_exactly_four_tools_all_read_only(self):
        tools = SCHEMA["x-tools"]
        self.assertEqual(set(tools), EXPECTED_TOOLS)
        for name, spec in tools.items():
            self.assertEqual(spec["mode"], "read-only", name)

    def test_no_forbidden_tool_in_the_registry(self):
        """Surface fermee: un nom d'outil dangereux ne doit pas exister dans
        x-tools. On teste le REGISTRE, pas les $defs: une description qui cite
        legitinement read_file entre guillemets ne doit pas casser ce test."""
        self.assertFalse(set(SCHEMA["x-tools"]) & FORBIDDEN_TOOL_NAMES)

    def test_every_tool_ref_resolves(self):
        for name, spec in SCHEMA["x-tools"].items():
            for side in ("input", "output"):
                ref = spec[side]["$ref"]
                self.assertTrue(ref.startswith("#/$defs/"), (name, side))
                self.assertIn(ref.removeprefix("#/$defs/"), SCHEMA["$defs"], (name, side))

    def test_every_internal_ref_resolves(self):
        """Aucun $defs ne pointe vers un $defs inexistant (sinon le serveur
        charge au runtime et le contrat passe pour valide)."""
        for name, sub in SCHEMA["$defs"].items():
            for ref in re.findall(r'"#/\$defs/([A-Za-z0-9_]+)"', json.dumps(sub)):
                self.assertIn(ref, SCHEMA["$defs"], name)

    def test_every_object_schema_forbids_extra_properties(self):
        # Un champ en trop pourrait transporter une consigne detournee (voir #34.3).
        for name, sub in SCHEMA["$defs"].items():
            if sub.get("type") == "object":
                self.assertIs(sub.get("additionalProperties"), False, name)

    def test_shared_defs_invent_no_bound_absent_from_finding(self):
        """Les $defs partages avec Finding (#14) ne doivent pas inventer une
        borne de longueur que le contrat Finding ignore: deux sources de
        verite, c'est la derive silencieuse. `type` de Finding n'a que
        maxLength, donc SecretType n'a pas de minLength a cote."""
        for ours, theirs in (("SecretType", "type"), ("SnippetHash", "snippet_hash")):
            with self.subTest(name=ours):
                for bound in ("minLength", "maxLength"):
                    self.assertEqual(
                        SCHEMA["$defs"][ours].get(bound),
                        FINDING["properties"][theirs].get(bound),
                        f"{ours}.{bound}",
                    )

    # --- formes de reponse ----------------------------------------------------

    def test_each_tool_output_is_success_or_error(self):
        """x-tools[output] doit pointer vers un oneOf succes/erreur PROPRE A
        L'OUTIL: c'est ce qui attache les codes d'erreur a chaque outil au
        lieu de laisser une enveloppe globale. Un code hors sous-ensemble
        (ex. UNKNOWN_CANDIDATE pour read_diff) est une erreur du serveur."""
        for name, spec in SCHEMA["x-tools"].items():
            with self.subTest(tool=name):
                result = SCHEMA["$defs"][spec["output"]["$ref"].removeprefix("#/$defs/")]
                self.assertIn("oneOf", result, name)
                branches = [b["$ref"].removeprefix("#/$defs/") for b in result["oneOf"]]
                self.assertEqual(len(branches), 2, name)
                self.assertEqual(branches[1], TOOL_ERROR_CODES[name][1], name)

    def test_each_tool_accepts_only_its_error_codes(self):
        """Chaque outil accepte ses codes et refuse tous les autres: un
        read_diff qui renverrait UNKNOWN_CANDIDATE, ou un propose_patch qui
        renverrait PATH_ESCAPE, echoue la validation au lieu de passer."""
        all_codes = set(SCHEMA["$defs"]["ErrorCode"]["enum"])
        for tool, (result, _, allowed) in TOOL_ERROR_CODES.items():
            for code in sorted(all_codes):
                payload = {"error": {"code": code, "message": "Message de test."}}
                with self.subTest(tool=tool, code=code):
                    if code in allowed:
                        self.assertTrue(validator(result).is_valid(payload),
                                        f"{tool} devrait accepter {code}")
                    else:
                        self.assertFalse(validator(result).is_valid(payload),
                                         f"{tool} accepte {code} alors qu'il ne le devrait pas")

    def test_success_and_error_forms_are_mutually_exclusive(self):
        """Une charge utile de succes ne doit pas pouvoir etre lue comme une
        erreur, et reciproquement: c'est ce qui rend le oneOf exhaustif."""
        for tool, spec in SCHEMA["x-tools"].items():
            result_name = spec["output"]["$ref"].removeprefix("#/$defs/")
            result = SCHEMA["$defs"][result_name]
            branches = result["oneOf"]
            ok = next(n for n in (b["$ref"].removeprefix("#/$defs/") for b in branches)
                      if not n.endswith("ErrorResponse"))
            err_name = next(n for n in (b["$ref"].removeprefix("#/$defs/") for b in branches)
                            if n.endswith("ErrorResponse"))
            ok_payload = next(p for n, p in VALID if n == ok)
            with self.subTest(tool=tool):
                self.assertTrue(validator(result_name).is_valid(ok_payload))
                self.assertEqual(len(list(validator(result_name).iter_errors(ok_payload))), 0)
                err = validator(err_name)
                self.assertFalse(err.is_valid(ok_payload))

    def test_a_response_cannot_be_both_success_and_error(self):
        """Mixer les deux formes doit etre refuse, pas resolu au hasard."""
        mixed = patch_out(error={"code": "INTERNAL", "message": "x"})
        self.assertFalse(validator("ProposePatchResult").is_valid(mixed))

    # --- invariants conditionnels ---------------------------------------------

    def test_conditional_invariants_reject_violations(self):
        for name, payload, motif in CONDITIONAL_INVALID:
            with self.subTest(case=name, payload=str(payload)[:70]):
                errors = list(validator(name).iter_errors(payload))
                self.assertTrue(errors, "invariant conditionnel non respecte")
                self.assertTrue(
                    any(e.validator == motif for e in errors),
                    [(e.validator, e.message) for e in errors],
                )

    # --- patterns : comportement, pas forme ----------------------------------

    def test_patterns_reject_trailing_line_terminators(self):
        """`$` ancre la fin de chaine AVANT un saut de ligne final: une valeur
        suivie de \\n, \\r ou U+2028 passerait le controle. On verifie le
        COMPORTEMENT (suffixes ajoutes, rejet attendu) et non la presence
        d'un motif dans la chaine du pattern."""
        rel = Draft202012Validator(SCHEMA["$defs"]["RelPath"])
        cid = Draft202012Validator(SCHEMA["$defs"]["CandidateId"])
        evn = Draft202012Validator(SCHEMA["$defs"]["EnvVarName"])
        stype = Draft202012Validator(SCHEMA["$defs"]["SecretType"])
        snip = Draft202012Validator(SCHEMA["$defs"]["SnippetHash"])
        env = Draft202012Validator(SCHEMA["$defs"]["EnvExampleLine"])
        msg = Draft202012Validator(SCHEMA["$defs"]["ErrorMessage"])
        snap = Draft202012Validator(SCHEMA["$defs"]["SnapshotId"])
        cases = [
            (rel, "src/app.py"),
            (cid, "c1"),
            (evn, "AWS_KEY"),
            (stype, "aws"),
            (snip, HASH),
            (env, "AWS_KEY="),
            (msg, "Chemin hors du depot."),
            (snap, SNAPSHOT),
        ]
        for check, base in cases:
            with self.subTest(base=base):
                self.assertTrue(check.is_valid(base), f"{base} devrait etre valide")
                for suffix in ("\n", "\r", "\r\n", "\u2028", "\u2029", "\x0b", "\x0c"):
                    with self.subTest(suffix=repr(suffix)):
                        self.assertFalse(
                            check.is_valid(base + suffix),
                            f"{base!r} + {suffix!r} passe le controle",
                        )

    def test_relpath_pattern_rejects_traversal(self):
        rel = Draft202012Validator(SCHEMA["$defs"]["RelPath"])
        for value in ("../x", "a/../../b", "/abs", "C:/x", "a\\b", "a\u0000b",
                      "a\nb", "a/", "a//b", ".", "..", "./a", "a/./b", ""):
            with self.subTest(value=value):
                self.assertFalse(rel.is_valid(value))
        for value in ("config.py", "src/app.py", "src/a/b.py", "src/.env.example", "src/été.py"):
            with self.subTest(valid=value):
                self.assertTrue(rel.is_valid(value), value)

    def test_snapshot_id_is_a_full_sha256_digest(self):
        """SHA-256 hexadécimal, 64 caractères exacts. On refuse la forme
        courte: une empreinte tronquée serait ambiguë entre deux périmètres
        proches, et un OID git ne convient pas (voir SnapshotId)."""
        snap = Draft202012Validator(SCHEMA["$defs"]["SnapshotId"])
        self.assertTrue(snap.is_valid("b" * 64))
        for value in ("", "abc", "b" * 40, "b" * 63, "b" * 65,
                      "ABCDEF" + "1" * 58, "b" * 64 + "\n", "b" * 63 + " "):
            with self.subTest(invalid=value):
                self.assertFalse(snap.is_valid(value))

    def test_snapshot_id_is_not_a_git_oid_reference(self):
        """Le schema ne doit pas redevenir un OID git: `git write-tree`
        ecrit dans .git/objects et violerait l'invariant lecture seule.
        Ce test echoue si quelqu'un reintroduit une longueur de OID git."""
        desc = SCHEMA["$defs"]["SnapshotId"]["description"]
        self.assertIn("EN MEMOIRE", desc)
        self.assertIn("write-tree", desc)
        self.assertIn("working_tree", desc)

    # --- le secret ne sort pas ------------------------------------------------

    def test_patch_preview_never_carries_a_clear_value(self):
        """Un aperçu sans aucun marqueur est refuse: soit il est vide avec
        manual_remediation (cas ambigu assume), soit il montre au moins une
        valeur masquee. Voir aussi test_patch_preview_check_is_minimal pour
        la limite de ce filet."""
        pp = Draft202012Validator(SCHEMA["$defs"]["PatchPreview"])
        self.assertTrue(pp.is_valid(""))
        self.assertTrue(pp.is_valid(preview()))
        for value in (
            "-KEY = \"AKIA1234567890\"\n",
            "+KEY = os.environ[\"AWS_KEY\"]\n",
            "--- a/x.py\n",
        ):
            with self.subTest(value=value):
                self.assertFalse(pp.is_valid(value))

    def test_free_text_fields_have_no_structural_redaction_check(self):
        """AddedLine.text, masked_snippet et les contextes acceptent une
        valeur sans marqueur, et c'est NORMAL: exiger un marqueur y serait
        faux, car la plupart des lignes n'ont legitimement aucun secret.
        Le masquage de ces champs est donc une obligation de #27 AVANT
        serialisation (x-obligations.masking_before_serialization), a prouver
        par des tests qui cherchent une valeur connue dans chaque champ texte,
        pas par ce schema."""
        self.assertTrue(validator("AddedLine").is_valid({"line": 1, "text": "AKIA1234567890"}))
        self.assertTrue(validator("Candidate").is_valid(candidate(masked_snippet="AKIA1234567890")))
        self.assertTrue(validator("Candidate").is_valid(
            candidate(context_before=["password = 'hunter2'"])))
        self.assertIn("masking_before_serialization", SCHEMA["x-obligations"])

    def test_patch_preview_check_is_minimal_and_we_say_so(self):
        """Ce test verifie la LIMITE connue de PatchPreview, pour qu'on ne la
        présente pas comme une garantie. Un aperçu contenant une valeur en
        clair A COTE d'un marqueur passe la validation: le schema ne voit pas
        les lignes. C'est documenté dans x-obligations et c'est à #27 de le
        prouver par un test de masquage ligne à ligne."""
        pp = Draft202012Validator(SCHEMA["$defs"]["PatchPreview"])
        leaky = (
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "-KEY = \"AKIA1234567890\"\n"
            "-OTHER = \"<REDACTED:aws:len=20>\"\n"
        )
        self.assertTrue(pp.is_valid(leaky), "le schema est plus permissif que prevu")
        # le contrat doit donc declarer cette limite, sans ambiguite
        self.assertIn("FORME MINIMALE", SCHEMA["$defs"]["PatchPreview"]["description"])
        self.assertIn("every_removed_line_is_masked", SCHEMA["x-obligations"])

    def test_examples_contain_no_secret_values(self):
        """Garde-fou: aucun exemple ne doit ressembler a une cle en clair.
        Un prefixe de famille (AKIA, sk_live_...) n'est autorise que suivi du
        marqueur de masquage."""
        blob = json.dumps(VALID)
        for marker in ("sk_live_", "AKIA", "ghp_", "xoxb-", "ghs_", "AIza"):
            for match in re.finditer(re.escape(marker), blob):
                after = blob[match.end():]
                with self.subTest(marker=marker):
                    self.assertTrue(
                        after.startswith("<REDACTED:"),
                        f"{marker} apparait sans marqueur de masquage juste apres",
                    )
        self.assertNotIn("-----BEGIN", blob)

    # --- coherence avec le contrat Finding (#14) ------------------------------

    def test_candidate_matches_finding_contract(self):
        """Les champs partages avec Finding (#14) doivent rester identiques:
        enum status/source, bornes entropy, grammaire path/snippet_hash."""
        finding_props = FINDING["properties"]
        cand = SCHEMA["$defs"]["Candidate"]["properties"]
        self.assertEqual(
            set(finding_props) - set(cand), set(),
            "Candidate perd un champ du contrat Finding",
        )
        self.assertEqual(SCHEMA["$defs"]["SecretStatus"]["enum"], finding_props["status"]["enum"])
        self.assertEqual(SCHEMA["$defs"]["Source"]["enum"], finding_props["source"]["enum"])
        self.assertEqual(cand["source"]["$ref"], "#/$defs/Source")
        # Candidate reference les $defs du contrat; on compare la definition resolue.
        self.assertEqual(cand["type"]["$ref"], "#/$defs/SecretType")
        self.assertEqual(
            SCHEMA["$defs"]["SecretType"]["pattern"], finding_props["type"]["pattern"]
        )
        self.assertEqual(SCHEMA["$defs"]["RelPath"]["pattern"], finding_props["file"]["pattern"])
        self.assertEqual(cand["file"]["$ref"], "#/$defs/RelPath")
        self.assertEqual(
            SCHEMA["$defs"]["SnippetHash"]["pattern"], finding_props["snippet_hash"]["pattern"]
        )
        self.assertEqual(cand["snippet_hash"]["$ref"], "#/$defs/SnippetHash")

    def test_candidate_requires_the_finding_fields(self):
        """Les champs obligatoires de Finding le restent dans Candidate."""
        self.assertTrue(set(FINDING["required"]) <= set(SCHEMA["$defs"]["Candidate"]["required"]))

    # --- coherence entre le schema et la documentation ------------------------

    def test_every_error_code_is_listed_in_the_markdown_table(self):
        """Chaque code d'erreur du schema doit apparaitre dans le tableau de la
        section Codes d'erreur. On analyse les LIGNES DE TABLE du markdown, pas
        le texte libre: pas de fragile dependance a la formulation."""
        table = [line for line in CONTRACT_MD.splitlines()
                 if line.startswith("| `") and line.rstrip().endswith("|")]
        codes = set()
        for line in table:
            codes.update(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", line))
        self.assertEqual(set(SCHEMA["$defs"]["ErrorCode"]["enum"]) - codes, set(),
                         "code d'erreur du schema absent du tableau de la doc")

    def test_error_codes_are_unique(self):
        """JSON Schema l'exige (meta-schema), on le verifie quand meme: une
        duplication passerait inaperue dans une lecture rapide du tableau."""
        codes = SCHEMA["$defs"]["ErrorCode"]["enum"]
        self.assertEqual(len(codes), len(set(codes)))

    def test_forbidden_list_documents_every_invariant(self):
        """Les 4 interdits explicitement demandes par le ticket, plus les 3
        ajoutes par ce contrat (snapshot, apercu, diff reel)."""
        for needle in ("hors de la racine", "réseau", "commande arbitraire", "ignorés",
                       "snapshot_id", "proposal_id", "patch_preview"):
            self.assertIn(needle, CONTRACT_MD, needle)

    def test_markdown_does_not_overclaim(self):
        """Le mode read-only est une EXIGENCE, pas une preuve. La doc doit le
        dire, sinon le rapport et l'audit croisé présenteront une déclaration
        comme une démonstration."""
        # la doc doit distinguer ce qui est prouvé de ce qui ne l'est pas
        self.assertIn("prouvé statiquement", CONTRACT_MD)
        self.assertIn("non preuve", CONTRACT_MD)
        # le schema ne doit pas pretendre prouver le comportement lui-meme
        self.assertIn("EXIGENCES", SCHEMA["x-guarantees"]["note"])
        self.assertIn("verified_by", SCHEMA["x-guarantees"])
        # et la ligne SAMM ne doit pas survendre la protection du secret
        samm = CONTRACT_MD.split("## 12.")[-1]
        self.assertIn("Forme minimale", samm)
        self.assertNotIn("Le secret ne sort pas", CONTRACT_MD)

    # --- exemples -------------------------------------------------------------

    def test_valid_examples(self):
        for name, payload in VALID:
            with self.subTest(case=name):
                errors = [e.message for e in validator(name).iter_errors(payload)]
                self.assertEqual(errors, [], errors)

    def test_invalid_examples_rejected_for_expected_reason(self):
        for name, payload, motif, path in INVALID:
            with self.subTest(case=name, payload=str(payload)[:60]):
                errors = list(validator(name).iter_errors(payload))
                self.assertTrue(errors, "payload accepte alors qu'il ne doit pas l'etre")
                self.assertTrue(
                    any(e.validator == motif and list(e.absolute_path) == path for e in errors),
                    [(e.validator, list(e.absolute_path), e.message) for e in errors],
                )


def main():
    unittest_main(verbosity=2)


if __name__ == "__main__":
    main()