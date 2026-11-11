"""Preuves T30.1 (#83) : templates de remplacement Python et JavaScript.

Toutes les valeurs sont synthétiques. Le corpus piège est matérialisé dans un
dossier temporaire ; aucun fichier du dépôt n'est modifié et aucun secret réel
n'est utilisé.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import cast

import pytest
from support.trap_corpus import FIXTURES, build_corpus

from heimdall.remediation import (
    EXTENSION_LANGUAGE,
    TEMPLATES,
    Language,
    ManualReason,
    ReplacementPlan,
    TemplateError,
    build_replacement,
    detect_language,
    plan_for_finding,
    replacement_expression,
)
from heimdall.remediation import templates as templates_module
from heimdall.scanner.finding import Finding

SECRET = "SYNTHETIC_ONLY_VALUE"  # noqa: S105 - valeur synthétique de test
#: Nom de variable déjà présent dans les cas d'idempotence (pas un secret).
ENV_NAME = "APP_KEY"
#: Directive prologue utilisée comme valeur à remplacer.
DIRECTIVE = "use strict"


def patch(
    file: str, source: str, line: int, secret: str = SECRET, variable: str = "APP_KEY"
) -> ReplacementPlan:
    plan = build_replacement(file, source, line, secret, variable)
    assert plan.manual_remediation is False, plan.reason
    return plan


def manual(
    file: str,
    source: str,
    line: int,
    secret: str = SECRET,
    variable: str = "APP_KEY",
) -> ReplacementPlan:
    plan = build_replacement(file, source, line, secret, variable)
    assert plan.manual_remediation is True
    assert plan.after == plan.before == source
    assert plan.expression is None
    return plan


@pytest.fixture()
def finding() -> Finding:
    return Finding(
        file="app.py",
        line=1,
        type="generic_secret",
        entropy=1.0,
        snippet_hash="0" * 64,
    )


# --- Détection et templates -------------------------------------------------


@pytest.mark.parametrize("suffix", sorted(EXTENSION_LANGUAGE))
def test_language_detection_follows_extension(suffix: str) -> None:
    expected = EXTENSION_LANGUAGE[suffix]
    assert detect_language(f"src/app{suffix}") is expected
    assert detect_language(f"src/app{suffix.upper()}") is expected


@pytest.mark.parametrize(
    "file", ["app.ts", "app.jsx", "app.pyi", "app.txt", "app", ".env", "app.js.map"]
)
def test_unknown_extensions_request_manual_remediation(file: str) -> None:
    plan = manual(file, 'KEY = "SYNTHETIC_ONLY_VALUE"\n', 1)
    assert plan.language is None
    assert plan.reason is ManualReason.UNSUPPORTED_LANGUAGE


@pytest.mark.parametrize("file", ["../app.py", "/app.py", "a//b.py", "a\x00b.py"])
def test_language_detection_refuses_unsafe_paths(file: str) -> None:
    with pytest.raises(TemplateError):
        detect_language(file)


def test_templates_are_closed_and_exact() -> None:
    assert TEMPLATES[Language.PYTHON] == 'os.environ["{variable}"]'
    assert TEMPLATES[Language.JAVASCRIPT] == "process.env.{variable}"
    assert replacement_expression(Language.PYTHON, "APP_KEY") == 'os.environ["APP_KEY"]'
    assert replacement_expression(Language.JAVASCRIPT, "APP_KEY") == "process.env.APP_KEY"


@pytest.mark.parametrize(
    "variable",
    ["", "a", "APP-KEY", "APP KEY", 'APP"]', "APP\nKEY", "ÄPP_KEY", "A" * 65],
)
def test_variable_grammar_prevents_code_injection(variable: str) -> None:
    with pytest.raises(TemplateError):
        replacement_expression(Language.PYTHON, variable)
    with pytest.raises(TemplateError):
        replacement_expression(Language.JAVASCRIPT, variable)


# --- Python -----------------------------------------------------------------


def test_python_replaces_only_the_literal_and_adds_import() -> None:
    source = f'KEY = "{SECRET}"  # commentaire\n'
    plan = patch("app.py", source, 1)

    assert plan.language is Language.PYTHON
    assert plan.expression == 'os.environ["APP_KEY"]'
    assert plan.import_added is True
    assert plan.line_after == 2
    assert plan.after == 'import os\nKEY = os.environ["APP_KEY"]  # commentaire\n'
    assert SECRET not in plan.after
    ast.parse(plan.after)


def test_python_existing_import_is_not_duplicated() -> None:
    source = f'import os\nKEY = "{SECRET}"\n'
    plan = patch("app.py", source, 2)

    assert plan.import_added is False
    assert plan.after == 'import os\nKEY = os.environ["APP_KEY"]\n'
    assert plan.after.count("import os") == 1


def test_python_import_after_the_target_is_completed_at_the_top() -> None:
    source = f'KEY = "{SECRET}"\nimport os\n'
    plan = patch("app.py", source, 1)

    assert plan.import_added is True
    assert plan.after == 'import os\nKEY = os.environ["APP_KEY"]\nimport os\n'
    ast.parse(plan.after)


@pytest.mark.parametrize("import_os", ["import os.path\n", "import os as operating_system\n"])
def test_python_import_forms_that_bind_os_are_respected(import_os: str) -> None:
    plan = patch("app.py", import_os + f'KEY = "{SECRET}"\n', 2)
    if import_os == "import os.path\n":
        assert plan.import_added is False
    else:
        assert plan.import_added is True
        assert plan.after.startswith("import os\n")
    ast.parse(plan.after)


def test_python_import_goes_after_docstring_and_future_import() -> None:
    source = f'"""Documentation."""\nfrom __future__ import annotations\nKEY = "{SECRET}"\n'
    plan = patch("app.py", source, 3)

    assert plan.after == (
        '"""Documentation."""\n'
        "from __future__ import annotations\n"
        "import os\n"
        'KEY = os.environ["APP_KEY"]\n'
    )
    assert plan.line_after == 4
    ast.parse(plan.after)


def test_python_preserves_shebang_and_encoding_comment() -> None:
    source = f'#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nKEY = "{SECRET}"\n'
    plan = patch("app.py", source, 3)

    assert plan.after.startswith("#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nimport os\n")
    ast.parse(plan.after)


def test_python_import_goes_before_a_decorator() -> None:
    source = f'@decorator\ndef f():\n    KEY = "{SECRET}"\n'
    plan = patch("app.py", source, 3)

    assert plan.after == ('import os\n@decorator\ndef f():\n    KEY = os.environ["APP_KEY"]\n')
    ast.parse(plan.after)


def test_python_preserves_crlf_and_non_ascii_prefix() -> None:
    source = f'# héllo Δ\r\nKEY = "{SECRET}"\r\nTAIL = 1\r\n'
    plan = patch("app.py", source, 2)

    assert "\n" not in plan.after.replace("\r\n", "")
    assert plan.after == ('# héllo Δ\r\nimport os\r\nKEY = os.environ["APP_KEY"]\r\nTAIL = 1\r\n')
    ast.parse(plan.after)


@pytest.mark.parametrize(
    "literal",
    [
        '"{secret}"',
        "'{secret}'",
        'u"{secret}"',
        'r"{secret}"',
        '"""{secret}"""',
        '"\\x53YNTHETIC_ONLY_VALUE"',
    ],
)
def test_python_accepts_simple_string_forms(literal: str) -> None:
    # La dernière forme encode la même valeur (SYNTHETIC_ONLY_VALUE) sans
    # écrire le secret en clair dans la source du test.
    line = f"KEY = {literal.format(secret=SECRET)}\n"
    plan = patch("app.py", line, 1)
    assert plan.after.endswith('KEY = os.environ["APP_KEY"]\n')
    ast.parse(plan.after)


def test_python_replaces_only_the_target_literal_in_a_structure() -> None:
    source = f'HEADERS = {{"Authorization": "{SECRET}", "count": 1}}\n'
    plan = patch("app.py", source, 1)

    assert plan.after == (
        'import os\nHEADERS = {"Authorization": os.environ["APP_KEY"], "count": 1}\n'
    )


def test_python_inserts_space_before_expression_when_needed() -> None:
    plan = patch("app.py", f'x = not"{SECRET}"\n', 1)
    assert 'x = not os.environ["APP_KEY"]\n' in plan.after
    ast.parse(plan.after)


def test_python_handles_non_ascii_on_the_same_line() -> None:
    plan = patch("app.py", f'é = 1; KEY = "{SECRET}"\n', 1)
    assert 'é = 1; KEY = os.environ["APP_KEY"]\n' in plan.after
    ast.parse(plan.after)


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (f'KEY = f"{SECRET}"\n', ManualReason.AMBIGUOUS_STRING),
        (f'KEY = f"{{value}}{SECRET}"\n', ManualReason.AMBIGUOUS_STRING),
        (f'KEY = "{SECRET[:5]}" "{SECRET[5:]}"\n', ManualReason.AMBIGUOUS_CONCATENATION),
        (f'KEY = "{SECRET}" + suffix\n', ManualReason.AMBIGUOUS_CONCATENATION),
        (f'KEY = "prefix-{SECRET}"\n', ManualReason.NO_SIMPLE_LITERAL),
        (f'KEY = "{SECRET}"; OTHER = "{SECRET}"\n', ManualReason.MULTIPLE_LITERALS),
        (f'KEY: "{SECRET}" = value\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'match x:\n    case "{SECRET}":\n        pass\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'"""{SECRET}"""\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'KEY = ("{SECRET[:10]}"\n    "{SECRET[10:]}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        ('KEY = "another value"\n', ManualReason.SECRET_NOT_FOUND),
        (f'x = eval("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = exec("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = builtins.eval("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = __builtins__.exec("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(__builtins__, "eval")("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(b, "exec")("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = vars(__builtins__)["eval"]("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = vars(b)["exec"]("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(vars(), "{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = vars().get("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = operator.getitem(vars(), "{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = vars()["{SECRET}"]\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = locals()["{SECRET}"]\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(os.environ, "get")("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = vars(os.environ)["{SECRET}"]\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(os, "environ")["{SECRET}"]\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = getattr(__import__("os"), "{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'x = importlib.import_module("{SECRET}")\n', ManualReason.AMBIGUOUS_CONTEXT),
    ],
)
def test_python_refuses_ambiguous_or_absent_cases(source: str, reason: ManualReason) -> None:
    line = 2 if source.startswith("match ") else 1
    plan = manual("app.py", source, line)
    assert plan.reason is reason


@pytest.mark.parametrize(
    "source",
    [
        f'os = None\nKEY = "{SECRET}"\n',
        f'import sys as os\nKEY = "{SECRET}"\n',
        f'from helpers import os\nKEY = "{SECRET}"\n',
        f'def f(os):\n    return "{SECRET}"\n',
    ],
)
def test_python_refuses_shadowed_os(source: str) -> None:
    line = 2
    plan = manual("app.py", source, line)
    assert plan.reason is ManualReason.SHADOWED_MODULE


@pytest.mark.parametrize(
    "source",
    [
        'os.environ["APP_KEY"]\n',
        'os.environ["APP_KEY"] = value\n',
        'os.environ.get("APP_KEY")\n',
        'os.getenv("APP_KEY")\n',
        'KEY = getattr(os, "APP_KEY")\n',
        'KEY = operator.getitem(os.environ, "APP_KEY")\n',
    ],
)
def test_python_refuses_environment_key_auto_targeting(source: str) -> None:
    """Un indice ``os.environ`` déjà assaini ne doit pas être re-ciblé."""
    plan = manual("app.py", source, 1, secret=ENV_NAME)
    assert plan.reason is ManualReason.AMBIGUOUS_CONTEXT


def test_python_environment_key_guard_does_not_refuse_other_subscripts() -> None:
    source = 'headers["APP_KEY"] = value\n'
    plan = patch("app.py", source, 1, secret=ENV_NAME)
    assert plan.after == 'import os\nheaders[os.environ["APP_KEY"]] = value\n'
    ast.parse(plan.after)


def test_python_invalid_syntax_and_stale_line_are_manual() -> None:
    assert manual("app.py", f'KEY = "{SECRET}"\n', 9).reason is ManualReason.STALE_LINE
    assert manual("app.py", f'KEY = "{SECRET}\n', 1).reason is ManualReason.INVALID_SYNTAX
    assert manual("app.py", "\x00\n", 1).reason is ManualReason.INVALID_SYNTAX


def test_plan_for_finding_uses_contract_fields(finding: Finding) -> None:
    plan = plan_for_finding(finding, f'KEY = "{SECRET}"\n', SECRET, "APP_KEY")
    assert plan.file == "app.py"
    assert plan.line == 1
    assert plan.manual_remediation is False
    with pytest.raises(TemplateError):
        plan_for_finding(cast(Finding, "nope"), "", SECRET, "APP_KEY")


# --- JavaScript -------------------------------------------------------------


def test_javascript_replaces_only_the_literal() -> None:
    source = f'const KEY = "{SECRET}"; // commentaire\n'
    plan = patch("app.js", source, 1)

    assert plan.language is Language.JAVASCRIPT
    assert plan.expression == "process.env.APP_KEY"
    assert plan.after == "const KEY = process.env.APP_KEY; // commentaire\n"
    assert SECRET not in plan.after


@pytest.mark.parametrize(
    "source",
    [
        f"const KEY = '{SECRET}';\n",
        'const KEY = "\\x53YNTHETIC_ONLY_VALUE";\n',
    ],
)
def test_javascript_accepts_simple_string_forms(source: str) -> None:
    plan = patch("app.js", source, 1)
    assert plan.after == "const KEY = process.env.APP_KEY;\n"


def test_javascript_preserves_crlf() -> None:
    plan = patch("app.js", f'const KEY = "{SECRET}";\r\nconst N = 1;\r\n', 1)
    assert plan.after == "const KEY = process.env.APP_KEY;\r\nconst N = 1;\r\n"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (f'return"{SECRET}";\n', "return process.env.APP_KEY;\n"),
        (f'x = "{SECRET}"in obj;\n', "x = process.env.APP_KEY in obj;\n"),
        (f'x = "{SECRET}".trim();\n', "x = process.env.APP_KEY.trim();\n"),
        (f'x = obj["{SECRET}"];\n', "x = obj[process.env.APP_KEY];\n"),
        (f'x = cond ? "{SECRET}" : y;\n', "x = cond ? process.env.APP_KEY : y;\n"),
    ],
)
def test_javascript_boundaries_remain_valid(source: str, expected: str) -> None:
    plan = patch("app.js", source, 1)
    assert plan.after == expected


def test_javascript_regex_with_quotes_does_not_hide_the_real_string() -> None:
    plan = patch("app.js", f'const re = /["\']/; const KEY = "{SECRET}";\n', 1)
    assert plan.after == "const re = /[\"']/; const KEY = process.env.APP_KEY;\n"


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (f"const KEY = `{SECRET}`;\n", ManualReason.AMBIGUOUS_STRING),
        (f'const KEY = "{SECRET}" + suffix;\n', ManualReason.AMBIGUOUS_CONCATENATION),
        (f'const KEY = suffix + "{SECRET}";\n', ManualReason.AMBIGUOUS_CONCATENATION),
        (f'const x = "{SECRET}" "other";\n', ManualReason.AMBIGUOUS_CONCATENATION),
        (f'const x = {{"{SECRET}": 1}};\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'const x = {{"{SECRET}"() {{}}}};\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'class X {{ "{SECRET}"() {{}} }}\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'class X {{ "{SECRET}" = 1; }}\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'class X {{ "{SECRET}" }}\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'class X {{ a = 1; "{SECRET}" }}\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'import x from "{SECRET}";\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'const x = require("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'const KEY = "prefix-{SECRET}";\n', ManualReason.NO_SIMPLE_LITERAL),
        (f"// {SECRET}\n", ManualReason.NO_SIMPLE_LITERAL),
        (f'const x = "{SECRET}"; const y = "{SECRET}";\n', ManualReason.MULTIPLE_LITERALS),
        ('const KEY = "other";\n', ManualReason.SECRET_NOT_FOUND),
        (f'const x = process["en" + "v"]["{SECRET}"];\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'const x = process?.["{SECRET}"];\n', ManualReason.AMBIGUOUS_CONTEXT),
        (
            f'const x = process.env[(a0, a1, ..., a14, "{SECRET}")];\n',
            ManualReason.AMBIGUOUS_CONTEXT,
        ),
        (
            f'const x = process.env[(k0, k1, ..., k14, "{SECRET}")];\n',
            ManualReason.AMBIGUOUS_CONTEXT,
        ),
        (f'eval("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'Function("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'eval?.("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'Function?.("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'(0, eval)("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'(0,eval)("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'(0, eval)?.("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'(0, Function)?.("{SECRET}");\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'setTimeout("{SECRET}", 0);\n', ManualReason.AMBIGUOUS_CONTEXT),
        (f'setInterval("{SECRET}", 0);\n', ManualReason.AMBIGUOUS_CONTEXT),
    ],
)
def test_javascript_refuses_ambiguous_or_absent_cases(source: str, reason: ManualReason) -> None:
    assert manual("app.js", source, 1).reason is reason


@pytest.mark.parametrize(
    "source",
    [
        f'function f(process) {{ const k = "{SECRET}"; }}\n',
        f'function f(...process) {{ const k = "{SECRET}"; }}\n',
        f'const f = (process) => {{ const k = "{SECRET}"; }};\n',
        f'const f = process => {{ const k = "{SECRET}"; }};\n',
        f'const f = async (process) => {{ const k = "{SECRET}"; }};\n',
        f'let process = {{}}; const k = "{SECRET}";\n',
        f'var process; const k = "{SECRET}";\n',
        f'const process = 1; const k = "{SECRET}";\n',
        f'function process() {{}} const k = "{SECRET}";\n',
        f'function* process() {{}} const k = "{SECRET}";\n',
        f'class process {{}} const k = "{SECRET}";\n',
        f'import process from "module"; const k = "{SECRET}";\n',
        f'import {{ process }} from "module"; const k = "{SECRET}";\n',
        f'import * as process from "module"; const k = "{SECRET}";\n',
        f'const {{process}} = source; const k = "{SECRET}";\n',
        f'function f({{process}}) {{ const k = "{SECRET}"; }}\n',
        f'try {{}} catch (process) {{ const k = "{SECRET}"; }}\n',
        f'process = {{}}; const k = "{SECRET}";\n',
        f'process += 1; const k = "{SECRET}";\n',
        f'process++; const k = "{SECRET}";\n',
    ],
)
def test_javascript_refuses_shadowed_process(source: str) -> None:
    plan = manual("app.js", source, 1)
    assert plan.reason is ManualReason.SHADOWED_MODULE


@pytest.mark.parametrize(
    "source",
    [
        'process.env["APP_KEY"];\n',
        "process.env['APP_KEY'];\n",
        'process.env.get("APP_KEY");\n',
        'x = process["env"]["APP_KEY"];\n',
        'KEY = Reflect.get(process.env, "APP_KEY");\n',
        'KEY = operator.getitem(process.env, "APP_KEY");\n',
        'const x = process?.env["APP_KEY"];\n',
        'const x = process?.env.get("APP_KEY");\n',
        'const x = process?.env?.["APP_KEY"];\n',
        'const x = process ?. env ["APP_KEY"];\n',
        'const x = process?.["env"]["APP_KEY"];\n',
    ],
)
def test_javascript_refuses_environment_key_auto_targeting(source: str) -> None:
    plan = manual("app.js", source, 1, secret=ENV_NAME)
    assert plan.reason is ManualReason.AMBIGUOUS_CONTEXT


@pytest.mark.parametrize(
    "source",
    [
        '"use strict";\n',
        'function f() { "use strict"; }\n',
        '"use strict"\n"other";\n',
    ],
)
def test_javascript_refuses_directive_prologue(source: str) -> None:
    plan = manual("app.js", source, 1, secret=DIRECTIVE)
    assert plan.reason is ManualReason.AMBIGUOUS_CONTEXT


def test_javascript_global_process_references_are_not_shadowing() -> None:
    source = f'const k = "{SECRET}"; const home = process.env.HOME; f(process.argv);\n'
    plan = patch("app.js", source, 1)
    assert plan.after == (
        "const k = process.env.APP_KEY; const home = process.env.HOME; f(process.argv);\n"
    )


def test_javascript_global_process_in_parameter_default_is_not_shadowing() -> None:
    source = f'function f(home = process.env.HOME) {{ const k = "{SECRET}"; }}\n'
    plan = patch("app.js", source, 1)
    assert plan.after == (
        "function f(home = process.env.HOME) { const k = process.env.APP_KEY; }\n"
    )


def test_javascript_process_comparisons_are_not_shadowing() -> None:
    source = (
        f'const k = "{SECRET}"; const same = process === other; const lower = process.pid <= 10;\n'
    )
    plan = patch("app.js", source, 1)
    assert plan.after == (
        "const k = process.env.APP_KEY; const same = process === other; "
        "const lower = process.pid <= 10;\n"
    )


def test_javascript_process_property_names_are_not_shadowing() -> None:
    source = f'const k = "{SECRET}"; const x = {{ process: process.env.HOME }}; obj.process = 1;\n'
    plan = patch("app.js", source, 1)
    assert plan.after == (
        "const k = process.env.APP_KEY; const x = { process: process.env.HOME }; obj.process = 1;\n"
    )


def test_javascript_comparison_operators_are_not_field_names() -> None:
    plan = patch("app.js", f'const ok = "{SECRET}" == expected;\n', 1)
    assert plan.after == "const ok = process.env.APP_KEY == expected;\n"


def test_javascript_array_values_and_arguments_are_expression_positions() -> None:
    array = patch("app.js", f'const xs = ["a", "{SECRET}"];\n', 1)
    assert array.after == 'const xs = ["a", process.env.APP_KEY];\n'

    call = patch("app.js", f'f("a", "{SECRET}");\n', 1)
    assert call.after == 'f("a", process.env.APP_KEY);\n'


def test_javascript_invalid_and_stale_lines_are_manual() -> None:
    assert manual("app.js", f'const K = "{SECRET}";', 2).reason is ManualReason.STALE_LINE
    assert manual("app.js", f'const K = "{SECRET};\n', 1).reason is ManualReason.INVALID_SYNTAX
    too_many_tokens = ";" * 100_001 + f'\nconst K = "{SECRET}";\n'
    assert manual("app.js", too_many_tokens, 2).reason is ManualReason.INVALID_SYNTAX


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs"])
def test_javascript_extensions_are_supported(suffix: str) -> None:
    plan = patch(f"src/app{suffix}", f'const KEY = "{SECRET}";\n', 1)
    assert plan.language is Language.JAVASCRIPT


# --- API, secrecy et bornes -------------------------------------------------


@pytest.mark.parametrize(
    ("file", "source", "line", "secret", "variable"),
    [
        ("app.py", "x = 1\n", 1, "", "APP_KEY"),
        ("app.py", "x = 1\n", True, SECRET, "APP_KEY"),
        ("app.py", "x = 1\n", 0, SECRET, "APP_KEY"),
        ("app.py", cast(str, None), 1, SECRET, "APP_KEY"),
        ("app.py", "x = 1\n", 1, cast(str, 12), "APP_KEY"),
        ("app.py", "x = 1\n", 1, SECRET, cast(str, None)),
        ("../app.py", "x = 1\n", 1, SECRET, "APP_KEY"),
        ("app.py", "x = 1\n" * 200_000, 1, SECRET, "APP_KEY"),
        ("app.py", "x = 1\n", 1, "x" * 100_001, "APP_KEY"),
    ],
)
def test_invalid_api_inputs_are_static_errors(
    file: str, source: str, line: int, secret: str, variable: str
) -> None:
    with pytest.raises(TemplateError):
        build_replacement(file, source, line, secret, variable)


def test_repr_never_contains_the_secret_or_source() -> None:
    plan = patch("app.py", f'TOKEN = "{SECRET}"\n', 1)
    rendered = repr(plan)
    assert SECRET not in rendered
    assert "TOKEN" not in rendered
    assert "app.py" in rendered
    assert "patch" in rendered
    assert SECRET not in repr(manual("app.py", f'TOKEN = f"{SECRET}"\n', 1))


def test_token_repr_never_contains_the_decoded_secret() -> None:
    tokens = templates_module._tokenize_js(f'"{SECRET}"')
    assert len(tokens) == 1
    assert tokens[0].value == SECRET
    assert SECRET not in repr(tokens[0])
    assert "SYNTHETIC" not in repr(tokens[0])


def test_manual_plan_invariants_are_checked() -> None:
    with pytest.raises(TemplateError):
        ReplacementPlan(
            file="app.py",
            line=1,
            language=Language.PYTHON,
            variable="APP_KEY",
            before="x",
            after="y",
            expression=None,
            manual_remediation=True,
            reason=ManualReason.AMBIGUOUS_STRING,
        )
    with pytest.raises(TemplateError):
        ReplacementPlan(
            file="app.py",
            line=1,
            language=Language.PYTHON,
            variable="APP_KEY",
            before="x",
            after="x",
            expression='os.environ["APP_KEY"]',
            manual_remediation=False,
            reason=None,
        )


def test_module_has_no_execution_or_network_dependency() -> None:
    """Analyse statique de l'implémentation : lecture pure, aucune I/O."""
    source = Path(templates_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    allowed = {
        "ast",
        "dataclasses",
        "enum",
        "__future__",
        "heimdall",
        "io",
        "pathlib",
        "re",
        "tokenize",
        "typing",
    }
    assert imported <= allowed

    forbidden_calls = {"eval", "exec", "open", "compile", "__import__", "system", "popen", "run"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_calls


# --- Acceptation sur le corpus piège ---------------------------------------


def _literal_value(source: str, line: int, suffix: str) -> str:
    if suffix == ".py":
        tree = ast.parse(source)
        values = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.lineno == line
        ]
        assert len(values) == 1
        return values[0]
    matched = re.search(r'"((?:[^"\\]|\\.)*)"', source.split("\n")[line - 1])
    assert matched is not None
    return cast(str, ast.literal_eval('"' + matched.group(1) + '"'))


def test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo(
    tmp_path: Path,
) -> None:
    """Checklist #83 : Python et JS corrects sur les fichiers du repo piège."""
    root = tmp_path / "corpus"
    root.mkdir()
    build_corpus(root)
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    patched = 0

    for item in expected:
        if not item["leak"] or item["group"] != "plain":
            continue
        path = root / item["file"]
        source = path.read_text(encoding="utf-8")
        line = item["line"]
        secret = _literal_value(source, line, path.suffix)
        variable = item["id"].split("-", 1)[1].upper().replace("-", "_")
        plan = build_replacement(item["file"], source, line, secret, variable)

        assert plan.manual_remediation is False, (item["id"], plan.reason)
        assert secret not in plan.after
        assert plan.variable in plan.after
        if path.suffix == ".py":
            ast.parse(plan.after)
        patched += 1

    # 5 fuites simples par langage, conformément à l'oracle T21.
    assert patched == 10
