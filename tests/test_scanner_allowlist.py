"""Tests unitaires et de sécurité pour l'allowlist déterministe (#24).

Couvre :
- Les 4 règles demandées : example, changeme, dummy, fixtures de test
- La traçabilité de chaque rejet (règle, fichier, ligne) sans fuite de secret
- Le chargement sécurisé du fichier versionné heimdall.toml
- L'affichage permanent du nombre de findings ignorés dans les rapports
- Les gardes de sécurité (CWE-22, CWE-1333, CWE-20, CWE-200, CWE-1188)
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GitRepo
from typer.testing import CliRunner, Result

from heimdall.cli.main import app
from heimdall.cli.scan import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    SCOPE_TREE,
    ScanReport,
    collect,
    render_json,
    render_text,
)
from heimdall.scanner.allowlist import (
    MAX_CONFIG_BYTES,
    Allowlist,
    AllowlistRule,
    AllowlistTrace,
    _compile_safe_regex,
    _validate_path_pattern,
    create_default_rules,
    load_allowlist,
    load_allowlist_from_file,
    parse_allowlist_toml,
)
from heimdall.scanner.detect import Scanner
from heimdall.scanner.errors import ScanError


@pytest.fixture
def git_repo() -> Iterator[GitRepo]:
    """Dépôt git jetable pour les tests de l'allowlist."""
    repo = GitRepo("heimdall-t24-")
    try:
        yield repo
    finally:
        repo.close()


def _run(*arguments: str) -> Result:
    return CliRunner().invoke(app, list(arguments))


# --- 1. Tests unitaires des composants de base -------------------------------


def test_allowlist_trace_immutability_and_validation() -> None:
    """La trace est immuable et valide ses champs sans refléter de secret."""
    trace = AllowlistTrace(rule="example-placeholders", file="src/app.py", line=42)
    assert trace.rule == "example-placeholders"
    assert trace.file == "src/app.py"
    assert trace.line == 42
    assert trace.as_dict() == {
        "rule": "example-placeholders",
        "file": "src/app.py",
        "line": 42,
    }

    with pytest.raises(ValueError):
        AllowlistTrace(rule="", file="src/app.py", line=1)

    with pytest.raises(ValueError):
        AllowlistTrace(rule="valid", file="", line=1)

    with pytest.raises(ValueError):
        AllowlistTrace(rule="valid", file="src/app.py", line=0)


def test_allowlist_rule_validation() -> None:
    """Une règle doit avoir un identifiant sûr et au moins un critère."""
    # Règle valide
    rule = AllowlistRule(
        name="test-rule",
        description="Règle de test",
        keywords=("dummy",),
    )
    assert rule.name == "test-rule"

    # Nom invalide (espaces, caractères spéciaux)
    with pytest.raises(ScanError):
        AllowlistRule(name="invalid name!", description="desc", keywords=("k",))

    # Aucun critère
    with pytest.raises(ScanError):
        AllowlistRule(name="empty-criteria", description="desc")

    # Description vide
    with pytest.raises(ScanError):
        AllowlistRule(name="valid-name", description="", keywords=("k",))


def test_allowlist_duplicate_rule_names_rejected() -> None:
    """Deux règles ne peuvent pas porter le même nom (traçabilité univoque)."""
    r1 = AllowlistRule(name="dup", description="first", keywords=("a",))
    r2 = AllowlistRule(name="dup", description="second", keywords=("b",))
    with pytest.raises(ScanError):
        Allowlist([r1, r2])


# --- 2. Vérification des 4 règles obligatoires (#24) -------------------------


def test_rule_example_placeholders() -> None:
    """Règle 'example' : écarte les jetons et placeholders évidents."""
    al = Allowlist.default()
    # Dans la valeur
    assert al.evaluate(
        value="AKIAIOSFODNN7EXAMPLE",
        file="config.py",
        line=10,
        secret_type="aws",
    ) == "example-placeholders"

    assert al.evaluate(
        value="your_key_here",
        file="app.py",
        line=5,
        secret_type="api_key",
    ) == "example-placeholders"

    # Dans la ligne
    assert al.evaluate(
        value="unrelated_string",
        file="app.py",
        line=5,
        secret_type="aws",
        line_text="EXAMPLE_AWS_KEY = 'unrelated_string'",
    ) == "example-placeholders"


def test_rule_changeme_passwords() -> None:
    """Règle 'changeme' : écarte les mots de passe et configs changeme."""
    al = Allowlist.default()
    assert al.evaluate(
        value="changeme",
        file="env.json",
        line=3,
        secret_type="password",
    ) == "changeme-passwords"

    assert al.evaluate(
        value="admin:changeme123",
        file="docker-compose.yml",
        line=8,
        secret_type="password",
    ) == "changeme-passwords"


def test_rule_dummy_tokens() -> None:
    """Règle 'dummy' : écarte les jetons et identifiants factices dummy."""
    al = Allowlist.default()
    assert al.evaluate(
        value="dummy-secret-token",
        file="client.py",
        line=20,
        secret_type="token",
    ) == "dummy-tokens"

    assert al.evaluate(
        value="xoxb-dummy-12345",
        file="slack.py",
        line=2,
        secret_type="slack",
    ) == "dummy-tokens"


def test_rule_test_fixtures() -> None:
    """Règle 'test-fixtures' : écarte les fixtures factices délimitées aux tests."""
    al = Allowlist.default()
    # Factice dans tests/ -> écarté
    assert al.evaluate(
        value="fake_slack_token_12345",
        file="tests/test_slack.py",
        line=15,
        secret_type="slack",
    ) == "test-fixtures"

    assert al.evaluate(
        value="mock_jwt_token_payload",
        file="tests/fixtures/payload.json",
        line=4,
        secret_type="jwt",
    ) == "test-fixtures"


# --- 3. Piège à éviter (CWE-1188) : Pas d'allowlist aveugle de tests/ --------


def test_trap_real_secret_in_tests_is_never_ignored() -> None:
    """PIÈGE ÉVITÉ : un vrai secret placé dans tests/ N'EST PAS ignoré !

    Un attaquant qui placerait un vrai token AWS dans un fichier de tests/
    sans mot-clé factice reste détecté.
    """
    al = Allowlist.default()
    # Clé AWS sans marqueur 'example', 'changeme', 'dummy' ou 'fake'
    real_looking_secret = "AKIA1234567890ABCDEF"
    result = al.evaluate(
        value=real_looking_secret,
        file="tests/test_live.py",
        line=10,
        secret_type="aws",
        line_text=f"AWS_KEY = '{real_looking_secret}'",
    )
    # L'allowlist REFUSE d'ignorer ce secret : verdict None
    assert result is None


# --- 4. Intégration Scanner et traçabilité des rejets -------------------------


def test_scanner_with_allowlist_produces_traces(tmp_path: Path) -> None:
    """Le scanner n'ajoute pas les secrets ignorés et consigne une trace."""
    # Créer un dépôt avec un secret réel et deux cas de l'allowlist
    (tmp_path / "app.py").write_text(
        'REAL_SECRET = "AKIA1234567890ABCDEF"\n'
        'EXAMPLE_SECRET = "AKIAIOSFODNN7EXAMPLE"\n',
        encoding="utf-8",
    )
    (tmp_path / "test_sample.py").write_text(
        'DUMMY = "dummy-value-12345"\n',
        encoding="utf-8",
    )

    al = Allowlist.default()
    scanner = Scanner(tmp_path, allowlist=al)
    findings = scanner.scan()

    # Seul le secret réel est retenu comme finding
    assert len(findings) == 1
    assert findings[0].file == "app.py"
    assert findings[0].line == 1

    # Les deux cas de l'allowlist sont tracés avec leur règle et localisation
    traces = scanner.traces
    assert len(traces) == 1  # AKIAIOSFODNN7EXAMPLE est une signature AWS
    assert traces[0].file == "app.py"
    assert traces[0].line == 2
    assert traces[0].rule == "example-placeholders"


def test_scanner_traces_contain_no_secret(tmp_path: Path) -> None:
    """Invariant 8 : aucune trace d'allowlist ne contient de secret."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    (tmp_path / "app.py").write_text(f'AWS = "{secret}"\n', encoding="utf-8")
    scanner = Scanner(tmp_path, allowlist=Allowlist.default())
    scanner.scan()
    assert len(scanner.traces) == 1
    trace_dict = scanner.traces[0].as_dict()
    assert secret not in json.dumps(trace_dict)
    assert repr(scanner.traces[0]).find(secret) == -1


# --- 5. Chargement sécurisé de heimdall.toml ----------------------------------


def test_parse_valid_heimdall_toml() -> None:
    """Vérifie le parsing d'un fichier TOML de configuration valide."""
    toml_content = """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "custom-rule"
description = "Règle personnalisée d'exemple"
keywords = ["custom-sample"]
paths = ["custom/**"]
secret_types = ["aws"]
"""
    al = parse_allowlist_toml(toml_content)
    assert len(al.rules) == 1
    rule = al.rules[0]
    assert rule.name == "custom-rule"
    assert rule.description == "Règle personnalisée d'exemple"
    assert rule.keywords == ("custom-sample",)
    assert rule.paths == ("custom/**",)
    assert rule.secret_types == ("aws",)


def test_load_allowlist_from_file_detects_symlink(tmp_path: Path) -> None:
    """CWE-22 : un lien symbolique comme fichier de configuration est refusé."""
    real_config = tmp_path / "real.toml"
    real_config.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    symlink_config = tmp_path / "link.toml"
    symlink_config.symlink_to(real_config)

    with pytest.raises(ScanError):
        load_allowlist_from_file(symlink_config)


def test_load_allowlist_refuses_parent_symlink(tmp_path: Path) -> None:
    """CWE-22 : un dossier parent symlinké est refusé."""
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    config = real_dir / "heimdall.toml"
    config.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")

    link_dir = tmp_path / "link_dir"
    link_dir.symlink_to(real_dir, target_is_directory=True)

    with pytest.raises(ScanError):
        load_allowlist_from_file(link_dir / "heimdall.toml")


def test_load_allowlist_outside_repo_root_is_refused(tmp_path: Path) -> None:
    """CWE-22 : un fichier hors du dépôt est refusé (path traversal)."""
    outside = tmp_path / "outside.toml"
    outside.write_text('[allowlist]\nversion = "1"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(ScanError):
        load_allowlist_from_file(outside, repo_root=repo)


def test_load_allowlist_size_limit_fail_closed(tmp_path: Path) -> None:
    """CWE-400 : un fichier dépassant MAX_CONFIG_BYTES est refusé."""
    big_config = tmp_path / "big.toml"
    big_config.write_text(" " * (MAX_CONFIG_BYTES + 1), encoding="utf-8")
    with pytest.raises(ScanError):
        load_allowlist_from_file(big_config)


def test_parse_allowlist_unknown_keys_rejected() -> None:
    """CWE-20 : contrat fermé - les clés inattendues sont rejetées fail-closed."""
    # Clé inconnue dans [allowlist]
    with pytest.raises(ScanError):
        parse_allowlist_toml('[allowlist]\nversion = "1"\nextra_key = true\n')

    # Clé inconnue dans une règle
    with pytest.raises(ScanError):
        parse_allowlist_toml("""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "rule1"
description = "desc"
keywords = ["a"]
unsupported_key = "value"
""")


def test_parse_allowlist_path_traversal_in_paths_rejected() -> None:
    """CWE-22 : un motif de chemin contenant '..' est rejeté."""
    with pytest.raises(ScanError):
        parse_allowlist_toml("""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "traversal"
description = "desc"
paths = ["../../etc/*"]
""")


def test_parse_allowlist_redos_pattern_rejected() -> None:
    """CWE-1333 : une regex avec quantificateurs imbriqués est refusée."""
    with pytest.raises(ScanError):
        parse_allowlist_toml("""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "redos-rule"
description = "desc"
patterns = ["(a+)+"]
""")


# --- 6. CLI et rapports (render_text, render_json, --ci) ----------------------


def test_render_text_always_shows_ignored_count() -> None:
    """Exigence #24 : le rapport affiche toujours le nombre de findings ignorés."""
    # 1. 0 secret détecté, 0 ignoré
    rep0 = ScanReport(scope=SCOPE_TREE, findings=(), traces=())
    out0 = render_text(rep0)
    assert "Aucun secret détecté." in out0
    assert "Allowlist : 0 finding(s) ignoré(s)." in out0

    # 2. 0 secret détecté, 2 ignorés
    traces = (
        AllowlistTrace(rule="example-placeholders", file="app.py", line=10),
        AllowlistTrace(rule="test-fixtures", file="tests/test_x.py", line=5),
    )
    rep2 = ScanReport(scope=SCOPE_TREE, findings=(), traces=traces)
    out2 = render_text(rep2)
    assert "Aucun secret détecté." in out2
    assert "Allowlist : 2 finding(s) ignoré(s) :" in out2
    assert "app.py:10  règle=example-placeholders" in out2
    assert "tests/test_x.py:5  règle=test-fixtures" in out2


def test_render_json_includes_traces_and_ignored_count() -> None:
    """Contrat JSON machine : inclut ignored_count et traces (règle, fichier, ligne)."""
    traces = (
        AllowlistTrace(rule="example-placeholders", file="config.py", line=1),
    )
    rep = ScanReport(scope=SCOPE_TREE, findings=(), traces=traces)
    payload = json.loads(render_json(rep))
    assert payload["count"] == 0
    assert payload["ignored_count"] == 1
    assert payload["traces"] == [
        {"rule": "example-placeholders", "file": "config.py", "line": 1}
    ]


def test_cli_scan_integration_with_allowlist(git_repo: GitRepo) -> None:
    """Test d'intégration CLI : heimdall scan avec heimdall.toml et traces."""
    # Créer le heimdall.toml dans le dépôt
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "Exemple"
keywords = ["example"]
""",
    )
    # Fichier avec une clé contenant 'EXAMPLE'
    git_repo.write("app.py", 'FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    git_repo.stage("heimdall.toml", "app.py")

    # 1. Scan working-tree avec allowlist active -> code 0 (propre), 1 ignoré
    report = collect(git_repo.root, staged=False)
    assert len(report.findings) == 0
    assert report.ignored_count == 1
    assert report.traces[0].rule == "example-placeholders"

    # 2. Scan staged avec allowlist active -> code 0 (propre), 1 ignoré
    report_staged = collect(git_repo.root, staged=True)
    assert len(report_staged.findings) == 0
    assert report_staged.ignored_count == 1

    # 3. Scan avec allowlist désactivée -> le secret est détecté
    report_no_al = collect(git_repo.root, staged=False, allowlist=Allowlist.empty())
    assert len(report_no_al.findings) == 1
    assert report_no_al.ignored_count == 0


def test_cli_scan_with_explicit_config_flag(git_repo: GitRepo) -> None:
    """Option --config : permet de spécifier un chemin de configuration alternatif."""
    git_repo.write(
        "custom_allowlist.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "my-custom-rule"
description = "desc"
keywords = ["example"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    report = collect(git_repo.root, staged=False, config="custom_allowlist.toml")
    assert report.ignored_count == 1
    assert report.traces[0].rule == "my-custom-rule"


def test_cli_scan_with_invalid_config_fails_closed(git_repo: GitRepo) -> None:
    """Configuration corrompue -> lève ScanError (code sortie 2, fail-closed)."""
    git_repo.write("heimdall.toml", "corrupted [ [ toml syntax")
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=False)


def test_cli_scan_runner_shows_allowlist_output(git_repo: GitRepo) -> None:
    """Vérifie la commande heimdall scan complète avec Typer."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "desc"
keywords = ["example"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    git_repo.stage("heimdall.toml", "app.py")

    # 1. Scan texte par défaut : code 0, affiche le nombre et la trace
    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_CLEAN
    assert "Allowlist : 1 finding(s) ignoré(s) :" in res.stdout
    assert "app.py:1  règle=example-placeholders" in res.stdout

    # 2. Mode --ci : résumé sur stderr avec nombre d'ignorés
    res_ci = _run("scan", "--ci", str(git_repo.root))
    assert res_ci.exit_code == EXIT_CLEAN
    assert "1 ignoré(s) par l'allowlist" in res_ci.stderr

    # 3. Mode --json : sortie JSON valide
    res_json = _run("scan", "--json", str(git_repo.root))
    assert res_json.exit_code == EXIT_CLEAN
    doc = json.loads(res_json.stdout)
    assert doc["count"] == 0
    assert doc["ignored_count"] == 1
    assert doc["traces"] == [
        {"rule": "example-placeholders", "file": "app.py", "line": 1}
    ]

    # 4. Mode --no-allowlist : le secret n'est pas ignoré -> sortie code 1
    res_no_al = _run("scan", "--no-allowlist", str(git_repo.root))
    assert res_no_al.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s) :" in res_no_al.stdout


def test_cli_scan_runner_config_flag(git_repo: GitRepo) -> None:
    """Option --config transmise à la commande CLI."""
    git_repo.write(
        "custom.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "custom-rule"
description = "desc"
keywords = ["example"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    res = _run("scan", "--config", "custom.toml", str(git_repo.root))
    assert res.exit_code == EXIT_CLEAN
    assert "règle=custom-rule" in res.stdout


def test_create_default_rules_and_load_allowlist(git_repo: GitRepo) -> None:
    """Vérifie create_default_rules et load_allowlist sur un dépôt."""
    rules = create_default_rules()
    assert len(rules) == 4
    names = {r.name for r in rules}
    assert names == {
        "example-placeholders",
        "changeme-passwords",
        "dummy-tokens",
        "test-fixtures",
    }
    # Sans fichier -> empty
    al_empty = load_allowlist(git_repo.root)
    assert al_empty.is_empty()

    # Avec fichier heimdall.toml
    git_repo.write("heimdall.toml", '[allowlist]\nversion = "1"\n')
    al_loaded = load_allowlist(git_repo.root)
    assert al_loaded.is_empty()


def test_cli_scan_runner_config_outside_repo_exits_two(git_repo: GitRepo) -> None:
    """Tentative de path traversal avec --config -> code 2 (erreur d'outillage)."""
    res = _run("scan", "--config", "../../etc/passwd", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr


# --- 7. Tests d'exhaustivité et de robustesse supplémentaire -----------------


def test_rule_description_too_long_rejected() -> None:
    """Description dépassant 512 caractères -> ScanError."""
    with pytest.raises(ScanError):
        AllowlistRule(name="long-desc", description="x" * 513, keywords=("k",))


def test_rule_matching_criteria_combinations() -> None:
    """Teste les combinaisons de critères : secret_types, hashes, paths seuls."""
    # Règle avec secret_types restreint
    r_type = AllowlistRule(
        name="aws-only",
        description="desc",
        secret_types=("aws",),
        keywords=("sample",),
    )
    assert not r_type.matches(
        value="sample",
        file_path="app.py",
        line_number=1,
        secret_type="stripe",
    )
    assert r_type.matches(
        value="sample",
        file_path="app.py",
        line_number=1,
        secret_type="aws",
    )

    # Règle avec hashes restreints
    r_hash = AllowlistRule(
        name="hash-only",
        description="desc",
        hashes=("abcdef123456",),
    )
    assert not r_hash.matches(
        value="any",
        file_path="app.py",
        line_number=1,
        secret_type="aws",
        snippet_hash="other_hash",
    )
    assert r_hash.matches(
        value="any",
        file_path="app.py",
        line_number=1,
        secret_type="aws",
        snippet_hash="abcdef123456",
    )

    # Règle avec paths seulement (sans keywords ni patterns)
    r_path = AllowlistRule(
        name="fixtures-dir",
        description="desc",
        paths=("fixtures/**",),
    )
    assert r_path.matches(
        value="any_value",
        file_path="fixtures/test.json",
        line_number=1,
        secret_type="aws",
    )
    assert not r_path.matches(
        value="any_value",
        file_path="src/app.py",
        line_number=1,
        secret_type="aws",
    )


def test_allowlist_is_empty() -> None:
    """Vérifie is_empty sur Allowlist."""
    assert Allowlist.empty().is_empty()
    assert not Allowlist.default().is_empty()


def test_path_pattern_validation_errors() -> None:
    """Validation stricte des motifs de chemin."""
    with pytest.raises(ScanError):
        _validate_path_pattern("")
    with pytest.raises(ScanError):
        _validate_path_pattern("/absolute/path")
    with pytest.raises(ScanError):
        _validate_path_pattern("\\backslash\\root")
    with pytest.raises(ScanError):
        _validate_path_pattern("path/with/\x00/null")
    with pytest.raises(ScanError):
        _validate_path_pattern("a" * 4097)


def test_regex_compilation_errors() -> None:
    """Validation stricte des regex."""
    with pytest.raises(ScanError):
        _compile_safe_regex("")
    with pytest.raises(ScanError):
        _compile_safe_regex("(?P<invalid")
    with pytest.raises(ScanError):
        _compile_safe_regex("a" * 257)


def test_parse_toml_edge_case_errors() -> None:
    """Erreurs de validation de la structure TOML."""
    # Version différente de 1
    with pytest.raises(ScanError):
        parse_allowlist_toml('[allowlist]\nversion = "2"\n')

    # allowlist non dict
    with pytest.raises(ScanError):
        parse_allowlist_toml('allowlist = "not a table"\n')

    # rules non list
    with pytest.raises(ScanError):
        parse_allowlist_toml('[allowlist]\nversion = "1"\nrules = "not a list"\n')

    # Trop de règles (>100)
    many_rules = '[allowlist]\nversion = "1"\n' + "\n".join(
        f'[[allowlist.rules]]\nname = "r{i}"\ndescription = "d"\nkeywords = ["k"]\n'
        for i in range(101)
    )
    with pytest.raises(ScanError):
        parse_allowlist_toml(many_rules)

    # Règle non dictionnaire
    with pytest.raises(ScanError):
        parse_allowlist_toml('[allowlist]\nversion = "1"\nrules = ["string_rule"]\n')

    # Règle avec listes non conformes
    with pytest.raises(ScanError):
        parse_allowlist_toml("""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "bad-list"
description = "d"
keywords = "not_a_list"
""")

    # Règle avec trop d'items dans une liste (>50)
    too_many_kw = (
        '[allowlist]\nversion = "1"\n[[allowlist.rules]]\n'
        'name = "r"\ndescription = "d"\nkeywords = ['
    )
    too_many_kw += ", ".join(f'"k{i}"' for i in range(51)) + "]\n"
    with pytest.raises(ScanError):
        parse_allowlist_toml(too_many_kw)


def test_load_allowlist_file_is_directory(tmp_path: Path) -> None:
    """Un répertoire fourni comme fichier de configuration lève ScanError."""
    dir_path = tmp_path / "a_dir"
    dir_path.mkdir()
    with pytest.raises(ScanError):
        load_allowlist_from_file(dir_path)


def test_load_allowlist_invalid_utf8(tmp_path: Path) -> None:
    """Fichier binaire non décodable en UTF-8 -> ScanError."""
    bad_utf8 = tmp_path / "bad.toml"
    bad_utf8.write_bytes(b"\xff\xfe\x00\x00invalid")
    with pytest.raises(ScanError):
        load_allowlist_from_file(bad_utf8)


