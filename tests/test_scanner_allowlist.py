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
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from support.git_repo import GIT, GitRepo
from typer.testing import CliRunner, Result

import heimdall.cli.scan as scan_module
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
from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GitAccess
from heimdall.scanner import allowlist as al_module
from heimdall.scanner.allowlist import (
    MAX_CONFIG_BYTES,
    MAX_DESCRIPTION_LENGTH,
    MAX_MATCH_PATH_LENGTH,
    MAX_PATH_WILDCARDS,
    MAX_REGEX_VALUE_LENGTH,
    MAX_RULE_NAME_LENGTH,
    MIN_KEYWORD_LENGTH,
    MIN_PATTERN_LITERALS,
    Allowlist,
    AllowlistRule,
    AllowlistTrace,
    _compile_safe_regex,
    _keyword_matches_value,
    _validate_path_pattern,
    create_default_rules,
    load_allowlist,
    load_allowlist_from_file,
    parse_allowlist_toml,
)
from heimdall.scanner.detect import Scanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import validate_relative_path


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


def _run_cli_process(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Lance la CLI dans un sous-processus borné (test anti-blocage FIFO)."""
    return subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [sys.executable, "-c", "from heimdall.cli.main import main; main()", *arguments],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


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

    # Patterns non compilés : ScanError, jamais AttributeError (invariant 11).
    with pytest.raises(ScanError):
        AllowlistRule(name="bad-pattern", description="desc", patterns=("x",))
    with pytest.raises(ScanError):
        AllowlistRule(
            name="bytes-pattern",
            description="desc",
            patterns=(re.compile(b"x"),),
        )

    # Les autres critères sont également typés.
    with pytest.raises(ScanError):
        AllowlistRule(name="bad-keyword", description="desc", keywords=(1,))
    with pytest.raises(ScanError):
        AllowlistRule(name="bad-path", description="desc", keywords=("x",), paths=(1,))


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

    # Dans la ligne uniquement (ne doit PAS matcher pour éviter tout contournement par commentaire)
    assert (
        al.evaluate(
            value="unrelated_string",
            file="app.py",
            line=5,
            secret_type="aws",
        )
        is None
    )


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
        value="admin:changeme",
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
    # Factice dans tests/ -> écarté (séparateur non-mot, frontière \b stricte)
    assert al.evaluate(
        value="fake-token-12345",
        file="tests/test_slack.py",
        line=15,
        secret_type="slack",
    ) == "test-fixtures"

    assert al.evaluate(
        value="mock-jwt-token-payload",
        file="tests/fixtures/payload.json",
        line=4,
        secret_type="jwt",
    ) == "test-fixtures"


def test_rule_test_fixtures_does_not_treat_underscore_as_separator() -> None:
    """Une valeur `_fake_`/`_dummy_` sous tests/ reste signalée (Invariant 1).

    `_` est un caractère de mot pour `\\b` : élargir la frontière aux
    séparateurs de code élargirait l'allowlist et pourrait masquer un vrai
    secret délimité par des underscores. Le comportement est volontairement
    strict : `fake_slack_token` et `my_dummy_key` ne sont PAS des fixtures.
    """
    al = Allowlist.default()
    for value in ("fake_slack_token_12345", "my_dummy_key"):
        assert (
            al.evaluate(
                value=value,
                file="tests/test_fixture.py",
                line=1,
                secret_type="password",
            )
            is None
        )


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


def test_load_allowlist_explicit_external_config_accepted(tmp_path: Path) -> None:
    """Revue (LOW) : un `--config` explicite hors dépôt est accepté hors CI.

    C'est un choix opérateur explicite (disponibilité, cf. l'aide `--config`)
    : la garde `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et le
    contrat fermé s'appliquent toujours. Sans `allow_external`, le refus
    fail-closed reste la norme.
    """
    outside = tmp_path / "outside.toml"
    outside.write_text(
        '[allowlist]\nversion = "1"\n\n[[allowlist.rules]]\n'
        'name = "dummy"\ndescription = "d"\nkeywords = ["dummy"]\n',
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()

    # Sans l'opt-in explicite : refus fail-closed (comportement historique).
    with pytest.raises(ScanError):
        load_allowlist(repo, config_file=outside, allow_external=False)

    # Avec l'opt-in explicite : accepté et fonctionnel.
    allowlist = load_allowlist(repo, config_file=outside, allow_external=True)
    assert allowlist.evaluate(
        value="dummy",
        file="app.py",
        line=1,
        secret_type="password",
    ) is not None

    # Un contenu invalide reste fail-closed, même explicitement opté.
    outside.write_text("[allowlist]\nversion = 1\n", encoding="utf-8")
    with pytest.raises(ScanError):
        load_allowlist(repo, config_file=outside, allow_external=True)


def test_config_with_nul_stays_in_scan_error_contract(git_repo: GitRepo) -> None:
    """Revue (LOW) : un chemin avec NUL reste dans le contrat `ScanError`.

    Un NUL fait échouer les appels OS en `ValueError`
    (« embedded null character ») : chaque frontière (`_resolve_root`,
    `load_allowlist`, la garde anti auto-attestation via `collect`) doit
    convertir en `ScanError` statique (invariant 11), jamais laisser fuir
    le brut vers l'appelant.
    """
    with pytest.raises(ScanError):
        load_allowlist(git_repo.root, config_file="a\x00b")
    with pytest.raises(ScanError):
        load_allowlist(git_repo.root, config_file=Path("a\x00b"))
    with pytest.raises(ScanError):
        load_allowlist(Path("a\x00b"))
    with pytest.raises(ScanError):
        load_allowlist_from_file(Path("a\x00b"))
    # La garde anti auto-attestation convertit aussi (arbre comme staged).
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=False, config="a\x00b")
    git_repo.write("app.py", 'KEY = "x"\n')
    git_repo.stage("app.py")
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=True, config="a\x00b")


def test_load_allowlist_size_limit_fail_closed(tmp_path: Path) -> None:
    """CWE-400 : un fichier dépassant MAX_CONFIG_BYTES est refusé."""
    big_config = tmp_path / "big.toml"
    big_config.write_text(" " * (MAX_CONFIG_BYTES + 1), encoding="utf-8")
    with pytest.raises(ScanError):
        load_allowlist_from_file(big_config)


def test_parse_allowlist_unknown_keys_rejected() -> None:
    """CWE-20 : contrat fermé - les clés inattendues sont rejetées fail-closed."""
    # Clé inconnue au premier niveau : une faute de frappe ne doit pas
    # être ignorée silencieusement.
    with pytest.raises(ScanError):
        parse_allowlist_toml("""
[tool.foo]
bar = 1

[allowlist]
version = "1"
""")

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
keywords = ["abc"]
unsupported_key = "value"
""")


def test_parse_allowlist_version_is_strictly_typed() -> None:
    """`version = 1` (int) est refusé ; seul le littéral `"1"` est accepté."""
    with pytest.raises(ScanError):
        parse_allowlist_toml("[allowlist]\nversion = 1\n")

    parsed = parse_allowlist_toml('[allowlist]\nversion = "1"\n')
    assert parsed.is_empty()


def test_parse_allowlist_missing_version_is_rejected() -> None:
    """Revue (LOW) : `version` est obligatoire, jamais une valeur par défaut.

    Le contrat annoncé est fermé : une table `[allowlist]` sans `version`
    échoue en `ScanError` (code 2) au lieu d'impliquer silencieusement la
    grammaire "1".
    """
    with pytest.raises(ScanError):
        parse_allowlist_toml("[allowlist]\n")

    with pytest.raises(ScanError):
        parse_allowlist_toml(
            '[allowlist]\n[[allowlist.rules]]\nname = "r"\ndescription = "d"\n'
            'keywords = ["abc"]\n'
        )

    # Avec explication de la table racine, la version reste le seul littéral admis.
    with pytest.raises(ScanError):
        parse_allowlist_toml('[allowlist]\nversion = "2"\n')

def test_pattern_min_literals_reformulation_is_accepted() -> None:
    """Revue (LOW) : le refus des motifs à 1-2 littéraux est figé, avec
    l'exemple de reformulation documenté (`EXAMPLE-[0-9]{4}`).

    Un motif doit porter au moins MIN_PATTERN_LITERALS caractères littéraux
    hors classes, ancres et quantificateurs pour rester auditable.
    """
    # Refusés : pas assez de littéraux (motif trop large).
    for narrow in (r"\d{3}-\d{4}", "x{3}y{3}", r"\w+", "[a-z]+"):
        with pytest.raises(ScanError):
            _compile_safe_regex(narrow)

    # La reformulation documentée porte des marqueurs concrets : acceptée,
    # et elle ignore UNIQUEMENT la forme allowlistée visée.
    ok = _compile_safe_regex(r"EXAMPLE-[0-9]{4}")
    assert ok.search("AKIAIOSFODNN7EXAMPLE-1234")
    rule = AllowlistRule(
        name="example-form",
        description="d",
        patterns=(ok,),
    )
    assert rule.matches(
        value="EXAMPLE-1234",
        file_path="app.py",
        line_number=1,
        secret_type="password",
    )
    # Un secret réel ne respectant pas la forme reste signalé (invariant 1).
    assert not rule.matches(
        value="AKIAIOSFODNN7EXAMPLE",
        file_path="app.py",
        line_number=1,
        secret_type="password",
    )


def test_parse_allowlist_short_keywords_rejected() -> None:
    """Un mot-clé de moins de 3 caractères est refusé (règle trop large)."""
    for short_keyword in ("a", "ab"):
        with pytest.raises(ScanError):
            parse_allowlist_toml(f"""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "short-keyword"
description = "d"
keywords = ["{short_keyword}"]
""")

    parsed = parse_allowlist_toml("""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "minimum-keyword"
description = "d"
keywords = ["abc"]
""")
    assert parsed.rules[0].keywords == ("abc",)


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
patterns = ["^AKIA.*EXAMPLE$"]
""",
    )
    # Committer heimdall.toml pour qu'il soit une configuration de dépôt validée
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: add allowlist")
    # Fichier avec une clé contenant 'EXAMPLE'
    git_repo.write("app.py", 'FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    git_repo.stage("app.py")

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
patterns = ["^AKIA.*EXAMPLE$"]
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


def test_cli_scan_runner_shows_allowlist_output(git_repo: GitRepo, tmp_path: Path) -> None:
    """Vérifie la commande heimdall scan complète avec Typer."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "desc"
patterns = ["^AKIA.*EXAMPLE$"]
""",
    )
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: add allowlist")
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    git_repo.stage("app.py")
    git_repo.commit_all("feat: app")

    # 1. Scan texte par défaut : code 0, affiche le nombre et la trace
    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_CLEAN
    assert "Allowlist : 1 finding(s) ignoré(s) :" in res.stdout
    assert "app.py:1  règle=example-placeholders" in res.stdout

    # 2. Mode --ci : avec --config externe explicite, résumé sur stderr
    ext_ci_cfg = tmp_path / "ci_heimdall.toml"
    ext_ci_cfg.write_text(
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "example-placeholders"
description = "desc"
patterns = ["^AKIA.*EXAMPLE$"]
""",
        encoding="utf-8",
    )
    res_ci = _run("scan", "--ci", "--config", str(ext_ci_cfg), str(git_repo.root))
    assert res_ci.exit_code == EXIT_CLEAN
    assert "1 ignoré(s) par l'allowlist (config sha256:" in res_ci.stderr

    # 3. Mode --json : sortie JSON valide
    res_json = _run("scan", "--json", str(git_repo.root))
    assert res_json.exit_code == EXIT_CLEAN
    doc = json.loads(res_json.stdout)
    assert doc["count"] == 0
    assert doc["ignored_count"] == 1
    assert doc["traces"] == [
        {"rule": "example-placeholders", "file": "app.py", "line": 1}
    ]
    assert doc["config_hash"] is not None and len(doc["config_hash"]) == 64

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
patterns = ["^AKIA.*EXAMPLE$"]
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


def test_cli_without_config_does_not_apply_default_factories(git_repo: GitRepo) -> None:
    """Sans heimdall.toml, aucune règle implicite ne s'applique au verdict.

    `Allowlist.default()` et `create_default_rules()` sont des fabriques
    d'API/test ; le chargement CLI utilise `Allowlist.empty()` en l'absence
    de configuration auditée. Ce test fige cette frontière.
    """
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_FINDINGS
    assert "Allowlist : 0 finding(s) ignoré(s)" in res.stdout


def test_cli_scan_runner_config_outside_repo_exits_two(git_repo: GitRepo) -> None:
    """Tentative de path traversal avec --config -> code 2 (erreur d'outillage)."""
    res = _run("scan", "--config", "../../etc/passwd", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr


def test_cli_external_config_accepted_outside_ci(
    git_repo: GitRepo,
    tmp_path: Path,
) -> None:
    """Revue (LOW) : `--config` externe hors CI est accepté (choix opérateur).

    L'aide `--config PATH` promet un fichier alternatif ; un opérateur local
    peut donc épingler sa configuration hors dépôt. La garde `_resolve_root`
    + `O_NOFOLLOW`, le plafond de taille et le contrat fermé s'appliquent.
    """
    outside = tmp_path / "outside.toml"
    outside.write_text(
        '[allowlist]\nversion = "1"\n\n[[allowlist.rules]]\n'
        'name = "custom-rule"\ndescription = "d"\n'
        'patterns = ["^AKIA.*EXAMPLE$"]\n',
        encoding="utf-8",
    )
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    # En mode arbre local (non CI) : accepté, la règle `custom-rule` s'applique.
    res = _run("scan", "--config", str(outside), str(git_repo.root))
    assert res.exit_code == EXIT_CLEAN
    assert "règle=custom-rule" in res.stdout

    # En staged (non CI) : même disponibilité.
    git_repo.stage("app.py")
    res_staged = _run("scan", "--staged", "--config", str(outside), str(git_repo.root))
    assert res_staged.exit_code == EXIT_CLEAN

    # Une externe invalide reste un code 2 (fail-closed).
    outside.write_text("[allowlist]\nversion = 1\n", encoding="utf-8")
    res_bad = _run("scan", "--config", str(outside), str(git_repo.root))
    assert res_bad.exit_code == EXIT_ERROR


def test_cli_config_with_nul_fail_closed(git_repo: GitRepo) -> None:
    """Revue (LOW) : `--config`/racine avec NUL → code 2, jamais 0.

    Via un argv réel un NUL est impossible (terminateur C), mais l'appel
    in-process l'accepte : le contrat CLI reste le code 2 avec le message
    statique (invariant 8), sans `ValueError` brut ni traceback.
    """
    res = _run("scan", "--config", "a\x00b", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr.lower()
    assert "\x00" not in res.stderr
    assert not isinstance(res.exception, ValueError)

    res_root = _run("scan", "a\x00b")
    assert res_root.exit_code == EXIT_ERROR
    assert "scan impossible" in res_root.stderr.lower()
    assert "\x00" not in res_root.stderr
    assert not isinstance(res_root.exception, ValueError)


def test_close_failure_never_leaks_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : `os.close` en échec ne sort jamais en `OSError` brute.

    `load_allowlist_from_file` convertit en `ScanError` (contrat unique,
    invariant 11) ; `_read_worktree_file` rend `None` (fail-closed).
    La fermeture réelle a lieu avant la panne simulée (pas de fuite de fd).
    """
    cfg = tmp_path / "config.toml"
    cfg.write_text(_config_saine(), encoding="utf-8")
    real_close = os.close

    def boom(fd: int) -> None:
        real_close(fd)
        raise OSError("EBADF simulé")

    monkeypatch.setattr(os, "close", boom)
    with pytest.raises(ScanError):
        load_allowlist_from_file(cfg)
    assert scan_module._read_worktree_file(cfg) is None


def test_guard_messages_never_reflect_config_path(git_repo: GitRepo) -> None:
    """Revue (LOW) : la garde anti auto-attestation parle sans nommer.

    `rel_cfg` est une entrée opérateur normalisée : les messages sont
    strictement statiques (invariant 8), en arbre comme en staged, via
    `--config` interne comme via `heimdall.toml`.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    with pytest.raises(ScanError) as excinfo:
        collect(git_repo.root, staged=False)
    assert "auto-attestation" in str(excinfo.value)
    assert "heimdall.toml" not in str(excinfo.value)

    git_repo.write("custom-xyz.toml", _config_saine())
    git_repo.stage("custom-xyz.toml")
    with pytest.raises(ScanError) as excinfo_custom:
        collect(git_repo.root, staged=False, config="custom-xyz.toml")
    assert "auto-attestation" in str(excinfo_custom.value)
    assert "custom-xyz" not in str(excinfo_custom.value)

    # Worktree sale en mode staged : même statut, aucun chemin reflété.
    git_repo.commit_all("chore: config initiale")
    git_repo.write("heimdall.toml", _config_saine() + "# retouche locale\n")
    with pytest.raises(ScanError) as excinfo_dirty:
        collect(git_repo.root, staged=True)
    assert "auto-attestation" in str(excinfo_dirty.value)
    assert "heimdall.toml" not in str(excinfo_dirty.value)


def test_verified_reload_message_is_static(
    git_repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : le re-contrôle anti-TOCTOU parle sans nommer.

    Substitution entre garde et parsing → `ScanError` statique, sans le
    chemin vérifié dans le message (même oracle que la garde ci-dessus).
    """
    content = _config_saine().encode("utf-8")
    monkeypatch.setattr(
        scan_module, "_read_worktree_file", lambda path: b"contenu-substitue"
    )
    verified = scan_module._VerifiedConfig(path="heimdall.toml", content=content)
    with pytest.raises(ScanError) as excinfo:
        scan_module._load_allowlist_verified(GitAccess(git_repo.root), verified)
    assert "auto-attestation" in str(excinfo.value)
    assert "heimdall.toml" not in str(excinfo.value)


def test_default_config_unreadable_is_scan_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : `exists()` en échec → code 2, pas allowlist vide.

    Un répertoire illisible est une panne d'outillage (invariant 11), pas
    une absence de config. Seule l'absence avérée vaut « pas de config ».
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    def boom(self: Path) -> bool:
        raise OSError("EIO simulé")

    monkeypatch.setattr(Path, "exists", boom)
    with pytest.raises(ScanError):
        load_allowlist(repo)

    # Sans panne : l'absence avérée reste une allowlist vide (fail-closed).
    monkeypatch.undo()
    assert load_allowlist(repo).is_empty()


def test_guard_default_config_unreadable_is_scan_error(
    git_repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : `exists()` en échec dans la garde → `ScanError`/code 2.

    Même contrat que `load_allowlist` : un répertoire illisible est une
    panne d'outillage (invariant 11), pas une absence silencieuse qui
    contournerait la garde anti auto-attestation.
    """
    real_exists = Path.exists

    def boom(self: Path) -> bool:
        if self.name == "heimdall.toml":
            raise OSError("EIO simulé")
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", boom)
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=False)
    with pytest.raises(ScanError):
        collect(git_repo.root, staged=True)
    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr.lower()
    assert not isinstance(res.exception, OSError)


def test_worktree_check_logs_distinct_refusal_causes(
    git_repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Revue (LOW) : les causes de refus de la garde se distinguent en logs.

    `None` légitime (untracked) vs panne (index illisible) vs dirty : même
    verdict fail-closed (`None`), mais libellés debug distincts et
    statiques (aucune entrée ni secret reflété, invariant 8).
    """
    access = GitAccess(git_repo.root)
    with caplog.at_level(logging.DEBUG, logger="heimdall.cli.scan"):
        assert (
            scan_module._is_worktree_file_clean_and_tracked(
                access, "ghost.toml", timeout=30
            )
            is None
        )
    assert "lecture worktree impossible" in caplog.text
    caplog.clear()

    # Index lisible mais fichier non suivi : `None` légitime.
    git_repo.write("app.py", 'KEY = "x"\n')
    git_repo.commit_all("chore: init")
    git_repo.write("heimdall.toml", _config_saine())
    with caplog.at_level(logging.DEBUG, logger="heimdall.cli.scan"):
        assert (
            scan_module._is_worktree_file_clean_and_tracked(
                access, "heimdall.toml", timeout=30
            )
            is None
        )
    assert "non suivie" in caplog.text
    caplog.clear()

    def boom_index(self: GitAccess, *args: object, **kwargs: object) -> None:
        raise ToolFailure("INTERNAL")

    monkeypatch.setattr(GitAccess, "index_entry", boom_index)
    with caplog.at_level(logging.DEBUG, logger="heimdall.cli.scan"):
        assert (
            scan_module._is_worktree_file_clean_and_tracked(
                access, "heimdall.toml", timeout=30
            )
            is None
        )
    assert "lecture index impossible" in caplog.text
    caplog.clear()
    monkeypatch.undo()

    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    git_repo.write("heimdall.toml", _config_saine() + "# retouche locale\n")
    with caplog.at_level(logging.DEBUG, logger="heimdall.cli.scan"):
        assert (
            scan_module._is_worktree_file_clean_and_tracked(
                access, "heimdall.toml", timeout=30
            )
            is None
        )
    assert "divergente" in caplog.text


# --- 7. Tests d'exhaustivité et de robustesse supplémentaire -----------------


def test_rule_description_too_long_rejected() -> None:
    """Description dépassant 512 caractères -> ScanError."""
    with pytest.raises(ScanError):
        AllowlistRule(name="long-desc", description="x" * 513, keywords=("k",))


def test_rule_matching_criteria_combinations() -> None:
    """Teste les combinaisons de critères : restrictions conjonctives de chemin et de type."""
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

    # Règle avec paths et keywords
    r_path = AllowlistRule(
        name="fixtures-dir",
        description="desc",
        paths=("fixtures/**", "**/fixtures/**"),
        keywords=("sample",),
    )
    assert r_path.matches(
        value="sample",
        file_path="fixtures/test.json",
        line_number=1,
        secret_type="aws",
    )
    assert not r_path.matches(
        value="sample",
        file_path="src/app.py",
        line_number=1,
        secret_type="aws",
    )
    assert not r_path.matches(
        value="other_secret",
        file_path="fixtures/test.json",
        line_number=1,
        secret_type="aws",
    )


def test_rule_must_have_value_criterion_rejects_paths_or_types_alone() -> None:
    """Toute règle sans keywords ni patterns est refusée à la validation (fail-closed)."""
    with pytest.raises(ScanError):
        AllowlistRule(name="blind-paths", description="d", paths=("src/**",))
    with pytest.raises(ScanError):
        AllowlistRule(name="blind-types", description="d", secret_types=("aws",))
    with pytest.raises(ScanError):
        AllowlistRule(name="blind-both", description="d", paths=("src/**",), secret_types=("aws",))

    bad_toml = """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "blind-rule"
description = "d"
paths = ["src/**"]
"""
    with pytest.raises(ScanError):
        parse_allowlist_toml(bad_toml)


def test_allowlist_is_empty() -> None:
    """Vérifie is_empty sur Allowlist."""
    assert Allowlist.empty().is_empty()
    assert not Allowlist.default().is_empty()


def test_path_pattern_validation_errors() -> None:
    """Validation stricte des motifs de chemin (même grammaire que Finding #14)."""
    for bad_pattern in (
        "",
        "/absolute/path",
        "\\backslash\\root",
        "C:/Windows/system.ini",
        "C:\\Windows\\system.ini",
        "path/with/\x00/null",
        "path/with\nnewline",
        "path/../traversal",
        "path//empty-segment",
        "path/./dot-segment",
        "a" * 4097,
    ):
        with pytest.raises(ScanError):
            _validate_path_pattern(bad_pattern)


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
        f'[[allowlist.rules]]\nname = "r{i}"\ndescription = "d"\nkeywords = ["key"]\n'
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
    too_many_kw += ", ".join(f'"kw{i}"' for i in range(51)) + "]\n"
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


def test_comment_bypass_abuse_prevented(git_repo: GitRepo) -> None:
    """Un vrai secret avec # dummy ou # example sur la même ligne reste détecté (CWE-200)."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "dummy-tokens"
description = "tokens factices"
keywords = ["dummy"]

[[allowlist.rules]]
name = "example-placeholders"
description = "placeholders"
keywords = ["example"]
""",
    )
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: add allowlist")
    # Vrai secret AWS (synthétique sans dummy/example dans la valeur) + commentaire piège
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"  # dummy example changeme token\n')
    git_repo.stage("app.py")

    # Mode staged : doit détecter le secret (exit 1) et ne pas le bypasser
    res_staged = _run("scan", "--staged", str(git_repo.root))
    assert res_staged.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s) :" in res_staged.stdout

    # Mode arbre : doit aussi détecter le secret (exit 1)
    res_tree = _run("scan", str(git_repo.root))
    assert res_tree.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s) :" in res_tree.stdout


def test_substring_keyword_in_tests_does_not_mask_real_secret(git_repo: GitRepo) -> None:
    """latest/contest sous tests/ ne doit pas matcher 'test' et ignorer un vrai secret."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "test-fixtures"
description = "fixtures factices"
paths = ["tests/**"]
keywords = ["fake", "mock", "dummy", "placeholder", "synthetic", "factice", "fixture"]
""",
    )
    git_repo.write("tests/test_foo.py", 'latest_token = "AKIA0123456789ABCDEF"\n')
    git_repo.write("tests/contest.py", 'contest_key = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("tests/test_foo.py", "tests/contest.py")

    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_FINDINGS
    assert "2 secret(s) détecté(s) :" in res.stdout


def test_self_attestation_staged_modifying_heimdall_toml_fails_loud(git_repo: GitRepo) -> None:
    """Stager une modification de heimdall.toml lève ScanError (code 2, fail-closed)."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "bypass"
description = "d"
keywords = ["AKIA"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("heimdall.toml", "app.py")

    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr.lower() or "auto-attestation" in res.stderr.lower()


def test_self_attestation_tree_modifying_heimdall_toml_fails_loud(git_repo: GitRepo) -> None:
    """Stager heimdall.toml et scanner l'arbre lève ScanError (code 2, CWE-345)."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "bypass"
description = "d"
keywords = ["AKIA"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("heimdall.toml", "app.py")

    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr.lower() or "auto-attestation" in res.stderr.lower()


def test_self_attestation_committed_heimdall_toml_in_ci_fails_loud(
    git_repo: GitRepo, tmp_path: Path
) -> None:
    """En mode --ci, un heimdall.toml committé dans le dépôt ne peut pas s'auto-attester."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "hostile-bypass"
description = "d"
patterns = ["^AKIA.*"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("heimdall.toml", "app.py")
    git_repo.commit_all("feat: hostile bypass committed")

    # 1. En --ci par défaut (sans --config) : refus fail-closed loud (code 2)
    res_ci = _run("scan", "--ci", str(git_repo.root))
    assert res_ci.exit_code == EXIT_ERROR
    assert "auto-attestation" in res_ci.stderr.lower() or "scan impossible" in res_ci.stderr.lower()

    # 2. En --ci avec --no-allowlist : le secret est bien détecté (code 1)
    res_no_al = _run("scan", "--ci", "--no-allowlist", str(git_repo.root))
    assert res_no_al.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in res_no_al.stderr

    # 3. En --ci avec --config interne pointant dans le dépôt : refus fail-closed loud (code 2)
    res_repo_cfg = _run("scan", "--ci", "--config", "heimdall.toml", str(git_repo.root))
    assert res_repo_cfg.exit_code == EXIT_ERROR
    err_lower = res_repo_cfg.stderr.lower()
    assert "auto-attestation" in err_lower or "scan impossible" in err_lower

    # 4. En --ci avec --config externe (hors dépôt attaqué) : accepté (code 0)
    ext_config = tmp_path / "ci_approved.toml"
    ext_config.write_text(
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "ci-approved"
description = "d"
patterns = ["^AKIA.*"]
""",
        encoding="utf-8",
    )
    res_ext = _run("scan", "--ci", "--config", str(ext_config), str(git_repo.root))
    assert res_ext.exit_code == EXIT_CLEAN


def test_real_prod_password_with_dummy_or_fake_remains_detected() -> None:
    """Un secret de prod contenant 'dummy' ou 'fake' comme sous-chaîne reste détecté (CWE-200)."""
    al = Allowlist(
        [
            AllowlistRule(
                name="dummy-tokens",
                description="tokens factices",
                keywords=("dummy", "fake"),
            )
        ]
    )
    # 1. Mot de passe de prod avec 'dummy' dans la chaîne
    assert (
        al.evaluate(
            value="prod_dummy_password_12345",
            file="prod.env",
            line=1,
            secret_type="password",
        )
        is None
    )

    # 2. Mot de passe de prod avec 'fake'
    assert (
        al.evaluate(
            value="fakePassword999!",
            file="prod.env",
            line=2,
            secret_type="password",
        )
        is None
    )

    # 3. Valeur exacte 'dummy' : reconnue
    assert (
        al.evaluate(
            value="dummy",
            file="test.py",
            line=3,
            secret_type="password",
        )
        == "dummy-tokens"
    )


def test_cli_scan_incompatible_config_and_no_allowlist(git_repo: GitRepo) -> None:
    """--config et --no-allowlist combinés lèvent une erreur explicite (code 2)."""
    git_repo.write("custom.toml", '[allowlist]\nversion = "1"\n')
    res = _run("scan", "--config", "custom.toml", "--no-allowlist", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "options incompatibles" in res.stderr


def test_redos_dangerous_patterns_refused() -> None:
    """Vérifie le rejet des constructions regex à risque ReDoS (CWE-1333)."""
    dangerous_patterns = [
        "(a|aa)+",
        "(.*a)+",
        "(a|a)+",
        "a++",
        "(a+)+",
        ".*.*",
        "a*a*",
        r"\d+\d+",
        r"\w+\w+",
        r"[0-9]+[0-9]+",
        "(a|b){2,5}",
        "a*?",
        "a+?",
        "a?a?",
        "(a?)+",
    ]
    for pattern in dangerous_patterns:
        with pytest.raises(ScanError):
            _compile_safe_regex(pattern)


def test_redos_nested_alternation_refused() -> None:
    """Revue (MEDIUM) : l'imbrication réelle est refusée, pas seulement (a|aa)+.

    Les regex `[^)]*` du premier filtre ne traversaient pas `)` : des motifs
    comme `((a|aa))+$` passaient. L'analyse structurelle les refuse.
    """
    for pattern in (
        r"((a|aa))+$",
        r"(a|(b|c))+$",
        r"(?:(a|aa))+$",
        r"((a+))+$",
        r"(?:(?:a|aa))+",
        r"((ab|cd))+",
    ):
        with pytest.raises(ScanError):
            _compile_safe_regex(pattern)


def test_redos_nested_fuzz_is_bounded_in_time() -> None:
    """Fuzz des imbrications ancrées : refus immédiat, jamais de `search` explosif."""
    start = time.monotonic()
    for prefix in ("", "^"):
        for suffix in ("", "$"):
            for body in (r"((a|aa))+", r"(a|(b|c))+", r"(?:(a|aa))+"):
                with pytest.raises(ScanError):
                    _compile_safe_regex(f"{prefix}{body}{suffix}")
    # Un motif sûr reste linéaire sur la valeur piège utilisée par la revue.
    safe = _compile_safe_regex(r"^AKIA[A-Z0-9]{16}$")
    assert safe.search("a" * 30 + "!") is None
    assert time.monotonic() - start < 2.0


def test_universal_patterns_are_refused() -> None:
    """Revue (MEDIUM) : `.`, `.*`, `^`, `^.*$` ne peuvent pas être une allowlist aveugle."""
    # Les quatre motifs universels de la revue sont refusés via le TOML.
    for pattern in (".", ".*", "^", "^.*$"):
        with pytest.raises(ScanError):
            parse_allowlist_toml(f"""
[allowlist]
version = "1"

[[allowlist.rules]]
name = "blind"
description = "d"
patterns = ["{pattern}"]
""")

    for pattern in (
        ".",
        ".*",
        ".+",
        "^",
        "$",
        "^.*$",
        "^.+$",
        r"\w+",
        r"\d{16}",
        "[a-z]+",
        "[A-Z]{20}",
        "[^x]+",
        ".|AKIA",
        "(?:.|AKIA)",
    ):
        with pytest.raises(ScanError):
            _compile_safe_regex(pattern)

    # Un motif spécifique ne doit jamais ignorer un secret réel qui ne le respecte pas.
    rule = AllowlistRule(
        name="specific-pattern",
        description="d",
        patterns=(_compile_safe_regex(r"^AKIA[A-Z0-9]{16}$"),),
    )
    al = Allowlist([rule])
    assert (
        al.evaluate(
            value="AKIA" + "A" * 15 + "!",
            file="app.py",
            line=1,
            secret_type="aws",
        )
        is None
    )


def test_specific_patterns_still_accepted() -> None:
    """Les motifs porteurs de marqueurs littéraux restent acceptés."""
    for pattern in (
        r"^AKIA.*EXAMPLE$",
        r"^ghp_[A-Za-z0-9]{36}$",
        r"^sk-[A-Za-z0-9]{20}$",
        r"\bAKIA[A-Z0-9]{16}\b",
    ):
        assert _compile_safe_regex(pattern) is not None


def test_regex_value_length_cap_is_fail_closed() -> None:
    """Une valeur trop longue n'est jamais ignorée par une regex (fail-closed)."""
    rule = AllowlistRule(
        name="long-value",
        description="d",
        patterns=(_compile_safe_regex(r"^AKIA.*EXAMPLE$"),),
    )
    assert rule.matches(
        value="AKIA" + "A" * 10 + "EXAMPLE",
        file_path="app.py",
        line_number=1,
        secret_type="aws",
    )
    long_value = "AKIA" + "A" * (MAX_REGEX_VALUE_LENGTH + 1) + "EXAMPLE"
    assert not rule.matches(
        value=long_value,
        file_path="app.py",
        line_number=1,
        secret_type="aws",
    )


def test_cli_universal_pattern_config_exits_two(git_repo: GitRepo) -> None:
    """Une config avec un motif universel échoue loud (code 2), jamais exit 0."""
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "blind"
description = "d"
patterns = ["."]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    res = _run("scan", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR


def test_example_substring_myexample_remains_detected() -> None:
    """Une valeur se terminant par 'example' (ex: myexample) reste détectée (Invariant 1)."""
    al = Allowlist.default()
    assert (
        al.evaluate(
            value="myexample",
            file="app.py",
            line=1,
            secret_type="password",
        )
        is None
    )
    assert (
        al.evaluate(
            value="not_an_example_token",
            file="app.py",
            line=2,
            secret_type="password",
        )
        is None
    )
    # Le mot-clé exact ou délimité reste reconnu
    assert (
        al.evaluate(
            value="example",
            file="app.py",
            line=3,
            secret_type="password",
        )
        == "example-placeholders"
    )


def test_fuzz_patterns_and_paths() -> None:
    """Fuzzing défensif sur les motifs de chemins et regex (CWE-22, CWE-20)."""
    # Chemins hostiles, y compris formes Windows et segments ambigus
    for bad_path in [
        "../secret.txt",
        "/etc/passwd",
        "tests/../../etc",
        "C:/Windows/system.ini",
        "C:\\Windows\\system.ini",
        "a\x00b",
        "a\nb",
        "a//b",
        "a/./b",
    ]:
        with pytest.raises(ScanError):
            _validate_path_pattern(bad_path)

    # Glob très répétitif : refusé à la validation (CWE-400). Chaque `*`
    # devient un quantificateur dans fnmatch ; une longue chaîne de `*`
    # croisée à un chemin adverse pourrait ralentir la passe sous les
    # interpréteurs sans groupes atomiques. Plafond MAX_PATH_WILDCARDS.
    long_glob = "*a" * 1024 + "*b"
    with pytest.raises(ScanError):
        _validate_path_pattern(long_glob)
    # À la limite du plafond, le motif reste accepté et jamais bloquant :
    # fuzz adversarial borné en temps (chemin à la limite, peu de `a`).
    edge_glob = "*a" * (MAX_PATH_WILDCARDS - 1) + "*b"
    assert _validate_path_pattern(edge_glob) == edge_glob
    rule = AllowlistRule(
        name="edge-glob",
        description="fuzz",
        paths=(edge_glob,),
        keywords=("dummy",),
    )
    adversarial = "ab" * (MAX_MATCH_PATH_LENGTH // 2) + "Z"
    start = time.monotonic()
    assert not rule.matches(
        value="dummy",
        file_path=adversarial,
        line_number=1,
        secret_type="password",
    )
    # Dépassee le plafond de longueur, fnmatch n'est même pas sollicité
    # (fail-closed : le candidat reste signalé).
    assert not rule.matches(
        value="dummy",
        file_path="a" * (MAX_MATCH_PATH_LENGTH + 1),
        line_number=1,
        secret_type="password",
    )
    assert time.monotonic() - start < 2.0

    # `fnmatch` ne doit jamais transformer un chemin hostile en match.
    fixtures_rule = AllowlistRule(
        name="fixtures-only",
        description="fuzz",
        paths=("tests/**",),
        keywords=("dummy",),
    )
    for hostile_path in (
        "../tests/secret.py",
        "/tests/secret.py",
        "tests\\secret.py",
    ):
        assert not fixtures_rule.matches(
            value="dummy",
            file_path=hostile_path,
            line_number=1,
            secret_type="password",
        )
    # `fnmatch` n'est pas une garde de confinement : un chemin `..` peut
    # correspondre au glob, mais il est refusé en amont par le contrat
    # Finding #14 avant d'atteindre l'allowlist.
    with pytest.raises(ValueError):
        validate_relative_path("tests/../../etc/passwd")

    # Regex hostiles
    for bad_regex in ["a" * 129, "a\x00b", ""]:
        with pytest.raises(ScanError):
            _compile_safe_regex(bad_regex)


def test_contract_scan_report_ignored_count_and_config_hash(git_repo: GitRepo) -> None:
    """Invariants du rapport : ignored_count == len(traces), config_hash déterministe."""
    toml_content = """
[allowlist]
version = "1"

[[allowlist.rules]]
name = "dummy-tokens"
description = "tokens factices"
patterns = ["^AKIA.*DUMMY.*$"]
"""
    git_repo.write("heimdall.toml", toml_content)
    git_repo.write("app.py", 'KEY = "AKIA0123456789DUMMY1"\n')

    report = collect(git_repo.root, staged=False)
    assert report.ignored_count == len(report.traces) == 1
    assert report.config_hash is not None
    assert len(report.config_hash) == 64
    # La trace ne contient que règle, fichier, ligne — JAMAIS la valeur candidate
    trace = report.traces[0]
    assert trace.rule == "dummy-tokens"
    assert trace.file == "app.py"
    assert trace.line == 1
    assert "AKIA" not in str(trace.as_dict())

    # Non-fuite absolue (CWE-200 / Invariant 8) dans toutes les sorties CLI (texte, JSON, stderr)
    raw_secret = "AKIA0123456789DUMMY1"
    res_text = _run("scan", str(git_repo.root))
    assert raw_secret not in res_text.stdout
    assert raw_secret not in res_text.stderr

    res_json = _run("scan", "--json", str(git_repo.root))
    assert raw_secret not in res_json.stdout
    assert raw_secret not in res_json.stderr


def test_keyword_boundary_matches_isolated_and_strict() -> None:
    """Vérifie que les sous-chaînes sans frontières sont strictement rejetées."""
    # Faux-positifs en sous-chaîne sans séparateur : JAMAIS ignorés (Invariant 1)
    for kw in ("fake", "test", "example", "dummy"):
        assert not _keyword_matches_value(kw, f"pro{kw}")
        assert not _keyword_matches_value(kw, f"{kw}abc")

    assert not _keyword_matches_value("test", "latest")
    assert not _keyword_matches_value("example", "myexample")

    # '_' est un caractère de mot : jamais un séparateur, même avec paths
    assert not _keyword_matches_value("fake", "fake_slack_token")
    assert not _keyword_matches_value("dummy", "my_dummy_key")

    # Frontières de mot standards '\b' acceptées
    assert _keyword_matches_value("fake", "fake-token")
    assert _keyword_matches_value("dummy", "dummy")


def test_self_attestation_staged_custom_config_fails_loud(git_repo: GitRepo) -> None:
    """Stager un fichier de config alternatif lève ScanError (code 2, fail-closed)."""
    git_repo.write(
        "custom_al.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "bypass"
description = "d"
keywords = ["AKIA"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("custom_al.toml", "app.py")

    res = _run("scan", "--config", "custom_al.toml", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "auto-attestation" in res.stderr.lower() or "scan impossible" in res.stderr.lower()


def test_self_attestation_staged_scan_worktree_config_dirty_fails_loud(git_repo: GitRepo) -> None:
    """En --staged, un heimdall.toml dirty dans le worktree lève ScanError (code 2)."""
    # 1. Config légitime committée initialement
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "safe-rule"
description = "safe"
keywords = ["dummy"]
""",
    )
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: initial commit with allowlist")

    # 2. L'attaquant altère heimdall.toml dans le worktree SANS le stager
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "malicious-bypass"
description = "bypass"
keywords = ["AKIA"]
""",
    )

    # 3. L'attaquant stage un vrai secret
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("app.py")

    # 4. Le hook (scan --staged) refuse immédiatement en code 2 (fail-closed)
    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "auto-attestation" in res.stderr.lower() or "scan impossible" in res.stderr.lower()


def test_self_attestation_staged_scan_worktree_config_untracked_fails_loud(
    git_repo: GitRepo,
) -> None:
    """En --staged, un heimdall.toml non suivi (untracked) dans le worktree lève ScanError."""
    # heimdall.toml créé mais jamais committé ni stagé
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "untracked-bypass"
description = "bypass"
keywords = ["AKIA"]
""",
    )
    # Stage d'un vrai secret
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("app.py")

    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "auto-attestation" in res.stderr.lower() or "scan impossible" in res.stderr.lower()


def test_staged_config_race_uses_verified_bytes_and_fails_closed(
    git_repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revue (LOW) : substitution entre garde et parsing -> code 2, jamais 0.

    La garde rend les octets vérifiés contre l'index ; le parseur les
    consomme sans relire. Un second contrôle détecte la substitution
    concurrente et refuse loud.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("app.py")

    config_path = git_repo.root / "heimdall.toml"
    clean_bytes = config_path.read_bytes()
    hostile_bytes = b"""
[allowlist]
version = "1"
[[allowlist.rules]]
name = "hostile-bypass"
description = "bypass"
patterns = ["^AKIA.*$"]
"""
    real_read = scan_module._read_worktree_file
    calls = 0

    def read_then_swap(path: Path) -> bytes | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            # La garde lit le contenu propre, puis l'attaquant substitue.
            config_path.write_bytes(hostile_bytes)
            return clean_bytes
        return real_read(path)

    monkeypatch.setattr(scan_module, "_read_worktree_file", read_then_swap)
    res = _run("scan", "--staged", str(git_repo.root))
    assert calls >= 2
    assert res.exit_code == EXIT_ERROR
    assert "auto-attestation" in res.stderr.lower() or "scan impossible" in res.stderr.lower()


def _config_saine() -> str:
    return """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "safe-rule"
description = "safe"
keywords = ["dummy"]
"""


def test_staged_index_v4_with_clean_config_is_not_a_spurious_error(
    git_repo: GitRepo,
) -> None:
    """Revue (LOW) : index v4 + heimdall.toml propre -> verdict normal, jamais 2.

    L'ancien parseur DIRC maison ne comprenait pas la compression de chemins
    de l'index v4 et pouvait refuser un dépôt sain. Le passage par
    `git ls-files -s` couvre v2/v3/v4 sans dette de format.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    git_repo.git("update-index", "--index-version", "4")
    index = (git_repo.root / ".git" / "index").read_bytes()
    assert index[4:8] == (4).to_bytes(4, "big")

    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("app.py")
    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in res.stdout


def test_staged_linked_worktree_with_clean_config_is_not_a_spurious_error(
    git_repo: GitRepo,
    tmp_path: Path,
) -> None:
    """Revue (LOW) : worktree lié (`.git` fichier) + config propre -> 1, pas 2.

    `git rev-parse --git-path index` localise l'index réel du worktree ; la
    garde unique vérifie ensuite ce chemin sans suivre de lien.
    """
    assert GIT is not None
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    worktree = tmp_path / "worktree"
    git_repo.git("worktree", "add", "-q", "--detach", str(worktree))
    (worktree / "app.py").write_text('KEY = "AKIA0123456789ABCDEF"\n', encoding="utf-8")
    subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(worktree), "add", "--", "app.py"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    res = _run("scan", "--staged", str(worktree))
    assert res.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in res.stdout


def test_staged_gitlink_in_index_with_clean_config_is_not_a_spurious_error(
    git_repo: GitRepo,
) -> None:
    """Revue (LOW) : un gitlink (sous-module) dans l'index ne fait pas échouer le scan.

    Le SHA d'un gitlink désigne un commit, pas un blob ; il est ignoré comme
    une suppression. La config propre reste vérifiée par `ls-files -s`.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    head = git_repo.git_output("rev-parse", "HEAD").strip()
    git_repo.git("update-index", "--add", "--cacheinfo", f"160000,{head},vendor/sub")

    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    git_repo.stage("app.py")
    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_FINDINGS
    assert "1 secret(s) détecté(s)" in res.stdout


def test_staged_symlinked_index_fails_closed(git_repo: GitRepo) -> None:
    """Revue (LOW) : `.git/index` symlinké -> code 2, jamais un verdict propre.

    `git ls-files` suivrait le lien sans le dire ; `_checked_index_path`
    passe par `_resolve_root` + `O_NOFOLLOW` et refuse avant lecture.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    git_repo.commit_all("chore: config initiale")
    index = git_repo.root / ".git" / "index"
    cible = git_repo.root / "index-copie"
    cible.write_bytes(index.read_bytes())
    index.unlink()
    index.symlink_to(cible)

    res = _run("scan", "--staged", str(git_repo.root))
    assert res.exit_code == EXIT_ERROR
    assert "scan impossible" in res.stderr.lower() or "auto-attestation" in res.stderr.lower()


def test_index_entry_rejects_invalid_paths(git_repo: GitRepo) -> None:
    """Fuzz : `..`, NUL, absolu et traversée sont refusés avant tout appel git."""
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    access = GitAccess(git_repo.root)
    for chemin in ("../heimdall.toml", "a\x00b", "/etc/passwd", "a/../b"):
        with pytest.raises(ToolFailure):
            access.index_entry(chemin)


@pytest.mark.parametrize(
    ("raw", "attendu"),
    [
        (b"", "none"),
        (b"100644\n", "erreur"),
        (b"100644 " + b"a" * 40 + b" 1\theimdall.toml\x00", "erreur"),
        (b"100644 " + b"g" * 40 + b" 0\theimdall.toml\x00", "erreur"),
        (b"100644 " + b"a" * 40 + b" 0\tautre.toml\x00", "erreur"),
        (b"100644 " + b"a" * 40 + b" 0\theimdall.toml\x00extra\x00", "erreur"),
        (b"160000 " + b"a" * 40 + b" 0\theimdall.toml\x00", "none"),
    ],
)
def test_index_entry_rejects_malformed_plumbing_output(
    git_repo: GitRepo,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    attendu: str,
) -> None:
    """Fuzz : toute sortie `ls-files` ambiguë est fail-closed, jamais True.

    `none` = non suivi / mode non ordinaire (l'appelant refuse le scan) ;
    `erreur` = ``ToolFailure``. Aucun cas ne rend une entrée exploitable.
    """
    git_repo.write("heimdall.toml", _config_saine())
    git_repo.stage("heimdall.toml")
    access = GitAccess(git_repo.root)
    original = GitAccess.execute

    def execute_faux(
        self: GitAccess,
        arguments: object,
        **options: object,
    ) -> subprocess.CompletedProcess[bytes]:
        if tuple(arguments)[:1] == ("ls-files",):
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=raw, stderr=b"")
        return original(self, arguments, **options)

    monkeypatch.setattr(GitAccess, "execute", execute_faux)
    if attendu == "none":
        assert access.index_entry("heimdall.toml") is None
    else:
        with pytest.raises(ToolFailure):
            access.index_entry("heimdall.toml")


@pytest.mark.parametrize("tracked_config", [True, False])
def test_tree_scan_dirty_or_untracked_config_is_advisory_but_ci_and_staged_refuse(
    git_repo: GitRepo,
    tracked_config: bool,
) -> None:
    """Revue (LOW) : le mode arbre local est indicatif, --ci/--staged font foi.

    Un heimdall.toml dirty ou untracked, accompagné d'un secret non stagé,
    peut fausser le verdict local (0 toléré, comportement figé). En CI et en
    --staged, la même configuration est refusée en code 2.
    """
    if tracked_config:
        git_repo.write("heimdall.toml", _config_saine())
        git_repo.stage("heimdall.toml")
        git_repo.commit_all("chore: config initiale")

    # Configuration hostile dirty (ou untracked) + secret non stagé.
    git_repo.write(
        "heimdall.toml",
        """
[allowlist]
version = "1"
[[allowlist.rules]]
name = "hostile-bypass"
description = "bypass"
patterns = ["^AKIA.*$"]
""",
    )
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')

    res_tree = _run("scan", str(git_repo.root))
    assert res_tree.exit_code == EXIT_CLEAN
    assert "Allowlist : 1 finding(s) ignoré(s)" in res_tree.stdout

    # Les deux périmètres opposables refusent la config non propre.
    res_ci = _run("scan", "--ci", str(git_repo.root))
    assert res_ci.exit_code == EXIT_ERROR
    assert "auto-attestation" in res_ci.stderr.lower() or "scan impossible" in res_ci.stderr.lower()

    res_staged = _run("scan", "--staged", str(git_repo.root))
    assert res_staged.exit_code == EXIT_ERROR
    assert (
        "auto-attestation" in res_staged.stderr.lower()
        or "scan impossible" in res_staged.stderr.lower()
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO POSIX uniquement")
@pytest.mark.parametrize("explicit_config", [False, True])
def test_scan_tree_fifo_config_fails_closed_without_blocking(
    git_repo: GitRepo,
    explicit_config: bool,
) -> None:
    """Revue (LOW) : un FIFO à la place de la config -> code 2, jamais un blocage.

    Le sous-processus est borné : sans O_NONBLOCK, le test échoue par timeout
    au lieu de suspendre toute la suite.
    """
    git_repo.write("app.py", 'KEY = "AKIA0123456789ABCDEF"\n')
    if explicit_config:
        os.mkfifo(git_repo.root / "custom.toml")
        arguments = ("scan", "--config", "custom.toml", str(git_repo.root))
    else:
        os.mkfifo(git_repo.root / "heimdall.toml")
        arguments = ("scan", str(git_repo.root))

    completed = _run_cli_process(*arguments)
    assert completed.returncode == EXIT_ERROR
    assert "scan impossible" in completed.stderr.lower()


def test_allowlist_exports_and_default_docstring() -> None:
    """Vérifie l'export des constantes de taille et la documentation de Allowlist.default."""
    assert "MAX_RULE_NAME_LENGTH" in al_module.__all__
    assert "MAX_DESCRIPTION_LENGTH" in al_module.__all__
    assert "MIN_KEYWORD_LENGTH" in al_module.__all__
    assert "MIN_PATTERN_LITERALS" in al_module.__all__
    assert "MAX_REGEX_VALUE_LENGTH" in al_module.__all__
    assert "MAX_PATH_WILDCARDS" in al_module.__all__
    assert "MAX_MATCH_PATH_LENGTH" in al_module.__all__
    assert MAX_RULE_NAME_LENGTH == 64
    assert MAX_DESCRIPTION_LENGTH == 512
    assert MIN_KEYWORD_LENGTH == 3
    assert MIN_PATTERN_LITERALS == 3
    assert MAX_REGEX_VALUE_LENGTH == 256
    assert MAX_PATH_WILDCARDS == 10
    assert MAX_MATCH_PATH_LENGTH == 1024

    # Allowlist.default() fournit les règles standards et possède une docstring explicite
    default_al = Allowlist.default()
    assert not default_al.is_empty()
    assert len(default_al.rules) == 4
    assert "Allowlist par défaut" in (Allowlist.default.__doc__ or "")
