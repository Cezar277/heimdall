"""T21: oracle indépendant, mesure et acceptation avant le scanner T22."""

import ast
import base64
import builtins
import json
import re
from pathlib import Path

import pytest
from measure_trap import main
from support.trap_corpus import build_corpus, load_expected, measure, scan_corpus


def test_corpus_is_reproducible_and_manifest_points_to_cases(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    build_corpus(first)
    build_corpus(second)
    expected = load_expected()
    assert len(expected) == 34
    assert len({case["id"] for case in expected}) == len(expected)
    assert len({(case["file"], case["line"]) for case in expected}) == len(expected)
    for case in expected:
        assert type(case["line"]) is int and case["line"] > 0
        assert type(case["leak"]) is bool
        assert (case["leak"], case["expected_status"]) == {
            "plain": (True, "detecte"),
            "negative": (False, "non_signale"),
            "obfuscated": (True, "limite_connue"),
        }[case["group"]]
        path = first / case["file"]
        assert path.read_bytes() == (second / case["file"]).read_bytes()
        assert case["id"] in path.read_text().splitlines()[case["line"] - 1]
    assert {c["type"] for c in expected if c["group"] == "plain"} == {
        "aws",
        "stripe",
        "jwt",
        "pat",
        "pem",
    }


def test_metrics_match_locations_deduplicate_and_count_unexpected_alerts():
    cases = [
        {"file": "a.py", "line": 1, "leak": True, "group": "plain"},
        {"file": "a.py", "line": 2, "leak": True, "group": "plain"},
        {"file": "b.js", "line": 1, "leak": False, "group": "negative"},
        {"file": "c.py", "line": 1, "leak": True, "group": "obfuscated"},
    ]
    findings = [
        {"file": "a.py", "line": 1},
        {"file": "a.py", "line": 1},
        {"file": "b.js", "line": 1},
        {"file": "a.py", "line": 99},
    ]
    result = measure(cases, findings)
    assert result["core"] == {"tp": 1, "fp": 2, "fn": 1, "precision": 1 / 3, "recall": 0.5}
    assert result["all"]["fn"] == 2
    assert result["known_limits_missed"] == [["c.py", 1]]
    assert measure(cases, findings + [{"file": "c.py", "line": 1}])["all"]["tp"] == 2


def test_empty_predictions_do_not_claim_perfect_precision():
    result = measure([{"file": "a", "line": 1, "leak": True, "group": "plain"}], [])
    assert result["core"]["precision"] == 0
    assert result["core"]["recall"] == 0
    assert measure([], [])["core"]["recall"] == 0


def test_scanner_errors_are_not_clean_results(tmp_path, monkeypatch):
    def unavailable(path):
        raise RuntimeError("scan incomplet")

    monkeypatch.setattr("support.trap_corpus.find_candidates", unavailable)
    with pytest.raises(RuntimeError, match="scan incomplet"):
        scan_corpus(tmp_path)


@pytest.mark.parametrize("findings", [None, [{}]])
def test_invalid_findings_are_rejected(tmp_path, monkeypatch, findings):
    monkeypatch.setattr("support.trap_corpus.find_candidates", lambda path: findings)
    with pytest.raises(ValueError):
        scan_corpus(tmp_path)


@pytest.mark.parametrize("path", ["../escape", "/etc/passwd", r"a\b"])
def test_invalid_finding_paths_are_rejected(tmp_path, monkeypatch, path):
    finding = {
        "file": "python/samples.py",
        "line": 1,
        "type": "aws",
        "entropy": 4.0,
        "snippet_hash": "a" * 64,
        "status": "detecte",
        "source": "regex",
    }
    monkeypatch.setattr("support.trap_corpus.find_candidates", lambda root: [finding])
    # Le témoin est conforme : le rejet suivant doit venir du chemin seul.
    assert scan_corpus(tmp_path / "valid")["core"]["tp"] == 1
    finding["file"] = path
    with pytest.raises(ValueError, match="Finding non conforme"):
        scan_corpus(tmp_path / "invalid")


def test_real_adapter_uses_scanner_results_not_expected(tmp_path, monkeypatch):
    monkeypatch.setattr("support.trap_corpus.find_candidates", lambda path: [])
    report = scan_corpus(tmp_path)
    assert report["core"]["fn"] == 10
    assert report["all"]["fn"] == 16
    assert report["core"]["recall"] == 0


def test_generation_refuses_to_overwrite_files(tmp_path):
    (tmp_path / "existing").write_text("keep")
    with pytest.raises(ValueError, match="vide"):
        build_corpus(tmp_path)
    assert (tmp_path / "existing").read_text() == "keep"


def test_generation_refuses_source_outside_fixture_root(tmp_path, monkeypatch):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    outside = tmp_path / "outside.tmpl"
    outside.write_text("PRIVATE_FIXTURE_DO_NOT_COPY")
    monkeypatch.setattr("support.trap_corpus.FIXTURES", fixtures)
    monkeypatch.setattr(Path, "rglob", lambda root, pattern: [fixtures / ".." / outside.name])
    with pytest.raises(ValueError, match="Gabarit hors corpus"):
        build_corpus(tmp_path / "generated")
    assert not (tmp_path / "generated").exists()


def _symlink_or_skip(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Création de liens symboliques non autorisée sous Windows")
        raise


def test_generation_refuses_template_symlink(tmp_path, monkeypatch):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("PRIVATE_FIXTURE_DO_NOT_COPY")
    _symlink_or_skip(fixtures / "leak.py.tmpl", outside)
    monkeypatch.setattr("support.trap_corpus.FIXTURES", fixtures)
    with pytest.raises(ValueError, match="lien symbolique interdit"):
        build_corpus(tmp_path / "generated")
    assert not (tmp_path / "generated").exists()


def test_generation_refuses_target_symlink_escape(tmp_path, monkeypatch):
    fixtures = tmp_path / "fixtures"
    (fixtures / "python").mkdir(parents=True)
    template = fixtures / "python" / "sample.py.tmpl"
    template.write_text("PUBLIC_FIXTURE")
    destination = tmp_path / "generated"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    # Reproduit l'apparition d'un lien après le contrôle du dossier vide.
    def templates(root, pattern):
        _symlink_or_skip(destination / "python", outside, directory=True)
        return [template]

    monkeypatch.setattr("support.trap_corpus.FIXTURES", fixtures)
    monkeypatch.setattr(Path, "rglob", templates)
    with pytest.raises(ValueError, match="hors corpus temporaire"):
        build_corpus(destination)
    assert not list(outside.iterdir())


@pytest.mark.xfail(
    raises=NotImplementedError, reason="Scanner T22 non livré; aucune métrique inventée"
)
def test_scanner_precision_and_recall(tmp_path):
    report = scan_corpus(tmp_path)
    print(json.dumps(report, indent=2))
    assert report["core"]["precision"] >= 0.9
    assert report["core"]["recall"] >= 0.9


def test_generated_python_is_valid_source(tmp_path):
    build_corpus(tmp_path)
    for path in tmp_path.rglob("*.py"):
        compile(path.read_text(), str(path), "exec")


def test_generated_formats_and_obfuscations(tmp_path):
    build_corpus(tmp_path)
    tree = ast.parse((tmp_path / "python" / "samples.py").read_text())
    values = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
    }
    assert re.fullmatch(r"AKIA[A-Z0-9]{16}", values["AWS"])
    assert re.fullmatch(r"sk_live_[A-Za-z0-9]{24}", values["STRIPE"])
    assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", values["PAT"])
    assert len(values["JWT"].split(".")) == 3
    assert values["PEM"].startswith("-----BEGIN RSA PRIVATE KEY-----\n")
    assert base64.b64decode(values["ENCODED"]).decode() == values["STRIPE"]
    assert values["part_a"] + values["part_b"] == values["STRIPE"]


@pytest.mark.parametrize(
    "precision,recall,code", [(1, 1, 0), (0.9, 0.9, 0), (0.89, 1, 1), (1, 0.89, 1)]
)
def test_measure_command_thresholds(monkeypatch, capsys, precision, recall, code):
    monkeypatch.setattr(
        "support.trap_corpus.scan_corpus",
        lambda path: {"core": {"precision": precision, "recall": recall}},
    )
    assert main() == code
    assert json.loads(capsys.readouterr().out)["core"]["recall"] == recall


def test_measure_command_reports_unavailable(monkeypatch, capsys):
    def unavailable(path):
        raise NotImplementedError

    monkeypatch.setattr("support.trap_corpus.scan_corpus", unavailable)
    assert main() == 2
    assert "indisponibles" in capsys.readouterr().out


def test_measure_command_import_error_returns_two(monkeypatch, capsys):
    original_import = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "support.trap_corpus":
            raise ImportError("PRIVATE_IMPORT_DO_NOT_PRINT")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    assert main() == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "erreur interne" in output.err
    assert "PRIVATE_IMPORT_DO_NOT_PRINT" not in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("error", [ValueError, OSError, RuntimeError])
def test_measure_command_internal_errors_return_two(monkeypatch, capsys, error):
    def broken(path):
        raise error("PRIVATE_CANARY_DO_NOT_PRINT")

    monkeypatch.setattr("support.trap_corpus.scan_corpus", broken)
    assert main() == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "erreur interne" in output.err
    assert "PRIVATE_CANARY_DO_NOT_PRINT" not in output.err


def test_measure_command_temporary_directory_failure_returns_two(monkeypatch, capsys):
    def broken(**kwargs):
        raise OSError("PRIVATE_PATH_DO_NOT_PRINT")

    monkeypatch.setattr("measure_trap.tempfile.TemporaryDirectory", broken)
    assert main() == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "erreur interne" in output.err
    assert "PRIVATE_PATH_DO_NOT_PRINT" not in output.err


def test_only_templates_are_versioned():
    root = Path(__file__).parent / "fixtures" / "trap_repo"
    assert not list(root.rglob("*.py"))
    assert not list(root.rglob("*.js"))
