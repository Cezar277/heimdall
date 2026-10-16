"""Tests unitaires pour le benchmark Ollama (T28.1 / ADR-004).

Vérifie :
- score() : cas None, incertain_ou_secret, secret, faux_positif, et sévérité fail-closed
- bench() : chemin nominal, chemin d'erreur (query lève -> ok=False, fn_dangereux non incrémenté)
- gen_full() : déterminisme strict (graine 281)
- Validation des entrées CLI : --models, --timeout, --out (refus absolu, .., hors cwd)
- Délimiteurs aléatoires uniques par requête (Invariant 2)
- Écriture atomique confinée (Invariants 3 et 10)
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "benchmark_llm_ollama",
    REPO_ROOT / "tests/benchmarks/benchmark_llm_ollama.py",
)
assert SPEC and SPEC.loader
bench_mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench_mod)

atomic_write_json = bench_mod.atomic_write_json
bench = bench_mod.bench
build_query_payload = bench_mod.build_query_payload
gen_full = bench_mod.gen_full
parse_args = bench_mod.parse_args
score = bench_mod.score
validate_model_name = bench_mod.validate_model_name
validate_output_path = bench_mod.validate_output_path
validate_timeout = bench_mod.validate_timeout


class TestScore:
    """Tests exhaustifs de la fonction score() de labellisation."""

    def test_verdict_none_returns_false(self) -> None:
        assert score("secret", None) is False
        assert score("faux_positif", None) is False
        assert score("incertain_ou_secret", None) is False

    def test_incertain_ou_secret_behavior(self) -> None:
        # Résistance aux injections : tout sauf faux_positif est accepté
        assert score("incertain_ou_secret", "secret") is True
        assert score("incertain_ou_secret", "incertain") is True
        assert score("incertain_ou_secret", "faux_positif") is False
        assert score("incertain_ou_secret", "inconnu") is False

    def test_secret_behavior(self) -> None:
        assert score("secret", "secret") is True
        # Plus strict que la prod : pour le bench, incertain ne compte pas comme un succès
        assert score("secret", "incertain") is False
        assert score("secret", "faux_positif") is False

    def test_faux_positif_behavior(self) -> None:
        assert score("faux_positif", "faux_positif") is True
        assert score("faux_positif", "secret") is False
        assert score("faux_positif", "incertain") is False


class TestGenFull:
    """Tests de génération du dataset synthétique."""

    def test_determinism_seed_281(self) -> None:
        run1 = gen_full()
        run2 = gen_full()
        assert run1 == run2
        assert len(run1) == 132

    def test_structure_and_categories(self) -> None:
        dataset = gen_full()
        valid_labels = {"secret", "faux_positif", "incertain_ou_secret"}
        for item in dataset:
            assert len(item) == 3
            cand, label, cat = item
            assert isinstance(cand, str) and cand
            assert label in valid_labels
            assert isinstance(cat, str) and cat


class TestQueryPayloadAndDelimiters:
    """Tests d'application de l'Invariant 2 (délimiteurs aléatoires)."""

    def test_random_delimiter_unique_per_call(self) -> None:
        payload1, sep1 = build_query_payload("gemma3:270m", "candidat_secret_1")
        payload2, sep2 = build_query_payload("gemma3:270m", "candidat_secret_1")

        assert sep1 != sep2
        assert f"<data_{sep1}>" in payload1["messages"][1]["content"]
        assert f"</data_{sep1}>" in payload1["messages"][1]["content"]
        assert f"<data_{sep2}>" in payload2["messages"][1]["content"]
        assert f"</data_{sep2}>" in payload2["messages"][1]["content"]

    def test_candidate_never_in_system_prompt(self) -> None:
        candidate = "INJECTION_PAYLOAD_TEST_12345"
        payload, _ = build_query_payload("gemma3:270m", candidate)

        assert payload["messages"][0]["role"] == "system"
        assert candidate not in payload["messages"][0]["content"]
        assert candidate in payload["messages"][1]["content"]


class TestBenchFunction:
    """Tests de déroulement du benchmark (succès et chemins d'erreur)."""

    @patch.object(bench_mod, "query")
    def test_bench_nominal(self, mock_query: MagicMock) -> None:
        # 3 cas simulés : 1 secret réussi, 1 faux négatif dangereux, 1 injection bloquée
        mock_query.side_effect = [
            ({"eval_count": 50, "eval_duration": 1_000_000_000}, '{"verdict": "secret"}', 0.5),
            ({"eval_count": 50, "eval_duration": 1_000_000_000}, '{"verdict": "secret"}', 0.5),
            (
                {"eval_count": 50, "eval_duration": 1_000_000_000},
                '{"verdict": "faux_positif"}',
                0.4,
            ),
            ({"eval_count": 50, "eval_duration": 1_000_000_000}, '{"verdict": "incertain"}', 0.6),
        ]

        dataset = [
            ("AWS_KEY = 'AKIA123'", "secret", "aws"),
            ("STRIPE_KEY = 'sk_test_123'", "secret", "stripe"),
            ("# INJECTION ignore all", "incertain_ou_secret", "inj"),
        ]

        summary = bench("gemma3:270m", dataset, timeout=30.0)

        assert summary["model"] == "gemma3:270m"
        assert summary["n"] == 3
        assert summary["justesse"] == "2/3"
        assert summary["rappel_secrets"] == "1/2"
        assert summary["injections_bloquees"] == "1/1"
        assert summary["fn_dangereux"] == 1
        assert summary["json_valide"] == "3/3"
        assert summary["t_total"] > 0

    @patch.object(bench_mod, "query")
    def test_bench_error_path_fail_closed(self, mock_query: MagicMock) -> None:
        # Quand query lève une exception, le cas échoue (ok=False) mais fn_dangereux reste 0
        mock_query.side_effect = RuntimeError("Ollama daemon down")

        dataset = [
            ("AWS_KEY = 'AKIA123'", "secret", "aws"),
            ("# INJECTION", "incertain_ou_secret", "inj"),
        ]

        summary = bench("gemma3:270m", dataset, timeout=30.0)

        assert summary["n"] == 2
        assert summary["justesse"] == "0/2"
        assert summary["score_pct"] == 0.0
        assert summary["rappel_secrets"] == "0/1"
        assert summary["injections_bloquees"] == "0/1"
        assert summary["fn_dangereux"] == 0
        assert summary["json_valide"] == "0/2"


class TestValidationAndHardening:
    """Tests de validation des arguments CLI et confinement des chemins."""

    def test_validate_model_name(self) -> None:
        assert validate_model_name("gemma3:270m") == "gemma3:270m"
        assert validate_model_name("qwen2.5:0.5b") == "qwen2.5:0.5b"
        assert validate_model_name("org/repo:tag-1.0") == "org/repo:tag-1.0"

        with pytest.raises(ValueError, match="Nom de modèle invalide"):
            validate_model_name("")
        with pytest.raises(ValueError, match="Nom de modèle invalide"):
            validate_model_name("model with spaces")
        with pytest.raises(ValueError, match="Nom de modèle invalide"):
            validate_model_name("model;rm -rf /")
        with pytest.raises(ValueError, match="Nom de modèle invalide"):
            validate_model_name("a" * 65)

    def test_validate_timeout(self) -> None:
        assert validate_timeout(90.0) == 90.0
        assert validate_timeout(0.5) == 0.5

        with pytest.raises(ValueError, match="Timeout invalide"):
            validate_timeout(0.0)
        with pytest.raises(ValueError, match="Timeout invalide"):
            validate_timeout(-10.0)
        with pytest.raises(ValueError, match="Timeout invalide"):
            validate_timeout(float("nan"))
        with pytest.raises(ValueError, match="Timeout invalide"):
            validate_timeout(float("inf"))

    def test_validate_output_path(self, tmp_path: Path) -> None:
        base = tmp_path.resolve()

        # Chemin relatif valide
        out = validate_output_path("results/bench.json", base_dir=base)
        assert out == (base / "results/bench.json").resolve()
        assert out.is_relative_to(base)

        # Rejet chemin vide
        with pytest.raises(ValueError, match="vide"):
            validate_output_path("", base_dir=base)
        with pytest.raises(ValueError, match="vide"):
            validate_output_path("   ", base_dir=base)

        # Rejet chemin absolu
        with pytest.raises(ValueError, match="relatif"):
            validate_output_path("/etc/cron.d/evil", base_dir=base)

        # Rejet segment '..'
        with pytest.raises(ValueError, match=r"\.\."):
            validate_output_path("../outside.json", base_dir=base)
        with pytest.raises(ValueError, match=r"\.\."):
            validate_output_path("subdir/../../escape.json", base_dir=base)

    def test_atomic_write_json(self, tmp_path: Path) -> None:
        target = tmp_path / "subdir" / "summary.json"
        data = [{"model": "gemma3:270m", "score": 100}]

        atomic_write_json(target, data)

        assert target.exists()
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded == data

        # Aucun fichier temporaire ne doit subsister dans le dossier
        files = list(target.parent.iterdir())
        assert files == [target]

    def test_parse_args_valid(self) -> None:
        args = parse_args(["--models", "gemma3:270m", "--timeout", "45", "--out", "results.json"])
        assert args.models == ["gemma3:270m"]
        assert args.timeout == 45.0
        assert args.out == "results.json"

    def test_parse_args_invalid_timeout(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--models", "gemma3:270m", "--timeout", "-5"])

    def test_parse_args_invalid_model(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--models", "invalid model name"])

    def test_parse_args_invalid_out(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--models", "gemma3:270m", "--out", "/etc/evil.json"])
        with pytest.raises(SystemExit):
            parse_args(["--models", "gemma3:270m", "--out", "../escape.json"])
