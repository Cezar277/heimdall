"""Preuve T28.2 (#80) : « sortie JSON valide sur 20 candidats » (vrai Ollama).

Le jeu de 20 candidats est celui du ticket T21 (factices synthétiques,
``CASES_20`` du bench T28.1) : chaque extrait est d'abord masqué par le même
module que le serveur MCP (le flux produit ne montre jamais une valeur au
modèle), puis qualifié par ``heimdall.llm.qualify`` — client Ollama épinglé
boucle locale, modèle ``gemma3:270m`` (ADR-004).

Skippée si Ollama n'écoute pas sur la boucle locale ou si le modèle n'est
pas téléchargé : aucun échec pour une machine sans Ollama (la sonde n'appelle
que 127.0.0.1), mais aucune preuve n'est inventée non plus. La justesse du
tri (rappel secrets / injections) est le périmètre du bench T28.1 et des
tickets #38/#28.4 ; ici on prouve le contrat de sortie du ticket.

Lancer pour capturer la preuve (Ollama local requis) :

    .venv/bin/python -m pytest tests/test_llm_qualify_ollama.py -v -s
"""

from __future__ import annotations

import importlib.util
from collections import Counter
from pathlib import Path

import pytest

from heimdall.llm.qualify import DEFAULT_MODEL, QualifyError, qualify
from heimdall.mcp import masking

REPO_ROOT = Path(__file__).resolve().parents[1]
_BENCH_SPEC = importlib.util.spec_from_file_location(
    "benchmark_llm_ollama_for_t282",
    REPO_ROOT / "tests" / "benchmarks" / "benchmark_llm_ollama.py",
)
assert _BENCH_SPEC is not None and _BENCH_SPEC.loader is not None
_bench = importlib.util.module_from_spec(_BENCH_SPEC)
_BENCH_SPEC.loader.exec_module(_bench)
CASES_20: list[tuple[str, str, str]] = _bench.CASES_20

VERDICTS = ("secret", "faux_positif", "incertain")


def _ollama_ready() -> bool:
    """Sonde locale : serveur Ollama joignable + modèle admissible présent.

    Client dédié, épinglé boucle locale et borné à 2 s : la collection ne
    dépend jamais d'une machine distante ni d'un environnement proxy.
    """
    try:
        # Import paresseux : sans SDK ollama (env minimal), la sonde répond
        # False et la preuve est ignorée au lieu d'échouer à la collecte.
        import ollama  # noqa: PLC0415 - sonde optionnelle, dépendance déclarée en dev
    except ImportError:
        return False

    try:
        client = ollama.Client(
            host="http://127.0.0.1:11434",
            trust_env=False,
            follow_redirects=False,
            timeout=2.0,
        )
        models = client.list().models
    except Exception:
        return False
    names = {
        name
        for model in models
        for name in (getattr(model, "model", None), getattr(model, "name", None))
        if isinstance(name, str)
    }
    return DEFAULT_MODEL in names


@pytest.mark.skipif(
    not _ollama_ready(),
    reason="Ollama local (boucle locale) ou gemma3:270m absent : preuve non jouable",
)
class TestTwentyCandidates:
    """Le critère d'acceptation du ticket, joué sur les 20 cas T21 masqués."""

    def test_twenty_masked_candidates_yield_valid_json(self) -> None:
        assert len(CASES_20) == 20
        counter: Counter[str] = Counter()
        for index, (snippet, expected, category) in enumerate(CASES_20, start=1):
            masked, _ = masking.mask_text(snippet)
            try:
                result = qualify(masked)
            except QualifyError as error:
                pytest.fail(
                    f"candidat {index}/20 ({category}) : sortie non exploitable "
                    f"(code {error.code})"
                )
            assert isinstance(result, dict)
            verdict = result.get("verdict")
            assert verdict in VERDICTS, f"candidat {index}/20 ({category}) : verdict hors enum"
            confidence = result.get("confidence")
            assert isinstance(confidence, (int, float)), f"candidat {index}/20 ({category})"
            assert 0.0 <= float(confidence) <= 1.0, f"candidat {index}/20 ({category})"
            counter[verdict] += 1
            # Trace de preuve (masquée, jamais la valeur) pour la PR.
            print(
                f"[{index:02d}/20] {category:12} attendu={expected:20} "
                f"verdict={verdict:11} confiance={float(confidence):.2f}"
            )
        print(f"\n20/20 réponses JSON valides, verdicts : {dict(counter)}")
