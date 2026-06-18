"""Tests for the RAG evaluation harness (offline retrieval-quality metrics)."""

import json

from typer.testing import CliRunner

from rlsguard.cli.main import app
from rlsguard.rag.corpus import load_corpus
from rlsguard.rag.evaluate import (
    CaseResult,
    EvalCase,
    _precision,
    _recall,
    _reciprocal_rank,
    evaluate,
    load_dataset,
)
from rlsguard.rules.rule_help import RULE_HELP


def _corpus_ids() -> set[str]:
    return {c.id for c in load_corpus()}


def _docs_tagged(rule_id: str) -> set[str]:
    return {c.id for c in load_corpus() if rule_id in c.rule_ids}


# --- dataset integrity -----------------------------------------------------


def test_dataset_is_well_formed():
    dataset = load_dataset()
    assert dataset
    corpus_ids = _corpus_ids()
    seen_ids: set[str] = set()

    for case in dataset:
        assert case.id not in seen_ids, f"duplicate case id {case.id}"
        seen_ids.add(case.id)
        assert case.query.strip()
        assert case.relevant, f"{case.id} has no relevant docs"
        # Every gold doc id must exist in the corpus.
        unknown = case.relevant - corpus_ids
        assert not unknown, f"{case.id} references unknown docs {unknown}"
        # Rule ids, when present, must be real rules.
        if case.rule_id is not None:
            assert case.rule_id in RULE_HELP, f"{case.id} has unknown rule {case.rule_id}"


def test_rule_scoped_labels_cover_all_tagged_docs():
    # Labeling policy: for a rule-scoped query, every doc tagged with that rule
    # counts as relevant. This keeps the rule-id boost meaningful and makes the
    # top-1 guarantee below well-defined.
    for case in load_dataset():
        if case.rule_id is None:
            continue
        tagged = _docs_tagged(case.rule_id)
        assert tagged <= case.relevant, (
            f"{case.id}: tagged docs {tagged - case.relevant} not marked relevant"
        )


# --- metric helpers --------------------------------------------------------


def test_metric_helpers_on_known_inputs():
    relevant = frozenset({"a", "b"})
    assert _reciprocal_rank(("x", "a", "b"), relevant) == 0.5
    assert _reciprocal_rank(("a", "x"), relevant) == 1.0
    assert _reciprocal_rank(("x", "y"), relevant) == 0.0

    assert _recall(("a", "b"), relevant) == 1.0
    assert _recall(("a", "x"), relevant) == 0.5
    assert _recall((), relevant) == 0.0

    assert _precision(("a", "b"), relevant) == 1.0
    assert _precision(("a", "x"), relevant) == 0.5
    assert _precision((), relevant) == 0.0


def test_evaluate_on_synthetic_cases():
    # A perfect retrieval and a total miss, so aggregates are predictable.
    cases = (
        EvalCase("perfect", "table without rls", "SUPA-RLS-001", frozenset({"rls-basics"})),
        EvalCase("miss", "zzzzz nonsense qqqqq", None, frozenset({"does-not-exist"})),
    )
    report = evaluate(k=2, cases=cases)
    assert report.n == 2
    by_id = {r.case.id: r for r in report.results}
    assert isinstance(by_id["perfect"], CaseResult)
    assert by_id["perfect"].hit and by_id["perfect"].reciprocal_rank == 1.0
    assert not by_id["miss"].hit and by_id["miss"].reciprocal_rank == 0.0
    assert report.hit_rate == 0.5


# --- retrieval-quality regression guard ------------------------------------


def test_retrieval_quality_meets_bar():
    report = evaluate(k=2)
    summary = report.summary()
    # Measured baseline: hit 1.00, recall 0.94, precision 0.81, MRR 1.00.
    # Bars sit below baseline with margin, so they guard against regressions
    # without being brittle to small, intentional corpus edits.
    assert summary["hit_rate"] == 1.0, summary
    assert summary["mrr"] >= 0.90, summary
    assert summary["recall"] >= 0.85, summary
    assert summary["precision"] >= 0.70, summary


def test_rule_scoped_queries_rank_a_relevant_doc_first():
    # When a query carries a rule id, the rule-tagged (and therefore relevant)
    # doc should be boosted to rank 1 every time.
    report = evaluate(k=2)
    for r in report.results:
        if r.case.rule_id is not None:
            assert r.reciprocal_rank == 1.0, f"{r.case.id} -> {r.retrieved}"


def test_lexical_only_queries_still_find_a_relevant_doc():
    # Queries with no rule id rely purely on BM25; they must still hit.
    report = evaluate(k=2)
    lexical = [r for r in report.results if r.case.rule_id is None]
    assert lexical
    assert all(r.hit for r in lexical)


# --- CLI -------------------------------------------------------------------


def test_rag_eval_cli_emits_json():
    result = CliRunner().invoke(app, ["rag-eval", "--json", "--k", "2"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["k"] == 2
    assert payload["n"] == len(load_dataset())
    assert payload["hit_rate"] == 1.0
    assert set(payload) >= {"hit_rate", "recall", "precision", "mrr"}
