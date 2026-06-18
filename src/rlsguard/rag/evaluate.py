"""Offline evaluation harness for the retrieval layer.

A RAG system is only as trustworthy as its retriever, and "it feels about right"
is not a metric. This module runs a labeled set of queries (``eval_queries.json``)
through :func:`rlsguard.rag.retriever.retrieve` and reports standard information-
retrieval metrics, so a change to the corpus or the ranking can be *proven* not to
regress quality rather than eyeballed.

Metrics, all averaged over the query set at a cutoff ``k``:

* **hit rate** - fraction of queries with at least one relevant doc in the top-k
  (a.k.a. success@k). The headline "did we find anything useful" number.
* **recall@k** - fraction of a query's relevant docs that appear in the top-k.
* **precision@k** - fraction of the returned docs that are relevant.
* **MRR** - mean reciprocal rank of the first relevant doc; rewards putting the
  right answer first.

Everything here is pure-Python and offline - no API key, no network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rlsguard.rag.retriever import retrieve

_DATASET_PATH = Path(__file__).parent / "eval_queries.json"


@dataclass(frozen=True)
class EvalCase:
    """One labeled query and the set of docs that genuinely answer it."""

    id: str
    query: str
    rule_id: str | None
    relevant: frozenset[str]


@dataclass(frozen=True)
class CaseResult:
    """The retriever's outcome on a single :class:`EvalCase`."""

    case: EvalCase
    retrieved: tuple[str, ...]
    hit: bool
    recall: float
    precision: float
    reciprocal_rank: float


@dataclass(frozen=True)
class EvalReport:
    """Aggregate metrics plus per-case detail for one evaluation run."""

    k: int
    results: tuple[CaseResult, ...]

    @property
    def n(self) -> int:
        return len(self.results)

    @property
    def hit_rate(self) -> float:
        return _mean(1.0 if r.hit else 0.0 for r in self.results)

    @property
    def mean_recall(self) -> float:
        return _mean(r.recall for r in self.results)

    @property
    def mean_precision(self) -> float:
        return _mean(r.precision for r in self.results)

    @property
    def mrr(self) -> float:
        return _mean(r.reciprocal_rank for r in self.results)

    def summary(self) -> dict[str, float | int]:
        """JSON-friendly headline metrics."""
        return {
            "k": self.k,
            "n": self.n,
            "hit_rate": round(self.hit_rate, 4),
            "recall": round(self.mean_recall, 4),
            "precision": round(self.mean_precision, 4),
            "mrr": round(self.mrr, 4),
        }


def _mean(values) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0


def _reciprocal_rank(retrieved: tuple[str, ...], relevant: frozenset[str]) -> float:
    for rank, doc_id in enumerate(retrieved, start=1):
        if doc_id in relevant:
            return 1.0 / rank
    return 0.0


def _recall(retrieved: tuple[str, ...], relevant: frozenset[str]) -> float:
    if not relevant:
        return 0.0
    hits = sum(1 for d in retrieved if d in relevant)
    return hits / len(relevant)


def _precision(retrieved: tuple[str, ...], relevant: frozenset[str]) -> float:
    if not retrieved:
        return 0.0
    hits = sum(1 for d in retrieved if d in relevant)
    return hits / len(retrieved)


@lru_cache(maxsize=1)
def load_dataset() -> tuple[EvalCase, ...]:
    """Load and cache the labeled evaluation queries."""
    raw = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))
    return tuple(
        EvalCase(
            id=c["id"],
            query=c["query"],
            rule_id=c.get("rule_id"),
            relevant=frozenset(c["relevant"]),
        )
        for c in raw
    )


def evaluate(k: int = 2, cases: tuple[EvalCase, ...] | None = None) -> EvalReport:
    """Run the retriever over ``cases`` (default: the bundled set) at cutoff ``k``."""
    cases = cases if cases is not None else load_dataset()
    results: list[CaseResult] = []
    for case in cases:
        docs = retrieve(case.query, rule_id=case.rule_id, k=k)
        retrieved = tuple(d.id for d in docs)
        results.append(
            CaseResult(
                case=case,
                retrieved=retrieved,
                hit=any(d in case.relevant for d in retrieved),
                recall=_recall(retrieved, case.relevant),
                precision=_precision(retrieved, case.relevant),
                reciprocal_rank=_reciprocal_rank(retrieved, case.relevant),
            )
        )
    return EvalReport(k=k, results=tuple(results))
