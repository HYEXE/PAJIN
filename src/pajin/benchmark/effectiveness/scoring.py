"""Response-level confusion matrices and complete-coordinate comparisons."""

from __future__ import annotations

from collections.abc import Sequence
from statistics import fmean, pstdev

from pajin.benchmark.effectiveness.suite import FrozenModel


class ScoredResponse(FrozenModel):
    detected: bool
    exposed: bool


def ratio(numerator: int, denominator: int) -> dict[str, object]:
    return {
        "value": numerator / denominator if denominator else None,
        "numerator": numerator,
        "denominator": denominator,
        "unavailable_reason": None if denominator else "empty-denominator",
    }


def confusion(rows: Sequence[ScoredResponse]) -> dict[str, object]:
    tp = sum(r.detected and r.exposed for r in rows)
    tn = sum(not r.detected and not r.exposed for r in rows)
    fp = sum(r.detected and not r.exposed for r in rows)
    fn = sum(not r.detected and r.exposed for r in rows)
    return {
        "scored": len(rows),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
        "oracle_exposure_rate": ratio(tp + fn, len(rows)),
    }


def distribution(values: Sequence[float]) -> dict[str, object]:
    if not values:
        return {
            "n": 0,
            "mean": None,
            "population_stddev": None,
            "min": None,
            "max": None,
            "median": None,
            "p95_nearest_rank": None,
        }
    ordered = sorted(values)
    n = len(ordered)
    median = (ordered[(n - 1) // 2] + ordered[n // 2]) / 2
    return {
        "n": n,
        "mean": fmean(ordered),
        "population_stddev": pstdev(ordered),
        "min": ordered[0],
        "max": ordered[-1],
        "median": median,
        "p95_nearest_rank": ordered[(95 * n + 99) // 100 - 1],
    }


def repetition_distributions(repetitions: Sequence[Sequence[ScoredResponse]]) -> dict[str, object]:
    metrics = [confusion(rows) for rows in repetitions]
    result: dict[str, object] = {}
    for name in (
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "oracle_exposure_rate",
    ):
        values = []
        for metric in metrics:
            entry = metric[name]
            if isinstance(entry, dict) and isinstance(entry.get("value"), float):
                values.append(entry["value"])
        result[name] = {
            **distribution(values),
            "unavailable_repetitions": len(metrics) - len(values),
        }
    return result
