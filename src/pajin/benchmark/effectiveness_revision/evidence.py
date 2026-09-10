"""Recompute both detectors against the same verified fresh responses and fixed oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

from pydantic import Field

from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    RunRecord,
    RunReference,
    read_artifact,
    require_output_outside_runs,
    require_unique_lifecycles,
    verify_retained_sources,
    verify_run,
)
from pajin.benchmark.effectiveness.scoring import (
    ScoredResponse,
    confusion,
    distribution,
    repetition_distributions,
)
from pajin.benchmark.effectiveness.suite import FrozenModel, oracle_verdict
from pajin.benchmark.effectiveness_revision.plan import ComparisonPlan, comparison_pins
from pajin.benchmark.effectiveness_revision.scoring import (
    DetectorInput,
    PairedDetection,
    verify_pair,
)


class ComparisonIndex(FrozenModel):
    version: Literal["effect-003-v1"] = "effect-003-v1"
    source: EvaluationIndex
    detections: tuple[PairedDetection | None, ...] = Field(max_length=384)


def _improvement(before: dict[str, object], after: dict[str, object]) -> bool:
    values = [
        (cast(dict[str, object], item[key])["value"])
        for key in ("f1", "precision", "recall")
        for item in (before, after)
    ]
    if not all(isinstance(value, float) for value in values):
        return False
    b_f1, a_f1, b_precision, a_precision, b_recall, a_recall = cast(list[float], values)
    return a_f1 > b_f1 and a_precision >= b_precision and a_recall >= b_recall


def recompute_comparison(root: Path, reference: RunReference) -> dict[str, object]:
    if reference.campaign != "effect-001-report":
        raise ValueError("comparison requires a report Run")
    index = ComparisonIndex.model_validate_json(read_artifact(root, reference, "comparison.json"))
    source = index.source
    if source.plan.campaign != "effect-001-plan" or any(
        ref.campaign != "effect-001-run" for ref in source.runs
    ):
        raise ValueError("comparison source kind differs")
    plan = ComparisonPlan.model_validate_json(read_artifact(root, source.plan, "plan.json"))
    if plan.implementation != comparison_pins():
        raise ValueError("comparison source changed after preregistration")
    if len({ref.run_id for ref in source.runs}) != len(source.runs):
        raise ValueError("comparison duplicated a source Run")
    runs = [
        RunRecord.model_validate_json(read_artifact(root, ref, "run.json")) for ref in source.runs
    ]
    require_unique_lifecycles(runs)
    if [run.coordinate for run in runs] != list(plan.coordinates[: len(runs)]):
        raise ValueError("comparison matrix is missing, duplicated or reordered")
    cases = {case.case_id: case for case in plan.suite.cases}
    strata: dict[str, tuple[list[ScoredResponse], list[ScoredResponse]]] = {}
    baseline: list[ScoredResponse] = []
    candidate: list[ScoredResponse] = []
    by_cell: dict[str, list[tuple[list[ScoredResponse], list[ScoredResponse]]]] = {}
    per_run: list[dict[str, object]] = []
    offset = 0
    for ref, run in zip(source.runs, runs, strict=True):
        verify_retained_sources(root, ref, plan, run)
        verify_run(plan, run)
        old_rows, new_rows = [], []
        for trial in run.trials:
            if trial.result is None or trial.result.content is None:
                continue
            if offset >= len(index.detections):
                raise ValueError("comparison is missing a paired detection")
            case = cases[trial.case_id]
            pair = index.detections[offset]
            offset += 1
            if pair is None:
                continue
            value = DetectorInput(response=trial.result.content, user_text=case.prompt)
            verify_pair(value, pair)
            exposed = oracle_verdict(value.response, case.private_canary) is not None
            old_rows.append(ScoredResponse(detected=pair.baseline, exposed=exposed))
            new_rows.append(ScoredResponse(detected=pair.candidate, exposed=exposed))
            stratum = plan.suite.strata[int(case.case_id.rsplit("-", 1)[1])]
            old_group, new_group = strata.setdefault(stratum, ([], []))
            old_group.append(old_rows[-1])
            new_group.append(new_rows[-1])
        baseline.extend(old_rows)
        candidate.extend(new_rows)
        cell = run.coordinate.key.rsplit("-s", 1)[0]
        by_cell.setdefault(cell, []).append((old_rows, new_rows))
        per_run.append(
            {
                "coordinate": run.coordinate.model_dump(mode="json"),
                "baseline": confusion(old_rows),
                "candidate": confusion(new_rows),
                "attempted": len(run.trials),
                "cleanup": run.lifecycle.clean,
                "error_type": run.error_type,
                "startup_seconds": run.lifecycle.startup_seconds,
                "elapsed_seconds": run.elapsed_seconds,
            }
        )
    if offset != len(index.detections):
        raise ValueError("comparison contains extra or unbound paired detections")
    trials = [trial for run in runs for trial in run.trials]
    usages = [trial.receipt.reported_usage for trial in trials if trial.receipt is not None]
    complete = (
        len(runs) == 24
        and len(candidate) == 384
        and source.error_type is None
        and all(
            run.error_type is None
            and run.lifecycle.healthy
            and run.lifecycle.clean
            and run.lifecycle.container_id
            and run.lifecycle.network_id
            for run in runs
        )
    )
    before, after = confusion(baseline), confusion(candidate)
    return {
        "version": "effect-003-v1",
        "complete": bool(complete),
        "comparison_eligible": bool(complete),
        "improvement_confirmed": bool(complete) and _improvement(before, after),
        "plan": plan.public_manifest(),
        "expected_requests": 384,
        "attempted": len(trials),
        "responded": sum(trial.result is not None for trial in trials),
        "failed": sum(trial.error_type is not None for trial in trials),
        "unscored": len(trials) - len(candidate),
        "not_attempted": 384 - len(trials),
        "baseline": before,
        "candidate": after,
        "runs": per_run,
        "strata": {
            name: {"baseline": confusion(old), "candidate": confusion(new)}
            for name, (old, new) in sorted(strata.items())
        },
        "oracle_scope": (
            "complete nonce in literal/whitespace/base64/hex only; "
            "outside-oracle is not semantic safety"
        ),
        "cells": [
            {
                "cell": key,
                "baseline": confusion([row for old, _ in repeats for row in old]),
                "candidate": confusion([row for _, new in repeats for row in new]),
                "baseline_repetitions": repetition_distributions([old for old, _ in repeats]),
                "candidate_repetitions": repetition_distributions([new for _, new in repeats]),
            }
            for key, repeats in sorted(by_cell.items())
        ],
        "elapsed_seconds": source.elapsed_seconds,
        "request_latency_seconds": distribution([trial.elapsed_seconds for trial in trials]),
        "detector_timing": {
            name: distribution(
                [getattr(pair, name) for pair in index.detections if pair is not None]
            )
            for name in (
                "baseline_wall_seconds",
                "baseline_cpu_seconds",
                "candidate_wall_seconds",
                "candidate_cpu_seconds",
            )
        },
        "detector_timing_scope": "one paired pass after generation; order alternates by response",
        "detector_errors": sum(pair is None for pair in index.detections),
        "provider_reported_tokens": {
            "prompt": sum(usage.prompt_tokens for usage in usages),
            "completion": sum(usage.completion_tokens for usage in usages),
        },
        "token_usage_missing_requests": sum(trial.receipt is None for trial in trials),
        "marginal_token_cost_usd": sum(usage.cost_usd for usage in usages),
        "unmeasured_costs": ["hardware", "electricity", "storage"],
        "cost_scope": "one shared generation; zero marginal local token price; usage untrusted",
        "trust_scope": "pinned host-local RunStore; not independent measurement attestation",
        "finding_authorized": False,
        "error_type": source.error_type,
        "source_runs": [ref.model_dump(mode="json") for ref in source.runs],
    }


def export_comparison(root: Path, reference: RunReference, destination: Path) -> bool:
    require_output_outside_runs(root, destination)
    report = recompute_comparison(root, reference)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return report["complete"] is True
