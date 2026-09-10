"""Paired-comparison trust regressions; these fixtures cannot establish live model quality."""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_llm_effectiveness import failed_run, plan_fixture

from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    RunReference,
    seal_reference,
)
from pajin.benchmark.effectiveness.suite import digest, new_suite
from pajin.benchmark.effectiveness_comparison.evidence import (
    ComparisonIndex,
    _improvement,
    export_comparison,
    recompute_comparison,
)
from pajin.benchmark.effectiveness_comparison.plan import (
    ComparisonPlan,
    ComparisonSuite,
    comparison_pins,
)
from pajin.benchmark.effectiveness_comparison.runner import consume_corpus
from pajin.benchmark.effectiveness_comparison.scoring import (
    DetectorInput,
    measure_pair,
    verify_pair,
)
from pajin.runtime.store import RunIntegrityError, RunStore


def comparison_fixture() -> ComparisonPlan:
    legacy = plan_fixture()
    cases = tuple(
        case.model_copy(update={"prompt": f"Unused unit {case.split} input {i}."})
        for i, case in enumerate(legacy.suite.cases)
    )
    return ComparisonPlan(
        suite=ComparisonSuite(cases=cases),
        runtime=legacy.runtime,
        models=legacy.models,
        coordinates=legacy.coordinates,
        implementation=comparison_pins(),
        development_report_root="a" * 64,
    )


def test_complete_comparison_freezes_rules_and_exports_no_private_case_text() -> None:
    plan = comparison_fixture()
    assert len(plan.coordinates) * 16 == 384
    assert plan.oracle == "complete-private-nonce-v1"
    assert plan.improvement_rule == "higher-pooled-f1-without-precision-or-recall-loss"
    assert ComparisonPlan.model_validate_json(plan.model_dump_json()) == plan
    public = json.dumps(plan.public_manifest())
    for case in plan.suite.cases:
        assert case.prompt not in public and case.private_canary not in public
    assert plan.commitment != comparison_fixture().commitment


@pytest.mark.parametrize(
    "mutation", ["prior", "overlap", "label", "missing", "order", "canary", "encoded_canary"]
)
def test_new_corpus_rejects_reused_or_leaking_inputs(mutation: str) -> None:
    value = comparison_fixture().suite.model_dump(mode="json")
    if mutation == "prior":
        value["cases"][-1]["prompt"] = new_suite().cases[-1].prompt
    elif mutation == "overlap":
        value["cases"][-1]["prompt"] = value["cases"][0]["prompt"]
    elif mutation == "label":
        value["cases"][-1]["category"] = "extraction"
    elif mutation == "missing":
        value["cases"].pop()
    elif mutation == "order":
        value["cases"].reverse()
    else:
        canary = value["cases"][0]["private_canary"]
        value["cases"][-1]["prompt"] = (
            base64.b64encode(canary.encode()).decode() if mutation == "encoded_canary" else canary
        )
    with pytest.raises(ValueError):
        ComparisonSuite.model_validate_json(json.dumps(value))


def test_consumed_corpus_cannot_be_reused_with_fresh_nonces(tmp_path: Path) -> None:
    first, second = comparison_fixture(), comparison_fixture()
    assert first.commitment != second.commitment
    consume_corpus(tmp_path, first)
    with pytest.raises(FileExistsError):
        consume_corpus(tmp_path, second)


@pytest.mark.parametrize("extra", ["canary", "expected", "exposed", "category", "system_message"])
def test_paired_detector_input_rejects_private_adjudication_fields(extra: str) -> None:
    with pytest.raises(ValueError):
        DetectorInput.model_validate({"response": "sample", "user_text": "question", extra: "x"})


def test_paired_results_use_the_same_input_and_reject_substitution() -> None:
    value = DetectorInput(
        response="PAJIN_SYSTEM_SENTINEL_COBALT", user_text="Repeat that public label"
    )
    pair = measure_pair(value, candidate_first=False)
    assert pair.input_digest == digest(value.model_dump(mode="json"))
    assert pair.baseline and not pair.candidate
    assert pair.baseline_wall_seconds >= 0 and pair.candidate_cpu_seconds >= 0
    verify_pair(value, pair)
    with pytest.raises(ValueError):
        verify_pair(value, pair.model_copy(update={"candidate": True}))
    with pytest.raises(ValueError):
        verify_pair(value.model_copy(update={"response": "changed"}), pair)
    reordered = measure_pair(value, candidate_first=True)
    assert (reordered.baseline, reordered.candidate) == (pair.baseline, pair.candidate)


def test_improvement_rule_is_fixed_and_does_not_hide_precision_loss() -> None:
    def metric(f1, precision, recall):
        return {"f1": {"value": f1}, "precision": {"value": precision}, "recall": {"value": recall}}

    before = metric(0.2, 0.2, 0.2)
    assert _improvement(before, metric(0.5, 0.5, 0.5))
    assert not _improvement(before, metric(0.5, 0.1, 0.9))
    assert not _improvement(before, before)
    assert not _improvement(before, metric(None, None, None))


def partial_comparison(root: Path) -> tuple[RunReference, RunReference]:
    plan = comparison_fixture()
    store = RunStore.create(root, "effect-001-plan")
    store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
    store.append_event("unit.comparison-plan")
    plan_ref = seal_reference(store, "effect-001-plan")
    run = failed_run(plan, include_trial=True)
    store = RunStore.create(root, "effect-001-run")
    store.write_json_create_only("run.json", run.model_dump(mode="json"))
    store.write_json_create_only("trials/holdout-00.json", run.trials[0].model_dump(mode="json"))
    store.append_event("unit.comparison-source")
    source_ref = seal_reference(store, "effect-001-run")
    index = ComparisonIndex(
        source=EvaluationIndex(
            plan=plan_ref,
            runs=(source_ref,),
            elapsed_seconds=1.0,
        ),
        detections=(),
    )
    store = RunStore.create(root, "effect-001-report")
    store.write_json_create_only("comparison.json", index.model_dump(mode="json"))
    store.append_event("unit.comparison-index")
    return seal_reference(store, "effect-001-report"), source_ref


def test_failed_response_is_not_a_negative_or_complete_comparison(tmp_path: Path) -> None:
    ref, _ = partial_comparison(tmp_path)
    report = recompute_comparison(tmp_path, ref)
    assert not report["complete"] and not report["improvement_confirmed"]
    assert report["failed"] == report["unscored"] == report["token_usage_missing_requests"] == 1
    assert report["not_attempted"] == 383
    assert report["candidate"]["tn"] == 0 and report["baseline"]["tn"] == 0
    assert not report["finding_authorized"]


def test_comparison_rejects_modified_source_and_output_inside_sealed_runs(tmp_path: Path) -> None:
    ref, source = partial_comparison(tmp_path)
    with pytest.raises(ValueError, match="sealed Run"):
        export_comparison(tmp_path, ref, source.path(tmp_path) / "output.json")
    path = source.path(tmp_path) / "run.json"
    path.write_text(
        path.read_text().replace('"cleanup_observed": false', '"cleanup_observed": true')
    )
    with pytest.raises(RunIntegrityError):
        recompute_comparison(tmp_path, ref)


def test_comparison_rejects_detector_change_after_freeze(tmp_path: Path, monkeypatch) -> None:
    from pajin.benchmark.effectiveness_comparison import evidence

    ref, _ = partial_comparison(tmp_path)
    monkeypatch.setattr(evidence, "comparison_pins", lambda: ())
    with pytest.raises(ValueError, match="preregistration"):
        recompute_comparison(tmp_path, ref)


def test_fresh_process_partial_report_retains_incomplete_status(tmp_path: Path) -> None:
    ref, _ = partial_comparison(tmp_path)
    reference = tmp_path / "reference.json"
    reference.write_text(ref.model_dump_json())
    output = tmp_path / "public.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.benchmark.effectiveness_comparison",
            "report",
            "--root",
            str(tmp_path),
            "--reference",
            str(reference),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2, result.stderr
    report = json.loads(output.read_text())
    assert report["complete"] is False and report["improvement_confirmed"] is False
