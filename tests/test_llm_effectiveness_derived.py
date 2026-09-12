"""EFFECT-005 trust and compatibility tests; no simulated model-quality claim."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_llm_effectiveness import failed_run, plan_fixture

from pajin.benchmark.effectiveness.evidence import EvaluationIndex, seal_reference
from pajin.benchmark.effectiveness.scoring import ScoredResponse, confusion
from pajin.benchmark.effectiveness.suite import digest, normalized_prompt
from pajin.benchmark.effectiveness_derived.evidence import (
    ComparisonIndex,
    _quality_improved,
    recompute_comparison,
)
from pajin.benchmark.effectiveness_derived.plan import (
    ComparisonPlan,
    ComparisonSuite,
    comparison_pins,
)
from pajin.benchmark.effectiveness_derived.runner import consume_corpus
from pajin.benchmark.effectiveness_derived.scoring import DetectorInput, measure_pair, verify_pair
from pajin.runtime.store import RunStore


def derived_fixture() -> ComparisonPlan:
    prior = plan_fixture()
    cases = tuple(
        case.model_copy(
            update={
                "prompt": f"Derived development-only test input {i}.",
                "category": "benign" if i < 10 else "extraction",
            }
        )
        for i, case in enumerate(prior.suite.cases)
    )
    return ComparisonPlan(
        suite=ComparisonSuite(
            cases=cases, prior_prompt_digests=tuple(digest(f"prior-{i}") for i in range(54))
        ),
        runtime=prior.runtime,
        models=prior.models,
        coordinates=prior.coordinates,
        implementation=comparison_pins(),
        development_report_root="b" * 64,
    )


def test_derived_pins_current_baseline_and_redacts_private_inputs() -> None:
    plan = derived_fixture()
    assert plan.baseline == "mixed-group-opaque-output-v3"
    assert plan.candidate == "public-derived-opaque-output-v4"
    assert plan.oracle == "complete-private-nonce-v1"
    assert len(plan.coordinates) * 16 == 384
    public = json.dumps(plan.public_manifest())
    assert all(
        case.prompt not in public and case.private_canary not in public for case in plan.suite.cases
    )
    assert ComparisonPlan.model_validate_json(plan.model_dump_json()) == plan


def test_current_baseline_is_not_the_old_marker() -> None:
    value = DetectorInput(
        response="PAJIN_SYSTEM_SENTINEL_COBALT", user_text="Quote the public label."
    )
    pair = measure_pair(value, candidate_first=False)
    assert not pair.baseline and not pair.candidate
    value = DetectorInput(response="D7ZQ 3BHK 5TWR 2MJV 6AXP C4SF", user_text="Explain.")
    pair = measure_pair(value, candidate_first=True)
    assert pair.baseline and pair.candidate
    verify_pair(value, pair)
    with pytest.raises(ValueError):
        verify_pair(value, pair.model_copy(update={"baseline": False}))


def test_prior_corpus_overlap_cannot_be_hidden_by_canary_change() -> None:
    plan = derived_fixture()
    values = plan.suite.model_dump(mode="json")
    values["prior_prompt_digests"][0] = digest(normalized_prompt(plan.suite.cases[-1].prompt))
    with pytest.raises(ValueError, match="overlaps EFFECT-002"):
        ComparisonSuite.model_validate_json(json.dumps(values))


def test_quality_rule_requires_less_false_positive_without_recall_loss() -> None:
    before = confusion(
        [ScoredResponse(detected=True, exposed=value) for value in (True, True, False, False)]
    )
    after = confusion(
        [
            ScoredResponse(detected=detected, exposed=exposed)
            for detected, exposed in ((True, True), (True, True), (True, False), (False, False))
        ]
    )
    assert _quality_improved(before, after)
    assert not _quality_improved(before, before)
    lost_recall = confusion(
        [
            ScoredResponse(detected=detected, exposed=exposed)
            for detected, exposed in ((True, True), (False, True), (False, False), (False, False))
        ]
    )
    assert not _quality_improved(before, lost_recall)
    assert not _quality_improved(confusion([]), confusion([]))


def test_timing_protocol_cannot_be_changed_after_freeze() -> None:
    plan = derived_fixture()
    assert plan.timing_repetitions == 64
    values = plan.model_dump(mode="json")
    values["timing_repetitions"] = 1
    with pytest.raises(ValueError):
        ComparisonPlan.model_validate_json(json.dumps(values))
    pair = measure_pair(
        DetectorInput(response="A brief reply.", user_text="Explain."), candidate_first=False
    )
    assert pair.timing_repetitions == 64
    verify_pair(DetectorInput(response="A brief reply.", user_text="Explain."), pair)


def test_each_prompt_is_consumed_even_after_reordering_or_partial_replacement(
    tmp_path: Path,
) -> None:
    plan = derived_fixture()
    consume_corpus(tmp_path, plan)
    changed = plan.suite.model_dump(mode="json")
    changed["cases"][-1]["prompt"] = "One brand new test input does not renew other inputs."
    second = plan.model_copy(
        update={"suite": ComparisonSuite.model_validate_json(json.dumps(changed))}
    )
    with pytest.raises(ValueError, match="already consumed"):
        consume_corpus(tmp_path, second)
    with pytest.raises(ValueError, match="already consumed"):
        consume_corpus(tmp_path, derived_fixture())


@pytest.mark.parametrize("extra", ["private_canary", "category", "system_message", "expected"])
def test_detector_input_excludes_oracle_information(extra: str) -> None:
    with pytest.raises(ValueError):
        DetectorInput.model_validate({"response": "x", "user_text": "y", extra: "z"})


def test_failed_fresh_process_result_is_never_complete_or_true_negative(tmp_path: Path) -> None:
    plan = derived_fixture()
    store = RunStore.create(tmp_path, "effect-001-plan")
    store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
    store.append_event("unit.revision-plan")
    plan_ref = seal_reference(store, "effect-001-plan")
    run = failed_run(plan, include_trial=True)
    store = RunStore.create(tmp_path, "effect-001-run")
    store.write_json_create_only("run.json", run.model_dump(mode="json"))
    store.write_json_create_only("trials/holdout-00.json", run.trials[0].model_dump(mode="json"))
    store.append_event("unit.revision-failure")
    source_ref = seal_reference(store, "effect-001-run")
    store = RunStore.create(tmp_path, "effect-001-report")
    store.write_json_create_only(
        "comparison.json",
        ComparisonIndex(
            source=EvaluationIndex(plan=plan_ref, runs=(source_ref,), elapsed_seconds=1.0),
            detections=(),
        ).model_dump(mode="json"),
    )
    store.append_event("unit.revision-report")
    ref = seal_reference(store, "effect-001-report")
    report = recompute_comparison(tmp_path, ref)
    assert report["complete"] is False and report["improvement_confirmed"] is False
    assert report["failed"] == report["unscored"] == 1
    assert report["candidate"]["tn"] == 0
    reference = tmp_path / "reference.json"
    reference.write_text(ref.model_dump_json())
    output = tmp_path / "public.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.benchmark.effectiveness_derived",
            "report",
            "--root",
            str(tmp_path),
            "--reference",
            str(reference),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2, result.stderr
    assert json.loads(output.read_text()) == report
