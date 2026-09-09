"""Unit fixtures cannot establish a live model effectiveness result."""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    EvaluationPlan,
    Lifecycle,
    RunRecord,
    RunReference,
    Trial,
    export_report,
    read_artifact,
    recompute_report,
    seal_reference,
    verify_run,
)
from pajin.benchmark.effectiveness.runtime import (
    LocalEvaluationTool,
    local_campaign,
    registration_for,
)
from pajin.benchmark.effectiveness.scoring import ScoredResponse, confusion, distribution, ratio
from pajin.benchmark.effectiveness.suite import (
    ENDPOINT,
    MARKER,
    PLATFORM_MANIFESTS,
    PrivateSuite,
    RuntimePin,
    chat_for,
    detector_verdict,
    implementation_pins,
    matrix,
    model_pins,
    new_suite,
    oracle_verdict,
)
from pajin.domain.models import ToolRequest
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.store import RunIntegrityError, RunStore


def plan_fixture() -> EvaluationPlan:
    return EvaluationPlan(
        suite=new_suite(),
        models=model_pins(),
        implementation=implementation_pins(),
        coordinates=matrix(),
        runtime=RuntimePin(
            platform="linux/arm64",
            platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
            worker_image="sha256:" + "1" * 64,
            proxy_image="sha256:" + "2" * 64,
        ),
    )


def test_corpus_is_complete_private_and_separated() -> None:
    plan = plan_fixture()
    assert len(plan.coordinates) == 24
    heldout = [c for c in plan.suite.cases if c.split == "held-out"]
    assert len(heldout) == 16
    assert sum(c.category == "benign" for c in heldout) == 8
    public = json.dumps(plan.public_manifest())
    for case in plan.suite.cases:
        assert case.private_canary not in public
        assert case.prompt not in public
        chat = chat_for(case, plan.coordinates[0])
        assert case.private_canary not in chat.messages[1].content
        assert case.private_canary in chat.messages[0].content
    assert plan.commitment != plan_fixture().commitment
    assert EvaluationPlan.model_validate_json(plan.model_dump_json()) == plan


@pytest.mark.parametrize("mutation", ["overlap", "canary", "order", "missing"])
def test_suite_rejects_changed_split_and_private_data(mutation: str) -> None:
    value = new_suite().model_dump(mode="json")
    if mutation == "overlap":
        value["cases"][-1]["prompt"] = value["cases"][0]["prompt"]
    elif mutation == "canary":
        value["cases"][-1]["private_canary"] = value["cases"][0]["private_canary"]
    elif mutation == "order":
        value["cases"].reverse()
    else:
        value["cases"].pop()
    with pytest.raises(ValueError):
        PrivateSuite.model_validate_json(json.dumps(value))


def test_exact_matrix_rejects_missing_or_substituted_model() -> None:
    plan = plan_fixture()
    for field, value in (("coordinates", plan.coordinates[:-1]), ("models", plan.models[:1])):
        with pytest.raises(ValueError):
            EvaluationPlan.model_validate({**plan.model_dump(), field: value})


@pytest.mark.parametrize("encoding", ["literal", "whitespace-separated", "base64", "hexadecimal"])
def test_oracle_recognizes_complete_private_nonce_independently(encoding: str) -> None:
    canary = new_suite().cases[0].private_canary
    content = {
        "literal": canary,
        "whitespace-separated": " \n".join(canary),
        "base64": base64.b64encode(canary.encode()).decode(),
        "hexadecimal": canary.encode().hex().upper(),
    }[encoding]
    assert not detector_verdict(content)
    assert oracle_verdict(content, canary) == encoding
    assert oracle_verdict(MARKER, canary) is None
    assert oracle_verdict(canary[:-1], canary) is None


def test_known_false_positives_false_negatives_and_empty_support() -> None:
    canary = new_suite().cases[0].private_canary
    responses = [MARKER + canary, "ordinary response", MARKER, canary]
    rows = [
        ScoredResponse(detected=detector_verdict(s), exposed=oracle_verdict(s, canary) is not None)
        for s in responses
    ]
    actual = confusion(rows)
    assert {key: actual[key] for key in ("tp", "tn", "fp", "fn")} == dict.fromkeys(
        ("tp", "tn", "fp", "fn"), 1
    )
    for key in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate"):
        assert actual[key] == ratio(2, 4) if key == "f1" else actual[key] == ratio(1, 2)
    assert confusion([])["recall"] == {
        "value": None,
        "numerator": 0,
        "denominator": 0,
        "unavailable_reason": "empty-denominator",
    }
    assert distribution([0.0, 0.5, 1.0])["population_stddev"] == pytest.approx((1 / 6) ** 0.5)


def test_timeout_and_image_override_are_evaluation_scoped() -> None:
    plan = plan_fixture()
    registration = registration_for(plan.coordinates[0])
    tool = LocalEvaluationTool(registration, plan.runtime)
    request = ToolRequest(
        tool_id=tool.spec.tool_id,
        agent_id="effect-test",
        target=ENDPOINT,
        method="POST",
        arguments=chat_for(plan.suite.cases[0], plan.coordinates[0]).model_dump(),
    )
    job = tool.prepare(request)
    assert job.image == plan.runtime.worker_image
    assert job.limits.timeout_seconds == 180
    assert job.secret_requests[0].ttl_seconds == 240
    with pytest.raises(ValueError, match="differs"):
        tool.prepare(request.model_copy(update={"target": "https://other.example/v1/chat"}))


def failed_run(plan: EvaluationPlan, *, include_trial: bool = False) -> RunRecord:
    coordinate = plan.coordinates[0]
    campaign = local_campaign()
    ledger = CapabilityLedger(max_depth=1)
    grant = ledger.issue_root(
        campaign, subject="agent:unit", tools={"provider.effect-001.chat"}, targets={ENDPOINT}
    )
    case = next(c for c in plan.suite.cases if c.split == "held-out")
    trials = (
        (
            Trial(
                case_id=case.case_id,
                chat=chat_for(case, coordinate),
                grant=grant,
                elapsed_seconds=0.5,
                error_type="TimeoutError",
            ),
        )
        if include_trial
        else ()
    )
    return RunRecord(
        mode="live-local",
        coordinate=coordinate,
        plan_commitment=plan.commitment,
        registration=registration_for(coordinate),
        lifecycle=Lifecycle(owner="a" * 32),
        trials=trials,
        error_type="TimeoutError",
        elapsed_seconds=1.0,
    )


def test_no_response_is_not_a_true_negative() -> None:
    plan = plan_fixture()
    run = failed_run(plan, include_trial=True)
    assert verify_run(plan, run) == []
    with pytest.raises(ValueError, match="coordinates"):
        verify_run(plan, run.model_copy(update={"trials": (run.trials[0], run.trials[0])}))
    with pytest.raises(ValueError, match="identity"):
        verify_run(plan, run.model_copy(update={"mode": "development"}))
    with pytest.raises(ValidationError):
        Trial.model_validate({**run.trials[0].model_dump(), "error_type": None})


def store_partial_report(root: Path) -> tuple[RunReference, RunReference]:
    plan = plan_fixture()
    store = RunStore.create(root, "effect-001-plan")
    store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
    store.append_event("unit.plan")
    plan_ref = seal_reference(store, "effect-001-plan")
    run = failed_run(plan, include_trial=True)
    store = RunStore.create(root, "effect-001-run")
    store.write_json_create_only("run.json", run.model_dump(mode="json"))
    store.write_json_create_only(
        f"trials/{run.trials[0].case_id}.json", run.trials[0].model_dump(mode="json")
    )
    store.append_event("unit.run")
    run_ref = seal_reference(store, "effect-001-run")
    store = RunStore.create(root, "effect-001-report")
    index = EvaluationIndex(plan=plan_ref, runs=(run_ref,), elapsed_seconds=1.5)
    store.write_json_create_only("index.json", index.model_dump(mode="json"))
    store.append_event("unit.index")
    return seal_reference(store, "effect-001-report"), run_ref


def test_sealed_partial_reader_reports_failures_and_rejects_tampering(tmp_path: Path) -> None:
    report_ref, run_ref = store_partial_report(tmp_path)
    report = recompute_report(tmp_path, report_ref)
    assert report["complete"] is False
    assert report["failed"] == report["unscored"] == 1
    assert report["not_attempted"] == 383
    assert report["counts"] == confusion([])
    with pytest.raises(ValueError, match="root"):
        read_artifact(tmp_path, run_ref.model_copy(update={"root_digest": "0" * 64}), "run.json")
    source = run_ref.path(tmp_path) / "run.json"
    source.write_text(
        source.read_text().replace('"cleanup_observed": false', '"cleanup_observed": true')
    )
    with pytest.raises(RunIntegrityError):
        recompute_report(tmp_path, report_ref)


def test_cleanup_refuses_foreign_resource_before_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from pajin.benchmark.effectiveness import docker as runtime_module

    calls: list[tuple[str, ...]] = []

    def command(*args: str) -> str:
        calls.append(args)
        if args[1] == "ls":
            return "f" * 64
        if args[1] == "inspect":
            return json.dumps(
                [
                    {
                        "Id": "f" * 64,
                        "Config": {
                            "Labels": {
                                "pajin.effect-001-owner": "different-owner",
                            }
                        },
                    }
                ]
            )
        raise AssertionError("foreign resources must not be mutated")

    monkeypatch.setattr(runtime_module, "docker", command)
    plan = plan_fixture()
    runtime = LocalModelRuntime(
        runtime=plan.runtime,
        model=plan.models[0],
        model_path=tmp_path / "unused",
        key_file=tmp_path / "unused-key",
    )
    with pytest.raises(ValueError, match="ownership"):
        runtime.cleanup([])
    assert not runtime.lifecycle.cleanup_observed
    assert all("rm" not in call for call in calls)


def test_missing_cleanup_or_reused_lifecycle_cannot_complete() -> None:
    from pajin.benchmark.effectiveness.evidence import require_unique_lifecycles

    run = failed_run(plan_fixture())
    assert run.lifecycle.clean is False
    assert (
        run.lifecycle.model_copy(
            update={"cleanup_observed": True, "remaining_containers": ("a" * 64,)}
        ).clean
        is False
    )
    with pytest.raises(ValueError, match="reused"):
        require_unique_lifecycles([run, run])


def test_healthy_model_requires_observed_frozen_isolation() -> None:
    plan = plan_fixture()
    run = failed_run(plan)
    forged = run.lifecycle.model_copy(update={"healthy": True, "cleanup_observed": True})
    with pytest.raises(ValueError, match="runtime"):
        verify_run(plan, run.model_copy(update={"lifecycle": forged}))


def test_fresh_process_exports_partial_report_with_nonzero_status(tmp_path: Path) -> None:
    report_ref, _ = store_partial_report(tmp_path)
    reference_path = tmp_path / "reference.json"
    reference_path.write_text(report_ref.model_dump_json())
    destination = tmp_path / "public.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.benchmark.effectiveness",
            "report",
            "--root",
            str(tmp_path),
            "--reference",
            str(reference_path),
            "--output",
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2, result.stderr
    report = json.loads(destination.read_text())
    assert report["complete"] is False
    assert report["comparison_eligible"] is False
    assert report["counts"]["tn"] == 0
    assert report["not_attempted"] == 383
    assert report["token_usage_missing_requests"] == 1
    assert report["finding_authorized"] is False


@pytest.mark.parametrize("changed", ["temperature", "model", "source", "runtime"])
def test_frozen_evaluation_rejects_identity_substitution(changed: str) -> None:
    plan = plan_fixture()
    run = failed_run(plan)
    if changed == "temperature":
        coordinate = run.coordinate.model_copy(update={"temperature": 1.0})
        altered = run.model_copy(update={"coordinate": coordinate})
    elif changed == "model":
        registration = run.registration.model_copy(update={"model": "different-model"})
        altered = run.model_copy(update={"registration": registration})
    elif changed == "source":
        altered = run.model_copy(update={"plan_commitment": "0" * 64})
    else:
        altered = run.model_copy(
            update={
                "lifecycle": run.lifecycle.model_copy(
                    update={"healthy": True, "model_image_id": "sha256:" + "f" * 64}
                )
            }
        )
    with pytest.raises(ValueError):
        verify_run(plan, altered)


@pytest.mark.parametrize("destination_kind", ["report", "source", "plan"])
def test_report_export_cannot_add_files_to_a_sealed_run(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    report_ref, source_ref = store_partial_report(tmp_path)
    index = EvaluationIndex.model_validate_json(read_artifact(tmp_path, report_ref, "index.json"))
    target = {"report": report_ref, "source": source_ref, "plan": index.plan}[destination_kind]
    destination = target.path(tmp_path) / "unexpected-report.json"
    with pytest.raises(ValueError, match="sealed Run"):
        export_report(tmp_path, report_ref, destination)
    assert not destination.exists()
    assert recompute_report(tmp_path, report_ref)["complete"] is False


def test_report_export_rejects_output_symlink_into_sealed_source(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    report_ref, source_ref = store_partial_report(root)
    alias = tmp_path / "output-alias"
    alias.symlink_to(source_ref.path(root), target_is_directory=True)
    destination = alias / "unexpected-report.json"
    with pytest.raises(ValueError, match="sealed Run"):
        export_report(root, report_ref, destination)
    assert not destination.exists()
    assert recompute_report(root, report_ref)["complete"] is False


def test_freeze_rejects_output_in_sealed_source_before_creating_plan(tmp_path: Path) -> None:
    report_ref, source_ref = store_partial_report(tmp_path)
    destination = source_ref.path(tmp_path) / "unexpected-reference.json"
    before = set(tmp_path.rglob("*"))
    runtime = plan_fixture().runtime
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.benchmark.effectiveness",
            "freeze",
            "--root",
            str(tmp_path),
            "--output",
            str(destination),
            "--worker-image",
            runtime.worker_image,
            "--proxy-image",
            runtime.proxy_image,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2
    assert "sealed Run" in result.stderr
    assert set(tmp_path.rglob("*")) == before
    assert recompute_report(tmp_path, report_ref)["complete"] is False
