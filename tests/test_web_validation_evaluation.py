from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from test_benchmark_zap_scanner import _reload_web_source, _run_web_source

from pajin.domain.models import ToolRequest
from pajin.runtime.worker import WorkerResult
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.workflow.web_validation_evaluation import (
    WebControlledValidationIdentitySet,
    WebObservedPolicyDenial,
    WebSourceRequestUnitObservation,
    WebValidationEvaluationError,
    WebValidationFloorEvaluation,
    _WebValidationEvaluationGate,
    observe_web_source_request_units,
)
from pajin.workflow.web_validation_floor import (
    bind_web_expected_finding_projection_policy,
    registered_web_benchmark_validation_floor_policy,
)
from tests.test_web_controlled_validation_runtime import _execute
from tests.test_web_proxy_route_authority import RouteContext

pytest_plugins = ("tests.test_web_proxy_route_authority",)


@pytest.fixture(scope="module")
def web002d_context(
    tmp_path_factory: pytest.TempPathFactory,
    route_context: RouteContext,
) -> SimpleNamespace:
    context = _run_web_source(tmp_path_factory.mktemp("web002d-source"))
    source = _reload_web_source(context)
    floor = registered_web_benchmark_validation_floor_policy(
        context.measured_case,
        capability_bundle=context.capability_bundle,
        lifecycle=context.lifecycle,
        release=context.measured_case.capability_release,
        target_adapter=context.target_adapter,
        private_ground_truth_profile=context.private_profile,
        scanner_plan=context.measured_case.scanner_plan,
        scanner_registration=context.measured_case.scanner_registration,
    )
    mapping = bind_web_expected_finding_projection_policy(
        measured_case=context.measured_case,
        floor_policy=floor,
        capability_bundle=context.capability_bundle,
        lifecycle=context.lifecycle,
        release=context.measured_case.capability_release,
        target_adapter=context.target_adapter,
        private_ground_truth_profile=context.private_profile,
        scanner_plan=context.measured_case.scanner_plan,
        scanner_registration=context.measured_case.scanner_registration,
    )
    worker_outcome = asyncio.run(
        _execute(
            route_context,
            tmp_path=tmp_path_factory.mktemp("web002d-evaluation-worker"),
        )
    )[0]
    return SimpleNamespace(
        source=source,
        floor=floor,
        mapping=mapping,
        source_context=context,
        worker_evidence=worker_outcome.evidence,
    )


def _identities(request: ToolRequest, worker: WorkerResult) -> WebControlledValidationIdentitySet:
    return WebControlledValidationIdentitySet(
        validationRunId="validation-run:web002d:1",
        targetRunId="target-run:web002d:1",
        targetAttemptId="target-attempt:web002d:1",
        executionOperationId="operation:web002d:execute:1",
        cleanupOperationId="operation:web002d:cleanup:1",
        routeId="route:web002d:1",
        approvalId="approval:web002d:1",
        permitId="permit:web002d:1",
        workerExecutionId=worker.execution_id,
        dispatchId="dispatch:web002d:1",
        toolRequestId=request.request_id,
        resultEvidenceId="evidence:web002d:1",
        targetFence=101,
    )


def _denial(floor) -> WebObservedPolicyDenial:
    registry = floor.policy_denial_control_registry
    case = registry.cases[0]
    return WebObservedPolicyDenial(
        registryId=registry.registry_id,
        registryDigest=registry.registry_digest,
        caseId=case.case_id,
        caseDigest=case.case_digest,
    )


def _source_request_units(context: SimpleNamespace) -> WebSourceRequestUnitObservation:
    return observe_web_source_request_units(context.source)


def _evaluate(context: SimpleNamespace, **changes):
    evidence = context.worker_evidence
    values = {
        "floor_policy": context.floor,
        "mapping": context.mapping,
        "measured_case_authority": context.source_context.measured_case,
        "private_ground_truth_profile": context.source_context.private_profile,
        "source_authority": context.source,
        "validation_identities": _identities(evidence.request, evidence.worker_result),
        "worker_evidence": evidence,
        "denial_control": _denial(context.floor),
        "source_request_units": _source_request_units(context),
    }
    values.update(changes)
    return _WebValidationEvaluationGate().evaluate(**values)


def test_independent_floor_evaluation_projects_only_public_bounded_finding(
    web002d_context: SimpleNamespace,
) -> None:
    outcome = _evaluate(web002d_context)
    retry = _evaluate(web002d_context)
    evaluation = outcome.evaluation
    finding = outcome.finding
    by_id = {item.metric.metric_id: item for item in evaluation.observations}

    assert outcome == retry
    assert len(evaluation.observations) == 14
    assert sum(item.applicability.value == "required" for item in evaluation.observations) == 11
    assert (
        sum(item.applicability.value == "not-applicable" for item in evaluation.observations) == 3
    )
    assert (
        by_id["common.ground-truth-coverage"].numerator,
        by_id["common.ground-truth-coverage"].denominator,
    ) == (1, 1)
    assert (
        by_id["common.false-positive-rate"].numerator,
        by_id["common.false-positive-rate"].denominator,
    ) == (0, 1)
    assert by_id["common.evidence-completeness"].numerator == 16
    assert by_id["common.policy-denial-correctness"].numerator == 1
    assert by_id["common.total-request-units"].numerator == (
        web002d_context.source.source_request_units + 3
    )
    assert by_id["common.total-tool-calls"].numerator == (len(web002d_context.source.lineages) + 1)
    elapsed = (
        web002d_context.worker_evidence.worker_result.finished_at
        - web002d_context.worker_evidence.worker_result.started_at
    )
    elapsed_microseconds = (
        elapsed.days * 86_400 + elapsed.seconds
    ) * 1_000_000 + elapsed.microseconds
    assert by_id["common.time-to-first-valid-result"].numerator == elapsed_microseconds
    assert evaluation.benchmark_validation_floor_satisfied is True
    assert evaluation.source_request_units == _source_request_units(web002d_context).reference()
    assert finding.claim_ceiling == "benchmark-ground-truth-match"
    assert finding.product_finding_confirmed is True
    assert finding.graph_mutation_authorized is False
    assert finding.reporting_authorized is False
    assert finding.external_delivery_authorized is False
    assert finding.additional_execution_authorized is False

    public_wire = json.dumps(
        {
            "evaluation": evaluation.model_dump(mode="json", by_alias=True),
            "finding": finding.model_dump(mode="json", by_alias=True),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    private = web002d_context.mapping.private_binding
    for forbidden in (
        private.ground_truth_id,
        private.expected_finding_id,
        private.matcher_id,
        private.matcher_digest,
        web002d_context.source.baseline_result_digest,
        web002d_context.source.lineages[0].raw_sarif_sha256,
        "1' AND '1'='2",
        "1' OR '1'='1",
        "responseBodyBase64",
    ):
        assert forbidden not in public_wire


@pytest.mark.parametrize(
    "field",
    (
        "sourceEvidenceNames",
        "controlledValidationEvidenceNames",
        "observations",
    ),
)
def test_floor_evaluation_json_tuple_roundtrip_rejects_python_list_coercion(
    web002d_context: SimpleNamespace,
    field: str,
) -> None:
    evaluation = _evaluate(web002d_context).evaluation

    assert (
        WebValidationFloorEvaluation.model_validate_json(evaluation.model_dump_json(by_alias=True))
        == evaluation
    )

    python_wire = evaluation.model_dump(mode="python", by_alias=True)
    python_wire[field] = list(python_wire[field])
    with pytest.raises(ValidationError, match="tuple"):
        WebValidationFloorEvaluation.model_validate(python_wire)


def test_worker_vulnerable_and_checks_are_not_authority(
    web002d_context: SimpleNamespace,
) -> None:
    evidence = web002d_context.worker_evidence
    request = evidence.request
    worker = evidence.worker_result
    output = json.loads(worker.stdout)
    output["vulnerable"] = False
    output["checks"] = {
        "baselineSingleRecord": False,
        "negativeControlEmpty": False,
        "booleanProbeExpanded": False,
        "syntheticLabOnly": False,
    }
    tampered_worker = worker.model_copy(
        update={"stdout": json.dumps(output, separators=(",", ":"))}
    )
    tampered_result = BooleanSQLiProbeTool().interpret(request, tampered_worker)
    tampered_evidence = evidence.model_copy(
        update={
            "worker_result": tampered_worker,
            "tool_result": tampered_result,
        }
    )

    with pytest.raises(WebValidationEvaluationError, match="failed closed"):
        _evaluate(
            web002d_context,
            worker_evidence=tampered_evidence,
            validation_identities=_identities(request, tampered_worker),
        )


def test_host_receipt_tampering_fails_before_floor_evaluation(
    web002d_context: SimpleNamespace,
) -> None:
    evidence = web002d_context.worker_evidence
    request = evidence.request
    worker = evidence.worker_result
    events = worker.network_log.splitlines()
    receipt = json.loads(events[1])
    receipt["targetSha256"] = "0" * 64
    events[1] = json.dumps(receipt, separators=(",", ":"))
    tampered_worker = worker.model_copy(update={"network_log": "\n".join(events)})
    tampered_evidence = evidence.model_copy(update={"worker_result": tampered_worker})

    with pytest.raises(WebValidationEvaluationError, match="failed closed"):
        _evaluate(
            web002d_context,
            worker_evidence=tampered_evidence,
            validation_identities=_identities(request, tampered_worker),
        )


def test_source_and_controlled_validation_identity_reuse_fails_closed(
    web002d_context: SimpleNamespace,
) -> None:
    evidence = web002d_context.worker_evidence
    identities = _identities(evidence.request, evidence.worker_result).model_copy(
        update={"target_run_id": web002d_context.source.lineages[0].target_run_id}
    )

    with pytest.raises(WebValidationEvaluationError, match="identities overlap"):
        _evaluate(web002d_context, validation_identities=identities)


def test_source_request_units_are_content_addressed_and_source_bound(
    web002d_context: SimpleNamespace,
) -> None:
    observation = _source_request_units(web002d_context)
    assert observation == _source_request_units(web002d_context)
    assert observation.execution_authorized is False

    smuggled_count = observation.model_copy(update={"request_units": 999})
    with pytest.raises(WebValidationEvaluationError, match="failed closed"):
        _evaluate(web002d_context, source_request_units=smuggled_count)

    foreign_result = WebSourceRequestUnitObservation(
        sourceMeasurement=web002d_context.source.reference(),
        measurementResultDigest="0" * 64,
        requestUnits=web002d_context.source.source_request_units,
    )
    with pytest.raises(
        WebValidationEvaluationError,
        match="source request-unit measurement is invalid",
    ):
        _evaluate(web002d_context, source_request_units=foreign_result)


def test_missing_evidence_and_bad_denial_block_the_floor(
    web002d_context: SimpleNamespace,
) -> None:
    evidence = web002d_context.worker_evidence
    incomplete = evidence.model_copy(
        update={"host_http_receipt_digests": evidence.host_http_receipt_digests[:-1]}
    )
    with pytest.raises(WebValidationEvaluationError, match="failed closed"):
        _evaluate(
            web002d_context,
            worker_evidence=incomplete,
        )

    bad_denial = _denial(web002d_context.floor).model_copy(
        update={"provider_execution_performed": True}
    )
    with pytest.raises(WebValidationEvaluationError, match="failed closed"):
        _evaluate(web002d_context, denial_control=bad_denial)


def test_hidden_instance_state_and_public_authority_escalation_are_rejected(
    web002d_context: SimpleNamespace,
) -> None:
    evidence = web002d_context.worker_evidence
    request = evidence.request
    smuggled = request.model_copy(update={"external_network": "foreign-network"})
    smuggled_evidence = evidence.model_copy(update={"request": smuggled})
    with pytest.raises(WebValidationEvaluationError, match="unmodeled instance state"):
        _evaluate(web002d_context, worker_evidence=smuggled_evidence)

    outcome = _evaluate(web002d_context)
    finding_payload = outcome.finding.model_dump(mode="json", by_alias=True)
    finding_payload["reportingAuthorized"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        type(outcome.finding).model_validate(finding_payload)

    evaluation_payload = outcome.evaluation.model_dump(mode="python", by_alias=True)
    evaluation_payload["observations"][0]["numerator"] = 0
    evaluation_payload["evaluationId"] = ""
    evaluation_payload["evaluationDigest"] = ""
    with pytest.raises(ValidationError, match="fixed metric observation"):
        WebValidationFloorEvaluation.model_validate(evaluation_payload)

    comparison_payload = outcome.evaluation.model_dump(mode="python", by_alias=True)
    comparison_payload["observations"][0]["comparison"] = outcome.evaluation.observations[
        3
    ].comparison
    comparison_payload["evaluationId"] = ""
    comparison_payload["evaluationDigest"] = ""
    with pytest.raises(ValidationError, match="public metric contract"):
        WebValidationFloorEvaluation.model_validate(comparison_payload)
