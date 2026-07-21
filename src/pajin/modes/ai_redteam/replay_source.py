"""Exact, read-only interpretation of sealed KISA replay source artifacts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.domain.orchestration import TaskGraph, TaskNode, TaskStatus
from pajin.domain.replay import ReplayRetestContext, ReplaySourceCapabilityReceipt
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.modes.ai_redteam.evidence import evaluate_kisa_transcript
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.policy.capability import CapabilityRecord
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityVerification,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json_bytes
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeOutput, AIChatRegressionInput
from pajin.tools.base import decode_strict_worker_json_object

MAX_REPLAY_SOURCE_JSON_BYTES = 64 * 1024 * 1024
MAX_REPLAY_SOURCE_EVIDENCE_BYTES = 16 * 1024 * 1024


class SealedRunReader:
    """Cache artifact bytes that all belong to one exact verified Run state."""

    def __init__(self, snapshot: VerifiedRunSnapshot) -> None:
        self.snapshot = snapshot
        self._artifacts: dict[str, bytes] = dict(snapshot.artifacts)

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        expected_run_id: str | None = None,
        expected_root_digest: str | None = None,
    ) -> SealedRunReader:
        snapshot = load_verified_run_snapshot(root.resolve(), expected_run_id=expected_run_id)
        if (
            expected_root_digest is not None
            and snapshot.verification.root_digest != expected_root_digest
        ):
            raise ValueError("sealed replay source Run root digest changed")
        return cls(snapshot)

    @property
    def root(self) -> Path:
        return self.snapshot.run_path

    @property
    def verification(self) -> RunIntegrityVerification:
        return self.snapshot.verification

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return self.snapshot.events

    @property
    def sealed_paths(self) -> frozenset[str]:
        return frozenset(
            artifact.path for seal in self.snapshot.seals for artifact in seal.artifacts
        )

    def preload(self, requests: Mapping[str, int]) -> None:
        pending = {
            relative_path: max_bytes
            for relative_path, max_bytes in requests.items()
            if relative_path not in self._artifacts
        }
        if not pending:
            return
        loaded = load_verified_run_artifacts(
            self.root,
            requests=pending,
            expected_run_id=self.verification.run_id,
        )
        self._require_same_snapshot(loaded)
        self._artifacts.update(loaded.artifacts)

    def bytes(self, relative_path: str, *, max_bytes: int) -> bytes:
        self.preload({relative_path: max_bytes})
        content = self._artifacts[relative_path]
        if len(content) > max_bytes:
            raise ValueError(f"sealed replay source artifact exceeds its limit: {relative_path}")
        return content

    def json(self, relative_path: str, *, expect: Literal["object", "array"]) -> object:
        max_bytes = (
            MAX_REPLAY_SOURCE_EVIDENCE_BYTES
            if relative_path.startswith("evidence/")
            else MAX_REPLAY_SOURCE_JSON_BYTES
        )
        try:
            raw = self.bytes(relative_path, max_bytes=max_bytes)
        except (KeyError, ValueError) as exc:
            raise ValueError(
                f"sealed replay source artifact could not be read: {relative_path}"
            ) from exc
        if expect == "object":
            return strict_json_bytes(
                raw,
                label=f"sealed replay source artifact {relative_path}",
                max_bytes=max_bytes,
                expected_type=dict,
                missing_or_invalid_message=(
                    f"sealed replay source artifact could not be read: {relative_path}"
                ),
                type_message=(f"sealed replay source artifact must be an object: {relative_path}"),
            )
        if expect == "array":
            return strict_json_bytes(
                raw,
                label=f"sealed replay source artifact {relative_path}",
                max_bytes=max_bytes,
                expected_type=list,
                missing_or_invalid_message=(
                    f"sealed replay source artifact could not be read: {relative_path}"
                ),
                type_message=f"sealed replay source artifact must be an array: {relative_path}",
            )
        raise ValueError(f"unsupported sealed replay source JSON type: {expect}")

    def require_current(self) -> None:
        self._require_same_snapshot(
            load_verified_run_snapshot(
                self.root,
                expected_run_id=self.verification.run_id,
            )
        )

    def _require_same_snapshot(self, observed: VerifiedRunSnapshot) -> None:
        require_same_authority(
            self.snapshot,
            observed,
            message="sealed replay source Run changed while inputs were loaded",
        )


def read_object(reader: SealedRunReader, relative_path: str) -> dict[str, object]:
    value = reader.json(relative_path, expect="object")
    assert isinstance(value, dict)
    return value


def read_array(reader: SealedRunReader, relative_path: str) -> list[object]:
    value = reader.json(relative_path, expect="array")
    assert isinstance(value, list)
    return value


@dataclass(frozen=True, slots=True)
class RemediationBinding:
    candidate_id: str
    decision_id: str
    finding_id: str
    remediation_id: str


def validate_parent_retest_plan_and_evidence(
    reader: SealedRunReader,
    *,
    campaign: CampaignManifest,
    repetitions: int,
) -> AgentPlan:
    """Bind a completed parent Retest's plan, Tasks, and terminal evidence."""

    if not 2 <= repetitions <= 20:
        raise ValueError("KISA parent Retest repetitions must be between 2 and 20")
    plan = AgentPlan.model_validate(read_object(reader, "plan.json"))
    expected_targets = _parent_retest_targets(campaign)
    planned_requests = _parent_retest_planned_requests(
        plan,
        expected_targets=expected_targets,
        repetitions=repetitions,
    )
    tasks_by_request_id = _parent_retest_tasks(reader, planned_requests)
    attempt_identities = _parent_retest_attempt_identities(tasks_by_request_id)
    results_by_request_id = _parent_retest_evidence_results(
        reader,
        planned_requests=planned_requests,
        tasks_by_request_id=tasks_by_request_id,
        attempt_identities=attempt_identities,
    )
    _validate_parent_retest_terminal_results(tasks_by_request_id, results_by_request_id)
    return plan


def _parent_retest_targets(campaign: CampaignManifest) -> list[str]:
    expected_targets = [
        target.endpoint
        for target in campaign.spec.targets
        if target.type in {"ai-chat-api", "rag-chat-api"}
    ]
    if not expected_targets or len(expected_targets) != len(set(expected_targets)):
        raise ValueError("KISA parent Retest Campaign targets must be unique AI chat endpoints")
    return expected_targets


def _parent_retest_planned_requests(
    plan: AgentPlan,
    *,
    expected_targets: list[str],
    repetitions: int,
) -> dict[str, ToolRequest]:
    sessions_by_target: dict[str, set[str]] = {target: set() for target in expected_targets}
    target_counts: Counter[str] = Counter()
    planned_requests: dict[str, ToolRequest] = {}
    for step in plan.steps:
        request, session_id = _parent_retest_plan_request(step, sessions_by_target)
        if session_id in sessions_by_target[request.target]:
            raise ValueError("KISA parent Retest repetitions require distinct sessions per target")
        if request.request_id in planned_requests:
            raise ValueError("KISA parent Retest plan contains duplicate request identities")
        sessions_by_target[request.target].add(session_id)
        target_counts[request.target] += 1
        planned_requests[request.request_id] = request

    expected_counts = Counter({target: repetitions for target in expected_targets})
    if target_counts != expected_counts or len(plan.steps) != len(expected_targets) * repetitions:
        raise ValueError(
            "KISA parent Retest plan must exactly cover every Campaign target and repetition"
        )
    return planned_requests


def _parent_retest_plan_request(
    step: PlannedStep,
    sessions_by_target: dict[str, set[str]],
) -> tuple[ToolRequest, str]:
    request = step.request
    if (
        request.tool_id != "ai.normal-probe"
        or request.method != "POST"
        or request.target not in sessions_by_target
        or step.scenario_id is not None
        or bool(step.threat_classes)
    ):
        raise ValueError(
            "KISA parent Retest plan must contain only normal probes without attack metadata"
        )
    try:
        regression = AIChatRegressionInput.model_validate(request.arguments)
    except ValueError as exc:
        raise ValueError("KISA parent Retest normal probe arguments are invalid") from exc
    return request, regression.session_id


def _parent_retest_tasks(
    reader: SealedRunReader,
    planned_requests: dict[str, ToolRequest],
) -> dict[str, TaskNode]:
    try:
        task_graph = TaskGraph.model_validate(read_object(reader, "task-graph.json"))
    except ValueError as exc:
        raise ValueError("KISA parent Retest task graph is not a typed TaskGraph") from exc

    tasks_by_request_id: dict[str, TaskNode] = {}
    for task in task_graph.tasks.values():
        task_request = task.request
        if task_request is None:
            continue
        planned = planned_requests.get(task_request.request_id)
        if planned is None:
            raise ValueError("KISA parent Retest task is not bound to a planned normal probe")
        if task_request.request_id in tasks_by_request_id:
            raise ValueError("KISA parent Retest plan request is bound to duplicate Tasks")
        _validate_parent_retest_task(task, planned)
        tasks_by_request_id[task_request.request_id] = task
    if set(tasks_by_request_id) != set(planned_requests):
        raise ValueError(
            "KISA parent Retest plan requests must each bind exactly one request-bearing Task"
        )
    return tasks_by_request_id


def _validate_parent_retest_task(task: TaskNode, planned: ToolRequest) -> None:
    task_request = task.request
    assert task_request is not None
    if (
        task_request.model_dump(mode="json", exclude={"agent_id"})
        != planned.model_dump(mode="json", exclude={"agent_id"})
        or task.assigned_agent_id is None
        or task_request.agent_id != task.assigned_agent_id
    ):
        raise ValueError(
            "KISA parent Retest Task operation or assigned agent differs from its plan"
        )
    if task.status not in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}:
        raise ValueError("completed KISA parent Retest request-bearing Tasks must be terminal")
    if not 1 <= task.attempts <= task.max_attempts:
        raise ValueError("KISA parent Retest Task attempt state is invalid")


def _parent_retest_attempt_identities(
    tasks_by_request_id: dict[str, TaskNode],
) -> dict[str, tuple[str, int]]:
    attempt_identities: dict[str, tuple[str, int]] = {}
    for request_id, task in tasks_by_request_id.items():
        for attempt in range(1, task.max_attempts + 1):
            attempt_request_id = request_id if attempt == 1 else f"{request_id}_attempt{attempt}"
            if attempt_request_id in attempt_identities:
                raise ValueError("KISA parent Retest attempt request identities overlap")
            attempt_identities[attempt_request_id] = (request_id, attempt)
    return attempt_identities


def _parent_retest_evidence_results(
    reader: SealedRunReader,
    *,
    planned_requests: dict[str, ToolRequest],
    tasks_by_request_id: dict[str, TaskNode],
    attempt_identities: dict[str, tuple[str, int]],
) -> dict[str, dict[int, ToolResult]]:
    results_by_request_id: dict[str, dict[int, ToolResult]] = {
        request_id: {} for request_id in planned_requests
    }
    evidence_paths = sorted(
        relative_path
        for relative_path in reader.sealed_paths
        if relative_path.startswith("evidence/")
        and relative_path.endswith(".json")
        and len(relative_path.split("/")) == 2
    )
    reader.preload({path: MAX_REPLAY_SOURCE_EVIDENCE_BYTES for path in evidence_paths})
    for evidence_path in evidence_paths:
        base_request_id, attempt_number, result = _parent_retest_evidence_result(
            reader,
            evidence_path,
            tasks_by_request_id=tasks_by_request_id,
            attempt_identities=attempt_identities,
        )
        if attempt_number in results_by_request_id[base_request_id]:
            raise ValueError("KISA parent Retest evidence differs from its planned normal probe")
        results_by_request_id[base_request_id][attempt_number] = result
    return results_by_request_id


def _parent_retest_evidence_result(
    reader: SealedRunReader,
    evidence_path: str,
    *,
    tasks_by_request_id: dict[str, TaskNode],
    attempt_identities: dict[str, tuple[str, int]],
) -> tuple[str, int, ToolResult]:
    payload = read_object(reader, evidence_path)
    try:
        executed = ToolRequest.model_validate(payload.get("request"))
        result = ToolResult.model_validate(payload.get("result"))
    except ValueError as exc:
        raise ValueError("KISA parent Retest evidence is not typed tool evidence") from exc
    if Path(evidence_path).stem != executed.request_id:
        raise ValueError("KISA parent Retest evidence filename changed request identity")
    attempt_identity = attempt_identities.get(executed.request_id)
    if attempt_identity is None:
        raise ValueError("KISA parent Retest evidence is not bound to a planned normal probe")
    base_request_id, attempt_number = attempt_identity
    task = tasks_by_request_id[base_request_id]
    assert task.request is not None
    if (
        executed.model_dump(mode="json", exclude={"request_id", "agent_id"})
        != task.request.model_dump(mode="json", exclude={"request_id", "agent_id"})
        or executed.agent_id != task.assigned_agent_id
        or result.request_id != executed.request_id
        or result.tool_id != executed.tool_id
    ):
        raise ValueError("KISA parent Retest evidence differs from its planned normal probe")
    return base_request_id, attempt_number, result


def _validate_parent_retest_terminal_results(
    tasks_by_request_id: dict[str, TaskNode],
    results_by_request_id: dict[str, dict[int, ToolResult]],
) -> None:
    for request_id, task in tasks_by_request_id.items():
        attempt_results = results_by_request_id[request_id]
        if set(attempt_results) != set(range(1, task.attempts + 1)):
            raise ValueError("KISA parent Retest evidence must exactly cover every Task attempt")
        ordered_results = [attempt_results[attempt] for attempt in range(1, task.attempts + 1)]
        if any(result.success for result in ordered_results[:-1]):
            raise ValueError("KISA parent Retest cannot retry after a successful attempt")
        terminal_succeeded = ordered_results[-1].success
        expected_status = TaskStatus.SUCCEEDED if terminal_succeeded else TaskStatus.FAILED
        if task.status is not expected_status:
            raise ValueError("KISA parent Retest terminal result differs from its Task status")


def validate_completed_run(reader: SealedRunReader, *, label: str) -> None:
    summary = read_object(reader, "run.json")
    if summary.get("runId") != reader.verification.run_id or summary.get("status") != "completed":
        raise ValueError(f"KISA replay requires a sealed completed {label} Run")


def confirmed_baseline_candidates(
    validation: FindingValidationSet,
) -> list[tuple[CandidateFinding, ValidationDecision]]:
    decisions = {decision.candidate_id: decision for decision in validation.decisions}
    findings = {finding.finding_id: finding for finding in validation.confirmed_findings}
    if len(decisions) != len(validation.decisions) or len(findings) != len(
        validation.confirmed_findings
    ):
        raise ValueError("KISA versioned baseline contains duplicate identities")
    confirmed: list[tuple[CandidateFinding, ValidationDecision]] = []
    for candidate in validation.candidates:
        decision = decisions[candidate.candidate_id]
        if decision.disposition is not FindingDisposition.CONFIRMED:
            continue
        finding = findings.get(candidate.claim.finding_id)
        if (
            candidate.source != "trusted-core:candidate-producer"
            or candidate.source_agent_id != "trusted-core:kisa-candidate-producer"
            or decision.confirmation_basis is not ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
            or decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE
            or decision.reason_codes != [ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED]
            or not decision.replay_lineage
            or finding != candidate.claim.model_copy(update={"validated": True})
        ):
            raise ValueError(
                "KISA retest baseline Candidate is not canonically reproduction-confirmed"
            )
        confirmed.append((candidate, decision))
    if len(confirmed) != len(validation.confirmed_findings):
        raise ValueError("KISA baseline confirmed Candidates and Findings differ")
    return confirmed


def load_remediation_bindings(
    reader: SealedRunReader,
) -> dict[str, RemediationBinding]:
    values = read_array(reader, "remediation-plan.json")
    bindings: dict[str, RemediationBinding] = {}
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("KISA remediation plan entries must be objects")
        candidate_id = value.get("baseline_candidate_id")
        decision_id = value.get("baseline_decision_id")
        finding_id = value.get("baseline_finding_id")
        remediation_id = value.get("remediation_id")
        if not all(
            isinstance(item, str) and bool(item)
            for item in (candidate_id, decision_id, finding_id, remediation_id)
        ):
            raise ValueError("KISA remediation plan is missing baseline identity bindings")
        assert isinstance(candidate_id, str)
        assert isinstance(decision_id, str)
        assert isinstance(finding_id, str)
        assert isinstance(remediation_id, str)
        binding = RemediationBinding(
            candidate_id=candidate_id,
            decision_id=decision_id,
            finding_id=finding_id,
            remediation_id=remediation_id,
        )
        if binding.candidate_id in bindings:
            raise ValueError("KISA remediation plan contains duplicate baseline Candidates")
        bindings[binding.candidate_id] = binding
    return bindings


def validate_retest_context(
    *,
    candidate: CandidateFinding,
    decision: ValidationDecision,
    context: ReplayRetestContext,
    remediation: RemediationBinding | None,
    retest_verification: RunIntegrityVerification,
) -> None:
    if (
        remediation is None
        or remediation.candidate_id != candidate.candidate_id
        or remediation.decision_id != decision.decision_id
        or remediation.finding_id != candidate.claim.finding_id
        or remediation.remediation_id != context.remediation_id
        or context.baseline_decision_id != decision.decision_id
        or context.baseline_finding_id != candidate.claim.finding_id
        or context.retest_run_id != retest_verification.run_id
        or context.retest_source_root_digest != retest_verification.root_digest
    ):
        raise ValueError("KISA retest context differs from sealed baseline or Retest lineage")


@dataclass(frozen=True, slots=True)
class SourceReplayContextData:
    scenario: KISAScenarioDefinition
    target_id: str
    original_request: ToolRequest
    source_capability: ReplaySourceCapabilityReceipt
    evidence_by_request: Mapping[str, list[str]]


def interpret_source_replay_context(
    *,
    source_reader: SealedRunReader,
    plan: AgentPlan,
    candidate: CandidateFinding,
    capability_records: Sequence[CapabilityRecord],
    scenario_resolver: Callable[[str], KISAScenarioDefinition],
) -> SourceReplayContextData:
    steps, scenario = _source_plan_steps(plan, candidate, scenario_resolver)
    requests, execution_windows, evidence_by_request = _source_execution_evidence(
        source_reader=source_reader,
        candidate=candidate,
        steps=steps,
        scenario=scenario,
    )
    original_request = requests[steps[0].request.request_id]
    source_capability = _resolve_source_capability_receipt(
        source_reader=source_reader,
        capability_records=capability_records,
        original_request=original_request,
        execution_window=execution_windows[original_request.request_id],
    )
    return SourceReplayContextData(
        scenario=scenario,
        target_id=_source_target_id(source_reader, original_request.target),
        original_request=original_request,
        source_capability=source_capability,
        evidence_by_request=evidence_by_request,
    )


def _source_plan_steps(
    plan: AgentPlan,
    candidate: CandidateFinding,
    scenario_resolver: Callable[[str], KISAScenarioDefinition],
) -> tuple[list[PlannedStep], KISAScenarioDefinition]:
    if (
        candidate.source != "trusted-core:candidate-producer"
        or candidate.source_agent_id != "trusted-core:kisa-candidate-producer"
    ):
        raise ValueError("KISA replay requires a trusted Candidate Producer source")
    source_request_ids = set(candidate.source_request_ids)
    steps = [step for step in plan.steps if step.request.request_id in source_request_ids]
    if len(steps) != len(source_request_ids) or not steps:
        raise ValueError("KISA Candidate source requests do not resolve to exact Plan steps")
    selected_step = steps[0]
    scenario = scenario_resolver(selected_step.scenario_id or "")
    if any(
        step.scenario_id != scenario.scenario_id
        or step.request.target != selected_step.request.target
        or step.threat_classes != scenario.threat_classes
        for step in steps
    ):
        raise ValueError("KISA Candidate source steps do not share one Scenario and target")
    return steps, scenario


def _source_execution_evidence(
    *,
    source_reader: SealedRunReader,
    candidate: CandidateFinding,
    steps: Sequence[PlannedStep],
    scenario: KISAScenarioDefinition,
) -> tuple[
    dict[str, ToolRequest],
    dict[str, tuple[datetime, datetime]],
    dict[str, list[str]],
]:
    source_request_ids = set(candidate.source_request_ids)
    steps_by_request = {step.request.request_id: step for step in steps}
    requests: dict[str, ToolRequest] = {}
    execution_windows: dict[str, tuple[datetime, datetime]] = {}
    evidence_by_request: dict[str, list[str]] = {
        request_id: [] for request_id in candidate.source_request_ids
    }
    for reference in candidate.claim.evidence:
        request, execution_window = _source_evidence_execution(
            source_reader=source_reader,
            reference=reference,
            steps_by_request=steps_by_request,
            source_request_ids=source_request_ids,
            scenario=scenario,
        )
        existing = requests.get(request.request_id)
        if existing is not None and existing != request:
            raise ValueError("KISA Candidate evidence contains conflicting source requests")
        existing_window = execution_windows.get(request.request_id)
        if existing_window is not None and existing_window != execution_window:
            raise ValueError("KISA Candidate evidence contains conflicting execution windows")
        requests[request.request_id] = request
        execution_windows[request.request_id] = execution_window
        evidence_by_request[request.request_id].append(reference)
    if set(requests) != source_request_ids or any(
        not references for references in evidence_by_request.values()
    ):
        raise ValueError("KISA Candidate evidence does not cover every source request")
    return requests, execution_windows, evidence_by_request


def _source_evidence_execution(
    *,
    source_reader: SealedRunReader,
    reference: str,
    steps_by_request: Mapping[str, PlannedStep],
    source_request_ids: set[str],
    scenario: KISAScenarioDefinition,
) -> tuple[ToolRequest, tuple[datetime, datetime]]:
    try:
        payload = read_object(source_reader, reference)
    except ValueError as exc:
        raise ValueError(
            "KISA Candidate evidence escaped or is missing from its source Run"
        ) from exc
    request = ToolRequest.model_validate(payload.get("request"))
    source_step = steps_by_request.get(request.request_id)
    result = payload.get("result")
    policy = payload.get("policyDecision")
    if (
        request.request_id not in source_request_ids
        or source_step is None
        or source_step.request.model_dump(mode="json", exclude={"agent_id"})
        != request.model_dump(mode="json", exclude={"agent_id"})
        or not isinstance(result, dict)
        or result.get("success") is not True
        or not isinstance(policy, dict)
        or policy.get("allowed") is not True
    ):
        raise ValueError("KISA Candidate evidence is not an allowed successful execution")
    result_with_evidence = dict(result)
    result_with_evidence["evidence"] = [reference]
    tool_result = ToolResult.model_validate(result_with_evidence)
    validate_source_transcript(
        request=request,
        tool_result=tool_result,
        worker_result=payload.get("workerResult"),
        scenario=scenario,
    )
    return request, (tool_result.started_at, tool_result.finished_at)


def validate_source_transcript(
    *,
    request: ToolRequest,
    tool_result: ToolResult,
    worker_result: object,
    scenario: KISAScenarioDefinition,
) -> None:
    if (
        tool_result.request_id != request.request_id
        or tool_result.tool_id != request.tool_id
        or not isinstance(worker_result, dict)
    ):
        raise ValueError("KISA Candidate evidence result identity is inconsistent")
    try:
        sealed_worker = WorkerResult.model_validate(worker_result)
        if (
            sealed_worker.status is not WorkerStatus.SUCCEEDED
            or sealed_worker.stdout_truncated
            or sealed_worker.stderr_truncated
            or tool_result.started_at != sealed_worker.started_at
            or tool_result.finished_at != sealed_worker.finished_at
        ):
            raise ValueError("KISA Candidate evidence Worker lifecycle is inconsistent")
        raw_output = AIChatProbeOutput.model_validate(
            decode_strict_worker_json_object(
                sealed_worker,
                label="KISA Candidate evidence Worker transcript",
            )
        )
        evaluation = evaluate_kisa_transcript(
            scenario=scenario,
            request=request,
            output_value=tool_result.data,
        )
    except ValueError as exc:
        raise ValueError("KISA Candidate evidence transcript is not trusted") from exc
    if raw_output != evaluation.output or not evaluation.supports_claim:
        raise ValueError("KISA Candidate source transcript does not support its claim")


def _resolve_source_capability_receipt(
    *,
    source_reader: SealedRunReader,
    capability_records: Sequence[CapabilityRecord],
    original_request: ToolRequest,
    execution_window: tuple[datetime, datetime],
) -> ReplaySourceCapabilityReceipt:
    matching_records = [
        record
        for record in capability_records
        if record.grant.subject == original_request.agent_id
        and original_request.tool_id in record.grant.tools
        and original_request.target in record.grant.targets
    ]
    if len(matching_records) != 1:
        raise ValueError("KISA source request does not resolve to one Specialist grant")
    execution_started_at, execution_finished_at = execution_window
    return _source_capability_receipt(
        capability_records,
        matching_records[0],
        request_id=original_request.request_id,
        execution_started_at=execution_started_at,
        execution_finished_at=execution_finished_at,
        events=source_reader.events,
    )


def _source_target_id(source_reader: SealedRunReader, endpoint: str) -> str:
    target_ids = [
        target.id
        for target in CampaignManifest.model_validate(
            read_object(source_reader, "campaign.json")
        ).spec.targets
        if target.endpoint == endpoint
    ]
    if len(target_ids) != 1:
        raise ValueError("KISA source target does not resolve to one Campaign target")
    return target_ids[0]


def _source_capability_receipt(
    capability_records: Sequence[CapabilityRecord],
    specialist_record: CapabilityRecord,
    *,
    request_id: str,
    execution_started_at: datetime,
    execution_finished_at: datetime,
    events: Sequence[AuditEvent],
) -> ReplaySourceCapabilityReceipt:
    records_by_id = _source_capability_records_by_id(capability_records)
    lineage_records = _consumed_source_capability_lineage(records_by_id, specialist_record)
    dispatch_sequence, completion_sequence = _source_worker_execution_sequences(
        events,
        request_id,
    )
    _validate_source_capability_events(
        lineage_records,
        events=events,
        dispatch_sequence=dispatch_sequence,
        completion_sequence=completion_sequence,
    )
    return ReplaySourceCapabilityReceipt(
        request_id=request_id,
        lineage=[record.grant for record in lineage_records],
        execution_started_at=execution_started_at,
        execution_finished_at=execution_finished_at,
    )


def _source_capability_records_by_id(
    capability_records: Sequence[CapabilityRecord],
) -> dict[str, CapabilityRecord]:
    records_by_id: dict[str, CapabilityRecord] = {}
    for record in capability_records:
        grant_id = record.grant.grant_id
        if grant_id in records_by_id:
            raise ValueError("KISA source capability ledger contains duplicate grant IDs")
        records_by_id[grant_id] = record
    return records_by_id


def _consumed_source_capability_lineage(
    records_by_id: Mapping[str, CapabilityRecord],
    specialist_record: CapabilityRecord,
) -> list[CapabilityRecord]:
    lineage_records: list[CapabilityRecord] = []
    seen: set[str] = set()
    current = specialist_record
    while True:
        grant = current.grant
        if grant.grant_id in seen:
            raise ValueError("KISA source capability lineage contains a cycle")
        if current.remaining_calls >= grant.max_calls:
            raise ValueError("KISA source capability lineage was not consumed")
        seen.add(grant.grant_id)
        lineage_records.append(current)
        if grant.parent_grant_id is None:
            break
        try:
            current = records_by_id[grant.parent_grant_id]
        except KeyError as exc:
            raise ValueError("KISA source capability lineage contains an orphan grant") from exc
    lineage_records.reverse()
    return lineage_records


def _source_worker_execution_sequences(
    events: Sequence[AuditEvent],
    request_id: str,
) -> tuple[int, int]:
    dispatches = [
        event
        for event in events
        if event.event_type == "worker.dispatched" and event.payload.get("requestId") == request_id
    ]
    completions = [
        event
        for event in events
        if event.event_type == "worker.completed" and event.payload.get("requestId") == request_id
    ]
    if (
        len(dispatches) != 1
        or len(completions) != 1
        or dispatches[0].sequence >= completions[0].sequence
    ):
        raise ValueError("KISA source request has no exact completed Worker dispatch")
    return dispatches[0].sequence, completions[0].sequence


def _validate_source_capability_events(
    lineage_records: Sequence[CapabilityRecord],
    *,
    events: Sequence[AuditEvent],
    dispatch_sequence: int,
    completion_sequence: int,
) -> None:
    for record in lineage_records:
        _validate_source_capability_record_events(
            record,
            events=events,
            dispatch_sequence=dispatch_sequence,
            completion_sequence=completion_sequence,
        )


def _validate_source_capability_record_events(
    record: CapabilityRecord,
    *,
    events: Sequence[AuditEvent],
    dispatch_sequence: int,
    completion_sequence: int,
) -> None:
    grant_id = record.grant.grant_id
    issuance = [
        event
        for event in events
        if event.event_type == "capability.issued" and event.payload.get("grant_id") == grant_id
    ]
    if len(issuance) != 1 or issuance[0].sequence >= dispatch_sequence:
        raise ValueError("KISA source capability was not issued before Worker dispatch")
    revocations = [
        event
        for event in events
        if event.event_type == "capability.revoked"
        and isinstance(event.payload.get("revokedGrantIds"), list)
        and grant_id in event.payload["revokedGrantIds"]
    ]
    if record.revoked != bool(revocations):
        raise ValueError("KISA source capability live revocation state is inconsistent")
    if any(event.sequence <= completion_sequence for event in revocations):
        raise ValueError("KISA source capability was revoked before execution completed")
