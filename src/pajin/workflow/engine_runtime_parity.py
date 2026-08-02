"""ENG-002B2A dual runtime fixture execution before parity admission."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.models import CampaignMode, StrictModel
from pajin.domain.orchestration import RunStatus
from pajin.policy.engine import PolicyEngine
from pajin.runtime.execution_context import WorkerExecutionContext, worker_execution_context
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry, ToolSpec
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.engine_planner_parity import (
    CommonEnginePlannerConstructorBinding,
    CommonEnginePlannerParityAuthority,
    CommonEnginePlannerPath,
    _construct_planner,
    _normalize_plan,
)
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome

COMMON_ENGINE_RUNTIME_COORDINATE_API_VERSION: Literal[
    "pajin.dev/common-engine-runtime-coordinate/v1alpha1"
] = "pajin.dev/common-engine-runtime-coordinate/v1alpha1"
COMMON_ENGINE_RUNTIME_EXECUTION_API_VERSION: Literal[
    "pajin.dev/common-engine-runtime-execution/v1alpha1"
] = "pajin.dev/common-engine-runtime-execution/v1alpha1"
COMMON_ENGINE_DUAL_RUNTIME_API_VERSION: Literal["pajin.dev/common-engine-dual-runtime/v1alpha1"] = (
    "pajin.dev/common-engine-dual-runtime/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_COORDINATE_BYTES = 2 * 1024 * 1024
_MAX_EXECUTION_BYTES = 4 * 1024 * 1024
_MAX_DUAL_BYTES = 8 * 1024 * 1024

_VALIDATOR_IDENTITIES = {
    CampaignMode.AI_REDTEAM: "pajin.modes.ai_redteam.runtime.KISAValidatorRuntime",
    CampaignMode.BUG_BOUNTY: "pajin.modes.bug_bounty.runtime.BugBountyValidatorRuntime",
    CampaignMode.CTF: "pajin.modes.ctf.runtime.CTFFlagValidatorRuntime",
}
_AI_CANDIDATE_IDENTITY = "pajin.modes.ai_redteam.candidates.KISACandidateProducer"
_DELEGATE_IDENTITY = "pajin.agents.deterministic.DeterministicAgentRuntime"
_RUNNER_IDENTITY: Literal["pajin.workflow.multi_agent.MultiAgentCampaignRunner"] = (
    "pajin.workflow.multi_agent.MultiAgentCampaignRunner"
)


class CommonEngineRuntimeParityError(RuntimeError):
    """Raised when a dual runtime fixture cannot prove its execution prerequisites."""


class CommonEngineToolRuntimeBinding(StrictModel):
    """Bind one exact ToolSpec to the implementation context that executes it."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    tool_id: str = Field(alias="toolId", min_length=1, max_length=200)
    spec: dict[str, Any]
    execution_context: dict[str, Any] = Field(alias="executionContext")

    @model_validator(mode="after")
    def bind_tool(self) -> Self:
        try:
            validated = ToolSpec.model_validate(self.spec)
        except ValueError as exc:
            raise ValueError("Tool runtime binding has an invalid ToolSpec") from exc
        if validated.tool_id != self.tool_id:
            raise ValueError("Tool runtime binding differs from its ToolSpec")
        object.__setattr__(self, "spec", _canonical_tool_spec(validated))
        return self


class CommonEngineRuntimeFixtureCoordinate(StrictModel):
    """One arm's exact semantic runtime inputs without a physical output path."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-runtime-coordinate/v1alpha1"] = Field(
        default=COMMON_ENGINE_RUNTIME_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineRuntimeFixtureCoordinate"] = "CommonEngineRuntimeFixtureCoordinate"
    path: CommonEnginePlannerPath
    source_mode: CampaignMode = Field(alias="sourceMode")
    planner_parity_digest: _Sha256 = Field(alias="plannerParityDigest")
    planner_constructor: CommonEnginePlannerConstructorBinding = Field(alias="plannerConstructor")
    validator_implementation_id: str = Field(
        alias="validatorImplementationId",
        min_length=1,
        max_length=200,
    )
    validator_delegate_implementation_id: str | None = Field(
        default=None,
        alias="validatorDelegateImplementationId",
        max_length=200,
    )
    candidate_producer_implementation_id: str | None = Field(
        default=None,
        alias="candidateProducerImplementationId",
        max_length=200,
    )
    runner_implementation_id: Literal["pajin.workflow.multi_agent.MultiAgentCampaignRunner"] = (
        Field(default=_RUNNER_IDENTITY, alias="runnerImplementationId")
    )
    tool_bindings: tuple[CommonEngineToolRuntimeBinding, ...] = Field(
        alias="toolBindings",
        min_length=1,
        max_length=100,
    )
    policy_context: dict[str, Any] = Field(alias="policyContext")
    worker_execution_context: WorkerExecutionContext = Field(alias="workerExecutionContext")
    worker_stable_context: dict[str, Any] = Field(alias="workerStableContext")
    output_role: Literal["common-engine-parity-fixture"] = Field(
        default="common-engine-parity-fixture",
        alias="outputRole",
    )
    max_parallel_specialists: Literal[4] = Field(
        default=4,
        alias="maxParallelSpecialists",
    )
    semantic_coordinate_digest: str = Field(
        default="",
        alias="semanticCoordinateDigest",
        max_length=64,
    )
    coordinate_digest: str = Field(
        default="",
        alias="coordinateDigest",
        max_length=64,
    )
    fixture_execution_authorized: Literal[True] = Field(
        default=True,
        alias="fixtureExecutionAuthorized",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        if self.planner_constructor.path is not self.path:
            raise ValueError("runtime coordinate path differs from Planner constructor")
        expected_validator = _VALIDATOR_IDENTITIES[self.source_mode]
        if self.validator_implementation_id != expected_validator:
            raise ValueError("runtime coordinate Validator differs from legacy authority")
        if self.source_mode is CampaignMode.AI_REDTEAM:
            if (
                self.validator_delegate_implementation_id != _DELEGATE_IDENTITY
                or self.candidate_producer_implementation_id != _AI_CANDIDATE_IDENTITY
            ):
                raise ValueError("AI runtime coordinate is missing exact delegate or candidate")
        elif (
            self.validator_delegate_implementation_id is not None
            or self.candidate_producer_implementation_id is not None
        ):
            raise ValueError("non-AI runtime coordinate cannot add delegate or candidate")
        tool_ids = [item.tool_id for item in self.tool_bindings]
        if tool_ids != sorted(set(tool_ids)):
            raise ValueError("runtime coordinate Tool set is not canonical")
        semantic_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"path", "coordinate_digest", "semantic_coordinate_digest"},
        )
        semantic_material["plannerConstructor"] = self.planner_constructor.model_dump(
            mode="json",
            by_alias=True,
            exclude={"path", "constructor_digest"},
        )
        semantic_digest = _common_engine_digest(
            "pajin.workflow.common-engine-runtime-semantic-coordinate/v1",
            semantic_material,
            max_bytes=_MAX_COORDINATE_BYTES,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_digest", "semantic_coordinate_digest"},
        )
        coordinate_digest = _common_engine_digest(
            "pajin.workflow.common-engine-runtime-coordinate/v1",
            material,
            max_bytes=_MAX_COORDINATE_BYTES,
        )
        if self.semantic_coordinate_digest and self.semantic_coordinate_digest != semantic_digest:
            raise ValueError("Runtime Semantic Coordinate Digest differs")
        if self.coordinate_digest and self.coordinate_digest != coordinate_digest:
            raise ValueError("Runtime Coordinate Digest differs")
        object.__setattr__(self, "semantic_coordinate_digest", semantic_digest)
        object.__setattr__(self, "coordinate_digest", coordinate_digest)
        return self


class CommonEngineRuntimeExecutionRecord(StrictModel):
    """One completed, sealed fixture Run before any parity conclusion."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-runtime-execution/v1alpha1"] = Field(
        default=COMMON_ENGINE_RUNTIME_EXECUTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineRuntimeExecutionRecord"] = "CommonEngineRuntimeExecutionRecord"
    path: CommonEnginePlannerPath
    coordinate: CommonEngineRuntimeFixtureCoordinate
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    sealed_root_digest: _Sha256 = Field(alias="sealedRootDigest")
    normalized_plan_digest: _Sha256 = Field(alias="normalizedPlanDigest")
    tool_request_ids: tuple[str, ...] = Field(
        alias="toolRequestIds",
        min_length=1,
        max_length=100,
    )
    evidence_paths: tuple[str, ...] = Field(
        alias="evidencePaths",
        min_length=1,
        max_length=100,
    )
    execution_digest: str = Field(
        default="",
        alias="executionDigest",
        max_length=64,
    )
    run_completed: Literal[True] = Field(default=True, alias="runCompleted")
    sealed_run_verified: Literal[True] = Field(default=True, alias="sealedRunVerified")
    parity_evaluated: Literal[False] = Field(default=False, alias="parityEvaluated")
    fixture_parity_proven: Literal[False] = Field(
        default=False,
        alias="fixtureParityProven",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_execution(self) -> Self:
        if (
            self.coordinate.path is not self.path
            or self.coordinate_digest != self.coordinate.coordinate_digest
            or self.tool_request_ids != tuple(sorted(set(self.tool_request_ids)))
            or self.evidence_paths != tuple(sorted(set(self.evidence_paths)))
        ):
            raise ValueError("runtime execution record differs from its coordinate")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"execution_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-runtime-execution/v1",
            material,
            max_bytes=_MAX_EXECUTION_BYTES,
        )
        if self.execution_digest and self.execution_digest != digest:
            raise ValueError("Runtime Execution Digest differs")
        object.__setattr__(self, "execution_digest", digest)
        return self


class CommonEngineDualRuntimeExecutionAuthority(StrictModel):
    """Two same-coordinate fresh Runs with parity deliberately not yet evaluated."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-dual-runtime/v1alpha1"] = Field(
        default=COMMON_ENGINE_DUAL_RUNTIME_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineDualRuntimeExecutionAuthority"] = (
        "CommonEngineDualRuntimeExecutionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    planner_parity: CommonEnginePlannerParityAuthority = Field(alias="plannerParity")
    planner_parity_digest: _Sha256 = Field(alias="plannerParityDigest")
    legacy_execution: CommonEngineRuntimeExecutionRecord = Field(alias="legacyExecution")
    adapter_execution: CommonEngineRuntimeExecutionRecord = Field(alias="adapterExecution")
    semantic_coordinate_digest: _Sha256 = Field(alias="semanticCoordinateDigest")
    distinct_run_identity: Literal[True] = Field(default=True, alias="distinctRunIdentity")
    distinct_request_identity: Literal[True] = Field(
        default=True,
        alias="distinctRequestIdentity",
    )
    distinct_evidence_identity: Literal[True] = Field(
        default=True,
        alias="distinctEvidenceIdentity",
    )
    parity_evaluated: Literal[False] = Field(default=False, alias="parityEvaluated")
    fixture_parity_proven: Literal[False] = Field(
        default=False,
        alias="fixtureParityProven",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_dual_execution(self) -> Self:
        planner = CommonEnginePlannerParityAuthority.model_validate(
            self.planner_parity.model_dump(mode="json", by_alias=True)
        )
        if (
            self.planner_parity != planner
            or self.planner_parity_digest != planner.authority_digest
            or self.legacy_execution.path is not CommonEnginePlannerPath.LEGACY_DIRECT
            or self.adapter_execution.path is not CommonEnginePlannerPath.PROFILE_ADAPTER
            or self.legacy_execution.coordinate.planner_parity_digest != planner.authority_digest
            or self.adapter_execution.coordinate.planner_parity_digest != planner.authority_digest
            or self.legacy_execution.normalized_plan_digest
            != planner.legacy_plan.semantic_plan_digest
            or self.adapter_execution.normalized_plan_digest
            != planner.adapter_plan.semantic_plan_digest
            or self.legacy_execution.coordinate.semantic_coordinate_digest
            != self.semantic_coordinate_digest
            or self.adapter_execution.coordinate.semantic_coordinate_digest
            != self.semantic_coordinate_digest
            or self.legacy_execution.run_id == self.adapter_execution.run_id
            or set(self.legacy_execution.tool_request_ids)
            & set(self.adapter_execution.tool_request_ids)
            or set(self.legacy_execution.evidence_paths)
            & set(self.adapter_execution.evidence_paths)
        ):
            raise ValueError("dual runtime execution authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "planner_parity"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-dual-runtime/v1",
            material,
            max_bytes=_MAX_DUAL_BYTES,
        )
        authority_id = f"common-engine-dual-runtime:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Dual Runtime Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Dual Runtime Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class CommonEngineRuntimeComponents:
    tools: ToolRegistry
    policy: PolicyEngine
    worker: WorkerBackend
    output_root: Path


@dataclass(frozen=True, slots=True)
class CommonEngineDualRuntimeResult:
    authority: CommonEngineDualRuntimeExecutionAuthority
    legacy_outcome: MultiAgentRunOutcome
    adapter_outcome: MultiAgentRunOutcome


async def execute_common_engine_dual_runtime_fixture(
    planner_parity: CommonEnginePlannerParityAuthority,
    *,
    legacy: CommonEngineRuntimeComponents,
    adapter: CommonEngineRuntimeComponents,
) -> CommonEngineDualRuntimeResult:
    """Execute independent same-coordinate Runs without making a parity conclusion."""

    authoritative_planner = CommonEnginePlannerParityAuthority.model_validate(
        planner_parity.model_dump(mode="json", by_alias=True)
    )
    _require_disjoint_output_roots(legacy.output_root, adapter.output_root)
    legacy_runner, legacy_coordinate = _construct_runtime(
        authoritative_planner,
        path=CommonEnginePlannerPath.LEGACY_DIRECT,
        components=legacy,
    )
    adapter_runner, adapter_coordinate = _construct_runtime(
        authoritative_planner,
        path=CommonEnginePlannerPath.PROFILE_ADAPTER,
        components=adapter,
    )
    if (
        legacy_coordinate.semantic_coordinate_digest
        != adapter_coordinate.semantic_coordinate_digest
    ):
        raise CommonEngineRuntimeParityError(
            "legacy and adapter runtime fixture coordinates differ"
        )
    campaign = authoritative_planner.adapter_selection.compilation.source_campaign
    legacy_outcome = await legacy_runner.run(campaign)
    adapter_outcome = await adapter_runner.run(campaign)
    legacy_record = _execution_record(
        authoritative_planner,
        legacy_coordinate,
        legacy_outcome,
    )
    adapter_record = _execution_record(
        authoritative_planner,
        adapter_coordinate,
        adapter_outcome,
    )
    authority = CommonEngineDualRuntimeExecutionAuthority(
        plannerParity=authoritative_planner,
        plannerParityDigest=authoritative_planner.authority_digest,
        legacyExecution=legacy_record,
        adapterExecution=adapter_record,
        semanticCoordinateDigest=legacy_coordinate.semantic_coordinate_digest,
    )
    return CommonEngineDualRuntimeResult(
        authority=authority,
        legacy_outcome=legacy_outcome,
        adapter_outcome=adapter_outcome,
    )


def _require_disjoint_output_roots(legacy: Path, adapter: Path) -> None:
    try:
        legacy_root = legacy.resolve(strict=False)
        adapter_root = adapter.resolve(strict=False)
    except OSError as exc:
        raise CommonEngineRuntimeParityError(
            "runtime fixture output roots cannot be resolved safely"
        ) from exc
    if (
        legacy_root == adapter_root
        or legacy_root in adapter_root.parents
        or adapter_root in legacy_root.parents
    ):
        raise CommonEngineRuntimeParityError(
            "legacy and adapter runtime fixture output roots must be disjoint"
        )


def _construct_runtime(
    planner_parity: CommonEnginePlannerParityAuthority,
    *,
    path: CommonEnginePlannerPath,
    components: CommonEngineRuntimeComponents,
) -> tuple[MultiAgentCampaignRunner, CommonEngineRuntimeFixtureCoordinate]:
    constructor = (
        planner_parity.legacy_constructor
        if path is CommonEnginePlannerPath.LEGACY_DIRECT
        else planner_parity.adapter_constructor
    )
    planner = _construct_planner(constructor)
    mode = planner_parity.adapter_selection.compilation.source_mode
    validator_type = _resolve_type(_VALIDATOR_IDENTITIES[mode])
    candidate = None
    delegate_id = None
    candidate_id = None
    if mode is CampaignMode.AI_REDTEAM:
        validator = validator_type(DeterministicAgentRuntime())
        candidate_type = _resolve_type(_AI_CANDIDATE_IDENTITY)
        candidate = candidate_type()
        delegate_id = _DELEGATE_IDENTITY
        candidate_id = _AI_CANDIDATE_IDENTITY
    else:
        validator = validator_type()
    tool_bindings = _tool_coordinate(
        components.tools,
        planner_parity,
    )
    coordinate = CommonEngineRuntimeFixtureCoordinate(
        path=path,
        sourceMode=mode,
        plannerParityDigest=planner_parity.authority_digest,
        plannerConstructor=constructor,
        validatorImplementationId=_VALIDATOR_IDENTITIES[mode],
        validatorDelegateImplementationId=delegate_id,
        candidateProducerImplementationId=candidate_id,
        toolBindings=tool_bindings,
        policyContext=_canonical_runtime_context(
            stable_execution_context(components.policy, component="Policy")
        ),
        workerExecutionContext=worker_execution_context(components.worker),
        workerStableContext=_canonical_runtime_context(
            stable_execution_context(
                components.worker,
                component="Worker",
            )
        ),
    )
    runner = MultiAgentCampaignRunner(
        planner=planner,
        validator=validator,
        candidate_producer=candidate,
        tools=components.tools,
        policy=components.policy,
        worker=components.worker,
        output_root=components.output_root,
    )
    return runner, coordinate


def _tool_coordinate(
    registry: ToolRegistry,
    planner_parity: CommonEnginePlannerParityAuthority,
) -> tuple[CommonEngineToolRuntimeBinding, ...]:
    plan = planner_parity.legacy_plan.normalized_plan
    required = sorted({step["request"]["tool_id"] for step in plan["steps"]})
    if sorted(registry.tool_ids()) != required:
        raise CommonEngineRuntimeParityError(
            "runtime Tool Registry must exactly match measured Planner requests"
        )
    bindings: list[CommonEngineToolRuntimeBinding] = []
    for tool_id in required:
        bindings.append(
            CommonEngineToolRuntimeBinding(
                toolId=tool_id,
                spec=_canonical_tool_spec(registry.spec(tool_id)),
                executionContext=_canonical_runtime_context(
                    stable_execution_context(
                        registry.tool(tool_id),
                        component=f"Tool {tool_id}",
                    )
                ),
            )
        )
    return tuple(bindings)


def _canonical_tool_spec(spec: ToolSpec) -> dict[str, Any]:
    payload = spec.model_dump(mode="json")
    payload["categories"] = sorted(spec.categories)
    payload["evidence_types"] = sorted(spec.evidence_types)
    return payload


def _canonical_runtime_context(value: Mapping[str, object]) -> dict[str, Any]:
    """Convert explicit stable contexts into deterministic JSON values."""

    def normalize(item: object) -> Any:
        if item is None or isinstance(item, (str, bool)):
            return item
        if isinstance(item, int):
            return int(item)
        if isinstance(item, float):
            if not math.isfinite(item):
                raise CommonEngineRuntimeParityError(
                    "runtime stable context contains a non-finite number"
                )
            return item
        if isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise CommonEngineRuntimeParityError(
                    "runtime stable context contains a non-string key"
                )
            return {key: normalize(item[key]) for key in sorted(item)}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if isinstance(item, (set, frozenset)):
            children = [normalize(child) for child in item]
            return sorted(
                children,
                key=lambda child: json.dumps(
                    child,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            )
        raise CommonEngineRuntimeParityError("runtime stable context contains a non-JSON value")

    canonical = normalize(value)
    if not isinstance(canonical, dict):  # pragma: no cover - Mapping input invariant
        raise CommonEngineRuntimeParityError("runtime stable context must be an object")
    return canonical


def _execution_record(
    planner_parity: CommonEnginePlannerParityAuthority,
    coordinate: CommonEngineRuntimeFixtureCoordinate,
    outcome: MultiAgentRunOutcome,
) -> CommonEngineRuntimeExecutionRecord:
    if outcome.status is not RunStatus.COMPLETED or outcome.plan is None:
        raise CommonEngineRuntimeParityError("runtime fixture Run did not complete")
    verification = verify_run_integrity(outcome.run_path)
    normalized = _normalize_plan(
        outcome.plan,
        path=coordinate.path,
        source_campaign_digest=planner_parity.source_campaign_digest,
        constructor_digest=coordinate.planner_constructor.constructor_digest,
    )
    measured_plan = (
        planner_parity.legacy_plan
        if coordinate.path is CommonEnginePlannerPath.LEGACY_DIRECT
        else planner_parity.adapter_plan
    )
    if normalized.normalized_plan != measured_plan.normalized_plan:
        raise CommonEngineRuntimeParityError(
            "runtime Planner output differs from ENG-002B1 measurement"
        )
    request_ids = tuple(sorted(result.request_id for result in outcome.tool_results))
    evidence_paths = tuple(
        sorted(reference for result in outcome.tool_results for reference in result.evidence)
    )
    if (
        not request_ids
        or len(request_ids) != len(set(request_ids))
        or not evidence_paths
        or len(evidence_paths) != len(set(evidence_paths))
    ):
        raise CommonEngineRuntimeParityError(
            "runtime fixture requires unique requests and sealed evidence"
        )
    return CommonEngineRuntimeExecutionRecord(
        path=coordinate.path,
        coordinate=coordinate,
        coordinateDigest=coordinate.coordinate_digest,
        runId=outcome.run_id,
        sealedRootDigest=verification.root_digest,
        normalizedPlanDigest=normalized.semantic_plan_digest,
        toolRequestIds=request_ids,
        evidencePaths=evidence_paths,
    )


def _resolve_type(identity: str) -> type[Any]:
    module_name, separator, type_name = identity.rpartition(".")
    if not separator:
        raise CommonEngineRuntimeParityError("runtime implementation identity is invalid")
    from importlib import import_module

    implementation = getattr(import_module(module_name), type_name, None)
    if not isinstance(implementation, type):
        raise CommonEngineRuntimeParityError(f"runtime implementation is unavailable: {identity}")
    return implementation
