"""ENG-002B1 deterministic Planner fixture parity without Campaign execution."""

from __future__ import annotations

from enum import StrEnum
from importlib import import_module
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import AgentPlan, CampaignManifest, CampaignMode, StrictModel
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.engine_adapter import (
    CommonEngineAdapterSelectionAuthority,
    select_common_engine_adapter,
)
from pajin.workflow.profile_compatibility import LegacyCampaignProfileCompilationAuthority

COMMON_ENGINE_PLANNER_CONSTRUCTOR_API_VERSION: Literal[
    "pajin.dev/common-engine-planner-constructor/v1alpha1"
] = "pajin.dev/common-engine-planner-constructor/v1alpha1"
COMMON_ENGINE_NORMALIZED_PLAN_API_VERSION: Literal[
    "pajin.dev/common-engine-normalized-plan/v1alpha1"
] = "pajin.dev/common-engine-normalized-plan/v1alpha1"
COMMON_ENGINE_PLANNER_PARITY_API_VERSION: Literal[
    "pajin.dev/common-engine-planner-parity/v1alpha1"
] = "pajin.dev/common-engine-planner-parity/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONSTRUCTOR_BYTES = 128 * 1024
_MAX_PLAN_BYTES = 2 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 8 * 1024 * 1024

_LEGACY_PLANNER_IDENTITIES = {
    CampaignMode.AI_REDTEAM: "pajin.modes.ai_redteam.runtime.KISAPlannerRuntime",
    CampaignMode.BUG_BOUNTY: "pajin.modes.bug_bounty.runtime.BugBountyPlannerRuntime",
    CampaignMode.CTF: "pajin.modes.ctf.runtime.CTFTriagePlannerRuntime",
}


class CommonEnginePlannerParityError(RuntimeError):
    """Raised when the opt-in Planner path differs from the legacy fixture path."""


class CommonEnginePlannerPath(StrEnum):
    LEGACY_DIRECT = "legacy-direct"
    PROFILE_ADAPTER = "profile-adapter"


class CommonEngineAIPlannerThresholds(StrictModel):
    """Exact KISA Planner threshold inputs without importing the Mode at module load."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    max_attack_success_rate: float = Field(default=0, ge=0, le=1)
    min_block_refusal_rate: float = Field(default=1, ge=0, le=1)
    max_sensitive_exposures: int = Field(default=0, ge=0)
    max_mean_latency_seconds: float = Field(default=2, gt=0)
    repetitions: int = Field(default=2, ge=1, le=20)


class _PlannerRuntime(Protocol):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan: ...


class CommonEnginePlannerConstructorBinding(StrictModel):
    """Exact Planner constructor inputs for one measured path."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-planner-constructor/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_PLANNER_CONSTRUCTOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEnginePlannerConstructorBinding"] = (
        "CommonEnginePlannerConstructorBinding"
    )
    path: CommonEnginePlannerPath
    source_mode: CampaignMode = Field(alias="sourceMode")
    planner_implementation_id: str = Field(
        alias="plannerImplementationId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    ai_thresholds: CommonEngineAIPlannerThresholds | None = Field(
        default=None,
        alias="aiThresholds",
    )
    constructor_digest: str = Field(
        default="",
        alias="constructorDigest",
        max_length=64,
    )
    tool_registry_bound: Literal[False] = Field(
        default=False,
        alias="toolRegistryBound",
    )
    policy_bound: Literal[False] = Field(default=False, alias="policyBound")
    worker_bound: Literal[False] = Field(default=False, alias="workerBound")
    output_path_bound: Literal[False] = Field(default=False, alias="outputPathBound")

    @model_validator(mode="after")
    def bind_constructor(self) -> Self:
        expected_id = _LEGACY_PLANNER_IDENTITIES[self.source_mode]
        if self.planner_implementation_id != expected_id:
            raise ValueError("Planner constructor implementation differs from legacy authority")
        if (self.source_mode is CampaignMode.AI_REDTEAM) != (self.ai_thresholds is not None):
            raise ValueError("AI thresholds must be present only for ai-redteam")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"constructor_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-planner-constructor/v1",
            material,
            max_bytes=_MAX_CONSTRUCTOR_BYTES,
        )
        if self.constructor_digest and self.constructor_digest != digest:
            raise ValueError("Planner Constructor Digest differs")
        object.__setattr__(self, "constructor_digest", digest)
        return self


class CommonEngineNormalizedPlan(StrictModel):
    """Planner output with fresh step/request identities replaced by fixture ordinals."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-normalized-plan/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_NORMALIZED_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineNormalizedPlan"] = "CommonEngineNormalizedPlan"
    path: CommonEnginePlannerPath
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    constructor_digest: _Sha256 = Field(alias="constructorDigest")
    normalized_plan: dict[str, Any] = Field(alias="normalizedPlan")
    semantic_plan_digest: str = Field(
        default="",
        alias="semanticPlanDigest",
        max_length=64,
    )
    observation_digest: str = Field(
        default="",
        alias="observationDigest",
        max_length=64,
    )

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        plan = AgentPlan.model_validate(self.normalized_plan)
        expected_step_ids = [f"fixture-step-{index}" for index in range(len(plan.steps))]
        expected_request_ids = [
            f"fixture-request-{index}" for index in range(len(plan.steps))
        ]
        if [step.step_id for step in plan.steps] != expected_step_ids:
            raise ValueError("normalized Planner step identities are not canonical")
        if [step.request.request_id for step in plan.steps] != expected_request_ids:
            raise ValueError("normalized Planner request identities are not canonical")
        normalized = _canonical_plan_payload(plan)
        if self.normalized_plan != normalized:
            raise ValueError("normalized Planner output differs from typed canonical form")
        semantic_digest = _common_engine_digest(
            "pajin.workflow.common-engine-semantic-plan/v1",
            {
                "sourceCampaignDigest": self.source_campaign_digest,
                "normalizedPlan": normalized,
            },
            max_bytes=_MAX_PLAN_BYTES,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"semantic_plan_digest", "observation_digest"},
        )
        observation_digest = _common_engine_digest(
            "pajin.workflow.common-engine-normalized-plan/v1",
            material,
            max_bytes=_MAX_PLAN_BYTES,
        )
        if self.semantic_plan_digest and self.semantic_plan_digest != semantic_digest:
            raise ValueError("Semantic Plan Digest differs")
        if self.observation_digest and self.observation_digest != observation_digest:
            raise ValueError("Normalized Plan Observation Digest differs")
        object.__setattr__(self, "semantic_plan_digest", semantic_digest)
        object.__setattr__(self, "observation_digest", observation_digest)
        object.__setattr__(self, "normalized_plan", normalized)
        return self


class CommonEnginePlannerParityAuthority(StrictModel):
    """Measured Planner parity while Capability and Outcome remain unmeasured."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-planner-parity/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_PLANNER_PARITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEnginePlannerParityAuthority"] = (
        "CommonEnginePlannerParityAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    adapter_selection: CommonEngineAdapterSelectionAuthority = Field(
        alias="adapterSelection"
    )
    adapter_selection_digest: _Sha256 = Field(alias="adapterSelectionDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    legacy_constructor: CommonEnginePlannerConstructorBinding = Field(
        alias="legacyConstructor"
    )
    adapter_constructor: CommonEnginePlannerConstructorBinding = Field(
        alias="adapterConstructor"
    )
    legacy_plan: CommonEngineNormalizedPlan = Field(alias="legacyPlan")
    adapter_plan: CommonEngineNormalizedPlan = Field(alias="adapterPlan")
    measured_dimensions: tuple[Literal["scope", "tool-request"], ...] = Field(
        default=("scope", "tool-request"),
        alias="measuredDimensions",
        min_length=2,
        max_length=2,
    )
    unmeasured_dimensions: tuple[Literal["capability", "outcome"], ...] = Field(
        default=("capability", "outcome"),
        alias="unmeasuredDimensions",
        min_length=2,
        max_length=2,
    )
    planner_behavior_measured: Literal[True] = Field(
        default=True,
        alias="plannerBehaviorMeasured",
    )
    planner_parity_proven: Literal[True] = Field(
        default=True,
        alias="plannerParityProven",
    )
    fixture_parity_proven: Literal[False] = Field(
        default=False,
        alias="fixtureParityProven",
    )
    capability_parity_proven: Literal[False] = Field(
        default=False,
        alias="capabilityParityProven",
    )
    outcome_parity_proven: Literal[False] = Field(
        default=False,
        alias="outcomeParityProven",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    common_engine_runtime_constructed: Literal[False] = Field(
        default=False,
        alias="commonEngineRuntimeConstructed",
    )
    worker_invoked: Literal[False] = Field(default=False, alias="workerInvoked")
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        selection = CommonEngineAdapterSelectionAuthority.model_validate(
            self.adapter_selection.model_dump(mode="json", by_alias=True)
        )
        mode = selection.compilation.source_mode
        if (
            self.measured_dimensions != ("scope", "tool-request")
            or self.unmeasured_dimensions != ("capability", "outcome")
            or self.adapter_selection != selection
            or self.adapter_selection_digest != selection.authority_digest
            or self.source_campaign_digest != selection.source_campaign_digest
            or self.legacy_constructor.path is not CommonEnginePlannerPath.LEGACY_DIRECT
            or self.adapter_constructor.path is not CommonEnginePlannerPath.PROFILE_ADAPTER
            or self.legacy_constructor.source_mode is not mode
            or self.adapter_constructor.source_mode is not mode
            or self.legacy_constructor.planner_implementation_id
            != selection.adapter.planner.implementation_id
            or self.adapter_constructor.planner_implementation_id
            != selection.adapter.planner.implementation_id
            or self.legacy_constructor.ai_thresholds
            != self.adapter_constructor.ai_thresholds
            or self.legacy_plan.path is not CommonEnginePlannerPath.LEGACY_DIRECT
            or self.adapter_plan.path is not CommonEnginePlannerPath.PROFILE_ADAPTER
            or self.legacy_plan.source_campaign_digest != self.source_campaign_digest
            or self.adapter_plan.source_campaign_digest != self.source_campaign_digest
            or self.legacy_plan.constructor_digest
            != self.legacy_constructor.constructor_digest
            or self.adapter_plan.constructor_digest
            != self.adapter_constructor.constructor_digest
            or self.legacy_plan.normalized_plan != self.adapter_plan.normalized_plan
            or self.legacy_plan.semantic_plan_digest
            != self.adapter_plan.semantic_plan_digest
        ):
            raise ValueError("Common Engine Planner parity authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "adapter_selection"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-planner-parity/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"common-engine-planner-parity:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Common Engine Planner Parity Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Common Engine Planner Parity Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


async def measure_common_engine_planner_parity(
    compilation: LegacyCampaignProfileCompilationAuthority,
    *,
    ai_thresholds: CommonEngineAIPlannerThresholds | None = None,
) -> CommonEnginePlannerParityAuthority:
    """Run both Planner construction paths and compare normalized ToolRequests."""

    authoritative_compilation = LegacyCampaignProfileCompilationAuthority.model_validate(
        compilation.model_dump(mode="json", by_alias=True)
    )
    selection = select_common_engine_adapter(authoritative_compilation)
    mode = authoritative_compilation.source_mode
    thresholds = None
    if mode is CampaignMode.AI_REDTEAM:
        thresholds = ai_thresholds or CommonEngineAIPlannerThresholds()
    if mode is not CampaignMode.AI_REDTEAM and ai_thresholds is not None:
        raise CommonEnginePlannerParityError(
            "AI thresholds cannot be supplied for a non-ai-redteam Planner"
        )
    implementation_id = _LEGACY_PLANNER_IDENTITIES[mode]
    if selection.adapter.planner.implementation_id != implementation_id:
        raise CommonEnginePlannerParityError(
            "selected Planner differs from the legacy direct implementation"
        )
    legacy_constructor = CommonEnginePlannerConstructorBinding(
        path=CommonEnginePlannerPath.LEGACY_DIRECT,
        sourceMode=mode,
        plannerImplementationId=implementation_id,
        aiThresholds=thresholds,
    )
    adapter_constructor = CommonEnginePlannerConstructorBinding(
        path=CommonEnginePlannerPath.PROFILE_ADAPTER,
        sourceMode=mode,
        plannerImplementationId=selection.adapter.planner.implementation_id,
        aiThresholds=thresholds,
    )
    legacy_planner = _construct_planner(legacy_constructor)
    adapter_planner = _construct_planner(adapter_constructor)
    legacy_raw = await legacy_planner.plan(authoritative_compilation.source_campaign)
    adapter_raw = await adapter_planner.plan(authoritative_compilation.source_campaign)
    legacy_plan = _normalize_plan(
        legacy_raw,
        path=CommonEnginePlannerPath.LEGACY_DIRECT,
        source_campaign_digest=authoritative_compilation.input_digest,
        constructor_digest=legacy_constructor.constructor_digest,
    )
    adapter_plan = _normalize_plan(
        adapter_raw,
        path=CommonEnginePlannerPath.PROFILE_ADAPTER,
        source_campaign_digest=authoritative_compilation.input_digest,
        constructor_digest=adapter_constructor.constructor_digest,
    )
    if legacy_plan.normalized_plan != adapter_plan.normalized_plan:
        raise CommonEnginePlannerParityError(
            "legacy and Profile adapter Planner outputs differ"
        )
    return CommonEnginePlannerParityAuthority(
        adapterSelection=selection,
        adapterSelectionDigest=selection.authority_digest,
        sourceCampaignDigest=authoritative_compilation.input_digest,
        legacyConstructor=legacy_constructor,
        adapterConstructor=adapter_constructor,
        legacyPlan=legacy_plan,
        adapterPlan=adapter_plan,
    )


def _construct_planner(
    binding: CommonEnginePlannerConstructorBinding,
) -> _PlannerRuntime:
    module_name, separator, type_name = binding.planner_implementation_id.rpartition(".")
    if not separator:
        raise CommonEnginePlannerParityError("Planner implementation identity is invalid")
    implementation = getattr(import_module(module_name), type_name, None)
    if not isinstance(implementation, type):
        raise CommonEnginePlannerParityError(
            f"Planner implementation is unavailable: {binding.planner_implementation_id}"
        )
    if binding.source_mode is CampaignMode.AI_REDTEAM:
        threshold_type = getattr(
            import_module("pajin.modes.ai_redteam.models"),
            "EvaluationThresholds",
            None,
        )
        if not isinstance(threshold_type, type) or binding.ai_thresholds is None:
            raise CommonEnginePlannerParityError("KISA threshold contract is unavailable")
        thresholds = threshold_type(**binding.ai_thresholds.model_dump(mode="json"))
        if thresholds.model_dump(mode="json") != binding.ai_thresholds.model_dump(mode="json"):
            raise CommonEnginePlannerParityError("KISA threshold conversion changed semantics")
        runtime = implementation(thresholds=thresholds)
    else:
        runtime = implementation()
    runtime_id = f"{type(runtime).__module__}.{type(runtime).__qualname__}"
    if runtime_id != binding.planner_implementation_id or not hasattr(runtime, "plan"):
        raise CommonEnginePlannerParityError("constructed Planner differs from its binding")
    return cast(_PlannerRuntime, runtime)


def _normalize_plan(
    plan: AgentPlan,
    *,
    path: CommonEnginePlannerPath,
    source_campaign_digest: str,
    constructor_digest: str,
) -> CommonEngineNormalizedPlan:
    authoritative = AgentPlan.model_validate(plan.model_dump(mode="json", by_alias=True))
    payload = _canonical_plan_payload(authoritative)
    for index, step in enumerate(payload["steps"]):
        step["step_id"] = f"fixture-step-{index}"
        step["request"]["request_id"] = f"fixture-request-{index}"
    return CommonEngineNormalizedPlan(
        path=path,
        sourceCampaignDigest=source_campaign_digest,
        constructorDigest=constructor_digest,
        normalizedPlan=payload,
    )


def _canonical_plan_payload(plan: AgentPlan) -> dict[str, Any]:
    payload = plan.model_dump(mode="json", by_alias=True)
    for step in payload["steps"]:
        step["threat_classes"] = sorted(step["threat_classes"])
    return payload
