"""ENG-002B2B sealed behavioral parity admission for the Common Engine adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    StrictModel,
    campaign_manifest_digest,
)
from pajin.domain.orchestration import AgentRole, RunStatus
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    AuditEvent,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.engine_planner_parity import CommonEnginePlannerPath
from pajin.workflow.engine_runtime_parity import (
    CommonEngineDualRuntimeExecutionAuthority,
    CommonEngineDualRuntimeResult,
    CommonEngineRuntimeExecutionRecord,
)
from pajin.workflow.multi_agent import MultiAgentRunOutcome

COMMON_ENGINE_NORMALIZED_BEHAVIOR_API_VERSION: Literal[
    "pajin.dev/common-engine-normalized-behavior/v1alpha1"
] = "pajin.dev/common-engine-normalized-behavior/v1alpha1"
COMMON_ENGINE_BEHAVIORAL_PARITY_API_VERSION: Literal[
    "pajin.dev/common-engine-behavioral-parity/v1alpha1"
] = "pajin.dev/common-engine-behavioral-parity/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_OBSERVATION_BYTES = 32 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 64 * 1024 * 1024
_PARITY_DIMENSIONS = ("scope", "capability", "tool-request", "outcome")
_FRESH_TIME_KEYS = frozenset(
    {
        "created_at",
        "createdAt",
        "dateTime",
        "decided_at",
        "decidedAt",
        "finished_at",
        "finishedAt",
        "generated_at",
        "generatedAt",
        "issued_at",
        "issuedAt",
        "occurred_at",
        "occurredAt",
        "sealed_at",
        "sealedAt",
        "started_at",
        "startedAt",
    }
)
_UNORDERED_LIST_KEYS = frozenset(
    {
        "depends_on",
        "evidence_types",
        "executed",
        "impact_dimensions",
        "layers",
        "allowed_methods",
        "allowedMethods",
        "allowed_tool_categories",
        "allowedToolCategories",
        "categories",
        "prohibit",
        "requested",
        "source_pdf_pages",
        "stop_on",
        "stopOn",
        "target_types",
        "targets",
        "threat_classes",
        "tools",
        "untested",
    }
)


class CommonEngineBehavioralParityError(RuntimeError):
    """Raised when sealed dual-runtime evidence cannot prove behavioral parity."""


class CommonEngineNormalizedBehaviorObservation(StrictModel):
    """One arm's complete normalized behavioral evidence and source lineage."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-normalized-behavior/v1alpha1"] = Field(
        default=COMMON_ENGINE_NORMALIZED_BEHAVIOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineNormalizedBehaviorObservation"] = (
        "CommonEngineNormalizedBehaviorObservation"
    )
    path: CommonEnginePlannerPath
    source_mode: CampaignMode = Field(alias="sourceMode")
    dual_runtime_digest: _Sha256 = Field(alias="dualRuntimeDigest")
    source_execution_digest: _Sha256 = Field(alias="sourceExecutionDigest")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    final_root_digest: _Sha256 = Field(alias="finalRootDigest")
    mode_source_digest: _Sha256 = Field(alias="modeSourceDigest")
    normalized_scope: dict[str, Any] = Field(alias="normalizedScope")
    normalized_capability: dict[str, Any] = Field(alias="normalizedCapability")
    normalized_tool_request: dict[str, Any] = Field(alias="normalizedToolRequest")
    normalized_receipt: dict[str, Any] = Field(alias="normalizedReceipt")
    normalized_outcome: dict[str, Any] = Field(alias="normalizedOutcome")
    normalized_mode_processing: dict[str, Any] = Field(alias="normalizedModeProcessing")
    scope_digest: str = Field(default="", alias="scopeDigest", max_length=64)
    capability_digest: str = Field(default="", alias="capabilityDigest", max_length=64)
    tool_request_digest: str = Field(default="", alias="toolRequestDigest", max_length=64)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    outcome_digest: str = Field(default="", alias="outcomeDigest", max_length=64)
    mode_processing_digest: str = Field(
        default="",
        alias="modeProcessingDigest",
        max_length=64,
    )
    semantic_behavior_digest: str = Field(
        default="",
        alias="semanticBehaviorDigest",
        max_length=64,
    )
    observation_digest: str = Field(
        default="",
        alias="observationDigest",
        max_length=64,
    )
    postprocessing_completed: Literal[True] = Field(
        default=True,
        alias="postprocessingCompleted",
    )
    parity_evaluated: Literal[False] = Field(default=False, alias="parityEvaluated")
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        if self.final_root_digest == self.source_root_digest:
            raise ValueError("Mode processing did not extend the dual-runtime source Run")
        _validate_normalized_observation_structure(self)
        axes = {
            "scope": self.normalized_scope,
            "capability": self.normalized_capability,
            "tool-request": self.normalized_tool_request,
            "receipt": self.normalized_receipt,
            "outcome": self.normalized_outcome,
            "mode-processing": self.normalized_mode_processing,
        }
        digests = {
            name: _common_engine_digest(
                f"pajin.workflow.common-engine-normalized-{name}/v1",
                payload,
                max_bytes=_MAX_OBSERVATION_BYTES,
            )
            for name, payload in axes.items()
        }
        supplied = {
            "scope": self.scope_digest,
            "capability": self.capability_digest,
            "tool-request": self.tool_request_digest,
            "receipt": self.receipt_digest,
            "outcome": self.outcome_digest,
            "mode-processing": self.mode_processing_digest,
        }
        if any(supplied[name] and supplied[name] != digest for name, digest in digests.items()):
            raise ValueError("Normalized Behavior axis digest differs")
        semantic_material = {
            "sourceMode": self.source_mode.value,
            "modeSourceDigest": self.mode_source_digest,
            "axisDigests": digests,
        }
        semantic_digest = _common_engine_digest(
            "pajin.workflow.common-engine-semantic-behavior/v1",
            semantic_material,
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "scope_digest",
                "capability_digest",
                "tool_request_digest",
                "receipt_digest",
                "outcome_digest",
                "mode_processing_digest",
                "semantic_behavior_digest",
                "observation_digest",
            },
        )
        material["axisDigests"] = digests
        observation_digest = _common_engine_digest(
            "pajin.workflow.common-engine-normalized-behavior-observation/v1",
            material,
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        if self.semantic_behavior_digest and self.semantic_behavior_digest != semantic_digest:
            raise ValueError("Semantic Behavior Digest differs")
        if self.observation_digest and self.observation_digest != observation_digest:
            raise ValueError("Behavior Observation Digest differs")
        for field_name, axis in (
            ("scope_digest", "scope"),
            ("capability_digest", "capability"),
            ("tool_request_digest", "tool-request"),
            ("receipt_digest", "receipt"),
            ("outcome_digest", "outcome"),
            ("mode_processing_digest", "mode-processing"),
        ):
            object.__setattr__(self, field_name, digests[axis])
        object.__setattr__(self, "semantic_behavior_digest", semantic_digest)
        object.__setattr__(self, "observation_digest", observation_digest)
        return self


def _validate_normalized_observation_structure(
    observation: CommonEngineNormalizedBehaviorObservation,
) -> None:
    if set(observation.normalized_scope) != {"campaignDigest", "normalizedPlan"}:
        raise ValueError("normalized Scope evidence is incomplete")
    if set(observation.normalized_capability) != {
        "agents",
        "taskGraph",
        "capabilities",
    }:
        raise ValueError("normalized Capability evidence is incomplete")
    tool_request = observation.normalized_tool_request
    if set(tool_request) != {"planRequests", "executionRequests"}:
        raise ValueError("normalized ToolRequest evidence is incomplete")
    plan_requests = tool_request["planRequests"]
    execution_requests = tool_request["executionRequests"]
    receipt_evidence = observation.normalized_receipt.get("evidence")
    outcome_evidence = observation.normalized_outcome.get("evidence")
    if (
        not isinstance(plan_requests, list)
        or not isinstance(execution_requests, list)
        or not isinstance(receipt_evidence, list)
        or not isinstance(outcome_evidence, list)
        or not plan_requests
        or len(
            {
                len(plan_requests),
                len(execution_requests),
                len(receipt_evidence),
                len(outcome_evidence),
            }
        )
        != 1
    ):
        raise ValueError("normalized request, receipt, and Outcome cardinality differs")
    required_receipt = {
        "networkLogTrusted",
        "policyDecision",
        "result",
        "workerJob",
        "workerResult",
    }
    if any(
        not isinstance(item, dict) or set(item) != required_receipt for item in receipt_evidence
    ):
        raise ValueError("normalized receipt evidence is incomplete")
    required_outcome = {
        "status",
        "plan",
        "agents",
        "taskGraph",
        "toolResults",
        "findings",
        "validation",
        "cancellationReason",
        "evidence",
    }
    if set(observation.normalized_outcome) != required_outcome:
        raise ValueError("normalized Outcome evidence is incomplete")
    mode_roles = _validate_mode_processing_structure(observation.normalized_mode_processing)
    if observation.source_mode is CampaignMode.AI_REDTEAM:
        expected_roles = {
            "assessment",
            "checklist",
            "test-plan",
            "completion-report",
            "execution-log",
            "report",
        }
        if mode_roles != expected_roles:
            raise ValueError("normalized AI Mode processing evidence is incomplete")
    elif observation.source_mode is CampaignMode.BUG_BOUNTY:
        if not {"triage", "report"} <= mode_roles or any(
            role not in {"triage", "report"} and not role.startswith("submission:")
            for role in mode_roles
        ):
            raise ValueError("normalized Bug Bounty processing evidence is incomplete")
    elif mode_roles != {"result", "writeup"}:
        raise ValueError("normalized CTF Mode processing evidence is incomplete")


def _validate_mode_processing_structure(mode_processing: dict[str, Any]) -> set[str]:
    if set(mode_processing) != {"artifactInventory", "artifacts", "auditEvents"}:
        raise ValueError("normalized Mode processing evidence is incomplete")
    mode_artifacts = mode_processing["artifacts"]
    artifact_inventory = mode_processing["artifactInventory"]
    audit_events = mode_processing["auditEvents"]
    if (
        not isinstance(mode_artifacts, dict)
        or not isinstance(artifact_inventory, dict)
        or set(artifact_inventory) != set(mode_artifacts)
        or not isinstance(audit_events, list)
    ):
        raise ValueError("normalized Mode processing structure is incomplete")
    mode_roles = set(mode_artifacts)
    if artifact_inventory != {
        role: f"fixture-mode-artifact:{role}" for role in sorted(mode_roles)
    }:
        raise ValueError("normalized Mode artifact inventory is not canonical")
    expected_event_keys = {
        "ordinal",
        "eventId",
        "runId",
        "eventType",
        "occurredAt",
        "payload",
    }
    if any(
        not isinstance(event, dict)
        or set(event) != expected_event_keys
        or event["ordinal"] != ordinal
        or event["eventId"] != f"fixture-mode-event-{ordinal}"
        or event["runId"] != "fixture-run"
        or event["occurredAt"] != "<fresh-time:occurredAt>"
        for ordinal, event in enumerate(audit_events)
    ):
        raise ValueError("normalized Mode audit suffix is not canonical")
    return mode_roles


class CommonEngineBehavioralParityAuthority(StrictModel):
    """Admit exact parity while keeping Envelope and Common execution disabled."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/common-engine-behavioral-parity/v1alpha1"] = Field(
        default=COMMON_ENGINE_BEHAVIORAL_PARITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineBehavioralParityAuthority"] = "CommonEngineBehavioralParityAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    dual_runtime: CommonEngineDualRuntimeExecutionAuthority = Field(alias="dualRuntime")
    dual_runtime_digest: _Sha256 = Field(alias="dualRuntimeDigest")
    legacy_observation: CommonEngineNormalizedBehaviorObservation = Field(alias="legacyObservation")
    adapter_observation: CommonEngineNormalizedBehaviorObservation = Field(
        alias="adapterObservation"
    )
    semantic_behavior_digest: _Sha256 = Field(alias="semanticBehaviorDigest")
    measured_dimensions: tuple[str, ...] = Field(
        alias="measuredDimensions",
        min_length=4,
        max_length=4,
    )
    proven_dimensions: tuple[str, ...] = Field(
        alias="provenDimensions",
        min_length=4,
        max_length=4,
    )
    receipt_parity_proven: Literal[True] = Field(
        default=True,
        alias="receiptParityProven",
    )
    mode_postprocessing_parity_proven: Literal[True] = Field(
        default=True,
        alias="modePostprocessingParityProven",
    )
    fixture_parity_proven: Literal[True] = Field(
        default=True,
        alias="fixtureParityProven",
    )
    profile_adapter_parity_admitted: Literal[True] = Field(
        default=True,
        alias="profileAdapterParityAdmitted",
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
    def bind_authority(self) -> Self:
        dual = CommonEngineDualRuntimeExecutionAuthority.model_validate(
            self.dual_runtime.model_dump(mode="json", by_alias=True)
        )
        legacy = self.legacy_observation
        adapter = self.adapter_observation
        if (
            self.dual_runtime != dual
            or self.dual_runtime_digest != dual.authority_digest
            or self.measured_dimensions != _PARITY_DIMENSIONS
            or self.proven_dimensions != _PARITY_DIMENSIONS
            or legacy.path is not CommonEnginePlannerPath.LEGACY_DIRECT
            or adapter.path is not CommonEnginePlannerPath.PROFILE_ADAPTER
            or legacy.dual_runtime_digest != dual.authority_digest
            or adapter.dual_runtime_digest != dual.authority_digest
            or not _observation_matches_execution(legacy, dual.legacy_execution)
            or not _observation_matches_execution(adapter, dual.adapter_execution)
            or legacy.source_mode is not adapter.source_mode
            or legacy.final_root_digest == adapter.final_root_digest
            or legacy.mode_source_digest != adapter.mode_source_digest
            or legacy.normalized_scope != adapter.normalized_scope
            or legacy.normalized_capability != adapter.normalized_capability
            or legacy.normalized_tool_request != adapter.normalized_tool_request
            or legacy.normalized_receipt != adapter.normalized_receipt
            or legacy.normalized_outcome != adapter.normalized_outcome
            or legacy.normalized_mode_processing != adapter.normalized_mode_processing
            or legacy.semantic_behavior_digest != adapter.semantic_behavior_digest
            or self.semantic_behavior_digest != legacy.semantic_behavior_digest
        ):
            raise ValueError("Common Engine behavioral parity evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "dual_runtime"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-behavioral-parity/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"common-engine-behavioral-parity:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Behavioral Parity Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Behavioral Parity Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class CommonEngineBehavioralParityResult:
    authority: CommonEngineBehavioralParityAuthority
    legacy_outcome: MultiAgentRunOutcome
    adapter_outcome: MultiAgentRunOutcome


@dataclass(frozen=True, slots=True)
class _ModeArtifacts:
    mode_source_digest: str
    paths: dict[str, Path]
    identities: tuple[tuple[str, str], ...] = ()


def measure_common_engine_behavioral_parity(
    dual_result: CommonEngineDualRuntimeResult,
    *,
    mode_source: object | None = None,
) -> CommonEngineBehavioralParityResult:
    """Run exact Mode post-processing and admit parity from fresh sealed snapshots."""

    dual = CommonEngineDualRuntimeExecutionAuthority.model_validate(
        dual_result.authority.model_dump(mode="json", by_alias=True)
    )
    _require_source_outcome(dual.legacy_execution, dual_result.legacy_outcome)
    _require_source_outcome(dual.adapter_execution, dual_result.adapter_outcome)
    campaign = dual.planner_parity.adapter_selection.compilation.source_campaign
    mode = campaign.spec.mode
    _validate_mode_source(mode, campaign, mode_source)
    legacy_mode = _run_mode_processing(
        mode,
        campaign,
        dual_result.legacy_outcome,
        dual,
        mode_source,
    )
    adapter_mode = _run_mode_processing(
        mode,
        campaign,
        dual_result.adapter_outcome,
        dual,
        mode_source,
    )
    if legacy_mode.mode_source_digest != adapter_mode.mode_source_digest:
        raise CommonEngineBehavioralParityError("Mode processing source digests differ")
    legacy_observation = _normalized_observation(
        dual,
        dual.legacy_execution,
        dual_result.legacy_outcome,
        legacy_mode,
    )
    adapter_observation = _normalized_observation(
        dual,
        dual.adapter_execution,
        dual_result.adapter_outcome,
        adapter_mode,
    )
    try:
        authority = CommonEngineBehavioralParityAuthority(
            dualRuntime=dual,
            dualRuntimeDigest=dual.authority_digest,
            legacyObservation=legacy_observation,
            adapterObservation=adapter_observation,
            semanticBehaviorDigest=legacy_observation.semantic_behavior_digest,
            measuredDimensions=_PARITY_DIMENSIONS,
            provenDimensions=_PARITY_DIMENSIONS,
        )
    except ValueError as exc:
        raise CommonEngineBehavioralParityError(
            "legacy and adapter sealed behavior differs"
        ) from exc
    return CommonEngineBehavioralParityResult(
        authority=authority,
        legacy_outcome=dual_result.legacy_outcome,
        adapter_outcome=dual_result.adapter_outcome,
    )


def _observation_matches_execution(
    observation: CommonEngineNormalizedBehaviorObservation,
    execution: CommonEngineRuntimeExecutionRecord,
) -> bool:
    return (
        observation.source_execution_digest == execution.execution_digest
        and observation.source_run_id == execution.run_id
        and observation.source_root_digest == execution.sealed_root_digest
        and observation.source_mode is execution.coordinate.source_mode
    )


def _require_source_outcome(
    execution: CommonEngineRuntimeExecutionRecord,
    outcome: MultiAgentRunOutcome,
) -> None:
    if (
        outcome.run_id != execution.run_id
        or outcome.status is not RunStatus.COMPLETED
        or outcome.plan is None
    ):
        raise CommonEngineBehavioralParityError(
            "dual runtime outcome differs from its completed source execution"
        )
    try:
        snapshot = load_verified_run_snapshot(
            outcome.run_path,
            expected_run_id=execution.run_id,
        )
    except ValueError as exc:
        raise CommonEngineBehavioralParityError(
            "dual runtime source integrity verification failed"
        ) from exc
    if snapshot.verification.root_digest != execution.sealed_root_digest:
        raise CommonEngineBehavioralParityError(
            "dual runtime source was extended or replaced before parity admission"
        )


def _validate_mode_source(
    mode: CampaignMode,
    campaign: CampaignManifest,
    mode_source: object | None,
) -> None:
    if mode is CampaignMode.AI_REDTEAM:
        if mode_source is not None:
            raise CommonEngineBehavioralParityError("AI parity does not accept a Mode source")
        return
    if mode is CampaignMode.BUG_BOUNTY:
        from pajin.modes.bug_bounty import BugBountyProgramManifest, BugBountyReportService

        if not isinstance(mode_source, BugBountyProgramManifest):
            raise CommonEngineBehavioralParityError(
                "Bug Bounty parity requires its exact Program manifest"
            )
        try:
            BugBountyReportService().validate_campaign(mode_source, campaign)
        except ValueError as exc:
            raise CommonEngineBehavioralParityError(
                "Bug Bounty Program differs from the parity Campaign"
            ) from exc
        return
    from pajin.modes.ctf import CTFChallengeManifest, CTFChallengeService

    if not isinstance(mode_source, CTFChallengeManifest):
        raise CommonEngineBehavioralParityError("CTF parity requires its exact Challenge manifest")
    expected = CTFChallengeService().compile_campaign(
        mode_source,
        evaluated_at=mode_source.spec.authorization.approved_at,
    )
    if campaign != expected:
        raise CommonEngineBehavioralParityError("CTF Challenge differs from the parity Campaign")


def _run_mode_processing(
    mode: CampaignMode,
    campaign: CampaignManifest,
    outcome: MultiAgentRunOutcome,
    dual: CommonEngineDualRuntimeExecutionAuthority,
    mode_source: object | None,
) -> _ModeArtifacts:
    if mode is CampaignMode.AI_REDTEAM:
        from pajin.modes.ai_redteam import KISA_CATALOG, KISAModePack
        from pajin.modes.ai_redteam.models import EvaluationThresholds

        thresholds = dual.planner_parity.legacy_constructor.ai_thresholds
        if thresholds is None:
            raise CommonEngineBehavioralParityError("AI parity is missing Planner thresholds")
        threshold_payload = thresholds.model_dump(mode="json")
        ai_result = KISAModePack(
            thresholds=EvaluationThresholds.model_validate(threshold_payload)
        ).evaluate(campaign, outcome)
        source_digest = _common_engine_digest(
            "pajin.workflow.common-engine-ai-mode-source/v1",
            {
                "processor": "pajin.modes.ai_redteam.service.KISAModePack",
                "thresholds": threshold_payload,
                "catalog": _normalize(
                    {
                        "threats": [item.model_dump(mode="json") for item in KISA_CATALOG.threats],
                        "scenarios": [
                            item.model_dump(mode="json") for item in KISA_CATALOG.scenarios
                        ],
                        "checklist": [
                            item.model_dump(mode="json") for item in KISA_CATALOG.checklist
                        ],
                    },
                    {},
                ),
            },
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        return _ModeArtifacts(
            mode_source_digest=source_digest,
            paths={
                "assessment": outcome.run_path / "kisa-results.json",
                "checklist": ai_result.checklist_path,
                "test-plan": ai_result.test_plan_path,
                "completion-report": ai_result.completion_report_path,
                "execution-log": ai_result.execution_log_path,
                "report": ai_result.report_path,
            },
        )
    if mode is CampaignMode.BUG_BOUNTY:
        from pajin.modes.bug_bounty import BugBountyProgramManifest, BugBountyReportService

        assert isinstance(mode_source, BugBountyProgramManifest)
        bug_result = BugBountyReportService().report_run(
            mode_source,
            outcome.run_path,
            generated_at=campaign.spec.authorization.approved_at,
        )
        source_digest = _mode_model_digest("bug-bounty", mode_source)
        paths = {
            "triage": bug_result.triage_path,
            "report": bug_result.report_path,
        }
        paths.update(
            {
                f"submission:{index}": submission_path
                for index, submission_path in enumerate(bug_result.submission_paths)
            }
        )
        return _ModeArtifacts(
            mode_source_digest=source_digest,
            paths=paths,
            identities=((bug_result.report.report_id, "fixture-mode-report"),),
        )
    from pajin.modes.ctf import CTFChallengeManifest, CTFModePack

    assert isinstance(mode_source, CTFChallengeManifest)
    ctf_result = CTFModePack().finalize(mode_source, outcome)
    return _ModeArtifacts(
        mode_source_digest=_mode_model_digest("ctf", mode_source),
        paths={"result": ctf_result.result_path, "writeup": ctf_result.writeup_path},
    )


def _mode_model_digest(mode: str, source: Any) -> str:
    return _common_engine_digest(
        f"pajin.workflow.common-engine-{mode}-mode-source/v1",
        _normalize(source.model_dump(mode="json", by_alias=True), {}),
        max_bytes=_MAX_OBSERVATION_BYTES,
    )


def _relative_mode_path(run_path: Path, artifact_path: Path) -> str:
    try:
        return artifact_path.resolve().relative_to(run_path.resolve()).as_posix()
    except (OSError, ValueError) as exc:
        raise CommonEngineBehavioralParityError(
            "Mode processing artifact path escapes its source Run"
        ) from exc


def _normalized_observation(
    dual: CommonEngineDualRuntimeExecutionAuthority,
    execution: CommonEngineRuntimeExecutionRecord,
    outcome: MultiAgentRunOutcome,
    mode_artifacts: _ModeArtifacts,
) -> CommonEngineNormalizedBehaviorObservation:
    requests = {
        "capabilities.json": _MAX_ARTIFACT_BYTES,
        **{path: _MAX_ARTIFACT_BYTES for path in execution.evidence_paths},
    }
    mode_paths: dict[str, str] = {}
    root = outcome.run_path.resolve()
    for role, artifact_path in mode_artifacts.paths.items():
        relative = _relative_mode_path(root, artifact_path)
        mode_paths[role] = relative
        requests[relative] = _MAX_ARTIFACT_BYTES
    snapshot = load_verified_run_artifacts(
        root,
        requests=requests,
        expected_run_id=execution.run_id,
    )
    if not any(seal.root_digest == execution.sealed_root_digest for seal in snapshot.seals):
        raise CommonEngineBehavioralParityError(
            "Mode processing Run does not extend the exact dual-runtime source root"
        )
    ordered_evidence_paths = _ordered_evidence_paths(outcome, snapshot, execution)
    identities = _identity_mapping(
        outcome,
        snapshot,
        ordered_evidence_paths,
        mode_artifacts.identities,
    )
    for role, relative in mode_paths.items():
        _add_identity(identities, relative, f"fixture-mode-artifact:{role}")
    extension_events = _validate_mode_extension(snapshot, execution, mode_paths)
    capabilities = _normalize(
        _strict_json(snapshot, "capabilities.json"),
        identities,
    )
    evidence = []
    evidence_requests = []
    evidence_receipts = []
    for evidence_path in ordered_evidence_paths:
        payload = _strict_json(snapshot, evidence_path)
        required_evidence_fields = {
            "networkLogTrusted",
            "policyDecision",
            "request",
            "result",
            "workerJob",
            "workerResult",
        }
        if not isinstance(payload, dict) or not required_evidence_fields <= set(payload):
            raise CommonEngineBehavioralParityError("sealed Tool evidence is incomplete")
        normalized = _normalize(payload, identities)
        evidence.append(
            {
                "path": _replace_identities(evidence_path, identities),
                "payload": normalized,
            }
        )
        evidence_requests.append(normalized["request"])
        evidence_receipts.append(
            {
                key: normalized[key]
                for key in (
                    "networkLogTrusted",
                    "policyDecision",
                    "result",
                    "workerJob",
                    "workerResult",
                )
                if key in normalized
            }
        )
    mode_artifact_payload: dict[str, Any] = {}
    for role, relative in sorted(mode_paths.items()):
        content = snapshot.artifact_bytes(relative)
        if relative.endswith(".json"):
            value = parse_strict_json_bytes(
                content,
                label=f"Common Engine Mode artifact {role}",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
        else:
            try:
                value = content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CommonEngineBehavioralParityError(
                    "Mode processing text artifact is not UTF-8"
                ) from exc
        mode_artifact_payload[role] = (
            _normalize_text(value, identities)
            if isinstance(value, str)
            else _normalize(value, identities)
        )
    mode_payload = {
        "artifactInventory": {
            role: _replace_identities(relative, identities)
            for role, relative in sorted(mode_paths.items())
        },
        "artifacts": mode_artifact_payload,
        "auditEvents": _normalized_mode_events(extension_events, identities),
    }
    measured_plan = (
        dual.planner_parity.legacy_plan
        if execution.path is CommonEnginePlannerPath.LEGACY_DIRECT
        else dual.planner_parity.adapter_plan
    )
    normalized_agents = _normalize(
        [agent.model_dump(mode="json") for agent in outcome.agents],
        identities,
    )
    normalized_graph = _normalize(outcome.task_graph.model_dump(mode="json"), identities)
    normalized_results = _normalize(
        [result.model_dump(mode="json") for result in outcome.tool_results],
        identities,
    )
    normalized_findings = _normalize(
        [finding.model_dump(mode="json") for finding in outcome.findings],
        identities,
    )
    normalized_validation = _normalize(outcome.validation.model_dump(mode="json"), identities)
    normalized_scope = {
        "campaignDigest": campaign_manifest_digest(
            dual.planner_parity.adapter_selection.compilation.source_campaign
        ),
        "normalizedPlan": measured_plan.normalized_plan,
    }
    normalized_capability = {
        "agents": normalized_agents,
        "taskGraph": normalized_graph,
        "capabilities": capabilities,
    }
    normalized_tool_request = {
        "planRequests": [step["request"] for step in measured_plan.normalized_plan["steps"]],
        "executionRequests": evidence_requests,
    }
    normalized_receipt = {"evidence": evidence_receipts}
    normalized_outcome = {
        "status": outcome.status.value,
        "plan": measured_plan.normalized_plan,
        "agents": normalized_agents,
        "taskGraph": normalized_graph,
        "toolResults": normalized_results,
        "findings": normalized_findings,
        "validation": normalized_validation,
        "cancellationReason": outcome.cancellation_reason,
        "evidence": evidence,
    }
    return CommonEngineNormalizedBehaviorObservation(
        path=execution.path,
        sourceMode=execution.coordinate.source_mode,
        dualRuntimeDigest=dual.authority_digest,
        sourceExecutionDigest=execution.execution_digest,
        sourceRunId=execution.run_id,
        sourceRootDigest=execution.sealed_root_digest,
        finalRootDigest=snapshot.verification.root_digest,
        modeSourceDigest=mode_artifacts.mode_source_digest,
        normalizedScope=normalized_scope,
        normalizedCapability=normalized_capability,
        normalizedToolRequest=normalized_tool_request,
        normalizedReceipt=normalized_receipt,
        normalizedOutcome=normalized_outcome,
        normalizedModeProcessing=mode_payload,
    )


def _validate_mode_extension(
    snapshot: VerifiedRunSnapshot,
    execution: CommonEngineRuntimeExecutionRecord,
    mode_paths: dict[str, str],
) -> tuple[AuditEvent, ...]:
    source_indexes = [
        index
        for index, seal in enumerate(snapshot.seals)
        if seal.root_digest == execution.sealed_root_digest
    ]
    if len(source_indexes) != 1:
        raise CommonEngineBehavioralParityError(
            "Mode processing seal chain does not contain one exact B2A source root"
        )
    source_seal = snapshot.seals[source_indexes[0]]
    extension_seals = snapshot.seals[source_indexes[0] + 1 :]
    extension_paths = [artifact.path for seal in extension_seals for artifact in seal.artifacts]
    if len(extension_paths) != len(set(extension_paths)) or set(extension_paths) != set(
        mode_paths.values()
    ):
        raise CommonEngineBehavioralParityError(
            "Mode processing sealed artifact inventory differs from declared outputs"
        )
    if source_seal.event_count > len(snapshot.events):
        raise CommonEngineBehavioralParityError(
            "Mode processing source event boundary is invalid"
        )
    return snapshot.events[source_seal.event_count :]


def _normalized_mode_events(
    events: tuple[AuditEvent, ...],
    identities: dict[str, str],
) -> list[dict[str, Any]]:
    return [
        {
            "ordinal": ordinal,
            "eventId": f"fixture-mode-event-{ordinal}",
            "runId": _replace_identities(event.run_id, identities),
            "eventType": event.event_type,
            "occurredAt": "<fresh-time:occurredAt>",
            "payload": _normalize(event.payload, identities),
        }
        for ordinal, event in enumerate(events)
    ]


def _identity_mapping(
    outcome: MultiAgentRunOutcome,
    snapshot: VerifiedRunSnapshot,
    evidence_paths: tuple[str, ...],
    extra: tuple[tuple[str, str], ...],
) -> dict[str, str]:
    if outcome.plan is None:
        raise CommonEngineBehavioralParityError("behavior normalization requires a Plan")
    identities: dict[str, str] = {outcome.run_id: "fixture-run"}
    request_tokens = _add_plan_identities(identities, outcome)
    agent_tokens = _agent_identity_tokens(outcome, request_tokens)
    _add_agent_and_task_identities(identities, outcome, agent_tokens, request_tokens)
    _add_evidence_identities(identities, snapshot, evidence_paths, request_tokens)
    _add_validation_identities(identities, outcome)
    for event in snapshot.events:
        _add_identity(identities, event.event_id, f"fixture-event-{event.sequence}")
    for source, target in extra:
        _add_identity(identities, source, target)
    return identities


def _ordered_evidence_paths(
    outcome: MultiAgentRunOutcome,
    snapshot: VerifiedRunSnapshot,
    execution: CommonEngineRuntimeExecutionRecord,
) -> tuple[str, ...]:
    if outcome.plan is None:
        raise CommonEngineBehavioralParityError("evidence ordering requires a Plan")
    by_request: dict[str, str] = {}
    for evidence_path in execution.evidence_paths:
        payload = _strict_json(snapshot, evidence_path)
        request = payload.get("request") if isinstance(payload, dict) else None
        request_id = request.get("request_id") if isinstance(request, dict) else None
        if not isinstance(request_id, str) or request_id in by_request:
            raise CommonEngineBehavioralParityError(
                "sealed evidence cannot be mapped one-to-one to ToolRequests"
            )
        by_request[request_id] = evidence_path
    ordered_request_ids = [step.request.request_id for step in outcome.plan.steps]
    if set(by_request) != set(ordered_request_ids):
        raise CommonEngineBehavioralParityError(
            "sealed evidence set differs from the measured Plan"
        )
    return tuple(by_request[request_id] for request_id in ordered_request_ids)


def _add_plan_identities(
    identities: dict[str, str],
    outcome: MultiAgentRunOutcome,
) -> dict[str, str]:
    assert outcome.plan is not None
    request_tokens: dict[str, str] = {}
    for index, step in enumerate(outcome.plan.steps):
        _add_identity(identities, step.step_id, f"fixture-step-{index}")
        request_token = f"fixture-request-{index}"
        _add_identity(identities, step.request.request_id, request_token)
        request_tokens[step.request.request_id] = request_token
    return request_tokens


def _agent_identity_tokens(
    outcome: MultiAgentRunOutcome,
    request_tokens: dict[str, str],
) -> dict[str, str]:
    agent_tokens: dict[str, str] = {}
    for agent in outcome.agents:
        if agent.role is not AgentRole.SPECIALIST:
            token = f"fixture-agent:{agent.role.value}"
            if token in agent_tokens.values():
                raise CommonEngineBehavioralParityError(
                    "behavior normalization requires one non-Specialist Agent per role"
                )
            agent_tokens[agent.agent_id] = token
    for task in outcome.task_graph.tasks.values():
        if task.request is not None:
            request_token = request_tokens.get(task.request.request_id)
            if request_token is None:
                raise CommonEngineBehavioralParityError(
                    "Task graph contains a request outside the measured Plan"
                )
            assigned_agent_id = _assigned_agent_id(task.assigned_agent_id)
            agent_tokens[assigned_agent_id] = request_token.replace(
                "fixture-request", "fixture-agent:specialist"
            )
    if set(agent_tokens) != {agent.agent_id for agent in outcome.agents}:
        raise CommonEngineBehavioralParityError("Agent topology cannot be normalized exactly")
    return agent_tokens


def _add_agent_and_task_identities(
    identities: dict[str, str],
    outcome: MultiAgentRunOutcome,
    agent_tokens: dict[str, str],
    request_tokens: dict[str, str],
) -> None:
    for agent in outcome.agents:
        agent_token = agent_tokens[agent.agent_id]
        _add_identity(identities, agent.agent_id, agent_token)
        _add_identity(
            identities,
            agent.capability_grant_id,
            agent_token.replace("fixture-agent", "fixture-grant"),
        )
    for task in outcome.task_graph.tasks.values():
        if task.request is not None:
            token = request_tokens[task.request.request_id].replace(
                "fixture-request", "fixture-task:request"
            )
        else:
            assigned_agent_id = _assigned_agent_id(task.assigned_agent_id)
            token = agent_tokens[assigned_agent_id].replace("fixture-agent", "fixture-task")
        _add_identity(identities, task.task_id, token)


def _add_evidence_identities(
    identities: dict[str, str],
    snapshot: VerifiedRunSnapshot,
    evidence_paths: tuple[str, ...],
    request_tokens: dict[str, str],
) -> None:
    for evidence_path in evidence_paths:
        payload = _strict_json(snapshot, evidence_path)
        if not isinstance(payload, dict):
            raise CommonEngineBehavioralParityError("sealed Tool evidence must be an object")
        worker_job = payload.get("workerJob")
        worker_result = payload.get("workerResult")
        execution_ids = {
            value
            for value in (
                worker_job.get("executionId") if isinstance(worker_job, dict) else None,
                worker_result.get("execution_id") if isinstance(worker_result, dict) else None,
            )
            if isinstance(value, str)
        }
        if len(execution_ids) != 1:
            raise CommonEngineBehavioralParityError(
                "sealed Tool evidence has inconsistent Worker execution identity"
            )
        request = payload.get("request")
        if not isinstance(request, dict) or not isinstance(request.get("request_id"), str):
            raise CommonEngineBehavioralParityError("sealed Tool evidence request is incomplete")
        request_id = request["request_id"]
        if request_id not in request_tokens:
            raise CommonEngineBehavioralParityError(
                "sealed Tool evidence belongs to an unknown request"
            )
        request_token = request_tokens[request_id]
        _add_identity(
            identities,
            execution_ids.pop(),
            request_token.replace("fixture-request", "fixture-execution"),
        )
        _add_identity(
            identities,
            evidence_path,
            f"evidence/{request_token}.json",
        )


def _add_validation_identities(
    identities: dict[str, str],
    outcome: MultiAgentRunOutcome,
) -> None:
    validation = outcome.validation
    candidate_tokens: dict[str, str] = {}
    for index, candidate in enumerate(validation.candidates):
        token = f"fixture-candidate-{index}"
        candidate_tokens[candidate.candidate_id] = token
        _add_identity(identities, candidate.candidate_id, token)
        _add_identity(identities, candidate.claim.finding_id, f"fixture-finding-{index}")
    for index, decision in enumerate(validation.decisions):
        if decision.candidate_id not in candidate_tokens:
            raise CommonEngineBehavioralParityError(
                "Validation decision references an unknown Candidate"
            )
        _add_identity(identities, decision.decision_id, f"fixture-decision-{index}")
    known_findings = {candidate.claim.finding_id for candidate in validation.candidates}
    for index, finding in enumerate(outcome.findings, start=len(known_findings)):
        if finding.finding_id not in known_findings:
            _add_identity(identities, finding.finding_id, f"fixture-finding-{index}")


def _assigned_agent_id(value: str | None) -> str:
    if value is None:
        raise CommonEngineBehavioralParityError("Task is missing its assigned Agent")
    return value


def _add_identity(identities: dict[str, str], source: str, target: str) -> None:
    current = identities.get(source)
    if current is not None and current != target:
        raise CommonEngineBehavioralParityError(
            "one fresh identity maps to different semantic ordinals"
        )
    if source != target and target in identities.values() and current is None:
        raise CommonEngineBehavioralParityError(
            "different fresh identities map to one semantic ordinal"
        )
    identities[source] = target


def _normalize(value: Any, identities: dict[str, str], *, key: str | None = None) -> Any:
    if key in _FRESH_TIME_KEYS:
        if not isinstance(value, str):
            raise CommonEngineBehavioralParityError(f"fresh time field is not text: {key}")
        return f"<fresh-time:{key}>"
    if isinstance(value, dict):
        return {
            _replace_identities(str(item_key), identities): _normalize(
                item,
                identities,
                key=str(item_key),
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        normalized = [_normalize(item, identities) for item in value]
        if key in _UNORDERED_LIST_KEYS:
            return sorted(
                normalized,
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            )
        return normalized
    if isinstance(value, str):
        return _replace_identities(value, identities)
    return value


def _replace_identities(value: str, identities: dict[str, str]) -> str:
    return identities.get(value, value)


def _normalize_text(value: str, identities: dict[str, str]) -> str:
    """Replace bound fresh identities only in a Mode-owned text artifact."""

    normalized = value
    for source in sorted(identities, key=len, reverse=True):
        normalized = normalized.replace(source, identities[source])
    return normalized


def _strict_json(snapshot: VerifiedRunSnapshot, relative_path: str) -> Any:
    try:
        return parse_strict_json_bytes(
            snapshot.artifact_bytes(relative_path),
            label=f"Common Engine artifact {relative_path}",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
    except (KeyError, ValueError) as exc:
        raise CommonEngineBehavioralParityError(
            f"Common Engine artifact is missing or invalid: {relative_path}"
        ) from exc
