"""Sealed operational-evidence admission for the CAP-005 Web + AI exit gate."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationError,
)
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.lifecycle import CapabilityReleaseRef, CapabilityUseProfile
from pajin.capabilities.metrics import (
    CapabilityDeliveryEvidence,
    CapabilityMetricsReportStatus,
    CapabilityOracleObservation,
    CapabilityRegistryMetricsReport,
    CapabilityReplayObservation,
)
from pajin.capabilities.models import capability_definition_digest
from pajin.capabilities.rollout import (
    ExistingModeCapabilityRollout,
    ExistingModeCapabilityRolloutError,
    existing_mode_capability_rollout_metrics,
)
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)

CAPABILITY_OPERATIONAL_EVIDENCE_SET_API_VERSION: Literal[
    "pajin.dev/capability-operational-evidence-set/v1alpha1"
] = "pajin.dev/capability-operational-evidence-set/v1alpha1"
WEB_AI_HYBRID_CAMPAIGN_EXIT_GATE_API_VERSION: Literal[
    "pajin.dev/web-ai-hybrid-campaign-exit-gate/v1alpha1"
] = "pajin.dev/web-ai-hybrid-campaign-exit-gate/v1alpha1"

CAPABILITY_OPERATIONAL_EVIDENCE_ARTIFACT = "capability/operational-evidence.json"
WEB_AI_HYBRID_CAPABILITY_IDS = (
    "pajin.ai.kisa.system-prompt-disclosure",
    "pajin.ctf.web-exposed-backup-config",
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_OPERATIONAL_EVIDENCE_BYTES = 8 * 1024 * 1024
_EXPECTED_CAPABILITY_COUNT = 7
_EXPECTED_REPLAY_CAPABILITY_COUNT = 3


class WebAIHybridCampaignExitGateError(ValueError):
    """Raised when operational evidence cannot pass the sealed Hybrid gate."""


class CapabilityOperationalEvidenceSet(StrictModel):
    """Content-addressed CAP-006 inputs whose source bytes live in one sealed Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-operational-evidence-set/v1alpha1"] = Field(
        default=CAPABILITY_OPERATIONAL_EVIDENCE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityOperationalEvidenceSet"] = "CapabilityOperationalEvidenceSet"
    evidence_set_id: str = Field(default="", alias="evidenceSetId", max_length=105)
    evidence_set_digest: str = Field(
        default="",
        alias="evidenceSetDigest",
        max_length=64,
    )
    release_set_digest: _Sha256 = Field(alias="releaseSetDigest")
    delivery_evidence: tuple[CapabilityDeliveryEvidence, ...] = Field(
        alias="deliveryEvidence",
        min_length=_EXPECTED_CAPABILITY_COUNT,
        max_length=_EXPECTED_CAPABILITY_COUNT,
    )
    oracle_observations: tuple[CapabilityOracleObservation, ...] = Field(
        alias="oracleObservations",
        min_length=_EXPECTED_CAPABILITY_COUNT,
        max_length=100,
    )
    replay_observations: tuple[CapabilityReplayObservation, ...] = Field(
        alias="replayObservations",
        min_length=_EXPECTED_REPLAY_CAPABILITY_COUNT,
        max_length=100,
    )

    @model_validator(mode="after")
    def bind_evidence_identity(self) -> Self:
        _require_sorted_unique(
            self.delivery_evidence,
            key=lambda item: (*_capability_key(item.capability), item.evidence_digest),
            label="delivery evidence",
        )
        _require_sorted_unique(
            self.oracle_observations,
            key=lambda item: (*_capability_key(item.capability), item.observation_digest),
            label="Oracle observations",
        )
        _require_sorted_unique(
            self.replay_observations,
            key=lambda item: (*_capability_key(item.capability), item.observation_digest),
            label="Replay observations",
        )
        delivery_capabilities = {
            _capability_key(item.capability) for item in self.delivery_evidence
        }
        oracle_capabilities = {
            _capability_key(item.capability) for item in self.oracle_observations
        }
        replay_capabilities = {
            _capability_key(item.capability) for item in self.replay_observations
        }
        if (
            len(delivery_capabilities) != _EXPECTED_CAPABILITY_COUNT
            or delivery_capabilities != oracle_capabilities
        ):
            raise ValueError(
                "operational evidence must cover the same exact seven delivery and Oracle "
                "Capabilities"
            )
        if len(replay_capabilities) != _EXPECTED_REPLAY_CAPABILITY_COUNT:
            raise ValueError("operational evidence must cover exactly three Replay Capabilities")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_set_id", "evidence_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.operational-evidence-set/v1",
            material,
        )
        evidence_set_id = f"capability-operational-evidence_{digest}"
        if self.evidence_set_digest and self.evidence_set_digest != digest:
            raise ValueError(
                "Capability operational evidence-set digest differs from canonical identity"
            )
        if self.evidence_set_id and self.evidence_set_id != evidence_set_id:
            raise ValueError(
                "Capability operational evidence-set ID differs from canonical identity"
            )
        object.__setattr__(self, "evidence_set_digest", digest)
        object.__setattr__(self, "evidence_set_id", evidence_set_id)
        return self

    def referenced_source_digests(self) -> tuple[str, ...]:
        """Return every raw source hash that must exist as a sealed Run artifact."""

        return tuple(
            sorted(
                {
                    *(item.source_digest for item in self.delivery_evidence),
                    *(item.evidence_digest for item in self.oracle_observations),
                    *(item.evidence_digest for item in self.replay_observations),
                }
            )
        )


class WebAIHybridDispatchResult(StrictModel):
    """One exact successful dispatch lifecycle included in the Hybrid gate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CodeBackedCapabilityRef
    release: CapabilityReleaseRef
    claimed_event_digest: _Sha256 = Field(alias="claimedEventDigest")
    completed_event_digest: _Sha256 = Field(alias="completedEventDigest")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    dispatch_id: str = Field(alias="dispatchId", min_length=1, max_length=80)
    request_digest: _Sha256 = Field(alias="requestDigest")
    gateway_outcome_digest: _Sha256 = Field(alias="gatewayOutcomeDigest")
    gateway_execution_id: str = Field(
        alias="gatewayExecutionId",
        min_length=1,
        max_length=200,
    )
    evidence: tuple[str, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_canonical_evidence(self) -> Self:
        if self.evidence != tuple(sorted(set(self.evidence))):
            raise ValueError("Hybrid dispatch evidence paths must be unique and sorted")
        return self


class WebAIHybridCampaignExitGate(StrictModel):
    """Content-addressed proof that one sealed Web + AI Campaign passed."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-ai-hybrid-campaign-exit-gate/v1alpha1"] = Field(
        default=WEB_AI_HYBRID_CAMPAIGN_EXIT_GATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAIHybridCampaignExitGate"] = "WebAIHybridCampaignExitGate"
    gate_id: str = Field(default="", alias="gateId", max_length=100)
    gate_digest: str = Field(default="", alias="gateDigest", max_length=64)
    outcome: Literal["passed"] = "passed"
    evaluated_at: datetime = Field(alias="evaluatedAt")
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    run_root_digest: _Sha256 = Field(alias="runRootDigest")
    run_event_count: int = Field(alias="runEventCount", strict=True, ge=4)
    run_seal_count: int = Field(alias="runSealCount", strict=True, ge=1)
    release_set_digest: _Sha256 = Field(alias="releaseSetDigest")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    operational_evidence_set_digest: _Sha256 = Field(alias="operationalEvidenceSetDigest")
    operational_evidence_artifact_sha256: _Sha256 = Field(alias="operationalEvidenceArtifactSha256")
    metrics_report: CapabilityRegistryMetricsReport = Field(alias="metricsReport")
    dispatches: tuple[WebAIHybridDispatchResult, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @field_validator("evaluated_at")
    @classmethod
    def normalize_evaluated_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Hybrid exit-gate evaluation time")

    @model_validator(mode="after")
    def bind_gate_identity(self) -> Self:
        dispatch_keys = [
            (*_capability_key(item.capability), item.completed_event_digest)
            for item in self.dispatches
        ]
        if dispatch_keys != sorted(set(dispatch_keys)):
            raise ValueError("Hybrid exit-gate dispatches must be unique and sorted")
        if (
            tuple(item.capability.capability.capability_id for item in self.dispatches)
            != WEB_AI_HYBRID_CAPABILITY_IDS
        ):
            raise ValueError("Hybrid exit gate requires the exact Web + AI Capability pair")
        if self.metrics_report.status is not CapabilityMetricsReportStatus.COMPLETE:
            raise ValueError("Hybrid exit gate requires a complete CAP-006 metrics report")
        if self.metrics_report.measured_at != self.evaluated_at:
            raise ValueError(
                "Hybrid exit-gate evaluation differs from its CAP-006 measurement time"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"gate_id", "gate_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-ai-hybrid-campaign-exit-gate/v1",
            material,
        )
        gate_id = f"web-ai-hybrid-exit-gate_{digest}"
        if self.gate_digest and self.gate_digest != digest:
            raise ValueError("Hybrid exit-gate digest differs from canonical identity")
        if self.gate_id and self.gate_id != gate_id:
            raise ValueError("Hybrid exit-gate ID differs from canonical identity")
        object.__setattr__(self, "gate_digest", digest)
        object.__setattr__(self, "gate_id", gate_id)
        return self


def verify_web_ai_hybrid_campaign_exit_gate(
    *,
    rollout: ExistingModeCapabilityRollout,
    activation: ExistingModeCapabilityActivation,
    run_path: Path,
    evaluated_at: datetime,
    operational_evidence_path: str = CAPABILITY_OPERATIONAL_EVIDENCE_ARTIFACT,
) -> WebAIHybridCampaignExitGate:
    """Admit one immutable Run only after complete evidence and Web + AI success."""

    if not isinstance(rollout, ExistingModeCapabilityRollout):
        raise TypeError("Hybrid exit gate requires a verified existing Mode rollout")
    if not isinstance(activation, ExistingModeCapabilityActivation):
        raise TypeError("Hybrid exit gate requires a verified existing Mode activation")
    evaluated = _aware_utc(evaluated_at, label="Hybrid exit-gate evaluation time")
    try:
        _require_exact_activation(rollout, activation)
        snapshot = load_verified_run_artifacts(
            run_path,
            requests={
                operational_evidence_path: _MAX_OPERATIONAL_EVIDENCE_BYTES,
            },
        )
        evidence_bytes = snapshot.artifact_bytes(operational_evidence_path)
        raw_evidence = parse_strict_json_bytes(
            evidence_bytes,
            label="sealed Capability operational evidence set",
            max_bytes=_MAX_OPERATIONAL_EVIDENCE_BYTES,
        )
        evidence_set = CapabilityOperationalEvidenceSet.model_validate(raw_evidence)
        _require_sealed_operational_evidence(
            snapshot,
            evidence_set,
            operational_evidence_path=operational_evidence_path,
        )
        _require_evidence_not_future(evidence_set, evaluated_at=evaluated)
        if evidence_set.release_set_digest != rollout.release_set.release_set_digest:
            raise WebAIHybridCampaignExitGateError(
                "operational evidence belongs to another signed release set"
            )
        report = existing_mode_capability_rollout_metrics(
            rollout,
            measured_at=evaluated,
            delivery_evidence=evidence_set.delivery_evidence,
            oracle_observations=evidence_set.oracle_observations,
            replay_observations=evidence_set.replay_observations,
        )
        if report.status is not CapabilityMetricsReportStatus.COMPLETE:
            raise WebAIHybridCampaignExitGateError(
                "operational evidence does not close the CAP-006 metric gaps"
            )
        dispatches, campaign_id = _verified_hybrid_dispatches(
            snapshot,
            activation=activation,
            evaluated_at=evaluated,
        )
        return WebAIHybridCampaignExitGate(
            evaluatedAt=evaluated,
            campaignId=campaign_id,
            runId=snapshot.verification.run_id,
            runRootDigest=snapshot.verification.root_digest,
            runEventCount=snapshot.verification.event_count,
            runSealCount=snapshot.verification.seal_count,
            releaseSetDigest=rollout.release_set.release_set_digest,
            activationSetDigest=activation.activation_set.activation_set_digest,
            operationalEvidenceSetDigest=evidence_set.evidence_set_digest,
            operationalEvidenceArtifactSha256=sha256(evidence_bytes).hexdigest(),
            metricsReport=report,
            dispatches=dispatches,
        )
    except WebAIHybridCampaignExitGateError:
        raise
    except (
        AttributeError,
        ExistingModeCapabilityActivationError,
        ExistingModeCapabilityRolloutError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebAIHybridCampaignExitGateError(
            "sealed Web + AI Hybrid Campaign evidence failed verification"
        ) from exc


def _require_exact_activation(
    rollout: ExistingModeCapabilityRollout,
    activation: ExistingModeCapabilityActivation,
) -> None:
    activation.action_registry()
    if activation.rollout is not rollout:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit-gate activation must use the exact verified rollout object"
        )
    if activation.activation_set.profile is not CapabilityUseProfile.RANGE:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit gate requires the bounded Range usage profile"
        )
    if activation.activation_set.release_set_digest != rollout.release_set.release_set_digest:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit-gate activation belongs to another signed release set"
        )
    capability_ids = tuple(
        item.capability.capability.capability_id for item in activation.activation_set.bindings
    )
    if capability_ids != WEB_AI_HYBRID_CAPABILITY_IDS:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit gate requires only the exact Web + AI Capability pair"
        )


def _require_sealed_operational_evidence(
    snapshot: VerifiedRunSnapshot,
    evidence_set: CapabilityOperationalEvidenceSet,
    *,
    operational_evidence_path: str,
) -> None:
    sealed_artifacts = {
        artifact.path: artifact for seal in snapshot.seals for artifact in seal.artifacts
    }
    evidence_record = sealed_artifacts.get(operational_evidence_path)
    if evidence_record is None:
        raise WebAIHybridCampaignExitGateError(
            "operational evidence set is not a sealed Run artifact"
        )
    available_source_digests = {
        artifact.sha256
        for path, artifact in sealed_artifacts.items()
        if path != operational_evidence_path
    }
    missing = set(evidence_set.referenced_source_digests()) - available_source_digests
    if missing:
        raise WebAIHybridCampaignExitGateError(
            "operational evidence references source bytes absent from the sealed Run"
        )


def _require_evidence_not_future(
    evidence_set: CapabilityOperationalEvidenceSet,
    *,
    evaluated_at: datetime,
) -> None:
    delivery_times = (
        timestamp
        for item in evidence_set.delivery_evidence
        for timestamp in (item.authored_at, item.code_backed_at, item.released_at)
        if timestamp is not None
    )
    observation_times = (
        *(item.observed_at for item in evidence_set.oracle_observations),
        *(item.observed_at for item in evidence_set.replay_observations),
    )
    if any(timestamp > evaluated_at for timestamp in (*delivery_times, *observation_times)):
        raise WebAIHybridCampaignExitGateError(
            "operational evidence contains a timestamp after gate evaluation"
        )


def _verified_hybrid_dispatches(
    snapshot: VerifiedRunSnapshot,
    *,
    activation: ExistingModeCapabilityActivation,
    evaluated_at: datetime,
) -> tuple[tuple[WebAIHybridDispatchResult, ...], str]:
    lifecycles = _dispatch_lifecycles(snapshot, activation=activation)
    sealed_paths = {artifact.path for seal in snapshot.seals for artifact in seal.artifacts}
    verified = tuple(
        _verified_hybrid_dispatch(
            lifecycle,
            activation=activation,
            sealed_paths=sealed_paths,
            evaluated_at=evaluated_at,
        )
        for lifecycle in lifecycles
    )
    campaign_ids = {item[1] for item in verified}
    request_digests = {item[2] for item in verified}
    dispatch_ids = {item[3] for item in verified}
    if len(campaign_ids) != 1 or len(request_digests) != 2 or len(dispatch_ids) != 2:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid dispatches do not share one Campaign with distinct requests"
        )
    canonical = tuple(
        sorted(
            (item[0] for item in verified),
            key=lambda item: _capability_key(item.capability),
        )
    )
    if (
        tuple(item.capability.capability.capability_id for item in canonical)
        != WEB_AI_HYBRID_CAPABILITY_IDS
    ):
        raise WebAIHybridCampaignExitGateError(
            "sealed Run does not contain the exact Web + AI Capability pair"
        )
    return canonical, next(iter(campaign_ids))


def _dispatch_lifecycles(
    snapshot: VerifiedRunSnapshot,
    *,
    activation: ExistingModeCapabilityActivation,
) -> tuple[tuple[CapabilityDispatchAuditEvent, ...], ...]:
    dispatch_events: list[CapabilityDispatchAuditEvent] = []
    for audit_event in snapshot.events:
        if not audit_event.event_type.startswith("capability.dispatch."):
            continue
        parsed = CapabilityDispatchAuditEvent.model_validate(audit_event.payload)
        if audit_event.event_type != f"capability.dispatch.{parsed.stage.value}":
            raise WebAIHybridCampaignExitGateError(
                "Capability dispatch event type differs from its content-addressed stage"
            )
        if parsed.run_id != snapshot.verification.run_id:
            raise WebAIHybridCampaignExitGateError(
                "Capability dispatch belongs to another sealed Run"
            )
        if parsed.activation_set_digest != activation.activation_set.activation_set_digest:
            raise WebAIHybridCampaignExitGateError(
                "Capability dispatch belongs to another activation set"
            )
        dispatch_events.append(parsed)
    lifecycles: dict[str, list[CapabilityDispatchAuditEvent]] = {}
    for dispatch_event in dispatch_events:
        lifecycles.setdefault(dispatch_event.permit_id, []).append(dispatch_event)
    if len(dispatch_events) != 4 or len(lifecycles) != 2:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit gate requires exactly two claimed-to-completed dispatch lifecycles"
        )
    return tuple(tuple(lifecycle) for lifecycle in lifecycles.values())


def _verified_hybrid_dispatch(
    lifecycle: tuple[CapabilityDispatchAuditEvent, ...],
    *,
    activation: ExistingModeCapabilityActivation,
    sealed_paths: set[str],
    evaluated_at: datetime,
) -> tuple[WebAIHybridDispatchResult, str, str, str]:
    if (
        len(lifecycle) != 2
        or lifecycle[0].stage is not CapabilityDispatchStage.CLAIMED
        or lifecycle[1].stage is not CapabilityDispatchStage.COMPLETED
    ):
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit-gate dispatch lifecycle is incomplete or unsuccessful"
        )
    claimed, completed = lifecycle
    if completed.occurred_at < claimed.occurred_at or completed.occurred_at > evaluated_at:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid dispatch timestamps fall outside the sealed gate interval"
        )
    if not _same_dispatch_identity(claimed, completed):
        raise WebAIHybridCampaignExitGateError(
            "Hybrid dispatch claimed and completed identities differ"
        )
    if not (
        completed.executed is True
        and completed.policy_allowed is True
        and completed.tool_success is True
        and completed.gateway_outcome_digest is not None
        and completed.gateway_execution_id is not None
        and completed.evidence
    ):
        raise WebAIHybridCampaignExitGateError(
            "Hybrid exit-gate dispatch does not attest successful Worker execution"
        )
    if not set(completed.evidence) <= sealed_paths:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid dispatch references evidence absent from the sealed Run"
        )
    binding = next(
        (item for item in activation.activation_set.bindings if item.release == completed.release),
        None,
    )
    if binding is None:
        raise WebAIHybridCampaignExitGateError(
            "Hybrid dispatch release is not in the exact Web + AI activation"
        )
    result = WebAIHybridDispatchResult(
        capability=binding.capability,
        release=completed.release,
        claimedEventDigest=claimed.event_digest,
        completedEventDigest=completed.event_digest,
        permitDigest=completed.permit_digest,
        dispatchId=completed.dispatch_id,
        requestDigest=completed.request_digest,
        gatewayOutcomeDigest=completed.gateway_outcome_digest,
        gatewayExecutionId=completed.gateway_execution_id,
        evidence=completed.evidence,
    )
    return (
        result,
        completed.campaign_id,
        completed.request_digest,
        completed.dispatch_id,
    )


def _same_dispatch_identity(
    claimed: CapabilityDispatchAuditEvent,
    completed: CapabilityDispatchAuditEvent,
) -> bool:
    return all(
        (
            claimed.activation_set_digest == completed.activation_set_digest,
            claimed.release == completed.release,
            claimed.permit_id == completed.permit_id,
            claimed.permit_digest == completed.permit_digest,
            claimed.dispatch_id == completed.dispatch_id,
            claimed.campaign_id == completed.campaign_id,
            claimed.run_id == completed.run_id,
            claimed.proposal_id == completed.proposal_id,
            claimed.proposal_digest == completed.proposal_digest,
            claimed.request_id == completed.request_id,
            claimed.request_digest == completed.request_digest,
            claimed.normalized_parameters_digest == completed.normalized_parameters_digest,
        )
    )


def _require_sorted_unique[ItemT](
    values: tuple[ItemT, ...],
    *,
    key: Callable[[ItemT], tuple[str, ...]],
    label: str,
) -> None:
    keyed = [key(item) for item in values]
    if keyed != sorted(set(keyed)):
        raise ValueError(f"Capability operational {label} must be unique and sorted")


def _capability_key(
    reference: CodeBackedCapabilityRef,
) -> tuple[str, str, str, str]:
    capability = reference.capability
    return (
        capability.capability_id,
        capability.capability_version,
        capability.capability_digest,
        reference.authority_set_digest,
    )


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset or Z")
    return value.astimezone(UTC)
