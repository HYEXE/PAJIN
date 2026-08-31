"""UX-009A sealed read-only projection over one exact WEB-002D authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import BenchmarkTargetOperationJournal
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.web_controlled_validation_authority import (
    WebControlledValidationAuthority,
    WebControlledValidationAuthorityError,
    WebControlledValidationAuthorityOutcome,
    load_web_controlled_validation_authority,
)
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
)
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityRef,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteTrustAnchor,
)
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementAuthorityRef,
    WebZAPSourceMeasurementReopenContext,
)
from pajin.workflow.web_validation_evaluation import (
    WebBenchmarkFindingRef,
    WebBenchmarkMetricObservation,
    WebValidationFloorEvaluationRef,
)
from pajin.workflow.web_validation_floor import (
    WebBenchmarkFindingProjectionPolicyRef,
    WebBenchmarkValidationFloorPolicy,
    WebBenchmarkValidationFloorPolicyRef,
    WebExpectedFindingProjectionMapping,
)

WEB_MEASURED_PRODUCT_FLOW_API_VERSION: Literal[
    "pajin.dev/web-measured-product-flow-projection/v1alpha1"
] = "pajin.dev/web-measured-product-flow-projection/v1alpha1"
WEB_MEASURED_PRODUCT_FLOW_PATH = "web-measured-product-flow-projection.json"

_MAX_PRODUCT_FLOW_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RunId = Annotated[
    str,
    Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"),
]


class WebMeasuredProductFlowError(RuntimeError):
    """Raised when UX-009A cannot reproduce its exact bounded projection."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class WebMeasuredProductScopeProjection(_FrozenStrictModel):
    """Exact measured-case boundary without Campaign Scope or Profile inference."""

    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    scope_state: Literal["measured-case-bounded-campaign-scope-unavailable"] = Field(
        default="measured-case-bounded-campaign-scope-unavailable",
        alias="scopeState",
    )
    campaign_scope_available: Literal[False] = Field(
        default=False,
        alias="campaignScopeAvailable",
    )
    scope_expanded: Literal[False] = Field(default=False, alias="scopeExpanded")
    profile_inferred: Literal[False] = Field(default=False, alias="profileInferred")

    @field_validator(
        "campaign_scope_available",
        "scope_expanded",
        "profile_inferred",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB measured product Scope authority markers must be false")
        return value


class WebMeasuredProductEvidenceProjection(_FrozenStrictModel):
    """Content-free references and requirement counts from one exact source authority."""

    floor_evaluation: WebValidationFloorEvaluationRef = Field(alias="floorEvaluation")
    finding: WebBenchmarkFindingRef
    denial_control_observation_id: str = Field(
        alias="denialControlObservationId",
        pattern=r"^web-observed-policy-denial:[a-f0-9]{64}$",
    )
    denial_control_observation_digest: _Sha256 = Field(alias="denialControlObservationDigest")
    source_evidence_requirement_count: Literal[6] = Field(
        default=6,
        alias="sourceEvidenceRequirementCount",
    )
    controlled_validation_evidence_requirement_count: Literal[10] = Field(
        default=10,
        alias="controlledValidationEvidenceRequirementCount",
    )
    evidence_state: Literal["content-free-authority-references-verified"] = Field(
        default="content-free-authority-references-verified",
        alias="evidenceState",
    )
    denial_control_satisfied: Literal[True] = Field(
        default=True,
        alias="denialControlSatisfied",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    evidence_content_included: Literal[False] = Field(
        default=False,
        alias="evidenceContentIncluded",
    )
    filesystem_coordinates_included: Literal[False] = Field(
        default=False,
        alias="filesystemCoordinatesIncluded",
    )

    @field_validator("denial_control_satisfied", "target_cleanup_verified", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB measured product Evidence verification markers must be true")
        return value

    @field_validator(
        "evidence_content_included",
        "filesystem_coordinates_included",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB measured product Evidence disclosure markers must be false")
        return value

    @model_validator(mode="after")
    def bind_denial_reference(self) -> Self:
        if self.denial_control_observation_id != (
            f"web-observed-policy-denial:{self.denial_control_observation_digest}"
        ):
            raise ValueError("WEB measured product denial Control reference differs")
        return self


class WebMeasuredProductFloorProjection(_FrozenStrictModel):
    """Public metric values and satisfied floor state from WEB-002D."""

    floor_policy: WebBenchmarkValidationFloorPolicyRef = Field(alias="floorPolicy")
    projection_policy: WebBenchmarkFindingProjectionPolicyRef = Field(alias="projectionPolicy")
    evaluation: WebValidationFloorEvaluationRef
    metrics: tuple[WebBenchmarkMetricObservation, ...] = Field(
        min_length=14,
        max_length=14,
    )
    public_metric_count: Literal[14] = Field(default=14, alias="publicMetricCount")
    required_metric_count: Literal[11] = Field(default=11, alias="requiredMetricCount")
    not_applicable_metric_count: Literal[3] = Field(
        default=3,
        alias="notApplicableMetricCount",
    )
    floor_state: Literal["satisfied-independent-controlled-validation"] = Field(
        default="satisfied-independent-controlled-validation",
        alias="floorState",
    )
    denial_control_satisfied: Literal[True] = Field(
        default=True,
        alias="denialControlSatisfied",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    benchmark_validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="benchmarkValidationFloorSatisfied",
    )

    @field_validator("metrics", mode="before")
    @classmethod
    def canonicalize_json_tuple(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator(
        "denial_control_satisfied",
        "target_cleanup_verified",
        "benchmark_validation_floor_satisfied",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB measured product floor completion markers must be true")
        return value

    @model_validator(mode="after")
    def bind_metric_counts(self) -> Self:
        required = sum(item.applicability.value == "required" for item in self.metrics)
        not_applicable = sum(item.applicability.value == "not-applicable" for item in self.metrics)
        identities = tuple(item.metric.metric_id for item in self.metrics)
        if (
            len(self.metrics) != self.public_metric_count
            or required != self.required_metric_count
            or not_applicable != self.not_applicable_metric_count
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("WEB measured product metric projection differs")
        return self


class WebMeasuredProductFindingProjection(_FrozenStrictModel):
    """Bounded confirmation that cannot be promoted to a production Finding."""

    finding: WebBenchmarkFindingRef
    evaluation: WebValidationFloorEvaluationRef
    projection_policy: WebBenchmarkFindingProjectionPolicyRef = Field(alias="projectionPolicy")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    claim_ceiling: Literal["benchmark-ground-truth-match"] = Field(
        default="benchmark-ground-truth-match",
        alias="claimCeiling",
    )
    finding_state: Literal[
        "confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated"
    ] = Field(
        default=("confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated"),
        alias="findingState",
    )
    impact_assurance: Literal["not-evaluated-information-only"] = Field(
        default="not-evaluated-information-only",
        alias="impactAssurance",
    )
    severity_assurance: Literal["not-evaluated-information-only"] = Field(
        default="not-evaluated-information-only",
        alias="severityAssurance",
    )
    benchmark_ground_truth_match_confirmed: Literal[True] = Field(
        default=True,
        alias="benchmarkGroundTruthMatchConfirmed",
    )
    product_finding_confirmed: Literal[True] = Field(
        default=True,
        alias="productFindingConfirmed",
    )
    generic_production_vulnerability_confirmed: Literal[False] = Field(
        default=False,
        alias="genericProductionVulnerabilityConfirmed",
    )
    negative_security_conclusion_authorized: Literal[False] = Field(
        default=False,
        alias="negativeSecurityConclusionAuthorized",
    )

    @field_validator(
        "benchmark_ground_truth_match_confirmed",
        "product_finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB measured product Finding confirmation markers must be true")
        return value

    @field_validator(
        "generic_production_vulnerability_confirmed",
        "negative_security_conclusion_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB measured product Finding escalation markers must be false")
        return value


class WebMeasuredProductReportProjection(_FrozenStrictModel):
    """Explicit absence of report and delivery authority."""

    report_state: Literal["unavailable-bounded-finding-not-report-authority"] = Field(
        default="unavailable-bounded-finding-not-report-authority",
        alias="reportState",
    )
    report_available: Literal[False] = Field(default=False, alias="reportAvailable")
    report_creation_authorized: Literal[False] = Field(
        default=False,
        alias="reportCreationAuthorized",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )

    @field_validator(
        "report_available",
        "report_creation_authorized",
        "report_delivery_authorized",
        "external_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB measured product report markers must be false")
        return value


_BOUNDARY_TRUE_FIELDS = (
    "source_authority_contextually_verified",
    "read_only_projection",
    "evidence_content_redacted",
)
_BOUNDARY_FALSE_FIELDS = (
    "web_002c_graph_predecessor_required",
    "campaign_scope_available",
    "scope_expanded",
    "profile_inferred",
    "private_ground_truth_disclosed",
    "expected_reference_disclosed",
    "raw_sarif_disclosed",
    "controlled_query_disclosed",
    "response_body_disclosed",
    "transcript_disclosed",
    "raw_evidence_disclosed",
    "route_details_disclosed",
    "filesystem_coordinates_disclosed",
    "graph_included",
    "graph_mutation_authorized",
    "report_creation_authorized",
    "report_delivery_authorized",
    "external_delivery_authorized",
    "capability_activation_authorized",
    "permit_issuance_authorized",
    "route_reuse_authorized",
    "additional_execution_authorized",
    "target_side_effect_performed",
    "provider_side_effect_performed",
    "docker_side_effect_performed",
    "worker_side_effect_performed",
    "network_side_effect_performed",
    "credential_side_effect_performed",
    "external_system_side_effect_performed",
    "http_entrypoint_available",
    "ui_entrypoint_available",
)


class WebMeasuredProductAuthorityBoundary(_FrozenStrictModel):
    """Literal non-authority ceiling attached to every UX-009A projection."""

    source_authority_contextually_verified: Literal[True] = Field(
        default=True,
        alias="sourceAuthorityContextuallyVerified",
    )
    read_only_projection: Literal[True] = Field(default=True, alias="readOnlyProjection")
    evidence_content_redacted: Literal[True] = Field(
        default=True,
        alias="evidenceContentRedacted",
    )
    web_002c_graph_predecessor_required: Literal[False] = Field(
        default=False,
        alias="web002cGraphPredecessorRequired",
    )
    campaign_scope_available: Literal[False] = Field(
        default=False,
        alias="campaignScopeAvailable",
    )
    scope_expanded: Literal[False] = Field(default=False, alias="scopeExpanded")
    profile_inferred: Literal[False] = Field(default=False, alias="profileInferred")
    private_ground_truth_disclosed: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthDisclosed",
    )
    expected_reference_disclosed: Literal[False] = Field(
        default=False,
        alias="expectedReferenceDisclosed",
    )
    raw_sarif_disclosed: Literal[False] = Field(default=False, alias="rawSarifDisclosed")
    controlled_query_disclosed: Literal[False] = Field(
        default=False,
        alias="controlledQueryDisclosed",
    )
    response_body_disclosed: Literal[False] = Field(
        default=False,
        alias="responseBodyDisclosed",
    )
    transcript_disclosed: Literal[False] = Field(
        default=False,
        alias="transcriptDisclosed",
    )
    raw_evidence_disclosed: Literal[False] = Field(
        default=False,
        alias="rawEvidenceDisclosed",
    )
    route_details_disclosed: Literal[False] = Field(
        default=False,
        alias="routeDetailsDisclosed",
    )
    filesystem_coordinates_disclosed: Literal[False] = Field(
        default=False,
        alias="filesystemCoordinatesDisclosed",
    )
    graph_included: Literal[False] = Field(default=False, alias="graphIncluded")
    graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="graphMutationAuthorized",
    )
    report_creation_authorized: Literal[False] = Field(
        default=False,
        alias="reportCreationAuthorized",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    route_reuse_authorized: Literal[False] = Field(
        default=False,
        alias="routeReuseAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )
    target_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="targetSideEffectPerformed",
    )
    provider_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="providerSideEffectPerformed",
    )
    docker_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="dockerSideEffectPerformed",
    )
    worker_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="workerSideEffectPerformed",
    )
    network_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="networkSideEffectPerformed",
    )
    credential_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="credentialSideEffectPerformed",
    )
    external_system_side_effect_performed: Literal[False] = Field(
        default=False,
        alias="externalSystemSideEffectPerformed",
    )
    http_entrypoint_available: Literal[False] = Field(
        default=False,
        alias="httpEntrypointAvailable",
    )
    ui_entrypoint_available: Literal[False] = Field(
        default=False,
        alias="uiEntrypointAvailable",
    )

    @field_validator(*_BOUNDARY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB measured product verification markers must be true")
        return value

    @field_validator(*_BOUNDARY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB measured product authority markers must be false")
        return value


class WebMeasuredProductFlowProjection(_FrozenStrictModel):
    """One content-addressed bounded product view over an exact WEB-002D authority."""

    api_version: Literal["pajin.dev/web-measured-product-flow-projection/v1alpha1"] = Field(
        default=WEB_MEASURED_PRODUCT_FLOW_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebMeasuredProductFlowProjection"] = "WebMeasuredProductFlowProjection"
    flow_id: str = Field(default="", alias="flowId", max_length=110)
    flow_digest: str = Field(default="", alias="flowDigest", max_length=64)
    source_run_id: _RunId = Field(alias="sourceRunId")
    source_authority_id: str = Field(
        alias="sourceAuthorityId",
        pattern=r"^web-controlled-validation:[a-f0-9]{64}$",
    )
    source_authority_digest: _Sha256 = Field(alias="sourceAuthorityDigest")
    scope: WebMeasuredProductScopeProjection
    evidence: WebMeasuredProductEvidenceProjection
    floor: WebMeasuredProductFloorProjection
    finding: WebMeasuredProductFindingProjection
    report: WebMeasuredProductReportProjection
    authority_boundary: WebMeasuredProductAuthorityBoundary = Field(alias="authorityBoundary")

    @model_validator(mode="after")
    def bind_product_flow(self) -> Self:
        if (
            self.source_authority_id != f"web-controlled-validation:{self.source_authority_digest}"
            or self.scope.source_measurement != self.finding.source_measurement
            or self.evidence.floor_evaluation != self.floor.evaluation
            or self.evidence.floor_evaluation != self.finding.evaluation
            or self.evidence.finding != self.finding.finding
            or self.floor.projection_policy != self.finding.projection_policy
        ):
            raise ValueError("WEB measured product source references differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"flow_id", "flow_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-measured-product-flow/v1",
            material,
            max_bytes=_MAX_PRODUCT_FLOW_BYTES,
        )
        flow_id = f"web-measured-product-flow:{digest}"
        if self.flow_digest and self.flow_digest != digest:
            raise ValueError("WEB measured product flow Digest differs")
        if self.flow_id and self.flow_id != flow_id:
            raise ValueError("WEB measured product flow ID differs")
        object.__setattr__(self, "flow_digest", digest)
        object.__setattr__(self, "flow_id", flow_id)
        return self


@dataclass(frozen=True, slots=True)
class WebMeasuredProductSourceReopenContext:
    """Complete verifier-owned context needed to reopen one WEB-002D authority."""

    measured_case_authority: WebMeasuredCaseAuthority
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    source_reopen_context: WebZAPSourceMeasurementReopenContext
    floor_policy: WebBenchmarkValidationFloorPolicy
    mapping: WebExpectedFindingProjectionMapping
    trust_anchor: WebProxyRouteTrustAnchor
    claim_ledger: WebControlledValidationRouteClaimLedger
    target_journal: BenchmarkTargetOperationJournal
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter
    adapter: DockerWebControlledValidationAdapter
    denial_route_authority: WebProxyRouteLiveAuthorityContext


@dataclass(frozen=True, slots=True)
class WebMeasuredProductFlowOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    projection: WebMeasuredProductFlowProjection
    source: WebControlledValidationAuthorityOutcome


class WebMeasuredProductFlowProjector:
    """Contextually reopen WEB-002D and seal one UX-009A projection."""

    def __init__(self, *, output_root: Path) -> None:
        if not isinstance(output_root, Path):
            raise TypeError("WEB measured product flow requires a Path output root")
        self._output_root = output_root

    def project(
        self,
        source: WebControlledValidationAuthorityOutcome,
        *,
        reopen_context: WebMeasuredProductSourceReopenContext,
    ) -> WebMeasuredProductFlowOutcome:
        try:
            authority = _load_source_authority(source, reopen_context)
            projection = _build_product_flow(source.run_id, authority)
            store = RunStore.create(self._output_root, "web-measured-product-flow")
            if store.run_id == source.run_id:
                raise ValueError("WEB measured product flow Run reuses its source Run")
            store.append_event(
                "campaign.started",
                {
                    "purpose": "web-measured-product-flow",
                    "sourceRunId": source.run_id,
                    "sourceAuthorityId": authority.authority_id,
                },
            )
            artifact_path = store.write_json(
                WEB_MEASURED_PRODUCT_FLOW_PATH,
                projection.model_dump(mode="json", by_alias=True),
            )
            store.append_event(
                "product.web-measured-flow.projected",
                _event_payload(artifact_path, projection),
            )
            store.append_event("campaign.completed", {"status": "completed"})
            store.seal()
            outcome = WebMeasuredProductFlowOutcome(
                run_id=store.run_id,
                run_path=store.path,
                artifact_path=artifact_path,
                projection=projection.model_copy(deep=True),
                source=source,
            )
            load_web_measured_product_flow(outcome, reopen_context=reopen_context)
            return outcome
        except WebMeasuredProductFlowError:
            raise
        except Exception as exc:
            raise WebMeasuredProductFlowError(
                "WEB measured product flow projection failed closed"
            ) from exc


def load_web_measured_product_flow(
    outcome: WebMeasuredProductFlowOutcome,
    *,
    reopen_context: WebMeasuredProductSourceReopenContext,
) -> WebMeasuredProductFlowProjection:
    """Reopen WEB-002D first, then verify and rebuild one sealed UX-009A Run."""

    try:
        authority = _load_source_authority(outcome.source, reopen_context)
        if outcome.artifact_path != WEB_MEASURED_PRODUCT_FLOW_PATH:
            raise ValueError("WEB measured product flow artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.artifact_path: _MAX_PRODUCT_FLOW_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        parse_strict_json_bytes(
            sealed_bytes,
            label="sealed WEB measured product flow",
            max_bytes=_MAX_PRODUCT_FLOW_BYTES,
        )
        sealed = WebMeasuredProductFlowProjection.model_validate_json(sealed_bytes)
        rebuilt = _build_product_flow(outcome.source.run_id, authority)
        expected_events = (
            "campaign.started",
            "product.web-measured-flow.projected",
            "campaign.completed",
        )
        if (
            outcome.run_id == outcome.source.run_id
            or tuple(item.event_type for item in snapshot.events) != expected_events
            or sealed != outcome.projection
            or sealed != rebuilt
            or sealed_bytes != _strict_run_json_bytes(sealed.model_dump(mode="json", by_alias=True))
            or snapshot.events[0].payload
            != {
                "purpose": "web-measured-product-flow",
                "sourceRunId": outcome.source.run_id,
                "sourceAuthorityId": authority.authority_id,
            }
            or snapshot.events[1].payload != _event_payload(outcome.artifact_path, sealed)
            or snapshot.events[2].payload != {"status": "completed"}
        ):
            raise ValueError("WEB measured product flow publication differs")
        return sealed.model_copy(deep=True)
    except WebMeasuredProductFlowError:
        raise
    except (
        AttributeError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
        WebControlledValidationAuthorityError,
    ) as exc:
        raise WebMeasuredProductFlowError(
            "WEB measured product flow is not sealed and reproducible"
        ) from exc


def _load_source_authority(
    source: WebControlledValidationAuthorityOutcome,
    context: WebMeasuredProductSourceReopenContext,
) -> WebControlledValidationAuthority:
    return load_web_controlled_validation_authority(
        source,
        measured_case_authority=context.measured_case_authority,
        private_ground_truth_profile=context.private_ground_truth_profile,
        source_reopen_context=context.source_reopen_context,
        floor_policy=context.floor_policy,
        mapping=context.mapping,
        trust_anchor=context.trust_anchor,
        claim_ledger=context.claim_ledger,
        target_journal=context.target_journal,
        provider=context.provider,
        adapter=context.adapter,
        denial_route_authority=context.denial_route_authority,
    )


def _build_product_flow(
    source_run_id: str,
    authority: WebControlledValidationAuthority,
) -> WebMeasuredProductFlowProjection:
    evaluation = authority.floor_evaluation
    finding = authority.finding
    denial = evaluation.denial_control
    metrics = tuple(
        WebBenchmarkMetricObservation.model_validate(item.model_dump(mode="python", by_alias=True))
        for item in evaluation.observations
    )
    if (
        authority.source_measurement_verified is not True
        or authority.policy_denial_control_satisfied is not True
        or authority.target_cleanup_verified is not True
        or authority.benchmark_validation_floor_satisfied is not True
        or authority.bounded_product_finding_confirmed is not True
        or authority.private_ground_truth_disclosure_authorized is not False
        or authority.raw_sarif_disclosure_authorized is not False
        or authority.controlled_query_disclosure_authorized is not False
        or authority.scope_expansion_authorized is not False
        or authority.graph_mutation_authorized is not False
        or authority.reporting_authorized is not False
        or authority.external_delivery_authorized is not False
        or authority.permit_issuance_authorized is not False
        or authority.additional_execution_authorized is not False
        or len(evaluation.source_evidence_names) != 6
        or len(evaluation.controlled_validation_evidence_names) != 10
        or len(metrics) != 14
        or sum(item.applicability.value == "required" for item in metrics) != 11
        or sum(item.applicability.value == "not-applicable" for item in metrics) != 3
        or finding.evaluation != evaluation.reference()
        or finding.source_measurement != authority.source_measurement
        or finding.projection_policy != authority.projection_policy
    ):
        raise ValueError("WEB measured product source authority ceiling differs")
    return WebMeasuredProductFlowProjection(
        sourceRunId=source_run_id,
        sourceAuthorityId=authority.authority_id,
        sourceAuthorityDigest=authority.authority_digest,
        scope=WebMeasuredProductScopeProjection(
            measuredCase=authority.measured_case,
            sourceMeasurement=authority.source_measurement,
        ),
        evidence=WebMeasuredProductEvidenceProjection(
            floorEvaluation=evaluation.reference(),
            finding=finding.reference(),
            denialControlObservationId=denial.observation_id,
            denialControlObservationDigest=denial.observation_digest,
            denialControlSatisfied=evaluation.denial_control_satisfied,
            targetCleanupVerified=evaluation.target_cleanup_verified,
        ),
        floor=WebMeasuredProductFloorProjection(
            floorPolicy=evaluation.floor_policy,
            projectionPolicy=evaluation.projection_policy,
            evaluation=evaluation.reference(),
            metrics=metrics,
            denialControlSatisfied=evaluation.denial_control_satisfied,
            targetCleanupVerified=evaluation.target_cleanup_verified,
            benchmarkValidationFloorSatisfied=(evaluation.benchmark_validation_floor_satisfied),
        ),
        finding=WebMeasuredProductFindingProjection(
            finding=finding.reference(),
            evaluation=evaluation.reference(),
            projectionPolicy=finding.projection_policy,
            sourceMeasurement=finding.source_measurement,
            claimCeiling=finding.claim_ceiling,
            findingState=finding.finding_state,
            impactAssurance=finding.impact_assurance,
            severityAssurance=finding.severity_assurance,
            benchmarkGroundTruthMatchConfirmed=(finding.benchmark_ground_truth_match_confirmed),
            productFindingConfirmed=finding.product_finding_confirmed,
        ),
        report=WebMeasuredProductReportProjection(),
        authorityBoundary=WebMeasuredProductAuthorityBoundary(),
    )


def _event_payload(
    artifact_path: str,
    projection: WebMeasuredProductFlowProjection,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "flowId": projection.flow_id,
        "flowDigest": projection.flow_digest,
        "sourceRunId": projection.source_run_id,
        "sourceAuthorityId": projection.source_authority_id,
        "sourceAuthorityDigest": projection.source_authority_digest,
        "evaluationDigest": projection.floor.evaluation.evaluation_digest,
        "findingDigest": projection.finding.finding.finding_digest,
        "claimCeiling": projection.finding.claim_ceiling,
        "reportAvailable": projection.report.report_available,
        "graphIncluded": projection.authority_boundary.graph_included,
        "additionalExecutionAuthorized": (
            projection.authority_boundary.additional_execution_authorized
        ),
    }


def _strict_run_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


__all__ = [
    "WEB_MEASURED_PRODUCT_FLOW_API_VERSION",
    "WEB_MEASURED_PRODUCT_FLOW_PATH",
    "WebMeasuredProductAuthorityBoundary",
    "WebMeasuredProductEvidenceProjection",
    "WebMeasuredProductFindingProjection",
    "WebMeasuredProductFloorProjection",
    "WebMeasuredProductFlowError",
    "WebMeasuredProductFlowOutcome",
    "WebMeasuredProductFlowProjection",
    "WebMeasuredProductFlowProjector",
    "WebMeasuredProductReportProjection",
    "WebMeasuredProductScopeProjection",
    "WebMeasuredProductSourceReopenContext",
    "load_web_measured_product_flow",
]
