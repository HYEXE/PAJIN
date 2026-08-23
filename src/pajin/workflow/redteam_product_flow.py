"""UX-008 read-only REDTEAM Scope, Evidence, Finding, and report projection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.benchmark.redteam import (
    RedteamBenchmarkError,
    RedteamBenchmarkMetric,
    RedteamBenchmarkMetricStatus,
    RedteamBenchmarkProfileSet,
    RedteamBenchmarkRunObservation,
    RedteamBenchmarkRunObservationOutcome,
    RedteamBenchmarkSourceKind,
    RedteamInitialBenchmarkOutcome,
    RedteamInitialBenchmarkReport,
    RedteamProfileBenchmarkContract,
    load_redteam_initial_benchmark_report,
)
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
    validate_run_artifact_path,
)

REDTEAM_PRODUCT_FLOW_API_VERSION: Literal[
    "pajin.dev/redteam-product-flow-projection/v1alpha1"
] = "pajin.dev/redteam-product-flow-projection/v1alpha1"
REDTEAM_PRODUCT_FLOW_PATH = "redteam-product-flow-projection.json"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_MAX_PRODUCT_FLOW_BYTES = 16 * 1024 * 1024


class RedteamProductFlowError(RuntimeError):
    """Raised when UX-008 cannot reproduce one exact read-only projection."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class RedteamProductScopeProjection(_FrozenStrictModel):
    """Profile-bound scope summary that intentionally omits Campaign Scope authority."""

    profile_id: _Identifier = Field(alias="profileId")
    profile_version: _Identifier = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    profile_contract_digest: _Sha256 = Field(alias="profileContractDigest")
    capabilities: tuple[CodeBackedCapabilityRef, ...] = Field(min_length=1, max_length=16)
    source_observation_count: int = Field(
        alias="sourceObservationCount",
        strict=True,
        ge=1,
        le=10_000,
    )
    scope_state: Literal["profile-bounded-campaign-scope-not-projected"] = Field(
        default="profile-bounded-campaign-scope-not-projected",
        alias="scopeState",
    )
    campaign_scope_available: Literal[False] = Field(
        default=False,
        alias="campaignScopeAvailable",
    )
    scope_authorized: Literal[False] = Field(default=False, alias="scopeAuthorized")
    scope_expanded: Literal[False] = Field(default=False, alias="scopeExpanded")

    @field_validator(
        "campaign_scope_available",
        "scope_authorized",
        "scope_expanded",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("REDTEAM product Scope authority markers must be false")
        return value

    @model_validator(mode="after")
    def require_unique_capabilities(self) -> Self:
        identities = tuple(
            (
                item.capability.capability_id,
                item.capability.capability_version,
                item.capability.capability_digest,
                item.authority_set_digest,
            )
            for item in self.capabilities
        )
        if identities != tuple(sorted(set(identities))):
            raise ValueError("REDTEAM product Scope Capabilities must be unique and ordered")
        return self


class RedteamProductEvidenceProjection(_FrozenStrictModel):
    """Content-free reference to one source Observation reverified from its sealed Run."""

    observation_id: str = Field(
        alias="observationId",
        min_length=1,
        max_length=110,
        pattern=r"^redteam-benchmark-observation:[a-f0-9]{64}$",
    )
    observation_digest: _Sha256 = Field(alias="observationDigest")
    profile_id: _Identifier = Field(alias="profileId")
    capability: CodeBackedCapabilityRef
    source_kind: RedteamBenchmarkSourceKind = Field(alias="sourceKind")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: str = Field(
        alias="sourceArtifactPath",
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,499}$",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    detection_case_count: int = Field(
        alias="detectionCaseCount",
        strict=True,
        ge=0,
        le=1_000,
    )
    replay_case_count: int = Field(
        alias="replayCaseCount",
        strict=True,
        ge=0,
        le=1_000,
    )
    evidence_expected_count: int = Field(
        alias="evidenceExpectedCount",
        strict=True,
        ge=0,
        le=1_000_000_000,
    )
    evidence_verified_count: int = Field(
        alias="evidenceVerifiedCount",
        strict=True,
        ge=0,
        le=1_000_000_000,
    )
    evidence_state: Literal["sealed-source-reference-verified"] = Field(
        default="sealed-source-reference-verified",
        alias="evidenceState",
    )
    sealed_source_verified: Literal[True] = Field(
        default=True,
        alias="sealedSourceVerified",
    )
    evidence_content_included: Literal[False] = Field(
        default=False,
        alias="evidenceContentIncluded",
    )
    observation_is_finding: Literal[False] = Field(
        default=False,
        alias="observationIsFinding",
    )

    @field_validator("sealed_source_verified", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("REDTEAM product Evidence verification marker must be true")
        return value

    @field_validator(
        "evidence_content_included",
        "observation_is_finding",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("REDTEAM product Evidence authority markers must be false")
        return value

    @field_validator("source_artifact_path")
    @classmethod
    def require_normalized_artifact_path(cls, value: str) -> str:
        if validate_run_artifact_path(value) != value:
            raise ValueError("REDTEAM product Evidence path must be normalized")
        return value

    @model_validator(mode="after")
    def require_evidence_count_order(self) -> Self:
        if (
            self.observation_id
            != f"redteam-benchmark-observation:{self.observation_digest}"
            or self.evidence_verified_count > self.evidence_expected_count
        ):
            raise ValueError("REDTEAM product Evidence identity or count differs")
        return self


class RedteamProductFindingProjection(_FrozenStrictModel):
    """Explicit absence of a confirmed Finding for one REDTEAM-001 product profile."""

    profile_id: _Identifier = Field(alias="profileId")
    source_observation_count: int = Field(
        alias="sourceObservationCount",
        strict=True,
        ge=1,
        le=10_000,
    )
    finding_state: Literal["not-confirmed-no-profile-validation-authority"] = Field(
        default="not-confirmed-no-profile-validation-authority",
        alias="findingState",
    )
    validation_floor_state: Literal[
        "not-evaluated-redteam-profile-is-not-campaign-profile"
    ] = Field(
        default="not-evaluated-redteam-profile-is-not-campaign-profile",
        alias="validationFloorState",
    )
    confirmed_finding_count: Literal[0] = Field(default=0, alias="confirmedFindingCount")
    campaign_profile_mapping_registered: Literal[False] = Field(
        default=False,
        alias="campaignProfileMappingRegistered",
    )
    validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="validationFloorSatisfied",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "campaign_profile_mapping_registered",
        "validation_floor_satisfied",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("REDTEAM product Finding authority markers must be false")
        return value

    @field_validator("confirmed_finding_count", mode="before")
    @classmethod
    def require_integer_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("REDTEAM product confirmed Finding count must be integer zero")
        return value


class RedteamProductMeasurementReportProjection(_FrozenStrictModel):
    """Exact REDTEAM-002 report retained as measurement, never as a Finding report."""

    report: RedteamInitialBenchmarkReport
    report_state: Literal["measurement-only-not-a-finding-report"] = Field(
        default="measurement-only-not-a-finding-report",
        alias="reportState",
    )
    confirmed_finding_count: Literal[0] = Field(default=0, alias="confirmedFindingCount")
    finding_report_available: Literal[False] = Field(
        default=False,
        alias="findingReportAvailable",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )

    @field_validator(
        "finding_report_available",
        "external_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("REDTEAM product report authority markers must be false")
        return value

    @field_validator("confirmed_finding_count", mode="before")
    @classmethod
    def require_integer_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("REDTEAM product report Finding count must be integer zero")
        return value


class RedteamProductFlowAuthorityBoundary(_FrozenStrictModel):
    """Literal non-authority boundary attached to every UX-008 projection."""

    sealed_benchmark_and_sources_verified: Literal[True] = Field(
        default=True,
        alias="sealedBenchmarkAndSourcesVerified",
    )
    read_only_projection: Literal[True] = Field(default=True, alias="readOnlyProjection")
    evidence_content_redacted: Literal[True] = Field(
        default=True,
        alias="evidenceContentRedacted",
    )
    campaign_profile_mapping_inferred: Literal[False] = Field(
        default=False,
        alias="campaignProfileMappingInferred",
    )
    scope_authority_granted: Literal[False] = Field(
        default=False,
        alias="scopeAuthorityGranted",
    )
    scope_expanded: Literal[False] = Field(default=False, alias="scopeExpanded")
    validation_authority_granted: Literal[False] = Field(
        default=False,
        alias="validationAuthorityGranted",
    )
    finding_authority_granted: Literal[False] = Field(
        default=False,
        alias="findingAuthorityGranted",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "sealed_benchmark_and_sources_verified",
        "read_only_projection",
        "evidence_content_redacted",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("REDTEAM product verification markers must be true")
        return value

    @field_validator(
        "campaign_profile_mapping_inferred",
        "scope_authority_granted",
        "scope_expanded",
        "validation_authority_granted",
        "finding_authority_granted",
        "report_delivery_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("REDTEAM product authority markers must be false")
        return value


class RedteamProductFlowProjection(_FrozenStrictModel):
    """One content-addressed read-only product flow over exact sealed inputs."""

    api_version: Literal["pajin.dev/redteam-product-flow-projection/v1alpha1"] = Field(
        default=REDTEAM_PRODUCT_FLOW_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RedteamProductFlowProjection"] = "RedteamProductFlowProjection"
    flow_id: str = Field(default="", alias="flowId", max_length=110)
    flow_digest: str = Field(default="", alias="flowDigest", max_length=64)
    profile_set_digest: _Sha256 = Field(alias="profileSetDigest")
    source_observation_digests: tuple[_Sha256, ...] = Field(
        alias="sourceObservationDigests",
        min_length=1,
        max_length=10_000,
    )
    scopes: tuple[RedteamProductScopeProjection, ...] = Field(min_length=4, max_length=4)
    evidence: tuple[RedteamProductEvidenceProjection, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    findings: tuple[RedteamProductFindingProjection, ...] = Field(
        min_length=4,
        max_length=4,
    )
    measurement_report: RedteamProductMeasurementReportProjection = Field(
        alias="measurementReport"
    )
    authority_boundary: RedteamProductFlowAuthorityBoundary = Field(alias="authorityBoundary")

    @model_validator(mode="after")
    def bind_product_flow(self) -> Self:
        report = self.measurement_report.report
        profile_ids = tuple(item.profile_id for item in report.profile_set.profiles)
        scope_ids = tuple(item.profile_id for item in self.scopes)
        finding_ids = tuple(item.profile_id for item in self.findings)
        evidence_digests = tuple(item.observation_digest for item in self.evidence)
        if (
            self.profile_set_digest != report.profile_set.profile_set_digest
            or self.source_observation_digests != report.source_observation_digests
            or evidence_digests != tuple(sorted(set(evidence_digests)))
            or evidence_digests != self.source_observation_digests
            or scope_ids != profile_ids
            or finding_ids != profile_ids
            or report.finding_authority_granted
            or report.execution_authority_granted
            or report.scope_expanded
        ):
            raise ValueError("REDTEAM product flow differs from its measurement report")
        source_counts = {
            profile_id: sum(item.profile_id == profile_id for item in self.evidence)
            for profile_id in profile_ids
        }
        evidence_sources = {
            profile_id: tuple(
                sorted(
                    item.observation_digest
                    for item in self.evidence
                    if item.profile_id == profile_id
                )
            )
            for profile_id in profile_ids
        }
        for profile, result, scope, finding in zip(
            report.profile_set.profiles,
            report.profile_results,
            self.scopes,
            self.findings,
            strict=True,
        ):
            expected_capabilities = tuple(
                sorted(
                    (item.capability for item in profile.capabilities),
                    key=lambda item: (
                        item.capability.capability_id,
                        item.capability.capability_version,
                        item.authority_set_digest,
                    ),
                )
            )
            if (
                scope.profile_version != profile.profile_version
                or scope.profile_digest != profile.profile_digest
                or scope.profile_contract_digest != profile.contract_digest
                or scope.capabilities != expected_capabilities
                or scope.source_observation_count != source_counts[scope.profile_id]
                or finding.source_observation_count != source_counts[finding.profile_id]
                or evidence_sources[profile.profile_id] != result.source_observation_digests
            ):
                raise ValueError("REDTEAM product Profile projection differs")
        for result in report.profile_results:
            finding_metric = next(
                item
                for item in result.metrics
                if item.metric is RedteamBenchmarkMetric.TIME_TO_FIRST_VALID_FINDING
            )
            if finding_metric.status is not RedteamBenchmarkMetricStatus.NOT_APPLICABLE:
                raise ValueError("REDTEAM product flow cannot project a measured Finding")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"flow_id", "flow_digest"},
        )
        canonical_benchmark_json(
            material,
            label="RedteamProductFlowProjection",
            max_bytes=_MAX_PRODUCT_FLOW_BYTES,
        )
        digest = benchmark_digest(
            "pajin.workflow.redteam-product-flow/v1",
            material,
            max_bytes=_MAX_PRODUCT_FLOW_BYTES,
        )
        flow_id = f"redteam-product-flow:{digest}"
        if self.flow_digest and self.flow_digest != digest:
            raise ValueError("REDTEAM product flow Digest differs")
        if self.flow_id and self.flow_id != flow_id:
            raise ValueError("REDTEAM product flow ID differs")
        object.__setattr__(self, "flow_digest", digest)
        object.__setattr__(self, "flow_id", flow_id)
        return self


@dataclass(frozen=True, slots=True)
class RedteamProductFlowOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    projection: RedteamProductFlowProjection
    benchmark: RedteamInitialBenchmarkOutcome
    sources: tuple[RedteamBenchmarkRunObservationOutcome, ...]


class RedteamProductFlowProjector:
    """Reopen REDTEAM-002 and seal one read-only UX-008 product projection."""

    def __init__(self, *, output_root: Path) -> None:
        if not isinstance(output_root, Path):
            raise TypeError("REDTEAM product flow requires a Path output root")
        self._output_root = output_root

    def project(
        self,
        profile_set: RedteamBenchmarkProfileSet,
        benchmark: RedteamInitialBenchmarkOutcome,
        *,
        source_outcomes: tuple[RedteamBenchmarkRunObservationOutcome, ...],
    ) -> RedteamProductFlowOutcome:
        try:
            projection = _build_product_flow(
                profile_set,
                benchmark,
                source_outcomes=source_outcomes,
            )
            store = RunStore.create(self._output_root, "redteam-product-flow")
            predecessor_runs = {benchmark.run_id, *(item.run_id for item in source_outcomes)}
            if store.run_id in predecessor_runs:
                raise ValueError("REDTEAM product flow Run reuses a predecessor Run")
            store.append_event("campaign.started", {"purpose": "redteam-product-flow"})
            artifact_path = store.write_json(
                REDTEAM_PRODUCT_FLOW_PATH,
                projection.model_dump(mode="json", by_alias=True),
            )
            store.append_event(
                "product.redteam-flow.projected",
                _event_payload(artifact_path, projection),
            )
            store.append_event("campaign.completed", {"status": "completed"})
            store.seal()
            outcome = RedteamProductFlowOutcome(
                run_id=store.run_id,
                run_path=store.path,
                artifact_path=artifact_path,
                projection=projection.model_copy(deep=True),
                benchmark=benchmark,
                sources=source_outcomes,
            )
            load_redteam_product_flow(profile_set, outcome)
            return outcome
        except RedteamProductFlowError:
            raise
        except Exception as exc:
            raise RedteamProductFlowError("REDTEAM product flow projection failed closed") from exc


def load_redteam_product_flow(
    profile_set: RedteamBenchmarkProfileSet,
    outcome: RedteamProductFlowOutcome,
) -> RedteamProductFlowProjection:
    """Reopen one UX-008 artifact and rebuild it from every sealed predecessor."""

    try:
        if outcome.artifact_path != REDTEAM_PRODUCT_FLOW_PATH:
            raise ValueError("REDTEAM product flow artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.artifact_path: _MAX_PRODUCT_FLOW_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed = RedteamProductFlowProjection.model_validate(
            parse_strict_json_bytes(
                snapshot.artifact_bytes(outcome.artifact_path),
                label="sealed REDTEAM product flow",
                max_bytes=_MAX_PRODUCT_FLOW_BYTES,
            )
        )
        rebuilt = _build_product_flow(
            profile_set,
            outcome.benchmark,
            source_outcomes=outcome.sources,
        )
        predecessor_runs = {
            outcome.benchmark.run_id,
            *(item.run_id for item in outcome.sources),
        }
        expected_events = (
            "campaign.started",
            "product.redteam-flow.projected",
            "campaign.completed",
        )
        if (
            outcome.run_id in predecessor_runs
            or tuple(item.event_type for item in snapshot.events) != expected_events
            or sealed != outcome.projection
            or sealed != rebuilt
            or snapshot.events[1].payload != _event_payload(outcome.artifact_path, sealed)
        ):
            raise ValueError("REDTEAM product flow publication differs")
        return sealed.model_copy(deep=True)
    except RedteamProductFlowError:
        raise
    except (
        AttributeError,
        OSError,
        RedteamBenchmarkError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise RedteamProductFlowError(
            "REDTEAM product flow is not sealed and reproducible"
        ) from exc


def _build_product_flow(
    profile_set: RedteamBenchmarkProfileSet,
    benchmark: RedteamInitialBenchmarkOutcome,
    *,
    source_outcomes: tuple[RedteamBenchmarkRunObservationOutcome, ...],
) -> RedteamProductFlowProjection:
    report = load_redteam_initial_benchmark_report(
        profile_set,
        benchmark,
        source_outcomes=source_outcomes,
    )
    observations = tuple(
        sorted(
            (item.observation.model_copy(deep=True) for item in source_outcomes),
            key=lambda item: item.observation_digest,
        )
    )
    if len({item.run_id for item in source_outcomes}) != len(source_outcomes):
        raise ValueError("REDTEAM product flow source Runs must be unique")
    if benchmark.run_id in {item.run_id for item in source_outcomes}:
        raise ValueError("REDTEAM product flow aggregate Run reuses a source Run")
    return RedteamProductFlowProjection(
        profileSetDigest=report.profile_set.profile_set_digest,
        sourceObservationDigests=tuple(item.observation_digest for item in observations),
        scopes=tuple(
            _scope_projection(profile, observations)
            for profile in report.profile_set.profiles
        ),
        evidence=tuple(_evidence_projection(item) for item in observations),
        findings=tuple(
            RedteamProductFindingProjection(
                profileId=profile.profile_id,
                sourceObservationCount=sum(
                    item.profile_id == profile.profile_id for item in observations
                ),
            )
            for profile in report.profile_set.profiles
        ),
        measurementReport=RedteamProductMeasurementReportProjection(report=report),
        authorityBoundary=RedteamProductFlowAuthorityBoundary(),
    )


def _scope_projection(
    profile: RedteamProfileBenchmarkContract,
    observations: tuple[RedteamBenchmarkRunObservation, ...],
) -> RedteamProductScopeProjection:
    return RedteamProductScopeProjection(
        profileId=profile.profile_id,
        profileVersion=profile.profile_version,
        profileDigest=profile.profile_digest,
        profileContractDigest=profile.contract_digest,
        capabilities=tuple(
            sorted(
                (item.capability for item in profile.capabilities),
                key=lambda item: (
                    item.capability.capability_id,
                    item.capability.capability_version,
                    item.authority_set_digest,
                ),
            )
        ),
        sourceObservationCount=sum(
            item.profile_id == profile.profile_id for item in observations
        ),
    )


def _evidence_projection(
    observation: RedteamBenchmarkRunObservation,
) -> RedteamProductEvidenceProjection:
    return RedteamProductEvidenceProjection(
        observationId=observation.observation_id,
        observationDigest=observation.observation_digest,
        profileId=observation.profile_id,
        capability=observation.capability,
        sourceKind=observation.source_kind,
        sourceRunId=observation.source_run_id,
        sourceRootDigest=observation.source_root_digest,
        sourceArtifactPath=observation.source_artifact_path,
        sourceArtifactSha256=observation.source_artifact_sha256,
        detectionCaseCount=len(observation.detection_cases),
        replayCaseCount=len(observation.replay_cases),
        evidenceExpectedCount=observation.evidence_expected_count,
        evidenceVerifiedCount=observation.evidence_verified_count,
    )


def _event_payload(
    artifact_path: str,
    projection: RedteamProductFlowProjection,
) -> dict[str, object]:
    report = projection.measurement_report.report
    return {
        "artifact": artifact_path,
        "flowId": projection.flow_id,
        "flowDigest": projection.flow_digest,
        "reportId": report.report_id,
        "reportDigest": report.report_digest,
        "sourceCount": len(projection.evidence),
        "findingConfirmed": any(item.finding_confirmed for item in projection.findings),
        "scopeExpanded": projection.authority_boundary.scope_expanded,
        "executionAuthorized": projection.authority_boundary.execution_authorized,
    }


__all__ = [
    "REDTEAM_PRODUCT_FLOW_API_VERSION",
    "REDTEAM_PRODUCT_FLOW_PATH",
    "RedteamProductEvidenceProjection",
    "RedteamProductFindingProjection",
    "RedteamProductFlowAuthorityBoundary",
    "RedteamProductFlowError",
    "RedteamProductFlowOutcome",
    "RedteamProductFlowProjection",
    "RedteamProductFlowProjector",
    "RedteamProductMeasurementReportProjection",
    "RedteamProductScopeProjection",
    "load_redteam_product_flow",
]
