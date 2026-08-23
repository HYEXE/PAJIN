"""WEB-001D independent Web Replay proof and private benchmark Ground Truth profile."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.target_catalog import (
    BenchmarkTargetGroundTruthBinding,
    BenchmarkTargetProfileCatalog,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
)
from pajin.discovery.models import HTTPSurfaceLocator
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow.pentest_recon_replay import (
    PentestReconReplayComparisonAuthority,
    PentestReconReplayComparisonOutcome,
    load_pentest_recon_replay_comparison,
)
from pajin.workflow.web_discovery_admission import WebDiscoveryAdmission

WEB_API_BENCHMARK_GROUND_TRUTH_PROFILE_API_VERSION: Literal[
    "pajin.dev/web-api-benchmark-ground-truth-profile/v1alpha1"
] = "pajin.dev/web-api-benchmark-ground-truth-profile/v1alpha1"
WEB_DISCOVERY_REPLAY_VALIDATION_API_VERSION: Literal[
    "pajin.dev/web-discovery-replay-validation/v1alpha1"
] = "pajin.dev/web-discovery-replay-validation/v1alpha1"

_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_REPLAY_FALSE_FIELDS = (
    "ground_truth_case_bound",
    "benchmark_measurement_observed",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "execution_authorized",
)
_GROUND_TRUTH_FALSE_FIELDS = (
    "target_profile_selected",
    "target_factory_authority",
    "provider_execution_authorized",
    "measurement_observed",
    "replay_evidence_bound",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "permit_issuance_authorized",
    "execution_authorized",
)


class WebReplayBenchmarkError(RuntimeError):
    """Raised when WEB-001D Replay or Ground Truth lineage differs."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WebDiscoveryReplayValidation(_FrozenStrictModel):
    """Body-free proof that WEB-001C received one independently authorized Replay."""

    api_version: Literal["pajin.dev/web-discovery-replay-validation/v1alpha1"] = Field(
        default=WEB_DISCOVERY_REPLAY_VALIDATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebDiscoveryReplayValidation"] = "WebDiscoveryReplayValidation"
    validation_id: str = Field(default="", alias="validationId", max_length=110)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    web_admission: WebDiscoveryAdmission = Field(alias="webAdmission")
    replay_comparison: PentestReconReplayComparisonAuthority = Field(alias="replayComparison")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    state: Literal[
        "independent-replay-response-match",
        "independent-replay-response-changed",
    ]
    independent_replay_verified: Literal[True] = Field(
        default=True,
        alias="independentReplayVerified",
    )
    response_replay_matched: bool = Field(alias="responseReplayMatched")
    ground_truth_case_bound: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("independent_replay_verified", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-001D independent Replay marker must be boolean true")
        return value

    @field_validator("response_replay_matched", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("WEB-001D response Replay marker must be a boolean")
        return value

    @field_validator(*_REPLAY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-001D Replay projection authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_replay_validation(self) -> Self:
        plan = self.replay_comparison.authorization.plan
        locator = self.web_admission.candidate.preparation.surface.locator
        try:
            domain_plan = resolve_registered_domain_benchmark_plan(self.domain_benchmark_plan)
        except Exception as exc:
            raise ValueError("WEB-001D Domain benchmark plan is not registered exactly") from exc
        matched = (
            self.replay_comparison.comparison.comparison_state
            == "response-metadata-and-body-digest-match"
        )
        expected_state = (
            "independent-replay-response-match"
            if matched
            else "independent-replay-response-changed"
        )
        if (
            not isinstance(locator, HTTPSurfaceLocator)
            or self.web_admission.pentest_admission != plan.source_admission
            or self.replay_comparison.source_admission_id
            != self.web_admission.pentest_admission.admission_id
            or self.replay_comparison.source_admission_digest
            != self.web_admission.pentest_admission.admission_digest
            or locator.url != plan.target
            or locator.method != plan.method
            or domain_plan.domain_classification.domain is not SecurityDomain.WEB
            or domain_plan.validation_strategy is not DomainValidationStrategy.INDEPENDENT_REPLAY
            or not self.replay_comparison.independently_authorized_replay_verified
            or self.response_replay_matched is not matched
            or self.state != expected_state
        ):
            raise ValueError("WEB-001D Replay differs from sealed Web source semantics")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-discovery-replay-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"web-discovery-replay_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("WEB-001D Replay validation Digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("WEB-001D Replay validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


class WebAPIBenchmarkGroundTruthProfile(_FrozenStrictModel):
    """Private code-owned P0-D1 Ground Truth bound to the DOMAIN-006 Web plan."""

    api_version: Literal["pajin.dev/web-api-benchmark-ground-truth-profile/v1alpha1"] = Field(
        default=WEB_API_BENCHMARK_GROUND_TRUTH_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAPIBenchmarkGroundTruthProfile"] = "WebAPIBenchmarkGroundTruthProfile"
    profile_id: str = Field(default="", alias="profileId", max_length=110)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    target_profile: DockerBugBountyTargetProfile = Field(alias="targetProfile")
    target_catalog: BenchmarkTargetProfileCatalog = Field(alias="targetCatalog")
    private_ground_truth: BenchmarkTargetGroundTruthBinding = Field(alias="privateGroundTruth")
    state: Literal["registered-ground-truth-not-measured"] = "registered-ground-truth-not-measured"
    private_ground_truth_verified: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthVerified",
    )
    target_profile_selected: Literal[False] = Field(
        default=False,
        alias="targetProfileSelected",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    measurement_observed: Literal[False] = Field(
        default=False,
        alias="measurementObserved",
    )
    replay_evidence_bound: Literal[False] = Field(
        default=False,
        alias="replayEvidenceBound",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("private_ground_truth_verified", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-001D Ground Truth marker must be boolean true")
        return value

    @field_validator(*_GROUND_TRUTH_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-001D Ground Truth authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_ground_truth_profile(self) -> Self:
        try:
            domain_plan = resolve_registered_domain_benchmark_plan(self.domain_benchmark_plan)
            expected_ground_truth = registered_traditional_web_api_ground_truth(
                self.target_profile,
                benchmark_id=self.private_ground_truth.ground_truth.benchmark_id,
            )
            expected_catalog = registered_traditional_web_api_target_catalog(
                self.target_profile,
                expected_ground_truth,
            )
            expected_private = BenchmarkTargetGroundTruthBinding(
                registration=expected_catalog.registrations[0],
                groundTruth=expected_ground_truth,
            )
        except Exception as exc:
            raise ValueError("WEB-001D Ground Truth profile is not code-registered") from exc
        if (
            domain_plan.domain_classification.domain is not SecurityDomain.WEB
            or domain_plan.validation_strategy is not DomainValidationStrategy.INDEPENDENT_REPLAY
            or self.target_catalog != expected_catalog
            or self.private_ground_truth != expected_private
        ):
            raise ValueError("WEB-001D Ground Truth differs from the registered Web profile")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-api-benchmark-ground-truth-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"web-api-ground-truth_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("WEB-001D Ground Truth profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("WEB-001D Ground Truth profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


def bind_web_discovery_independent_replay(
    web_admission: WebDiscoveryAdmission,
    comparison_outcome: PentestReconReplayComparisonOutcome,
) -> WebDiscoveryReplayValidation:
    """Reopen the sealed PENTEST-002B comparison and bind it to WEB-001C."""

    try:
        canonical_admission = WebDiscoveryAdmission.model_validate(
            web_admission.model_dump(mode="json", by_alias=True)
        )
        comparison = load_pentest_recon_replay_comparison(comparison_outcome)
        matched = (
            comparison.comparison.comparison_state == "response-metadata-and-body-digest-match"
        )
        return WebDiscoveryReplayValidation(
            webAdmission=canonical_admission,
            replayComparison=comparison,
            domainBenchmarkPlan=_web_domain_benchmark_plan_ref(),
            state=(
                "independent-replay-response-match"
                if matched
                else "independent-replay-response-changed"
            ),
            responseReplayMatched=matched,
        )
    except WebReplayBenchmarkError:
        raise
    except (AttributeError, ValidationError, ValueError, RuntimeError) as exc:
        raise WebReplayBenchmarkError("WEB-001D independent Replay binding failed closed") from exc


def registered_web_api_benchmark_ground_truth_profile(
    target_profile: DockerBugBountyTargetProfile,
    *,
    benchmark_id: str,
) -> WebAPIBenchmarkGroundTruthProfile:
    """Bind the existing private P0-D1 Ground Truth without selecting a Target Factory."""

    try:
        canonical_profile = DockerBugBountyTargetProfile.model_validate(
            target_profile.model_dump(mode="json", by_alias=True)
        )
        ground_truth = registered_traditional_web_api_ground_truth(
            canonical_profile,
            benchmark_id=benchmark_id,
        )
        catalog = registered_traditional_web_api_target_catalog(
            canonical_profile,
            ground_truth,
        )
        private_binding = BenchmarkTargetGroundTruthBinding(
            registration=catalog.registrations[0],
            groundTruth=ground_truth,
        )
        return WebAPIBenchmarkGroundTruthProfile(
            domainBenchmarkPlan=_web_domain_benchmark_plan_ref(),
            targetProfile=canonical_profile,
            targetCatalog=catalog,
            privateGroundTruth=private_binding,
        )
    except (AttributeError, ValidationError, ValueError, RuntimeError) as exc:
        raise WebReplayBenchmarkError(
            "WEB-001D Web/API Ground Truth registration failed closed"
        ) from exc


def _web_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.WEB:
            return plan.reference()
    raise WebReplayBenchmarkError("DOMAIN-006 Web benchmark plan is missing")


__all__ = [
    "WEB_API_BENCHMARK_GROUND_TRUTH_PROFILE_API_VERSION",
    "WEB_DISCOVERY_REPLAY_VALIDATION_API_VERSION",
    "WebAPIBenchmarkGroundTruthProfile",
    "WebDiscoveryReplayValidation",
    "WebReplayBenchmarkError",
    "bind_web_discovery_independent_replay",
    "registered_web_api_benchmark_ground_truth_profile",
]
