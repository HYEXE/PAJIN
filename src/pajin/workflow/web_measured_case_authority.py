"""Public-safe WEB-002A measured-case composition over exact existing authorities."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.scanner_baseline import (
    ScannerBaselineMeasurementPlanAuthority,
    plan_generic_scanner_baseline,
)
from pajin.benchmark.scanner_sarif import ZAPScannerRegistration, registered_zap_scanner
from pajin.benchmark.target_catalog import BenchmarkTargetProfileRegistration
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
)
from pajin.capabilities.models import CapabilityMaturity, capability_definition_digest
from pajin.capabilities.web_measured_validation import (
    WEB_MEASURED_VALIDATION_TARGET,
    WebMeasuredValidationCapabilityBundle,
    WebMeasuredValidationProfile,
    registered_web_measured_internal_surface,
    registered_web_measured_validation_profile,
)
from pajin.discovery.models import HTTPSurfaceLocator
from pajin.discovery.web_surfaces import WebHTTPOperationSurface
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow.web_replay_benchmark import (
    WebAPIBenchmarkGroundTruthProfile,
    registered_web_api_benchmark_ground_truth_profile,
)

WEB_MEASURED_CASE_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/web-measured-case-authority/v1alpha1"
] = "pajin.dev/web-measured-case-authority/v1alpha1"

_MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
_FALSE_FIELDS = (
    "capability_activation_authorized",
    "approval_satisfied",
    "permit_issuance_authorized",
    "proxy_route_materialized",
    "target_factory_authorized",
    "provider_execution_authorized",
    "scanner_execution_authorized",
    "worker_selected",
    "network_access_authorized",
    "measurement_observed",
    "raw_sarif_bound",
    "graph_admission_authorized",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "product_activation_authorized",
    "report_delivery_authorized",
    "execution_authorized",
)


class WebMeasuredCaseAuthorityError(RuntimeError):
    """Raised when one WEB-002A predecessor is missing, forged, or drifted."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WebMeasuredCaseAuthorityRef(_FrozenStrictModel):
    """Exact content-addressed reference to one public-safe measured case."""

    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^web-measured-case_[a-f0-9]{64}$",
    )
    authority_digest: str = Field(alias="authorityDigest", pattern=r"^[a-f0-9]{64}$")


class WebMeasuredCaseAuthority(_FrozenStrictModel):
    """Exact case composition that executes and measures nothing."""

    api_version: Literal["pajin.dev/web-measured-case-authority/v1alpha1"] = Field(
        default=WEB_MEASURED_CASE_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebMeasuredCaseAuthority"] = "WebMeasuredCaseAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=90)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    profile: WebMeasuredValidationProfile
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    capability_release_bundle_digest: str = Field(
        alias="capabilityReleaseBundleDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    surface: WebHTTPOperationSurface
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter = Field(alias="targetAdapter")
    target_registration: BenchmarkTargetProfileRegistration = Field(alias="targetRegistration")
    scanner_plan: ScannerBaselineMeasurementPlanAuthority = Field(alias="scannerPlan")
    scanner_registration: ZAPScannerRegistration = Field(alias="scannerRegistration")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    ground_truth_digest: str = Field(alias="groundTruthDigest", pattern=r"^[a-f0-9]{64}$")
    ground_truth_binding_digest: str = Field(
        alias="groundTruthBindingDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    state: Literal["registered-exact-measured-case-not-executable"] = (
        "registered-exact-measured-case-not-executable"
    )
    predecessors_verified: Literal[True] = Field(default=True, alias="predecessorsVerified")
    public_safe_registration: Literal[True] = Field(default=True, alias="publicSafeRegistration")
    private_ground_truth_verified: Literal[True] = Field(
        default=True, alias="privateGroundTruthVerified"
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    proxy_route_materialized: Literal[False] = Field(default=False, alias="proxyRouteMaterialized")
    target_factory_authorized: Literal[False] = Field(
        default=False, alias="targetFactoryAuthorized"
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False, alias="providerExecutionAuthorized"
    )
    scanner_execution_authorized: Literal[False] = Field(
        default=False, alias="scannerExecutionAuthorized"
    )
    worker_selected: Literal[False] = Field(default=False, alias="workerSelected")
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    raw_sarif_bound: Literal[False] = Field(default=False, alias="rawSarifBound")
    graph_admission_authorized: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthorized"
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="profileValidationFloorSatisfied"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    product_activation_authorized: Literal[False] = Field(
        default=False, alias="productActivationAuthorized"
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False, alias="reportDeliveryAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "predecessors_verified",
        "public_safe_registration",
        "private_ground_truth_verified",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002A measured-case verification markers must be boolean true")
        return value

    @field_validator(*_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A measured-case authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> WebMeasuredCaseAuthority:
        domain_plan = resolve_registered_domain_benchmark_plan(self.domain_benchmark_plan)
        expected_surface = registered_web_measured_internal_surface()
        expected_scanner = registered_zap_scanner(
            self.scanner_registration.scanner_image_id,
            parser_contract_digest=self.scanner_plan.scanner_contract.parser_contract_digest,
        )
        locator = self.surface.locator
        if (
            domain_plan.domain_classification.domain is not SecurityDomain.WEB
            or domain_plan.validation_strategy is not DomainValidationStrategy.INDEPENDENT_REPLAY
            or self.profile.surface != expected_surface.reference()
            or self.surface != expected_surface
            or not isinstance(locator, HTTPSurfaceLocator)
            or locator.url != WEB_MEASURED_VALIDATION_TARGET
            or locator.method != "GET"
            or self.target_adapter.adapter_digest
            != self.scanner_plan.target_selection.adapter_digest
            or self.target_adapter.target_factory_id != self.target_registration.target_factory_id
            or self.target_adapter.target_factory_version
            != self.target_registration.target_factory_version
            or self.target_adapter.target_factory_digest
            != self.target_registration.target_factory_digest
            or self.target_registration != self.scanner_plan.target_selection.registration
            or self.target_registration.ground_truth_digest != self.ground_truth_digest
            or self.scanner_plan.target_selection.ground_truth_binding_digest
            != self.ground_truth_binding_digest
            or self.scanner_registration != expected_scanner
            or self.scanner_registration.target_url != f"{WEB_MEASURED_VALIDATION_TARGET}?id=1"
        ):
            raise ValueError("WEB-002A measured-case public predecessor binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-measured-case-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"web-measured-case_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("WEB-002A measured-case authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("WEB-002A measured-case authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    def reference(self) -> WebMeasuredCaseAuthorityRef:
        """Return an exact public-safe lookup."""

        return WebMeasuredCaseAuthorityRef(
            authorityId=self.authority_id,
            authorityDigest=self.authority_digest,
        )


def bind_web_measured_case_authority(
    *,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebMeasuredCaseAuthority:
    """Rebuild every predecessor and expose only public-safe exact identities."""

    try:
        profile = registered_web_measured_validation_profile(capability_bundle)
        signed_release = lifecycle.resolve_release(release)
        _require_signed_release(signed_release, profile=profile, release=release)
        private_profile = _rebuild_private_profile(private_ground_truth_profile)
        expected_plan = plan_generic_scanner_baseline(
            scanner_plan.manifest,
            adapter=target_adapter,
            profile=private_profile.target_profile,
            catalog=private_profile.target_catalog,
            ground_truth=private_profile.private_ground_truth.ground_truth,
        )
        if scanner_plan != expected_plan:
            raise ValueError("P0-E2B Scanner plan differs from exact P0-D1 selection")
        expected_scanner = registered_zap_scanner(
            scanner_registration.scanner_image_id,
            parser_contract_digest=expected_plan.scanner_contract.parser_contract_digest,
        )
        if scanner_registration != expected_scanner:
            raise ValueError("P0-E2B ZAP registration differs from its parser contract")
        return WebMeasuredCaseAuthority(
            profile=profile,
            capabilityRelease=release,
            capabilityReleaseBundleDigest=_release_bundle_digest(signed_release),
            surface=registered_web_measured_internal_surface(),
            targetAdapter=target_adapter,
            targetRegistration=private_profile.target_catalog.registrations[0],
            scannerPlan=expected_plan,
            scannerRegistration=expected_scanner,
            domainBenchmarkPlan=private_profile.domain_benchmark_plan,
            groundTruthDigest=private_profile.private_ground_truth.ground_truth.digest(),
            groundTruthBindingDigest=private_profile.private_ground_truth.binding_digest,
        )
    except WebMeasuredCaseAuthorityError:
        raise
    except (
        AttributeError,
        CapabilityLifecycleError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebMeasuredCaseAuthorityError("WEB-002A measured-case binding failed closed") from exc


def load_web_measured_case_authority(
    authority: WebMeasuredCaseAuthority,
    *,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
) -> WebMeasuredCaseAuthority:
    """Contextfully reopen a public artifact and rebind all private predecessors."""

    try:
        candidate = WebMeasuredCaseAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = bind_web_measured_case_authority(
            capability_bundle=capability_bundle,
            lifecycle=lifecycle,
            release=release,
            target_adapter=target_adapter,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
        )
        if candidate != expected:
            raise ValueError("WEB-002A measured-case artifact differs from rebuilt authority")
        return expected.model_copy(deep=True)
    except WebMeasuredCaseAuthorityError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise WebMeasuredCaseAuthorityError("WEB-002A measured-case reload failed closed") from exc


def _rebuild_private_profile(
    supplied: WebAPIBenchmarkGroundTruthProfile,
) -> WebAPIBenchmarkGroundTruthProfile:
    canonical = WebAPIBenchmarkGroundTruthProfile.model_validate(
        supplied.model_dump(mode="json", by_alias=True)
    )
    expected = registered_web_api_benchmark_ground_truth_profile(
        canonical.target_profile,
        benchmark_id=canonical.private_ground_truth.ground_truth.benchmark_id,
    )
    if canonical != expected:
        raise ValueError("P0-D1 private Ground Truth profile differs from code authority")
    return expected


def _require_signed_release(
    bundle: CapabilityReleaseBundle,
    *,
    profile: WebMeasuredValidationProfile,
    release: CapabilityReleaseRef,
) -> None:
    statement = bundle.release.statement
    if (
        statement.reference() != release
        or statement.capability != profile.capability
        or statement.maturity is not CapabilityMaturity.EXPERIMENTAL
    ):
        raise ValueError("WEB-002A signed Capability release differs from its Profile")


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.web-measured-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


__all__ = [
    "WEB_MEASURED_CASE_AUTHORITY_API_VERSION",
    "WebMeasuredCaseAuthority",
    "WebMeasuredCaseAuthorityError",
    "WebMeasuredCaseAuthorityRef",
    "bind_web_measured_case_authority",
    "load_web_measured_case_authority",
]
