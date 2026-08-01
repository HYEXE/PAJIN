"""P0-E2A non-runnable generic Scanner baseline measurement plan."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.models import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.benchmark.target_catalog import (
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileSelectionAuthority,
    select_traditional_web_api_target_profile,
)
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.domain.models import StrictModel

GENERIC_SCANNER_ADAPTER_CONTRACT_API_VERSION: Literal[
    "pajin.dev/generic-scanner-adapter-contract/v1alpha1"
] = "pajin.dev/generic-scanner-adapter-contract/v1alpha1"
SCANNER_BASELINE_COORDINATE_API_VERSION: Literal[
    "pajin.dev/scanner-baseline-coordinate/v1alpha1"
] = "pajin.dev/scanner-baseline-coordinate/v1alpha1"
SCANNER_BASELINE_MEASUREMENT_PLAN_API_VERSION: Literal[
    "pajin.dev/scanner-baseline-measurement-plan/v1alpha1"
] = "pajin.dev/scanner-baseline-measurement-plan/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_COORDINATE_BYTES = 64 * 1024
_MAX_PLAN_BYTES = 2 * 1024 * 1024

_SCANNER_IMPLEMENTATION_ID = "scanner:generic-web-security"
_SCANNER_IMPLEMENTATION_VERSION = "contract-only-v1"
_SCANNER_CONFIGURATION_DIGEST = benchmark_digest(
    "pajin.benchmark.generic-scanner-configuration/v1",
    {
        "scope": "single-selected-target",
        "network": "target-isolation-only",
        "authentication": "none",
        "output": "sarif-2.1.0",
    },
    max_bytes=64 * 1024,
)
_SCANNER_PARSER_CONTRACT_DIGEST = benchmark_digest(
    "pajin.benchmark.generic-scanner-sarif-parser-contract/v1",
    {
        "format": "sarif-2.1.0",
        "requiredIdentity": ["tool.driver.name", "tool.driver.version"],
        "requiredFinding": ["ruleId", "message", "locations"],
        "unknownProperties": "reject-before-normalization",
        "rawArtifactRequired": True,
    },
    max_bytes=64 * 1024,
)


class GenericScannerAdapterContract(StrictModel):
    """Required identity and evidence surface before any Scanner can be runnable."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/generic-scanner-adapter-contract/v1alpha1"
    ] = Field(
        default=GENERIC_SCANNER_ADAPTER_CONTRACT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GenericScannerAdapterContract"] = "GenericScannerAdapterContract"
    contract_id: Literal["scanner-contract:generic-web-security-v1"] = Field(
        default="scanner-contract:generic-web-security-v1",
        alias="contractId",
    )
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    benchmark_implementation_id: Literal["scanner:generic-web-security"] = Field(
        default="scanner:generic-web-security",
        alias="benchmarkImplementationId",
    )
    benchmark_implementation_version: Literal["contract-only-v1"] = Field(
        default="contract-only-v1",
        alias="benchmarkImplementationVersion",
    )
    benchmark_configuration_digest: _Sha256 = Field(
        default=_SCANNER_CONFIGURATION_DIGEST,
        alias="benchmarkConfigurationDigest",
    )
    required_identity_fields: tuple[
        Literal[
            "scannerId",
            "scannerVersion",
            "executableArtifactSha256",
            "configurationDigest",
        ],
        ...,
    ] = Field(alias="requiredIdentityFields", min_length=4, max_length=4)
    output_format: Literal["sarif-2.1.0"] = Field(
        default="sarif-2.1.0",
        alias="outputFormat",
    )
    parser_contract_digest: _Sha256 = Field(alias="parserContractDigest")
    target_access_policy: Literal["target-isolation-endpoint-only"] = Field(
        default="target-isolation-endpoint-only",
        alias="targetAccessPolicy",
    )
    adapter_implementation_bound: Literal[False] = Field(
        default=False,
        alias="adapterImplementationBound",
    )
    scanner_execution_authorized: Literal[False] = Field(
        default=False,
        alias="scannerExecutionAuthorized",
    )

    @field_validator("required_identity_fields")
    @classmethod
    def require_exact_identity_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        expected = (
            "scannerId",
            "scannerVersion",
            "executableArtifactSha256",
            "configurationDigest",
        )
        if value != expected:
            raise ValueError("Generic Scanner identity fields differ from the contract")
        return value

    @model_validator(mode="after")
    def bind_contract(self) -> Self:
        if self.parser_contract_digest != _SCANNER_PARSER_CONTRACT_DIGEST:
            raise ValueError("Generic Scanner parser contract differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        canonical_benchmark_json(
            material,
            label="GenericScannerAdapterContract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.generic-scanner-adapter-contract/v1",
            material,
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Generic Scanner Adapter Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        return self


class ScannerBaselineCoordinate(StrictModel):
    """One planned Scanner baseline seed and repetition on an exact arm."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/scanner-baseline-coordinate/v1alpha1"] = Field(
        default=SCANNER_BASELINE_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ScannerBaselineCoordinate"] = "ScannerBaselineCoordinate"
    coordinate_digest: str = Field(default="", alias="coordinateDigest", max_length=64)
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    arm_id: _Identifier = Field(alias="armId")
    seed: int = Field(ge=0, le=2**63 - 1)
    repetition: int = Field(ge=1, le=10_000)

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.scanner-baseline-coordinate/v1",
            material,
            max_bytes=_MAX_COORDINATE_BYTES,
        )
        if self.coordinate_digest and self.coordinate_digest != digest:
            raise ValueError("Scanner Baseline Coordinate Digest differs")
        object.__setattr__(self, "coordinate_digest", digest)
        return self


class ScannerBaselineMeasurementPlanAuthority(StrictModel):
    """Exact non-runnable Scanner baseline plan without output or Result authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/scanner-baseline-measurement-plan/v1alpha1"
    ] = Field(
        default=SCANNER_BASELINE_MEASUREMENT_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ScannerBaselineMeasurementPlanAuthority"] = (
        "ScannerBaselineMeasurementPlanAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    target_selection: BenchmarkTargetProfileSelectionAuthority = Field(
        alias="targetSelection"
    )
    scanner_contract: GenericScannerAdapterContract = Field(alias="scannerContract")
    coordinates: tuple[ScannerBaselineCoordinate, ...] = Field(
        min_length=1,
        max_length=2_000,
    )
    plan_state: Literal["registered-contract-not-executable"] = Field(
        default="registered-contract-not-executable",
        alias="planState",
    )
    scanner_identity_bound: Literal[False] = Field(
        default=False,
        alias="scannerIdentityBound",
    )
    invocation_receipt_bound: Literal[False] = Field(
        default=False,
        alias="invocationReceiptBound",
    )
    raw_output_bound: Literal[False] = Field(default=False, alias="rawOutputBound")
    benchmark_result_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkResultEligible",
    )
    candidate_comparison_eligible: Literal[False] = Field(
        default=False,
        alias="candidateComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        arm = _require_scanner_manifest(self.manifest, self.scanner_contract)
        expected = _scanner_coordinates(self.manifest, arm.arm_id)
        if (
            self.manifest_digest != self.manifest.digest()
            or self.target_selection.manifest_digest != self.manifest_digest
            or self.target_selection.catalog_id
            != "target-catalog:pajin-traditional-web-api"
            or self.target_selection.catalog_revision != 1
            or self.target_selection.registration.target_family != "traditional-web-api"
            or self.target_selection.registration.target_profile_id
            != self.manifest.target_profile_id
            or self.target_selection.registration.target_profile_version
            != self.manifest.target_profile_version
            or self.target_selection.registration.target_factory_digest
            != self.manifest.target_factory_digest
            or self.target_selection.ground_truth_digest
            != self.manifest.ground_truth_digest
            or self.coordinates != expected
        ):
            raise ValueError("Scanner Baseline Measurement Plan differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        canonical_benchmark_json(
            material,
            label="ScannerBaselineMeasurementPlanAuthority",
            max_bytes=_MAX_PLAN_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.scanner-baseline-measurement-plan/v1",
            material,
            max_bytes=_MAX_PLAN_BYTES,
        )
        authority_id = f"scanner-baseline-plan:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Scanner Baseline Measurement Plan Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Scanner Baseline Measurement Plan ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_generic_scanner_adapter_contract() -> GenericScannerAdapterContract:
    """Return the code-owned non-runnable Scanner adapter contract."""

    return GenericScannerAdapterContract(
        requiredIdentityFields=(
            "scannerId",
            "scannerVersion",
            "executableArtifactSha256",
            "configurationDigest",
        ),
        parserContractDigest=_SCANNER_PARSER_CONTRACT_DIGEST,
    )


def plan_generic_scanner_baseline(
    manifest: BenchmarkManifest,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    profile: DockerBugBountyTargetProfile,
    catalog: BenchmarkTargetProfileCatalog,
    ground_truth: BenchmarkGroundTruth,
) -> ScannerBaselineMeasurementPlanAuthority:
    """Reconstruct the Target selection and bind a non-runnable Scanner plan."""

    authoritative_manifest = BenchmarkManifest.model_validate(
        manifest.model_dump(mode="json", by_alias=True)
    )
    contract = registered_generic_scanner_adapter_contract()
    arm = _require_scanner_manifest(authoritative_manifest, contract)
    selection = select_traditional_web_api_target_profile(
        authoritative_manifest,
        adapter=adapter,
        profile=profile,
        catalog=catalog,
        ground_truth=ground_truth,
    )
    return ScannerBaselineMeasurementPlanAuthority(
        manifest=authoritative_manifest,
        manifestDigest=authoritative_manifest.digest(),
        targetSelection=selection,
        scannerContract=contract,
        coordinates=_scanner_coordinates(authoritative_manifest, arm.arm_id),
    )


def _require_scanner_manifest(
    manifest: BenchmarkManifest,
    contract: GenericScannerAdapterContract,
) -> BenchmarkArm:
    if len(manifest.arms) != 1:
        raise ValueError("P0-E2A requires one Scanner baseline arm")
    arm = manifest.arms[0]
    if (
        arm.kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
        or arm.adaptive_supervisor is not False
        or arm.implementation_id != contract.benchmark_implementation_id
        or arm.implementation_version != contract.benchmark_implementation_version
        or arm.configuration_digest != contract.benchmark_configuration_digest
        or manifest.mutation_profile_id is not None
    ):
        raise ValueError("P0-E2A Scanner baseline Manifest differs")
    return arm


def _scanner_coordinates(
    manifest: BenchmarkManifest,
    arm_id: str,
) -> tuple[ScannerBaselineCoordinate, ...]:
    return tuple(
        ScannerBaselineCoordinate(
            manifestDigest=manifest.digest(),
            armId=arm_id,
            seed=seed,
            repetition=repetition,
        )
        for seed in manifest.protocol.seeds
        for repetition in range(1, manifest.protocol.repetitions_per_seed + 1)
    )
