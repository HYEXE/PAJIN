"""ENG-002A non-executable implementation selection and structural parity."""

from __future__ import annotations

from enum import StrEnum
from importlib import import_module
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import CampaignMode, StrictModel
from pajin.workflow.campaign_profile import (
    RegisteredCampaignProfile,
    resolve_registered_campaign_profile,
)
from pajin.workflow.common_engine import (
    CommonCampaignEngineContract,
    _common_engine_digest,
    registered_common_campaign_engine_contract,
)
from pajin.workflow.multi_agent import MultiAgentCampaignRunner
from pajin.workflow.multi_agent_execution import MultiAgentExecutionScheduler
from pajin.workflow.multi_agent_projection import MultiAgentResultProjector
from pajin.workflow.profile_compatibility import (
    LegacyCampaignProfileCompilationAuthority,
    LegacyModeProfileCompiler,
    registered_legacy_mode_profile_compiler,
)

COMMON_ENGINE_IMPLEMENTATION_API_VERSION: Literal[
    "pajin.dev/common-engine-implementation/v1alpha1"
] = "pajin.dev/common-engine-implementation/v1alpha1"
COMMON_ENGINE_MODE_ADAPTER_API_VERSION: Literal[
    "pajin.dev/common-engine-mode-adapter/v1alpha1"
] = "pajin.dev/common-engine-mode-adapter/v1alpha1"
COMMON_ENGINE_ADAPTER_CATALOG_API_VERSION: Literal[
    "pajin.dev/common-engine-adapter-catalog/v1alpha1"
] = "pajin.dev/common-engine-adapter-catalog/v1alpha1"
COMMON_ENGINE_STRUCTURAL_PARITY_API_VERSION: Literal[
    "pajin.dev/common-engine-structural-parity/v1alpha1"
] = "pajin.dev/common-engine-structural-parity/v1alpha1"
COMMON_ENGINE_ADAPTER_SELECTION_API_VERSION: Literal[
    "pajin.dev/common-engine-adapter-selection/v1alpha1"
] = "pajin.dev/common-engine-adapter-selection/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_IMPLEMENTATION_BYTES = 64 * 1024
_MAX_ADAPTER_BYTES = 512 * 1024
_MAX_CATALOG_BYTES = 2 * 1024 * 1024
_MAX_PARITY_BYTES = 128 * 1024
_MAX_SELECTION_BYTES = 4 * 1024 * 1024


class CommonEngineAdapterError(RuntimeError):
    """Raised when an exact legacy implementation adapter cannot be selected."""


class CommonEngineImplementationRole(StrEnum):
    PLANNER = "planner"
    VALIDATOR = "validator"
    CANDIDATE_PRODUCER = "candidate-producer"
    RUNNER = "runner"
    SCHEDULER = "scheduler"
    PROJECTOR = "projector"


class CommonEngineParityDimension(StrEnum):
    SCOPE = "scope"
    CAPABILITY = "capability"
    TOOL_REQUEST = "tool-request"
    OUTCOME = "outcome"


class CommonEngineStructuralParityBasis(StrEnum):
    CAMPAIGN_INPUT_IDENTITY = "campaign-input-identity"
    SHARED_RUNNER_SCHEDULER_IDENTITY = "shared-runner-scheduler-identity"
    PLANNER_IDENTITY = "planner-identity"
    VALIDATOR_PROJECTOR_IDENTITY = "validator-projector-identity"


class RegisteredCommonEngineImplementation(StrictModel):
    """One exact Python implementation identity without construction authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-implementation/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_IMPLEMENTATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredCommonEngineImplementation"] = (
        "RegisteredCommonEngineImplementation"
    )
    role: CommonEngineImplementationRole
    implementation_id: _Identifier = Field(alias="implementationId")
    implementation_version: Literal["python-contract-v1"] = Field(
        default="python-contract-v1",
        alias="implementationVersion",
    )
    implementation_digest: str = Field(
        default="",
        alias="implementationDigest",
        max_length=64,
    )
    construction_authorized: Literal[False] = Field(
        default=False,
        alias="constructionAuthorized",
    )

    @model_validator(mode="after")
    def bind_implementation_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"implementation_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-implementation/v1",
            material,
            max_bytes=_MAX_IMPLEMENTATION_BYTES,
        )
        if self.implementation_digest and self.implementation_digest != digest:
            raise ValueError("Common Engine Implementation Digest differs")
        object.__setattr__(self, "implementation_digest", digest)
        return self


class CommonEngineModeAdapter(StrictModel):
    """Exact Mode/Profile implementation selection that cannot instantiate a runtime."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-mode-adapter/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_MODE_ADAPTER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineModeAdapter"] = "CommonEngineModeAdapter"
    adapter_id: str = Field(default="", alias="adapterId", max_length=100)
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    source_mode: CampaignMode = Field(alias="sourceMode")
    profile: RegisteredCampaignProfile
    profile_digest: _Sha256 = Field(alias="profileDigest")
    planner: RegisteredCommonEngineImplementation
    validator: RegisteredCommonEngineImplementation
    candidate_producer: RegisteredCommonEngineImplementation | None = Field(
        default=None,
        alias="candidateProducer",
    )
    runner: RegisteredCommonEngineImplementation
    scheduler: RegisteredCommonEngineImplementation
    projector: RegisteredCommonEngineImplementation
    runtime_construction_authorized: Literal[False] = Field(
        default=False,
        alias="runtimeConstructionAuthorized",
    )
    tool_registry_bound: Literal[False] = Field(
        default=False,
        alias="toolRegistryBound",
    )
    policy_bound: Literal[False] = Field(default=False, alias="policyBound")
    worker_bound: Literal[False] = Field(default=False, alias="workerBound")
    output_path_bound: Literal[False] = Field(default=False, alias="outputPathBound")
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_adapter_digest(self) -> Self:
        expected = _mode_implementation_set(self.source_mode)
        if (
            self.profile != expected[0]
            or self.profile_digest != expected[0].profile_digest
            or self.planner != expected[1]
            or self.validator != expected[2]
            or self.candidate_producer != expected[3]
            or self.runner != expected[4]
            or self.scheduler != expected[5]
            or self.projector != expected[6]
        ):
            raise ValueError("Common Engine Mode Adapter differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"adapter_id", "adapter_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-mode-adapter/v1",
            material,
            max_bytes=_MAX_ADAPTER_BYTES,
        )
        adapter_id = f"common-engine-mode-adapter:{digest}"
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("Common Engine Mode Adapter Digest differs")
        if self.adapter_id and self.adapter_id != adapter_id:
            raise ValueError("Common Engine Mode Adapter ID differs")
        object.__setattr__(self, "adapter_digest", digest)
        object.__setattr__(self, "adapter_id", adapter_id)
        return self


class CommonEngineAdapterCatalog(StrictModel):
    """Code-owned full Mode adapter set bound to ENG-001 and PROF-002."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-adapter-catalog/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_ADAPTER_CATALOG_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineAdapterCatalog"] = "CommonEngineAdapterCatalog"
    catalog_id: Literal["common-engine-adapter-catalog:legacy-v1"] = Field(
        default="common-engine-adapter-catalog:legacy-v1",
        alias="catalogId",
    )
    catalog_revision: Literal[1] = Field(default=1, alias="catalogRevision")
    catalog_digest: str = Field(default="", alias="catalogDigest", max_length=64)
    common_engine_contract: CommonCampaignEngineContract = Field(
        alias="commonEngineContract"
    )
    common_engine_contract_digest: _Sha256 = Field(
        alias="commonEngineContractDigest"
    )
    profile_compiler: LegacyModeProfileCompiler = Field(alias="profileCompiler")
    profile_compiler_digest: _Sha256 = Field(alias="profileCompilerDigest")
    adapters: tuple[CommonEngineModeAdapter, ...] = Field(min_length=3, max_length=3)
    adapter_selection_authorized: Literal[True] = Field(
        default=True,
        alias="adapterSelectionAuthorized",
    )
    runtime_construction_authorized: Literal[False] = Field(
        default=False,
        alias="runtimeConstructionAuthorized",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_catalog_digest(self) -> Self:
        contract = registered_common_campaign_engine_contract()
        compiler = registered_legacy_mode_profile_compiler()
        expected_adapters = _registered_mode_adapters()
        if (
            self.common_engine_contract != contract
            or self.common_engine_contract_digest != contract.contract_digest
            or self.profile_compiler != compiler
            or self.profile_compiler_digest != compiler.compiler_digest
            or self.adapters != expected_adapters
        ):
            raise ValueError("Common Engine Adapter Catalog differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"catalog_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-adapter-catalog/v1",
            material,
            max_bytes=_MAX_CATALOG_BYTES,
        )
        if self.catalog_digest and self.catalog_digest != digest:
            raise ValueError("Common Engine Adapter Catalog Digest differs")
        object.__setattr__(self, "catalog_digest", digest)
        return self


class CommonEngineStructuralParity(StrictModel):
    """One required parity dimension with identity evidence but no fixture result."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-structural-parity/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_STRUCTURAL_PARITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineStructuralParity"] = "CommonEngineStructuralParity"
    parity_digest: str = Field(default="", alias="parityDigest", max_length=64)
    dimension: CommonEngineParityDimension
    basis: CommonEngineStructuralParityBasis
    evidence_digests: tuple[_Sha256, ...] = Field(
        alias="evidenceDigests",
        min_length=1,
        max_length=4,
    )
    fixture_measured: Literal[False] = Field(default=False, alias="fixtureMeasured")
    parity_proven: Literal[False] = Field(default=False, alias="parityProven")

    @field_validator("evidence_digests")
    @classmethod
    def require_canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Structural parity evidence digests must be unique and sorted")
        return value

    @model_validator(mode="after")
    def bind_parity_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"parity_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-structural-parity/v1",
            material,
            max_bytes=_MAX_PARITY_BYTES,
        )
        if self.parity_digest and self.parity_digest != digest:
            raise ValueError("Common Engine Structural Parity Digest differs")
        object.__setattr__(self, "parity_digest", digest)
        return self


class CommonEngineAdapterSelectionAuthority(StrictModel):
    """Exact adapter selection and incomplete structural parity with execution false."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-engine-adapter-selection/v1alpha1"
    ] = Field(
        default=COMMON_ENGINE_ADAPTER_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonEngineAdapterSelectionAuthority"] = (
        "CommonEngineAdapterSelectionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    compilation: LegacyCampaignProfileCompilationAuthority
    compilation_digest: _Sha256 = Field(alias="compilationDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    adapter_catalog: CommonEngineAdapterCatalog = Field(alias="adapterCatalog")
    adapter_catalog_digest: _Sha256 = Field(alias="adapterCatalogDigest")
    adapter: CommonEngineModeAdapter
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    structural_parity: tuple[CommonEngineStructuralParity, ...] = Field(
        alias="structuralParity",
        min_length=4,
        max_length=4,
    )
    all_required_dimensions_present: Literal[True] = Field(
        default=True,
        alias="allRequiredDimensionsPresent",
    )
    fixture_parity_proven: Literal[False] = Field(
        default=False,
        alias="fixtureParityProven",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    runtime_constructed: Literal[False] = Field(
        default=False,
        alias="runtimeConstructed",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_selection_authority(self) -> Self:
        compilation = LegacyCampaignProfileCompilationAuthority.model_validate(
            self.compilation.model_dump(mode="json", by_alias=True)
        )
        catalog = registered_common_engine_adapter_catalog()
        adapter = _adapter_for_compilation(compilation, catalog)
        parity = _structural_parity(compilation, adapter)
        if (
            self.compilation != compilation
            or self.compilation_digest != compilation.authority_digest
            or self.source_campaign_digest != compilation.input_digest
            or self.adapter_catalog != catalog
            or self.adapter_catalog_digest != catalog.catalog_digest
            or self.adapter != adapter
            or self.adapter_digest != adapter.adapter_digest
            or self.structural_parity != parity
        ):
            raise ValueError("Common Engine Adapter Selection authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "compilation"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-engine-adapter-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"common-engine-adapter-selection:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Common Engine Adapter Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Common Engine Adapter Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_common_engine_adapter_catalog() -> CommonEngineAdapterCatalog:
    """Return the exact ENG-002A implementation adapter catalog."""

    contract = registered_common_campaign_engine_contract()
    compiler = registered_legacy_mode_profile_compiler()
    return CommonEngineAdapterCatalog(
        commonEngineContract=contract,
        commonEngineContractDigest=contract.contract_digest,
        profileCompiler=compiler,
        profileCompilerDigest=compiler.compiler_digest,
        adapters=_registered_mode_adapters(),
    )


def select_common_engine_adapter(
    compilation: LegacyCampaignProfileCompilationAuthority,
) -> CommonEngineAdapterSelectionAuthority:
    """Select exact class identities and record unmeasured structural parity."""

    authoritative_compilation = LegacyCampaignProfileCompilationAuthority.model_validate(
        compilation.model_dump(mode="json", by_alias=True)
    )
    catalog = registered_common_engine_adapter_catalog()
    adapter = _adapter_for_compilation(authoritative_compilation, catalog)
    parity = _structural_parity(authoritative_compilation, adapter)
    return CommonEngineAdapterSelectionAuthority(
        compilation=authoritative_compilation,
        compilationDigest=authoritative_compilation.authority_digest,
        sourceCampaignDigest=authoritative_compilation.input_digest,
        adapterCatalog=catalog,
        adapterCatalogDigest=catalog.catalog_digest,
        adapter=adapter,
        adapterDigest=adapter.adapter_digest,
        structuralParity=parity,
    )


def _registered_mode_adapters() -> tuple[CommonEngineModeAdapter, ...]:
    return tuple(_mode_adapter(mode) for mode in tuple(CampaignMode))


def _mode_adapter(mode: CampaignMode) -> CommonEngineModeAdapter:
    profile, planner, validator, candidate, runner, scheduler, projector = (
        _mode_implementation_set(mode)
    )
    return CommonEngineModeAdapter(
        sourceMode=mode,
        profile=profile,
        profileDigest=profile.profile_digest,
        planner=planner,
        validator=validator,
        candidateProducer=candidate,
        runner=runner,
        scheduler=scheduler,
        projector=projector,
    )


def _mode_implementation_set(
    mode: CampaignMode,
) -> tuple[
    RegisteredCampaignProfile,
    RegisteredCommonEngineImplementation,
    RegisteredCommonEngineImplementation,
    RegisteredCommonEngineImplementation | None,
    RegisteredCommonEngineImplementation,
    RegisteredCommonEngineImplementation,
    RegisteredCommonEngineImplementation,
]:
    compiler = registered_legacy_mode_profile_compiler()
    mapping = next(item for item in compiler.mappings if item.source_mode is mode)
    profile = resolve_registered_campaign_profile(
        mapping.profile_id,
        mapping.profile_version,
    )
    planner_type: type[object]
    validator_type: type[object]
    candidate_type: type[object] | None
    if mode is CampaignMode.AI_REDTEAM:
        planner_type = _implementation_type(
            "pajin.modes.ai_redteam.runtime",
            "KISAPlannerRuntime",
        )
        validator_type = _implementation_type(
            "pajin.modes.ai_redteam.runtime",
            "KISAValidatorRuntime",
        )
        candidate_type = _implementation_type(
            "pajin.modes.ai_redteam.candidates",
            "KISACandidateProducer",
        )
    elif mode is CampaignMode.BUG_BOUNTY:
        planner_type = _implementation_type(
            "pajin.modes.bug_bounty.runtime",
            "BugBountyPlannerRuntime",
        )
        validator_type = _implementation_type(
            "pajin.modes.bug_bounty.runtime",
            "BugBountyValidatorRuntime",
        )
        candidate_type = None
    else:
        planner_type = _implementation_type(
            "pajin.modes.ctf.runtime",
            "CTFTriagePlannerRuntime",
        )
        validator_type = _implementation_type(
            "pajin.modes.ctf.runtime",
            "CTFFlagValidatorRuntime",
        )
        candidate_type = None
    return (
        profile,
        _implementation(CommonEngineImplementationRole.PLANNER, planner_type),
        _implementation(CommonEngineImplementationRole.VALIDATOR, validator_type),
        (
            _implementation(CommonEngineImplementationRole.CANDIDATE_PRODUCER, candidate_type)
            if candidate_type is not None
            else None
        ),
        _implementation(CommonEngineImplementationRole.RUNNER, MultiAgentCampaignRunner),
        _implementation(CommonEngineImplementationRole.SCHEDULER, MultiAgentExecutionScheduler),
        _implementation(CommonEngineImplementationRole.PROJECTOR, MultiAgentResultProjector),
    )


def _implementation(
    role: CommonEngineImplementationRole,
    implementation: type[object],
) -> RegisteredCommonEngineImplementation:
    return RegisteredCommonEngineImplementation(
        role=role,
        implementationId=f"{implementation.__module__}.{implementation.__qualname__}",
    )


def _implementation_type(module_name: str, type_name: str) -> type[object]:
    """Resolve an implementation only when catalog construction is requested."""

    implementation = getattr(import_module(module_name), type_name, None)
    if not isinstance(implementation, type):
        raise CommonEngineAdapterError(
            f"registered implementation is unavailable: {module_name}.{type_name}"
        )
    return implementation


def _adapter_for_compilation(
    compilation: LegacyCampaignProfileCompilationAuthority,
    catalog: CommonEngineAdapterCatalog,
) -> CommonEngineModeAdapter:
    for adapter in catalog.adapters:
        if adapter.source_mode is compilation.source_mode:
            if (
                adapter.profile.profile_id != compilation.profile.profile_id
                or adapter.profile.profile_version != compilation.profile.profile_version
                or adapter.profile_digest != compilation.profile_digest
            ):
                raise CommonEngineAdapterError(
                    "compiled Profile differs from the registered Mode adapter"
                )
            return adapter.model_copy(deep=True)
    raise CommonEngineAdapterError("legacy Mode has no registered Common Engine adapter")


def _structural_parity(
    compilation: LegacyCampaignProfileCompilationAuthority,
    adapter: CommonEngineModeAdapter,
) -> tuple[CommonEngineStructuralParity, ...]:
    outcome_digests = [
        adapter.validator.implementation_digest,
        adapter.projector.implementation_digest,
    ]
    if adapter.candidate_producer is not None:
        outcome_digests.append(adapter.candidate_producer.implementation_digest)
    return (
        CommonEngineStructuralParity(
            dimension=CommonEngineParityDimension.SCOPE,
            basis=CommonEngineStructuralParityBasis.CAMPAIGN_INPUT_IDENTITY,
            evidenceDigests=(compilation.input_digest,),
        ),
        CommonEngineStructuralParity(
            dimension=CommonEngineParityDimension.CAPABILITY,
            basis=CommonEngineStructuralParityBasis.SHARED_RUNNER_SCHEDULER_IDENTITY,
            evidenceDigests=tuple(
                sorted(
                    (
                        adapter.runner.implementation_digest,
                        adapter.scheduler.implementation_digest,
                    )
                )
            ),
        ),
        CommonEngineStructuralParity(
            dimension=CommonEngineParityDimension.TOOL_REQUEST,
            basis=CommonEngineStructuralParityBasis.PLANNER_IDENTITY,
            evidenceDigests=(adapter.planner.implementation_digest,),
        ),
        CommonEngineStructuralParity(
            dimension=CommonEngineParityDimension.OUTCOME,
            basis=CommonEngineStructuralParityBasis.VALIDATOR_PROJECTOR_IDENTITY,
            evidenceDigests=tuple(sorted(outcome_digests)),
        ),
    )
