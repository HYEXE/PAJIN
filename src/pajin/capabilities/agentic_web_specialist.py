"""Exact, non-dispatching Capabilities for AGENTIC Web specialists.

This module is the AGENTIC-003C3A boundary.  It turns one inert specialist
preparation plus one signed, pre-provisioned account receipt reference into a
deterministic :class:`PreparedCapabilityAction`.  It deliberately has no
Capability Grant, approval, Permit, Gateway, Worker, browser, model, or network
dispatch surface.  The Tool and its executor adapter remain fail-closed until
the later durable AGENTIC-003C3B bridge installs a one-shot dispatch binding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from re import fullmatch
from types import MappingProxyType
from typing import Annotated, ClassVar, Final, Literal, Never, Self, cast

from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

from pajin.agentic.execution_profiles import SpecialistExecutionProfileError
from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_definition_from_tool,
    registered_action_capability,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapability,
    CodeBackedCapabilityRef,
    RegisteredCapabilityAuthority,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ResolvedCapabilityRelease,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    RegisteredActionCapability,
)
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.web_assessment.governed_adapter_profile import (
    GovernedWebAdapterProfileError,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_models import (
    GovernedWebAssessmentModelError,
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRef,
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
)
from pajin.web_assessment.specialist_executors import (
    WebSpecialistExecutorError,
    production_web_specialist_executor_catalog,
)
from pajin.web_assessment.specialist_profiles import (
    WebSpecialistExecutionProfileError,
    production_web_specialist_execution_profile_catalog,
)

WEB_SPECIALIST_CAPABILITY_VERSION: Final = "1.0.0"
WEB_SPECIALIST_TOOL_VERSION: Final = "1.0.0"
WEB_SPECIALIST_REQUEST_UNITS: Final = 100
WEB_SPECIALIST_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/agentic-web-specialist-activation-set/v1alpha1"
] = "pajin.dev/agentic-web-specialist-activation-set/v1alpha1"

WEB_XSS_SPECIALIST_CAPABILITY_ID: Final = "pajin.bug-bounty.web-specialist.dom-xss"
WEB_XSS_SPECIALIST_TOOL_ID: Final = "web.specialist.dom-xss"
WEB_SQLI_SPECIALIST_CAPABILITY_ID: Final = "pajin.bug-bounty.web-specialist.sql-login"
WEB_SQLI_SPECIALIST_TOOL_ID: Final = "web.specialist.sql-login"
WEB_AUTHORIZATION_SPECIALIST_CAPABILITY_ID: Final = "pajin.bug-bounty.web-specialist.authorization"
WEB_AUTHORIZATION_SPECIALIST_TOOL_ID: Final = "web.specialist.authorization"

_AUTHORITY_VERSION: Final = "1.0.0"
_SHA256_PATTERN: Final = r"^[a-f0-9]{64}$"
_PREPARATION_ID_PATTERN: Final = r"^agentic-specialist-preparation_[a-f0-9]{64}$"
_PREPARATION_REGISTRY_DIGEST_DOMAIN: Final = "pajin.agentic.web-specialist-preparation-registry/v1"

_Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]


class AgenticWebSpecialistCapabilityError(ValueError):
    """Raised when exact specialist Capability preparation fails closed."""


@dataclass(frozen=True, slots=True)
class _SpecialistCapabilityConfig:
    specialization: PentestSpecialization
    threat_class: str
    capability_id: str
    tool_id: str
    description: str
    threat_classes: tuple[str, ...]
    evidence_types: frozenset[str]


_CONFIGS: Final = (
    _SpecialistCapabilityConfig(
        specialization=PentestSpecialization.AUTHORIZATION,
        threat_class="authorization",
        capability_id=WEB_AUTHORIZATION_SPECIALIST_CAPABILITY_ID,
        tool_id=WEB_AUTHORIZATION_SPECIALIST_TOOL_ID,
        description=(
            "Run the exact read-only object-authorization specialist closure after its "
            "code-owned SQL session dependency"
        ),
        threat_classes=tuple(sorted(("CWE-89", "CWE-639"))),
        evidence_types=frozenset(
            {"http-observation", "json", "signed-attestation", "web-session-lineage"}
        ),
    ),
    _SpecialistCapabilityConfig(
        specialization=PentestSpecialization.SQL_INJECTION,
        threat_class="sql-injection",
        capability_id=WEB_SQLI_SPECIALIST_CAPABILITY_ID,
        tool_id=WEB_SQLI_SPECIALIST_TOOL_ID,
        description="Run the exact read-only SQL-login specialist closure",
        threat_classes=("CWE-89",),
        evidence_types=frozenset({"http-observation", "json", "signed-attestation"}),
    ),
    _SpecialistCapabilityConfig(
        specialization=PentestSpecialization.XSS,
        threat_class="xss",
        capability_id=WEB_XSS_SPECIALIST_CAPABILITY_ID,
        tool_id=WEB_XSS_SPECIALIST_TOOL_ID,
        description="Run the exact read-only DOM-XSS specialist closure",
        threat_classes=("CWE-79",),
        evidence_types=frozenset(
            {"browser-screenshot", "http-observation", "json", "signed-attestation"}
        ),
    ),
)
_CONFIG_BY_SPECIALIZATION: Final = MappingProxyType(
    {item.specialization: item for item in _CONFIGS}
)


class WebSpecialistAssessmentParameters(StrictModel):
    """The complete caller-visible parameter schema for one specialist action."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    preparation_id: str = Field(
        alias="preparationId",
        pattern=_PREPARATION_ID_PATTERN,
    )
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    account_receipt_ref: ProvisionedWebAccountReceiptRef = Field(alias="accountReceiptRef")

    @model_validator(mode="after")
    def bind_preparation_identity(self) -> Self:
        if self.preparation_id != f"agentic-specialist-preparation_{self.preparation_digest}":
            raise ValueError("specialist preparation ID and digest differ")
        return self


def _strict_parameters(value: object) -> WebSpecialistAssessmentParameters:
    if type(value) is not dict:
        raise AgenticWebSpecialistCapabilityError(
            "specialist parameters must be one exact JSON object"
        )
    raw = cast(dict[object, object], value)
    if set(raw) != {"preparationId", "preparationDigest", "accountReceiptRef"} or any(
        type(key) is not str for key in raw
    ):
        raise AgenticWebSpecialistCapabilityError(
            "specialist parameters contain unsupported fields or aliases"
        )
    receipt = raw["accountReceiptRef"]
    if type(receipt) is not dict or set(cast(dict[object, object], receipt)) != {
        "receiptId",
        "receiptDigest",
    }:
        raise AgenticWebSpecialistCapabilityError(
            "specialist account receipt reference is not exact JSON"
        )
    try:
        parsed = WebSpecialistAssessmentParameters.model_validate(value)
    except ValidationError as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist parameters failed strict validation"
        ) from exc
    if parsed.model_dump(mode="json", by_alias=True) != value:
        raise AgenticWebSpecialistCapabilityError(
            "specialist parameters differ after strict reload"
        )
    return parsed


class AgenticSpecialistPreparationRegistry:
    """Immutable, exact process-local inventory of inert preparations.

    Registry membership is not execution authority.  A later bridge must
    independently revalidate the original durable reservation and current Graph
    head before it may consume a Grant or a Permit.
    """

    __slots__ = ("__installed", "__registry_digest", "__sealed")
    __installed: Mapping[tuple[str, str], AgenticSpecialistPreparation]
    __registry_digest: str
    __sealed: bool

    def __init__(self, preparations: Iterable[AgenticSpecialistPreparation]) -> None:
        installed: dict[tuple[str, str], AgenticSpecialistPreparation] = {}
        for raw in preparations:
            if type(raw) is not AgenticSpecialistPreparation:
                raise AgenticWebSpecialistCapabilityError(
                    "specialist preparation registry requires exact preparation values"
                )
            try:
                preparation = AgenticSpecialistPreparation.model_validate(
                    raw.model_dump(mode="json", by_alias=True)
                )
            except (AttributeError, TypeError, ValidationError, ValueError) as exc:
                raise AgenticWebSpecialistCapabilityError(
                    "specialist preparation registry rejected a non-canonical value"
                ) from exc
            if preparation != raw:
                raise AgenticWebSpecialistCapabilityError(
                    "specialist preparation differs after strict reload"
                )
            key = (preparation.preparation_id, preparation.preparation_digest)
            if key in installed:
                raise AgenticWebSpecialistCapabilityError(
                    "specialist preparation is registered more than once"
                )
            installed[key] = preparation
        if not installed:
            raise AgenticWebSpecialistCapabilityError(
                "specialist preparation registry cannot be empty"
            )
        object.__setattr__(
            self,
            "_AgenticSpecialistPreparationRegistry__installed",
            MappingProxyType(installed),
        )
        object.__setattr__(
            self,
            "_AgenticSpecialistPreparationRegistry__registry_digest",
            _preparation_registry_digest(installed),
        )
        object.__setattr__(self, "_AgenticSpecialistPreparationRegistry__sealed", True)

    def __setattr__(self, _name: str, _value: object) -> Never:
        if getattr(self, "_AgenticSpecialistPreparationRegistry__sealed", False):
            raise AttributeError("specialist preparation registry is immutable")
        raise AttributeError("specialist preparation registry requires constructor initialization")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist preparation registry is immutable")

    @property
    def registry_digest(self) -> str:
        return self.__registry_digest

    def resolve(
        self,
        preparation_id: str,
        preparation_digest: str,
    ) -> AgenticSpecialistPreparation:
        if (
            type(preparation_id) is not str
            or fullmatch(_PREPARATION_ID_PATTERN, preparation_id) is None
            or type(preparation_digest) is not str
            or fullmatch(_SHA256_PATTERN, preparation_digest) is None
            or preparation_id != f"agentic-specialist-preparation_{preparation_digest}"
        ):
            raise AgenticWebSpecialistCapabilityError(
                "specialist preparation is not registered exactly"
            )
        try:
            key = (preparation_id, preparation_digest)
            preparation = self.__installed[key]
        except KeyError as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist preparation is not registered exactly"
            ) from exc
        canonical = AgenticSpecialistPreparation.model_validate(
            preparation.model_dump(mode="json", by_alias=True)
        )
        if (
            canonical != preparation
            or canonical.preparation_id != preparation_id
            or canonical.preparation_digest != preparation_digest
            or _preparation_registry_digest(self.__installed) != self.__registry_digest
        ):
            raise AgenticWebSpecialistCapabilityError("registered specialist preparation drifted")
        return canonical


def _preparation_registry_digest(
    installed: Mapping[tuple[str, str], AgenticSpecialistPreparation],
) -> str:
    return capability_definition_digest(
        _PREPARATION_REGISTRY_DIGEST_DOMAIN,
        [installed[key].model_dump(mode="json", by_alias=True) for key in sorted(installed)],
    )


class WebSpecialistAssessmentTool(Tool):
    """One specialization-specific Tool that deliberately cannot dispatch yet."""

    def __init__(
        self,
        *,
        specialization: PentestSpecialization,
        preparations: AgenticSpecialistPreparationRegistry,
        adapters: WebAssessmentAdapterRegistry,
        account_receipts: ProvisionedWebAccountReceiptRegistry,
    ) -> None:
        try:
            selected = PentestSpecialization(specialization)
            config = _CONFIG_BY_SPECIALIZATION[selected]
        except (KeyError, ValueError) as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool specialization is unsupported"
            ) from exc
        if type(specialization) is not PentestSpecialization:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool specialization must be canonical"
            )
        if type(preparations) is not AgenticSpecialistPreparationRegistry:
            raise TypeError("specialist Tool requires its exact preparation registry")
        if type(adapters) is not WebAssessmentAdapterRegistry:
            raise TypeError("specialist Tool requires a signed adapter registry")
        if type(account_receipts) is not ProvisionedWebAccountReceiptRegistry:
            raise TypeError("specialist Tool requires a signed account receipt registry")
        self.specialization = selected
        self.preparations = preparations
        self.adapters = adapters
        self.account_receipts = account_receipts
        self._config = config
        self.spec = ToolSpec(
            tool_id=config.tool_id,
            version=WEB_SPECIALIST_TOOL_VERSION,
            description=config.description,
            risk_tier=ToolRiskTier.T2,
            categories=frozenset({"active-test", "bug-bounty", "specialist", "web"}),
            evidence_types=config.evidence_types,
            network_access=True,
            network_request_cost=WEB_SPECIALIST_REQUEST_UNITS,
            parallel_safe=False,
        )

    def stable_execution_context(self) -> dict[str, object]:
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "implementationVersion": "pajin.agentic-web-specialist-tool/v1",
            "specialization": self.specialization.value,
            "threatClass": self._config.threat_class,
            "spec": spec,
            "preparationRegistryDigest": self.preparations.registry_digest,
            "adapterRegistryDigest": self.adapters.registry_digest,
            "adapterCatalogDigest": self.adapters.catalog_digest,
            "accountReceiptTrustAnchorDigest": self.account_receipts.trust_anchor_digest,
            "requestIdentityVersion": "pajin.agentic.web-specialist-tool-request/v1",
            "dispatchBindingInstalled": False,
            "callerAuthoredRoutesAllowed": False,
            "callerAuthoredPayloadsAllowed": False,
            "callerAuthoredPoliciesAllowed": False,
            "callerAuthoredTransportAllowed": False,
            "accountCreationAllowed": False,
            "targetMutationAllowed": False,
        }

    def validate_request(
        self,
        request: ToolRequest,
    ) -> tuple[
        WebSpecialistAssessmentParameters,
        AgenticSpecialistPreparation,
        WebAssessmentAdapterManifest,
        ProvisionedWebAccountReceipt,
    ]:
        try:
            canonical_request = ToolRequest.model_validate(request.model_dump(mode="json"))
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool request is not canonical"
            ) from exc
        if canonical_request != request:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool request differs after strict reload"
            )
        if canonical_request.tool_id != self.spec.tool_id or canonical_request.method != "POST":
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool request identity is unsupported"
            )
        try:
            parameters = _strict_parameters(canonical_request.arguments)
            preparation = self.preparations.resolve(
                parameters.preparation_id,
                parameters.preparation_digest,
            )
            _require_current_preparation(preparation, self._config)
            receipt = self.account_receipts.resolve(parameters.account_receipt_ref)
            adapter = self.adapters.resolve(receipt.adapter)
            target_profile = production_governed_web_adapter_profile_registry().resolve(
                adapter_reference=preparation.adapter_reference,
                origin=preparation.target_endpoint,
            )
        except (
            AgenticWebSpecialistCapabilityError,
            GovernedWebAdapterProfileError,
            GovernedWebAssessmentModelError,
            ValidationError,
            ValueError,
        ) as exc:
            if isinstance(exc, AgenticWebSpecialistCapabilityError):
                raise
            raise AgenticWebSpecialistCapabilityError(
                "specialist request references untrusted deployment material"
            ) from exc
        if (
            canonical_request.request_id
            != _specialist_request_id(self._config, preparation, parameters)
            or canonical_request.agent_id != preparation.target_agent_id
            or canonical_request.target != preparation.target_endpoint
            or receipt.adapter != adapter.reference()
            or receipt.origin != preparation.target_endpoint
            or adapter.origin != preparation.target_endpoint
            or adapter.adapter_id != target_profile.adapter_id
            or adapter.adapter_version != target_profile.adapter_version
            or adapter.implementation_id != preparation.adapter_implementation_id
            or adapter.implementation_digest != preparation.adapter_implementation_digest
            or adapter.recipe_digest != preparation.adapter_plan_digest
            or self.adapters.catalog_digest != preparation.adapter_catalog_digest
        ):
            raise AgenticWebSpecialistCapabilityError(
                "specialist request, preparation, adapter, and account receipt differ"
            )
        return parameters, preparation, adapter, receipt

    def network_request_cost(self, request: ToolRequest) -> int:
        self.validate_request(request)
        return WEB_SPECIALIST_REQUEST_UNITS

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self.validate_request(request)
        raise AgenticWebSpecialistCapabilityError(
            "AGENTIC-003C3B specialist dispatch binding is not installed"
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        self.validate_request(request)
        raise AgenticWebSpecialistCapabilityError(
            "AGENTIC-003C3B specialist dispatch binding is not installed"
        )


@dataclass(frozen=True, slots=True)
class _SpecialistCapabilityContract:
    definition: CapabilityDefinition
    tool: WebSpecialistAssessmentTool

    def stable_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": "pajin.agentic-web-specialist-authority/v1",
            "capabilityId": self.definition.capability_id,
            "capabilityVersion": self.definition.capability_version,
            "specialization": self.tool.specialization.value,
            "sideEffectClass": CapabilitySideEffectClass.READ_ONLY.value,
            "freshApprovalRequired": True,
            "oneCallNonDelegableGrantRequired": True,
            "cleanupRequired": False,
            "dispatchBindingInstalled": False,
            "tool": self.tool.stable_execution_context(),
        }


class _SpecialistAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(self, contract: _SpecialistCapabilityContract) -> None:
        self._contract = contract

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{self._contract.definition.capability_id}.{self.ROLE.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._contract.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._contract.stable_context()

    def _require_request(self, request: ToolRequest) -> WebSpecialistAssessmentParameters:
        try:
            parameters, _preparation, _adapter, _receipt = self._contract.tool.validate_request(
                request
            )
            return parameters
        except AgenticWebSpecialistCapabilityError as exc:
            raise CapabilityAuthorityError(
                "specialist request differs from exact code and signed material"
            ) from exc

    @staticmethod
    def _dispatch_unavailable() -> Never:
        raise CapabilityAuthorityError(
            "AGENTIC-003C3B specialist dispatch binding is not installed"
        )


class _SpecialistMaterializer(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            parsed = _strict_parameters(parameters)
            preparation = self._contract.tool.preparations.resolve(
                parsed.preparation_id,
                parsed.preparation_digest,
            )
            _require_current_preparation(preparation, self._contract.tool._config)
            receipt = self._contract.tool.account_receipts.resolve(parsed.account_receipt_ref)
            adapter = self._contract.tool.adapters.resolve(receipt.adapter)
        except (
            AgenticWebSpecialistCapabilityError,
            GovernedWebAssessmentModelError,
            ValidationError,
            ValueError,
        ) as exc:
            raise CapabilityAuthorityError(
                "specialist parameters require exact signed installed references"
            ) from exc
        if receipt.origin != preparation.target_endpoint or adapter.origin != receipt.origin:
            raise CapabilityAuthorityError("specialist account receipt belongs to another target")
        return cast(dict[str, JsonValue], parsed.model_dump(mode="json", by_alias=True))


class _SpecialistActionCompiler(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        self._require_request(request)
        try:
            parsed = _strict_parameters(materialized_arguments)
        except (AgenticWebSpecialistCapabilityError, ValidationError) as exc:
            raise CapabilityAuthorityError(
                "specialist materialized parameters are invalid"
            ) from exc
        compiled = request.model_copy(
            update={"arguments": parsed.model_dump(mode="json", by_alias=True)}
        )
        self._require_request(compiled)
        return compiled


class _SpecialistExecutor(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_request(request)
        self._dispatch_unavailable()


class _SpecialistNormalizer(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _SpecialistOracle(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _SpecialistReplay(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _SpecialistCleanup(_SpecialistAuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


@dataclass(frozen=True, slots=True)
class WebSpecialistCapabilityEntry:
    """One exact Tool, Definition, and specialization identity."""

    specialization: PentestSpecialization
    tool: WebSpecialistAssessmentTool
    definition: CapabilityDefinition


@dataclass(frozen=True, slots=True)
class WebSpecialistCapabilityBundle:
    """Three separate specialist Definitions and their complete authority sets."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry
    entries: tuple[WebSpecialistCapabilityEntry, ...]

    def entry(self, specialization: PentestSpecialization) -> WebSpecialistCapabilityEntry:
        if type(specialization) is not PentestSpecialization:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Capability selection must be canonical"
            )
        for entry in self.entries:
            if entry.specialization is specialization:
                return entry
        raise AgenticWebSpecialistCapabilityError("specialist Capability is not registered")

    def capability(self, specialization: PentestSpecialization) -> CodeBackedCapability:
        selected = self.entry(specialization)
        for capability in self.authorities.capabilities():
            if capability.capability == selected.definition.reference():
                return capability
        raise AgenticWebSpecialistCapabilityError(
            "specialist code-backed Capability is unavailable"
        )


class WebSpecialistCapabilityActivationBinding(StrictModel):
    """One exact signed release for one specialization-specific Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    specialization: PentestSpecialization
    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        try:
            config = _CONFIG_BY_SPECIALIZATION[self.specialization]
        except KeyError as exc:
            raise ValueError("specialist activation specialization is unsupported") from exc
        definition = self.capability.capability
        action = self.action_capability
        if (
            definition.capability_id != config.capability_id
            or definition.capability_version != WEB_SPECIALIST_CAPABILITY_VERSION
            or action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
            or action.tool_id != config.tool_id
        ):
            raise ValueError("specialist activation references another Capability")
        return self


class WebSpecialistCapabilityActivationSet(StrictModel):
    """Content-addressed activation of one least-privilege specialist release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-web-specialist-activation-set/v1alpha1"] = Field(
        default=WEB_SPECIALIST_ACTIVATION_SET_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebSpecialistCapabilityActivationSet"] = "WebSpecialistCapabilityActivationSet"
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=120)
    activation_set_digest: str = Field(default="", alias="activationSetDigest", max_length=64)
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: WebSpecialistCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.agentic-web-specialist-activation-set/v1",
            material,
        )
        activation_set_id = f"agentic-web-specialist-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("specialist activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("specialist activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class WebSpecialistCapabilityActivation:
    """Signed Range activation that can compile, but cannot dispatch, one action."""

    bundle: WebSpecialistCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: WebSpecialistCapabilityActivationSet

    def __post_init__(self) -> None:
        _verify_activation(self)

    @property
    def specialization(self) -> PentestSpecialization:
        return self.activation_set.binding.specialization

    def action_registry(self) -> ActionCapabilityRegistry:
        _verify_activation(self)
        return ActionCapabilityRegistry((self.activation_set.binding.action_capability,))

    def definition(self) -> CapabilityDefinition:
        _verify_activation(self)
        return self.bundle.entry(self.specialization).definition.model_copy(deep=True)

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(
        self,
        reference: ActionCapabilityRef,
    ) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise AgenticWebSpecialistCapabilityError(
                "specialist GRAPH Capability is outside the activation"
            )
        return _resolve_activation_binding(self, binding)

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        preparation_id: str,
        preparation_digest: str,
        account_receipt_ref: ProvisionedWebAccountReceiptRef,
    ) -> PreparedCapabilityAction:
        """Compile one deterministic request from exact registry references only."""

        binding = self.activation_set.binding
        canonical_release = _canonical_release_ref(release)
        if binding.release != canonical_release:
            raise AgenticWebSpecialistCapabilityError(
                "specialist release is outside the activation"
            )
        resolved = self.resolve_for_dispatch(binding.action_capability.reference())
        entry = self.bundle.entry(self.specialization)
        parameters = WebSpecialistAssessmentParameters(
            preparationId=preparation_id,
            preparationDigest=preparation_digest,
            accountReceiptRef=account_receipt_ref,
        )
        preparation = entry.tool.preparations.resolve(
            parameters.preparation_id,
            parameters.preparation_digest,
        )
        _require_current_preparation(preparation, entry.tool._config)
        request = ToolRequest(
            request_id=_specialist_request_id(entry.tool._config, preparation, parameters),
            agent_id=preparation.target_agent_id,
            tool_id=entry.tool.spec.tool_id,
            target=preparation.target_endpoint,
            method="POST",
            arguments=parameters.model_dump(mode="json", by_alias=True),
        )
        try:
            materializer = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.MATERIALIZER,
            )
            compiler = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.ACTION_COMPILER,
            )
            materialized = materializer.materialize(
                cast(Mapping[str, JsonValue], request.arguments)
            )
            compiled = compiler.compile(request, materialized)
        except CapabilityAuthorityError as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


def web_specialist_assessment_tools(
    *,
    preparations: AgenticSpecialistPreparationRegistry,
    adapters: WebAssessmentAdapterRegistry,
    account_receipts: ProvisionedWebAccountReceiptRegistry,
) -> tuple[WebSpecialistAssessmentTool, ...]:
    """Build the closed inventory of three distinct specialist Tools."""

    return tuple(
        WebSpecialistAssessmentTool(
            specialization=config.specialization,
            preparations=preparations,
            adapters=adapters,
            account_receipts=account_receipts,
        )
        for config in _CONFIGS
    )


def registered_web_specialist_capability_definition(
    tool: WebSpecialistAssessmentTool,
) -> CapabilityDefinition:
    """Bind one exact specialization-specific Tool to one CAP-001 Definition."""

    if type(tool) is not WebSpecialistAssessmentTool:
        raise TypeError("specialist Definition requires its exact Tool")
    config = tool._config
    constraints: dict[str, JsonValue] = {
        "specialization": config.specialization.value,
        "threatClass": config.threat_class,
        "preparationRegistryDigest": tool.preparations.registry_digest,
        "adapterRegistryDigest": tool.adapters.registry_digest,
        "adapterCatalogDigest": tool.adapters.catalog_digest,
        "accountReceiptTrustAnchorDigest": tool.account_receipts.trust_anchor_digest,
        "callerSelectsReferencesOnly": True,
        "callerAuthoredRoutesAllowed": False,
        "callerAuthoredPayloadsAllowed": False,
        "callerAuthoredPoliciesAllowed": False,
        "callerAuthoredTransportAllowed": False,
        "accountCreationAllowed": False,
        "targetMutationAllowed": False,
        "freshApprovalRequired": True,
        "oneCallNonDelegableGrantRequired": True,
        "dispatchBindingInstalled": False,
        "requestUnits": WEB_SPECIALIST_REQUEST_UNITS,
    }
    schema_digest = capability_definition_digest(
        "pajin.capability.agentic-web-specialist-parameter-schema/v1",
        {
            "model": (
                f"{WebSpecialistAssessmentParameters.__module__}."
                f"{WebSpecialistAssessmentParameters.__qualname__}"
            ),
            "schema": WebSpecialistAssessmentParameters.model_json_schema(by_alias=True),
            "constraints": constraints,
        },
    )
    return capability_definition_from_tool(
        tool.spec,
        ToolCapabilityRegistration(
            capabilityId=config.capability_id,
            capabilityVersion=WEB_SPECIALIST_CAPABILITY_VERSION,
            toolId=config.tool_id,
            domain="bug-bounty",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("web.application",),
            threatClasses=config.threat_classes,
            preconditions=tuple(
                sorted(
                    (
                        "current-durable-specialist-reservation-required-at-dispatch",
                        "exact-code-owned-specialist-preparation",
                        "fresh-action-approval-required",
                        "one-call-non-delegable-grant-required",
                        "one-use-action-permit-required",
                        "preprovisioned-signed-account-receipt",
                        "signed-lifecycle-range-release-required",
                        "specialist-dispatch-binding-required",
                    )
                )
            ),
            parameterSchemaDigest=schema_digest,
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=WEB_SPECIALIST_REQUEST_UNITS,
        ),
    )


def web_specialist_capability_bundle(
    tools: ToolRegistry,
) -> WebSpecialistCapabilityBundle:
    """Bind all three exact Tools to separate seven-role authority sets."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("specialist Capability requires a ToolRegistry")
    selected_tools: list[WebSpecialistAssessmentTool] = []
    first: WebSpecialistAssessmentTool | None = None
    for config in _CONFIGS:
        try:
            tool = tools.tool(config.tool_id)
            spec = tools.spec(config.tool_id)
        except (KeyError, RuntimeError, ValueError) as exc:
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool inventory is incomplete"
            ) from exc
        if (
            type(tool) is not WebSpecialistAssessmentTool
            or tool.specialization is not config.specialization
            or tool._config != config
            or spec != tool.spec
        ):
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tool implementation or specification drifted"
            )
        if first is None:
            first = tool
        elif (
            tool.preparations is not first.preparations
            or tool.adapters is not first.adapters
            or tool.account_receipts is not first.account_receipts
        ):
            raise AgenticWebSpecialistCapabilityError(
                "specialist Tools do not share one sealed deployment inventory"
            )
        selected_tools.append(tool)

    definitions_values = tuple(
        registered_web_specialist_capability_definition(tool) for tool in selected_tools
    )
    definitions = CapabilityDefinitionRegistry(definitions_values)
    entries: list[WebSpecialistCapabilityEntry] = []
    authorities: list[CapabilityAuthorityAdapter] = []
    for tool, definition in zip(selected_tools, definitions_values, strict=True):
        contract = _SpecialistCapabilityContract(definition=definition, tool=tool)
        entries.append(
            WebSpecialistCapabilityEntry(
                specialization=tool.specialization,
                tool=tool,
                definition=definition,
            )
        )
        authorities.extend(
            (
                _SpecialistActionCompiler(contract),
                _SpecialistCleanup(contract),
                _SpecialistExecutor(contract),
                _SpecialistMaterializer(contract),
                _SpecialistReplay(contract),
                _SpecialistNormalizer(contract),
                _SpecialistOracle(contract),
            )
        )
    return WebSpecialistCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
        entries=tuple(entries),
    )


def activate_web_specialist_capability(
    *,
    bundle: WebSpecialistCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    specialization: PentestSpecialization,
    release: CapabilityReleaseRef,
) -> WebSpecialistCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if type(bundle) is not WebSpecialistCapabilityBundle:
        raise TypeError("specialist activation requires its exact Capability bundle")
    if type(lifecycle) is not CapabilityLifecycleRegistry:
        raise TypeError("specialist activation requires a lifecycle registry")
    if type(specialization) is not PentestSpecialization:
        raise AgenticWebSpecialistCapabilityError(
            "specialist activation selection must be canonical"
        )
    canonical_release = _canonical_release_ref(release)
    entry = bundle.entry(specialization)
    capability = bundle.capability(specialization).reference()
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        definition = bundle.definitions.resolve(capability.capability)
    except (
        CapabilityAuthorityError,
        CapabilityDefinitionError,
        CapabilityLifecycleError,
    ) as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist signed release activation failed closed"
        ) from exc
    if (
        entry.definition != definition
        or resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
        or not definition.approval_required
        or definition.cleanup_required
        or definition.risk_tier is not ToolRiskTier.T2
    ):
        raise AgenticWebSpecialistCapabilityError(
            "specialist signed release differs from code authority"
        )
    binding = WebSpecialistCapabilityActivationBinding(
        specialization=specialization,
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(specialization, signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return WebSpecialistCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=WebSpecialistCapabilityActivationSet(binding=binding),
    )


def _require_current_preparation(
    preparation: AgenticSpecialistPreparation,
    config: _SpecialistCapabilityConfig,
) -> None:
    try:
        canonical = AgenticSpecialistPreparation.model_validate(
            preparation.model_dump(mode="json", by_alias=True)
        )
        target_profile = production_governed_web_adapter_profile_registry().resolve(
            adapter_reference=canonical.adapter_reference,
            origin=canonical.target_endpoint,
        )
        profiles = production_web_specialist_execution_profile_catalog()
        profile = profiles.resolve(canonical.profile)
        profile_snapshot = profile.snapshot()
        executors = production_web_specialist_executor_catalog()
        executor = executors.resolve(profile)
    except (
        AttributeError,
        GovernedWebAdapterProfileError,
        TypeError,
        ValidationError,
        ValueError,
        SpecialistExecutionProfileError,
        WebSpecialistExecutionProfileError,
        WebSpecialistExecutorError,
    ) as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist preparation cannot be re-resolved from current code"
        ) from exc
    if canonical != preparation:
        raise AgenticWebSpecialistCapabilityError(
            "specialist preparation differs after strict reload"
        )
    if (
        canonical.specialization is not config.specialization
        or canonical.threat_class != config.threat_class
        or canonical.target_registry_digest != target_profile.registry_digest
        or canonical.target_profile_digest != target_profile.profile_digest
        or canonical.adapter_catalog_digest != target_profile.catalog_digest
        or canonical.adapter_implementation_id != target_profile.implementation_id
        or canonical.adapter_implementation_digest != target_profile.implementation_digest
        or canonical.adapter_plan_digest != target_profile.plan_digest
        or canonical.target_id != target_profile.target_id
        or canonical.target_type != target_profile.target_type
        or canonical.target_endpoint != target_profile.origin
        or canonical.profile_registry_digest != profiles.registry_digest
        or profile_snapshot.specialization is not config.specialization
        or profile_snapshot.threat_class != config.threat_class
        or executor.catalog_digest != executors.catalog_digest
        or canonical.executor_catalog_digest != executors.catalog_digest
        or canonical.executor_id != executor.executor_id
        or canonical.executor_version != executor.executor_version
        or canonical.executor_digest != executor.executor_digest
        or canonical.browser_implementation_id != executor.browser_implementation_id
        or canonical.browser_implementation_version != executor.browser_implementation_version
        or canonical.browser_implementation_digest != executor.browser_implementation_digest
        or canonical.diagnostic_steps != cast(tuple[str, ...], executor.diagnostic_steps)
        or canonical.promotable_steps != cast(tuple[str, ...], executor.promotable_steps)
    ):
        raise AgenticWebSpecialistCapabilityError(
            "specialist preparation differs from current target, profile, or executor code"
        )


def _specialist_request_id(
    config: _SpecialistCapabilityConfig,
    preparation: AgenticSpecialistPreparation,
    parameters: WebSpecialistAssessmentParameters,
) -> str:
    request_identity = capability_definition_digest(
        "pajin.agentic.web-specialist-tool-request/v1",
        {
            "toolId": config.tool_id,
            "toolVersion": WEB_SPECIALIST_TOOL_VERSION,
            "specialization": config.specialization.value,
            "agentId": preparation.target_agent_id,
            "target": preparation.target_endpoint,
            "parameters": parameters.model_dump(mode="json", by_alias=True),
        },
    )
    return f"agentic-specialist-request_{request_identity}"


def _verify_activation(activation: WebSpecialistCapabilityActivation) -> None:
    try:
        canonical = WebSpecialistCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist activation set is not canonical"
        ) from exc
    if canonical != activation.activation_set:
        raise AgenticWebSpecialistCapabilityError("specialist activation set drifted")
    _resolve_activation_binding(activation, canonical.binding)


def _resolve_activation_binding(
    activation: WebSpecialistCapabilityActivation,
    binding: WebSpecialistCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
        code_capability = activation.bundle.capability(binding.specialization).reference()
    except (CapabilityAuthorityError, CapabilityLifecycleError) as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or code_capability != binding.capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(binding.specialization, signed_bundle)
        != binding.release_bundle_digest
    ):
        raise AgenticWebSpecialistCapabilityError("specialist signed activation drifted")
    return resolved


def _release_bundle_digest(
    specialization: PentestSpecialization,
    bundle: CapabilityReleaseBundle,
) -> str:
    return capability_definition_digest(
        "pajin.capability.agentic-web-specialist-release-bundle/v1",
        {
            "specialization": specialization.value,
            "bundle": bundle.model_dump(mode="json", by_alias=True),
        },
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise AgenticWebSpecialistCapabilityError(
            "specialist release reference is not canonical"
        ) from exc


__all__ = [
    "WEB_AUTHORIZATION_SPECIALIST_CAPABILITY_ID",
    "WEB_AUTHORIZATION_SPECIALIST_TOOL_ID",
    "WEB_SPECIALIST_ACTIVATION_SET_API_VERSION",
    "WEB_SPECIALIST_CAPABILITY_VERSION",
    "WEB_SPECIALIST_REQUEST_UNITS",
    "WEB_SPECIALIST_TOOL_VERSION",
    "WEB_SQLI_SPECIALIST_CAPABILITY_ID",
    "WEB_SQLI_SPECIALIST_TOOL_ID",
    "WEB_XSS_SPECIALIST_CAPABILITY_ID",
    "WEB_XSS_SPECIALIST_TOOL_ID",
    "AgenticSpecialistPreparationRegistry",
    "AgenticWebSpecialistCapabilityError",
    "WebSpecialistAssessmentParameters",
    "WebSpecialistAssessmentTool",
    "WebSpecialistCapabilityActivation",
    "WebSpecialistCapabilityActivationBinding",
    "WebSpecialistCapabilityActivationSet",
    "WebSpecialistCapabilityBundle",
    "WebSpecialistCapabilityEntry",
    "activate_web_specialist_capability",
    "registered_web_specialist_capability_definition",
    "web_specialist_assessment_tools",
    "web_specialist_capability_bundle",
]
