"""Explicit Capability adapters for PAJIN's existing bounded Mode Tools."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import ClassVar, cast

from pydantic import BaseModel, JsonValue, ValidationError

from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_registry_from_tools,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapability,
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
from pajin.domain.ctf import CTFScenario
from pajin.domain.models import ToolRequest, ToolResult
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.modes.ai_redteam.evidence import evaluate_kisa_transcript
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.modes.ai_redteam.replay import (
    KISA_AUTOMATIC_REPLAY_SCENARIO_IDS,
    KISA_IMPACT_REPLAY_ORACLE_ID,
    KISA_NEGATIVE_RETEST_ORACLE_ID,
    KISA_NEGATIVE_RETEST_ORACLE_VERSION,
    KISA_REPLAY_MATERIALIZER_ID,
    KISA_REPLAY_MATERIALIZER_VERSION,
    KISA_REPLAY_OBSERVATION_SCHEMA,
    KISA_REPLAY_ORACLE_ID,
    KISA_REPLAY_ORACLE_VERSION,
    KISA_SEVERITY_REPLAY_ORACLE_ID,
    kisa_negative_retest_contract,
    kisa_replay_contract,
)
from pajin.replay import replay_scenario_digest
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.ai import AIChatProbeInput
from pajin.tools.base import Tool, ToolRegistry
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiObservation,
    BooleanSQLiProbeInput,
    BooleanSQLiProbeOutput,
)
from pajin.tools.ctf import (
    CTF_CRYPTO_XOR_TOOL_ID,
    CTF_WEB_BACKUP_TOOL_ID,
    CTFCryptoXORInput,
    CTFCryptoXOROutput,
    CTFWebBackupProbeInput,
    CTFWebBackupProbeOutput,
)
from pajin.tools.mock import MockAgentProbeInput, MockAgentProbeOutput

EXISTING_MODE_CAPABILITY_ADAPTER_VERSION = "pajin.existing-mode-capability-adapter/v1"
EXISTING_KISA_REPLAY_PLAN_API_VERSION = "pajin.dev/existing-kisa-replay-plan/v1alpha1"
_AUTHORITY_VERSION = "1.0.0"

_KISA_CAPABILITY_IDS = {
    "kisa.agent.indirect-tool-hijacking": "pajin.ai.kisa.indirect-tool-hijacking",
    "kisa.model.system-prompt-disclosure": "pajin.ai.kisa.system-prompt-disclosure",
    "kisa.model.jailbreak-policy-bypass": "pajin.ai.kisa.jailbreak-policy-bypass",
    "kisa.agent.memory-poisoning-persistence": ("pajin.ai.kisa.memory-poisoning-persistence"),
}


class ExistingCapabilitySuccessPolicy(StrEnum):
    """Stable semantic policies used by existing-mode success Oracles."""

    BOOLEAN_SQLI_OBSERVATIONS = "boolean-sqli-observations"
    CTF_CRYPTO_HOST_RECOMPUTE = "ctf-crypto-host-recompute"
    CTF_WEB_CANDIDATE = "ctf-web-candidate"
    KISA_CATALOG_TRANSCRIPT = "kisa-catalog-transcript"
    MOCK_AGENT_SIMULATION = "mock-agent-simulation"


@dataclass(frozen=True, slots=True)
class ExistingModeCapabilityBundle:
    """Frozen CAP-001 and CAP-002 registries for supported existing Mode Tools."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capabilities(self) -> tuple[CodeBackedCapability, ...]:
        """Return detached code-backed manifests in canonical order."""

        return self.authorities.capabilities()


@dataclass(frozen=True, slots=True)
class _ExistingCapabilityContract:
    registration: ToolCapabilityRegistration
    expected_tool_version: str
    method: str
    parameter_model: type[BaseModel]
    scenario_id: str
    success_policy: ExistingCapabilitySuccessPolicy
    kisa_scenario: KISAScenarioDefinition | None = None
    replay_enabled: bool = False

    def context(self, tool: Tool) -> dict[str, object]:
        replay = _kisa_replay_binding(self.kisa_scenario) if self.replay_enabled else None
        tool_context = stable_execution_context(
            tool,
            component=f"existing Capability Tool {self.registration.tool_id}",
        )
        return {
            "adapterContractVersion": EXISTING_MODE_CAPABILITY_ADAPTER_VERSION,
            "capabilityId": self.registration.capability_id,
            "capabilityVersion": self.registration.capability_version,
            "method": self.method,
            "parameterModel": _qualified_type(self.parameter_model),
            "parameterSchemaDigest": self.registration.parameter_schema_digest,
            "scenarioId": self.scenario_id,
            "successPolicy": self.success_policy.value,
            "replayBinding": replay,
            "tool": _json_context_value(tool_context),
        }


class _ExistingAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        contract: _ExistingCapabilityContract,
        definition: CapabilityDefinition,
        tool: Tool,
    ) -> None:
        self._contract = contract
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{self._contract.registration.capability_id}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def _stable_context(self) -> Mapping[str, object]:
        return self._contract.context(self._tool)


class _ExistingMaterializer(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        try:
            parsed = self._contract.parameter_model.model_validate(parameters)
        except ValidationError as exc:
            raise CapabilityAuthorityError(
                "existing Capability parameters do not match the exact Tool input"
            ) from exc
        materialized = cast(
            dict[str, JsonValue],
            parsed.model_dump(mode="json", by_alias=True),
        )
        _validate_scenario_arguments(self._contract, materialized)
        return materialized


class _ExistingActionCompiler(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        if request.method != self._contract.method:
            raise CapabilityAuthorityError(
                "existing Capability request method differs from its fixed Tool contract"
            )
        return request.model_copy(update={"arguments": dict(materialized_arguments)})


class _ExistingExecutorAdapter(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _ExistingResultNormalizer(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _ExistingSuccessOracle(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        return _semantic_decision(self._contract, request, result)


class _ExistingReplayStrategy(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        scenario = self._contract.kisa_scenario
        if (
            not self._contract.replay_enabled
            or scenario is None
            or _semantic_decision(self._contract, request, result)
            is not CapabilityOracleDecision.SUCCEEDED
        ):
            return None
        confirmation = kisa_replay_contract(scenario.scenario_id)
        negative_retest = kisa_negative_retest_contract(scenario.scenario_id)
        return {
            "apiVersion": EXISTING_KISA_REPLAY_PLAN_API_VERSION,
            "kind": "ExistingKISAReplayPlan",
            "executable": False,
            "newAuthorizationRequired": True,
            "scenarioId": scenario.scenario_id,
            "scenarioDigest": replay_scenario_digest(scenario),
            "confirmationContract": cast(
                JsonValue,
                confirmation.model_dump(mode="json", by_alias=True),
            ),
            "negativeRetestContract": cast(
                JsonValue,
                negative_retest.model_dump(mode="json", by_alias=True),
            ),
        }


class _ExistingCleanupHandler(_ExistingAuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


def existing_mode_capability_registrations() -> tuple[ToolCapabilityRegistration, ...]:
    """Return the seven explicit Tool registrations without discovering plugins."""

    return tuple(contract.registration for contract in _existing_capability_contracts())


def existing_mode_capability_bundle(
    tools: ToolRegistry,
) -> ExistingModeCapabilityBundle:
    """Bind supported current Mode Tools to complete CAP-001/CAP-002 registries."""

    contracts = _existing_capability_contracts()
    for contract in contracts:
        try:
            spec = tools.spec(contract.registration.tool_id)
        except (AttributeError, KeyError, RuntimeError, ValueError) as exc:
            raise CapabilityDefinitionError(
                "existing Capability Tool is unavailable or has drifted"
            ) from exc
        if spec.version != contract.expected_tool_version:
            raise CapabilityDefinitionError(
                "existing Capability Tool version differs from its explicit adapter"
            )

    definitions = capability_registry_from_tools(
        tools,
        (contract.registration for contract in contracts),
    )
    indexed = {
        (definition.capability_id, definition.capability_version): definition
        for definition in definitions.definitions()
    }
    authorities: list[CapabilityAuthorityAdapter] = []
    for contract in contracts:
        key = (
            contract.registration.capability_id,
            contract.registration.capability_version,
        )
        definition = indexed[key]
        tool = tools.tool(contract.registration.tool_id)
        authorities.extend(_authorities_for(contract, definition, tool))
    return ExistingModeCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def _authorities_for(
    contract: _ExistingCapabilityContract,
    definition: CapabilityDefinition,
    tool: Tool,
) -> tuple[CapabilityAuthorityAdapter, ...]:
    return (
        _ExistingMaterializer(contract, definition, tool),
        _ExistingActionCompiler(contract, definition, tool),
        _ExistingExecutorAdapter(contract, definition, tool),
        _ExistingResultNormalizer(contract, definition, tool),
        _ExistingSuccessOracle(contract, definition, tool),
        _ExistingReplayStrategy(contract, definition, tool),
        _ExistingCleanupHandler(contract, definition, tool),
    )


def _existing_capability_contracts() -> tuple[_ExistingCapabilityContract, ...]:
    contracts = [*(_kisa_contract(scenario) for scenario in KISA_CATALOG.scenarios)]
    contracts.extend((_boolean_sqli_contract(), _ctf_web_contract(), _ctf_crypto_contract()))
    return tuple(contracts)


def _kisa_contract(scenario: KISAScenarioDefinition) -> _ExistingCapabilityContract:
    try:
        capability_id = _KISA_CAPABILITY_IDS[scenario.scenario_id]
    except KeyError as exc:
        raise CapabilityDefinitionError(
            "KISA catalog scenario lacks an explicit Capability adapter"
        ) from exc
    if scenario.tool_id == "mock.agent-probe":
        parameter_model: type[BaseModel] = MockAgentProbeInput
        success_policy = ExistingCapabilitySuccessPolicy.MOCK_AGENT_SIMULATION
        side_effect = CapabilitySideEffectClass.NONE
    elif scenario.tool_id == "ai.chat-probe":
        parameter_model = AIChatProbeInput
        success_policy = ExistingCapabilitySuccessPolicy.KISA_CATALOG_TRANSCRIPT
        side_effect = CapabilitySideEffectClass.READ_ONLY
    else:
        raise CapabilityDefinitionError("KISA catalog scenario uses an unsupported existing Tool")
    constraints: dict[str, JsonValue] = {
        "scenarioId": scenario.scenario_id,
        "catalogScenarioDigest": replay_scenario_digest(scenario),
        "threatClasses": cast(JsonValue, sorted(scenario.threat_classes)),
        "exactCatalogProbe": scenario.probe is not None,
    }
    return _ExistingCapabilityContract(
        registration=ToolCapabilityRegistration(
            capabilityId=capability_id,
            capabilityVersion="1.0.0",
            toolId=scenario.tool_id,
            domain="ai-redteam",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=tuple(sorted(scenario.target_types)),
            threatClasses=tuple(sorted(scenario.threat_classes)),
            preconditions=(
                "authorized-target",
                "bounded-kisa-catalog-scenario",
            ),
            parameterSchemaDigest=_parameter_schema_digest(
                parameter_model,
                constraints=constraints,
            ),
            sideEffectClass=side_effect,
            approvalRequired=False,
            cleanupRequired=False,
        ),
        expected_tool_version="1.0.0",
        method=scenario.method,
        parameter_model=parameter_model,
        scenario_id=scenario.scenario_id,
        success_policy=success_policy,
        kisa_scenario=scenario,
        replay_enabled=scenario.scenario_id in KISA_AUTOMATIC_REPLAY_SCENARIO_IDS,
    )


def _boolean_sqli_contract() -> _ExistingCapabilityContract:
    return _ExistingCapabilityContract(
        registration=ToolCapabilityRegistration(
            capabilityId="pajin.bug-bounty.boolean-sqli-lab",
            capabilityVersion="1.0.0",
            toolId="bug-bounty.boolean-sqli-probe",
            domain="bug-bounty",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("bug-bounty-api",),
            threatClasses=("CWE-89",),
            preconditions=(
                "authorized-target",
                "fixed-local-lab-endpoint",
                "synthetic-local-lab",
            ),
            parameterSchemaDigest=_parameter_schema_digest(
                BooleanSQLiProbeInput,
                constraints={"scenarioId": BOOLEAN_SQLI_SCENARIO},
            ),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=False,
            cleanupRequired=False,
        ),
        expected_tool_version="1.0.0",
        method="GET",
        parameter_model=BooleanSQLiProbeInput,
        scenario_id=BOOLEAN_SQLI_SCENARIO,
        success_policy=ExistingCapabilitySuccessPolicy.BOOLEAN_SQLI_OBSERVATIONS,
    )


def _ctf_web_contract() -> _ExistingCapabilityContract:
    scenario_id = CTFScenario.WEB_EXPOSED_BACKUP_CONFIG.value
    return _ExistingCapabilityContract(
        registration=ToolCapabilityRegistration(
            capabilityId="pajin.ctf.web-exposed-backup-config",
            capabilityVersion="1.0.0",
            toolId=CTF_WEB_BACKUP_TOOL_ID,
            domain="ctf",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("ctf-web",),
            threatClasses=("CTF-WEB",),
            preconditions=(
                "fixed-local-lab-endpoint",
                "synthetic-local-lab",
            ),
            parameterSchemaDigest=_parameter_schema_digest(
                CTFWebBackupProbeInput,
                constraints={"scenarioId": scenario_id},
            ),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=False,
            cleanupRequired=False,
        ),
        expected_tool_version="1.0.0",
        method="GET",
        parameter_model=CTFWebBackupProbeInput,
        scenario_id=scenario_id,
        success_policy=ExistingCapabilitySuccessPolicy.CTF_WEB_CANDIDATE,
    )


def _ctf_crypto_contract() -> _ExistingCapabilityContract:
    scenario_id = CTFScenario.CRYPTO_SINGLE_BYTE_XOR.value
    return _ExistingCapabilityContract(
        registration=ToolCapabilityRegistration(
            capabilityId="pajin.ctf.crypto-single-byte-xor",
            capabilityVersion="1.0.0",
            toolId=CTF_CRYPTO_XOR_TOOL_ID,
            domain="ctf",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("ctf-crypto",),
            threatClasses=("CTF-CRYPTO",),
            preconditions=(
                "content-addressed-inline-artifact",
                "synthetic-local-lab",
            ),
            parameterSchemaDigest=_parameter_schema_digest(
                CTFCryptoXORInput,
                constraints={"scenarioId": scenario_id},
            ),
            sideEffectClass=CapabilitySideEffectClass.NONE,
            approvalRequired=False,
            cleanupRequired=False,
        ),
        expected_tool_version="1.0.0",
        method="POST",
        parameter_model=CTFCryptoXORInput,
        scenario_id=scenario_id,
        success_policy=ExistingCapabilitySuccessPolicy.CTF_CRYPTO_HOST_RECOMPUTE,
    )


def _parameter_schema_digest(
    model_type: type[BaseModel],
    *,
    constraints: Mapping[str, JsonValue],
) -> str:
    return capability_definition_digest(
        "pajin.capability.existing-parameter-schema/v1",
        {
            "model": _qualified_type(model_type),
            "schema": model_type.model_json_schema(by_alias=True),
            "constraints": dict(constraints),
        },
    )


def _validate_scenario_arguments(
    contract: _ExistingCapabilityContract,
    arguments: Mapping[str, JsonValue],
) -> None:
    scenario = contract.kisa_scenario
    if (
        scenario is not None
        and scenario.tool_id == "ai.chat-probe"
        and not scenario.matches_replay_arguments(arguments)
    ):
        raise CapabilityAuthorityError(
            "KISA Capability parameters differ from the exact catalog probe"
        )


def _semantic_decision(
    contract: _ExistingCapabilityContract,
    request: ToolRequest,
    result: ToolResult,
) -> CapabilityOracleDecision:
    if not result.success:
        return CapabilityOracleDecision.INCONCLUSIVE
    try:
        supported = _semantic_support(contract, request, result)
    except (TypeError, ValidationError, ValueError):
        return CapabilityOracleDecision.INCONCLUSIVE
    return CapabilityOracleDecision.SUCCEEDED if supported else CapabilityOracleDecision.FAILED


def _semantic_support(
    contract: _ExistingCapabilityContract,
    request: ToolRequest,
    result: ToolResult,
) -> bool:
    policy = contract.success_policy
    if policy is ExistingCapabilitySuccessPolicy.MOCK_AGENT_SIMULATION:
        return _mock_agent_support(request, result)
    if policy is ExistingCapabilitySuccessPolicy.KISA_CATALOG_TRANSCRIPT:
        scenario = contract.kisa_scenario
        if scenario is None:
            raise ValueError("KISA transcript policy is missing its catalog scenario")
        return evaluate_kisa_transcript(
            scenario=scenario,
            request=request,
            output_value=result.data,
        ).supports_claim
    if policy is ExistingCapabilitySuccessPolicy.BOOLEAN_SQLI_OBSERVATIONS:
        return _boolean_sqli_support(request, result)
    if policy is ExistingCapabilitySuccessPolicy.CTF_WEB_CANDIDATE:
        return _ctf_web_support(request, result)
    if policy is ExistingCapabilitySuccessPolicy.CTF_CRYPTO_HOST_RECOMPUTE:
        return _ctf_crypto_support(request, result)
    raise ValueError("existing Capability uses an unsupported success policy")


def _mock_agent_support(request: ToolRequest, result: ToolResult) -> bool:
    probe = MockAgentProbeInput.model_validate(request.arguments)
    output = MockAgentProbeOutput.model_validate(result.data)
    expected = probe.simulation.unauthorized_tool_call
    expected_observation = (
        "target accepted an untrusted instruction and invoked a protected tool"
        if expected
        else "target rejected the untrusted instruction"
    )
    if (
        output.target != request.target
        or output.network_performed
        or output.vulnerable is not expected
        or output.observation != expected_observation
    ):
        raise ValueError("mock agent observation differs from its authorized simulation")
    return expected


def _boolean_sqli_support(request: ToolRequest, result: ToolResult) -> bool:
    probe = BooleanSQLiProbeInput.model_validate(request.arguments)
    output = BooleanSQLiProbeOutput.model_validate(result.data)
    if (
        output.target != request.target
        or output.scenario_id != probe.scenario_id
        or not output.network_performed
    ):
        raise ValueError("Boolean SQLi observation identity differs from its request")
    return _boolean_sqli_observations_confirm(output.observations)


def _boolean_sqli_observations_confirm(
    observations: list[BooleanSQLiObservation],
) -> bool:
    by_name = {observation.name: observation for observation in observations}
    baseline = by_name["baseline"]
    negative = by_name["negative-control"]
    probe = by_name["boolean-probe"]
    return (
        baseline.status == 200
        and baseline.record_count == 1
        and negative.status in {200, 400}
        and negative.record_count == 0
        and probe.status == 200
        and probe.record_count > baseline.record_count
        and all(observation.synthetic for observation in observations)
    )


def _ctf_web_support(request: ToolRequest, result: ToolResult) -> bool:
    probe = CTFWebBackupProbeInput.model_validate(request.arguments)
    output = CTFWebBackupProbeOutput.model_validate(result.data)
    if (
        output.target != request.target
        or output.challenge_id != probe.challenge_id
        or output.scenario_id != probe.scenario_id
        or not output.network_performed
    ):
        raise ValueError("CTF Web observation identity differs from its request")
    return output.discovered


def _ctf_crypto_support(request: ToolRequest, result: ToolResult) -> bool:
    probe = CTFCryptoXORInput.model_validate(request.arguments)
    output = CTFCryptoXOROutput.model_validate(result.data)
    if (
        output.target != request.target
        or output.challenge_id != probe.challenge_id
        or output.scenario_id != probe.scenario_id
        or output.artifact_sha256 != probe.artifact_sha256
    ):
        raise ValueError("CTF Crypto observation identity differs from its request")
    expected_key, expected_candidate = _solve_single_byte_xor(probe.ciphertext_hex)
    if (
        output.solved != (expected_candidate is not None)
        or output.candidate_flag != expected_candidate
        or output.key != expected_key
    ):
        raise ValueError("CTF Crypto observation differs from host recomputation")
    return output.solved


def _solve_single_byte_xor(ciphertext_hex: str) -> tuple[int | None, str | None]:
    ciphertext = bytes.fromhex(ciphertext_hex)
    matches: list[tuple[int, str]] = []
    for key in range(256):
        plaintext_bytes = bytes(value ^ key for value in ciphertext)
        try:
            plaintext = plaintext_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if fullmatch(r"PAJIN\{[A-Za-z0-9_-]{1,128}\}", plaintext):
            matches.append((key, plaintext))
    if len(matches) > 1:
        raise ValueError("CTF Crypto host analysis produced ambiguous flag candidates")
    return matches[0] if matches else (None, None)


def _kisa_replay_binding(
    scenario: KISAScenarioDefinition | None,
) -> dict[str, JsonValue] | None:
    if scenario is None:
        return None
    return {
        "scenarioDigest": replay_scenario_digest(scenario),
        "sessionPolicy": "fresh-session",
        "materializerId": KISA_REPLAY_MATERIALIZER_ID,
        "materializerVersion": KISA_REPLAY_MATERIALIZER_VERSION,
        "confirmationOracleIds": [
            KISA_REPLAY_ORACLE_ID,
            KISA_IMPACT_REPLAY_ORACLE_ID,
            KISA_SEVERITY_REPLAY_ORACLE_ID,
        ],
        "confirmationOracleVersion": KISA_REPLAY_ORACLE_VERSION,
        "negativeRetestOracleId": KISA_NEGATIVE_RETEST_ORACLE_ID,
        "negativeRetestOracleVersion": KISA_NEGATIVE_RETEST_ORACLE_VERSION,
        "observationSchema": KISA_REPLAY_OBSERVATION_SCHEMA,
    }


def _qualified_type(value: type[object]) -> str:
    return f"{value.__module__}.{value.__qualname__}"


def _json_context_value(value: object) -> JsonValue:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, BaseModel):
        return cast(JsonValue, value.model_dump(mode="json", by_alias=True))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("stable Tool context keys must be strings")
        return {key: _json_context_value(child) for key, child in sorted(value.items())}
    if isinstance(value, set | frozenset):
        return [_json_context_value(child) for child in sorted(value, key=str)]
    if isinstance(value, list | tuple):
        return [_json_context_value(child) for child in value]
    raise TypeError("stable Tool context contains a non-JSON value")
