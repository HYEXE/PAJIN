"""Complete CAP-002 roles for the additive, approval-required SYS-004 Tool."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from pydantic import JsonValue

from pajin.capabilities.adapters import ToolCapabilityRegistration, capability_definition_from_tool
from pajin.capabilities.authorities import (
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapabilityRef,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
)
from pajin.capabilities.scaffold import capability_parameter_schema_digest
from pajin.domain.models import ToolRequest, ToolResult
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.system_aslr.models import (
    CAPABILITY_ID,
    TOOL_ID,
    AslrInput,
    AslrWorkerOutput,
    aslr_metadata,
)
from pajin.system_aslr.tool import AslrReadTool


@dataclass(frozen=True)
class AslrAuthority:
    """Each registered instance owns one exact role and the same immutable Tool contract."""

    authority_role: CapabilityAuthorityRole
    definition: CapabilityDefinition
    tool: AslrReadTool

    @property
    def authority_id(self) -> str:
        return CAPABILITY_ID + "." + self.authority_role.value

    @property
    def authority_version(self) -> str:
        return "1.0.0"

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "version": "pajin.sys-004-authority/v1",
            "role": self.authority_role.value,
            "tool": self.tool.stable_execution_context(),
            "oracle": "authenticated-kernel-aslr-setting",
            "findingAuthority": False,
        }

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        return cast(
            Mapping[str, JsonValue],
            AslrInput.model_validate(dict(parameters)).model_dump(mode="json", by_alias=True),
        )

    def compile(
        self, request: ToolRequest, materialized_arguments: Mapping[str, JsonValue]
    ) -> ToolRequest:
        value = AslrInput.model_validate(dict(materialized_arguments))
        if request.arguments or request.target != value.target:
            raise ValueError("System compiler requires empty input and the exact agent endpoint")
        compiled = ToolRequest.model_validate(
            {**request.model_dump(), "arguments": value.model_dump(by_alias=True)}
        )
        self.tool.validate_request(compiled)
        return compiled

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self.tool.prepare(request)

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self.tool.interpret(request, result)

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        value = self.tool.validate_request(request)
        if not result.success:
            return CapabilityOracleDecision.FAILED
        output = AslrWorkerOutput.model_validate(result.data["receipt"])
        if (
            result.request_id != request.request_id
            or result.tool_id != TOOL_ID
            or output.agent.request_id != request.request_id
            or output.agent.instance != value.instance
            or output.agent.agent_sha256 != self.tool.deployment.agent_sha256
            or output.client_sha256 != self.tool.deployment.client_sha256
            or output.server_cert_sha256 != self.tool.deployment.server_cert_sha256
            or output.client_cert_sha256 != self.tool.deployment.client_cert_sha256
            or result.data["metadata"] != aslr_metadata(output.agent.content())
        ):
            raise ValueError("System Oracle result identity differs")
        return CapabilityOracleDecision.SUCCEEDED

    def plan_replay(
        self, request: ToolRequest, result: ToolResult
    ) -> Mapping[str, JsonValue] | None:
        self.tool.validate_request(request)
        if not result.success:
            return None
        return {
            "version": "pajin.sys-004-reexecution-plan/v1",
            "toolId": TOOL_ID,
            "target": request.target,
            "arguments": request.arguments,
            "freshRunRequired": True,
            "freshApprovalRequired": True,
            "freshPermitRequired": True,
            "executionAuthorized": False,
        }

    def plan_cleanup(
        self, request: ToolRequest, result: ToolResult
    ) -> Mapping[str, JsonValue] | None:
        self.tool.validate_request(request)
        # No target writes or persistent target resources exist in this profile. Docker Worker
        # lifecycle owns its disposable process; its observed absence is verified separately.
        return None


@dataclass(frozen=True)
class AslrBundle:
    definition: CapabilityDefinition
    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    @property
    def reference(self) -> CodeBackedCapabilityRef:
        return self.authorities.capabilities()[0].reference()


def aslr_capability_bundle(tool: AslrReadTool) -> AslrBundle:
    if type(tool) is not AslrReadTool:
        raise TypeError("SYS-004 Capability requires its exact Tool implementation")
    schema = AslrInput.model_json_schema(by_alias=True)
    schema["required"] = sorted(schema["required"])
    definition = capability_definition_from_tool(
        tool.spec,
        ToolCapabilityRegistration(
            capabilityId=CAPABILITY_ID,
            capabilityVersion="1.0.0",
            toolId=TOOL_ID,
            domain="system",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("system-host-agent",),
            threatClasses=("kernel-aslr-setting",),
            parameterSchemaDigest=capability_parameter_schema_digest(schema),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
            preconditions=(
                "exact-authorized-authenticated-agent",
                "non-root-mtls-proxied-worker",
                "separate-operator-approval",
            ),
        ),
    )
    definitions = CapabilityDefinitionRegistry((definition,))
    return AslrBundle(
        definition,
        definitions,
        CapabilityAuthorityRegistry(
            definitions,
            tuple(AslrAuthority(role, definition, tool) for role in CapabilityAuthorityRole),
        ),
    )
