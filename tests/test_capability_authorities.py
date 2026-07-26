from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256

import pytest
from pydantic import JsonValue, ValidationError

from pajin.capabilities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilityOracleDecision,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    CodeBackedCapability,
    CodeBackedCapabilityRef,
    capability_authority_binding,
)
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import (
    EgressPolicy,
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)

DIGEST_A = sha256(b"a").hexdigest()
DIGEST_B = sha256(b"b").hexdigest()


def _definition() -> CapabilityDefinition:
    return CapabilityDefinition(
        capabilityId="pajin.discovery.read-surface",
        capabilityVersion="1.0.0",
        domain="web",
        maturity=CapabilityMaturity.CANARY,
        supportedSurfaceTypes=("http-endpoint",),
        threatClasses=("surface-discovery",),
        preconditions=("campaign-scope-approved",),
        parameterSchemaDigest=DIGEST_A,
        tool=CapabilityToolBinding(
            toolId="test.read-surface",
            toolVersion="1.2.3",
            toolDigest=DIGEST_B,
        ),
        riskTier=ToolRiskTier.T1,
        sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
        evidenceTypes=("json",),
        networkAccess=False,
        approvalRequired=False,
        requestUnitCost=1,
        cleanupRequired=False,
        parallelSafe=True,
    )


class _AuthorityBase:
    ROLE: CapabilityAuthorityRole
    NAME: str

    def __init__(
        self,
        definition: CapabilityDefinition,
        *,
        identity_suffix: str = "",
    ) -> None:
        self.authority_role = self.ROLE
        self.authority_id = f"test.capability.{self.NAME}{identity_suffix}"
        self.authority_version = "1.0.0"
        self.capability_reference = definition.reference()
        self.context_version = "test.authority/v1"
        self.context_extra: object | None = None
        self.mutate_during_call = False

    def _stable_context(self) -> Mapping[str, object]:
        context: dict[str, object] = {
            "implementationVersion": self.context_version,
            "role": self.ROLE.value,
        }
        if self.context_extra is not None:
            context["extra"] = self.context_extra
        return context

    def _maybe_mutate(self) -> None:
        if self.mutate_during_call:
            self.context_version = "test.authority/v2"


class _Materializer(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER
    NAME = "materializer"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        self._maybe_mutate()
        return dict(parameters)


class _Compiler(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER
    NAME = "compiler"

    def __init__(self, definition: CapabilityDefinition) -> None:
        super().__init__(definition)
        self.expand_target = False

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        self._maybe_mutate()
        return request.model_copy(
            update={
                "arguments": dict(materialized_arguments),
                "target": "https://expanded.invalid" if self.expand_target else request.target,
            }
        )


class _Executor(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER
    NAME = "executor"

    def __init__(self, definition: CapabilityDefinition) -> None:
        super().__init__(definition)
        self.enable_network = False

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._maybe_mutate()
        if self.enable_network:
            return WorkerJob(
                image="pajin-worker:test",
                command=["read-surface"],
                network=NetworkMode.EGRESS_PROXY,
                egress_policy=EgressPolicy(allow=[request.target]),
            )
        return WorkerJob(
            image="pajin-worker:test",
            command=["read-surface"],
        )


class _Normalizer(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER
    NAME = "normalizer"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self._maybe_mutate()
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=result.status is WorkerStatus.SUCCEEDED,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={"status": result.status.value},
        )


class _Oracle(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE
    NAME = "oracle"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        del request
        self._maybe_mutate()
        return (
            CapabilityOracleDecision.SUCCEEDED
            if result.success
            else CapabilityOracleDecision.FAILED
        )


class _Replay(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY
    NAME = "replay"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        self._maybe_mutate()
        return {"sessionPolicy": "fresh", "repetitions": 1}


class _Cleanup(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER
    NAME = "cleanup"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        self._maybe_mutate()
        return {"required": False}


class _BrokenMaterializer(_AuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER
    NAME = "broken-materializer"

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._stable_context()


def _authorities(definition: CapabilityDefinition) -> list[CapabilityAuthorityAdapter]:
    return [
        _Compiler(definition),
        _Cleanup(definition),
        _Executor(definition),
        _Materializer(definition),
        _Replay(definition),
        _Normalizer(definition),
        _Oracle(definition),
    ]


def _registry(
    definition: CapabilityDefinition,
    authorities: list[CapabilityAuthorityAdapter] | None = None,
) -> CapabilityAuthorityRegistry:
    return CapabilityAuthorityRegistry(
        CapabilityDefinitionRegistry([definition]),
        authorities or _authorities(definition),
    )


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="request-1",
        agent_id="agent-1",
        tool_id="test.read-surface",
        target="https://example.test",
        method="GET",
    )


def _worker_result(job: WorkerJob) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="test-worker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=now,
        finished_at=now,
    )


def test_registry_binds_complete_authority_set_and_invokes_each_role() -> None:
    definition = _definition()
    registry = _registry(definition)
    manifest = registry.capabilities()[0]

    assert manifest == _registry(definition).capabilities()[0]
    assert manifest.capability == definition.reference()
    assert [item.role.value for item in manifest.authorities] == sorted(
        role.value for role in CapabilityAuthorityRole
    )
    assert registry.resolve(manifest.reference()) == manifest

    parameters = {"path": "/health", "headers": {"accept": "application/json"}}
    materialized = registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.MATERIALIZER,
    ).materialize(parameters)
    request = registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.ACTION_COMPILER,
    ).compile(_request(), materialized)
    job = registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.EXECUTOR_ADAPTER,
    ).prepare(request)
    result = registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.RESULT_NORMALIZER,
    ).normalize(request, _worker_result(job))

    assert request.arguments == parameters
    assert job.network is NetworkMode.NONE
    assert result.success
    assert (
        registry.authority(
            manifest.reference(),
            CapabilityAuthorityRole.SUCCESS_ORACLE,
        ).evaluate(request, result)
        is CapabilityOracleDecision.SUCCEEDED
    )
    assert registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.REPLAY_STRATEGY,
    ).plan_replay(request, result) == {
        "repetitions": 1,
        "sessionPolicy": "fresh",
    }
    assert registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.CLEANUP_HANDLER,
    ).plan_cleanup(request, result) == {"required": False}


def test_registry_rejects_missing_duplicate_and_unregistered_authorities() -> None:
    definition = _definition()
    with pytest.raises(CapabilityAuthorityError, match="missing required authorities"):
        _registry(definition, _authorities(definition)[:-1])

    duplicate = _Materializer(definition, identity_suffix="-second")
    with pytest.raises(CapabilityAuthorityError, match="role is registered more than once"):
        _registry(definition, [*_authorities(definition), duplicate])

    unknown = _Materializer(definition)
    unknown.capability_reference = CapabilityDefinitionRef(
        capabilityId=definition.capability_id,
        capabilityVersion=definition.capability_version,
        capabilityDigest=DIGEST_A,
    )
    with pytest.raises(CapabilityAuthorityError, match="unregistered definition"):
        CapabilityAuthorityRegistry(
            CapabilityDefinitionRegistry([definition]),
            [unknown],
        )


def test_binding_rejects_wrong_interface_secret_context_and_non_json_context() -> None:
    definition = _definition()
    with pytest.raises(CapabilityAuthorityError, match="does not implement"):
        capability_authority_binding(_BrokenMaterializer(definition))

    secret = _Materializer(definition)
    secret.context_extra = {"apiToken": "not-allowed"}
    with pytest.raises(CapabilityAuthorityError, match="stable context is invalid"):
        capability_authority_binding(secret)

    non_json = _Materializer(definition)
    non_json.context_extra = {"unordered": {"a", "b"}}
    with pytest.raises(CapabilityAuthorityError, match="stable context is invalid"):
        capability_authority_binding(non_json)


def test_registry_detects_post_registration_and_in_call_identity_drift() -> None:
    definition = _definition()
    authorities = _authorities(definition)
    materializer = next(item for item in authorities if isinstance(item, _Materializer))
    registry = _registry(definition, authorities)
    manifest = registry.capabilities()[0]

    materializer.context_version = "test.authority/v2"
    with pytest.raises(CapabilityAuthorityError, match="identity changed"):
        registry.resolve(manifest.reference())

    authorities = _authorities(definition)
    materializer = next(item for item in authorities if isinstance(item, _Materializer))
    registry = _registry(definition, authorities)
    manifest = registry.capabilities()[0]
    handle = registry.authority(
        manifest.reference(),
        CapabilityAuthorityRole.MATERIALIZER,
    )
    materializer.mutate_during_call = True
    with pytest.raises(CapabilityAuthorityError, match="identity changed"):
        handle.materialize({"path": "/health"})


def test_compiler_and_executor_cannot_expand_declared_authority() -> None:
    definition = _definition()
    authorities = _authorities(definition)
    compiler = next(item for item in authorities if isinstance(item, _Compiler))
    executor = next(item for item in authorities if isinstance(item, _Executor))
    registry = _registry(definition, authorities)
    reference = registry.capabilities()[0].reference()

    compiler.expand_target = True
    with pytest.raises(CapabilityAuthorityError, match="expanded or changed"):
        registry.authority(
            reference,
            CapabilityAuthorityRole.ACTION_COMPILER,
        ).compile(_request(), {"path": "/health"})

    wrong_tool_request = _request().model_copy(update={"tool_id": "test.other-tool"})
    with pytest.raises(CapabilityAuthorityError, match="another registered Tool"):
        registry.authority(
            reference,
            CapabilityAuthorityRole.ACTION_COMPILER,
        ).compile(wrong_tool_request, {"path": "/health"})

    executor.enable_network = True
    with pytest.raises(CapabilityAuthorityError, match="network-disabled"):
        registry.authority(
            reference,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
        ).prepare(_request())


def test_authority_set_and_exact_reference_reject_tampering() -> None:
    definition = _definition()
    registry = _registry(definition)
    manifest = registry.capabilities()[0]

    raw = manifest.model_dump(mode="json", by_alias=True)
    raw["authoritySetDigest"] = DIGEST_A
    with pytest.raises(ValidationError, match="digest differs"):
        CodeBackedCapability.model_validate(raw)

    wrong = CodeBackedCapabilityRef(
        capability=manifest.capability,
        authoritySetId=manifest.authority_set_id,
        authoritySetDigest=DIGEST_A,
    )
    with pytest.raises(CapabilityAuthorityError, match="differs from the registry"):
        registry.resolve(wrong)


def test_wrong_role_wrapper_cannot_invoke_another_authority_interface() -> None:
    registry = _registry(_definition())
    reference = registry.capabilities()[0].reference()
    compiler = registry.authority(
        reference,
        CapabilityAuthorityRole.ACTION_COMPILER,
    )

    with pytest.raises(CapabilityAuthorityError, match="cannot perform materializer"):
        compiler.materialize({"path": "/health"})
