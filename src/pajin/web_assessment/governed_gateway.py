"""Exact ToolGateway launch and sealed completion authority for WEB-005."""

from __future__ import annotations

import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Literal, cast, final

from pydantic import ConfigDict, Field, model_validator

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.web_authenticated_assessment import (
    WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
    WebAuthenticatedAssessmentTool,
)
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    campaign_manifest_digest,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import (
    SecretBroker,
    SecretMaterial,
    secret_broker_system_utc_now,
)
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger, ToolGateway
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterRegistry,
    WebAssessmentDispatchBinding,
    WebAssessmentDispatchBindingRegistry,
    web_assessment_system_utc_now,
)
from pajin.web_assessment.governed_worker import (
    _WEB_WORKER_GATEWAY_FACTORY_TOKEN,
    WEB_WORKER_BACKEND_NAME,
    HostLoopbackBrowserWorkerBackend,
    HostLoopbackWebAssessmentJobCompiler,
    HostLoopbackWebAssessmentOutputVerifier,
    WebWorkerAuthorityBinding,
    WebWorkerCompletedActionAuthority,
    _WebWorkerGatewayLaunchAuthority,
    canonical_web_worker_sha256,
)

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_MAX_GATEWAY_ARTIFACT_BYTES = 10_000_000
_GATEWAY_FACTORY_TOKEN = object()
_EXACT_TOOL_GATEWAY_EXECUTE = ToolGateway.execute
_RunPathIdentity = tuple[int, int, int]


def _gateway_run_path_snapshot(
    value: Path,
) -> tuple[Path, _RunPathIdentity, _RunPathIdentity]:
    pinned = pinned_workspace_relative_path(value, label="Web Gateway audit Run path")
    if pinned is not None:
        path = pinned
    else:
        path = value.absolute()
        if not value.is_absolute() or path != value:
            raise ValueError("Web Gateway audit Run path must be canonical absolute")
    try:
        run_metadata = path.lstat()
        parent_metadata = path.parent.lstat()
    except OSError as error:
        raise ValueError("Web Gateway audit Run path is unavailable") from error
    if not stat.S_ISDIR(run_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("Web Gateway audit Run path or parent is not a directory")
    return (
        path,
        (run_metadata.st_dev, run_metadata.st_ino, run_metadata.st_mode),
        (parent_metadata.st_dev, parent_metadata.st_ino, parent_metadata.st_mode),
    )


_POLICY_METHODS: Mapping[str, object] = {
    name: getattr(PolicyEngine, name)
    for name in ("stable_execution_context", "evaluate_tool_request")
}
_TOOL_REGISTRY_METHODS: Mapping[str, object] = {
    name: getattr(ToolRegistry, name) for name in ("register", "spec", "tool", "tool_ids")
}
_SECRET_BROKER_METHODS: Mapping[str, object] = {
    name: getattr(SecretBroker, name) for name in ("issue", "materialize", "revoke", "fingerprint")
}
_RATE_LEDGER_METHODS: Mapping[str, object] = {
    name: getattr(RequestRateLimitLedger, name) for name in ("reserve_for_dispatch", "release")
}
_WEB_TOOL_METHODS: Mapping[str, object] = {
    name: getattr(WebAuthenticatedAssessmentTool, name)
    for name in (
        "stable_execution_context",
        "validate_request",
        "network_request_cost",
        "network_response_byte_limit",
        "prepare",
        "interpret",
        "validate_trusted_execution",
        "_verified_output",
    )
}
_COMPILER_METHODS: Mapping[str, object] = {
    name: getattr(HostLoopbackWebAssessmentJobCompiler, name)
    for name in ("stable_execution_context", "compile_job")
}
_OUTPUT_VERIFIER_METHODS: Mapping[str, object] = {
    name: getattr(HostLoopbackWebAssessmentOutputVerifier, name)
    for name in ("stable_execution_context", "verify_output")
}
_ADAPTER_REGISTRY_METHODS: Mapping[str, object] = {
    name: getattr(WebAssessmentAdapterRegistry, name)
    for name in ("resolve", "references", "_verify", "_now")
}
_ACCOUNT_REGISTRY_METHODS: Mapping[str, object] = {
    name: getattr(ProvisionedWebAccountReceiptRegistry, name)
    for name in ("resolve", "_verify", "_now")
}
_DISPATCH_REGISTRY_METHODS: Mapping[str, object] = {
    name: getattr(WebAssessmentDispatchBindingRegistry, name)
    for name in ("_exact_runtime", "stable_execution_context", "consume", "consumed", "complete")
}


def web_gateway_system_utc_now() -> datetime:
    """Code-owned live UTC clock required by every production Gateway dependency."""

    return datetime.now(UTC)


def _registry_inventory_digest(registry: object) -> str:
    if type(registry) is WebAssessmentAdapterRegistry:
        payload = {
            "keys": [
                registry._keys[key].model_dump(mode="json", by_alias=True)
                for key in sorted(registry._keys)
            ],
            "materials": [
                registry._adapters[key].model_dump(mode="json", by_alias=True)
                for key in sorted(registry._adapters)
            ],
        }
        domain = "pajin.web-gateway.adapter-registry-inventory/v1"
    elif type(registry) is ProvisionedWebAccountReceiptRegistry:
        payload = {
            "keys": [
                registry._keys[key].model_dump(mode="json", by_alias=True)
                for key in sorted(registry._keys)
            ],
            "materials": [
                registry._receipts[key].model_dump(mode="json", by_alias=True)
                for key in sorted(registry._receipts)
            ],
        }
        domain = "pajin.web-gateway.account-registry-inventory/v1"
    else:
        raise TypeError("Web Gateway registry inventory type is unsupported")
    return canonical_web_worker_sha256({"domain": domain, "inventory": payload})


def _exact_component_profile(
    component: object,
    expected_type: type[object],
    methods: Mapping[str, object],
) -> bool:
    instance_attributes = getattr(component, "__dict__", {})
    return (
        type(component) is expected_type
        and isinstance(instance_attributes, dict)
        and all(name not in instance_attributes for name in methods)
        and all(getattr(type(component), name, None) is method for name, method in methods.items())
    )


def _validated_production_tool(
    *,
    backend: HostLoopbackBrowserWorkerBackend,
    policy: PolicyEngine,
    tools: ToolRegistry,
    secrets: SecretBroker,
    rate_limits: RequestRateLimitLedger,
) -> WebAuthenticatedAssessmentTool:
    if type(backend) is not HostLoopbackBrowserWorkerBackend:
        raise TypeError("Web Gateway requires the exact production Web Worker backend")
    if (
        not _exact_component_profile(policy, PolicyEngine, _POLICY_METHODS)
        or not _exact_component_profile(tools, ToolRegistry, _TOOL_REGISTRY_METHODS)
        or not _exact_component_profile(secrets, SecretBroker, _SECRET_BROKER_METHODS)
        or not _exact_component_profile(
            rate_limits,
            RequestRateLimitLedger,
            _RATE_LEDGER_METHODS,
        )
    ):
        raise TypeError("Web Gateway requires exact production policy and runtime components")
    backend.require_authoritative_completion_profile()
    try:
        raw_tool = tools.tool(WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise ValueError("Web Gateway Tool registry lacks the exact WEB Tool") from exc
    if tools.tool_ids() != {WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID} or not _exact_component_profile(
        raw_tool,
        WebAuthenticatedAssessmentTool,
        _WEB_TOOL_METHODS,
    ):
        raise ValueError("Web Gateway Tool is not bound to the exact production backend")
    tool = cast(WebAuthenticatedAssessmentTool, raw_tool)
    compiler = tool.job_compiler
    output_verifier = tool.output_verifier
    if (
        not _exact_component_profile(
            compiler,
            HostLoopbackWebAssessmentJobCompiler,
            _COMPILER_METHODS,
        )
        or not _exact_component_profile(
            output_verifier,
            HostLoopbackWebAssessmentOutputVerifier,
            _OUTPUT_VERIFIER_METHODS,
        )
        or not _exact_component_profile(
            tool.adapters,
            WebAssessmentAdapterRegistry,
            _ADAPTER_REGISTRY_METHODS,
        )
        or not _exact_component_profile(
            tool.account_receipts,
            ProvisionedWebAccountReceiptRegistry,
            _ACCOUNT_REGISTRY_METHODS,
        )
        or not _exact_component_profile(
            tool.dispatch_bindings,
            WebAssessmentDispatchBindingRegistry,
            _DISPATCH_REGISTRY_METHODS,
        )
        or cast(HostLoopbackWebAssessmentJobCompiler, compiler).backend is not backend
        or cast(HostLoopbackWebAssessmentOutputVerifier, output_verifier).trust_registry.digest
        != backend.trust_registry.digest
    ):
        raise ValueError("Web Gateway Tool is not bound to the exact production backend")
    if (
        tool.adapters._clock is not web_assessment_system_utc_now
        or tool.account_receipts._clock is not web_assessment_system_utc_now
        or secrets._clock is not secret_broker_system_utc_now
    ):
        raise ValueError("Web Gateway requires code-owned system UTC dependency clocks")
    return tool


class WebGatewayCompletionReceipt(StrictModel):
    """Content-addressed receipt for the fully audited pre-receipt Gateway Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-gateway-completion-receipt/v1"] = Field(
        default="pajin.dev/web-gateway-completion-receipt/v1",
        alias="apiVersion",
    )
    kind: Literal["WebGatewayCompletionReceipt"] = "WebGatewayCompletionReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=120)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    role: Literal["source", "validation"]
    authority: WebWorkerAuthorityBinding
    dispatch_binding_digest: str = Field(
        alias="dispatchBindingDigest",
        pattern=_SHA256_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_SAFE_ID_PATTERN)
    worker_execution_id: str = Field(alias="workerExecutionId", pattern=_SAFE_ID_PATTERN)
    gateway_launch_id: str = Field(alias="gatewayLaunchId", pattern=_SAFE_ID_PATTERN)
    gateway_audit_run_id: str = Field(alias="gatewayAuditRunId", pattern=_SAFE_ID_PATTERN)
    gateway_audit_root_digest: str = Field(
        alias="gatewayAuditRootDigest",
        pattern=_SHA256_PATTERN,
    )
    gateway_event_head_digest: str = Field(
        alias="gatewayEventHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    gateway_evidence_reference: str = Field(
        alias="gatewayEvidenceReference",
        pattern=r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$",
    )
    gateway_evidence_digest: str = Field(
        alias="gatewayEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    gateway_request_reservation_reference: str = Field(
        alias="gatewayRequestReservationReference",
        pattern=r"^requests/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$",
    )
    gateway_request_reservation_digest: str = Field(
        alias="gatewayRequestReservationDigest",
        pattern=_SHA256_PATTERN,
    )
    backend_completion_digest: str = Field(
        alias="backendCompletionDigest",
        pattern=_SHA256_PATTERN,
    )
    worker_result_digest: str = Field(alias="workerResultDigest", pattern=_SHA256_PATTERN)
    tool_result_digest: str = Field(alias="toolResultDigest", pattern=_SHA256_PATTERN)
    policy_decision_digest: str = Field(
        alias="policyDecisionDigest",
        pattern=_SHA256_PATTERN,
    )
    gateway_outcome_digest: str = Field(alias="gatewayOutcomeDigest", pattern=_SHA256_PATTERN)
    completed_at: datetime = Field(alias="completedAt")

    @model_validator(mode="after")
    def bind_receipt(self) -> WebGatewayCompletionReceipt:
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("Web Gateway completion time must include a UTC offset")
        if (
            self.request_id != self.authority.request_id
            or self.dispatch_binding_digest != self.authority.dispatch_binding_digest
            or self.gateway_audit_run_id == self.authority.expected_run_id
        ):
            raise ValueError("Web Gateway receipt differs from its signed Worker authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = canonical_web_worker_sha256(
            {
                "domain": "pajin.web-gateway.completion-receipt/v1",
                "receipt": material,
            }
        )
        receipt_id = f"web-gateway-completion_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Web Gateway completion receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Web Gateway completion receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


@final
class WebGatewayCompletedActionAuthority:
    """Non-serializable handle to one exact sealed Gateway and Worker completion."""

    __slots__ = (
        "__authority_digest",
        "__backend_completion",
        "__final_event_head",
        "__final_root_digest",
        "__gateway",
        "__receipt",
        "__receipt_reference",
        "__run_parent_identity",
        "__run_path",
        "__run_path_identity",
        "__token",
    )

    def __init__(
        self,
        *,
        gateway: object,
        token: object,
        receipt: WebGatewayCompletionReceipt,
        receipt_reference: str,
        backend_completion: WebWorkerCompletedActionAuthority,
        final_root_digest: str,
        final_event_head: str,
        run_path: Path,
    ) -> None:
        self.__gateway = gateway
        self.__token = token
        self.__receipt = WebGatewayCompletionReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
        self.__receipt_reference = receipt_reference
        self.__backend_completion = backend_completion
        self.__final_root_digest = final_root_digest
        self.__final_event_head = final_event_head
        (
            self.__run_path,
            self.__run_path_identity,
            self.__run_parent_identity,
        ) = _gateway_run_path_snapshot(run_path)
        self.__authority_digest = canonical_web_worker_sha256(
            {
                "domain": "pajin.web-gateway.completed-action-authority/v1",
                "receiptDigest": receipt.receipt_digest,
                "receiptReference": receipt_reference,
                "backendCompletionDigest": backend_completion.completion_digest,
                "finalRootDigest": final_root_digest,
                "finalEventHead": final_event_head,
            }
        )

    @property
    def receipt(self) -> WebGatewayCompletionReceipt:
        return self.__receipt.model_copy(deep=True)

    @property
    def receipt_reference(self) -> str:
        return self.__receipt_reference

    @property
    def backend_completion(self) -> WebWorkerCompletedActionAuthority:
        return self.__backend_completion

    @property
    def final_root_digest(self) -> str:
        return self.__final_root_digest

    @property
    def final_event_head(self) -> str:
        return self.__final_event_head

    @property
    def authority_digest(self) -> str:
        return self.__authority_digest

    @property
    def run_path(self) -> Path:
        path, run_identity, parent_identity = _gateway_run_path_snapshot(self.__run_path)
        if (
            run_identity != self.__run_path_identity
            or parent_identity != self.__run_parent_identity
        ):
            raise ValueError("Web Gateway audit Run path identity changed")
        return path

    def _registration(self) -> tuple[object, object]:
        return self.__gateway, self.__token


@final
class _ExactGatewayWorkerProxy:
    """WorkerBackend visible only to the ToolGateway owned by this wrapper."""

    name = WEB_WORKER_BACKEND_NAME

    def __init__(self, owner: HostLoopbackWebAssessmentGateway) -> None:
        self.__owner = owner

    def stable_execution_context(self) -> dict[str, object]:
        return self.__owner._worker_stable_execution_context()

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        return await self.__owner._run_worker(job, secrets=secrets)

    def _owned_by(self, owner: object) -> bool:
        return self.__owner is owner


_PROXY_METHODS: Mapping[str, object] = {
    name: getattr(_ExactGatewayWorkerProxy, name)
    for name in ("stable_execution_context", "run", "_owned_by")
}


@final
class HostLoopbackWebAssessmentGateway:
    """One-action WEB Gateway that alone can launch a production host backend."""

    @classmethod
    def production(
        cls,
        *,
        backend: HostLoopbackBrowserWorkerBackend,
        role: Literal["source", "validation"],
        audit_output_root: Path,
        policy: PolicyEngine,
        tools: ToolRegistry,
        secrets: SecretBroker,
        rate_limits: RequestRateLimitLedger,
        audit_run_id: str | None = None,
    ) -> HostLoopbackWebAssessmentGateway:
        if cls is not HostLoopbackWebAssessmentGateway:
            raise TypeError("authoritative Web Gateway factory rejects subclasses")
        _validated_production_tool(
            backend=backend,
            policy=policy,
            tools=tools,
            secrets=secrets,
            rate_limits=rate_limits,
        )
        store = RunStore.create(
            audit_output_root,
            f"web-{role}-gateway",
            run_id=audit_run_id,
        )
        return cls(
            backend=backend,
            role=role,
            policy=policy,
            tools=tools,
            store=store,
            secrets=secrets,
            rate_limits=rate_limits,
            _factory_token=_GATEWAY_FACTORY_TOKEN,
        )

    def __init__(
        self,
        *,
        backend: HostLoopbackBrowserWorkerBackend,
        role: Literal["source", "validation"],
        policy: PolicyEngine,
        tools: ToolRegistry,
        store: RunStore,
        secrets: SecretBroker,
        rate_limits: RequestRateLimitLedger,
        _factory_token: object | None = None,
    ) -> None:
        if _factory_token is not _GATEWAY_FACTORY_TOKEN:
            raise TypeError("Web Gateway must be created by its production factory")
        tool = _validated_production_tool(
            backend=backend,
            policy=policy,
            tools=tools,
            secrets=secrets,
            rate_limits=rate_limits,
        )
        self.role = role
        self.store = store
        self.backend = backend
        self._clock = web_gateway_system_utc_now
        self._completion_lock = Lock()
        self.__completed: WebGatewayCompletedActionAuthority | None = None
        self.__consumed = False
        self.__attempted = False
        self.__active: (
            tuple[
                _WebWorkerGatewayLaunchAuthority,
                WebAssessmentDispatchBinding,
                object,
            ]
            | None
        ) = None
        self._worker = _ExactGatewayWorkerProxy(self)
        self._gateway = ToolGateway(
            policy=policy,
            tools=tools,
            worker=self._worker,
            store=store,
            secrets=secrets,
            rate_limits=rate_limits,
            allow_secret_requests=True,
            clock=self._clock,
        )
        self.__backend_owner_token = backend._bind_production_gateway(
            self,
            _WEB_WORKER_GATEWAY_FACTORY_TOKEN,
            role=role,
        )
        self.__completion_token = object()
        self.__pinned_backend = backend
        self.__pinned_store = store
        (
            self.__pinned_run_path,
            self.__pinned_run_path_identity,
            self.__pinned_run_parent_identity,
        ) = _gateway_run_path_snapshot(store.path)
        self.__pinned_worker = self._worker
        self.__pinned_gateway = self._gateway
        self.__pinned_policy = policy
        self.__pinned_tools = tools
        self.__pinned_secrets = secrets
        self.__pinned_secret_clock = secrets._clock
        self.__pinned_rate_limits = rate_limits
        self.__pinned_tool = tool
        self.__pinned_adapters = tool.adapters
        self.__pinned_adapter_clock = tool.adapters._clock
        self.__pinned_adapter_keys = tool.adapters._keys
        self.__pinned_adapter_materials = tool.adapters._adapters
        self.__pinned_adapter_inventory_digest = _registry_inventory_digest(tool.adapters)
        self.__pinned_account_receipts = tool.account_receipts
        self.__pinned_account_clock = tool.account_receipts._clock
        self.__pinned_account_keys = tool.account_receipts._keys
        self.__pinned_account_materials = tool.account_receipts._receipts
        self.__pinned_account_inventory_digest = _registry_inventory_digest(tool.account_receipts)
        self.__pinned_dispatch_bindings = tool.dispatch_bindings
        self.__pinned_job_compiler = cast(
            HostLoopbackWebAssessmentJobCompiler,
            tool.job_compiler,
        )
        self.__pinned_output_verifier = cast(
            HostLoopbackWebAssessmentOutputVerifier,
            tool.output_verifier,
        )
        self.__pinned_tool_context_digest = canonical_web_worker_sha256(
            tool.stable_execution_context()
        )
        self.__pinned_compiler_context_digest = canonical_web_worker_sha256(
            tool.job_compiler.stable_execution_context()
        )
        self.__pinned_verifier_context_digest = canonical_web_worker_sha256(
            tool.output_verifier.stable_execution_context()
        )
        self.__pinned_role = role
        self.__pinned_completion_lock = self._completion_lock

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "implementationVersion": "pajin.host-loopback-web-gateway/v1",
            "role": self.role,
            "auditRunId": self.store.run_id,
            "auditRunPath": str(self.store.path),
            "oneAction": True,
            "productionAuthorityEligible": self._authoritative_profile(),
            "workerBackend": self.backend.stable_execution_context(),
        }

    async def execute_approved(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        dispatch: WebAssessmentDispatchBinding,
        *,
        used_calls: int = 0,
    ) -> WebGatewayCompletedActionAuthority:
        """Execute and seal exactly one already-approved WEB dispatch."""

        self._require_authoritative_profile()
        canonical_dispatch = WebAssessmentDispatchBinding.model_validate(
            dispatch.model_dump(mode="json", by_alias=True)
        )
        if (
            canonical_dispatch.role != self.role
            or request.request_id != canonical_dispatch.request_id
            or campaign.metadata.name != canonical_dispatch.campaign_id
            or campaign_manifest_digest(campaign) != canonical_dispatch.campaign_digest
            or grant.grant_id != canonical_dispatch.capability_grant_id
            or capability_grant_digest(grant) != canonical_dispatch.capability_grant_digest
        ):
            raise ValueError("Web Gateway inputs differ from approved dispatch authority")
        with self._completion_lock:
            if (
                self.__attempted
                or self.__active is not None
                or self.__completed is not None
                or self.__consumed
            ):
                raise ValueError("Web Gateway action is already running, completed, or consumed")
            self.__attempted = True
            launch = self.backend._reserve_gateway_launch(
                owner=self,
                owner_token=self.__backend_owner_token,
                dispatch=canonical_dispatch,
                gateway_run_id=self.store.run_id,
            )
            active_token = object()
            self.__active = (launch, canonical_dispatch, active_token)
        try:
            outcome = await _EXACT_TOOL_GATEWAY_EXECUTE(
                self._gateway,
                campaign.model_copy(deep=True),
                grant.model_copy(deep=True),
                request.model_copy(deep=True),
                used_calls=used_calls,
            )
        finally:
            try:
                self.backend._clear_gateway_launch(
                    owner=self,
                    owner_token=self.__backend_owner_token,
                    launch=launch,
                    execution_id=canonical_dispatch.worker_execution_id,
                    role=self.role,
                )
            finally:
                with self._completion_lock:
                    if self.__active is not None and self.__active[2] is active_token:
                        self.__active = None
        authority = self._seal_successful_outcome(
            request=request,
            dispatch=canonical_dispatch,
            outcome=outcome,
            launch=launch,
        )
        with self._completion_lock:
            if self.__completed is not None or self.__consumed:
                raise ValueError("Web Gateway completion registry changed")
            self.__completed = authority
        return authority

    async def _run_worker(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None,
    ) -> WorkerResult:
        self._require_authoritative_profile()
        with self._completion_lock:
            active = self.__active
        if active is None:
            raise ValueError("Web Gateway Worker launch is absent")
        launch, dispatch, _active_token = active
        return await self.backend._run_from_production_gateway(
            job,
            secrets=secrets,
            owner=self,
            owner_token=self.__backend_owner_token,
            launch=launch,
            dispatch=dispatch,
            gateway_run_id=self.store.run_id,
        )

    def _worker_stable_execution_context(self) -> dict[str, object]:
        self._require_authoritative_profile()
        return {
            **self.backend.stable_execution_context(),
            "gatewayLaunchRequired": True,
            "gatewayAuditRunId": self.store.run_id,
            "gatewayRole": self.role,
        }

    def _seal_successful_outcome(
        self,
        *,
        request: ToolRequest,
        dispatch: WebAssessmentDispatchBinding,
        outcome: GatewayOutcome,
        launch: _WebWorkerGatewayLaunchAuthority,
    ) -> WebGatewayCompletedActionAuthority:
        self._require_authoritative_profile()
        worker_result = outcome.worker_result
        if (
            not outcome.decision.allowed
            or not outcome.executed
            or not outcome.result_identity_valid
            or not outcome.result.success
            or outcome.result.request_id != request.request_id
            or outcome.result.tool_id != request.tool_id
            or worker_result is None
            or worker_result.status is not WorkerStatus.SUCCEEDED
            or worker_result.backend != WEB_WORKER_BACKEND_NAME
            or worker_result.execution_id != dispatch.worker_execution_id
        ):
            raise ValueError("Web Gateway outcome is not an exact successful execution")
        backend_completion = self.backend.completed_action_authority(
            request_id=dispatch.request_id,
            execution_id=dispatch.worker_execution_id,
            dispatch_binding_digest=dispatch.binding_digest,
        )
        completion = backend_completion.completion
        if (
            completion.authority.capability_grant_consumption_receipt_id
            != dispatch.capability_grant_consumption_receipt_id
            or completion.authority.capability_grant_consumption_receipt_digest
            != dispatch.capability_grant_consumption_receipt_digest
            or completion.authority.approval_receipt_id != dispatch.approval_receipt_id
            or completion.authority.approval_receipt_digest != dispatch.approval_receipt_digest
            or completion.authority.expected_run_id != dispatch.expected_run_id
            or completion.gateway_audit_run_id != self.store.run_id
            or completion.gateway_launch_id != launch.launch_id
        ):
            raise ValueError("Web Gateway backend completion differs from dispatch receipts")
        evidence_reference = f"evidence/{request.request_id}.json"
        reservation_reference = f"requests/{request.request_id}.json"
        if evidence_reference not in outcome.result.evidence:
            raise ValueError("Web Gateway outcome lacks its canonical audit evidence")
        first_seal = self.store.seal()
        first = load_verified_run_artifacts(
            self.store.path,
            requests={
                evidence_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
                reservation_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
            },
            expected_run_id=self.store.run_id,
        )
        if (
            first.verification.root_digest != first_seal.root_digest
            or first.seals[-1].event_head_hash != first_seal.event_head_hash
            or first.seals[-1].seal_id != first_seal.seal_id
        ):
            raise ValueError("Web Gateway pre-receipt seal changed during verification")
        event_types = tuple(event.event_type for event in first.events)
        expected_event_types = (
            "tool.request_reserved",
            "tool.policy_evaluated",
            *("secret.lease.issued",) * 4,
            "worker.dispatched",
            *("secret.lease.revoked",) * 4,
            "worker.completed",
            "tool.completed",
        )
        first_paths = {artifact.path for seal in first.seals for artifact in seal.artifacts}
        if (
            event_types != expected_event_types
            or first.verification.seal_count != 1
            or first.verification.artifact_count != 2
            or first.verification.event_count != 13
            or first_paths != {evidence_reference, reservation_reference}
        ):
            raise ValueError("Web Gateway audit stream is incomplete or not singular")
        evidence_bytes = first.artifact_bytes(evidence_reference)
        reservation_bytes = first.artifact_bytes(reservation_reference)
        completed_at = self._clock()
        if completed_at < worker_result.finished_at:
            raise ValueError("Web Gateway completion time precedes Worker completion")
        receipt = WebGatewayCompletionReceipt(
            role=self.role,
            authority=completion.authority,
            dispatchBindingDigest=dispatch.binding_digest,
            requestId=request.request_id,
            workerExecutionId=dispatch.worker_execution_id,
            gatewayLaunchId=launch.launch_id,
            gatewayAuditRunId=self.store.run_id,
            gatewayAuditRootDigest=first_seal.root_digest,
            gatewayEventHeadDigest=first_seal.event_head_hash,
            gatewayEvidenceReference=evidence_reference,
            gatewayEvidenceDigest=sha256(evidence_bytes).hexdigest(),
            gatewayRequestReservationReference=reservation_reference,
            gatewayRequestReservationDigest=sha256(reservation_bytes).hexdigest(),
            backendCompletionDigest=backend_completion.completion_digest,
            workerResultDigest=canonical_web_worker_sha256(worker_result.model_dump(mode="json")),
            toolResultDigest=canonical_web_worker_sha256(outcome.result.model_dump(mode="json")),
            policyDecisionDigest=canonical_web_worker_sha256(
                outcome.decision.model_dump(mode="json")
            ),
            gatewayOutcomeDigest=canonical_web_worker_sha256(outcome.model_dump(mode="json")),
            completedAt=completed_at,
        )
        receipt_reference = f"gateway-completions/{receipt.receipt_digest}.json"
        self.store.write_json_create_only(
            receipt_reference,
            receipt.model_dump(mode="json", by_alias=True),
        )
        self.store.append_event(
            "web.gateway_completion.recorded",
            {
                "requestId": request.request_id,
                "executionId": dispatch.worker_execution_id,
                "receiptId": receipt.receipt_id,
                "receiptDigest": receipt.receipt_digest,
                "receiptReference": receipt_reference,
                "backendCompletionDigest": backend_completion.completion_digest,
            },
            occurred_at=receipt.completed_at,
        )
        final_seal = self.store.seal()
        final = load_verified_run_artifacts(
            self.store.path,
            requests={
                evidence_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
                reservation_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
                receipt_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
            },
            expected_run_id=self.store.run_id,
        )
        final_paths = {artifact.path for seal in final.seals for artifact in seal.artifacts}
        decoded_receipt = WebGatewayCompletionReceipt.model_validate(
            parse_strict_json_bytes(
                final.artifact_bytes(receipt_reference),
                label="Web Gateway completion receipt",
                max_bytes=_MAX_GATEWAY_ARTIFACT_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        if (
            final.verification.root_digest != final_seal.root_digest
            or final.seals[-1].event_head_hash != final_seal.event_head_hash
            or final.verification.seal_count != 2
            or final.verification.artifact_count != 3
            or final.verification.event_count != 14
            or final.seals[-1].previous_root_digest != first_seal.root_digest
            or final_paths != {evidence_reference, reservation_reference, receipt_reference}
            or tuple(event.event_type for event in final.events)
            != (*expected_event_types, "web.gateway_completion.recorded")
            or final.artifact_bytes(evidence_reference) != evidence_bytes
            or final.artifact_bytes(reservation_reference) != reservation_bytes
            or decoded_receipt != receipt
        ):
            raise ValueError("Web Gateway final completion seal changed during verification")
        return WebGatewayCompletedActionAuthority(
            gateway=self,
            token=self.__completion_token,
            receipt=receipt,
            receipt_reference=receipt_reference,
            backend_completion=backend_completion,
            final_root_digest=final_seal.root_digest,
            final_event_head=final_seal.event_head_hash,
            run_path=self.store.path,
        )

    def _authoritative_profile(self) -> bool:
        try:
            run_path, run_identity, parent_identity = _gateway_run_path_snapshot(self.store.path)
        except ValueError:
            return False
        return (
            type(self) is HostLoopbackWebAssessmentGateway
            and type(self.backend) is HostLoopbackBrowserWorkerBackend
            and self.backend is self.__pinned_backend
            and self.backend._authoritative_completion_profile()
            and self.store is self.__pinned_store
            and run_path == self.__pinned_run_path
            and run_identity == self.__pinned_run_path_identity
            and parent_identity == self.__pinned_run_parent_identity
            and self._worker is self.__pinned_worker
            and self._worker._owned_by(self)
            and _exact_component_profile(
                self._worker,
                _ExactGatewayWorkerProxy,
                _PROXY_METHODS,
            )
            and self._gateway is self.__pinned_gateway
            and type(self._gateway) is ToolGateway
            and "execute" not in vars(self._gateway)
            and type(self._gateway).execute is _EXACT_TOOL_GATEWAY_EXECUTE
            and self._gateway._worker is self._worker
            and self._gateway._store is self.store
            and self._gateway._policy is self.__pinned_policy
            and self._gateway._tools is self.__pinned_tools
            and self._gateway._secrets is self.__pinned_secrets
            and self._gateway._rate_limits is self.__pinned_rate_limits
            and self._gateway._clock is web_gateway_system_utc_now
            and self.__pinned_tools.tool(WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID) is self.__pinned_tool
            and self.role == self.__pinned_role
            and self.__pinned_tool.adapters is self.__pinned_adapters
            and self.__pinned_tool.account_receipts is self.__pinned_account_receipts
            and self.__pinned_tool.dispatch_bindings is self.__pinned_dispatch_bindings
            and self.__pinned_tool.job_compiler is self.__pinned_job_compiler
            and self.__pinned_tool.output_verifier is self.__pinned_output_verifier
            and self.__pinned_job_compiler.backend is self.backend
            and self.__pinned_output_verifier.trust_registry.digest
            == self.backend.trust_registry.digest
            and self.__pinned_adapters._clock is self.__pinned_adapter_clock
            and self.__pinned_adapters._keys is self.__pinned_adapter_keys
            and self.__pinned_adapters._adapters is self.__pinned_adapter_materials
            and self.__pinned_adapters._clock is web_assessment_system_utc_now
            and _registry_inventory_digest(self.__pinned_adapters)
            == self.__pinned_adapter_inventory_digest
            and self.__pinned_account_receipts._clock is self.__pinned_account_clock
            and self.__pinned_account_receipts._keys is self.__pinned_account_keys
            and self.__pinned_account_receipts._receipts is self.__pinned_account_materials
            and self.__pinned_account_receipts._clock is web_assessment_system_utc_now
            and _registry_inventory_digest(self.__pinned_account_receipts)
            == self.__pinned_account_inventory_digest
            and self.__pinned_secrets._clock is self.__pinned_secret_clock
            and self.__pinned_secrets._clock is secret_broker_system_utc_now
            and _exact_component_profile(
                self.__pinned_tool,
                WebAuthenticatedAssessmentTool,
                _WEB_TOOL_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_adapters,
                WebAssessmentAdapterRegistry,
                _ADAPTER_REGISTRY_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_account_receipts,
                ProvisionedWebAccountReceiptRegistry,
                _ACCOUNT_REGISTRY_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_dispatch_bindings,
                WebAssessmentDispatchBindingRegistry,
                _DISPATCH_REGISTRY_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_job_compiler,
                HostLoopbackWebAssessmentJobCompiler,
                _COMPILER_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_output_verifier,
                HostLoopbackWebAssessmentOutputVerifier,
                _OUTPUT_VERIFIER_METHODS,
            )
            and canonical_web_worker_sha256(self.__pinned_tool.stable_execution_context())
            == self.__pinned_tool_context_digest
            and canonical_web_worker_sha256(self.__pinned_job_compiler.stable_execution_context())
            == self.__pinned_compiler_context_digest
            and canonical_web_worker_sha256(
                self.__pinned_output_verifier.stable_execution_context()
            )
            == self.__pinned_verifier_context_digest
            and _exact_component_profile(
                self.__pinned_policy,
                PolicyEngine,
                _POLICY_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_tools,
                ToolRegistry,
                _TOOL_REGISTRY_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_secrets,
                SecretBroker,
                _SECRET_BROKER_METHODS,
            )
            and _exact_component_profile(
                self.__pinned_rate_limits,
                RequestRateLimitLedger,
                _RATE_LEDGER_METHODS,
            )
            and self._completion_lock is self.__pinned_completion_lock
            and all(
                name not in vars(self)
                for name in ("_attempted", "_active", "_completed", "_consumed")
            )
            and all(name not in vars(self) for name in _GATEWAY_METHODS)
            and all(
                getattr(getattr(self, name, None), "__func__", None) is _GATEWAY_METHODS[name]
                for name in _GATEWAY_METHODS
            )
        )

    def _require_authoritative_profile(self) -> None:
        if not self._authoritative_profile():
            raise ValueError("Web Gateway runtime differs from its production profile")

    def _validate_registered_locked(
        self,
        authority: WebGatewayCompletedActionAuthority,
        token: object,
        *,
        role: Literal["source", "validation"],
    ) -> None:
        self._require_authoritative_profile()
        if (
            role != self.role
            or token is not self.__completion_token
            or self.__completed is not authority
            or self.__consumed
        ):
            raise ValueError("Web Gateway completion authority is foreign or consumed")
        self._validate_sealed_authority_locked(authority)

    def _validate_consumed_locked(
        self,
        authority: WebGatewayCompletedActionAuthority,
        token: object,
        *,
        role: Literal["source", "validation"],
    ) -> None:
        self._require_authoritative_profile()
        if (
            role != self.role
            or token is not self.__completion_token
            or self.__completed is not None
            or not self.__consumed
        ):
            raise ValueError("Web Gateway completion authority is not exactly consumed")
        self._validate_sealed_authority_locked(authority)

    def _validate_sealed_authority_locked(
        self,
        authority: WebGatewayCompletedActionAuthority,
    ) -> None:
        self._require_authoritative_profile()
        receipt = authority.receipt
        if authority.run_path != self.store.path:
            raise ValueError("Web Gateway completion authority audit Run path differs")
        snapshot = load_verified_run_artifacts(
            authority.run_path,
            requests={
                receipt.gateway_evidence_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
                receipt.gateway_request_reservation_reference: (_MAX_GATEWAY_ARTIFACT_BYTES),
                authority.receipt_reference: _MAX_GATEWAY_ARTIFACT_BYTES,
            },
            expected_run_id=receipt.gateway_audit_run_id,
        )
        sealed_paths = {artifact.path for seal in snapshot.seals for artifact in seal.artifacts}
        decoded_receipt = WebGatewayCompletionReceipt.model_validate(
            parse_strict_json_bytes(
                snapshot.artifact_bytes(authority.receipt_reference),
                label="Web Gateway completion receipt",
                max_bytes=_MAX_GATEWAY_ARTIFACT_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        if (
            snapshot.verification.root_digest != authority.final_root_digest
            or snapshot.seals[-1].event_head_hash != authority.final_event_head
            or snapshot.verification.seal_count != 2
            or snapshot.verification.artifact_count != 3
            or snapshot.verification.event_count != 14
            or snapshot.seals[0].root_digest != receipt.gateway_audit_root_digest
            or snapshot.seals[0].event_head_hash != receipt.gateway_event_head_digest
            or snapshot.seals[1].previous_root_digest != receipt.gateway_audit_root_digest
            or sealed_paths
            != {
                receipt.gateway_evidence_reference,
                receipt.gateway_request_reservation_reference,
                authority.receipt_reference,
            }
            or decoded_receipt != receipt
            or sha256(snapshot.artifact_bytes(receipt.gateway_evidence_reference)).hexdigest()
            != receipt.gateway_evidence_digest
            or sha256(
                snapshot.artifact_bytes(receipt.gateway_request_reservation_reference)
            ).hexdigest()
            != receipt.gateway_request_reservation_digest
            or authority.backend_completion.completion_digest != receipt.backend_completion_digest
        ):
            raise ValueError("Web Gateway completion authority failed sealed reload")

    def _mark_consumed_locked(
        self,
        authority: WebGatewayCompletedActionAuthority,
        token: object,
    ) -> None:
        if (
            token is not self.__completion_token
            or self.__completed is not authority
            or self.__consumed
        ):
            raise ValueError("Web Gateway completion changed before consumption")
        self.__completed = None
        self.__consumed = True


_GATEWAY_METHODS: Mapping[str, object] = {
    name: getattr(HostLoopbackWebAssessmentGateway, name)
    for name in (
        "stable_execution_context",
        "execute_approved",
        "_run_worker",
        "_worker_stable_execution_context",
        "_seal_successful_outcome",
        "_authoritative_profile",
        "_require_authoritative_profile",
        "_validate_registered_locked",
        "_validate_consumed_locked",
        "_validate_sealed_authority_locked",
        "_mark_consumed_locked",
    )
}


def consume_web_gateway_completed_action_pair(
    *,
    expected_backend: HostLoopbackBrowserWorkerBackend,
    source: WebGatewayCompletedActionAuthority,
    validation: WebGatewayCompletedActionAuthority,
) -> tuple[WebGatewayCompletedActionAuthority, WebGatewayCompletedActionAuthority]:
    """Validate, reload, and consume exact source/validation Gateway handles once."""

    if (
        type(source) is not WebGatewayCompletedActionAuthority
        or type(validation) is not WebGatewayCompletedActionAuthority
        or source is validation
    ):
        raise TypeError("Web Gateway completion requires two opaque authorities")
    source_gateway, source_token = source._registration()
    validation_gateway, validation_token = validation._registration()
    if (
        type(source_gateway) is not HostLoopbackWebAssessmentGateway
        or type(validation_gateway) is not HostLoopbackWebAssessmentGateway
        or source_gateway is validation_gateway
    ):
        raise ValueError("source and validation Gateway authorities are not independent")
    if (
        type(expected_backend) is not HostLoopbackBrowserWorkerBackend
        or source_gateway.backend is not expected_backend
        or validation_gateway.backend is not expected_backend
        or not expected_backend._authoritative_completion_profile()
    ):
        raise ValueError("Web Gateway completions differ from the expected production backend")
    gateways = sorted(
        (source_gateway, validation_gateway),
        key=lambda item: (item.store.run_id, id(item)),
    )
    first, second = gateways
    with first._completion_lock, second._completion_lock:
        source_gateway._validate_registered_locked(
            source,
            source_token,
            role="source",
        )
        validation_gateway._validate_registered_locked(
            validation,
            validation_token,
            role="validation",
        )
        if (
            source.receipt.gateway_audit_run_id == validation.receipt.gateway_audit_run_id
            or source.final_root_digest == validation.final_root_digest
            or source.authority_digest == validation.authority_digest
        ):
            raise ValueError("source and validation Gateway completions must be distinct")
        source_gateway.backend.consume_completed_action_authorities(
            source=source.backend_completion,
            validation=validation.backend_completion,
        )
        source_gateway._mark_consumed_locked(source, source_token)
        validation_gateway._mark_consumed_locked(validation, validation_token)
    return source, validation


def verify_consumed_web_gateway_completed_action_pair(
    *,
    expected_backend: HostLoopbackBrowserWorkerBackend,
    source: WebGatewayCompletedActionAuthority,
    validation: WebGatewayCompletedActionAuthority,
) -> None:
    """Reload both already-consumed Gateway audits without creating new authority."""

    if (
        type(source) is not WebGatewayCompletedActionAuthority
        or type(validation) is not WebGatewayCompletedActionAuthority
        or source is validation
    ):
        raise TypeError("Web Gateway verification requires two opaque authorities")
    source_gateway, source_token = source._registration()
    validation_gateway, validation_token = validation._registration()
    if (
        type(source_gateway) is not HostLoopbackWebAssessmentGateway
        or type(validation_gateway) is not HostLoopbackWebAssessmentGateway
        or source_gateway is validation_gateway
    ):
        raise ValueError("source and validation Gateway authorities are not independent")
    if (
        type(expected_backend) is not HostLoopbackBrowserWorkerBackend
        or source_gateway.backend is not expected_backend
        or validation_gateway.backend is not expected_backend
        or not expected_backend._authoritative_completion_profile()
    ):
        raise ValueError("Web Gateway completions differ from the expected production backend")
    gateways = sorted(
        (source_gateway, validation_gateway),
        key=lambda item: (item.store.run_id, id(item)),
    )
    first, second = gateways
    with first._completion_lock, second._completion_lock:
        source_gateway._validate_consumed_locked(
            source,
            source_token,
            role="source",
        )
        validation_gateway._validate_consumed_locked(
            validation,
            validation_token,
            role="validation",
        )
        if (
            source.receipt.gateway_audit_run_id == validation.receipt.gateway_audit_run_id
            or source.final_root_digest == validation.final_root_digest
            or source.authority_digest == validation.authority_digest
        ):
            raise ValueError("source and validation Gateway completions must remain distinct")
