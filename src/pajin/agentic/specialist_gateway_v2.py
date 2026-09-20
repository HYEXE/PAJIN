"""Deployment-owned, Target-I/O-zero specialist Gateway runtime.

This module seals the exact structured-fake backend, verifier, verification
key, job template, and execution inventory in its private module registry while
exposing only a non-copyable process-local token.  The durable C3C boundary can
therefore derive a pre-attempt WorkerJob identity and perform one irreversible
handoff without accepting caller-authored runtime records.  The public token
intentionally contains no raw backend or verifier handle; only the Store-owned
TCB path can reach the private specialist Worker.
"""

from __future__ import annotations

import asyncio
import threading
import weakref
from _thread import RLock as RLockType
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, Never, Self, SupportsIndex, cast, final

from pydantic import ConfigDict, Field, field_validator, model_validator

import pajin.agentic._specialist_gateway_runtime_owner_v2 as _runtime_owner_module
from pajin.agentic._specialist_gateway_runtime_owner_v2 import (
    _RUNTIME_OWNER_ACCESS_AUTHORITY,
    _SpecialistGatewayRuntimeOwnerV2,
    _SpecialistGatewayRuntimeOwnerV2Error,
)
from pajin.agentic.models import AgenticStrictModel, Identifier, Sha256, _literal_false
from pajin.agentic.specialist_backend_v2 import (
    SignedSpecialistBackendResultV2,
    SpecialistBackendJobTemplateV2,
    SpecialistBackendLaunchEnvelopeV2,
    SpecialistBackendOutputVerifierV2,
    SpecialistBackendV2ContractError,
    SpecialistBackendVerificationKeyV2,
    SpecialistExecutionInventoryV2,
    StructuredFakeSpecialistBackendV2,
    specialist_backend_launch_envelope_v2,
    specialist_backend_public_key_base64url_v2,
    specialist_execution_inventory_v2,
    structured_fake_specialist_job_template_v2,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

SPECIALIST_GATEWAY_DEPLOYMENT_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-gateway-deployment/v1alpha1"
)
SPECIALIST_WORKER_JOB_REF_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-worker-job-ref/v1alpha1"
)

_MAX_DEPLOYMENT_BYTES: Final = 256 * 1024
_MAX_WORKER_JOB_BYTES: Final = 128 * 1024
_DEPLOYMENT_FACTORY_TOKEN: Final = object()
_DEPLOYMENT_CLAIM_AUTHORITY: Final = object()

_BACKEND_CLASS: Final = StructuredFakeSpecialistBackendV2
_BACKEND_INIT_IMPLEMENTATION: Final = StructuredFakeSpecialistBackendV2.__init__
_BACKEND_INVOCATION_COUNT_IMPLEMENTATION: Final[property] = cast(
    property,
    vars(StructuredFakeSpecialistBackendV2)["invocation_count"],
)
_BACKEND_CONTEXT_IMPLEMENTATION: Final = StructuredFakeSpecialistBackendV2.stable_execution_context
_BACKEND_RUN_IMPLEMENTATION: Final = StructuredFakeSpecialistBackendV2.run
_BACKEND_LAUNCH_IMPLEMENTATION: Final = specialist_backend_launch_envelope_v2
_SIGNED_RESULT_DIGEST_PROPERTY: Final[property] = cast(
    property,
    vars(SignedSpecialistBackendResultV2)["result_digest"],
)
_SIGNED_RESULT_DIGEST_IMPLEMENTATION = _SIGNED_RESULT_DIGEST_PROPERTY.fget
_VERIFIER_CLASS: Final = SpecialistBackendOutputVerifierV2
_VERIFIER_INIT_IMPLEMENTATION: Final = SpecialistBackendOutputVerifierV2.__init__
_VERIFIER_CONTEXT_IMPLEMENTATION: Final = SpecialistBackendOutputVerifierV2.stable_execution_context
_VERIFIER_OUTPUT_IMPLEMENTATION: Final = SpecialistBackendOutputVerifierV2.verify_output
_PUBLIC_KEY_IMPLEMENTATION: Final = specialist_backend_public_key_base64url_v2
_INVENTORY_IMPLEMENTATION: Final = specialist_execution_inventory_v2
_TEMPLATE_IMPLEMENTATION: Final = structured_fake_specialist_job_template_v2
_REGISTER_RUNTIME_OWNER_IMPLEMENTATION: Final = (
    _runtime_owner_module._register_specialist_gateway_runtime_owner_v2
)
_RESOLVE_RUNTIME_OWNER_IMPLEMENTATION: Final = (
    _runtime_owner_module._resolve_specialist_gateway_runtime_owner_v2
)
_RETIRE_RUNTIME_OWNER_IMPLEMENTATION: Final = (
    _runtime_owner_module._retire_specialist_gateway_runtime_owner_v2
)


class SpecialistGatewayDeploymentV2Error(RuntimeError):
    """Raised when the live v2 Gateway deployment differs from its pins."""


class SpecialistGatewayDeploymentSnapshotV2(AgenticStrictModel):
    """Serializable identity of one live deployment; never bearer authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-gateway-deployment/v1alpha1"] = Field(
        default=SPECIALIST_GATEWAY_DEPLOYMENT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistGatewayDeployment"] = "AgenticSpecialistGatewayDeployment"
    deployment_id: str = Field(default="", alias="deploymentId", max_length=120)
    deployment_digest: str = Field(default="", alias="deploymentDigest", max_length=64)
    gateway_id: Identifier = Field(alias="gatewayId")
    gateway_version: str = Field(alias="gatewayVersion", min_length=1, max_length=40)
    gateway_digest: Sha256 = Field(alias="gatewayDigest")
    execution_inventory_id: str = Field(
        alias="executionInventoryId",
        pattern=r"^agentic-specialist-execution-inventory_[a-f0-9]{64}$",
    )
    execution_inventory_digest: Sha256 = Field(alias="executionInventoryDigest")
    worker_backend_id: Identifier = Field(alias="workerBackendId")
    worker_backend_version: str = Field(
        alias="workerBackendVersion",
        min_length=1,
        max_length=40,
    )
    worker_backend_digest: Sha256 = Field(alias="workerBackendDigest")
    worker_backend_context_digest: Sha256 = Field(alias="workerBackendContextDigest")
    worker_job_template_id: str = Field(alias="workerJobTemplateId", max_length=120)
    worker_job_template_digest: Sha256 = Field(alias="workerJobTemplateDigest")
    worker_command_digest: Sha256 = Field(alias="workerCommandDigest")
    worker_compiler_id: Identifier = Field(alias="workerCompilerId")
    worker_compiler_version: str = Field(
        alias="workerCompilerVersion",
        min_length=1,
        max_length=40,
    )
    worker_compiler_digest: Sha256 = Field(alias="workerCompilerDigest")
    worker_image_reference: Identifier = Field(alias="workerImageReference")
    worker_image_digest: Sha256 = Field(alias="workerImageDigest")
    worker_verifier_id: Identifier = Field(alias="workerVerifierId")
    worker_verifier_version: str = Field(
        alias="workerVerifierVersion",
        min_length=1,
        max_length=40,
    )
    worker_verifier_digest: Sha256 = Field(alias="workerVerifierDigest")
    worker_verifier_context_digest: Sha256 = Field(alias="workerVerifierContextDigest")
    worker_verification_key_id: Identifier = Field(alias="workerVerificationKeyId")
    worker_verification_key_digest: Sha256 = Field(alias="workerVerificationKeyDigest")
    contract_implementation_digest: Sha256 = Field(alias="contractImplementationDigest")
    network_mode: Literal["none"] = Field(default="none", alias="networkMode")
    target_io_allowed: Literal[False] = Field(default=False, alias="targetIOAllowed")
    production_authority_eligible: Literal[False] = Field(
        default=False,
        alias="productionAuthorityEligible",
    )

    @field_validator("target_io_allowed", "production_authority_eligible", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"deployment_id", "deployment_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-gateway-deployment/v2",
            material,
        )
        expected_id = f"agentic-specialist-gateway-deployment_{digest}"
        if self.deployment_digest and self.deployment_digest != digest:
            raise ValueError("specialist Gateway deployment Digest differs")
        if self.deployment_id and self.deployment_id != expected_id:
            raise ValueError("specialist Gateway deployment ID differs")
        object.__setattr__(self, "deployment_digest", digest)
        object.__setattr__(self, "deployment_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist Gateway deployment snapshot",
            max_bytes=_MAX_DEPLOYMENT_BYTES,
        )
        return self


class SpecialistWorkerJobRefV2(AgenticStrictModel):
    """Unique pre-attempt WorkerJob identity derived only from live C3C inputs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-worker-job-ref/v1alpha1"] = Field(
        default=SPECIALIST_WORKER_JOB_REF_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistWorkerJobRef"] = "AgenticSpecialistWorkerJobRef"
    worker_job_id: str = Field(default="", alias="workerJobId", max_length=120)
    worker_job_digest: str = Field(default="", alias="workerJobDigest", max_length=64)
    gateway_deployment_id: str = Field(alias="gatewayDeploymentId", max_length=120)
    gateway_deployment_digest: Sha256 = Field(alias="gatewayDeploymentDigest")
    execution_inventory_id: str = Field(
        alias="executionInventoryId",
        pattern=r"^agentic-specialist-execution-inventory_[a-f0-9]{64}$",
    )
    execution_inventory_digest: Sha256 = Field(alias="executionInventoryDigest")
    worker_job_template_id: str = Field(alias="workerJobTemplateId", max_length=120)
    worker_job_template_digest: Sha256 = Field(alias="workerJobTemplateDigest")
    plan_id: str = Field(
        alias="planId",
        pattern=r"^agentic-specialist-plan_[a-f0-9]{64}$",
    )
    plan_digest: Sha256 = Field(alias="planDigest")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: Sha256 = Field(alias="requestDigest")
    runtime_capsule_token_digest: Sha256 = Field(alias="runtimeCapsuleTokenDigest")
    dispatch_binding_id: str = Field(
        alias="dispatchBindingId",
        pattern=r"^agentic-specialist-dispatch-binding_[a-f0-9]{64}$",
    )
    dispatch_binding_digest: Sha256 = Field(alias="dispatchBindingDigest")
    target_io_allowed: Literal[False] = Field(default=False, alias="targetIOAllowed")
    caller_executable_input: Literal[False] = Field(
        default=False,
        alias="callerExecutableInput",
    )

    @field_validator("target_io_allowed", "caller_executable_input", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"worker_job_id", "worker_job_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-worker-job-ref/v2",
            material,
        )
        expected_id = f"agentic-specialist-worker-job_{digest}"
        if self.worker_job_digest and self.worker_job_digest != digest:
            raise ValueError("specialist WorkerJob Digest differs")
        if self.worker_job_id and self.worker_job_id != expected_id:
            raise ValueError("specialist WorkerJob ID differs")
        object.__setattr__(self, "worker_job_digest", digest)
        object.__setattr__(self, "worker_job_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist WorkerJob reference",
            max_bytes=_MAX_WORKER_JOB_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class _SpecialistGatewayDeploymentClaimObservationV2:
    """Detached, non-bearer inventory observed under the deployment claim lock."""

    snapshot: SpecialistGatewayDeploymentSnapshotV2
    execution_inventory: SpecialistExecutionInventoryV2


@dataclass(slots=True)
class _SpecialistGatewayDeploymentStateV2:
    snapshot: SpecialistGatewayDeploymentSnapshotV2
    runtime_identity_token: object | None
    state: Literal["open", "claimed", "retired"] = "open"
    store_identity_token: object | None = None
    owner_task: asyncio.Task[object] | None = None
    owner_token: object | None = None
    lease_identity_token: object | None = None
    backend_attempted: bool = False
    active_backend_task: asyncio.Task[object] | None = None


_MINT_LEASE_FACTORY_TOKEN: Final = object()


@final
class _VerifiedSpecialistGatewayDeploymentMintLeaseV2:
    """Non-copyable exact claim over one deployment during JobAttempt minting."""

    __slots__ = (
        "__deployment",
        "__factory_token",
        "__lease_identity_token",
        "__owner_task",
        "__owner_token",
        "__runtime_identity_token",
        "__store_identity_token",
    )
    __deployment: VerifiedSpecialistGatewayDeploymentV2
    __factory_token: object
    __lease_identity_token: object
    __owner_task: asyncio.Task[object]
    __owner_token: object
    __runtime_identity_token: object
    __store_identity_token: object

    def __init__(
        self,
        *,
        deployment: VerifiedSpecialistGatewayDeploymentV2,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
        lease_identity_token: object,
        runtime_identity_token: object,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _MINT_LEASE_FACTORY_TOKEN:
            raise TypeError("specialist Gateway mint lease requires its code-owned factory")
        prefix = "_VerifiedSpecialistGatewayDeploymentMintLeaseV2__"
        object.__setattr__(self, prefix + "deployment", deployment)
        object.__setattr__(self, prefix + "store_identity_token", store_identity_token)
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "owner_token", owner_token)
        object.__setattr__(self, prefix + "lease_identity_token", lease_identity_token)
        object.__setattr__(self, prefix + "runtime_identity_token", runtime_identity_token)
        object.__setattr__(self, prefix + "factory_token", _factory_token)

    def _identity(
        self,
    ) -> tuple[
        VerifiedSpecialistGatewayDeploymentV2,
        object,
        asyncio.Task[object],
        object,
        object,
        object,
    ]:
        if (
            type(self) is not _VerifiedSpecialistGatewayDeploymentMintLeaseV2
            or self.__factory_token is not _MINT_LEASE_FACTORY_TOKEN
        ):
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway mint lease implementation changed"
            )
        return (
            self.__deployment,
            self.__store_identity_token,
            self.__owner_task,
            self.__owner_token,
            self.__lease_identity_token,
            self.__runtime_identity_token,
        )

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist Gateway mint lease is immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist Gateway mint lease is immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist Gateway mint lease cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist Gateway mint lease cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist Gateway mint lease cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist Gateway mint lease cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist Gateway mint lease cannot be serialized")


_MINT_LEASE_IDENTITY_IMPLEMENTATION = _VerifiedSpecialistGatewayDeploymentMintLeaseV2._identity
_MINT_LEASE_INIT_IMPLEMENTATION = _VerifiedSpecialistGatewayDeploymentMintLeaseV2.__init__


_COMPLETION_FACTORY_TOKEN: Final = object()


@final
class _VerifiedSpecialistGatewayCompletionV2:
    """One-shot provenance that only the exact Gateway verifier can mint."""

    __slots__ = (
        "__attempt_digest",
        "__consumed",
        "__deployment",
        "__dispatch_verification_digest",
        "__envelope",
        "__factory_token",
        "__lease",
        "__lock",
        "__owner_task",
        "__owner_token",
        "__result_digest",
        "__signed_result",
        "__store_identity_token",
    )
    __attempt_digest: str
    __consumed: bool
    __deployment: VerifiedSpecialistGatewayDeploymentV2
    __dispatch_verification_digest: str
    __envelope: SpecialistBackendLaunchEnvelopeV2
    __factory_token: object
    __lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2
    __lock: RLockType
    __owner_task: asyncio.Task[object]
    __owner_token: object
    __result_digest: str
    __signed_result: SignedSpecialistBackendResultV2
    __store_identity_token: object

    def __init__(
        self,
        *,
        deployment: VerifiedSpecialistGatewayDeploymentV2,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
        attempt_digest: str,
        dispatch_verification_digest: str,
        envelope: SpecialistBackendLaunchEnvelopeV2,
        signed_result: SignedSpecialistBackendResultV2,
        result_digest: str,
        _factory_token: object,
    ) -> None:
        if (
            _factory_token is not _COMPLETION_FACTORY_TOKEN
            or type(deployment) is not VerifiedSpecialistGatewayDeploymentV2
            or type(lease) is not _VerifiedSpecialistGatewayDeploymentMintLeaseV2
            or type(owner_task) is not asyncio.Task
            or owner_task is not asyncio.current_task()
            or owner_task.done()
            or type(attempt_digest) is not str
            or not attempt_digest
            or type(dispatch_verification_digest) is not str
            or not dispatch_verification_digest
            or type(envelope) is not SpecialistBackendLaunchEnvelopeV2
            or type(signed_result) is not SignedSpecialistBackendResultV2
            or type(result_digest) is not str
            or not result_digest
        ):
            raise TypeError(
                "specialist Gateway completion requires its exact verified factory"
            )
        prefix = "_VerifiedSpecialistGatewayCompletionV2__"
        object.__setattr__(self, prefix + "deployment", deployment)
        object.__setattr__(self, prefix + "lease", lease)
        object.__setattr__(self, prefix + "store_identity_token", store_identity_token)
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "owner_token", owner_token)
        object.__setattr__(self, prefix + "attempt_digest", attempt_digest)
        object.__setattr__(
            self,
            prefix + "dispatch_verification_digest",
            dispatch_verification_digest,
        )
        object.__setattr__(self, prefix + "envelope", envelope)
        object.__setattr__(self, prefix + "signed_result", signed_result)
        object.__setattr__(self, prefix + "result_digest", result_digest)
        object.__setattr__(self, prefix + "factory_token", _factory_token)
        object.__setattr__(self, prefix + "lock", threading.RLock())
        object.__setattr__(self, prefix + "consumed", False)

    def _consume_for_terminal_receipt(
        self,
        *,
        claim_authority: object,
        deployment: VerifiedSpecialistGatewayDeploymentV2,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
        attempt_digest: str,
        dispatch_verification_digest: str,
    ) -> tuple[SpecialistBackendLaunchEnvelopeV2, SignedSpecialistBackendResultV2, str]:
        """Spend verified provenance in its exact Store Task exactly once."""

        with self.__lock:
            digest_getter = _SIGNED_RESULT_DIGEST_IMPLEMENTATION
            if (
                type(self) is not _VerifiedSpecialistGatewayCompletionV2
                or self.__factory_token is not _COMPLETION_FACTORY_TOKEN
                or claim_authority is not _DEPLOYMENT_CLAIM_AUTHORITY
                or self.__consumed
                or self.__deployment is not deployment
                or self.__lease is not lease
                or self.__store_identity_token is not store_identity_token
                or self.__owner_task is not owner_task
                or owner_task is not asyncio.current_task()
                or owner_task.done()
                or self.__owner_token is not owner_token
                or self.__attempt_digest != attempt_digest
                or self.__dispatch_verification_digest
                != dispatch_verification_digest
                or type(self.__envelope) is not SpecialistBackendLaunchEnvelopeV2
                or type(self.__signed_result) is not SignedSpecialistBackendResultV2
                or self.__envelope.attempt_digest != attempt_digest
                or self.__envelope.dispatch_verification_digest
                != dispatch_verification_digest
                or self.__signed_result.statement.attempt_digest != attempt_digest
                or self.__signed_result.statement.dispatch_verification_digest
                != dispatch_verification_digest
                or self.__signed_result.statement.launch_envelope_id
                != self.__envelope.envelope_id
                or self.__signed_result.statement.launch_envelope_digest
                != self.__envelope.envelope_digest
                or digest_getter is None
                or digest_getter(self.__signed_result) != self.__result_digest
            ):
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway completion is foreign, consumed, or changed"
                )
            envelope = self.__envelope
            signed_result = self.__signed_result
            object.__setattr__(self, "_VerifiedSpecialistGatewayCompletionV2__consumed", True)
            return envelope, signed_result, self.__result_digest

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist Gateway completion is immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist Gateway completion is immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist Gateway completion cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist Gateway completion cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist Gateway completion cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist Gateway completion cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist Gateway completion cannot be serialized")


_VERIFIED_COMPLETION_INIT_IMPLEMENTATION = _VerifiedSpecialistGatewayCompletionV2.__init__
_VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION = (
    _VerifiedSpecialistGatewayCompletionV2._consume_for_terminal_receipt
)


def _context_digest(domain: str, value: Mapping[str, object]) -> str:
    if type(value) is not dict:
        value = dict(value)
    return discovery_digest(domain, cast(dict[str, object], value))


def _snapshot_for_runtime(
    *,
    verification_key: SpecialistBackendVerificationKeyV2,
    job_template: SpecialistBackendJobTemplateV2,
    execution_inventory: SpecialistExecutionInventoryV2,
    backend: StructuredFakeSpecialistBackendV2,
    verifier: SpecialistBackendOutputVerifierV2,
) -> SpecialistGatewayDeploymentSnapshotV2:
    backend_context = _BACKEND_CONTEXT_IMPLEMENTATION(backend)
    verifier_context = _VERIFIER_CONTEXT_IMPLEMENTATION(verifier)
    return SpecialistGatewayDeploymentSnapshotV2(
        gatewayId=execution_inventory.gateway_id,
        gatewayVersion=execution_inventory.gateway_version,
        gatewayDigest=execution_inventory.gateway_digest,
        executionInventoryId=execution_inventory.inventory_id,
        executionInventoryDigest=execution_inventory.inventory_digest,
        workerBackendId=execution_inventory.worker_backend_id,
        workerBackendVersion=execution_inventory.worker_backend_version,
        workerBackendDigest=execution_inventory.worker_backend_digest,
        workerBackendContextDigest=_CONTEXT_DIGEST_IMPLEMENTATION(
            "pajin.agentic.specialist-worker-backend-runtime-context/v2",
            backend_context,
        ),
        workerJobTemplateId=job_template.template_id,
        workerJobTemplateDigest=job_template.template_digest,
        workerCommandDigest=job_template.worker_command_digest,
        workerCompilerId=execution_inventory.worker_compiler_id,
        workerCompilerVersion=execution_inventory.worker_compiler_version,
        workerCompilerDigest=execution_inventory.worker_compiler_digest,
        workerImageReference=job_template.worker_image_reference,
        workerImageDigest=job_template.worker_image_digest,
        workerVerifierId=execution_inventory.worker_verifier_id,
        workerVerifierVersion=execution_inventory.worker_verifier_version,
        workerVerifierDigest=execution_inventory.worker_verifier_digest,
        workerVerifierContextDigest=_CONTEXT_DIGEST_IMPLEMENTATION(
            "pajin.agentic.specialist-worker-verifier-runtime-context/v2",
            verifier_context,
        ),
        workerVerificationKeyId=verification_key.key_id,
        workerVerificationKeyDigest=verification_key.key_digest,
        contractImplementationDigest=execution_inventory.contract_implementation_digest,
    )


_CONTEXT_DIGEST_IMPLEMENTATION = _context_digest
_SNAPSHOT_FOR_RUNTIME_IMPLEMENTATION = _snapshot_for_runtime


@final
class VerifiedSpecialistGatewayDeploymentV2:
    """Exact process-local mint token; it is not backend execution authority."""

    __slots__ = (
        "__factory_token",
        "__identity_token",
        "__snapshot",
        "__weakref__",
    )
    __factory_token: object
    __identity_token: object
    __snapshot: SpecialistGatewayDeploymentSnapshotV2

    def __init__(
        self,
        *,
        snapshot: SpecialistGatewayDeploymentSnapshotV2,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _DEPLOYMENT_FACTORY_TOKEN:
            raise TypeError("specialist Gateway deployment requires its code-owned factory")
        prefix = "_VerifiedSpecialistGatewayDeploymentV2__"
        object.__setattr__(self, prefix + "snapshot", snapshot)
        object.__setattr__(self, prefix + "factory_token", _factory_token)
        object.__setattr__(self, prefix + "identity_token", object())

    @property
    def snapshot(self) -> SpecialistGatewayDeploymentSnapshotV2:
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(self, state)
            return SpecialistGatewayDeploymentSnapshotV2.model_validate(
                state.snapshot.model_dump(mode="json", by_alias=True)
            )

    @property
    def invocation_count(self) -> int:
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            runtime = _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(self, state)
            getter = _BACKEND_INVOCATION_COUNT_IMPLEMENTATION.fget
            if getter is None:
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway backend invocation counter changed"
                )
            count = getter(runtime.backend)
            if type(count) is not int:
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway backend invocation counter is invalid"
                )
            return count

    @contextmanager
    def _claim_job_attempt_scope(
        self,
        *,
        claim_authority: object,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> Iterator[_VerifiedSpecialistGatewayDeploymentMintLeaseV2]:
        if (
            claim_authority is not _DEPLOYMENT_CLAIM_AUTHORITY
            or type(owner_task) is not asyncio.Task
            or owner_task is not asyncio.current_task()
            or owner_task.done()
        ):
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway deployment claim lacks its scheduler authority"
            )
        lease_identity_token = object()
        runtime_identity_token: object | None = None
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2 | None = None
        transitioned = False
        try:
            with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
                state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
                runtime = _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(self, state)
                if state.state != "open":
                    raise SpecialistGatewayDeploymentV2Error(
                        "specialist Gateway deployment is already claimed or retired"
                    )
                runtime_identity_token = runtime.identity_token
                lease = object.__new__(_VerifiedSpecialistGatewayDeploymentMintLeaseV2)
                _MINT_LEASE_INIT_IMPLEMENTATION(
                    lease,
                    deployment=self,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    lease_identity_token=lease_identity_token,
                    runtime_identity_token=runtime_identity_token,
                    _factory_token=_MINT_LEASE_FACTORY_TOKEN,
                )
                state.state = "claimed"
                state.store_identity_token = store_identity_token
                state.owner_task = owner_task
                state.owner_token = owner_token
                state.lease_identity_token = lease_identity_token
                transitioned = True
            assert lease is not None
            yield lease
        except BaseException:
            if transitioned and runtime_identity_token is not None:
                with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
                    state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
                    try:
                        _FORCE_RETIRE_CLAIM_STATE_LOCKED_IMPLEMENTATION(state)
                    finally:
                        _RETIRE_RUNTIME_OWNER_IMPLEMENTATION(
                            self,
                            access_authority=_RUNTIME_OWNER_ACCESS_AUTHORITY,
                            identity_token=runtime_identity_token,
                        )
            raise

    def _claim_observation(
        self,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        *,
        claim_authority: object,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> _SpecialistGatewayDeploymentClaimObservationV2:
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            runtime = _REQUIRE_CLAIM_LOCKED_IMPLEMENTATION(
                self,
                lease,
                claim_authority=claim_authority,
                store_identity_token=store_identity_token,
                owner_task=owner_task,
                owner_token=owner_token,
                require_current_task=True,
            )
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            return _SpecialistGatewayDeploymentClaimObservationV2(
                snapshot=SpecialistGatewayDeploymentSnapshotV2.model_validate(
                    state.snapshot.model_dump(mode="json", by_alias=True)
                ),
                execution_inventory=SpecialistExecutionInventoryV2.model_validate(
                    runtime.execution_inventory.model_dump(mode="json", by_alias=True)
                ),
            )

    def _worker_job_ref_from_claim(
        self,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        *,
        claim_authority: object,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
        plan_id: str,
        plan_digest: str,
        request_id: str,
        request_digest: str,
        runtime_capsule_token_digest: str,
        dispatch_binding_id: str,
        dispatch_binding_digest: str,
    ) -> SpecialistWorkerJobRefV2:
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            runtime = _REQUIRE_CLAIM_LOCKED_IMPLEMENTATION(
                self,
                lease,
                claim_authority=claim_authority,
                store_identity_token=store_identity_token,
                owner_task=owner_task,
                owner_token=owner_token,
                require_current_task=True,
            )
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            return SpecialistWorkerJobRefV2(
                gatewayDeploymentId=state.snapshot.deployment_id,
                gatewayDeploymentDigest=state.snapshot.deployment_digest,
                executionInventoryId=runtime.execution_inventory.inventory_id,
                executionInventoryDigest=runtime.execution_inventory.inventory_digest,
                workerJobTemplateId=runtime.job_template.template_id,
                workerJobTemplateDigest=runtime.job_template.template_digest,
                planId=plan_id,
                planDigest=plan_digest,
                requestId=request_id,
                requestDigest=request_digest,
                runtimeCapsuleTokenDigest=runtime_capsule_token_digest,
                dispatchBindingId=dispatch_binding_id,
                dispatchBindingDigest=dispatch_binding_digest,
            )

    async def _execute_job_attempt_claim(
        self,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        *,
        claim_authority: object,
        store_identity_token: object,
        owner_task: asyncio.Task[object],
        owner_token: object,
        attempt_digest: str,
        dispatch_verification_digest: str,
        backend_handoff_deadline: datetime,
    ) -> _VerifiedSpecialistGatewayCompletionV2:
        """Invoke and verify the private zero-I/O Worker exactly once.

        The durable Store commits its dispatch marker before calling this
        method.  No registry lock is held across the backend await, and both a
        successful return and every exceptional exit permanently spend the
        deployment.
        """

        if (
            claim_authority is not _DEPLOYMENT_CLAIM_AUTHORITY
            or type(owner_task) is not asyncio.Task
            or owner_task is not asyncio.current_task()
            or owner_task.done()
        ):
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway execution lacks its scheduler authority"
            )
        backend: StructuredFakeSpecialistBackendV2
        verifier: SpecialistBackendOutputVerifierV2
        envelope: SpecialistBackendLaunchEnvelopeV2
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            runtime = _REQUIRE_CLAIM_LOCKED_IMPLEMENTATION(
                self,
                lease,
                claim_authority=claim_authority,
                store_identity_token=store_identity_token,
                owner_task=owner_task,
                owner_token=owner_token,
                require_current_task=True,
                expected_invocation_count=0,
            )
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            if state.backend_attempted or state.active_backend_task is not None:
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway backend handoff was already attempted"
                )
            try:
                envelope = _BACKEND_LAUNCH_IMPLEMENTATION(
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                    job_template=runtime.job_template,
                    runtime_inventory=runtime.execution_inventory,
                    backend_handoff_deadline=backend_handoff_deadline,
                )
            except (TypeError, ValueError) as exc:
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway launch-envelope construction failed closed"
                ) from exc
            if (
                type(envelope) is not SpecialistBackendLaunchEnvelopeV2
                or envelope.attempt_digest != attempt_digest
                or envelope.dispatch_verification_digest != dispatch_verification_digest
                or envelope.backend_handoff_deadline != backend_handoff_deadline
            ):
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway launch envelope differs from the durable marker"
                )
            backend = runtime.backend
            verifier = runtime.verifier
            state.backend_attempted = True
            state.active_backend_task = owner_task

        failure: BaseException | None = None
        try:
            signed_result = await _BACKEND_RUN_IMPLEMENTATION(backend, envelope)
            with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
                current = _REQUIRE_CLAIM_LOCKED_IMPLEMENTATION(
                    self,
                    lease,
                    claim_authority=claim_authority,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    require_current_task=True,
                    expected_invocation_count=1,
                )
                state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
                if (
                    state.active_backend_task is not owner_task
                    or current.backend is not backend
                    or current.verifier is not verifier
                ):
                    raise SpecialistGatewayDeploymentV2Error(
                        "specialist Gateway runtime changed during backend handoff"
                    )
                verified = _VERIFIER_OUTPUT_IMPLEMENTATION(
                    verifier,
                    expected_envelope=envelope,
                    signed_result=signed_result,
                )
                if (
                    type(verified) is not SignedSpecialistBackendResultV2
                    or verified != signed_result
                    or verified.statement.attempt_digest != attempt_digest
                    or verified.statement.dispatch_verification_digest
                    != dispatch_verification_digest
                    or verified.statement.target_io_performed is not False
                    or verified.statement.backend_terminal_proven is not True
                ):
                    raise SpecialistGatewayDeploymentV2Error(
                        "specialist Gateway verified result differs from its handoff"
                    )
                digest_getter = _SIGNED_RESULT_DIGEST_IMPLEMENTATION
                if digest_getter is None:
                    raise SpecialistGatewayDeploymentV2Error(
                        "specialist Gateway result Digest implementation is absent"
                    )
                return _VerifiedSpecialistGatewayCompletionV2(
                    deployment=self,
                    lease=lease,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                    envelope=envelope,
                    signed_result=verified,
                    result_digest=digest_getter(verified),
                    _factory_token=_COMPLETION_FACTORY_TOKEN,
                )
        except asyncio.CancelledError as exc:
            failure = exc
            raise
        except SpecialistGatewayDeploymentV2Error as exc:
            failure = exc
            raise
        except (SpecialistBackendV2ContractError, TypeError, ValueError) as exc:
            failure = exc
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway backend execution failed closed"
            ) from exc
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
                    state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
                    if state.active_backend_task is not owner_task:
                        raise SpecialistGatewayDeploymentV2Error(
                            "specialist Gateway active backend Task changed"
                        )
                    state.active_backend_task = None
            except BaseException as cleanup_exc:
                if failure is None:
                    raise
                failure.add_note(
                    "specialist Gateway active-task cleanup also failed: "
                    f"{type(cleanup_exc).__name__}"
                )

    def _retire_job_attempt_claim(
        self,
        lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        *,
        claim_authority: object,
        store_identity_token: object,
        owner_token: object,
    ) -> None:
        if (
            claim_authority is not _DEPLOYMENT_CLAIM_AUTHORITY
            or type(self) is not VerifiedSpecialistGatewayDeploymentV2
            or type(lease) is not _VerifiedSpecialistGatewayDeploymentMintLeaseV2
        ):
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway deployment retirement lacks TCB authority"
            )
        with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
            state = _DEPLOYMENT_STATE_IMPLEMENTATION(self)
            runtime_identity_token = state.runtime_identity_token
            failure: BaseException | None = None
            try:
                (
                    _deployment,
                    lease_store,
                    _task,
                    lease_owner,
                    lease_identity,
                    lease_runtime_identity,
                ) = _MINT_LEASE_IDENTITY_IMPLEMENTATION(lease)
                if (
                    _deployment is not self
                    or lease_store is not store_identity_token
                    or lease_owner is not owner_token
                    or state.state != "claimed"
                    or state.store_identity_token is not store_identity_token
                    or state.owner_task is not _task
                    or state.owner_token is not owner_token
                    or state.lease_identity_token is not lease_identity
                    or runtime_identity_token is not lease_runtime_identity
                ):
                    raise SpecialistGatewayDeploymentV2Error(
                        "specialist Gateway deployment retirement authority changed"
                    )
                _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(
                    self,
                    state,
                    expected_invocation_count=None,
                )
            except BaseException as exc:
                failure = exc
            finally:
                try:
                    _FORCE_RETIRE_CLAIM_STATE_LOCKED_IMPLEMENTATION(state)
                finally:
                    try:
                        _RETIRE_RUNTIME_OWNER_IMPLEMENTATION(
                            self,
                            access_authority=_RUNTIME_OWNER_ACCESS_AUTHORITY,
                            identity_token=runtime_identity_token,
                        )
                    except BaseException as exc:
                        if failure is None:
                            failure = exc
            if failure is not None:
                if isinstance(failure, SpecialistGatewayDeploymentV2Error):
                    raise failure
                raise SpecialistGatewayDeploymentV2Error(
                    "specialist Gateway deployment retirement failed closed"
                ) from failure

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist Gateway deployment is immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist Gateway deployment is immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist Gateway deployment cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist Gateway deployment cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist Gateway deployment cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist Gateway deployment cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist Gateway deployment cannot be serialized")


_DEPLOYMENT_REGISTRY_LOCK: Final = threading.RLock()
_DEPLOYMENT_REGISTRY: weakref.WeakKeyDictionary[
    VerifiedSpecialistGatewayDeploymentV2,
    _SpecialistGatewayDeploymentStateV2,
] = weakref.WeakKeyDictionary()
_DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION = _DEPLOYMENT_REGISTRY_LOCK
_DEPLOYMENT_REGISTRY_IMPLEMENTATION = _DEPLOYMENT_REGISTRY


def _deployment_state(
    deployment: VerifiedSpecialistGatewayDeploymentV2,
) -> _SpecialistGatewayDeploymentStateV2:
    if (
        _DEPLOYMENT_REGISTRY_LOCK is not _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION
        or type(_DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION) is not RLockType
        or _DEPLOYMENT_REGISTRY is not _DEPLOYMENT_REGISTRY_IMPLEMENTATION
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment registry lock changed"
        )
    try:
        state = _DEPLOYMENT_REGISTRY_IMPLEMENTATION[deployment]
    except (KeyError, TypeError) as exc:
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment is not factory registered"
        ) from exc
    if type(state) is not _SpecialistGatewayDeploymentStateV2:
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment registry state changed"
        )
    return state


def _force_retire_claim_state_locked(
    state: _SpecialistGatewayDeploymentStateV2,
) -> None:
    state.state = "retired"
    state.runtime_identity_token = None
    state.store_identity_token = None
    state.owner_task = None
    state.owner_token = None
    state.lease_identity_token = None
    state.active_backend_task = None


def _require_exact_runtime_locked(
    deployment: VerifiedSpecialistGatewayDeploymentV2,
    state: _SpecialistGatewayDeploymentStateV2,
    *,
    expected_invocation_count: Literal[0, 1] | None = 0,
) -> _SpecialistGatewayRuntimeOwnerV2:
    prefix = "_VerifiedSpecialistGatewayDeploymentV2__"
    try:
        runtime = _RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
            deployment,
            access_authority=_RUNTIME_OWNER_ACCESS_AUTHORITY,
            identity_token=state.runtime_identity_token,
        )
    except _SpecialistGatewayRuntimeOwnerV2Error as exc:
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway private runtime owner changed"
        ) from exc
    if (
        type(deployment) is not VerifiedSpecialistGatewayDeploymentV2
        or type(runtime) is not _SpecialistGatewayRuntimeOwnerV2
        or getattr(deployment, prefix + "factory_token") is not _DEPLOYMENT_FACTORY_TOKEN
        or getattr(deployment, prefix + "identity_token") is not runtime.identity_token
        or getattr(deployment, prefix + "snapshot") is not state.snapshot
        or state.runtime_identity_token is not runtime.identity_token
        or type(runtime.backend) is not _BACKEND_CLASS
        or type(runtime.verifier) is not _VERIFIER_CLASS
        or type(runtime.verification_key) is not SpecialistBackendVerificationKeyV2
        or type(runtime.job_template) is not SpecialistBackendJobTemplateV2
        or type(runtime.execution_inventory) is not SpecialistExecutionInventoryV2
        or type(state.snapshot) is not SpecialistGatewayDeploymentSnapshotV2
        or type(state.backend_attempted) is not bool
        or (
            state.active_backend_task is not None
            and type(state.active_backend_task) is not asyncio.Task
        )
        or StructuredFakeSpecialistBackendV2.__init__ is not _BACKEND_INIT_IMPLEMENTATION
        or vars(StructuredFakeSpecialistBackendV2).get("invocation_count")
        is not _BACKEND_INVOCATION_COUNT_IMPLEMENTATION
        or StructuredFakeSpecialistBackendV2.stable_execution_context
        is not _BACKEND_CONTEXT_IMPLEMENTATION
        or StructuredFakeSpecialistBackendV2.run is not _BACKEND_RUN_IMPLEMENTATION
        or specialist_backend_launch_envelope_v2 is not _BACKEND_LAUNCH_IMPLEMENTATION
        or vars(SignedSpecialistBackendResultV2).get("result_digest")
        is not _SIGNED_RESULT_DIGEST_PROPERTY
        or SpecialistBackendOutputVerifierV2.__init__ is not _VERIFIER_INIT_IMPLEMENTATION
        or SpecialistBackendOutputVerifierV2.stable_execution_context
        is not _VERIFIER_CONTEXT_IMPLEMENTATION
        or SpecialistBackendOutputVerifierV2.verify_output is not _VERIFIER_OUTPUT_IMPLEMENTATION
        or specialist_backend_public_key_base64url_v2 is not _PUBLIC_KEY_IMPLEMENTATION
        or specialist_execution_inventory_v2 is not _INVENTORY_IMPLEMENTATION
        or structured_fake_specialist_job_template_v2 is not _TEMPLATE_IMPLEMENTATION
        or _runtime_owner_module._register_specialist_gateway_runtime_owner_v2
        is not _REGISTER_RUNTIME_OWNER_IMPLEMENTATION
        or _runtime_owner_module._resolve_specialist_gateway_runtime_owner_v2
        is not _RESOLVE_RUNTIME_OWNER_IMPLEMENTATION
        or _runtime_owner_module._retire_specialist_gateway_runtime_owner_v2
        is not _RETIRE_RUNTIME_OWNER_IMPLEMENTATION
        or _context_digest is not _CONTEXT_DIGEST_IMPLEMENTATION
        or _snapshot_for_runtime is not _SNAPSHOT_FOR_RUNTIME_IMPLEMENTATION
        or _deployment_state is not _DEPLOYMENT_STATE_IMPLEMENTATION
        or _require_exact_runtime_locked is not _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION
        or _require_claim_locked is not _REQUIRE_CLAIM_LOCKED_IMPLEMENTATION
        or _force_retire_claim_state_locked is not _FORCE_RETIRE_CLAIM_STATE_LOCKED_IMPLEMENTATION
        or _VerifiedSpecialistGatewayDeploymentMintLeaseV2.__init__
        is not _MINT_LEASE_INIT_IMPLEMENTATION
        or _VerifiedSpecialistGatewayDeploymentMintLeaseV2._identity
        is not _MINT_LEASE_IDENTITY_IMPLEMENTATION
        or _VerifiedSpecialistGatewayCompletionV2.__init__
        is not _VERIFIED_COMPLETION_INIT_IMPLEMENTATION
        or _VerifiedSpecialistGatewayCompletionV2._consume_for_terminal_receipt
        is not _VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._claim_job_attempt_scope
        is not _VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._claim_observation
        is not _VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._worker_job_ref_from_claim
        is not _VERIFIED_DEPLOYMENT_WORKER_JOB_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._retire_job_attempt_claim
        is not _VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._execute_job_attempt_claim
        is not _VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION
        or vars(VerifiedSpecialistGatewayDeploymentV2).get("snapshot")
        is not _VERIFIED_DEPLOYMENT_SNAPSHOT_PROPERTY
        or vars(VerifiedSpecialistGatewayDeploymentV2).get("invocation_count")
        is not _VERIFIED_DEPLOYMENT_INVOCATION_COUNT_PROPERTY
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment implementation or exact runtime changed"
        )
    invocation_getter = _BACKEND_INVOCATION_COUNT_IMPLEMENTATION.fget
    if (
        expected_invocation_count not in (None, 0, 1)
        or isinstance(expected_invocation_count, bool)
        or invocation_getter is None
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment invocation expectation is invalid"
        )
    invocation_count = invocation_getter(runtime.backend)
    if (
        type(invocation_count) is not int
        or (
            expected_invocation_count is not None
            and invocation_count != expected_invocation_count
        )
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment backend invocation state changed"
        )
    expected_template = _TEMPLATE_IMPLEMENTATION()
    expected_inventory = _INVENTORY_IMPLEMENTATION(
        job_template=runtime.job_template,
        verification_key=runtime.verification_key,
    )
    expected_snapshot = _SNAPSHOT_FOR_RUNTIME_IMPLEMENTATION(
        verification_key=runtime.verification_key,
        job_template=runtime.job_template,
        execution_inventory=runtime.execution_inventory,
        backend=runtime.backend,
        verifier=runtime.verifier,
    )
    if (
        runtime.job_template != expected_template
        or runtime.execution_inventory != expected_inventory
        or state.snapshot != expected_snapshot
    ):
        raise SpecialistGatewayDeploymentV2Error("specialist Gateway deployment identity changed")
    return runtime


def _require_claim_locked(
    deployment: VerifiedSpecialistGatewayDeploymentV2,
    lease: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
    *,
    claim_authority: object,
    store_identity_token: object,
    owner_task: asyncio.Task[object],
    owner_token: object,
    require_current_task: bool,
    expected_invocation_count: Literal[0, 1] | None = 0,
) -> _SpecialistGatewayRuntimeOwnerV2:
    (
        lease_deployment,
        lease_store,
        lease_task,
        lease_owner,
        lease_identity,
        lease_runtime_identity,
    ) = _MINT_LEASE_IDENTITY_IMPLEMENTATION(lease)
    state = _DEPLOYMENT_STATE_IMPLEMENTATION(deployment)
    runtime = _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(
        deployment,
        state,
        expected_invocation_count=expected_invocation_count,
    )
    if (
        claim_authority is not _DEPLOYMENT_CLAIM_AUTHORITY
        or type(require_current_task) is not bool
        or lease_deployment is not deployment
        or lease_store is not store_identity_token
        or lease_task is not owner_task
        or lease_owner is not owner_token
        or state.state != "claimed"
        or state.store_identity_token is not store_identity_token
        or state.owner_task is not owner_task
        or state.owner_token is not owner_token
        or state.lease_identity_token is not lease_identity
        or runtime.identity_token is not lease_runtime_identity
        or owner_task.done()
        or (require_current_task and owner_task is not asyncio.current_task())
        or (
            expected_invocation_count == 0
            and state.backend_attempted
        )
        or (
            expected_invocation_count == 1
            and not state.backend_attempted
        )
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment claim is foreign or retired"
        )
    return runtime


_DEPLOYMENT_STATE_IMPLEMENTATION = _deployment_state
_FORCE_RETIRE_CLAIM_STATE_LOCKED_IMPLEMENTATION = _force_retire_claim_state_locked
_REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION = _require_exact_runtime_locked
_REQUIRE_CLAIM_LOCKED_IMPLEMENTATION = _require_claim_locked
_VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION = (
    VerifiedSpecialistGatewayDeploymentV2._claim_job_attempt_scope
)
_VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION = (
    VerifiedSpecialistGatewayDeploymentV2._claim_observation
)
_VERIFIED_DEPLOYMENT_WORKER_JOB_IMPLEMENTATION = (
    VerifiedSpecialistGatewayDeploymentV2._worker_job_ref_from_claim
)
_VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION = (
    VerifiedSpecialistGatewayDeploymentV2._retire_job_attempt_claim
)
_VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION = (
    VerifiedSpecialistGatewayDeploymentV2._execute_job_attempt_claim
)
_VERIFIED_DEPLOYMENT_SNAPSHOT_PROPERTY = cast(
    property,
    vars(VerifiedSpecialistGatewayDeploymentV2)["snapshot"],
)
_VERIFIED_DEPLOYMENT_INVOCATION_COUNT_PROPERTY = cast(
    property,
    vars(VerifiedSpecialistGatewayDeploymentV2)["invocation_count"],
)


def structured_fake_specialist_gateway_deployment_v2(
    *,
    signing_private_key: bytes,
    verification_key_id: str,
    trust_domain: str,
    issuer: str,
) -> VerifiedSpecialistGatewayDeploymentV2:
    """Create one exact one-call fake deployment without dispatching it."""

    if (
        specialist_backend_public_key_base64url_v2 is not _PUBLIC_KEY_IMPLEMENTATION
        or specialist_execution_inventory_v2 is not _INVENTORY_IMPLEMENTATION
        or structured_fake_specialist_job_template_v2 is not _TEMPLATE_IMPLEMENTATION
        or StructuredFakeSpecialistBackendV2.__init__ is not _BACKEND_INIT_IMPLEMENTATION
        or SpecialistBackendOutputVerifierV2.__init__ is not _VERIFIER_INIT_IMPLEMENTATION
    ):
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway deployment factory implementation changed"
        )
    key = SpecialistBackendVerificationKeyV2(
        keyId=verification_key_id,
        trustDomain=trust_domain,
        issuer=issuer,
        publicKeyBase64url=_PUBLIC_KEY_IMPLEMENTATION(signing_private_key),
    )
    template = _TEMPLATE_IMPLEMENTATION()
    inventory = _INVENTORY_IMPLEMENTATION(
        job_template=template,
        verification_key=key,
    )
    backend = object.__new__(_BACKEND_CLASS)
    _BACKEND_INIT_IMPLEMENTATION(
        backend,
        signing_private_key=signing_private_key,
        deployment_verification_key=key,
        job_template=template,
        execution_inventory=inventory,
    )
    verifier = object.__new__(_VERIFIER_CLASS)
    _VERIFIER_INIT_IMPLEMENTATION(
        verifier,
        deployment_verification_key=key,
        job_template=template,
        execution_inventory=inventory,
    )
    snapshot = _SNAPSHOT_FOR_RUNTIME_IMPLEMENTATION(
        verification_key=key,
        job_template=template,
        execution_inventory=inventory,
        backend=backend,
        verifier=verifier,
    )
    deployment = VerifiedSpecialistGatewayDeploymentV2(
        snapshot=snapshot,
        _factory_token=_DEPLOYMENT_FACTORY_TOKEN,
    )
    identity_token = object.__getattribute__(
        deployment,
        "_VerifiedSpecialistGatewayDeploymentV2__identity_token",
    )
    try:
        _REGISTER_RUNTIME_OWNER_IMPLEMENTATION(
            deployment,
            access_authority=_RUNTIME_OWNER_ACCESS_AUTHORITY,
            identity_token=identity_token,
            verification_key=key,
            job_template=template,
            execution_inventory=inventory,
            backend=backend,
            verifier=verifier,
        )
    except _SpecialistGatewayRuntimeOwnerV2Error as exc:
        raise SpecialistGatewayDeploymentV2Error(
            "specialist Gateway private runtime owner registration failed"
        ) from exc
    with _DEPLOYMENT_REGISTRY_LOCK_IMPLEMENTATION:
        if deployment in _DEPLOYMENT_REGISTRY_IMPLEMENTATION:
            raise SpecialistGatewayDeploymentV2Error(
                "specialist Gateway deployment was already factory registered"
            )
        _DEPLOYMENT_REGISTRY_IMPLEMENTATION[deployment] = _SpecialistGatewayDeploymentStateV2(
            snapshot=snapshot,
            runtime_identity_token=identity_token,
        )
        _REQUIRE_EXACT_RUNTIME_LOCKED_IMPLEMENTATION(
            deployment,
            _DEPLOYMENT_STATE_IMPLEMENTATION(deployment),
        )
    return deployment


_STRUCTURED_FAKE_GATEWAY_DEPLOYMENT_FACTORY_IMPLEMENTATION = (
    structured_fake_specialist_gateway_deployment_v2
)


__all__ = [
    "SPECIALIST_GATEWAY_DEPLOYMENT_API_VERSION",
    "SPECIALIST_WORKER_JOB_REF_API_VERSION",
    "SpecialistGatewayDeploymentSnapshotV2",
    "SpecialistGatewayDeploymentV2Error",
    "SpecialistWorkerJobRefV2",
    "VerifiedSpecialistGatewayDeploymentV2",
    "structured_fake_specialist_gateway_deployment_v2",
]
